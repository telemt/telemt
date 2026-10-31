//! Per-source-IP limit on concurrent unauthenticated handshakes.
//!
//! A connection occupies handshake processing until it authenticates, fails
//! or hits `timeouts.client_handshake`. A single address that opens hundreds
//! of connections and never completes the handshake can therefore keep that
//! capacity busy for a long time and starve legitimate clients.
//!
//! The limit counts only connections that are still in the handshake phase.
//! A slot is released as soon as the handshake ends (success, failure,
//! timeout or masking fallback), so authenticated sessions and bursts of
//! short-lived media connections, which authenticate within milliseconds,
//! are not affected. Entries exist only while an address has pending
//! handshakes, so the map is bounded by the number of in-flight connections.

use std::net::IpAddr;
use std::sync::Arc;

use dashmap::DashMap;

#[derive(Debug, Default)]
pub(crate) struct PendingHandshakeLimiter {
    pending: DashMap<IpAddr, u32>,
}

/// Holds one pending-handshake slot for an address until dropped.
#[derive(Debug)]
pub(crate) struct PendingHandshakeGuard {
    limiter: Arc<PendingHandshakeLimiter>,
    ip: IpAddr,
}

/// Result of an admission attempt.
#[derive(Debug)]
pub(crate) enum PendingHandshakeAdmission {
    /// The limit is disabled; nothing is tracked.
    Disabled,
    /// Under the limit; the slot is held by the guard.
    Admitted(PendingHandshakeGuard),
    /// Over the limit in dry-run mode: the connection proceeds and is still
    /// tracked, so the observed concurrency stays accurate.
    Observed(PendingHandshakeGuard),
    /// Over the limit: the connection must be closed.
    Rejected,
}

impl PendingHandshakeLimiter {
    /// Tries to take a pending-handshake slot for `ip`. `limit == 0` disables
    /// the check. In `dry_run` mode an address over the limit is admitted and
    /// reported as `Observed` instead of `Rejected`.
    pub(crate) fn try_acquire(
        self: &Arc<Self>,
        ip: IpAddr,
        limit: u32,
        dry_run: bool,
    ) -> PendingHandshakeAdmission {
        if limit == 0 {
            return PendingHandshakeAdmission::Disabled;
        }

        let mut pending = self.pending.entry(ip).or_insert(0);
        let over_limit = *pending >= limit;
        if over_limit && !dry_run {
            return PendingHandshakeAdmission::Rejected;
        }

        *pending = pending.saturating_add(1);
        drop(pending);

        let guard = PendingHandshakeGuard {
            limiter: Arc::clone(self),
            ip,
        };

        if over_limit {
            PendingHandshakeAdmission::Observed(guard)
        } else {
            PendingHandshakeAdmission::Admitted(guard)
        }
    }

    /// Number of pending handshakes currently held by `ip`.
    pub(crate) fn pending_for(&self, ip: IpAddr) -> u32 {
        self.pending.get(&ip).map(|v| *v).unwrap_or(0)
    }

    /// Number of addresses that currently have pending handshakes.
    pub(crate) fn tracked_ips(&self) -> usize {
        self.pending.len()
    }
}

impl Drop for PendingHandshakeGuard {
    fn drop(&mut self) {
        if let Some(mut pending) = self.limiter.pending.get_mut(&self.ip) {
            *pending = pending.saturating_sub(1);
        }
        // The predicate runs under the shard lock, so a concurrent acquire
        // that bumped the counter back above zero keeps the entry.
        self.limiter
            .pending
            .remove_if(&self.ip, |_, pending| *pending == 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, last))
    }

    #[test]
    fn zero_limit_disables_tracking() {
        let limiter = Arc::new(PendingHandshakeLimiter::default());
        for _ in 0..100 {
            assert!(matches!(
                limiter.try_acquire(ip(1), 0, false),
                PendingHandshakeAdmission::Disabled
            ));
        }
        assert_eq!(limiter.tracked_ips(), 0);
    }

    #[test]
    fn rejects_over_limit_and_frees_slot_on_drop() {
        let limiter = Arc::new(PendingHandshakeLimiter::default());
        let mut guards = Vec::new();
        for _ in 0..3 {
            match limiter.try_acquire(ip(1), 3, false) {
                PendingHandshakeAdmission::Admitted(guard) => guards.push(guard),
                other => panic!("expected admission, got {other:?}"),
            }
        }
        assert_eq!(limiter.pending_for(ip(1)), 3);
        assert!(matches!(
            limiter.try_acquire(ip(1), 3, false),
            PendingHandshakeAdmission::Rejected
        ));
        // A rejection does not take a slot.
        assert_eq!(limiter.pending_for(ip(1)), 3);

        guards.pop();
        assert!(matches!(
            limiter.try_acquire(ip(1), 3, false),
            PendingHandshakeAdmission::Admitted(_)
        ));
    }

    #[test]
    fn addresses_are_independent() {
        let limiter = Arc::new(PendingHandshakeLimiter::default());
        let _a = limiter.try_acquire(ip(1), 1, false);
        assert!(matches!(
            limiter.try_acquire(ip(1), 1, false),
            PendingHandshakeAdmission::Rejected
        ));
        assert!(matches!(
            limiter.try_acquire(ip(2), 1, false),
            PendingHandshakeAdmission::Admitted(_)
        ));
        assert!(matches!(
            limiter.try_acquire(IpAddr::V6(Ipv6Addr::LOCALHOST), 1, false),
            PendingHandshakeAdmission::Admitted(_)
        ));
    }

    #[test]
    fn dry_run_admits_and_keeps_counting() {
        let limiter = Arc::new(PendingHandshakeLimiter::default());
        let first = limiter.try_acquire(ip(1), 1, true);
        assert!(matches!(first, PendingHandshakeAdmission::Admitted(_)));
        let second = limiter.try_acquire(ip(1), 1, true);
        assert!(matches!(second, PendingHandshakeAdmission::Observed(_)));
        assert_eq!(limiter.pending_for(ip(1)), 2);
        drop(first);
        drop(second);
        assert_eq!(limiter.pending_for(ip(1)), 0);
    }

    #[test]
    fn entries_are_removed_when_idle() {
        let limiter = Arc::new(PendingHandshakeLimiter::default());
        {
            let _a = limiter.try_acquire(ip(1), 4, false);
            let _b = limiter.try_acquire(ip(2), 4, false);
            assert_eq!(limiter.tracked_ips(), 2);
        }
        assert_eq!(limiter.tracked_ips(), 0);
    }

    #[test]
    fn concurrent_acquire_release_never_exceeds_limit() {
        let limiter = Arc::new(PendingHandshakeLimiter::default());
        let limit = 8;
        let peak = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let limiter = Arc::clone(&limiter);
                let peak = Arc::clone(&peak);
                std::thread::spawn(move || {
                    for _ in 0..2_000 {
                        if let PendingHandshakeAdmission::Admitted(guard) =
                            limiter.try_acquire(ip(7), limit, false)
                        {
                            let now = limiter.pending_for(ip(7));
                            peak.fetch_max(now, std::sync::atomic::Ordering::Relaxed);
                            drop(guard);
                        }
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        assert!(peak.load(std::sync::atomic::Ordering::Relaxed) <= limit);
        assert_eq!(limiter.tracked_ips(), 0);
    }
}
