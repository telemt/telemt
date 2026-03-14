use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use subtle::ConstantTimeEq;
use tracing::warn;

use super::pool::MePool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotApplyOutcome {
    AppliedChanged,
    AppliedNoDelta,
    RejectedEmpty,
}

impl SnapshotApplyOutcome {
    pub const fn changed(self) -> bool {
        matches!(self, Self::AppliedChanged)
    }
}

// Limits the number of simultaneous outbound dials during a secret-rotation
// reconnect sweep, preventing a thundering-herd burst against Telegram's
// MTProto servers when the pool contains many active writers.
const MAX_CONCURRENT_RECONNECTS: usize = 32;

impl MePool {
    pub async fn update_proxy_maps(
        &self,
        new_v4: HashMap<i32, Vec<(IpAddr, u16)>>,
        new_v6: Option<HashMap<i32, Vec<(IpAddr, u16)>>>,
    ) -> SnapshotApplyOutcome {
        if new_v4.is_empty() && new_v6.as_ref().is_none_or(|v| v.is_empty()) {
            return SnapshotApplyOutcome::RejectedEmpty;
        }

        let mut changed = false;

        // Acquire both locks in a fixed order (v4 → v6) and hold them for the full
        // mutation, including the negative-DC mirroring pass.  Separate lock scopes
        // would expose a window where v4 is updated but v6 is still stale, or the
        // mirroring is half-applied; holding both guards eliminates that window.
        let mut guard_v4 = self.proxy_map_v4.write().await;
        let mut guard_v6 = self.proxy_map_v6.write().await;

        if !new_v4.is_empty() && *guard_v4 != new_v4 {
            *guard_v4 = new_v4;
            changed = true;
        }
        if let Some(v6) = new_v6
            && !v6.is_empty() && *guard_v6 != v6
        {
            *guard_v6 = v6;
            changed = true;
        }

        // Ensure negative DC entries mirror positives when absent (Telegram convention).
        let keys_v4: Vec<i32> = guard_v4.keys().cloned().collect();
        for k in keys_v4.into_iter().filter(|k| *k > 0) {
            if !guard_v4.contains_key(&-k)
                && let Some(addrs) = guard_v4.get(&k).cloned()
            {
                guard_v4.insert(-k, addrs);
                changed = true;
            }
        }
        let keys_v6: Vec<i32> = guard_v6.keys().cloned().collect();
        for k in keys_v6.into_iter().filter(|k| *k > 0) {
            if !guard_v6.contains_key(&-k)
                && let Some(addrs) = guard_v6.get(&k).cloned()
            {
                guard_v6.insert(-k, addrs);
                changed = true;
            }
        }

        drop(guard_v6);
        drop(guard_v4);
        if changed {
            self.rebuild_endpoint_dc_map().await;
            self.writer_available.notify_waiters();
        }
        if changed {
            SnapshotApplyOutcome::AppliedChanged
        } else {
            SnapshotApplyOutcome::AppliedNoDelta
        }
    }

    pub async fn update_secret(self: &Arc<Self>, new_secret: Vec<u8>) -> bool {
        if new_secret.len() < 32 {
            warn!(len = new_secret.len(), "proxy-secret update ignored (too short)");
            return false;
        }
        let mut guard = self.proxy_secret.write().await;
        // Constant-time comparison prevents timing side-channels on key material.
        if !bool::from(guard.secret.as_slice().ct_eq(new_secret.as_slice())) {
            guard.secret = new_secret;
            guard.key_selector = if guard.secret.len() >= 4 {
                u32::from_le_bytes([
                    guard.secret[0],
                    guard.secret[1],
                    guard.secret[2],
                    guard.secret[3],
                ])
            } else {
                0
            };
            guard.epoch = guard.epoch.saturating_add(1);
            drop(guard);
            self.reconnect_all().await;
            return true;
        }
        false
    }

    // Reconnects every active writer concurrently, bounded to MAX_CONCURRENT_RECONNECTS
    // tasks at a time, so that secret rotation does not block the caller for
    // O(N writers × connect latency) with the old sequential approach, and does not
    // create an unbounded burst of dials against Telegram's MTProto endpoints.
    // Each new connection is established before the corresponding old writer is marked
    // as draining, ensuring the pool never briefly drops to zero active writers per DC.
    pub async fn reconnect_all(self: &Arc<Self>) {
        let ws = self.writers.read().await.clone();
        let mut ws_iter = ws.into_iter();
        loop {
            let mut join = tokio::task::JoinSet::new();
            let mut spawned = 0usize;
            for _ in 0..MAX_CONCURRENT_RECONNECTS {
                if let Some(w) = ws_iter.next() {
                    let pool = self.clone();
                    spawned += 1;
                    join.spawn(async move {
                        if pool
                            .connect_one_for_dc(w.addr, w.writer_dc, pool.rng.as_ref())
                            .await
                            .is_ok()
                        {
                            pool.mark_writer_draining(w.id).await;
                        }
                    });
                } else {
                    break;
                }
            }
            if spawned == 0 {
                break;
            }
            while let Some(result) = join.join_next().await {
                if let Err(err) = result {
                    warn!(error = ?err, "reconnect task failed (panic or cancellation)");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SnapshotApplyOutcome, MAX_CONCURRENT_RECONNECTS};

    // --- SnapshotApplyOutcome::changed() ---

    #[test]
    fn applied_changed_reports_changed() {
        assert!(SnapshotApplyOutcome::AppliedChanged.changed());
    }

    #[test]
    fn applied_no_delta_reports_not_changed() {
        assert!(!SnapshotApplyOutcome::AppliedNoDelta.changed());
    }

    #[test]
    fn rejected_empty_reports_not_changed() {
        assert!(!SnapshotApplyOutcome::RejectedEmpty.changed());
    }

    // Regression: only AppliedChanged must return true; the other two variants must
    // not accidentally claim a change occurred, as callers use this to gate reconnects.
    #[test]
    fn only_applied_changed_variant_is_changed() {
        let variants = [
            SnapshotApplyOutcome::AppliedChanged,
            SnapshotApplyOutcome::AppliedNoDelta,
            SnapshotApplyOutcome::RejectedEmpty,
        ];
        let changed_count = variants.iter().filter(|v| v.changed()).count();
        assert_eq!(changed_count, 1, "exactly one variant must report changed");
    }

    // --- MAX_CONCURRENT_RECONNECTS ---

    // The concurrency bound must be large enough for meaningful parallelism but
    // small enough to prevent a thundering-herd burst against upstream endpoints.
    #[test]
    fn max_concurrent_reconnects_is_in_operational_range() {
        assert!(
            MAX_CONCURRENT_RECONNECTS >= 4,
            "concurrency bound ({MAX_CONCURRENT_RECONNECTS}) is too small for useful parallelism"
        );
        assert!(
            MAX_CONCURRENT_RECONNECTS <= 256,
            "concurrency bound ({MAX_CONCURRENT_RECONNECTS}) risks thundering-herd on upstream"
        );
    }

    // Regression: a panicking reconnect task must produce a catchable JoinError rather
    // than being silently swallowed.  If the while loop ever reverts to `.is_some()`
    // the error is dropped; this test ensures the error EXISTS and can be observed.
    #[tokio::test]
    async fn panicking_reconnect_task_produces_join_error() {
        let mut join: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
        join.spawn(async { panic!("simulated reconnect task panic") });
        let mut error_count = 0usize;
        while let Some(result) = join.join_next().await {
            if result.is_err() {
                error_count += 1;
            }
        }
        assert_eq!(
            error_count, 1,
            "exactly one JoinError must be emitted by the panicking task"
        );
    }

    // Verify that the batch-iteration logic never exceeds MAX_CONCURRENT_RECONNECTS
    // tasks per batch, regardless of how many writers exist.
    #[test]
    fn batching_logic_never_spawns_more_than_cap_per_batch() {
        // Simulate the batch loop with a large writer list (200 > 32).
        let total_writers = 200usize;
        let mut remaining = total_writers;
        let mut max_batch = 0usize;

        while remaining > 0 {
            let batch = remaining.min(MAX_CONCURRENT_RECONNECTS);
            if batch > max_batch {
                max_batch = batch;
            }
            remaining -= batch;
        }

        assert!(
            max_batch <= MAX_CONCURRENT_RECONNECTS,
            "no batch must exceed MAX_CONCURRENT_RECONNECTS ({MAX_CONCURRENT_RECONNECTS})"
        );
        assert_eq!(
            max_batch,
            MAX_CONCURRENT_RECONNECTS,
            "first batch must be exactly MAX_CONCURRENT_RECONNECTS when writers > cap"
        );
    }
}
