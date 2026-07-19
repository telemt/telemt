use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

use super::{QuotaReserveError, UserQuotaSnapshot};

/// Process-scoped per-user quota accounting shared by runtime generations.
#[derive(Default)]
pub struct QuotaStore {
    users: DashMap<String, Arc<UserQuotaCounters>>,
}

/// Atomic quota state for one configured user.
#[derive(Default)]
pub(crate) struct UserQuotaCounters {
    used_bytes: AtomicU64,
    last_reset_epoch_secs: AtomicU64,
}

impl QuotaStore {
    pub(crate) fn user(&self, user: &str) -> Arc<UserQuotaCounters> {
        if let Some(existing) = self.users.get(user) {
            return Arc::clone(existing.value());
        }
        Arc::clone(
            self.users
                .entry(user.to_string())
                .or_insert_with(|| Arc::new(UserQuotaCounters::default()))
                .value(),
        )
    }

    pub(crate) fn used(&self, user: &str) -> u64 {
        self.users.get(user).map(|state| state.used()).unwrap_or(0)
    }

    pub(crate) fn load(&self, user: &str, used_bytes: u64, last_reset_epoch_secs: u64) {
        let state = self.user(user);
        state.used_bytes.store(used_bytes, Ordering::Relaxed);
        state
            .last_reset_epoch_secs
            .store(last_reset_epoch_secs, Ordering::Relaxed);
    }

    pub(crate) fn reset(&self, user: &str, now_epoch_secs: u64) -> UserQuotaSnapshot {
        let state = self.user(user);
        state.used_bytes.store(0, Ordering::Relaxed);
        state
            .last_reset_epoch_secs
            .store(now_epoch_secs, Ordering::Relaxed);
        UserQuotaSnapshot {
            used_bytes: 0,
            last_reset_epoch_secs: now_epoch_secs,
        }
    }

    pub(crate) fn snapshot(&self) -> HashMap<String, UserQuotaSnapshot> {
        let mut out = HashMap::new();
        for entry in self.users.iter() {
            let state = entry.value();
            let used_bytes = state.used();
            let last_reset_epoch_secs = state.last_reset_epoch_secs.load(Ordering::Relaxed);
            if used_bytes == 0 && last_reset_epoch_secs == 0 {
                continue;
            }
            out.insert(
                entry.key().clone(),
                UserQuotaSnapshot {
                    used_bytes,
                    last_reset_epoch_secs,
                },
            );
        }
        out
    }
}

impl UserQuotaCounters {
    #[inline]
    pub(crate) fn used(&self) -> u64 {
        self.used_bytes.load(Ordering::Relaxed)
    }

    #[inline]
    pub(crate) fn charge(&self, bytes: u64) -> u64 {
        self.used_bytes
            .fetch_add(bytes, Ordering::Relaxed)
            .saturating_add(bytes)
    }

    #[inline]
    pub(crate) fn refund(&self, bytes: u64) {
        let mut current = self.used_bytes.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_sub(bytes);
            match self.used_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    #[inline]
    pub(crate) fn try_reserve(&self, bytes: u64, limit: u64) -> Result<u64, QuotaReserveError> {
        let current = self.used_bytes.load(Ordering::Relaxed);
        if bytes > limit.saturating_sub(current) {
            return Err(QuotaReserveError::LimitExceeded);
        }

        let next = current.saturating_add(bytes);
        match self.used_bytes.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => Ok(next),
            Err(_) => Err(QuotaReserveError::Contended),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::Stats;

    #[test]
    fn quota_counters_are_shared_across_stats_generations() {
        let store = Arc::new(QuotaStore::default());
        let first = Stats::with_quota_store(store.clone());
        store.user("alice").charge(512);
        assert_eq!(first.get_user_quota_used("alice"), 512);

        let second = Stats::with_quota_store(store);
        assert_eq!(second.get_user_quota_used("alice"), 512);
        second.reset_user_quota("alice");
        assert_eq!(first.get_user_quota_used("alice"), 0);
    }
}
