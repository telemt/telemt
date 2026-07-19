use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::MeTelemetryLevel;

use super::*;

impl Stats {
    pub(super) fn telemetry_me_level(&self) -> MeTelemetryLevel {
        MeTelemetryLevel::from_u8(self.telemetry_me_level.load(Ordering::Relaxed))
    }

    pub(super) fn telemetry_core_enabled(&self) -> bool {
        self.telemetry_core_enabled.load(Ordering::Relaxed)
    }

    pub(super) fn telemetry_user_enabled(&self) -> bool {
        self.telemetry_user_enabled.load(Ordering::Relaxed)
    }

    pub(super) fn telemetry_me_allows_normal(&self) -> bool {
        self.telemetry_me_level().allows_normal()
    }

    pub(super) fn telemetry_me_allows_debug(&self) -> bool {
        self.telemetry_me_level().allows_debug()
    }

    pub(super) fn decrement_atomic_saturating(counter: &AtomicU64) {
        let mut current = counter.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                break;
            }
            match counter.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    pub(super) fn now_epoch_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub(super) fn refresh_cached_epoch_secs(&self) -> u64 {
        let now_epoch_secs = Self::now_epoch_secs();
        self.cached_epoch_secs
            .store(now_epoch_secs, Ordering::Relaxed);
        now_epoch_secs
    }

    pub(super) fn cached_epoch_secs(&self) -> u64 {
        let cached = self.cached_epoch_secs.load(Ordering::Relaxed);
        if cached != 0 {
            return cached;
        }
        self.refresh_cached_epoch_secs()
    }

    pub(super) fn touch_user_stats(&self, stats: &UserStats) {
        stats
            .last_seen_epoch_secs
            .store(self.cached_epoch_secs(), Ordering::Relaxed);
    }

    pub(crate) fn get_or_create_user_stats_handle(&self, user: &str) -> Arc<UserStats> {
        if let Some(existing) = self.user_stats.get(user) {
            let handle = Arc::clone(existing.value());
            self.touch_user_stats(handle.as_ref());
            return handle;
        }

        let quota = self.quota_store.user(user);
        let entry = self
            .user_stats
            .entry(user.to_string())
            .or_insert_with(|| Arc::new(UserStats::with_quota(quota)));
        if entry.last_seen_epoch_secs.load(Ordering::Relaxed) == 0 {
            self.touch_user_stats(entry.value().as_ref());
        }
        Arc::clone(entry.value())
    }

    pub(crate) async fn run_periodic_user_stats_maintenance(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            self.maybe_cleanup_user_stats();
        }
    }

    #[inline]
    pub(crate) fn add_user_octets_from_handle(&self, user_stats: &UserStats, bytes: u64) {
        if !self.telemetry_user_enabled() {
            return;
        }
        self.touch_user_stats(user_stats);
        user_stats
            .octets_from_client
            .fetch_add(bytes, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn add_user_octets_to_handle(&self, user_stats: &UserStats, bytes: u64) {
        if !self.telemetry_user_enabled() {
            return;
        }
        self.touch_user_stats(user_stats);
        user_stats
            .octets_to_client
            .fetch_add(bytes, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn add_user_traffic_from_handle(&self, user_stats: &UserStats, bytes: u64) {
        if !self.telemetry_user_enabled() {
            return;
        }
        self.touch_user_stats(user_stats);
        user_stats
            .octets_from_client
            .fetch_add(bytes, Ordering::Relaxed);
        user_stats.msgs_from_client.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn add_user_traffic_to_handle(&self, user_stats: &UserStats, bytes: u64) {
        if !self.telemetry_user_enabled() {
            return;
        }
        self.touch_user_stats(user_stats);
        user_stats
            .octets_to_client
            .fetch_add(bytes, Ordering::Relaxed);
        user_stats.msgs_to_client.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn increment_user_msgs_from_handle(&self, user_stats: &UserStats) {
        if !self.telemetry_user_enabled() {
            return;
        }
        self.touch_user_stats(user_stats);
        user_stats.msgs_from_client.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn increment_user_msgs_to_handle(&self, user_stats: &UserStats) {
        if !self.telemetry_user_enabled() {
            return;
        }
        self.touch_user_stats(user_stats);
        user_stats.msgs_to_client.fetch_add(1, Ordering::Relaxed);
    }

    /// Charges already committed bytes in a post-I/O path.
    ///
    /// This helper is intentionally separate from `quota_try_reserve` to avoid
    /// mixing reserve and post-charge on a single I/O event.
    #[inline]
    pub(crate) fn quota_charge_post_write(&self, user_stats: &UserStats, bytes: u64) -> u64 {
        self.touch_user_stats(user_stats);
        user_stats.quota.charge(bytes)
    }

    pub(super) fn maybe_cleanup_user_stats(&self) {
        const USER_STATS_CLEANUP_INTERVAL_SECS: u64 = 60;
        const USER_STATS_IDLE_TTL_SECS: u64 = 24 * 60 * 60;

        let now_epoch_secs = self.refresh_cached_epoch_secs();
        let last_cleanup_epoch_secs = self
            .user_stats_last_cleanup_epoch_secs
            .load(Ordering::Relaxed);
        if now_epoch_secs.saturating_sub(last_cleanup_epoch_secs) < USER_STATS_CLEANUP_INTERVAL_SECS
        {
            return;
        }
        if self
            .user_stats_last_cleanup_epoch_secs
            .compare_exchange(
                last_cleanup_epoch_secs,
                now_epoch_secs,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return;
        }

        self.user_stats.retain(|_, stats| {
            if stats.curr_connects.load(Ordering::Relaxed) > 0 {
                return true;
            }
            let last_seen_epoch_secs = stats.last_seen_epoch_secs.load(Ordering::Relaxed);
            now_epoch_secs.saturating_sub(last_seen_epoch_secs) <= USER_STATS_IDLE_TTL_SECS
        });
    }
}
