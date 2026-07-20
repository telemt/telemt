use super::*;

impl Stats {
    pub fn increment_user_connects(&self, user: &str) {
        if !self.telemetry_user_enabled() {
            return;
        }
        let stats = self.get_or_create_user_stats_handle(user);
        self.touch_user_stats(stats.as_ref());
        stats.connects.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_user_curr_connects(&self, user: &str) {
        if !self.telemetry_user_enabled() {
            return;
        }
        let stats = self.get_or_create_user_stats_handle(user);
        self.touch_user_stats(stats.as_ref());
        stats.curr_connects.fetch_add(1, Ordering::Relaxed);
    }

    pub fn try_acquire_user_curr_connects(&self, user: &str, limit: Option<u64>) -> bool {
        if !self.telemetry_user_enabled() {
            return true;
        }

        let stats = self.get_or_create_user_stats_handle(user);
        self.touch_user_stats(stats.as_ref());

        let counter = &stats.curr_connects;
        let mut current = counter.load(Ordering::Relaxed);
        loop {
            if let Some(max) = limit
                && current >= max
            {
                return false;
            }
            match counter.compare_exchange_weak(
                current,
                current.saturating_add(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    pub fn decrement_user_curr_connects(&self, user: &str) {
        if let Some(stats) = self.user_stats.get(user) {
            self.touch_user_stats(stats.value().as_ref());
            let counter = &stats.curr_connects;
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
    }

    pub fn get_user_curr_connects(&self, user: &str) -> u64 {
        self.user_stats
            .get(user)
            .map(|s| s.curr_connects.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn add_user_octets_from(&self, user: &str, bytes: u64) {
        if !self.telemetry_user_enabled() {
            return;
        }
        let stats = self.get_or_create_user_stats_handle(user);
        self.add_user_octets_from_handle(stats.as_ref(), bytes);
    }

    pub fn add_user_octets_to(&self, user: &str, bytes: u64) {
        if !self.telemetry_user_enabled() {
            return;
        }
        let stats = self.get_or_create_user_stats_handle(user);
        self.add_user_octets_to_handle(stats.as_ref(), bytes);
    }

    pub fn increment_user_msgs_from(&self, user: &str) {
        if !self.telemetry_user_enabled() {
            return;
        }
        let stats = self.get_or_create_user_stats_handle(user);
        self.increment_user_msgs_from_handle(stats.as_ref());
    }

    pub fn increment_user_msgs_to(&self, user: &str) {
        if !self.telemetry_user_enabled() {
            return;
        }
        let stats = self.get_or_create_user_stats_handle(user);
        self.increment_user_msgs_to_handle(stats.as_ref());
    }

    pub fn get_user_total_octets(&self, user: &str) -> u64 {
        self.user_stats
            .get(user)
            .map(|s| {
                s.octets_from_client.load(Ordering::Relaxed)
                    + s.octets_to_client.load(Ordering::Relaxed)
            })
            .unwrap_or(0)
    }

    pub fn get_user_quota_used(&self, user: &str) -> u64 {
        self.quota_store.used(user)
    }

    pub fn load_user_quota_state(&self, user: &str, used_bytes: u64, last_reset_epoch_secs: u64) {
        self.quota_store
            .load(user, used_bytes, last_reset_epoch_secs);
    }

    pub fn reset_user_quota(&self, user: &str) -> UserQuotaSnapshot {
        let last_reset_epoch_secs = Self::now_epoch_secs();
        self.quota_store.reset(user, last_reset_epoch_secs)
    }

    pub fn user_quota_snapshot(&self) -> HashMap<String, UserQuotaSnapshot> {
        self.quota_store.snapshot()
    }

    pub fn get_handshake_timeouts(&self) -> u64 {
        self.handshake_timeouts.load(Ordering::Relaxed)
    }
    pub fn get_upstream_connect_attempt_total(&self) -> u64 {
        self.upstream_connect_attempt_total.load(Ordering::Relaxed)
    }
    pub fn get_upstream_connect_success_total(&self) -> u64 {
        self.upstream_connect_success_total.load(Ordering::Relaxed)
    }
    pub fn get_upstream_connect_fail_total(&self) -> u64 {
        self.upstream_connect_fail_total.load(Ordering::Relaxed)
    }
    pub fn get_upstream_connect_failfast_hard_error_total(&self) -> u64 {
        self.upstream_connect_failfast_hard_error_total
            .load(Ordering::Relaxed)
    }
    pub fn get_upstream_connect_attempts_bucket_1(&self) -> u64 {
        self.upstream_connect_attempts_bucket_1
            .load(Ordering::Relaxed)
    }
    pub fn get_upstream_connect_attempts_bucket_2(&self) -> u64 {
        self.upstream_connect_attempts_bucket_2
            .load(Ordering::Relaxed)
    }
    pub fn get_upstream_connect_attempts_bucket_3_4(&self) -> u64 {
        self.upstream_connect_attempts_bucket_3_4
            .load(Ordering::Relaxed)
    }
    pub fn get_upstream_connect_attempts_bucket_gt_4(&self) -> u64 {
        self.upstream_connect_attempts_bucket_gt_4
            .load(Ordering::Relaxed)
    }
    pub fn get_upstream_connect_duration_success_bucket_le_100ms(&self) -> u64 {
        self.upstream_connect_duration_success_bucket_le_100ms
            .load(Ordering::Relaxed)
    }
    pub fn get_upstream_connect_duration_success_bucket_101_500ms(&self) -> u64 {
        self.upstream_connect_duration_success_bucket_101_500ms
            .load(Ordering::Relaxed)
    }
    pub fn get_upstream_connect_duration_success_bucket_501_1000ms(&self) -> u64 {
        self.upstream_connect_duration_success_bucket_501_1000ms
            .load(Ordering::Relaxed)
    }
    pub fn get_upstream_connect_duration_success_bucket_gt_1000ms(&self) -> u64 {
        self.upstream_connect_duration_success_bucket_gt_1000ms
            .load(Ordering::Relaxed)
    }
    pub fn get_upstream_connect_duration_fail_bucket_le_100ms(&self) -> u64 {
        self.upstream_connect_duration_fail_bucket_le_100ms
            .load(Ordering::Relaxed)
    }
    pub fn get_upstream_connect_duration_fail_bucket_101_500ms(&self) -> u64 {
        self.upstream_connect_duration_fail_bucket_101_500ms
            .load(Ordering::Relaxed)
    }
    pub fn get_upstream_connect_duration_fail_bucket_501_1000ms(&self) -> u64 {
        self.upstream_connect_duration_fail_bucket_501_1000ms
            .load(Ordering::Relaxed)
    }
    pub fn get_upstream_connect_duration_fail_bucket_gt_1000ms(&self) -> u64 {
        self.upstream_connect_duration_fail_bucket_gt_1000ms
            .load(Ordering::Relaxed)
    }

    pub fn iter_user_stats(&self) -> dashmap::iter::Iter<'_, String, Arc<UserStats>> {
        self.user_stats.iter()
    }

    /// Current number of retained per-user stats entries.
    pub fn user_stats_len(&self) -> usize {
        self.user_stats.len()
    }

    pub fn uptime_secs(&self) -> f64 {
        self.start_time
            .read()
            .map(|t| t.elapsed().as_secs_f64())
            .unwrap_or(0.0)
    }
}
