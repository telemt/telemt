use super::*;

impl Stats {
    pub fn apply_telemetry_policy(&self, policy: TelemetryPolicy) {
        self.telemetry_core_enabled
            .store(policy.core_enabled, Ordering::Relaxed);
        self.telemetry_user_enabled
            .store(policy.user_enabled, Ordering::Relaxed);
        self.telemetry_me_level
            .store(policy.me_level.as_u8(), Ordering::Relaxed);
    }

    pub fn telemetry_policy(&self) -> TelemetryPolicy {
        TelemetryPolicy {
            core_enabled: self.telemetry_core_enabled(),
            user_enabled: self.telemetry_user_enabled(),
            me_level: self.telemetry_me_level(),
        }
    }

    pub fn increment_connects_all(&self) {
        if self.telemetry_core_enabled() {
            self.connects_all.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn increment_connects_bad_with_class(&self, class: &'static str) {
        if !self.telemetry_core_enabled() {
            return;
        }
        self.connects_bad.fetch_add(1, Ordering::Relaxed);
        let entry = self
            .connects_bad_classes
            .entry(class)
            .or_insert_with(|| AtomicU64::new(0));
        entry.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_connects_bad(&self) {
        self.increment_connects_bad_with_class("other");
    }

    pub fn increment_handshake_failure_class(&self, class: &'static str) {
        if !self.telemetry_core_enabled() {
            return;
        }
        let entry = self
            .handshake_failure_classes
            .entry(class)
            .or_insert_with(|| AtomicU64::new(0));
        entry.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_current_connections_direct(&self) {
        self.current_connections_direct
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn decrement_current_connections_direct(&self) {
        Self::decrement_atomic_saturating(&self.current_connections_direct);
    }
    pub fn increment_current_connections_me(&self) {
        self.current_connections_me.fetch_add(1, Ordering::Relaxed);
    }
    pub fn decrement_current_connections_me(&self) {
        Self::decrement_atomic_saturating(&self.current_connections_me);
    }

    pub fn acquire_direct_connection_lease(self: &Arc<Self>) -> RouteConnectionLease {
        self.increment_current_connections_direct();
        RouteConnectionLease::new(self.clone(), RouteConnectionGauge::Direct)
    }

    pub fn acquire_me_connection_lease(self: &Arc<Self>) -> RouteConnectionLease {
        self.increment_current_connections_me();
        RouteConnectionLease::new(self.clone(), RouteConnectionGauge::Middle)
    }

    pub(super) fn decrement_route_cutover_parked_direct(&self) {
        Self::decrement_atomic_saturating(&self.route_cutover_parked_direct_current);
    }

    pub(super) fn decrement_route_cutover_parked_middle(&self) {
        Self::decrement_atomic_saturating(&self.route_cutover_parked_middle_current);
    }

    pub fn acquire_direct_cutover_park_lease(self: &Arc<Self>) -> RouteCutoverParkLease {
        self.route_cutover_parked_direct_current
            .fetch_add(1, Ordering::Relaxed);
        self.route_cutover_parked_direct_total
            .fetch_add(1, Ordering::Relaxed);
        RouteCutoverParkLease::new(self.clone(), RouteCutoverParkGauge::Direct)
    }

    pub fn acquire_middle_cutover_park_lease(self: &Arc<Self>) -> RouteCutoverParkLease {
        self.route_cutover_parked_middle_current
            .fetch_add(1, Ordering::Relaxed);
        self.route_cutover_parked_middle_total
            .fetch_add(1, Ordering::Relaxed);
        RouteCutoverParkLease::new(self.clone(), RouteCutoverParkGauge::Middle)
    }
    pub fn increment_handshake_timeouts(&self) {
        if self.telemetry_core_enabled() {
            self.handshake_timeouts.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn increment_accept_permit_timeout_total(&self) {
        if self.telemetry_core_enabled() {
            self.accept_permit_timeout_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn set_conntrack_control_enabled(&self, enabled: bool) {
        self.conntrack_control_enabled_gauge
            .store(enabled, Ordering::Relaxed);
    }

    pub fn set_conntrack_control_available(&self, available: bool) {
        self.conntrack_control_available_gauge
            .store(available, Ordering::Relaxed);
    }

    pub fn set_conntrack_pressure_active(&self, active: bool) {
        self.conntrack_pressure_active_gauge
            .store(active, Ordering::Relaxed);
    }

    pub fn set_conntrack_event_queue_depth(&self, depth: u64) {
        self.conntrack_event_queue_depth_gauge
            .store(depth, Ordering::Relaxed);
    }

    pub fn set_conntrack_rule_apply_ok(&self, ok: bool) {
        self.conntrack_rule_apply_ok_gauge
            .store(ok, Ordering::Relaxed);
    }

    pub fn increment_conntrack_delete_attempt_total(&self) {
        if self.telemetry_core_enabled() {
            self.conntrack_delete_attempt_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn increment_conntrack_delete_success_total(&self) {
        if self.telemetry_core_enabled() {
            self.conntrack_delete_success_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn increment_conntrack_delete_not_found_total(&self) {
        if self.telemetry_core_enabled() {
            self.conntrack_delete_not_found_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn increment_conntrack_delete_error_total(&self) {
        if self.telemetry_core_enabled() {
            self.conntrack_delete_error_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn increment_conntrack_close_event_drop_total(&self) {
        if self.telemetry_core_enabled() {
            self.conntrack_close_event_drop_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn increment_upstream_connect_attempt_total(&self) {
        if self.telemetry_core_enabled() {
            self.upstream_connect_attempt_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_upstream_connect_success_total(&self) {
        if self.telemetry_core_enabled() {
            self.upstream_connect_success_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_upstream_connect_fail_total(&self) {
        if self.telemetry_core_enabled() {
            self.upstream_connect_fail_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_upstream_connect_failfast_hard_error_total(&self) {
        if self.telemetry_core_enabled() {
            self.upstream_connect_failfast_hard_error_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn observe_upstream_connect_attempts_per_request(&self, attempts: u32) {
        if !self.telemetry_core_enabled() {
            return;
        }
        match attempts {
            0 => {}
            1 => {
                self.upstream_connect_attempts_bucket_1
                    .fetch_add(1, Ordering::Relaxed);
            }
            2 => {
                self.upstream_connect_attempts_bucket_2
                    .fetch_add(1, Ordering::Relaxed);
            }
            3..=4 => {
                self.upstream_connect_attempts_bucket_3_4
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.upstream_connect_attempts_bucket_gt_4
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn observe_upstream_connect_duration_ms(&self, duration_ms: u64, success: bool) {
        if !self.telemetry_core_enabled() {
            return;
        }
        let bucket = match duration_ms {
            0..=100 => 0u8,
            101..=500 => 1u8,
            501..=1000 => 2u8,
            _ => 3u8,
        };
        match (success, bucket) {
            (true, 0) => {
                self.upstream_connect_duration_success_bucket_le_100ms
                    .fetch_add(1, Ordering::Relaxed);
            }
            (true, 1) => {
                self.upstream_connect_duration_success_bucket_101_500ms
                    .fetch_add(1, Ordering::Relaxed);
            }
            (true, 2) => {
                self.upstream_connect_duration_success_bucket_501_1000ms
                    .fetch_add(1, Ordering::Relaxed);
            }
            (true, _) => {
                self.upstream_connect_duration_success_bucket_gt_1000ms
                    .fetch_add(1, Ordering::Relaxed);
            }
            (false, 0) => {
                self.upstream_connect_duration_fail_bucket_le_100ms
                    .fetch_add(1, Ordering::Relaxed);
            }
            (false, 1) => {
                self.upstream_connect_duration_fail_bucket_101_500ms
                    .fetch_add(1, Ordering::Relaxed);
            }
            (false, 2) => {
                self.upstream_connect_duration_fail_bucket_501_1000ms
                    .fetch_add(1, Ordering::Relaxed);
            }
            (false, _) => {
                self.upstream_connect_duration_fail_bucket_gt_1000ms
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}
