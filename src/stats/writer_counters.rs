use super::*;

impl Stats {
    pub fn increment_me_writer_pick_success_try_total(&self, mode: MeWriterPickMode) {
        if !self.telemetry_me_allows_normal() {
            return;
        }
        match mode {
            MeWriterPickMode::SortedRr => {
                self.me_writer_pick_sorted_rr_success_try_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            MeWriterPickMode::P2c => {
                self.me_writer_pick_p2c_success_try_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn increment_me_writer_pick_success_fallback_total(&self, mode: MeWriterPickMode) {
        if !self.telemetry_me_allows_normal() {
            return;
        }
        match mode {
            MeWriterPickMode::SortedRr => {
                self.me_writer_pick_sorted_rr_success_fallback_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            MeWriterPickMode::P2c => {
                self.me_writer_pick_p2c_success_fallback_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn increment_me_writer_pick_full_total(&self, mode: MeWriterPickMode) {
        if !self.telemetry_me_allows_normal() {
            return;
        }
        match mode {
            MeWriterPickMode::SortedRr => {
                self.me_writer_pick_sorted_rr_full_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            MeWriterPickMode::P2c => {
                self.me_writer_pick_p2c_full_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn increment_me_writer_pick_closed_total(&self, mode: MeWriterPickMode) {
        if !self.telemetry_me_allows_normal() {
            return;
        }
        match mode {
            MeWriterPickMode::SortedRr => {
                self.me_writer_pick_sorted_rr_closed_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            MeWriterPickMode::P2c => {
                self.me_writer_pick_p2c_closed_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn increment_me_writer_pick_no_candidate_total(&self, mode: MeWriterPickMode) {
        if !self.telemetry_me_allows_normal() {
            return;
        }
        match mode {
            MeWriterPickMode::SortedRr => {
                self.me_writer_pick_sorted_rr_no_candidate_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            MeWriterPickMode::P2c => {
                self.me_writer_pick_p2c_no_candidate_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn increment_me_writer_pick_blocking_fallback_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_writer_pick_blocking_fallback_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_writer_pick_mode_switch_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_writer_pick_mode_switch_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    /// Publishes the configured resident-memory limit applied to each ME writer.
    pub fn set_me_writer_byte_budget_limit_bytes(&self, bytes: usize) {
        self.me_writer_byte_budget_limit_bytes_gauge
            .store(bytes as u64, Ordering::Relaxed);
    }
    pub(crate) fn add_me_writer_byte_budget_queued_bytes(&self, bytes: u64) {
        self.me_writer_byte_budget_queued_bytes_gauge
            .fetch_add(bytes, Ordering::Relaxed);
    }
    pub(crate) fn move_me_writer_byte_budget_to_inflight(&self, bytes: u64) {
        let _ = self.me_writer_byte_budget_queued_bytes_gauge.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| Some(current.saturating_sub(bytes)),
        );
        self.me_writer_byte_budget_inflight_bytes_gauge
            .fetch_add(bytes, Ordering::Relaxed);
    }
    pub(crate) fn release_me_writer_byte_budget_queued_bytes(&self, bytes: u64) {
        let _ = self.me_writer_byte_budget_queued_bytes_gauge.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| Some(current.saturating_sub(bytes)),
        );
    }
    pub(crate) fn release_me_writer_byte_budget_inflight_bytes(&self, bytes: u64) {
        let _ = self
            .me_writer_byte_budget_inflight_bytes_gauge
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(bytes))
            });
    }
    pub(crate) fn increment_me_writer_byte_budget_wait_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_writer_byte_budget_wait_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub(crate) fn increment_me_writer_byte_budget_timeout_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_writer_byte_budget_timeout_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub(crate) fn increment_me_writer_byte_budget_oversize_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_writer_byte_budget_oversize_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_socks_kdf_strict_reject(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_socks_kdf_strict_reject
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_socks_kdf_compat_fallback(&self) {
        if self.telemetry_me_allows_debug() {
            self.me_socks_kdf_compat_fallback
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_secure_padding_invalid(&self) {
        if self.telemetry_me_allows_normal() {
            self.secure_padding_invalid.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_desync_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.desync_total.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_desync_full_logged(&self) {
        if self.telemetry_me_allows_normal() {
            self.desync_full_logged.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_desync_suppressed(&self) {
        if self.telemetry_me_allows_normal() {
            self.desync_suppressed.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn observe_desync_frames_ok(&self, frames_ok: u64) {
        if !self.telemetry_me_allows_normal() {
            return;
        }
        match frames_ok {
            0 => {
                self.desync_frames_bucket_0.fetch_add(1, Ordering::Relaxed);
            }
            1..=2 => {
                self.desync_frames_bucket_1_2
                    .fetch_add(1, Ordering::Relaxed);
            }
            3..=10 => {
                self.desync_frames_bucket_3_10
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.desync_frames_bucket_gt_10
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn increment_pool_swap_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.pool_swap_total.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_pool_drain_active(&self) {
        if self.telemetry_me_allows_debug() {
            self.pool_drain_active.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn decrement_pool_drain_active(&self) {
        if !self.telemetry_me_allows_debug() {
            return;
        }
        let mut current = self.pool_drain_active.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                break;
            }
            match self.pool_drain_active.compare_exchange_weak(
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
    pub fn increment_pool_force_close_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.pool_force_close_total.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_pool_stale_pick_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.pool_stale_pick_total.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_writer_removed_total(&self) {
        if self.telemetry_me_allows_debug() {
            self.me_writer_removed_total.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_writer_removed_unexpected_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_writer_removed_unexpected_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_refill_triggered_total(&self) {
        if self.telemetry_me_allows_debug() {
            self.me_refill_triggered_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_refill_skipped_inflight_total(&self) {
        if self.telemetry_me_allows_debug() {
            self.me_refill_skipped_inflight_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_refill_failed_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_refill_failed_total.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_writer_restored_same_endpoint_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_writer_restored_same_endpoint_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_writer_restored_fallback_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_writer_restored_fallback_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_no_writer_failfast_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_no_writer_failfast_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_hybrid_timeout_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_hybrid_timeout_total.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_async_recovery_trigger_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_async_recovery_trigger_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_inline_recovery_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_inline_recovery_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_ip_reservation_rollback_tcp_limit_total(&self) {
        if self.telemetry_core_enabled() {
            self.ip_reservation_rollback_tcp_limit_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_ip_reservation_rollback_quota_limit_total(&self) {
        if self.telemetry_core_enabled() {
            self.ip_reservation_rollback_quota_limit_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn add_quota_refund_bytes_total(&self, bytes: u64) {
        if self.telemetry_core_enabled() {
            self.quota_refund_bytes_total
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }
    pub fn increment_quota_contention_total(&self) {
        if self.telemetry_core_enabled() {
            self.quota_contention_total.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_quota_contention_timeout_total(&self) {
        if self.telemetry_core_enabled() {
            self.quota_contention_timeout_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_quota_acquire_cancelled_total(&self) {
        if self.telemetry_core_enabled() {
            self.quota_acquire_cancelled_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn add_quota_write_fail_bytes_total(&self, bytes: u64) {
        if self.telemetry_core_enabled() {
            self.quota_write_fail_bytes_total
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }
    pub fn increment_quota_write_fail_events_total(&self) {
        if self.telemetry_core_enabled() {
            self.quota_write_fail_events_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_child_join_timeout_total(&self) {
        if self.telemetry_core_enabled() {
            self.me_child_join_timeout_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_child_abort_total(&self) {
        if self.telemetry_core_enabled() {
            self.me_child_abort_total.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn observe_flow_wait_middle_rate_limit_ms(&self, wait_ms: u64) {
        if self.telemetry_core_enabled() {
            self.flow_wait_middle_rate_limit_total
                .fetch_add(1, Ordering::Relaxed);
            self.flow_wait_middle_rate_limit_ms_total
                .fetch_add(wait_ms, Ordering::Relaxed);
        }
    }
    pub fn increment_flow_wait_middle_rate_limit_cancelled_total(&self) {
        if self.telemetry_core_enabled() {
            self.flow_wait_middle_rate_limit_cancelled_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_session_drop_fallback_total(&self) {
        if self.telemetry_core_enabled() {
            self.session_drop_fallback_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_endpoint_quarantine_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_endpoint_quarantine_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_endpoint_quarantine_unexpected_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_endpoint_quarantine_unexpected_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_endpoint_quarantine_draining_suppressed_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_endpoint_quarantine_draining_suppressed_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_kdf_drift_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_kdf_drift_total.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_kdf_port_only_drift_total(&self) {
        if self.telemetry_me_allows_debug() {
            self.me_kdf_port_only_drift_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_hardswap_pending_reuse_total(&self) {
        if self.telemetry_me_allows_debug() {
            self.me_hardswap_pending_reuse_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_hardswap_pending_ttl_expired_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_hardswap_pending_ttl_expired_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_single_endpoint_outage_enter_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_single_endpoint_outage_enter_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_single_endpoint_outage_exit_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_single_endpoint_outage_exit_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_single_endpoint_outage_reconnect_attempt_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_single_endpoint_outage_reconnect_attempt_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_single_endpoint_outage_reconnect_success_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_single_endpoint_outage_reconnect_success_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_single_endpoint_quarantine_bypass_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_single_endpoint_quarantine_bypass_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_single_endpoint_shadow_rotate_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_single_endpoint_shadow_rotate_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_single_endpoint_shadow_rotate_skipped_quarantine_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_single_endpoint_shadow_rotate_skipped_quarantine_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_floor_mode_switch_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_floor_mode_switch_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_floor_mode_switch_static_to_adaptive_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_floor_mode_switch_static_to_adaptive_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_floor_mode_switch_adaptive_to_static_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_floor_mode_switch_adaptive_to_static_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn set_me_floor_cpu_cores_detected_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_floor_cpu_cores_detected_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_floor_cpu_cores_effective_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_floor_cpu_cores_effective_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_floor_global_cap_raw_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_floor_global_cap_raw_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_floor_global_cap_effective_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_floor_global_cap_effective_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_floor_target_writers_total_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_floor_target_writers_total_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_floor_active_cap_configured_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_floor_active_cap_configured_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_floor_active_cap_effective_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_floor_active_cap_effective_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_floor_warm_cap_configured_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_floor_warm_cap_configured_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_floor_warm_cap_effective_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_floor_warm_cap_effective_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_writers_active_current_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_writers_active_current_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_writers_warm_current_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_writers_warm_current_gauge
                .store(value, Ordering::Relaxed);
        }
    }

    pub fn set_buffer_pool_gauges(&self, pooled: usize, allocated: usize, in_use: usize) {
        if self.telemetry_me_allows_normal() {
            self.buffer_pool_pooled_gauge
                .store(pooled as u64, Ordering::Relaxed);
            self.buffer_pool_allocated_gauge
                .store(allocated as u64, Ordering::Relaxed);
            self.buffer_pool_in_use_gauge
                .store(in_use as u64, Ordering::Relaxed);
        }
    }

    /// Publishes the cumulative count of non-standard pool buffer replacements.
    pub fn set_buffer_pool_replaced_nonstandard_total(&self, value: usize) {
        if self.telemetry_me_allows_normal() {
            self.buffer_pool_replaced_nonstandard_total
                .store(value as u64, Ordering::Relaxed);
        }
    }

    pub fn increment_me_c2me_send_full_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_c2me_send_full_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn increment_me_c2me_send_high_water_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_c2me_send_high_water_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn increment_me_c2me_send_timeout_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_c2me_send_timeout_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_floor_cap_block_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_floor_cap_block_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_floor_swap_idle_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_floor_swap_idle_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_floor_swap_idle_failed_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_floor_swap_idle_failed_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}
