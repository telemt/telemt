//! Statistics and replay protection

#![allow(dead_code)]

pub mod beobachten;
mod core_counters;
mod core_getters;
mod helpers;
mod me_counters;
mod me_getters;
mod replay;
pub mod telemetry;
pub mod tls_fingerprints;
mod users;
mod writer_counters;

use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Instant;

#[allow(unused_imports)]
pub use self::replay::{ReplayChecker, ReplayStats};
use self::telemetry::TelemetryPolicy;
pub use self::tls_fingerprints::TlsFingerprintSnapshotRow;
use crate::config::MeWriterPickMode;

#[derive(Clone, Copy)]
enum RouteConnectionGauge {
    Direct,
    Middle,
}

#[derive(Clone, Copy)]
enum RouteCutoverParkGauge {
    Direct,
    Middle,
}

#[derive(Debug, Clone, Copy)]
pub enum MeD2cFlushReason {
    QueueDrain,
    BatchFrames,
    BatchBytes,
    MaxDelay,
    AckImmediate,
    Close,
}

#[derive(Debug, Clone, Copy)]
pub enum MeD2cWriteMode {
    Coalesced,
    Split,
}

#[derive(Debug, Clone, Copy)]
pub enum MeD2cQuotaRejectStage {
    PreWrite,
    PostWrite,
}

#[must_use = "RouteConnectionLease must be kept alive to hold the connection gauge increment"]
pub struct RouteConnectionLease {
    stats: Arc<Stats>,
    gauge: RouteConnectionGauge,
    active: bool,
}

#[must_use = "RouteCutoverParkLease must be kept alive while a route cutover is parked"]
pub struct RouteCutoverParkLease {
    stats: Arc<Stats>,
    gauge: RouteCutoverParkGauge,
    active: bool,
}

impl RouteConnectionLease {
    fn new(stats: Arc<Stats>, gauge: RouteConnectionGauge) -> Self {
        Self {
            stats,
            gauge,
            active: true,
        }
    }

    #[cfg(test)]
    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for RouteConnectionLease {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        match self.gauge {
            RouteConnectionGauge::Direct => self.stats.decrement_current_connections_direct(),
            RouteConnectionGauge::Middle => self.stats.decrement_current_connections_me(),
        }
    }
}

impl RouteCutoverParkLease {
    fn new(stats: Arc<Stats>, gauge: RouteCutoverParkGauge) -> Self {
        Self {
            stats,
            gauge,
            active: true,
        }
    }
}

impl Drop for RouteCutoverParkLease {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        match self.gauge {
            RouteCutoverParkGauge::Direct => self.stats.decrement_route_cutover_parked_direct(),
            RouteCutoverParkGauge::Middle => self.stats.decrement_route_cutover_parked_middle(),
        }
    }
}

// ============= Stats =============

#[derive(Default)]
pub struct Stats {
    connects_all: AtomicU64,
    connects_bad: AtomicU64,
    connects_bad_classes: DashMap<&'static str, AtomicU64>,
    handshake_failure_classes: DashMap<&'static str, AtomicU64>,
    current_connections_direct: AtomicU64,
    current_connections_me: AtomicU64,
    route_cutover_parked_direct_current: AtomicU64,
    route_cutover_parked_middle_current: AtomicU64,
    route_cutover_parked_direct_total: AtomicU64,
    route_cutover_parked_middle_total: AtomicU64,
    handshake_timeouts: AtomicU64,
    accept_permit_timeout_total: AtomicU64,
    conntrack_control_enabled_gauge: AtomicBool,
    conntrack_control_available_gauge: AtomicBool,
    conntrack_pressure_active_gauge: AtomicBool,
    conntrack_event_queue_depth_gauge: AtomicU64,
    conntrack_rule_apply_ok_gauge: AtomicBool,
    conntrack_delete_attempt_total: AtomicU64,
    conntrack_delete_success_total: AtomicU64,
    conntrack_delete_not_found_total: AtomicU64,
    conntrack_delete_error_total: AtomicU64,
    conntrack_close_event_drop_total: AtomicU64,
    upstream_connect_attempt_total: AtomicU64,
    upstream_connect_success_total: AtomicU64,
    upstream_connect_fail_total: AtomicU64,
    upstream_connect_failfast_hard_error_total: AtomicU64,
    upstream_connect_attempts_bucket_1: AtomicU64,
    upstream_connect_attempts_bucket_2: AtomicU64,
    upstream_connect_attempts_bucket_3_4: AtomicU64,
    upstream_connect_attempts_bucket_gt_4: AtomicU64,
    upstream_connect_duration_success_bucket_le_100ms: AtomicU64,
    upstream_connect_duration_success_bucket_101_500ms: AtomicU64,
    upstream_connect_duration_success_bucket_501_1000ms: AtomicU64,
    upstream_connect_duration_success_bucket_gt_1000ms: AtomicU64,
    upstream_connect_duration_fail_bucket_le_100ms: AtomicU64,
    upstream_connect_duration_fail_bucket_101_500ms: AtomicU64,
    upstream_connect_duration_fail_bucket_501_1000ms: AtomicU64,
    upstream_connect_duration_fail_bucket_gt_1000ms: AtomicU64,
    me_keepalive_sent: AtomicU64,
    me_keepalive_failed: AtomicU64,
    me_keepalive_pong: AtomicU64,
    me_keepalive_timeout: AtomicU64,
    me_rpc_proxy_req_signal_sent_total: AtomicU64,
    me_rpc_proxy_req_signal_failed_total: AtomicU64,
    me_rpc_proxy_req_signal_skipped_no_meta_total: AtomicU64,
    me_rpc_proxy_req_signal_response_total: AtomicU64,
    me_rpc_proxy_req_signal_close_sent_total: AtomicU64,
    me_reconnect_attempts: AtomicU64,
    me_reconnect_success: AtomicU64,
    me_handshake_reject_total: AtomicU64,
    me_reader_eof_total: AtomicU64,
    me_idle_close_by_peer_total: AtomicU64,
    relay_idle_soft_mark_total: AtomicU64,
    relay_idle_hard_close_total: AtomicU64,
    relay_pressure_evict_total: AtomicU64,
    relay_protocol_desync_close_total: AtomicU64,
    me_crc_mismatch: AtomicU64,
    me_seq_mismatch: AtomicU64,
    me_endpoint_quarantine_total: AtomicU64,
    me_endpoint_quarantine_unexpected_total: AtomicU64,
    me_endpoint_quarantine_draining_suppressed_total: AtomicU64,
    me_kdf_drift_total: AtomicU64,
    me_kdf_port_only_drift_total: AtomicU64,
    me_hardswap_pending_reuse_total: AtomicU64,
    me_hardswap_pending_ttl_expired_total: AtomicU64,
    me_single_endpoint_outage_enter_total: AtomicU64,
    me_single_endpoint_outage_exit_total: AtomicU64,
    me_single_endpoint_outage_reconnect_attempt_total: AtomicU64,
    me_single_endpoint_outage_reconnect_success_total: AtomicU64,
    me_single_endpoint_quarantine_bypass_total: AtomicU64,
    me_single_endpoint_shadow_rotate_total: AtomicU64,
    me_single_endpoint_shadow_rotate_skipped_quarantine_total: AtomicU64,
    me_floor_mode_switch_total: AtomicU64,
    me_floor_mode_switch_static_to_adaptive_total: AtomicU64,
    me_floor_mode_switch_adaptive_to_static_total: AtomicU64,
    me_floor_cpu_cores_detected_gauge: AtomicU64,
    me_floor_cpu_cores_effective_gauge: AtomicU64,
    me_floor_global_cap_raw_gauge: AtomicU64,
    me_floor_global_cap_effective_gauge: AtomicU64,
    me_floor_target_writers_total_gauge: AtomicU64,
    me_floor_active_cap_configured_gauge: AtomicU64,
    me_floor_active_cap_effective_gauge: AtomicU64,
    me_floor_warm_cap_configured_gauge: AtomicU64,
    me_floor_warm_cap_effective_gauge: AtomicU64,
    me_writers_active_current_gauge: AtomicU64,
    me_writers_warm_current_gauge: AtomicU64,
    me_floor_cap_block_total: AtomicU64,
    me_floor_swap_idle_total: AtomicU64,
    me_floor_swap_idle_failed_total: AtomicU64,
    me_handshake_error_codes: DashMap<i32, AtomicU64>,
    me_route_drop_no_conn: AtomicU64,
    me_route_drop_channel_closed: AtomicU64,
    me_route_drop_queue_full: AtomicU64,
    me_route_drop_queue_full_base: AtomicU64,
    me_route_drop_queue_full_high: AtomicU64,
    me_fair_pressure_state_gauge: AtomicU64,
    me_fair_active_flows_gauge: AtomicU64,
    me_fair_queued_bytes_gauge: AtomicU64,
    me_fair_standing_flows_gauge: AtomicU64,
    me_fair_backpressured_flows_gauge: AtomicU64,
    me_fair_scheduler_rounds_total: AtomicU64,
    me_fair_deficit_grants_total: AtomicU64,
    me_fair_deficit_skips_total: AtomicU64,
    me_fair_enqueue_rejects_total: AtomicU64,
    me_fair_shed_drops_total: AtomicU64,
    me_fair_penalties_total: AtomicU64,
    me_fair_downstream_stalls_total: AtomicU64,
    me_d2c_batches_total: AtomicU64,
    me_d2c_batch_frames_total: AtomicU64,
    me_d2c_batch_bytes_total: AtomicU64,
    me_d2c_flush_reason_queue_drain_total: AtomicU64,
    me_d2c_flush_reason_batch_frames_total: AtomicU64,
    me_d2c_flush_reason_batch_bytes_total: AtomicU64,
    me_d2c_flush_reason_max_delay_total: AtomicU64,
    me_d2c_flush_reason_ack_immediate_total: AtomicU64,
    me_d2c_flush_reason_close_total: AtomicU64,
    me_d2c_data_frames_total: AtomicU64,
    me_d2c_ack_frames_total: AtomicU64,
    me_d2c_payload_bytes_total: AtomicU64,
    me_d2c_write_mode_coalesced_total: AtomicU64,
    me_d2c_write_mode_split_total: AtomicU64,
    me_d2c_quota_reject_pre_write_total: AtomicU64,
    me_d2c_quota_reject_post_write_total: AtomicU64,
    me_d2c_frame_buf_shrink_total: AtomicU64,
    me_d2c_frame_buf_shrink_bytes_total: AtomicU64,
    me_d2c_batch_frames_bucket_1: AtomicU64,
    me_d2c_batch_frames_bucket_2_4: AtomicU64,
    me_d2c_batch_frames_bucket_5_8: AtomicU64,
    me_d2c_batch_frames_bucket_9_16: AtomicU64,
    me_d2c_batch_frames_bucket_17_32: AtomicU64,
    me_d2c_batch_frames_bucket_gt_32: AtomicU64,
    me_d2c_batch_bytes_bucket_0_1k: AtomicU64,
    me_d2c_batch_bytes_bucket_1k_4k: AtomicU64,
    me_d2c_batch_bytes_bucket_4k_16k: AtomicU64,
    me_d2c_batch_bytes_bucket_16k_64k: AtomicU64,
    me_d2c_batch_bytes_bucket_64k_128k: AtomicU64,
    me_d2c_batch_bytes_bucket_gt_128k: AtomicU64,
    me_d2c_flush_duration_us_bucket_0_50: AtomicU64,
    me_d2c_flush_duration_us_bucket_51_200: AtomicU64,
    me_d2c_flush_duration_us_bucket_201_1000: AtomicU64,
    me_d2c_flush_duration_us_bucket_1001_5000: AtomicU64,
    me_d2c_flush_duration_us_bucket_5001_20000: AtomicU64,
    me_d2c_flush_duration_us_bucket_gt_20000: AtomicU64,
    // Buffer pool gauges
    buffer_pool_pooled_gauge: AtomicU64,
    buffer_pool_allocated_gauge: AtomicU64,
    buffer_pool_in_use_gauge: AtomicU64,
    buffer_pool_replaced_nonstandard_total: AtomicU64,
    // C2ME enqueue observability
    me_c2me_send_full_total: AtomicU64,
    me_c2me_send_high_water_total: AtomicU64,
    me_c2me_send_timeout_total: AtomicU64,
    me_d2c_batch_timeout_armed_total: AtomicU64,
    me_d2c_batch_timeout_fired_total: AtomicU64,
    me_writer_pick_sorted_rr_success_try_total: AtomicU64,
    me_writer_pick_sorted_rr_success_fallback_total: AtomicU64,
    me_writer_pick_sorted_rr_full_total: AtomicU64,
    me_writer_pick_sorted_rr_closed_total: AtomicU64,
    me_writer_pick_sorted_rr_no_candidate_total: AtomicU64,
    me_writer_pick_p2c_success_try_total: AtomicU64,
    me_writer_pick_p2c_success_fallback_total: AtomicU64,
    me_writer_pick_p2c_full_total: AtomicU64,
    me_writer_pick_p2c_closed_total: AtomicU64,
    me_writer_pick_p2c_no_candidate_total: AtomicU64,
    me_writer_pick_blocking_fallback_total: AtomicU64,
    me_writer_pick_mode_switch_total: AtomicU64,
    me_writer_byte_budget_limit_bytes_gauge: AtomicU64,
    me_writer_byte_budget_queued_bytes_gauge: AtomicU64,
    me_writer_byte_budget_inflight_bytes_gauge: AtomicU64,
    me_writer_byte_budget_wait_total: AtomicU64,
    me_writer_byte_budget_timeout_total: AtomicU64,
    me_writer_byte_budget_oversize_total: AtomicU64,
    me_socks_kdf_strict_reject: AtomicU64,
    me_socks_kdf_compat_fallback: AtomicU64,
    secure_padding_invalid: AtomicU64,
    desync_total: AtomicU64,
    desync_full_logged: AtomicU64,
    desync_suppressed: AtomicU64,
    desync_frames_bucket_0: AtomicU64,
    desync_frames_bucket_1_2: AtomicU64,
    desync_frames_bucket_3_10: AtomicU64,
    desync_frames_bucket_gt_10: AtomicU64,
    pool_swap_total: AtomicU64,
    pool_drain_active: AtomicU64,
    pool_force_close_total: AtomicU64,
    pool_stale_pick_total: AtomicU64,
    me_writer_removed_total: AtomicU64,
    me_writer_removed_unexpected_total: AtomicU64,
    me_refill_triggered_total: AtomicU64,
    me_refill_skipped_inflight_total: AtomicU64,
    me_refill_failed_total: AtomicU64,
    me_writer_restored_same_endpoint_total: AtomicU64,
    me_writer_restored_fallback_total: AtomicU64,
    me_no_writer_failfast_total: AtomicU64,
    me_hybrid_timeout_total: AtomicU64,
    me_async_recovery_trigger_total: AtomicU64,
    me_inline_recovery_total: AtomicU64,
    ip_reservation_rollback_tcp_limit_total: AtomicU64,
    ip_reservation_rollback_quota_limit_total: AtomicU64,
    quota_refund_bytes_total: AtomicU64,
    quota_contention_total: AtomicU64,
    quota_contention_timeout_total: AtomicU64,
    quota_acquire_cancelled_total: AtomicU64,
    quota_write_fail_bytes_total: AtomicU64,
    quota_write_fail_events_total: AtomicU64,
    me_child_join_timeout_total: AtomicU64,
    me_child_abort_total: AtomicU64,
    flow_wait_middle_rate_limit_total: AtomicU64,
    flow_wait_middle_rate_limit_cancelled_total: AtomicU64,
    flow_wait_middle_rate_limit_ms_total: AtomicU64,
    session_drop_fallback_total: AtomicU64,
    telemetry_core_enabled: AtomicBool,
    telemetry_user_enabled: AtomicBool,
    telemetry_me_level: AtomicU8,
    cached_epoch_secs: AtomicU64,
    tls_fingerprints: tls_fingerprints::TlsFingerprintCollector,
    user_stats: DashMap<String, Arc<UserStats>>,
    user_stats_last_cleanup_epoch_secs: AtomicU64,
    start_time: parking_lot::RwLock<Option<Instant>>,
}

#[derive(Default)]
pub struct UserStats {
    pub connects: AtomicU64,
    pub curr_connects: AtomicU64,
    pub octets_from_client: AtomicU64,
    pub octets_to_client: AtomicU64,
    pub msgs_from_client: AtomicU64,
    pub msgs_to_client: AtomicU64,
    /// Total bytes charged against per-user quota admission.
    ///
    /// This counter is the single source of truth for quota enforcement and
    /// intentionally tracks attempted traffic, not guaranteed delivery.
    pub quota_used: AtomicU64,
    pub quota_last_reset_epoch_secs: AtomicU64,
    pub last_seen_epoch_secs: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct UserQuotaSnapshot {
    pub used_bytes: u64,
    pub last_reset_epoch_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaReserveError {
    LimitExceeded,
    Contended,
}

impl UserStats {
    #[inline]
    pub fn quota_used(&self) -> u64 {
        self.quota_used.load(Ordering::Relaxed)
    }

    /// Attempts one CAS reservation step against the quota counter.
    ///
    /// Callers control retry/yield policy. This primitive intentionally does
    /// not block or sleep so both sync poll paths and async paths can wrap it
    /// with their own contention strategy.
    #[inline]
    pub fn quota_try_reserve(&self, bytes: u64, limit: u64) -> Result<u64, QuotaReserveError> {
        let current = self.quota_used.load(Ordering::Relaxed);
        if bytes > limit.saturating_sub(current) {
            return Err(QuotaReserveError::LimitExceeded);
        }

        let next = current.saturating_add(bytes);
        match self.quota_used.compare_exchange_weak(
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

impl Stats {
    pub fn new() -> Self {
        let stats = Self::default();
        stats.apply_telemetry_policy(TelemetryPolicy::default());
        stats.refresh_cached_epoch_secs();
        *stats.start_time.write() = Some(Instant::now());
        stats
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "tests/connection_lease_security_tests.rs"]
mod connection_lease_security_tests;

#[cfg(test)]
#[path = "tests/replay_checker_security_tests.rs"]
mod replay_checker_security_tests;
