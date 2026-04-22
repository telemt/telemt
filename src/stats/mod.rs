//! Statistics and replay protection

#![allow(dead_code)]

pub mod beobachten;
pub mod telemetry;

use dashmap::DashMap;
use lru::LruCache;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::debug;

use self::telemetry::TelemetryPolicy;
use crate::config::{MeTelemetryLevel, MeWriterPickMode};

#[derive(Clone, Copy)]
enum RouteConnectionGauge {
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

// ============= Stats =============

#[derive(Default)]
pub struct Stats {
    connects_all: AtomicU64,
    connects_bad: AtomicU64,
    current_connections_direct: AtomicU64,
    current_connections_me: AtomicU64,
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
    me_admission_configured_dcs_gauge: AtomicU64,
    me_admission_ready_dcs_gauge: AtomicU64,
    me_partial_degradation_active_gauge: AtomicU64,
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
    quota_write_fail_bytes_total: AtomicU64,
    quota_write_fail_events_total: AtomicU64,
    telemetry_core_enabled: AtomicBool,
    telemetry_user_enabled: AtomicBool,
    telemetry_me_level: AtomicU8,
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
    pub last_seen_epoch_secs: AtomicU64,
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
        *stats.start_time.write() = Some(Instant::now());
        stats
    }

    fn telemetry_me_level(&self) -> MeTelemetryLevel {
        MeTelemetryLevel::from_u8(self.telemetry_me_level.load(Ordering::Relaxed))
    }

    fn telemetry_core_enabled(&self) -> bool {
        self.telemetry_core_enabled.load(Ordering::Relaxed)
    }

    fn telemetry_user_enabled(&self) -> bool {
        self.telemetry_user_enabled.load(Ordering::Relaxed)
    }

    fn telemetry_me_allows_normal(&self) -> bool {
        self.telemetry_me_level().allows_normal()
    }

    fn telemetry_me_allows_debug(&self) -> bool {
        self.telemetry_me_level().allows_debug()
    }

    fn decrement_atomic_saturating(counter: &AtomicU64) {
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

    fn now_epoch_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn touch_user_stats(stats: &UserStats) {
        stats
            .last_seen_epoch_secs
            .store(Self::now_epoch_secs(), Ordering::Relaxed);
    }

    pub(crate) fn get_or_create_user_stats_handle(&self, user: &str) -> Arc<UserStats> {
        self.maybe_cleanup_user_stats();
        if let Some(existing) = self.user_stats.get(user) {
            let handle = Arc::clone(existing.value());
            Self::touch_user_stats(handle.as_ref());
            return handle;
        }

        let entry = self.user_stats.entry(user.to_string()).or_default();
        if entry.last_seen_epoch_secs.load(Ordering::Relaxed) == 0 {
            Self::touch_user_stats(entry.value().as_ref());
        }
        Arc::clone(entry.value())
    }

    #[inline]
    pub(crate) fn add_user_octets_from_handle(&self, user_stats: &UserStats, bytes: u64) {
        if !self.telemetry_user_enabled() {
            return;
        }
        Self::touch_user_stats(user_stats);
        user_stats
            .octets_from_client
            .fetch_add(bytes, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn add_user_octets_to_handle(&self, user_stats: &UserStats, bytes: u64) {
        if !self.telemetry_user_enabled() {
            return;
        }
        Self::touch_user_stats(user_stats);
        user_stats
            .octets_to_client
            .fetch_add(bytes, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn increment_user_msgs_from_handle(&self, user_stats: &UserStats) {
        if !self.telemetry_user_enabled() {
            return;
        }
        Self::touch_user_stats(user_stats);
        user_stats.msgs_from_client.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn increment_user_msgs_to_handle(&self, user_stats: &UserStats) {
        if !self.telemetry_user_enabled() {
            return;
        }
        Self::touch_user_stats(user_stats);
        user_stats.msgs_to_client.fetch_add(1, Ordering::Relaxed);
    }

    /// Charges already committed bytes in a post-I/O path.
    ///
    /// This helper is intentionally separate from `quota_try_reserve` to avoid
    /// mixing reserve and post-charge on a single I/O event.
    #[inline]
    pub(crate) fn quota_charge_post_write(&self, user_stats: &UserStats, bytes: u64) -> u64 {
        Self::touch_user_stats(user_stats);
        user_stats
            .quota_used
            .fetch_add(bytes, Ordering::Relaxed)
            .saturating_add(bytes)
    }

    fn maybe_cleanup_user_stats(&self) {
        const USER_STATS_CLEANUP_INTERVAL_SECS: u64 = 60;
        const USER_STATS_IDLE_TTL_SECS: u64 = 24 * 60 * 60;

        let now_epoch_secs = Self::now_epoch_secs();
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
    pub fn increment_connects_bad(&self) {
        if self.telemetry_core_enabled() {
            self.connects_bad.fetch_add(1, Ordering::Relaxed);
        }
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
    pub fn increment_me_keepalive_sent(&self) {
        if self.telemetry_me_allows_debug() {
            self.me_keepalive_sent.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_keepalive_failed(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_keepalive_failed.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_keepalive_pong(&self) {
        if self.telemetry_me_allows_debug() {
            self.me_keepalive_pong.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_keepalive_timeout(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_keepalive_timeout.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_keepalive_timeout_by(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_keepalive_timeout
                .fetch_add(value, Ordering::Relaxed);
        }
    }
    pub fn increment_me_rpc_proxy_req_signal_sent_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_rpc_proxy_req_signal_sent_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_rpc_proxy_req_signal_failed_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_rpc_proxy_req_signal_failed_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_rpc_proxy_req_signal_skipped_no_meta_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_rpc_proxy_req_signal_skipped_no_meta_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_rpc_proxy_req_signal_response_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_rpc_proxy_req_signal_response_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_rpc_proxy_req_signal_close_sent_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_rpc_proxy_req_signal_close_sent_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_reconnect_attempt(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_reconnect_attempts.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_reconnect_success(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_reconnect_success.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_handshake_reject_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_handshake_reject_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_handshake_error_code(&self, code: i32) {
        if !self.telemetry_me_allows_normal() {
            return;
        }
        let entry = self
            .me_handshake_error_codes
            .entry(code)
            .or_insert_with(|| AtomicU64::new(0));
        entry.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_me_reader_eof_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_reader_eof_total.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_idle_close_by_peer_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_idle_close_by_peer_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_relay_idle_soft_mark_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.relay_idle_soft_mark_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_relay_idle_hard_close_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.relay_idle_hard_close_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_relay_pressure_evict_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.relay_pressure_evict_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_relay_protocol_desync_close_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.relay_protocol_desync_close_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_crc_mismatch(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_crc_mismatch.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_seq_mismatch(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_seq_mismatch.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_route_drop_no_conn(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_route_drop_no_conn.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_route_drop_channel_closed(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_route_drop_channel_closed
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_route_drop_queue_full(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_route_drop_queue_full
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_route_drop_queue_full_base(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_route_drop_queue_full_base
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_route_drop_queue_full_high(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_route_drop_queue_full_high
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn set_me_fair_pressure_state_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_fair_pressure_state_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_fair_active_flows_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_fair_active_flows_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_fair_queued_bytes_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_fair_queued_bytes_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_fair_standing_flows_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_fair_standing_flows_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_fair_backpressured_flows_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_fair_backpressured_flows_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn add_me_fair_scheduler_rounds_total(&self, value: u64) {
        if self.telemetry_me_allows_normal() && value > 0 {
            self.me_fair_scheduler_rounds_total
                .fetch_add(value, Ordering::Relaxed);
        }
    }
    pub fn add_me_fair_deficit_grants_total(&self, value: u64) {
        if self.telemetry_me_allows_normal() && value > 0 {
            self.me_fair_deficit_grants_total
                .fetch_add(value, Ordering::Relaxed);
        }
    }
    pub fn add_me_fair_deficit_skips_total(&self, value: u64) {
        if self.telemetry_me_allows_normal() && value > 0 {
            self.me_fair_deficit_skips_total
                .fetch_add(value, Ordering::Relaxed);
        }
    }
    pub fn add_me_fair_enqueue_rejects_total(&self, value: u64) {
        if self.telemetry_me_allows_normal() && value > 0 {
            self.me_fair_enqueue_rejects_total
                .fetch_add(value, Ordering::Relaxed);
        }
    }
    pub fn add_me_fair_shed_drops_total(&self, value: u64) {
        if self.telemetry_me_allows_normal() && value > 0 {
            self.me_fair_shed_drops_total
                .fetch_add(value, Ordering::Relaxed);
        }
    }
    pub fn add_me_fair_penalties_total(&self, value: u64) {
        if self.telemetry_me_allows_normal() && value > 0 {
            self.me_fair_penalties_total
                .fetch_add(value, Ordering::Relaxed);
        }
    }
    pub fn add_me_fair_downstream_stalls_total(&self, value: u64) {
        if self.telemetry_me_allows_normal() && value > 0 {
            self.me_fair_downstream_stalls_total
                .fetch_add(value, Ordering::Relaxed);
        }
    }
    pub fn increment_me_d2c_batches_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_d2c_batches_total.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn add_me_d2c_batch_frames_total(&self, frames: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_d2c_batch_frames_total
                .fetch_add(frames, Ordering::Relaxed);
        }
    }
    pub fn add_me_d2c_batch_bytes_total(&self, bytes: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_d2c_batch_bytes_total
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }
    pub fn increment_me_d2c_flush_reason(&self, reason: MeD2cFlushReason) {
        if !self.telemetry_me_allows_normal() {
            return;
        }
        match reason {
            MeD2cFlushReason::QueueDrain => {
                self.me_d2c_flush_reason_queue_drain_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            MeD2cFlushReason::BatchFrames => {
                self.me_d2c_flush_reason_batch_frames_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            MeD2cFlushReason::BatchBytes => {
                self.me_d2c_flush_reason_batch_bytes_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            MeD2cFlushReason::MaxDelay => {
                self.me_d2c_flush_reason_max_delay_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            MeD2cFlushReason::AckImmediate => {
                self.me_d2c_flush_reason_ack_immediate_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            MeD2cFlushReason::Close => {
                self.me_d2c_flush_reason_close_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn increment_me_d2c_data_frames_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_d2c_data_frames_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_d2c_ack_frames_total(&self) {
        if self.telemetry_me_allows_normal() {
            self.me_d2c_ack_frames_total.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn add_me_d2c_payload_bytes_total(&self, bytes: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_d2c_payload_bytes_total
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }
    pub fn increment_me_d2c_write_mode(&self, mode: MeD2cWriteMode) {
        if !self.telemetry_me_allows_normal() {
            return;
        }
        match mode {
            MeD2cWriteMode::Coalesced => {
                self.me_d2c_write_mode_coalesced_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            MeD2cWriteMode::Split => {
                self.me_d2c_write_mode_split_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn increment_me_d2c_quota_reject_total(&self, stage: MeD2cQuotaRejectStage) {
        if !self.telemetry_me_allows_normal() {
            return;
        }
        match stage {
            MeD2cQuotaRejectStage::PreWrite => {
                self.me_d2c_quota_reject_pre_write_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            MeD2cQuotaRejectStage::PostWrite => {
                self.me_d2c_quota_reject_post_write_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn observe_me_d2c_frame_buf_shrink(&self, bytes_freed: u64) {
        if !self.telemetry_me_allows_normal() {
            return;
        }
        self.me_d2c_frame_buf_shrink_total
            .fetch_add(1, Ordering::Relaxed);
        self.me_d2c_frame_buf_shrink_bytes_total
            .fetch_add(bytes_freed, Ordering::Relaxed);
    }
    pub fn observe_me_d2c_batch_frames(&self, frames: u64) {
        if !self.telemetry_me_allows_debug() {
            return;
        }
        match frames {
            0 => {}
            1 => {
                self.me_d2c_batch_frames_bucket_1
                    .fetch_add(1, Ordering::Relaxed);
            }
            2..=4 => {
                self.me_d2c_batch_frames_bucket_2_4
                    .fetch_add(1, Ordering::Relaxed);
            }
            5..=8 => {
                self.me_d2c_batch_frames_bucket_5_8
                    .fetch_add(1, Ordering::Relaxed);
            }
            9..=16 => {
                self.me_d2c_batch_frames_bucket_9_16
                    .fetch_add(1, Ordering::Relaxed);
            }
            17..=32 => {
                self.me_d2c_batch_frames_bucket_17_32
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.me_d2c_batch_frames_bucket_gt_32
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn observe_me_d2c_batch_bytes(&self, bytes: u64) {
        if !self.telemetry_me_allows_debug() {
            return;
        }
        match bytes {
            0..=1024 => {
                self.me_d2c_batch_bytes_bucket_0_1k
                    .fetch_add(1, Ordering::Relaxed);
            }
            1025..=4096 => {
                self.me_d2c_batch_bytes_bucket_1k_4k
                    .fetch_add(1, Ordering::Relaxed);
            }
            4097..=16_384 => {
                self.me_d2c_batch_bytes_bucket_4k_16k
                    .fetch_add(1, Ordering::Relaxed);
            }
            16_385..=65_536 => {
                self.me_d2c_batch_bytes_bucket_16k_64k
                    .fetch_add(1, Ordering::Relaxed);
            }
            65_537..=131_072 => {
                self.me_d2c_batch_bytes_bucket_64k_128k
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.me_d2c_batch_bytes_bucket_gt_128k
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn observe_me_d2c_flush_duration_us(&self, duration_us: u64) {
        if !self.telemetry_me_allows_debug() {
            return;
        }
        match duration_us {
            0..=50 => {
                self.me_d2c_flush_duration_us_bucket_0_50
                    .fetch_add(1, Ordering::Relaxed);
            }
            51..=200 => {
                self.me_d2c_flush_duration_us_bucket_51_200
                    .fetch_add(1, Ordering::Relaxed);
            }
            201..=1000 => {
                self.me_d2c_flush_duration_us_bucket_201_1000
                    .fetch_add(1, Ordering::Relaxed);
            }
            1001..=5000 => {
                self.me_d2c_flush_duration_us_bucket_1001_5000
                    .fetch_add(1, Ordering::Relaxed);
            }
            5001..=20_000 => {
                self.me_d2c_flush_duration_us_bucket_5001_20000
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.me_d2c_flush_duration_us_bucket_gt_20000
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn increment_me_d2c_batch_timeout_armed_total(&self) {
        if self.telemetry_me_allows_debug() {
            self.me_d2c_batch_timeout_armed_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn increment_me_d2c_batch_timeout_fired_total(&self) {
        if self.telemetry_me_allows_debug() {
            self.me_d2c_batch_timeout_fired_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
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
    pub fn set_me_admission_configured_dcs_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_admission_configured_dcs_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_admission_ready_dcs_gauge(&self, value: u64) {
        if self.telemetry_me_allows_normal() {
            self.me_admission_ready_dcs_gauge
                .store(value, Ordering::Relaxed);
        }
    }
    pub fn set_me_partial_degradation_active_gauge(&self, value: bool) {
        if self.telemetry_me_allows_normal() {
            self.me_partial_degradation_active_gauge
                .store(u64::from(value), Ordering::Relaxed);
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
    pub fn get_connects_all(&self) -> u64 {
        self.connects_all.load(Ordering::Relaxed)
    }
    pub fn get_connects_bad(&self) -> u64 {
        self.connects_bad.load(Ordering::Relaxed)
    }
    pub fn get_accept_permit_timeout_total(&self) -> u64 {
        self.accept_permit_timeout_total.load(Ordering::Relaxed)
    }
    pub fn get_current_connections_direct(&self) -> u64 {
        self.current_connections_direct.load(Ordering::Relaxed)
    }
    pub fn get_current_connections_me(&self) -> u64 {
        self.current_connections_me.load(Ordering::Relaxed)
    }
    pub fn get_current_connections_total(&self) -> u64 {
        self.get_current_connections_direct()
            .saturating_add(self.get_current_connections_me())
    }
    pub fn get_conntrack_control_enabled(&self) -> bool {
        self.conntrack_control_enabled_gauge.load(Ordering::Relaxed)
    }
    pub fn get_conntrack_control_available(&self) -> bool {
        self.conntrack_control_available_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_conntrack_pressure_active(&self) -> bool {
        self.conntrack_pressure_active_gauge.load(Ordering::Relaxed)
    }
    pub fn get_conntrack_event_queue_depth(&self) -> u64 {
        self.conntrack_event_queue_depth_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_conntrack_rule_apply_ok(&self) -> bool {
        self.conntrack_rule_apply_ok_gauge.load(Ordering::Relaxed)
    }
    pub fn get_conntrack_delete_attempt_total(&self) -> u64 {
        self.conntrack_delete_attempt_total.load(Ordering::Relaxed)
    }
    pub fn get_conntrack_delete_success_total(&self) -> u64 {
        self.conntrack_delete_success_total.load(Ordering::Relaxed)
    }
    pub fn get_conntrack_delete_not_found_total(&self) -> u64 {
        self.conntrack_delete_not_found_total
            .load(Ordering::Relaxed)
    }
    pub fn get_conntrack_delete_error_total(&self) -> u64 {
        self.conntrack_delete_error_total.load(Ordering::Relaxed)
    }
    pub fn get_conntrack_close_event_drop_total(&self) -> u64 {
        self.conntrack_close_event_drop_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_keepalive_sent(&self) -> u64 {
        self.me_keepalive_sent.load(Ordering::Relaxed)
    }
    pub fn get_me_keepalive_failed(&self) -> u64 {
        self.me_keepalive_failed.load(Ordering::Relaxed)
    }
    pub fn get_me_keepalive_pong(&self) -> u64 {
        self.me_keepalive_pong.load(Ordering::Relaxed)
    }
    pub fn get_me_keepalive_timeout(&self) -> u64 {
        self.me_keepalive_timeout.load(Ordering::Relaxed)
    }
    pub fn get_me_rpc_proxy_req_signal_sent_total(&self) -> u64 {
        self.me_rpc_proxy_req_signal_sent_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_rpc_proxy_req_signal_failed_total(&self) -> u64 {
        self.me_rpc_proxy_req_signal_failed_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_rpc_proxy_req_signal_skipped_no_meta_total(&self) -> u64 {
        self.me_rpc_proxy_req_signal_skipped_no_meta_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_rpc_proxy_req_signal_response_total(&self) -> u64 {
        self.me_rpc_proxy_req_signal_response_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_rpc_proxy_req_signal_close_sent_total(&self) -> u64 {
        self.me_rpc_proxy_req_signal_close_sent_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_reconnect_attempts(&self) -> u64 {
        self.me_reconnect_attempts.load(Ordering::Relaxed)
    }
    pub fn get_me_reconnect_success(&self) -> u64 {
        self.me_reconnect_success.load(Ordering::Relaxed)
    }
    pub fn get_me_handshake_reject_total(&self) -> u64 {
        self.me_handshake_reject_total.load(Ordering::Relaxed)
    }
    pub fn get_me_reader_eof_total(&self) -> u64 {
        self.me_reader_eof_total.load(Ordering::Relaxed)
    }
    pub fn get_me_idle_close_by_peer_total(&self) -> u64 {
        self.me_idle_close_by_peer_total.load(Ordering::Relaxed)
    }
    pub fn get_relay_idle_soft_mark_total(&self) -> u64 {
        self.relay_idle_soft_mark_total.load(Ordering::Relaxed)
    }
    pub fn get_relay_idle_hard_close_total(&self) -> u64 {
        self.relay_idle_hard_close_total.load(Ordering::Relaxed)
    }
    pub fn get_relay_pressure_evict_total(&self) -> u64 {
        self.relay_pressure_evict_total.load(Ordering::Relaxed)
    }
    pub fn get_relay_protocol_desync_close_total(&self) -> u64 {
        self.relay_protocol_desync_close_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_crc_mismatch(&self) -> u64 {
        self.me_crc_mismatch.load(Ordering::Relaxed)
    }
    pub fn get_me_seq_mismatch(&self) -> u64 {
        self.me_seq_mismatch.load(Ordering::Relaxed)
    }
    pub fn get_me_endpoint_quarantine_total(&self) -> u64 {
        self.me_endpoint_quarantine_total.load(Ordering::Relaxed)
    }
    pub fn get_me_endpoint_quarantine_unexpected_total(&self) -> u64 {
        self.me_endpoint_quarantine_unexpected_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_endpoint_quarantine_draining_suppressed_total(&self) -> u64 {
        self.me_endpoint_quarantine_draining_suppressed_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_kdf_drift_total(&self) -> u64 {
        self.me_kdf_drift_total.load(Ordering::Relaxed)
    }
    pub fn get_me_kdf_port_only_drift_total(&self) -> u64 {
        self.me_kdf_port_only_drift_total.load(Ordering::Relaxed)
    }
    pub fn get_me_hardswap_pending_reuse_total(&self) -> u64 {
        self.me_hardswap_pending_reuse_total.load(Ordering::Relaxed)
    }
    pub fn get_me_hardswap_pending_ttl_expired_total(&self) -> u64 {
        self.me_hardswap_pending_ttl_expired_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_single_endpoint_outage_enter_total(&self) -> u64 {
        self.me_single_endpoint_outage_enter_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_single_endpoint_outage_exit_total(&self) -> u64 {
        self.me_single_endpoint_outage_exit_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_single_endpoint_outage_reconnect_attempt_total(&self) -> u64 {
        self.me_single_endpoint_outage_reconnect_attempt_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_single_endpoint_outage_reconnect_success_total(&self) -> u64 {
        self.me_single_endpoint_outage_reconnect_success_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_single_endpoint_quarantine_bypass_total(&self) -> u64 {
        self.me_single_endpoint_quarantine_bypass_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_single_endpoint_shadow_rotate_total(&self) -> u64 {
        self.me_single_endpoint_shadow_rotate_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_single_endpoint_shadow_rotate_skipped_quarantine_total(&self) -> u64 {
        self.me_single_endpoint_shadow_rotate_skipped_quarantine_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_mode_switch_total(&self) -> u64 {
        self.me_floor_mode_switch_total.load(Ordering::Relaxed)
    }
    pub fn get_me_floor_mode_switch_static_to_adaptive_total(&self) -> u64 {
        self.me_floor_mode_switch_static_to_adaptive_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_mode_switch_adaptive_to_static_total(&self) -> u64 {
        self.me_floor_mode_switch_adaptive_to_static_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_cpu_cores_detected_gauge(&self) -> u64 {
        self.me_floor_cpu_cores_detected_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_cpu_cores_effective_gauge(&self) -> u64 {
        self.me_floor_cpu_cores_effective_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_global_cap_raw_gauge(&self) -> u64 {
        self.me_floor_global_cap_raw_gauge.load(Ordering::Relaxed)
    }
    pub fn get_me_floor_global_cap_effective_gauge(&self) -> u64 {
        self.me_floor_global_cap_effective_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_target_writers_total_gauge(&self) -> u64 {
        self.me_floor_target_writers_total_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_active_cap_configured_gauge(&self) -> u64 {
        self.me_floor_active_cap_configured_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_active_cap_effective_gauge(&self) -> u64 {
        self.me_floor_active_cap_effective_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_warm_cap_configured_gauge(&self) -> u64 {
        self.me_floor_warm_cap_configured_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_warm_cap_effective_gauge(&self) -> u64 {
        self.me_floor_warm_cap_effective_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writers_active_current_gauge(&self) -> u64 {
        self.me_writers_active_current_gauge.load(Ordering::Relaxed)
    }
    pub fn get_me_writers_warm_current_gauge(&self) -> u64 {
        self.me_writers_warm_current_gauge.load(Ordering::Relaxed)
    }
    pub fn get_me_admission_configured_dcs_gauge(&self) -> u64 {
        self.me_admission_configured_dcs_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_admission_ready_dcs_gauge(&self) -> u64 {
        self.me_admission_ready_dcs_gauge.load(Ordering::Relaxed)
    }
    pub fn get_me_partial_degradation_active_gauge(&self) -> u64 {
        self.me_partial_degradation_active_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_floor_cap_block_total(&self) -> u64 {
        self.me_floor_cap_block_total.load(Ordering::Relaxed)
    }
    pub fn get_me_floor_swap_idle_total(&self) -> u64 {
        self.me_floor_swap_idle_total.load(Ordering::Relaxed)
    }
    pub fn get_me_floor_swap_idle_failed_total(&self) -> u64 {
        self.me_floor_swap_idle_failed_total.load(Ordering::Relaxed)
    }
    pub fn get_me_handshake_error_code_counts(&self) -> Vec<(i32, u64)> {
        let mut out: Vec<(i32, u64)> = self
            .me_handshake_error_codes
            .iter()
            .map(|entry| (*entry.key(), entry.value().load(Ordering::Relaxed)))
            .collect();
        out.sort_by_key(|(code, _)| *code);
        out
    }
    pub fn get_me_route_drop_no_conn(&self) -> u64 {
        self.me_route_drop_no_conn.load(Ordering::Relaxed)
    }
    pub fn get_me_route_drop_channel_closed(&self) -> u64 {
        self.me_route_drop_channel_closed.load(Ordering::Relaxed)
    }
    pub fn get_me_route_drop_queue_full(&self) -> u64 {
        self.me_route_drop_queue_full.load(Ordering::Relaxed)
    }
    pub fn get_me_route_drop_queue_full_base(&self) -> u64 {
        self.me_route_drop_queue_full_base.load(Ordering::Relaxed)
    }
    pub fn get_me_route_drop_queue_full_high(&self) -> u64 {
        self.me_route_drop_queue_full_high.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_pressure_state_gauge(&self) -> u64 {
        self.me_fair_pressure_state_gauge.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_active_flows_gauge(&self) -> u64 {
        self.me_fair_active_flows_gauge.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_queued_bytes_gauge(&self) -> u64 {
        self.me_fair_queued_bytes_gauge.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_standing_flows_gauge(&self) -> u64 {
        self.me_fair_standing_flows_gauge.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_backpressured_flows_gauge(&self) -> u64 {
        self.me_fair_backpressured_flows_gauge
            .load(Ordering::Relaxed)
    }
    pub fn get_me_fair_scheduler_rounds_total(&self) -> u64 {
        self.me_fair_scheduler_rounds_total.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_deficit_grants_total(&self) -> u64 {
        self.me_fair_deficit_grants_total.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_deficit_skips_total(&self) -> u64 {
        self.me_fair_deficit_skips_total.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_enqueue_rejects_total(&self) -> u64 {
        self.me_fair_enqueue_rejects_total.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_shed_drops_total(&self) -> u64 {
        self.me_fair_shed_drops_total.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_penalties_total(&self) -> u64 {
        self.me_fair_penalties_total.load(Ordering::Relaxed)
    }
    pub fn get_me_fair_downstream_stalls_total(&self) -> u64 {
        self.me_fair_downstream_stalls_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batches_total(&self) -> u64 {
        self.me_d2c_batches_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_frames_total(&self) -> u64 {
        self.me_d2c_batch_frames_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_bytes_total(&self) -> u64 {
        self.me_d2c_batch_bytes_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_reason_queue_drain_total(&self) -> u64 {
        self.me_d2c_flush_reason_queue_drain_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_reason_batch_frames_total(&self) -> u64 {
        self.me_d2c_flush_reason_batch_frames_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_reason_batch_bytes_total(&self) -> u64 {
        self.me_d2c_flush_reason_batch_bytes_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_reason_max_delay_total(&self) -> u64 {
        self.me_d2c_flush_reason_max_delay_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_reason_ack_immediate_total(&self) -> u64 {
        self.me_d2c_flush_reason_ack_immediate_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_reason_close_total(&self) -> u64 {
        self.me_d2c_flush_reason_close_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_data_frames_total(&self) -> u64 {
        self.me_d2c_data_frames_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_ack_frames_total(&self) -> u64 {
        self.me_d2c_ack_frames_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_payload_bytes_total(&self) -> u64 {
        self.me_d2c_payload_bytes_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_write_mode_coalesced_total(&self) -> u64 {
        self.me_d2c_write_mode_coalesced_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_write_mode_split_total(&self) -> u64 {
        self.me_d2c_write_mode_split_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_quota_reject_pre_write_total(&self) -> u64 {
        self.me_d2c_quota_reject_pre_write_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_quota_reject_post_write_total(&self) -> u64 {
        self.me_d2c_quota_reject_post_write_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_frame_buf_shrink_total(&self) -> u64 {
        self.me_d2c_frame_buf_shrink_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_frame_buf_shrink_bytes_total(&self) -> u64 {
        self.me_d2c_frame_buf_shrink_bytes_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_frames_bucket_1(&self) -> u64 {
        self.me_d2c_batch_frames_bucket_1.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_frames_bucket_2_4(&self) -> u64 {
        self.me_d2c_batch_frames_bucket_2_4.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_frames_bucket_5_8(&self) -> u64 {
        self.me_d2c_batch_frames_bucket_5_8.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_frames_bucket_9_16(&self) -> u64 {
        self.me_d2c_batch_frames_bucket_9_16.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_frames_bucket_17_32(&self) -> u64 {
        self.me_d2c_batch_frames_bucket_17_32
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_frames_bucket_gt_32(&self) -> u64 {
        self.me_d2c_batch_frames_bucket_gt_32
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_bytes_bucket_0_1k(&self) -> u64 {
        self.me_d2c_batch_bytes_bucket_0_1k.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_bytes_bucket_1k_4k(&self) -> u64 {
        self.me_d2c_batch_bytes_bucket_1k_4k.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_bytes_bucket_4k_16k(&self) -> u64 {
        self.me_d2c_batch_bytes_bucket_4k_16k
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_bytes_bucket_16k_64k(&self) -> u64 {
        self.me_d2c_batch_bytes_bucket_16k_64k
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_bytes_bucket_64k_128k(&self) -> u64 {
        self.me_d2c_batch_bytes_bucket_64k_128k
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_bytes_bucket_gt_128k(&self) -> u64 {
        self.me_d2c_batch_bytes_bucket_gt_128k
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_duration_us_bucket_0_50(&self) -> u64 {
        self.me_d2c_flush_duration_us_bucket_0_50
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_duration_us_bucket_51_200(&self) -> u64 {
        self.me_d2c_flush_duration_us_bucket_51_200
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_duration_us_bucket_201_1000(&self) -> u64 {
        self.me_d2c_flush_duration_us_bucket_201_1000
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_duration_us_bucket_1001_5000(&self) -> u64 {
        self.me_d2c_flush_duration_us_bucket_1001_5000
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_duration_us_bucket_5001_20000(&self) -> u64 {
        self.me_d2c_flush_duration_us_bucket_5001_20000
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_flush_duration_us_bucket_gt_20000(&self) -> u64 {
        self.me_d2c_flush_duration_us_bucket_gt_20000
            .load(Ordering::Relaxed)
    }

    pub fn get_buffer_pool_pooled_gauge(&self) -> u64 {
        self.buffer_pool_pooled_gauge.load(Ordering::Relaxed)
    }

    pub fn get_buffer_pool_allocated_gauge(&self) -> u64 {
        self.buffer_pool_allocated_gauge.load(Ordering::Relaxed)
    }

    pub fn get_buffer_pool_in_use_gauge(&self) -> u64 {
        self.buffer_pool_in_use_gauge.load(Ordering::Relaxed)
    }

    pub fn get_me_c2me_send_full_total(&self) -> u64 {
        self.me_c2me_send_full_total.load(Ordering::Relaxed)
    }

    pub fn get_me_c2me_send_high_water_total(&self) -> u64 {
        self.me_c2me_send_high_water_total.load(Ordering::Relaxed)
    }

    pub fn get_me_c2me_send_timeout_total(&self) -> u64 {
        self.me_c2me_send_timeout_total.load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_timeout_armed_total(&self) -> u64 {
        self.me_d2c_batch_timeout_armed_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_d2c_batch_timeout_fired_total(&self) -> u64 {
        self.me_d2c_batch_timeout_fired_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_sorted_rr_success_try_total(&self) -> u64 {
        self.me_writer_pick_sorted_rr_success_try_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_sorted_rr_success_fallback_total(&self) -> u64 {
        self.me_writer_pick_sorted_rr_success_fallback_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_sorted_rr_full_total(&self) -> u64 {
        self.me_writer_pick_sorted_rr_full_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_sorted_rr_closed_total(&self) -> u64 {
        self.me_writer_pick_sorted_rr_closed_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_sorted_rr_no_candidate_total(&self) -> u64 {
        self.me_writer_pick_sorted_rr_no_candidate_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_p2c_success_try_total(&self) -> u64 {
        self.me_writer_pick_p2c_success_try_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_p2c_success_fallback_total(&self) -> u64 {
        self.me_writer_pick_p2c_success_fallback_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_p2c_full_total(&self) -> u64 {
        self.me_writer_pick_p2c_full_total.load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_p2c_closed_total(&self) -> u64 {
        self.me_writer_pick_p2c_closed_total.load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_p2c_no_candidate_total(&self) -> u64 {
        self.me_writer_pick_p2c_no_candidate_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_blocking_fallback_total(&self) -> u64 {
        self.me_writer_pick_blocking_fallback_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_pick_mode_switch_total(&self) -> u64 {
        self.me_writer_pick_mode_switch_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_socks_kdf_strict_reject(&self) -> u64 {
        self.me_socks_kdf_strict_reject.load(Ordering::Relaxed)
    }
    pub fn get_me_socks_kdf_compat_fallback(&self) -> u64 {
        self.me_socks_kdf_compat_fallback.load(Ordering::Relaxed)
    }
    pub fn get_secure_padding_invalid(&self) -> u64 {
        self.secure_padding_invalid.load(Ordering::Relaxed)
    }
    pub fn get_desync_total(&self) -> u64 {
        self.desync_total.load(Ordering::Relaxed)
    }
    pub fn get_desync_full_logged(&self) -> u64 {
        self.desync_full_logged.load(Ordering::Relaxed)
    }
    pub fn get_desync_suppressed(&self) -> u64 {
        self.desync_suppressed.load(Ordering::Relaxed)
    }
    pub fn get_desync_frames_bucket_0(&self) -> u64 {
        self.desync_frames_bucket_0.load(Ordering::Relaxed)
    }
    pub fn get_desync_frames_bucket_1_2(&self) -> u64 {
        self.desync_frames_bucket_1_2.load(Ordering::Relaxed)
    }
    pub fn get_desync_frames_bucket_3_10(&self) -> u64 {
        self.desync_frames_bucket_3_10.load(Ordering::Relaxed)
    }
    pub fn get_desync_frames_bucket_gt_10(&self) -> u64 {
        self.desync_frames_bucket_gt_10.load(Ordering::Relaxed)
    }
    pub fn get_pool_swap_total(&self) -> u64 {
        self.pool_swap_total.load(Ordering::Relaxed)
    }
    pub fn get_pool_drain_active(&self) -> u64 {
        self.pool_drain_active.load(Ordering::Relaxed)
    }
    pub fn get_pool_force_close_total(&self) -> u64 {
        self.pool_force_close_total.load(Ordering::Relaxed)
    }
    pub fn get_pool_stale_pick_total(&self) -> u64 {
        self.pool_stale_pick_total.load(Ordering::Relaxed)
    }
    pub fn get_me_writer_removed_total(&self) -> u64 {
        self.me_writer_removed_total.load(Ordering::Relaxed)
    }
    pub fn get_me_writer_removed_unexpected_total(&self) -> u64 {
        self.me_writer_removed_unexpected_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_refill_triggered_total(&self) -> u64 {
        self.me_refill_triggered_total.load(Ordering::Relaxed)
    }
    pub fn get_me_refill_skipped_inflight_total(&self) -> u64 {
        self.me_refill_skipped_inflight_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_refill_failed_total(&self) -> u64 {
        self.me_refill_failed_total.load(Ordering::Relaxed)
    }
    pub fn get_me_writer_restored_same_endpoint_total(&self) -> u64 {
        self.me_writer_restored_same_endpoint_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_writer_restored_fallback_total(&self) -> u64 {
        self.me_writer_restored_fallback_total
            .load(Ordering::Relaxed)
    }
    pub fn get_me_no_writer_failfast_total(&self) -> u64 {
        self.me_no_writer_failfast_total.load(Ordering::Relaxed)
    }
    pub fn get_me_hybrid_timeout_total(&self) -> u64 {
        self.me_hybrid_timeout_total.load(Ordering::Relaxed)
    }
    pub fn get_me_async_recovery_trigger_total(&self) -> u64 {
        self.me_async_recovery_trigger_total.load(Ordering::Relaxed)
    }
    pub fn get_me_inline_recovery_total(&self) -> u64 {
        self.me_inline_recovery_total.load(Ordering::Relaxed)
    }
    pub fn get_ip_reservation_rollback_tcp_limit_total(&self) -> u64 {
        self.ip_reservation_rollback_tcp_limit_total
            .load(Ordering::Relaxed)
    }
    pub fn get_ip_reservation_rollback_quota_limit_total(&self) -> u64 {
        self.ip_reservation_rollback_quota_limit_total
            .load(Ordering::Relaxed)
    }
    pub fn get_quota_write_fail_bytes_total(&self) -> u64 {
        self.quota_write_fail_bytes_total.load(Ordering::Relaxed)
    }
    pub fn get_quota_write_fail_events_total(&self) -> u64 {
        self.quota_write_fail_events_total.load(Ordering::Relaxed)
    }

    pub fn increment_user_connects(&self, user: &str) {
        if !self.telemetry_user_enabled() {
            return;
        }
        let stats = self.get_or_create_user_stats_handle(user);
        Self::touch_user_stats(stats.as_ref());
        stats.connects.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_user_curr_connects(&self, user: &str) {
        if !self.telemetry_user_enabled() {
            return;
        }
        let stats = self.get_or_create_user_stats_handle(user);
        Self::touch_user_stats(stats.as_ref());
        stats.curr_connects.fetch_add(1, Ordering::Relaxed);
    }

    pub fn try_acquire_user_curr_connects(&self, user: &str, limit: Option<u64>) -> bool {
        if !self.telemetry_user_enabled() {
            return true;
        }

        let stats = self.get_or_create_user_stats_handle(user);
        Self::touch_user_stats(stats.as_ref());

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
        self.maybe_cleanup_user_stats();
        if let Some(stats) = self.user_stats.get(user) {
            Self::touch_user_stats(stats.value().as_ref());
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
        self.user_stats
            .get(user)
            .map(|s| s.quota_used.load(Ordering::Relaxed))
            .unwrap_or(0)
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

    pub fn uptime_secs(&self) -> f64 {
        self.start_time
            .read()
            .map(|t| t.elapsed().as_secs_f64())
            .unwrap_or(0.0)
    }
}

// ============= Replay Checker =============

pub struct ReplayChecker {
    handshake_shards: Vec<Mutex<ReplayShard>>,
    tls_shards: Vec<Mutex<ReplayShard>>,
    shard_mask: usize,
    window: Duration,
    tls_window: Duration,
    checks: AtomicU64,
    hits: AtomicU64,
    additions: AtomicU64,
    cleanups: AtomicU64,
}

struct ReplayEntry {
    seen_at: Instant,
    seq: u64,
}

struct ReplayShard {
    cache: LruCache<Box<[u8]>, ReplayEntry>,
    queue: VecDeque<(Instant, Box<[u8]>, u64)>,
    seq_counter: u64,
}

impl ReplayShard {
    fn new(cap: NonZeroUsize) -> Self {
        Self {
            cache: LruCache::new(cap),
            queue: VecDeque::with_capacity(cap.get()),
            seq_counter: 0,
        }
    }

    fn next_seq(&mut self) -> u64 {
        self.seq_counter += 1;
        self.seq_counter
    }

    fn cleanup(&mut self, now: Instant, window: Duration) {
        if window.is_zero() {
            self.cache.clear();
            self.queue.clear();
            return;
        }
        let cutoff = now.checked_sub(window).unwrap_or(now);

        while let Some((ts, _, _)) = self.queue.front() {
            if *ts >= cutoff {
                break;
            }
            let (_, key, queue_seq) = self.queue.pop_front().unwrap();

            // Use key.as_ref() to get &[u8] — avoids Borrow<Q> ambiguity
            // between Borrow<[u8]> and Borrow<Box<[u8]>>
            if let Some(entry) = self.cache.peek(key.as_ref())
                && entry.seq == queue_seq
            {
                self.cache.pop(key.as_ref());
            }
        }
    }

    fn check(&mut self, key: &[u8], now: Instant, window: Duration) -> bool {
        if window.is_zero() {
            return false;
        }
        self.cleanup(now, window);
        // key is &[u8], resolves Q=[u8] via Box<[u8]>: Borrow<[u8]>
        self.cache.get(key).is_some()
    }

    fn add(&mut self, key: &[u8], now: Instant, window: Duration) {
        if window.is_zero() {
            return;
        }
        self.cleanup(now, window);
        if self.cache.peek(key).is_some() {
            return;
        }

        let seq = self.next_seq();
        let boxed_key: Box<[u8]> = key.into();

        self.cache
            .put(boxed_key.clone(), ReplayEntry { seen_at: now, seq });
        self.queue.push_back((now, boxed_key, seq));
    }

    fn len(&self) -> usize {
        self.cache.len()
    }
}

impl ReplayChecker {
    pub fn new(total_capacity: usize, window: Duration) -> Self {
        const MIN_TLS_REPLAY_WINDOW: Duration = Duration::from_secs(120);
        let num_shards = 64;
        let shard_capacity = (total_capacity / num_shards).max(1);
        let cap = NonZeroUsize::new(shard_capacity).unwrap();

        let mut handshake_shards = Vec::with_capacity(num_shards);
        let mut tls_shards = Vec::with_capacity(num_shards);
        for _ in 0..num_shards {
            handshake_shards.push(Mutex::new(ReplayShard::new(cap)));
            tls_shards.push(Mutex::new(ReplayShard::new(cap)));
        }

        Self {
            handshake_shards,
            tls_shards,
            shard_mask: num_shards - 1,
            window,
            tls_window: window.max(MIN_TLS_REPLAY_WINDOW),
            checks: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            additions: AtomicU64::new(0),
            cleanups: AtomicU64::new(0),
        }
    }

    fn get_shard_idx(&self, key: &[u8]) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) & self.shard_mask
    }

    fn check_and_add_internal(
        &self,
        data: &[u8],
        shards: &[Mutex<ReplayShard>],
        window: Duration,
    ) -> bool {
        self.checks.fetch_add(1, Ordering::Relaxed);
        let idx = self.get_shard_idx(data);
        let mut shard = shards[idx].lock();
        let now = Instant::now();
        let found = shard.check(data, now, window);
        if found {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            shard.add(data, now, window);
            self.additions.fetch_add(1, Ordering::Relaxed);
        }
        found
    }

    fn check_only_internal(
        &self,
        data: &[u8],
        shards: &[Mutex<ReplayShard>],
        window: Duration,
    ) -> bool {
        self.checks.fetch_add(1, Ordering::Relaxed);
        let idx = self.get_shard_idx(data);
        let mut shard = shards[idx].lock();
        let found = shard.check(data, Instant::now(), window);
        if found {
            self.hits.fetch_add(1, Ordering::Relaxed);
        }
        found
    }

    fn add_only(&self, data: &[u8], shards: &[Mutex<ReplayShard>], window: Duration) {
        self.additions.fetch_add(1, Ordering::Relaxed);
        let idx = self.get_shard_idx(data);
        let mut shard = shards[idx].lock();
        shard.add(data, Instant::now(), window);
    }

    pub fn check_and_add_handshake(&self, data: &[u8]) -> bool {
        self.check_and_add_internal(data, &self.handshake_shards, self.window)
    }

    pub fn check_and_add_tls_digest(&self, data: &[u8]) -> bool {
        self.check_and_add_internal(data, &self.tls_shards, self.tls_window)
    }

    // Compatibility helpers (non-atomic split operations) — prefer check_and_add_*.
    pub fn check_handshake(&self, data: &[u8]) -> bool {
        self.check_and_add_handshake(data)
    }
    pub fn add_handshake(&self, data: &[u8]) {
        self.add_only(data, &self.handshake_shards, self.window)
    }
    pub fn check_tls_digest(&self, data: &[u8]) -> bool {
        self.check_only_internal(data, &self.tls_shards, self.tls_window)
    }
    pub fn add_tls_digest(&self, data: &[u8]) {
        self.add_only(data, &self.tls_shards, self.tls_window)
    }

    pub fn stats(&self) -> ReplayStats {
        let mut total_entries = 0;
        let mut total_queue_len = 0;
        for shard in &self.handshake_shards {
            let s = shard.lock();
            total_entries += s.cache.len();
            total_queue_len += s.queue.len();
        }
        for shard in &self.tls_shards {
            let s = shard.lock();
            total_entries += s.cache.len();
            total_queue_len += s.queue.len();
        }

        ReplayStats {
            total_entries,
            total_queue_len,
            total_checks: self.checks.load(Ordering::Relaxed),
            total_hits: self.hits.load(Ordering::Relaxed),
            total_additions: self.additions.load(Ordering::Relaxed),
            total_cleanups: self.cleanups.load(Ordering::Relaxed),
            num_shards: self.handshake_shards.len() + self.tls_shards.len(),
            window_secs: self.window.as_secs(),
        }
    }

    pub async fn run_periodic_cleanup(&self) {
        let interval = if self.window.as_secs() > 60 {
            Duration::from_secs(30)
        } else {
            Duration::from_secs((self.window.as_secs().max(1) / 2).max(1))
        };

        loop {
            tokio::time::sleep(interval).await;

            let now = Instant::now();
            let mut cleaned = 0usize;

            for shard_mutex in &self.handshake_shards {
                let mut shard = shard_mutex.lock();
                let before = shard.len();
                shard.cleanup(now, self.window);
                let after = shard.len();
                cleaned += before.saturating_sub(after);
            }
            for shard_mutex in &self.tls_shards {
                let mut shard = shard_mutex.lock();
                let before = shard.len();
                shard.cleanup(now, self.tls_window);
                let after = shard.len();
                cleaned += before.saturating_sub(after);
            }

            self.cleanups.fetch_add(1, Ordering::Relaxed);

            if cleaned > 0 {
                debug!(cleaned = cleaned, "Replay checker: periodic cleanup");
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReplayStats {
    pub total_entries: usize,
    pub total_queue_len: usize,
    pub total_checks: u64,
    pub total_hits: u64,
    pub total_additions: u64,
    pub total_cleanups: u64,
    pub num_shards: usize,
    pub window_secs: u64,
}

impl ReplayStats {
    pub fn hit_rate(&self) -> f64 {
        if self.total_checks == 0 {
            0.0
        } else {
            (self.total_hits as f64 / self.total_checks as f64) * 100.0
        }
    }

    pub fn ghost_ratio(&self) -> f64 {
        if self.total_entries == 0 {
            0.0
        } else {
            self.total_queue_len as f64 / self.total_entries as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MeTelemetryLevel;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn test_stats_shared_counters() {
        let stats = Arc::new(Stats::new());
        stats.increment_connects_all();
        stats.increment_connects_all();
        stats.increment_connects_all();
        assert_eq!(stats.get_connects_all(), 3);
    }

    #[test]
    fn test_telemetry_policy_disables_core_and_user_counters() {
        let stats = Stats::new();
        stats.apply_telemetry_policy(TelemetryPolicy {
            core_enabled: false,
            user_enabled: false,
            me_level: MeTelemetryLevel::Normal,
        });

        stats.increment_connects_all();
        stats.increment_user_connects("alice");
        stats.add_user_octets_from("alice", 1024);
        assert_eq!(stats.get_connects_all(), 0);
        assert_eq!(stats.get_user_curr_connects("alice"), 0);
        assert_eq!(stats.get_user_total_octets("alice"), 0);
    }

    #[test]
    fn test_telemetry_policy_me_silent_blocks_me_counters() {
        let stats = Stats::new();
        stats.apply_telemetry_policy(TelemetryPolicy {
            core_enabled: true,
            user_enabled: true,
            me_level: MeTelemetryLevel::Silent,
        });

        stats.increment_me_crc_mismatch();
        stats.increment_me_keepalive_sent();
        stats.increment_me_route_drop_queue_full();
        stats.increment_me_d2c_batches_total();
        stats.add_me_d2c_batch_frames_total(4);
        stats.add_me_d2c_batch_bytes_total(4096);
        stats.increment_me_d2c_flush_reason(MeD2cFlushReason::BatchBytes);
        stats.increment_me_d2c_write_mode(MeD2cWriteMode::Coalesced);
        stats.increment_me_d2c_quota_reject_total(MeD2cQuotaRejectStage::PreWrite);
        stats.observe_me_d2c_frame_buf_shrink(1024);
        stats.observe_me_d2c_batch_frames(4);
        stats.observe_me_d2c_batch_bytes(4096);
        stats.observe_me_d2c_flush_duration_us(120);
        stats.increment_me_d2c_batch_timeout_armed_total();
        stats.increment_me_d2c_batch_timeout_fired_total();
        assert_eq!(stats.get_me_crc_mismatch(), 0);
        assert_eq!(stats.get_me_keepalive_sent(), 0);
        assert_eq!(stats.get_me_route_drop_queue_full(), 0);
        assert_eq!(stats.get_me_d2c_batches_total(), 0);
        assert_eq!(stats.get_me_d2c_flush_reason_batch_bytes_total(), 0);
        assert_eq!(stats.get_me_d2c_write_mode_coalesced_total(), 0);
        assert_eq!(stats.get_me_d2c_quota_reject_pre_write_total(), 0);
        assert_eq!(stats.get_me_d2c_frame_buf_shrink_total(), 0);
        assert_eq!(stats.get_me_d2c_batch_frames_bucket_2_4(), 0);
        assert_eq!(stats.get_me_d2c_batch_bytes_bucket_1k_4k(), 0);
        assert_eq!(stats.get_me_d2c_flush_duration_us_bucket_51_200(), 0);
        assert_eq!(stats.get_me_d2c_batch_timeout_armed_total(), 0);
        assert_eq!(stats.get_me_d2c_batch_timeout_fired_total(), 0);
    }

    #[test]
    fn test_telemetry_policy_me_normal_blocks_d2c_debug_metrics() {
        let stats = Stats::new();
        stats.apply_telemetry_policy(TelemetryPolicy {
            core_enabled: true,
            user_enabled: true,
            me_level: MeTelemetryLevel::Normal,
        });

        stats.increment_me_d2c_batches_total();
        stats.add_me_d2c_batch_frames_total(2);
        stats.add_me_d2c_batch_bytes_total(2048);
        stats.increment_me_d2c_flush_reason(MeD2cFlushReason::QueueDrain);
        stats.observe_me_d2c_batch_frames(2);
        stats.observe_me_d2c_batch_bytes(2048);
        stats.observe_me_d2c_flush_duration_us(100);
        stats.increment_me_d2c_batch_timeout_armed_total();
        stats.increment_me_d2c_batch_timeout_fired_total();

        assert_eq!(stats.get_me_d2c_batches_total(), 1);
        assert_eq!(stats.get_me_d2c_batch_frames_total(), 2);
        assert_eq!(stats.get_me_d2c_batch_bytes_total(), 2048);
        assert_eq!(stats.get_me_d2c_flush_reason_queue_drain_total(), 1);
        assert_eq!(stats.get_me_d2c_batch_frames_bucket_2_4(), 0);
        assert_eq!(stats.get_me_d2c_batch_bytes_bucket_1k_4k(), 0);
        assert_eq!(stats.get_me_d2c_flush_duration_us_bucket_51_200(), 0);
        assert_eq!(stats.get_me_d2c_batch_timeout_armed_total(), 0);
        assert_eq!(stats.get_me_d2c_batch_timeout_fired_total(), 0);
    }

    #[test]
    fn test_telemetry_policy_me_debug_enables_d2c_debug_metrics() {
        let stats = Stats::new();
        stats.apply_telemetry_policy(TelemetryPolicy {
            core_enabled: true,
            user_enabled: true,
            me_level: MeTelemetryLevel::Debug,
        });

        stats.observe_me_d2c_batch_frames(7);
        stats.observe_me_d2c_batch_bytes(70_000);
        stats.observe_me_d2c_flush_duration_us(1400);
        stats.increment_me_d2c_batch_timeout_armed_total();
        stats.increment_me_d2c_batch_timeout_fired_total();

        assert_eq!(stats.get_me_d2c_batch_frames_bucket_5_8(), 1);
        assert_eq!(stats.get_me_d2c_batch_bytes_bucket_64k_128k(), 1);
        assert_eq!(stats.get_me_d2c_flush_duration_us_bucket_1001_5000(), 1);
        assert_eq!(stats.get_me_d2c_batch_timeout_armed_total(), 1);
        assert_eq!(stats.get_me_d2c_batch_timeout_fired_total(), 1);
    }

    #[test]
    fn test_replay_checker_basic() {
        let checker = ReplayChecker::new(100, Duration::from_secs(60));
        assert!(!checker.check_handshake(b"test1")); // first time, inserts
        assert!(checker.check_handshake(b"test1")); // duplicate
        assert!(!checker.check_handshake(b"test2")); // new key inserts
    }

    #[test]
    fn test_replay_checker_duplicate_add() {
        let checker = ReplayChecker::new(100, Duration::from_secs(60));
        checker.add_handshake(b"dup");
        checker.add_handshake(b"dup");
        assert!(checker.check_handshake(b"dup"));
    }

    #[test]
    fn test_replay_checker_expiration() {
        let checker = ReplayChecker::new(100, Duration::from_millis(50));
        assert!(!checker.check_handshake(b"expire"));
        assert!(checker.check_handshake(b"expire"));
        std::thread::sleep(Duration::from_millis(100));
        assert!(!checker.check_handshake(b"expire"));
    }

    #[test]
    fn test_replay_checker_zero_window_does_not_retain_entries() {
        let checker = ReplayChecker::new(100, Duration::ZERO);

        for _ in 0..1_000 {
            assert!(!checker.check_handshake(b"no-retain"));
            checker.add_handshake(b"no-retain");
        }

        let stats = checker.stats();
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.total_queue_len, 0);
    }

    #[test]
    fn test_replay_checker_stats() {
        let checker = ReplayChecker::new(100, Duration::from_secs(60));
        assert!(!checker.check_handshake(b"k1"));
        assert!(!checker.check_handshake(b"k2"));
        assert!(checker.check_handshake(b"k1"));
        assert!(!checker.check_handshake(b"k3"));
        let stats = checker.stats();
        assert_eq!(stats.total_additions, 3);
        assert_eq!(stats.total_checks, 4);
        assert_eq!(stats.total_hits, 1);
    }

    #[test]
    fn test_replay_checker_many_keys() {
        let checker = ReplayChecker::new(10_000, Duration::from_secs(60));
        for i in 0..500u32 {
            checker.add_handshake(&i.to_le_bytes());
        }
        for i in 0..500u32 {
            assert!(checker.check_handshake(&i.to_le_bytes()));
        }
        assert_eq!(checker.stats().total_entries, 500);
    }

    #[test]
    fn test_quota_reserve_under_contention_hits_limit_exactly() {
        let user_stats = Arc::new(UserStats::default());
        let successes = Arc::new(AtomicU64::new(0));
        let limit = 8_192u64;
        let mut workers = Vec::new();

        for _ in 0..8 {
            let user_stats = user_stats.clone();
            let successes = successes.clone();
            workers.push(std::thread::spawn(move || {
                loop {
                    match user_stats.quota_try_reserve(1, limit) {
                        Ok(_) => {
                            successes.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(QuotaReserveError::Contended) => {
                            std::hint::spin_loop();
                        }
                        Err(QuotaReserveError::LimitExceeded) => {
                            break;
                        }
                    }
                }
            }));
        }

        for worker in workers {
            worker.join().expect("worker thread must finish");
        }

        assert_eq!(
            successes.load(Ordering::Relaxed),
            limit,
            "successful reservations must stop exactly at limit"
        );
        assert_eq!(user_stats.quota_used(), limit);
    }

    #[test]
    fn test_quota_reserve_200x_1k_reaches_100k_without_overshoot() {
        let user_stats = Arc::new(UserStats::default());
        let successes = Arc::new(AtomicU64::new(0));
        let failures = Arc::new(AtomicU64::new(0));
        let attempts = 200usize;
        let reserve_bytes = 1_024u64;
        let limit = 100 * 1_024u64;
        let mut workers = Vec::with_capacity(attempts);

        for _ in 0..attempts {
            let user_stats = user_stats.clone();
            let successes = successes.clone();
            let failures = failures.clone();
            workers.push(std::thread::spawn(move || {
                loop {
                    match user_stats.quota_try_reserve(reserve_bytes, limit) {
                        Ok(_) => {
                            successes.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                        Err(QuotaReserveError::LimitExceeded) => {
                            failures.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                        Err(QuotaReserveError::Contended) => {
                            std::hint::spin_loop();
                        }
                    }
                }
            }));
        }

        for worker in workers {
            worker.join().expect("reservation worker must finish");
        }

        assert_eq!(
            successes.load(Ordering::Relaxed),
            100,
            "exactly 100 reservations of 1 KiB must fit into a 100 KiB quota"
        );
        assert_eq!(
            failures.load(Ordering::Relaxed),
            100,
            "remaining workers must fail once quota is fully reserved"
        );
        assert_eq!(user_stats.quota_used(), limit);
    }

    #[test]
    fn test_quota_used_is_authoritative_and_independent_from_octets_telemetry() {
        let stats = Stats::new();
        let user = "quota-authoritative-user";
        let user_stats = stats.get_or_create_user_stats_handle(user);

        stats.add_user_octets_to_handle(&user_stats, 5);
        assert_eq!(stats.get_user_total_octets(user), 5);
        assert_eq!(stats.get_user_quota_used(user), 0);

        stats.quota_charge_post_write(&user_stats, 7);
        assert_eq!(stats.get_user_total_octets(user), 5);
        assert_eq!(stats.get_user_quota_used(user), 7);
    }

    #[test]
    fn test_cached_handle_survives_map_cleanup_until_last_drop() {
        let stats = Stats::new();
        let user = "quota-handle-lifetime-user";
        let user_stats = stats.get_or_create_user_stats_handle(user);
        let weak = Arc::downgrade(&user_stats);

        stats.user_stats.remove(user);
        assert!(
            stats.user_stats.get(user).is_none(),
            "map cleanup should remove idle entry"
        );
        assert!(
            weak.upgrade().is_some(),
            "cached handle must keep user stats object alive after map removal"
        );

        stats.quota_charge_post_write(user_stats.as_ref(), 3);
        assert_eq!(user_stats.quota_used(), 3);

        drop(user_stats);
        assert!(
            weak.upgrade().is_none(),
            "user stats object must be dropped after the last cached handle is released"
        );
    }
}

#[cfg(test)]
#[path = "tests/connection_lease_security_tests.rs"]
mod connection_lease_security_tests;

#[cfg(test)]
#[path = "tests/replay_checker_security_tests.rs"]
mod replay_checker_security_tests;
