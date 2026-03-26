use std::net::IpAddr;
use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};

use crate::crypto::SecureRandom;

const MAX_USERNAME_LEN: usize = 64;

#[derive(Debug)]
pub(super) struct ApiFailure {
    pub(super) status: StatusCode,
    pub(super) code: &'static str,
    pub(super) message: String,
}

impl ApiFailure {
    pub(super) fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub(super) fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
    }

    pub(super) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }
}

#[derive(Serialize)]
pub(super) struct ErrorBody {
    pub(super) code: &'static str,
    pub(super) message: String,
}

#[derive(Serialize)]
pub(super) struct ErrorResponse {
    pub(super) ok: bool,
    pub(super) error: ErrorBody,
    pub(super) request_id: u64,
}

#[derive(Serialize)]
pub(super) struct SuccessResponse<T> {
    pub(super) ok: bool,
    pub(super) data: T,
    pub(super) revision: String,
}

#[derive(Serialize)]
pub(super) struct HealthData {
    pub(super) status: &'static str,
    pub(super) read_only: bool,
}

#[derive(Serialize)]
pub(super) struct SummaryData {
    pub(super) uptime_seconds: f64,
    pub(super) connections_total: u64,
    pub(super) connections_bad_total: u64,
    pub(super) handshake_timeouts_total: u64,
    pub(super) configured_users: usize,
}

#[derive(Serialize, Clone)]
pub(super) struct ZeroCodeCount {
    pub(super) code: i32,
    pub(super) total: u64,
}

#[derive(Serialize, Clone)]
pub(super) struct ZeroCoreData {
    pub(super) uptime_seconds: f64,
    pub(super) connections_total: u64,
    pub(super) connections_bad_total: u64,
    pub(super) handshake_timeouts_total: u64,
    pub(super) configured_users: usize,
    pub(super) telemetry_core_enabled: bool,
    pub(super) telemetry_user_enabled: bool,
    pub(super) telemetry_me_level: String,
}

#[derive(Serialize, Clone)]
pub(super) struct ZeroUpstreamData {
    pub(super) connect_attempt_total: u64,
    pub(super) connect_success_total: u64,
    pub(super) connect_fail_total: u64,
    pub(super) connect_failfast_hard_error_total: u64,
    pub(super) connect_attempts_bucket_1: u64,
    pub(super) connect_attempts_bucket_2: u64,
    pub(super) connect_attempts_bucket_3_4: u64,
    pub(super) connect_attempts_bucket_gt_4: u64,
    pub(super) connect_duration_success_bucket_le_100ms: u64,
    pub(super) connect_duration_success_bucket_101_500ms: u64,
    pub(super) connect_duration_success_bucket_501_1000ms: u64,
    pub(super) connect_duration_success_bucket_gt_1000ms: u64,
    pub(super) connect_duration_fail_bucket_le_100ms: u64,
    pub(super) connect_duration_fail_bucket_101_500ms: u64,
    pub(super) connect_duration_fail_bucket_501_1000ms: u64,
    pub(super) connect_duration_fail_bucket_gt_1000ms: u64,
}

#[derive(Serialize, Clone)]
pub(super) struct UpstreamDcStatus {
    pub(super) dc: i16,
    pub(super) latency_ema_ms: Option<f64>,
    pub(super) ip_preference: &'static str,
}

#[derive(Serialize, Clone)]
pub(super) struct UpstreamStatus {
    pub(super) upstream_id: usize,
    pub(super) route_kind: &'static str,
    pub(super) address: String,
    pub(super) weight: u16,
    pub(super) scopes: String,
    pub(super) healthy: bool,
    pub(super) fails: u32,
    pub(super) last_check_age_secs: u64,
    pub(super) effective_latency_ms: Option<f64>,
    pub(super) dc: Vec<UpstreamDcStatus>,
}

#[derive(Serialize, Clone)]
pub(super) struct UpstreamSummaryData {
    pub(super) configured_total: usize,
    pub(super) healthy_total: usize,
    pub(super) unhealthy_total: usize,
    pub(super) direct_total: usize,
    pub(super) socks4_total: usize,
    pub(super) socks5_total: usize,
    pub(super) shadowsocks_total: usize,
}

#[derive(Serialize, Clone)]
pub(super) struct UpstreamsData {
    pub(super) enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) generated_at_epoch_secs: u64,
    pub(super) zero: ZeroUpstreamData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) summary: Option<UpstreamSummaryData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) upstreams: Option<Vec<UpstreamStatus>>,
}

#[derive(Serialize, Clone)]
pub(super) struct ZeroMiddleProxyData {
    pub(super) keepalive_sent_total: u64,
    pub(super) keepalive_failed_total: u64,
    pub(super) keepalive_pong_total: u64,
    pub(super) keepalive_timeout_total: u64,
    pub(super) rpc_proxy_req_signal_sent_total: u64,
    pub(super) rpc_proxy_req_signal_failed_total: u64,
    pub(super) rpc_proxy_req_signal_skipped_no_meta_total: u64,
    pub(super) rpc_proxy_req_signal_response_total: u64,
    pub(super) rpc_proxy_req_signal_close_sent_total: u64,
    pub(super) reconnect_attempt_total: u64,
    pub(super) reconnect_success_total: u64,
    pub(super) handshake_reject_total: u64,
    pub(super) handshake_error_codes: Vec<ZeroCodeCount>,
    pub(super) reader_eof_total: u64,
    pub(super) idle_close_by_peer_total: u64,
    pub(super) route_drop_no_conn_total: u64,
    pub(super) route_drop_channel_closed_total: u64,
    pub(super) route_drop_queue_full_total: u64,
    pub(super) route_drop_queue_full_base_total: u64,
    pub(super) route_drop_queue_full_high_total: u64,
    pub(super) d2c_batches_total: u64,
    pub(super) d2c_batch_frames_total: u64,
    pub(super) d2c_batch_bytes_total: u64,
    pub(super) d2c_flush_reason_queue_drain_total: u64,
    pub(super) d2c_flush_reason_batch_frames_total: u64,
    pub(super) d2c_flush_reason_batch_bytes_total: u64,
    pub(super) d2c_flush_reason_max_delay_total: u64,
    pub(super) d2c_flush_reason_ack_immediate_total: u64,
    pub(super) d2c_flush_reason_close_total: u64,
    pub(super) d2c_data_frames_total: u64,
    pub(super) d2c_ack_frames_total: u64,
    pub(super) d2c_payload_bytes_total: u64,
    pub(super) d2c_write_mode_coalesced_total: u64,
    pub(super) d2c_write_mode_split_total: u64,
    pub(super) d2c_quota_reject_pre_write_total: u64,
    pub(super) d2c_quota_reject_post_write_total: u64,
    pub(super) d2c_frame_buf_shrink_total: u64,
    pub(super) d2c_frame_buf_shrink_bytes_total: u64,
    pub(super) socks_kdf_strict_reject_total: u64,
    pub(super) socks_kdf_compat_fallback_total: u64,
    pub(super) endpoint_quarantine_total: u64,
    pub(super) kdf_drift_total: u64,
    pub(super) kdf_port_only_drift_total: u64,
    pub(super) hardswap_pending_reuse_total: u64,
    pub(super) hardswap_pending_ttl_expired_total: u64,
    pub(super) single_endpoint_outage_enter_total: u64,
    pub(super) single_endpoint_outage_exit_total: u64,
    pub(super) single_endpoint_outage_reconnect_attempt_total: u64,
    pub(super) single_endpoint_outage_reconnect_success_total: u64,
    pub(super) single_endpoint_quarantine_bypass_total: u64,
    pub(super) single_endpoint_shadow_rotate_total: u64,
    pub(super) single_endpoint_shadow_rotate_skipped_quarantine_total: u64,
    pub(super) floor_mode_switch_total: u64,
    pub(super) floor_mode_switch_static_to_adaptive_total: u64,
    pub(super) floor_mode_switch_adaptive_to_static_total: u64,
}

#[derive(Serialize, Clone)]
pub(super) struct ZeroPoolData {
    pub(super) pool_swap_total: u64,
    pub(super) pool_drain_active: u64,
    pub(super) pool_force_close_total: u64,
    pub(super) pool_stale_pick_total: u64,
    pub(super) writer_removed_total: u64,
    pub(super) writer_removed_unexpected_total: u64,
    pub(super) refill_triggered_total: u64,
    pub(super) refill_skipped_inflight_total: u64,
    pub(super) refill_failed_total: u64,
    pub(super) writer_restored_same_endpoint_total: u64,
    pub(super) writer_restored_fallback_total: u64,
}

#[derive(Serialize, Clone)]
pub(super) struct ZeroDesyncData {
    pub(super) secure_padding_invalid_total: u64,
    pub(super) desync_total: u64,
    pub(super) desync_full_logged_total: u64,
    pub(super) desync_suppressed_total: u64,
    pub(super) desync_frames_bucket_0: u64,
    pub(super) desync_frames_bucket_1_2: u64,
    pub(super) desync_frames_bucket_3_10: u64,
    pub(super) desync_frames_bucket_gt_10: u64,
}

#[derive(Serialize, Clone)]
pub(super) struct ZeroAllData {
    pub(super) generated_at_epoch_secs: u64,
    pub(super) core: ZeroCoreData,
    pub(super) upstream: ZeroUpstreamData,
    pub(super) middle_proxy: ZeroMiddleProxyData,
    pub(super) pool: ZeroPoolData,
    pub(super) desync: ZeroDesyncData,
}

#[derive(Serialize, Clone)]
pub(super) struct MeWritersSummary {
    pub(super) configured_dc_groups: usize,
    pub(super) configured_endpoints: usize,
    pub(super) available_endpoints: usize,
    pub(super) available_pct: f64,
    pub(super) required_writers: usize,
    pub(super) alive_writers: usize,
    pub(super) coverage_pct: f64,
    pub(super) fresh_alive_writers: usize,
    pub(super) fresh_coverage_pct: f64,
}

#[derive(Serialize, Clone)]
pub(super) struct MeWriterStatus {
    pub(super) writer_id: u64,
    pub(super) dc: Option<i16>,
    pub(super) endpoint: String,
    pub(super) generation: u64,
    pub(super) state: &'static str,
    pub(super) draining: bool,
    pub(super) degraded: bool,
    pub(super) bound_clients: usize,
    pub(super) idle_for_secs: Option<u64>,
    pub(super) rtt_ema_ms: Option<f64>,
    pub(super) matches_active_generation: bool,
    pub(super) in_desired_map: bool,
    pub(super) allow_drain_fallback: bool,
    pub(super) drain_started_at_epoch_secs: Option<u64>,
    pub(super) drain_deadline_epoch_secs: Option<u64>,
    pub(super) drain_over_ttl: bool,
}

#[derive(Serialize, Clone)]
pub(super) struct MeWritersData {
    pub(super) middle_proxy_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) generated_at_epoch_secs: u64,
    pub(super) summary: MeWritersSummary,
    pub(super) writers: Vec<MeWriterStatus>,
}

#[derive(Serialize, Clone)]
pub(super) struct DcStatus {
    pub(super) dc: i16,
    pub(super) endpoints: Vec<String>,
    pub(super) endpoint_writers: Vec<DcEndpointWriters>,
    pub(super) available_endpoints: usize,
    pub(super) available_pct: f64,
    pub(super) required_writers: usize,
    pub(super) floor_min: usize,
    pub(super) floor_target: usize,
    pub(super) floor_max: usize,
    pub(super) floor_capped: bool,
    pub(super) alive_writers: usize,
    pub(super) coverage_pct: f64,
    pub(super) fresh_alive_writers: usize,
    pub(super) fresh_coverage_pct: f64,
    pub(super) rtt_ms: Option<f64>,
    pub(super) load: usize,
}

#[derive(Serialize, Clone)]
pub(super) struct DcEndpointWriters {
    pub(super) endpoint: String,
    pub(super) active_writers: usize,
}

#[derive(Serialize, Clone)]
pub(super) struct DcStatusData {
    pub(super) middle_proxy_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) generated_at_epoch_secs: u64,
    pub(super) dcs: Vec<DcStatus>,
}

#[derive(Serialize, Clone)]
pub(super) struct MinimalQuarantineData {
    pub(super) endpoint: String,
    pub(super) remaining_ms: u64,
}

#[derive(Serialize, Clone)]
pub(super) struct MinimalDcPathData {
    pub(super) dc: i16,
    pub(super) ip_preference: Option<&'static str>,
    pub(super) selected_addr_v4: Option<String>,
    pub(super) selected_addr_v6: Option<String>,
}

#[derive(Serialize, Clone)]
pub(super) struct MinimalMeRuntimeData {
    pub(super) active_generation: u64,
    pub(super) warm_generation: u64,
    pub(super) pending_hardswap_generation: u64,
    pub(super) pending_hardswap_age_secs: Option<u64>,
    pub(super) hardswap_enabled: bool,
    pub(super) floor_mode: &'static str,
    pub(super) adaptive_floor_idle_secs: u64,
    pub(super) adaptive_floor_min_writers_single_endpoint: u8,
    pub(super) adaptive_floor_min_writers_multi_endpoint: u8,
    pub(super) adaptive_floor_recover_grace_secs: u64,
    pub(super) adaptive_floor_writers_per_core_total: u16,
    pub(super) adaptive_floor_cpu_cores_override: u16,
    pub(super) adaptive_floor_max_extra_writers_single_per_core: u16,
    pub(super) adaptive_floor_max_extra_writers_multi_per_core: u16,
    pub(super) adaptive_floor_max_active_writers_per_core: u16,
    pub(super) adaptive_floor_max_warm_writers_per_core: u16,
    pub(super) adaptive_floor_max_active_writers_global: u32,
    pub(super) adaptive_floor_max_warm_writers_global: u32,
    pub(super) adaptive_floor_cpu_cores_detected: u32,
    pub(super) adaptive_floor_cpu_cores_effective: u32,
    pub(super) adaptive_floor_global_cap_raw: u64,
    pub(super) adaptive_floor_global_cap_effective: u64,
    pub(super) adaptive_floor_target_writers_total: u64,
    pub(super) adaptive_floor_active_cap_configured: u64,
    pub(super) adaptive_floor_active_cap_effective: u64,
    pub(super) adaptive_floor_warm_cap_configured: u64,
    pub(super) adaptive_floor_warm_cap_effective: u64,
    pub(super) adaptive_floor_active_writers_current: u64,
    pub(super) adaptive_floor_warm_writers_current: u64,
    pub(super) me_keepalive_enabled: bool,
    pub(super) me_keepalive_interval_secs: u64,
    pub(super) me_keepalive_jitter_secs: u64,
    pub(super) me_keepalive_payload_random: bool,
    pub(super) rpc_proxy_req_every_secs: u64,
    pub(super) me_reconnect_max_concurrent_per_dc: u32,
    pub(super) me_reconnect_backoff_base_ms: u64,
    pub(super) me_reconnect_backoff_cap_ms: u64,
    pub(super) me_reconnect_fast_retry_count: u32,
    pub(super) me_pool_drain_ttl_secs: u64,
    pub(super) me_pool_force_close_secs: u64,
    pub(super) me_pool_min_fresh_ratio: f32,
    pub(super) me_bind_stale_mode: &'static str,
    pub(super) me_bind_stale_ttl_secs: u64,
    pub(super) me_single_endpoint_shadow_writers: u8,
    pub(super) me_single_endpoint_outage_mode_enabled: bool,
    pub(super) me_single_endpoint_outage_disable_quarantine: bool,
    pub(super) me_single_endpoint_outage_backoff_min_ms: u64,
    pub(super) me_single_endpoint_outage_backoff_max_ms: u64,
    pub(super) me_single_endpoint_shadow_rotate_every_secs: u64,
    pub(super) me_deterministic_writer_sort: bool,
    pub(super) me_writer_pick_mode: &'static str,
    pub(super) me_writer_pick_sample_size: u8,
    pub(super) me_socks_kdf_policy: &'static str,
    pub(super) quarantined_endpoints_total: usize,
    pub(super) quarantined_endpoints: Vec<MinimalQuarantineData>,
}

#[derive(Serialize, Clone)]
pub(super) struct MinimalAllPayload {
    pub(super) me_writers: MeWritersData,
    pub(super) dcs: DcStatusData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) me_runtime: Option<MinimalMeRuntimeData>,
    pub(super) network_path: Vec<MinimalDcPathData>,
}

#[derive(Serialize, Clone)]
pub(super) struct MinimalAllData {
    pub(super) enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) generated_at_epoch_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) data: Option<MinimalAllPayload>,
}

#[derive(Serialize)]
pub(super) struct UserLinks {
    pub(super) classic: Vec<String>,
    pub(super) secure: Vec<String>,
    pub(super) tls: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct UserInfo {
    pub(super) username: String,
    pub(super) user_ad_tag: Option<String>,
    pub(super) max_tcp_conns: Option<usize>,
    pub(super) expiration_rfc3339: Option<String>,
    pub(super) data_quota_bytes: Option<u64>,
    pub(super) max_unique_ips: Option<usize>,
    pub(super) current_connections: u64,
    pub(super) active_unique_ips: usize,
    pub(super) active_unique_ips_list: Vec<IpAddr>,
    pub(super) recent_unique_ips: usize,
    pub(super) recent_unique_ips_list: Vec<IpAddr>,
    pub(super) total_octets: u64,
    pub(super) links: UserLinks,
}

#[derive(Serialize)]
pub(super) struct CreateUserResponse {
    pub(super) user: UserInfo,
    pub(super) secret: String,
}

#[derive(Deserialize)]
pub(super) struct CreateUserRequest {
    pub(super) username: String,
    pub(super) secret: Option<String>,
    pub(super) user_ad_tag: Option<String>,
    pub(super) max_tcp_conns: Option<usize>,
    pub(super) expiration_rfc3339: Option<String>,
    pub(super) data_quota_bytes: Option<u64>,
    pub(super) max_unique_ips: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct PatchUserRequest {
    pub(super) secret: Option<String>,
    pub(super) user_ad_tag: Option<String>,
    pub(super) max_tcp_conns: Option<usize>,
    pub(super) expiration_rfc3339: Option<String>,
    pub(super) data_quota_bytes: Option<u64>,
    pub(super) max_unique_ips: Option<usize>,
}

#[derive(Default, Deserialize)]
pub(super) struct RotateSecretRequest {
    pub(super) secret: Option<String>,
}

pub(super) fn parse_optional_expiration(
    value: Option<&str>,
) -> Result<Option<DateTime<Utc>>, ApiFailure> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let parsed = DateTime::parse_from_rfc3339(raw)
        .map_err(|_| ApiFailure::bad_request("expiration_rfc3339 must be valid RFC3339"))?;
    Ok(Some(parsed.with_timezone(&Utc)))
}

pub(super) fn is_valid_user_secret(secret: &str) -> bool {
    secret.len() == 32 && secret.chars().all(|c| c.is_ascii_hexdigit())
}

pub(super) fn is_valid_ad_tag(tag: &str) -> bool {
    tag.len() == 32 && tag.chars().all(|c| c.is_ascii_hexdigit())
}

pub(super) fn is_valid_username(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= MAX_USERNAME_LEN
        && user
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
}

pub(super) fn random_user_secret() -> String {
    static API_SECRET_RNG: OnceLock<SecureRandom> = OnceLock::new();
    let rng = API_SECRET_RNG.get_or_init(SecureRandom::new);
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes);
    hex::encode(bytes)
}
