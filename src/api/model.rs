use std::net::IpAddr;
use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};

use super::patch::{Patch, patch_field};
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
pub(super) struct HealthReadyData {
    pub(super) ready: bool,
    pub(super) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) admission_open: bool,
    pub(super) healthy_upstreams: usize,
    pub(super) total_upstreams: usize,
}

#[derive(Serialize, Clone)]
pub(super) struct ClassCount {
    pub(super) class: String,
    pub(super) total: u64,
}

#[derive(Serialize)]
pub(super) struct SummaryData {
    pub(super) uptime_seconds: f64,
    pub(super) connections_total: u64,
    pub(super) connections_bad_total: u64,
    pub(super) connections_bad_by_class: Vec<ClassCount>,
    pub(super) handshake_failures_by_class: Vec<ClassCount>,
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
    pub(super) connections_bad_by_class: Vec<ClassCount>,
    pub(super) handshake_failures_by_class: Vec<ClassCount>,
    pub(super) handshake_timeouts_total: u64,
    pub(super) accept_permit_timeout_total: u64,
    pub(super) configured_users: usize,
    pub(super) telemetry_core_enabled: bool,
    pub(super) telemetry_user_enabled: bool,
    pub(super) telemetry_me_level: String,
    pub(super) conntrack_control_enabled: bool,
    pub(super) conntrack_control_available: bool,
    pub(super) conntrack_pressure_active: bool,
    pub(super) conntrack_event_queue_depth: u64,
    pub(super) conntrack_rule_apply_ok: bool,
    pub(super) conntrack_delete_attempt_total: u64,
    pub(super) conntrack_delete_success_total: u64,
    pub(super) conntrack_delete_not_found_total: u64,
    pub(super) conntrack_delete_error_total: u64,
    pub(super) conntrack_close_event_drop_total: u64,
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
    pub(super) tls_domains: Vec<TlsDomainLink>,
}

#[derive(Serialize)]
pub(super) struct TlsDomainLink {
    pub(super) domain: String,
    pub(super) link: String,
}

#[derive(Serialize)]
pub(super) struct UserInfo {
    pub(super) username: String,
    pub(super) in_runtime: bool,
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
pub(super) struct UserActiveIps {
    pub(super) username: String,
    pub(super) active_ips: Vec<IpAddr>,
}

#[derive(Serialize)]
pub(super) struct CreateUserResponse {
    pub(super) user: UserInfo,
    pub(super) secret: String,
}

#[derive(Serialize)]
pub(super) struct DeleteUserResponse {
    pub(super) username: String,
    pub(super) in_runtime: bool,
}

#[derive(Serialize)]
pub(super) struct ResetUserQuotaResponse {
    pub(super) username: String,
    pub(super) used_bytes: u64,
    pub(super) last_reset_epoch_secs: u64,
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
    #[serde(default, deserialize_with = "patch_field")]
    pub(super) user_ad_tag: Patch<String>,
    #[serde(default, deserialize_with = "patch_field")]
    pub(super) max_tcp_conns: Patch<usize>,
    #[serde(default, deserialize_with = "patch_field")]
    pub(super) expiration_rfc3339: Patch<String>,
    #[serde(default, deserialize_with = "patch_field")]
    pub(super) data_quota_bytes: Patch<u64>,
    #[serde(default, deserialize_with = "patch_field")]
    pub(super) max_unique_ips: Patch<usize>,
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

pub(super) fn parse_patch_expiration(
    value: &Patch<String>,
) -> Result<Patch<DateTime<Utc>>, ApiFailure> {
    match value {
        Patch::Unchanged => Ok(Patch::Unchanged),
        Patch::Remove => Ok(Patch::Remove),
        Patch::Set(raw) => {
            let parsed = DateTime::parse_from_rfc3339(raw)
                .map_err(|_| ApiFailure::bad_request("expiration_rfc3339 must be valid RFC3339"))?;
            Ok(Patch::Set(parsed.with_timezone(&Utc)))
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    // ============= ApiFailure constructors =============

    #[test]
    fn api_failure_internal_uses_500_with_internal_error_code() {
        let f = ApiFailure::internal("boom");
        assert_eq!(f.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(f.code, "internal_error");
        assert_eq!(f.message, "boom");
    }

    #[test]
    fn api_failure_bad_request_uses_400_with_bad_request_code() {
        let f = ApiFailure::bad_request("nope");
        assert_eq!(f.status, StatusCode::BAD_REQUEST);
        assert_eq!(f.code, "bad_request");
        assert_eq!(f.message, "nope");
    }

    #[test]
    fn api_failure_new_preserves_caller_supplied_fields() {
        let f = ApiFailure::new(StatusCode::CONFLICT, "user_exists", "duplicate");
        assert_eq!(f.status, StatusCode::CONFLICT);
        assert_eq!(f.code, "user_exists");
        assert_eq!(f.message, "duplicate");
    }

    // ============= parse_optional_expiration =============

    #[test]
    fn parse_optional_expiration_returns_none_for_none() {
        let r = parse_optional_expiration(None).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn parse_optional_expiration_accepts_zulu_rfc3339() {
        let r = parse_optional_expiration(Some("2030-01-02T03:04:05Z")).unwrap();
        let dt = r.unwrap();
        assert_eq!(dt.to_rfc3339(), "2030-01-02T03:04:05+00:00");
    }

    #[test]
    fn parse_optional_expiration_accepts_offset_rfc3339() {
        let r = parse_optional_expiration(Some("2030-01-02T03:04:05+02:00")).unwrap();
        let dt = r.unwrap();
        // The result must be normalized to UTC.
        assert_eq!(dt.to_rfc3339(), "2030-01-02T01:04:05+00:00");
    }

    #[test]
    fn parse_optional_expiration_rejects_garbage() {
        let err = parse_optional_expiration(Some("not-a-date")).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("RFC3339"));
    }

    #[test]
    fn parse_optional_expiration_rejects_naive_datetime_without_offset() {
        // RFC3339 requires a timezone offset; chrono refuses a bare timestamp.
        let err = parse_optional_expiration(Some("2030-01-02T03:04:05")).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    // ============= parse_patch_expiration =============

    #[test]
    fn parse_patch_expiration_pass_through_unchanged_and_remove() {
        assert!(matches!(
            parse_patch_expiration(&Patch::Unchanged).unwrap(),
            Patch::Unchanged
        ));
        assert!(matches!(
            parse_patch_expiration(&Patch::Remove).unwrap(),
            Patch::Remove
        ));
    }

    #[test]
    fn parse_patch_expiration_parses_valid_set_value() {
        let out = parse_patch_expiration(&Patch::Set("2031-06-15T12:00:00Z".into())).unwrap();
        match out {
            Patch::Set(dt) => assert_eq!(dt.to_rfc3339(), "2031-06-15T12:00:00+00:00"),
            _ => panic!("expected Patch::Set"),
        }
    }

    #[test]
    fn parse_patch_expiration_rejects_bad_rfc3339() {
        let err = parse_patch_expiration(&Patch::Set("garbage".into())).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("RFC3339"));
    }

    // ============= is_valid_user_secret =============

    #[test]
    fn user_secret_accepts_exactly_32_hex_chars() {
        assert!(is_valid_user_secret("0123456789abcdef0123456789ABCDEF"));
        assert!(is_valid_user_secret("00000000000000000000000000000000"));
        assert!(is_valid_user_secret("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));
    }

    #[test]
    fn user_secret_rejects_wrong_length() {
        assert!(!is_valid_user_secret(""));
        // 31 chars
        assert!(!is_valid_user_secret("0123456789abcdef0123456789abcde"));
        // 33 chars
        assert!(!is_valid_user_secret("0123456789abcdef0123456789abcdefa"));
    }

    #[test]
    fn user_secret_rejects_non_hex_chars() {
        // Has a 'g' which is not hex.
        assert!(!is_valid_user_secret("g123456789abcdef0123456789abcdef"));
        // Has whitespace.
        assert!(!is_valid_user_secret("0123456789abcdef0123456789abcde "));
        // Has unicode.
        assert!(!is_valid_user_secret("zzzz4567890abcdef0123456789abcde"));
    }

    // ============= is_valid_ad_tag =============

    #[test]
    fn ad_tag_follows_same_rules_as_user_secret() {
        // ad_tag is byte-for-byte identical contract (32 hex chars).
        assert!(is_valid_ad_tag("0123456789abcdef0123456789abcdef"));
        assert!(!is_valid_ad_tag("not-an-ad-tag"));
        assert!(!is_valid_ad_tag(""));
    }

    // ============= is_valid_username =============

    #[test]
    fn username_accepts_alnum_and_safe_punct() {
        assert!(is_valid_username("alice"));
        assert!(is_valid_username("user_42"));
        assert!(is_valid_username("foo-bar.baz"));
        assert!(is_valid_username("A"));
        // Boundary: exactly MAX_USERNAME_LEN must pass.
        let max = "a".repeat(MAX_USERNAME_LEN);
        assert!(is_valid_username(&max));
    }

    #[test]
    fn username_rejects_empty_and_oversized() {
        assert!(!is_valid_username(""));
        let too_long = "a".repeat(MAX_USERNAME_LEN + 1);
        assert!(!is_valid_username(&too_long));
    }

    #[test]
    fn username_rejects_unsafe_chars() {
        assert!(!is_valid_username("alice/bob"));
        assert!(!is_valid_username("user space"));
        assert!(!is_valid_username("user@host"));
        assert!(!is_valid_username("user;rm -rf /"));
        assert!(!is_valid_username("ümlaut"));
    }

    // ============= random_user_secret =============

    #[test]
    fn random_user_secret_returns_valid_hex_secret() {
        let s = random_user_secret();
        assert!(is_valid_user_secret(&s));
    }

    #[test]
    fn random_user_secret_does_not_repeat() {
        let a = random_user_secret();
        let b = random_user_secret();
        // 128 bits of entropy: collision probability is negligible.
        assert_ne!(a, b);
    }

    // ============= Request deserialization =============

    #[test]
    fn create_user_request_deserializes_minimum_fields() {
        let raw = r#"{"username": "alice"}"#;
        let req: CreateUserRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.username, "alice");
        assert!(req.secret.is_none());
        assert!(req.user_ad_tag.is_none());
        assert!(req.max_tcp_conns.is_none());
        assert!(req.expiration_rfc3339.is_none());
        assert!(req.data_quota_bytes.is_none());
        assert!(req.max_unique_ips.is_none());
    }

    #[test]
    fn create_user_request_deserializes_all_fields() {
        let raw = r#"{
            "username": "bob",
            "secret": "0123456789abcdef0123456789abcdef",
            "user_ad_tag": "fedcba9876543210fedcba9876543210",
            "max_tcp_conns": 100,
            "expiration_rfc3339": "2030-01-02T03:04:05Z",
            "data_quota_bytes": 1048576,
            "max_unique_ips": 8
        }"#;
        let req: CreateUserRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.username, "bob");
        assert_eq!(req.max_tcp_conns, Some(100));
        assert_eq!(req.data_quota_bytes, Some(1_048_576));
        assert_eq!(req.max_unique_ips, Some(8));
    }

    #[test]
    fn rotate_secret_request_defaults_secret_to_none() {
        let r = RotateSecretRequest::default();
        assert!(r.secret.is_none());
        let r: RotateSecretRequest = serde_json::from_str("{}").unwrap();
        assert!(r.secret.is_none());
        let r: RotateSecretRequest = serde_json::from_str(r#"{"secret": "abc"}"#).unwrap();
        assert_eq!(r.secret.as_deref(), Some("abc"));
    }
}
