use std::collections::HashMap;

use serde::Deserialize;

use super::*;

pub(crate) fn default_me_writer_pick_sample_size() -> u8 {
    DEFAULT_ME_WRITER_PICK_SAMPLE_SIZE
}

pub(crate) fn default_me_health_interval_ms_unhealthy() -> u64 {
    DEFAULT_ME_HEALTH_INTERVAL_MS_UNHEALTHY
}

pub(crate) fn default_me_health_interval_ms_healthy() -> u64 {
    DEFAULT_ME_HEALTH_INTERVAL_MS_HEALTHY
}

pub(crate) fn default_me_admission_poll_ms() -> u64 {
    DEFAULT_ME_ADMISSION_POLL_MS
}

pub(crate) fn default_me_warn_rate_limit_ms() -> u64 {
    DEFAULT_ME_WARN_RATE_LIMIT_MS
}

pub(crate) fn default_me_route_hybrid_max_wait_ms() -> u64 {
    DEFAULT_ME_ROUTE_HYBRID_MAX_WAIT_MS
}

pub(crate) fn default_me_route_blocking_send_timeout_ms() -> u64 {
    DEFAULT_ME_ROUTE_BLOCKING_SEND_TIMEOUT_MS
}

pub(crate) fn default_me_c2me_send_timeout_ms() -> u64 {
    DEFAULT_ME_C2ME_SEND_TIMEOUT_MS
}

pub(crate) fn default_upstream_connect_retry_attempts() -> u32 {
    DEFAULT_UPSTREAM_CONNECT_RETRY_ATTEMPTS
}

pub(crate) fn default_upstream_connect_retry_backoff_ms() -> u64 {
    100
}

pub(crate) fn default_upstream_unhealthy_fail_threshold() -> u32 {
    DEFAULT_UPSTREAM_UNHEALTHY_FAIL_THRESHOLD
}

pub(crate) fn default_upstream_connect_budget_ms() -> u64 {
    DEFAULT_UPSTREAM_CONNECT_BUDGET_MS
}

pub(crate) fn default_upstream_connect_failfast_hard_errors() -> bool {
    false
}

pub(crate) fn default_rpc_proxy_req_every() -> u64 {
    0
}

pub(crate) fn default_crypto_pending_buffer() -> usize {
    256 * 1024
}

pub(crate) fn default_max_client_frame() -> usize {
    16 * 1024 * 1024
}

pub(crate) fn default_desync_all_full() -> bool {
    false
}

pub(crate) fn default_me_route_backpressure_base_timeout_ms() -> u64 {
    25
}

pub(crate) fn default_me_route_backpressure_enabled() -> bool {
    DEFAULT_ME_ROUTE_BACKPRESSURE_ENABLED
}

pub(crate) fn default_me_route_fairshare_enabled() -> bool {
    DEFAULT_ME_ROUTE_FAIRSHARE_ENABLED
}

pub(crate) fn default_me_route_backpressure_high_timeout_ms() -> u64 {
    120
}

pub(crate) fn default_me_route_backpressure_high_watermark_pct() -> u8 {
    80
}

pub(crate) fn default_me_route_no_writer_wait_ms() -> u64 {
    250
}

pub(crate) fn default_me_route_inline_recovery_attempts() -> u32 {
    3
}

pub(crate) fn default_me_route_inline_recovery_wait_ms() -> u64 {
    3000
}

pub(crate) fn default_beobachten_minutes() -> u64 {
    10
}

pub(crate) fn default_beobachten_flush_secs() -> u64 {
    15
}

pub(crate) fn default_beobachten_file() -> String {
    "beobachten.txt".to_string()
}

pub(crate) fn default_tls_new_session_tickets() -> u8 {
    0
}

pub(crate) fn default_serverhello_compact() -> bool {
    false
}

pub(crate) fn default_tls_full_cert_ttl_secs() -> u64 {
    90
}

pub(crate) fn default_server_hello_delay_min_ms() -> u64 {
    8
}

pub(crate) fn default_server_hello_delay_max_ms() -> u64 {
    24
}

pub(crate) fn default_alpn_enforce() -> bool {
    true
}

pub(crate) fn default_mask_shape_hardening() -> bool {
    true
}

pub(crate) fn default_mask_shape_hardening_aggressive_mode() -> bool {
    false
}

pub(crate) fn default_mask_shape_bucket_floor_bytes() -> usize {
    512
}

pub(crate) fn default_mask_shape_bucket_cap_bytes() -> usize {
    4096
}

pub(crate) fn default_mask_shape_above_cap_blur() -> bool {
    false
}

pub(crate) fn default_mask_shape_above_cap_blur_max_bytes() -> usize {
    512
}

#[cfg(not(test))]
pub(crate) fn default_mask_relay_max_bytes() -> usize {
    5 * 1024 * 1024
}

#[cfg(test)]
pub(crate) fn default_mask_relay_max_bytes() -> usize {
    32 * 1024
}

#[cfg(not(test))]
pub(crate) fn default_mask_relay_timeout_ms() -> u64 {
    60_000
}

#[cfg(test)]
pub(crate) fn default_mask_relay_timeout_ms() -> u64 {
    200
}

#[cfg(not(test))]
pub(crate) fn default_mask_relay_idle_timeout_ms() -> u64 {
    5_000
}

#[cfg(test)]
pub(crate) fn default_mask_relay_idle_timeout_ms() -> u64 {
    100
}

pub(crate) fn default_mask_classifier_prefetch_timeout_ms() -> u64 {
    5
}

pub(crate) fn default_mask_timing_normalization_enabled() -> bool {
    false
}

pub(crate) fn default_mask_timing_normalization_floor_ms() -> u64 {
    0
}

pub(crate) fn default_mask_timing_normalization_ceiling_ms() -> u64 {
    0
}

pub(crate) fn default_stun_servers() -> Vec<String> {
    vec![
        "stun.l.google.com:5349".to_string(),
        "stun1.l.google.com:3478".to_string(),
        "stun.gmx.net:3478".to_string(),
        "stun.l.google.com:19302".to_string(),
        "stun.1und1.de:3478".to_string(),
        "stun1.l.google.com:19302".to_string(),
        "stun2.l.google.com:19302".to_string(),
        "stun3.l.google.com:19302".to_string(),
        "stun4.l.google.com:19302".to_string(),
        "stun.services.mozilla.com:3478".to_string(),
        "stun.stunprotocol.org:3478".to_string(),
        "stun.nextcloud.com:3478".to_string(),
        "stun.voip.eutelia.it:3478".to_string(),
    ]
}

pub(crate) fn default_http_ip_detect_urls() -> Vec<String> {
    vec![
        "https://ifconfig.me/ip".to_string(),
        "https://api.ipify.org".to_string(),
    ]
}

pub(crate) fn default_cache_public_ip_path() -> String {
    "cache/public_ip.txt".to_string()
}

pub(crate) fn default_proxy_secret_reload_secs() -> u64 {
    60 * 60
}

pub(crate) fn default_proxy_config_reload_secs() -> u64 {
    60 * 60
}

pub(crate) fn default_update_every_secs() -> u64 {
    5 * 60
}

pub(crate) fn default_update_every() -> Option<u64> {
    Some(default_update_every_secs())
}

pub(crate) fn default_me_reinit_every_secs() -> u64 {
    15 * 60
}

pub(crate) fn default_me_reinit_singleflight() -> bool {
    true
}

pub(crate) fn default_me_reinit_max_concurrency() -> usize {
    2
}

pub(crate) fn default_me_reinit_trigger_channel() -> usize {
    64
}

pub(crate) fn default_me_reinit_coalesce_window_ms() -> u64 {
    200
}

pub(crate) fn default_me_hardswap_warmup_delay_min_ms() -> u64 {
    1000
}

pub(crate) fn default_me_hardswap_warmup_delay_max_ms() -> u64 {
    2000
}

pub(crate) fn default_me_hardswap_warmup_extra_passes() -> u8 {
    3
}

pub(crate) fn default_me_hardswap_warmup_pass_backoff_base_ms() -> u64 {
    500
}

pub(crate) fn default_me_config_stable_snapshots() -> u8 {
    2
}

pub(crate) fn default_me_config_apply_cooldown_secs() -> u64 {
    300
}

pub(crate) fn default_me_snapshot_require_http_2xx() -> bool {
    true
}

pub(crate) fn default_me_snapshot_reject_empty_map() -> bool {
    true
}

pub(crate) fn default_me_snapshot_min_proxy_for_lines() -> u32 {
    1
}

pub(crate) fn default_proxy_secret_stable_snapshots() -> u8 {
    2
}

pub(crate) fn default_proxy_secret_rotate_runtime() -> bool {
    true
}

pub(crate) fn default_me_secret_atomic_snapshot() -> bool {
    true
}

pub(crate) fn default_proxy_secret_len_max() -> usize {
    256
}

pub(crate) fn default_me_reinit_drain_timeout_secs() -> u64 {
    90
}

pub(crate) fn default_me_pool_drain_ttl_secs() -> u64 {
    90
}

pub(crate) fn default_me_instadrain() -> bool {
    false
}

pub(crate) fn default_me_pool_drain_threshold() -> u64 {
    32
}

pub(crate) fn default_me_pool_drain_soft_evict_enabled() -> bool {
    DEFAULT_ME_POOL_DRAIN_SOFT_EVICT_ENABLED
}

pub(crate) fn default_me_pool_drain_soft_evict_grace_secs() -> u64 {
    DEFAULT_ME_POOL_DRAIN_SOFT_EVICT_GRACE_SECS
}

pub(crate) fn default_me_pool_drain_soft_evict_per_writer() -> u8 {
    DEFAULT_ME_POOL_DRAIN_SOFT_EVICT_PER_WRITER
}

pub(crate) fn default_me_pool_drain_soft_evict_budget_per_core() -> u16 {
    DEFAULT_ME_POOL_DRAIN_SOFT_EVICT_BUDGET_PER_CORE
}

pub(crate) fn default_me_pool_drain_soft_evict_cooldown_ms() -> u64 {
    DEFAULT_ME_POOL_DRAIN_SOFT_EVICT_COOLDOWN_MS
}

pub(crate) fn default_me_bind_stale_ttl_secs() -> u64 {
    default_me_pool_drain_ttl_secs()
}

pub(crate) fn default_me_pool_min_fresh_ratio() -> f32 {
    0.8
}

pub(crate) fn default_me_deterministic_writer_sort() -> bool {
    true
}

pub(crate) fn default_hardswap() -> bool {
    true
}

pub(crate) fn default_ntp_check() -> bool {
    true
}

pub(crate) fn default_ntp_servers() -> Vec<String> {
    vec!["pool.ntp.org".to_string()]
}

pub(crate) fn default_fast_mode_min_tls_record() -> usize {
    0
}

pub(crate) fn default_degradation_min_unavailable_dc_groups() -> u8 {
    2
}

pub(crate) fn default_listen_addr_ipv6() -> String {
    DEFAULT_LISTEN_ADDR_IPV6.to_string()
}

pub(crate) fn default_listen_addr_ipv6_opt() -> Option<String> {
    Some(default_listen_addr_ipv6())
}

pub(crate) fn default_access_users() -> HashMap<String, String> {
    HashMap::from([(
        DEFAULT_ACCESS_USER.to_string(),
        DEFAULT_ACCESS_SECRET.to_string(),
    )])
}

pub(crate) fn default_user_max_unique_ips_window_secs() -> u64 {
    DEFAULT_USER_MAX_UNIQUE_IPS_WINDOW_SECS
}

pub(crate) fn default_user_max_tcp_conns_global_each() -> usize {
    0
}

pub(crate) fn default_user_max_unique_ips_global_each() -> usize {
    0
}

// Custom deserializer helpers

#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

pub(crate) fn deserialize_dc_overrides<'de, D>(
    deserializer: D,
) -> std::result::Result<HashMap<String, Vec<String>>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let raw: HashMap<String, OneOrMany> = HashMap::deserialize(deserializer)?;
    let mut out = HashMap::new();
    for (dc, val) in raw {
        let mut addrs = match val {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
        };
        addrs.retain(|s| !s.trim().is_empty());
        if !addrs.is_empty() {
            out.insert(dc, addrs);
        }
    }
    Ok(out)
}
