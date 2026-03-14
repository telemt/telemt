#![allow(clippy::missing_const_for_fn)]

use std::collections::HashMap;
use ipnetwork::IpNetwork;
use serde::Deserialize;

// Helper defaults kept private to the config module.
const DEFAULT_NETWORK_IPV6: Option<bool> = Some(false);
const DEFAULT_STUN_TCP_FALLBACK: bool = true;
const DEFAULT_MIDDLE_PROXY_WARM_STANDBY: usize = 16;
const DEFAULT_ME_RECONNECT_MAX_CONCURRENT_PER_DC: u32 = 8;
const DEFAULT_ME_RECONNECT_FAST_RETRY_COUNT: u32 = 16;
const DEFAULT_ME_SINGLE_ENDPOINT_SHADOW_WRITERS: u8 = 2;
const DEFAULT_ME_ADAPTIVE_FLOOR_IDLE_SECS: u64 = 90;
const DEFAULT_ME_ADAPTIVE_FLOOR_MIN_WRITERS_SINGLE_ENDPOINT: u8 = 1;
const DEFAULT_ME_ADAPTIVE_FLOOR_MIN_WRITERS_MULTI_ENDPOINT: u8 = 1;
const DEFAULT_ME_ADAPTIVE_FLOOR_RECOVER_GRACE_SECS: u64 = 180;
const DEFAULT_ME_ADAPTIVE_FLOOR_WRITERS_PER_CORE_TOTAL: u16 = 48;
const DEFAULT_ME_ADAPTIVE_FLOOR_CPU_CORES_OVERRIDE: u16 = 0;
const DEFAULT_ME_ADAPTIVE_FLOOR_MAX_EXTRA_WRITERS_SINGLE_PER_CORE: u16 = 1;
const DEFAULT_ME_ADAPTIVE_FLOOR_MAX_EXTRA_WRITERS_MULTI_PER_CORE: u16 = 2;
const DEFAULT_ME_ADAPTIVE_FLOOR_MAX_ACTIVE_WRITERS_PER_CORE: u16 = 64;
const DEFAULT_ME_ADAPTIVE_FLOOR_MAX_WARM_WRITERS_PER_CORE: u16 = 64;
const DEFAULT_ME_ADAPTIVE_FLOOR_MAX_ACTIVE_WRITERS_GLOBAL: u32 = 256;
const DEFAULT_ME_ADAPTIVE_FLOOR_MAX_WARM_WRITERS_GLOBAL: u32 = 256;
const DEFAULT_ME_WRITER_CMD_CHANNEL_CAPACITY: usize = 4096;
const DEFAULT_ME_ROUTE_CHANNEL_CAPACITY: usize = 768;
const DEFAULT_ME_C2ME_CHANNEL_CAPACITY: usize = 1024;
const DEFAULT_ME_READER_ROUTE_DATA_WAIT_MS: u64 = 2;
const DEFAULT_ME_D2C_FLUSH_BATCH_MAX_FRAMES: usize = 32;
const DEFAULT_ME_D2C_FLUSH_BATCH_MAX_BYTES: usize = 128 * 1024;
const DEFAULT_ME_D2C_FLUSH_BATCH_MAX_DELAY_US: u64 = 1500;
const DEFAULT_ME_D2C_ACK_FLUSH_IMMEDIATE: bool = false;
const DEFAULT_DIRECT_RELAY_COPY_BUF_C2S_BYTES: usize = 64 * 1024;
const DEFAULT_DIRECT_RELAY_COPY_BUF_S2C_BYTES: usize = 256 * 1024;
const DEFAULT_ME_WRITER_PICK_SAMPLE_SIZE: u8 = 3;
const DEFAULT_ME_HEALTH_INTERVAL_MS_UNHEALTHY: u64 = 1000;
const DEFAULT_ME_HEALTH_INTERVAL_MS_HEALTHY: u64 = 3000;
const DEFAULT_ME_ADMISSION_POLL_MS: u64 = 1000;
const DEFAULT_ME_WARN_RATE_LIMIT_MS: u64 = 5000;
const DEFAULT_USER_MAX_UNIQUE_IPS_WINDOW_SECS: u64 = 30;
const DEFAULT_UPSTREAM_CONNECT_RETRY_ATTEMPTS: u32 = 2;
const DEFAULT_UPSTREAM_UNHEALTHY_FAIL_THRESHOLD: u32 = 5;
const DEFAULT_UPSTREAM_CONNECT_BUDGET_MS: u64 = 3000;
const DEFAULT_LISTEN_ADDR_IPV6: &str = "::";
const DEFAULT_ACCESS_USER: &str = "default";
// All-zeros is the conventional public-proxy secret for MTProto obfuscation.
// The secret identifies the *proxy* to connecting clients, NOT individual users.
// Telegram's own end-to-end encryption is independent of this value, so a
// public (zero) secret does not weaken message confidentiality.
// Operators who want to restrict access publish a non-zero secret; operators
// who want an open, freely-sharable proxy leave it at the default.  ASVS
// "weak default credential" rules do not apply here because exposure of this
// value by definition makes the proxy publicly accessible — which is the
// intended behaviour for share-to-groups deployments.
const DEFAULT_ACCESS_SECRET: &str = "00000000000000000000000000000000";

pub fn default_true() -> bool {
    true
}

pub fn default_port() -> u16 {
    443
}

pub fn default_tls_domain() -> String {
    "petrovich.ru".to_string()
}

pub fn default_mask_port() -> u16 {
    443
}

pub fn default_fake_cert_len() -> usize {
    2048
}

pub fn default_tls_front_dir() -> String {
    "tlsfront".to_string()
}

pub fn default_replay_check_len() -> usize {
    65_536
}

pub fn default_replay_window_secs() -> u64 {
    1800
}

pub fn default_handshake_timeout() -> u64 {
    30
}

pub fn default_connect_timeout() -> u64 {
    10
}

pub fn default_keepalive() -> u64 {
    60
}

pub fn default_ack_timeout() -> u64 {
    300
}
pub fn default_me_one_retry() -> u8 {
    12
}

pub fn default_me_one_timeout() -> u64 {
    1200
}

pub fn default_listen_addr() -> String {
    "0.0.0.0".to_string()
}

pub fn default_listen_addr_ipv4() -> Option<String> {
    Some(default_listen_addr())
}

pub fn default_weight() -> u16 {
    1
}

pub fn default_metrics_whitelist() -> Vec<IpNetwork> {
    vec![
        parse_ip_network_literal("127.0.0.1/32"),
        parse_ip_network_literal("::1/128"),
    ]
}

pub fn default_api_listen() -> String {
    "0.0.0.0:9091".to_string()
}

pub fn default_api_whitelist() -> Vec<IpNetwork> {
    vec![parse_ip_network_literal("127.0.0.0/8")]
}

fn parse_ip_network_literal(cidr: &str) -> IpNetwork {
    match cidr.parse::<IpNetwork>() {
        Ok(network) => network,
        Err(_) => std::process::abort(),
    }
}

pub fn default_api_request_body_limit_bytes() -> usize {
    64 * 1024
}

pub fn default_api_minimal_runtime_enabled() -> bool {
    true
}

pub fn default_api_minimal_runtime_cache_ttl_ms() -> u64 {
    1000
}

pub fn default_api_runtime_edge_enabled() -> bool { false }
pub fn default_api_runtime_edge_cache_ttl_ms() -> u64 { 1000 }
pub fn default_api_runtime_edge_top_n() -> usize { 10 }
pub fn default_api_runtime_edge_events_capacity() -> usize { 256 }

pub fn default_proxy_protocol_header_timeout_ms() -> u64 {
    500
}

pub fn default_prefer_4() -> u8 {
    4
}

pub fn default_network_ipv6() -> Option<bool> {
    DEFAULT_NETWORK_IPV6
}

pub fn default_stun_tcp_fallback() -> bool {
    DEFAULT_STUN_TCP_FALLBACK
}

pub fn default_unknown_dc_log_path() -> Option<String> {
    Some("unknown-dc.txt".to_string())
}

pub fn default_unknown_dc_file_log_enabled() -> bool {
    false
}

pub fn default_pool_size() -> usize {
    8
}

pub fn default_proxy_secret_path() -> Option<String> {
    Some("proxy-secret".to_string())
}

pub fn default_proxy_config_v4_cache_path() -> Option<String> {
    Some("cache/proxy-config-v4.txt".to_string())
}

pub fn default_proxy_config_v6_cache_path() -> Option<String> {
    Some("cache/proxy-config-v6.txt".to_string())
}

pub fn default_middle_proxy_nat_stun() -> Option<String> {
    None
}

pub fn default_middle_proxy_nat_stun_servers() -> Vec<String> {
    Vec::new()
}

pub fn default_stun_nat_probe_concurrency() -> usize {
    8
}

pub fn default_middle_proxy_warm_standby() -> usize {
    DEFAULT_MIDDLE_PROXY_WARM_STANDBY
}

pub fn default_me_init_retry_attempts() -> u32 {
    0
}

/// Base delay in milliseconds for the first ME init retry.
const DEFAULT_ME_INIT_RETRY_BACKOFF_BASE_MS: u64 = 2_000;

/// Maximum delay in milliseconds for ME init retries (exponential backoff cap).
const DEFAULT_ME_INIT_RETRY_BACKOFF_CAP_MS: u64 = 60_000;

/// Maximum number of simultaneous client connections accepted.
const DEFAULT_MAX_CONNECTIONS: usize = 10_000;

pub fn default_me_init_retry_backoff_base_ms() -> u64 {
    DEFAULT_ME_INIT_RETRY_BACKOFF_BASE_MS
}

pub fn default_me_init_retry_backoff_cap_ms() -> u64 {
    DEFAULT_ME_INIT_RETRY_BACKOFF_CAP_MS
}

pub fn default_max_connections() -> usize {
    DEFAULT_MAX_CONNECTIONS
}

pub fn default_me2dc_fallback() -> bool {
    true
}

pub fn default_keepalive_interval() -> u64 {
    8
}

pub fn default_keepalive_jitter() -> u64 {
    2
}

pub fn default_warmup_step_delay_ms() -> u64 {
    500
}

pub fn default_warmup_step_jitter_ms() -> u64 {
    300
}

pub fn default_reconnect_backoff_base_ms() -> u64 {
    500
}

pub fn default_reconnect_backoff_cap_ms() -> u64 {
    30_000
}

pub fn default_me_reconnect_max_concurrent_per_dc() -> u32 {
    DEFAULT_ME_RECONNECT_MAX_CONCURRENT_PER_DC
}

pub fn default_me_reconnect_fast_retry_count() -> u32 {
    DEFAULT_ME_RECONNECT_FAST_RETRY_COUNT
}

pub fn default_me_single_endpoint_shadow_writers() -> u8 {
    DEFAULT_ME_SINGLE_ENDPOINT_SHADOW_WRITERS
}

pub fn default_me_single_endpoint_outage_mode_enabled() -> bool {
    true
}

pub fn default_me_single_endpoint_outage_disable_quarantine() -> bool {
    true
}

pub fn default_me_single_endpoint_outage_backoff_min_ms() -> u64 {
    250
}

pub fn default_me_single_endpoint_outage_backoff_max_ms() -> u64 {
    3000
}

pub fn default_me_single_endpoint_shadow_rotate_every_secs() -> u64 {
    900
}

pub fn default_me_adaptive_floor_idle_secs() -> u64 {
    DEFAULT_ME_ADAPTIVE_FLOOR_IDLE_SECS
}

pub fn default_me_adaptive_floor_min_writers_single_endpoint() -> u8 {
    DEFAULT_ME_ADAPTIVE_FLOOR_MIN_WRITERS_SINGLE_ENDPOINT
}

pub fn default_me_adaptive_floor_min_writers_multi_endpoint() -> u8 {
    DEFAULT_ME_ADAPTIVE_FLOOR_MIN_WRITERS_MULTI_ENDPOINT
}

pub fn default_me_adaptive_floor_recover_grace_secs() -> u64 {
    DEFAULT_ME_ADAPTIVE_FLOOR_RECOVER_GRACE_SECS
}

pub fn default_me_adaptive_floor_writers_per_core_total() -> u16 {
    DEFAULT_ME_ADAPTIVE_FLOOR_WRITERS_PER_CORE_TOTAL
}

pub fn default_me_adaptive_floor_cpu_cores_override() -> u16 {
    DEFAULT_ME_ADAPTIVE_FLOOR_CPU_CORES_OVERRIDE
}

pub fn default_me_adaptive_floor_max_extra_writers_single_per_core() -> u16 {
    DEFAULT_ME_ADAPTIVE_FLOOR_MAX_EXTRA_WRITERS_SINGLE_PER_CORE
}

pub fn default_me_adaptive_floor_max_extra_writers_multi_per_core() -> u16 {
    DEFAULT_ME_ADAPTIVE_FLOOR_MAX_EXTRA_WRITERS_MULTI_PER_CORE
}

pub fn default_me_adaptive_floor_max_active_writers_per_core() -> u16 {
    DEFAULT_ME_ADAPTIVE_FLOOR_MAX_ACTIVE_WRITERS_PER_CORE
}

pub fn default_me_adaptive_floor_max_warm_writers_per_core() -> u16 {
    DEFAULT_ME_ADAPTIVE_FLOOR_MAX_WARM_WRITERS_PER_CORE
}

pub fn default_me_adaptive_floor_max_active_writers_global() -> u32 {
    DEFAULT_ME_ADAPTIVE_FLOOR_MAX_ACTIVE_WRITERS_GLOBAL
}

pub fn default_me_adaptive_floor_max_warm_writers_global() -> u32 {
    DEFAULT_ME_ADAPTIVE_FLOOR_MAX_WARM_WRITERS_GLOBAL
}

pub fn default_me_writer_cmd_channel_capacity() -> usize {
    DEFAULT_ME_WRITER_CMD_CHANNEL_CAPACITY
}

pub fn default_me_route_channel_capacity() -> usize {
    DEFAULT_ME_ROUTE_CHANNEL_CAPACITY
}

pub fn default_me_c2me_channel_capacity() -> usize {
    DEFAULT_ME_C2ME_CHANNEL_CAPACITY
}

pub fn default_me_reader_route_data_wait_ms() -> u64 {
    DEFAULT_ME_READER_ROUTE_DATA_WAIT_MS
}

pub fn default_me_d2c_flush_batch_max_frames() -> usize {
    DEFAULT_ME_D2C_FLUSH_BATCH_MAX_FRAMES
}

pub fn default_me_d2c_flush_batch_max_bytes() -> usize {
    DEFAULT_ME_D2C_FLUSH_BATCH_MAX_BYTES
}

pub fn default_me_d2c_flush_batch_max_delay_us() -> u64 {
    DEFAULT_ME_D2C_FLUSH_BATCH_MAX_DELAY_US
}

pub fn default_me_d2c_ack_flush_immediate() -> bool {
    DEFAULT_ME_D2C_ACK_FLUSH_IMMEDIATE
}

pub fn default_direct_relay_copy_buf_c2s_bytes() -> usize {
    DEFAULT_DIRECT_RELAY_COPY_BUF_C2S_BYTES
}

pub fn default_direct_relay_copy_buf_s2c_bytes() -> usize {
    DEFAULT_DIRECT_RELAY_COPY_BUF_S2C_BYTES
}

pub fn default_me_writer_pick_sample_size() -> u8 {
    DEFAULT_ME_WRITER_PICK_SAMPLE_SIZE
}

pub fn default_me_health_interval_ms_unhealthy() -> u64 {
    DEFAULT_ME_HEALTH_INTERVAL_MS_UNHEALTHY
}

pub fn default_me_health_interval_ms_healthy() -> u64 {
    DEFAULT_ME_HEALTH_INTERVAL_MS_HEALTHY
}

pub fn default_me_admission_poll_ms() -> u64 {
    DEFAULT_ME_ADMISSION_POLL_MS
}

pub fn default_me_warn_rate_limit_ms() -> u64 {
    DEFAULT_ME_WARN_RATE_LIMIT_MS
}

pub fn default_upstream_connect_retry_attempts() -> u32 {
    DEFAULT_UPSTREAM_CONNECT_RETRY_ATTEMPTS
}

pub fn default_upstream_connect_retry_backoff_ms() -> u64 {
    100
}

pub fn default_upstream_unhealthy_fail_threshold() -> u32 {
    DEFAULT_UPSTREAM_UNHEALTHY_FAIL_THRESHOLD
}

pub fn default_upstream_connect_budget_ms() -> u64 {
    DEFAULT_UPSTREAM_CONNECT_BUDGET_MS
}

pub fn default_upstream_connect_failfast_hard_errors() -> bool {
    false
}

pub fn default_rpc_proxy_req_every() -> u64 {
    0
}

pub fn default_crypto_pending_buffer() -> usize {
    256 * 1024
}

pub fn default_max_client_frame() -> usize {
    16 * 1024 * 1024
}

pub fn default_desync_all_full() -> bool {
    false
}

pub fn default_me_route_backpressure_base_timeout_ms() -> u64 {
    25
}

pub fn default_me_route_backpressure_high_timeout_ms() -> u64 {
    120
}

pub fn default_me_route_backpressure_high_watermark_pct() -> u8 {
    80
}

pub fn default_me_route_no_writer_wait_ms() -> u64 {
    250
}

pub fn default_me_route_inline_recovery_attempts() -> u32 {
    3
}

pub fn default_me_route_inline_recovery_wait_ms() -> u64 {
    3000
}

pub fn default_beobachten_minutes() -> u64 {
    10
}

pub fn default_beobachten_flush_secs() -> u64 {
    15
}

pub fn default_beobachten_file() -> String {
    "cache/beobachten.txt".to_string()
}

pub fn default_tls_new_session_tickets() -> u8 {
    0
}

pub fn default_tls_full_cert_ttl_secs() -> u64 {
    90
}

pub fn default_server_hello_delay_min_ms() -> u64 {
    0
}

pub fn default_server_hello_delay_max_ms() -> u64 {
    0
}

pub fn default_alpn_enforce() -> bool {
    true
}

pub fn default_stun_servers() -> Vec<String> {
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

pub fn default_http_ip_detect_urls() -> Vec<String> {
    vec![
        "https://ifconfig.me/ip".to_string(),
        "https://api.ipify.org".to_string(),
    ]
}

pub fn default_cache_public_ip_path() -> String {
    "cache/public_ip.txt".to_string()
}

pub fn default_proxy_secret_reload_secs() -> u64 {
    60 * 60
}

pub fn default_proxy_config_reload_secs() -> u64 {
    60 * 60
}

pub fn default_update_every_secs() -> u64 {
    5 * 60
}

pub fn default_update_every() -> Option<u64> {
    Some(default_update_every_secs())
}

pub fn default_me_reinit_every_secs() -> u64 {
    15 * 60
}

pub fn default_me_reinit_singleflight() -> bool {
    true
}

pub fn default_me_reinit_trigger_channel() -> usize {
    64
}

pub fn default_me_reinit_coalesce_window_ms() -> u64 {
    200
}

pub fn default_me_hardswap_warmup_delay_min_ms() -> u64 {
    1000
}

pub fn default_me_hardswap_warmup_delay_max_ms() -> u64 {
    2000
}

pub fn default_me_hardswap_warmup_extra_passes() -> u8 {
    3
}

pub fn default_me_hardswap_warmup_pass_backoff_base_ms() -> u64 {
    500
}

pub fn default_me_config_stable_snapshots() -> u8 {
    2
}

pub fn default_me_config_apply_cooldown_secs() -> u64 {
    300
}

pub fn default_me_snapshot_require_http_2xx() -> bool {
    true
}

pub fn default_me_snapshot_reject_empty_map() -> bool {
    true
}

pub fn default_me_snapshot_min_proxy_for_lines() -> u32 {
    1
}

pub fn default_proxy_secret_stable_snapshots() -> u8 {
    2
}

pub fn default_proxy_secret_rotate_runtime() -> bool {
    true
}

pub fn default_me_secret_atomic_snapshot() -> bool {
    true
}

pub fn default_proxy_secret_len_max() -> usize {
    256
}

pub fn default_me_reinit_drain_timeout_secs() -> u64 {
    120
}

pub fn default_me_pool_drain_ttl_secs() -> u64 {
    90
}

pub fn default_me_bind_stale_ttl_secs() -> u64 {
    default_me_pool_drain_ttl_secs()
}

pub fn default_me_pool_min_fresh_ratio() -> f32 {
    0.8
}

pub fn default_me_deterministic_writer_sort() -> bool {
    true
}

pub fn default_hardswap() -> bool {
    true
}

pub fn default_ntp_check() -> bool {
    true
}

pub fn default_ntp_servers() -> Vec<String> {
    vec!["pool.ntp.org".to_string()]
}

pub fn default_fast_mode_min_tls_record() -> usize {
    0
}

pub fn default_degradation_min_unavailable_dc_groups() -> u8 {
    2
}

pub fn default_listen_addr_ipv6() -> String {
    DEFAULT_LISTEN_ADDR_IPV6.to_string()
}

pub fn default_listen_addr_ipv6_opt() -> Option<String> {
    Some(default_listen_addr_ipv6())
}

pub fn default_access_users() -> HashMap<String, String> {
    HashMap::from([(
        DEFAULT_ACCESS_USER.to_string(),
        DEFAULT_ACCESS_SECRET.to_string(),
    )])
}

pub fn default_user_max_unique_ips_window_secs() -> u64 {
    DEFAULT_USER_MAX_UNIQUE_IPS_WINDOW_SECS
}

// Custom deserializer helpers

#[derive(Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

pub fn deserialize_dc_overrides<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, Vec<String>>, D::Error>
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

#[cfg(test)]
mod tests {
    use super::{default_api_whitelist, default_metrics_whitelist};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn metrics_whitelist_contains_localhost_v4_and_v6() {
        let whitelist = default_metrics_whitelist();
        let localhost_v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let localhost_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);

        assert_eq!(whitelist.len(), 2);
        assert!(whitelist.iter().any(|net| net.contains(localhost_v4)));
        assert!(whitelist.iter().any(|net| net.contains(localhost_v6)));
    }

    #[test]
    fn api_whitelist_limits_to_local_v4_block() {
        let whitelist = default_api_whitelist();

        assert_eq!(whitelist.len(), 1);
        assert!(whitelist.iter().any(|net| net.contains(IpAddr::V4(Ipv4Addr::LOCALHOST))));
        assert!(!whitelist.iter().any(|net| net.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))));
    }
}
