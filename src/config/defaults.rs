use ipnetwork::IpNetwork;

// Extended transport, masking, and ME default values.
mod extended;

pub(crate) use extended::*;

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
const DEFAULT_ME_ROUTE_BACKPRESSURE_ENABLED: bool = false;
const DEFAULT_ME_ROUTE_FAIRSHARE_ENABLED: bool = false;
const DEFAULT_ME_WRITER_CMD_CHANNEL_CAPACITY: usize = 4096;
pub(crate) const ME_WRITER_BYTE_PERMIT_UNIT_BYTES: usize = 16 * 1024;
pub(crate) const ME_WRITER_FRAME_OVERHEAD_RESERVE_BYTES: usize = 256;
const DEFAULT_ME_WRITER_BYTE_BUDGET_BYTES: usize =
    32 * 1024 * 1024 + ME_WRITER_BYTE_PERMIT_UNIT_BYTES;
const DEFAULT_ME_ROUTE_CHANNEL_CAPACITY: usize = 768;
const DEFAULT_ME_C2ME_CHANNEL_CAPACITY: usize = 1024;
const DEFAULT_ME_READER_ROUTE_DATA_WAIT_MS: u64 = 2;
const DEFAULT_ME_D2C_FLUSH_BATCH_MAX_FRAMES: usize = 32;
const DEFAULT_ME_D2C_FLUSH_BATCH_MAX_BYTES: usize = 128 * 1024;
const DEFAULT_ME_D2C_FLUSH_BATCH_MAX_DELAY_US: u64 = 500;
const DEFAULT_ME_D2C_ACK_FLUSH_IMMEDIATE: bool = true;
const DEFAULT_ME_QUOTA_SOFT_OVERSHOOT_BYTES: u64 = 64 * 1024;
const DEFAULT_ME_D2C_FRAME_BUF_SHRINK_THRESHOLD_BYTES: usize = 256 * 1024;
const DEFAULT_DIRECT_RELAY_COPY_BUF_C2S_BYTES: usize = 64 * 1024;
const DEFAULT_DIRECT_RELAY_COPY_BUF_S2C_BYTES: usize = 256 * 1024;
pub(crate) const DIRECT_RELAY_BUFFER_BUDGET_UNIT_BYTES: usize = 4 * 1024;
const DEFAULT_DIRECT_RELAY_BUFFER_BUDGET_MAX_BYTES: usize = 0;
const DEFAULT_ME_WRITER_PICK_SAMPLE_SIZE: u8 = 3;
const DEFAULT_ME_HEALTH_INTERVAL_MS_UNHEALTHY: u64 = 1000;
const DEFAULT_ME_HEALTH_INTERVAL_MS_HEALTHY: u64 = 3000;
const DEFAULT_ME_ADMISSION_POLL_MS: u64 = 1000;
const DEFAULT_ME_WARN_RATE_LIMIT_MS: u64 = 5000;
const DEFAULT_ME_ROUTE_HYBRID_MAX_WAIT_MS: u64 = 3000;
const DEFAULT_ME_ROUTE_BLOCKING_SEND_TIMEOUT_MS: u64 = 250;
const DEFAULT_ME_C2ME_SEND_TIMEOUT_MS: u64 = 4000;
const DEFAULT_ME_POOL_DRAIN_SOFT_EVICT_ENABLED: bool = true;
const DEFAULT_ME_POOL_DRAIN_SOFT_EVICT_GRACE_SECS: u64 = 10;
const DEFAULT_ME_POOL_DRAIN_SOFT_EVICT_PER_WRITER: u8 = 2;
const DEFAULT_ME_POOL_DRAIN_SOFT_EVICT_BUDGET_PER_CORE: u16 = 16;
const DEFAULT_ME_POOL_DRAIN_SOFT_EVICT_COOLDOWN_MS: u64 = 1000;
const DEFAULT_USER_MAX_UNIQUE_IPS_WINDOW_SECS: u64 = 30;
const DEFAULT_ACCEPT_PERMIT_TIMEOUT_MS: u64 = 250;
const DEFAULT_CONNTRACK_CONTROL_ENABLED: bool = true;
const DEFAULT_CONNTRACK_PRESSURE_HIGH_WATERMARK_PCT: u8 = 85;
const DEFAULT_CONNTRACK_PRESSURE_LOW_WATERMARK_PCT: u8 = 70;
const DEFAULT_CONNTRACK_DELETE_BUDGET_PER_SEC: u64 = 4096;
const DEFAULT_SYNLIMIT_SECONDS: u32 = 60;
const DEFAULT_SYNLIMIT_HITCOUNT: u32 = 48;
const DEFAULT_SYNLIMIT_BURST: u32 = 24;
const DEFAULT_SYNLIMIT_IOS_SECONDS: u32 = 1;
const DEFAULT_SYNLIMIT_IOS_HITCOUNT: u32 = 12;
const DEFAULT_SYNLIMIT_IOS_BURST: u32 = 24;
const DEFAULT_SYNLIMIT_HASHLIMIT_EXPIRE_MS: u32 = 60_000;
const DEFAULT_SYNLIMIT_HASHLIMIT_SIZE: u32 = 32_768;
const DEFAULT_UPSTREAM_CONNECT_RETRY_ATTEMPTS: u32 = 2;
const DEFAULT_UPSTREAM_UNHEALTHY_FAIL_THRESHOLD: u32 = 5;
const DEFAULT_UPSTREAM_CONNECT_BUDGET_MS: u64 = 3000;
const DEFAULT_LISTEN_ADDR_IPV6: &str = "::";
const DEFAULT_ACCESS_USER: &str = "default";
const DEFAULT_ACCESS_SECRET: &str = "00000000000000000000000000000000";

pub(crate) fn default_true() -> bool {
    true
}

pub(crate) fn default_port() -> u16 {
    443
}

pub(crate) fn default_tls_domain() -> String {
    "petrovich.ru".to_string()
}

pub(crate) fn default_tls_fetch_scope() -> String {
    String::new()
}

pub(crate) fn default_tls_fetch_attempt_timeout_ms() -> u64 {
    5_000
}

pub(crate) fn default_tls_fetch_total_budget_ms() -> u64 {
    15_000
}

pub(crate) fn default_tls_fetch_strict_route() -> bool {
    true
}

pub(crate) fn default_tls_fetch_profile_cache_ttl_secs() -> u64 {
    600
}

pub(crate) fn default_mask_port() -> u16 {
    443
}

pub(crate) fn default_fake_cert_len() -> usize {
    2048
}

pub(crate) fn default_tls_front_dir() -> String {
    "tlsfront".to_string()
}

pub(crate) fn default_replay_check_len() -> usize {
    65_536
}

pub(crate) fn default_replay_window_secs() -> u64 {
    // Keep replay cache TTL tight by default to reduce replay surface.
    // Deployments with higher RTT or longer reconnect jitter can override this in config.
    120
}

pub(crate) fn default_handshake_timeout() -> u64 {
    60
}

pub(crate) fn default_client_first_byte_idle_secs() -> u64 {
    300
}

pub(crate) fn default_relay_idle_policy_v2_enabled() -> bool {
    true
}

pub(crate) fn default_relay_client_idle_soft_secs() -> u64 {
    120
}

pub(crate) fn default_relay_client_idle_hard_secs() -> u64 {
    360
}

pub(crate) fn default_relay_idle_grace_after_downstream_activity_secs() -> u64 {
    30
}

pub(crate) fn default_connect_timeout() -> u64 {
    10
}

pub(crate) fn default_keepalive() -> u64 {
    15
}

pub(crate) fn default_ack_timeout() -> u64 {
    90
}
pub(crate) fn default_me_one_retry() -> u8 {
    12
}

pub(crate) fn default_me_one_timeout() -> u64 {
    1200
}

pub(crate) fn default_listen_addr() -> String {
    "0.0.0.0".to_string()
}

pub(crate) fn default_listen_addr_ipv4() -> Option<String> {
    Some(default_listen_addr())
}

pub(crate) fn default_weight() -> u16 {
    1
}

pub(crate) fn default_metrics_whitelist() -> Vec<IpNetwork> {
    vec!["127.0.0.1/32".parse().unwrap(), "::1/128".parse().unwrap()]
}

pub(crate) fn default_api_listen() -> String {
    "0.0.0.0:9091".to_string()
}

pub(crate) fn default_api_whitelist() -> Vec<IpNetwork> {
    vec!["127.0.0.0/8".parse().unwrap()]
}

pub(crate) fn default_api_request_body_limit_bytes() -> usize {
    64 * 1024
}

pub(crate) fn default_api_minimal_runtime_enabled() -> bool {
    true
}

pub(crate) fn default_api_minimal_runtime_cache_ttl_ms() -> u64 {
    1000
}

pub(crate) fn default_api_runtime_edge_enabled() -> bool {
    false
}
pub(crate) fn default_api_runtime_edge_cache_ttl_ms() -> u64 {
    1000
}
pub(crate) fn default_api_runtime_edge_top_n() -> usize {
    10
}
pub(crate) fn default_api_runtime_edge_events_capacity() -> usize {
    256
}

pub(crate) fn default_proxy_protocol_header_timeout_ms() -> u64 {
    500
}

pub(crate) fn default_proxy_protocol_trusted_cidrs() -> Vec<IpNetwork> {
    vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()]
}

pub(crate) fn default_server_max_connections() -> u32 {
    10_000
}

pub(crate) fn default_listen_backlog() -> u32 {
    1024
}

pub(crate) fn default_accept_permit_timeout_ms() -> u64 {
    DEFAULT_ACCEPT_PERMIT_TIMEOUT_MS
}

pub(crate) fn default_conntrack_control_enabled() -> bool {
    DEFAULT_CONNTRACK_CONTROL_ENABLED
}

pub(crate) fn default_conntrack_pressure_high_watermark_pct() -> u8 {
    DEFAULT_CONNTRACK_PRESSURE_HIGH_WATERMARK_PCT
}

pub(crate) fn default_conntrack_pressure_low_watermark_pct() -> u8 {
    DEFAULT_CONNTRACK_PRESSURE_LOW_WATERMARK_PCT
}

pub(crate) fn default_conntrack_delete_budget_per_sec() -> u64 {
    DEFAULT_CONNTRACK_DELETE_BUDGET_PER_SEC
}

pub(crate) fn default_synlimit_seconds() -> u32 {
    DEFAULT_SYNLIMIT_SECONDS
}

pub(crate) fn default_synlimit_hitcount() -> u32 {
    DEFAULT_SYNLIMIT_HITCOUNT
}

pub(crate) fn default_synlimit_burst() -> u32 {
    DEFAULT_SYNLIMIT_BURST
}

pub(crate) fn default_synlimit_ios_seconds() -> u32 {
    DEFAULT_SYNLIMIT_IOS_SECONDS
}

pub(crate) fn default_synlimit_ios_hitcount() -> u32 {
    DEFAULT_SYNLIMIT_IOS_HITCOUNT
}

pub(crate) fn default_synlimit_ios_burst() -> u32 {
    DEFAULT_SYNLIMIT_IOS_BURST
}

pub(crate) fn default_synlimit_hashlimit_expire_ms() -> u32 {
    DEFAULT_SYNLIMIT_HASHLIMIT_EXPIRE_MS
}

pub(crate) fn default_synlimit_hashlimit_size() -> u32 {
    DEFAULT_SYNLIMIT_HASHLIMIT_SIZE
}

pub(crate) fn default_prefer_4() -> u8 {
    4
}

pub(crate) fn default_network_ipv6() -> Option<bool> {
    DEFAULT_NETWORK_IPV6
}

pub(crate) fn default_stun_tcp_fallback() -> bool {
    DEFAULT_STUN_TCP_FALLBACK
}

pub(crate) fn default_unknown_dc_log_path() -> Option<String> {
    Some("unknown-dc.txt".to_string())
}

pub(crate) fn default_unknown_dc_file_log_enabled() -> bool {
    false
}

pub(crate) fn default_pool_size() -> usize {
    8
}

pub(crate) fn default_proxy_secret_path() -> Option<String> {
    Some("proxy-secret".to_string())
}

pub(crate) fn default_proxy_config_v4_cache_path() -> Option<String> {
    Some("cache/proxy-config-v4.txt".to_string())
}

pub(crate) fn default_proxy_config_v6_cache_path() -> Option<String> {
    Some("cache/proxy-config-v6.txt".to_string())
}

pub(crate) fn default_middle_proxy_nat_stun() -> Option<String> {
    None
}

pub(crate) fn default_middle_proxy_nat_stun_servers() -> Vec<String> {
    Vec::new()
}

pub(crate) fn default_stun_nat_probe_concurrency() -> usize {
    8
}

pub(crate) fn default_middle_proxy_warm_standby() -> usize {
    DEFAULT_MIDDLE_PROXY_WARM_STANDBY
}

pub(crate) fn default_me_init_retry_attempts() -> u32 {
    0
}

pub(crate) fn default_me2dc_fallback() -> bool {
    true
}

pub(crate) fn default_me2dc_fast() -> bool {
    true
}

pub(crate) fn default_keepalive_interval() -> u64 {
    8
}

pub(crate) fn default_keepalive_jitter() -> u64 {
    2
}

pub(crate) fn default_warmup_step_delay_ms() -> u64 {
    500
}

pub(crate) fn default_warmup_step_jitter_ms() -> u64 {
    300
}

pub(crate) fn default_reconnect_backoff_base_ms() -> u64 {
    500
}

pub(crate) fn default_reconnect_backoff_cap_ms() -> u64 {
    30_000
}

pub(crate) fn default_me_reconnect_max_concurrent_per_dc() -> u32 {
    DEFAULT_ME_RECONNECT_MAX_CONCURRENT_PER_DC
}

pub(crate) fn default_me_reconnect_fast_retry_count() -> u32 {
    DEFAULT_ME_RECONNECT_FAST_RETRY_COUNT
}

pub(crate) fn default_me_single_endpoint_shadow_writers() -> u8 {
    DEFAULT_ME_SINGLE_ENDPOINT_SHADOW_WRITERS
}

pub(crate) fn default_me_single_endpoint_outage_mode_enabled() -> bool {
    true
}

pub(crate) fn default_me_single_endpoint_outage_disable_quarantine() -> bool {
    true
}

pub(crate) fn default_me_single_endpoint_outage_backoff_min_ms() -> u64 {
    250
}

pub(crate) fn default_me_single_endpoint_outage_backoff_max_ms() -> u64 {
    3000
}

pub(crate) fn default_me_single_endpoint_shadow_rotate_every_secs() -> u64 {
    900
}

pub(crate) fn default_me_adaptive_floor_idle_secs() -> u64 {
    DEFAULT_ME_ADAPTIVE_FLOOR_IDLE_SECS
}

pub(crate) fn default_me_adaptive_floor_min_writers_single_endpoint() -> u8 {
    DEFAULT_ME_ADAPTIVE_FLOOR_MIN_WRITERS_SINGLE_ENDPOINT
}

pub(crate) fn default_me_adaptive_floor_min_writers_multi_endpoint() -> u8 {
    DEFAULT_ME_ADAPTIVE_FLOOR_MIN_WRITERS_MULTI_ENDPOINT
}

pub(crate) fn default_me_adaptive_floor_recover_grace_secs() -> u64 {
    DEFAULT_ME_ADAPTIVE_FLOOR_RECOVER_GRACE_SECS
}

pub(crate) fn default_me_adaptive_floor_writers_per_core_total() -> u16 {
    DEFAULT_ME_ADAPTIVE_FLOOR_WRITERS_PER_CORE_TOTAL
}

pub(crate) fn default_me_adaptive_floor_cpu_cores_override() -> u16 {
    DEFAULT_ME_ADAPTIVE_FLOOR_CPU_CORES_OVERRIDE
}

pub(crate) fn default_me_adaptive_floor_max_extra_writers_single_per_core() -> u16 {
    DEFAULT_ME_ADAPTIVE_FLOOR_MAX_EXTRA_WRITERS_SINGLE_PER_CORE
}

pub(crate) fn default_me_adaptive_floor_max_extra_writers_multi_per_core() -> u16 {
    DEFAULT_ME_ADAPTIVE_FLOOR_MAX_EXTRA_WRITERS_MULTI_PER_CORE
}

pub(crate) fn default_me_adaptive_floor_max_active_writers_per_core() -> u16 {
    DEFAULT_ME_ADAPTIVE_FLOOR_MAX_ACTIVE_WRITERS_PER_CORE
}

pub(crate) fn default_me_adaptive_floor_max_warm_writers_per_core() -> u16 {
    DEFAULT_ME_ADAPTIVE_FLOOR_MAX_WARM_WRITERS_PER_CORE
}

pub(crate) fn default_me_adaptive_floor_max_active_writers_global() -> u32 {
    DEFAULT_ME_ADAPTIVE_FLOOR_MAX_ACTIVE_WRITERS_GLOBAL
}

pub(crate) fn default_me_adaptive_floor_max_warm_writers_global() -> u32 {
    DEFAULT_ME_ADAPTIVE_FLOOR_MAX_WARM_WRITERS_GLOBAL
}

pub(crate) fn default_me_writer_cmd_channel_capacity() -> usize {
    DEFAULT_ME_WRITER_CMD_CHANNEL_CAPACITY
}

pub(crate) fn default_me_writer_byte_budget_bytes() -> usize {
    DEFAULT_ME_WRITER_BYTE_BUDGET_BYTES
}

pub(crate) fn minimum_me_writer_byte_budget_bytes(max_client_frame: usize) -> usize {
    max_client_frame
        .saturating_mul(2)
        .saturating_add(ME_WRITER_FRAME_OVERHEAD_RESERVE_BYTES)
        .div_ceil(ME_WRITER_BYTE_PERMIT_UNIT_BYTES)
        .saturating_mul(ME_WRITER_BYTE_PERMIT_UNIT_BYTES)
}

pub(crate) fn default_me_route_channel_capacity() -> usize {
    DEFAULT_ME_ROUTE_CHANNEL_CAPACITY
}

pub(crate) fn default_me_c2me_channel_capacity() -> usize {
    DEFAULT_ME_C2ME_CHANNEL_CAPACITY
}

pub(crate) fn default_me_reader_route_data_wait_ms() -> u64 {
    DEFAULT_ME_READER_ROUTE_DATA_WAIT_MS
}

pub(crate) fn default_me_d2c_flush_batch_max_frames() -> usize {
    DEFAULT_ME_D2C_FLUSH_BATCH_MAX_FRAMES
}

pub(crate) fn default_me_d2c_flush_batch_max_bytes() -> usize {
    DEFAULT_ME_D2C_FLUSH_BATCH_MAX_BYTES
}

pub(crate) fn default_me_d2c_flush_batch_max_delay_us() -> u64 {
    DEFAULT_ME_D2C_FLUSH_BATCH_MAX_DELAY_US
}

pub(crate) fn default_me_d2c_ack_flush_immediate() -> bool {
    DEFAULT_ME_D2C_ACK_FLUSH_IMMEDIATE
}

pub(crate) fn default_me_quota_soft_overshoot_bytes() -> u64 {
    DEFAULT_ME_QUOTA_SOFT_OVERSHOOT_BYTES
}

pub(crate) fn default_me_d2c_frame_buf_shrink_threshold_bytes() -> usize {
    DEFAULT_ME_D2C_FRAME_BUF_SHRINK_THRESHOLD_BYTES
}

pub(crate) fn default_direct_relay_copy_buf_c2s_bytes() -> usize {
    DEFAULT_DIRECT_RELAY_COPY_BUF_C2S_BYTES
}

pub(crate) fn default_direct_relay_copy_buf_s2c_bytes() -> usize {
    DEFAULT_DIRECT_RELAY_COPY_BUF_S2C_BYTES
}

pub(crate) fn default_direct_relay_buffer_budget_max_bytes() -> usize {
    DEFAULT_DIRECT_RELAY_BUFFER_BUDGET_MAX_BYTES
}
