use std::collections::HashMap;
use ipnetwork::IpNetwork;
use serde::Deserialize;

// Helper defaults kept private to the config module.
const DEFAULT_NETWORK_IPV6: Option<bool> = Some(false);
const DEFAULT_STUN_TCP_FALLBACK: bool = true;
const DEFAULT_MIDDLE_PROXY_WARM_STANDBY: usize = 16;
const DEFAULT_ME_RECONNECT_MAX_CONCURRENT_PER_DC: u32 = 8;
const DEFAULT_ME_RECONNECT_FAST_RETRY_COUNT: u32 = 12;
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
    "www.google.com".to_string()
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
    1800
}

pub(crate) fn default_handshake_timeout() -> u64 {
    15
}

pub(crate) fn default_connect_timeout() -> u64 {
    10
}

pub(crate) fn default_keepalive() -> u64 {
    60
}

pub(crate) fn default_ack_timeout() -> u64 {
    300
}
pub(crate) fn default_me_one_retry() -> u8 {
    3
}

pub(crate) fn default_me_one_timeout() -> u64 {
    1500
}

pub(crate) fn default_listen_addr() -> String {
    "0.0.0.0".to_string()
}

pub(crate) fn default_weight() -> u16 {
    1
}

pub(crate) fn default_metrics_whitelist() -> Vec<IpNetwork> {
    vec![
        "127.0.0.1/32".parse().unwrap(),
        "::1/128".parse().unwrap(),
    ]
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

pub(crate) fn default_pool_size() -> usize {
    8
}

pub(crate) fn default_middle_proxy_warm_standby() -> usize {
    DEFAULT_MIDDLE_PROXY_WARM_STANDBY
}

pub(crate) fn default_keepalive_interval() -> u64 {
    25
}

pub(crate) fn default_keepalive_jitter() -> u64 {
    5
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

pub(crate) fn default_crypto_pending_buffer() -> usize {
    256 * 1024
}

pub(crate) fn default_max_client_frame() -> usize {
    16 * 1024 * 1024
}

pub(crate) fn default_desync_all_full() -> bool {
    false
}

pub(crate) fn default_beobachten_minutes() -> u64 {
    10
}

pub(crate) fn default_beobachten_flush_secs() -> u64 {
    15
}

pub(crate) fn default_beobachten_file() -> String {
    "cache/beobachten.txt".to_string()
}

pub(crate) fn default_tls_new_session_tickets() -> u8 {
    0
}

pub(crate) fn default_tls_full_cert_ttl_secs() -> u64 {
    90
}

pub(crate) fn default_server_hello_delay_min_ms() -> u64 {
    0
}

pub(crate) fn default_server_hello_delay_max_ms() -> u64 {
    0
}

pub(crate) fn default_alpn_enforce() -> bool {
    true
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

pub(crate) fn default_proxy_secret_stable_snapshots() -> u8 {
    2
}

pub(crate) fn default_proxy_secret_rotate_runtime() -> bool {
    true
}

pub(crate) fn default_proxy_secret_len_max() -> usize {
    256
}

pub(crate) fn default_me_reinit_drain_timeout_secs() -> u64 {
    120
}

pub(crate) fn default_me_pool_drain_ttl_secs() -> u64 {
    90
}

pub(crate) fn default_me_pool_min_fresh_ratio() -> f32 {
    0.8
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

pub(crate) fn default_access_users() -> HashMap<String, String> {
    HashMap::from([(
        DEFAULT_ACCESS_USER.to_string(),
        DEFAULT_ACCESS_SECRET.to_string(),
    )])
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
