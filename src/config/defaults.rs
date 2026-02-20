use std::net::IpAddr;
use std::collections::HashMap;
use serde::Deserialize;

// Helper defaults kept private to the config module.
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

pub(crate) fn default_metrics_whitelist() -> Vec<IpAddr> {
    vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()]
}

pub(crate) fn default_prefer_4() -> u8 {
    4
}

pub(crate) fn default_unknown_dc_log_path() -> Option<String> {
    Some("unknown-dc.txt".to_string())
}

pub(crate) fn default_pool_size() -> usize {
    2
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
