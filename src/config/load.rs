#![allow(deprecated)]

use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rand::RngExt;
use serde::{Deserialize, Serialize};
use shadowsocks::config::ServerConfig as ShadowsocksServerConfig;
use tracing::warn;

use crate::error::{ProxyError, Result};

use super::defaults::*;
use super::types::*;

const ACCESS_SECRET_BYTES: usize = 16;
const MAX_ME_WRITER_CMD_CHANNEL_CAPACITY: usize = 16_384;
const MAX_ME_ROUTE_CHANNEL_CAPACITY: usize = 8_192;
const MAX_ME_C2ME_CHANNEL_CAPACITY: usize = 8_192;
const MIN_MAX_CLIENT_FRAME_BYTES: usize = 4 * 1024;
const MAX_MAX_CLIENT_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_API_REQUEST_BODY_LIMIT_BYTES: usize = 1024 * 1024;

fn is_valid_tls_domain_name(domain: &str) -> bool {
    !domain.is_empty()
        && !domain
            .chars()
            .any(|ch| ch.is_whitespace() || matches!(ch, '/' | '\\'))
}

fn normalize_domain_to_ascii(domain: &str, field: &str) -> Result<String> {
    let domain = domain.trim();
    if !is_valid_tls_domain_name(domain) {
        return Err(ProxyError::Config(format!(
            "Invalid {field}: '{}'. Must be a valid domain name",
            domain
        )));
    }

    let parsed = url::Url::parse(&format!("https://{domain}/")).map_err(|error| {
        ProxyError::Config(format!(
            "Invalid {field}: '{}'. IDNA conversion failed: {error}",
            domain
        ))
    })?;
    let host = parsed.host_str().ok_or_else(|| {
        ProxyError::Config(format!("Invalid {field}: '{}'. Host is empty", domain))
    })?;
    Ok(host.to_ascii_lowercase())
}

fn normalize_mask_host_to_ascii(host: &str, field: &str) -> Result<String> {
    let host = host.trim();
    if host.starts_with('[') && host.ends_with(']') {
        let inner = &host[1..host.len() - 1];
        let ip = inner.parse::<std::net::IpAddr>().map_err(|_| {
            ProxyError::Config(format!(
                "Invalid {field}: '{}'. IPv6 literal is invalid",
                host
            ))
        })?;
        return match ip {
            std::net::IpAddr::V6(v6) => Ok(format!("[{v6}]")),
            std::net::IpAddr::V4(v4) => Ok(v4.to_string()),
        };
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => Ok(v4.to_string()),
            std::net::IpAddr::V6(v6) => Ok(format!("[{v6}]")),
        };
    }

    normalize_domain_to_ascii(host, field)
}

fn parse_exclusive_mask_target(target: &str) -> Option<(&str, u16)> {
    let target = target.trim();
    if target.is_empty() {
        return None;
    }

    if target.starts_with('[') {
        let end = target.find(']')?;
        if target.get(end + 1..end + 2)? != ":" {
            return None;
        }
        let host = &target[..=end];
        let port = target[end + 2..].parse::<u16>().ok()?;
        return (port > 0).then_some((host, port));
    }

    let (host, port) = target.rsplit_once(':')?;
    if host.is_empty() || host.contains(':') {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    (port > 0).then_some((host, port))
}

fn normalize_exclusive_mask_target(target: &str, field: &str) -> Result<String> {
    let (host, port) = parse_exclusive_mask_target(target).ok_or_else(|| {
        ProxyError::Config(format!(
            "Invalid {field}: '{}'. Expected host:port with port > 0",
            target
        ))
    })?;
    let host = normalize_mask_host_to_ascii(host, field)?;
    Ok(format!("{host}:{port}"))
}

const TOP_LEVEL_CONFIG_KEYS: &[&str] = &[
    "general",
    "logging",
    "network",
    "server",
    "timeouts",
    "censorship",
    "access",
    "upstreams",
    "show_link",
    "dc_overrides",
    "default_dc",
    "beobachten",
    "beobachten_minutes",
    "beobachten_flush_secs",
    "beobachten_file",
    "include",
];

const GENERAL_CONFIG_KEYS: &[&str] = &[
    "data_path",
    "quota_state_path",
    "config_strict",
    "modes",
    "prefer_ipv6",
    "fast_mode",
    "use_middle_proxy",
    "proxy_secret_path",
    "proxy_secret_url",
    "proxy_config_v4_cache_path",
    "proxy_config_v4_url",
    "proxy_config_v6_cache_path",
    "proxy_config_v6_url",
    "ad_tag",
    "middle_proxy_nat_ip",
    "middle_proxy_nat_probe",
    "middle_proxy_nat_stun",
    "middle_proxy_nat_stun_servers",
    "stun_nat_probe_concurrency",
    "middle_proxy_pool_size",
    "middle_proxy_warm_standby",
    "me_init_retry_attempts",
    "me2dc_fallback",
    "me2dc_fast",
    "me_keepalive_enabled",
    "me_keepalive_interval_secs",
    "me_keepalive_jitter_secs",
    "me_keepalive_payload_random",
    "rpc_proxy_req_every",
    "me_writer_cmd_channel_capacity",
    "me_route_channel_capacity",
    "me_c2me_channel_capacity",
    "me_c2me_send_timeout_ms",
    "me_reader_route_data_wait_ms",
    "me_d2c_flush_batch_max_frames",
    "me_d2c_flush_batch_max_bytes",
    "me_d2c_flush_batch_max_delay_us",
    "me_d2c_ack_flush_immediate",
    "me_quota_soft_overshoot_bytes",
    "me_d2c_frame_buf_shrink_threshold_bytes",
    "direct_relay_copy_buf_c2s_bytes",
    "direct_relay_copy_buf_s2c_bytes",
    "crypto_pending_buffer",
    "max_client_frame",
    "desync_all_full",
    "beobachten",
    "beobachten_minutes",
    "beobachten_flush_secs",
    "beobachten_file",
    "hardswap",
    "me_warmup_stagger_enabled",
    "me_warmup_step_delay_ms",
    "me_warmup_step_jitter_ms",
    "me_reconnect_max_concurrent_per_dc",
    "me_reconnect_backoff_base_ms",
    "me_reconnect_backoff_cap_ms",
    "me_reconnect_fast_retry_count",
    "me_single_endpoint_shadow_writers",
    "me_single_endpoint_outage_mode_enabled",
    "me_single_endpoint_outage_disable_quarantine",
    "me_single_endpoint_outage_backoff_min_ms",
    "me_single_endpoint_outage_backoff_max_ms",
    "me_single_endpoint_shadow_rotate_every_secs",
    "me_floor_mode",
    "me_adaptive_floor_idle_secs",
    "me_adaptive_floor_min_writers_single_endpoint",
    "me_adaptive_floor_min_writers_multi_endpoint",
    "me_adaptive_floor_recover_grace_secs",
    "me_adaptive_floor_writers_per_core_total",
    "me_adaptive_floor_cpu_cores_override",
    "me_adaptive_floor_max_extra_writers_single_per_core",
    "me_adaptive_floor_max_extra_writers_multi_per_core",
    "me_adaptive_floor_max_active_writers_per_core",
    "me_adaptive_floor_max_warm_writers_per_core",
    "me_adaptive_floor_max_active_writers_global",
    "me_adaptive_floor_max_warm_writers_global",
    "upstream_connect_retry_attempts",
    "upstream_connect_retry_backoff_ms",
    "upstream_connect_budget_ms",
    "tg_connect",
    "upstream_unhealthy_fail_threshold",
    "upstream_connect_failfast_hard_errors",
    "stun_iface_mismatch_ignore",
    "unknown_dc_log_path",
    "unknown_dc_file_log_enabled",
    "log_level",
    "disable_colors",
    "telemetry",
    "me_socks_kdf_policy",
    "me_route_backpressure_enabled",
    "me_route_fairshare_enabled",
    "me_route_backpressure_base_timeout_ms",
    "me_route_backpressure_high_timeout_ms",
    "me_route_backpressure_high_watermark_pct",
    "me_health_interval_ms_unhealthy",
    "me_health_interval_ms_healthy",
    "me_admission_poll_ms",
    "me_warn_rate_limit_ms",
    "me_route_no_writer_mode",
    "me_route_no_writer_wait_ms",
    "me_route_hybrid_max_wait_ms",
    "me_route_blocking_send_timeout_ms",
    "me_route_inline_recovery_attempts",
    "me_route_inline_recovery_wait_ms",
    "links",
    "fast_mode_min_tls_record",
    "update_every",
    "me_reinit_every_secs",
    "me_hardswap_warmup_delay_min_ms",
    "me_hardswap_warmup_delay_max_ms",
    "me_hardswap_warmup_extra_passes",
    "me_hardswap_warmup_pass_backoff_base_ms",
    "me_config_stable_snapshots",
    "me_config_apply_cooldown_secs",
    "me_snapshot_require_http_2xx",
    "me_snapshot_reject_empty_map",
    "me_snapshot_min_proxy_for_lines",
    "proxy_secret_stable_snapshots",
    "proxy_secret_rotate_runtime",
    "me_secret_atomic_snapshot",
    "proxy_secret_len_max",
    "me_pool_drain_ttl_secs",
    "me_instadrain",
    "me_pool_drain_threshold",
    "me_pool_drain_soft_evict_enabled",
    "me_pool_drain_soft_evict_grace_secs",
    "me_pool_drain_soft_evict_per_writer",
    "me_pool_drain_soft_evict_budget_per_core",
    "me_pool_drain_soft_evict_cooldown_ms",
    "me_bind_stale_mode",
    "me_bind_stale_ttl_secs",
    "me_pool_min_fresh_ratio",
    "me_reinit_drain_timeout_secs",
    "proxy_secret_auto_reload_secs",
    "proxy_config_auto_reload_secs",
    "me_reinit_singleflight",
    "me_reinit_trigger_channel",
    "me_reinit_coalesce_window_ms",
    "me_deterministic_writer_sort",
    "me_writer_pick_mode",
    "me_writer_pick_sample_size",
    "ntp_check",
    "ntp_servers",
    "auto_degradation_enabled",
    "degradation_min_unavailable_dc_groups",
    "rst_on_close",
];

const NETWORK_CONFIG_KEYS: &[&str] = &[
    "ipv4",
    "ipv6",
    "prefer",
    "multipath",
    "stun_use",
    "stun_servers",
    "stun_tcp_fallback",
    "http_ip_detect_urls",
    "cache_public_ip_path",
    "dns_overrides",
];

const SERVER_CONFIG_KEYS: &[&str] = &[
    "port",
    "listen_addr_ipv4",
    "listen_addr_ipv6",
    "listen_unix_sock",
    "listen_unix_sock_perm",
    "listen_tcp",
    "client_mss",
    "client_mss_bulk",
    "proxy_protocol",
    "proxy_protocol_header_timeout_ms",
    "proxy_protocol_trusted_cidrs",
    "metrics_port",
    "metrics_listen",
    "metrics_whitelist",
    "api",
    "admin_api",
    "listeners",
    "listen_backlog",
    "max_connections",
    "accept_permit_timeout_ms",
    "conntrack_control",
];

const API_CONFIG_KEYS: &[&str] = &[
    "enabled",
    "listen",
    "whitelist",
    "gray_action",
    "auth_header",
    "request_body_limit_bytes",
    "minimal_runtime_enabled",
    "minimal_runtime_cache_ttl_ms",
    "runtime_edge_enabled",
    "runtime_edge_cache_ttl_ms",
    "runtime_edge_top_n",
    "runtime_edge_events_capacity",
    "read_only",
];

const CONNTRACK_CONTROL_CONFIG_KEYS: &[&str] = &[
    "inline_conntrack_control",
    "mode",
    "backend",
    "profile",
    "hybrid_listener_ips",
    "pressure_high_watermark_pct",
    "pressure_low_watermark_pct",
    "delete_budget_per_sec",
];

const LISTENER_CONFIG_KEYS: &[&str] = &[
    "ip",
    "port",
    "client_mss",
    "synlimit",
    "synlimit_seconds",
    "synlimit_hitcount",
    "synlimit_burst",
    "announce",
    "announce_ip",
    "proxy_protocol",
    "reuse_allow",
];

const TIMEOUTS_CONFIG_KEYS: &[&str] = &[
    "client_first_byte_idle_secs",
    "client_handshake",
    "relay_idle_policy_v2_enabled",
    "relay_client_idle_soft_secs",
    "relay_client_idle_hard_secs",
    "relay_idle_grace_after_downstream_activity_secs",
    "client_keepalive",
    "client_ack",
    "me_one_retry",
    "me_one_timeout_ms",
];

const CENSORSHIP_CONFIG_KEYS: &[&str] = &[
    "tls_domain",
    "tls_domains",
    "unknown_sni_action",
    "tls_fetch_scope",
    "tls_fetch",
    "mask",
    "mask_dynamic",
    "mask_host",
    "mask_port",
    "exclusive_mask",
    "mask_unix_sock",
    "fake_cert_len",
    "tls_emulation",
    "tls_front_dir",
    "server_hello_delay_min_ms",
    "server_hello_delay_max_ms",
    "tls_new_session_tickets",
    "serverhello_compact",
    "tls_full_cert_ttl_secs",
    "alpn_enforce",
    "mask_proxy_protocol",
    "http_mask",
    "mask_shape_hardening",
    "mask_shape_hardening_aggressive_mode",
    "mask_shape_bucket_floor_bytes",
    "mask_shape_bucket_cap_bytes",
    "mask_shape_above_cap_blur",
    "mask_shape_above_cap_blur_max_bytes",
    "mask_relay_max_bytes",
    "mask_relay_timeout_ms",
    "mask_relay_idle_timeout_ms",
    "mask_classifier_prefetch_timeout_ms",
    "mask_timing_normalization_enabled",
    "mask_timing_normalization_floor_ms",
    "mask_timing_normalization_ceiling_ms",
];

const HTTP_MASK_CONFIG_KEYS: &[&str] = &[
    "enabled",
    "cert_file",
    "key_file",
    "upstream",
    "alpn",
];

const TLS_FETCH_CONFIG_KEYS: &[&str] = &[
    "profiles",
    "strict_route",
    "attempt_timeout_ms",
    "total_budget_ms",
    "grease_enabled",
    "deterministic",
    "profile_cache_ttl_secs",
];

const ACCESS_CONFIG_KEYS: &[&str] = &[
    "users",
    "user_enabled",
    "user_ad_tags",
    "user_max_tcp_conns",
    "user_max_tcp_conns_global_each",
    "user_expirations",
    "user_data_quota",
    "user_rate_limits",
    "cidr_rate_limits",
    "user_max_unique_ips",
    "user_max_unique_ips_global_each",
    "user_max_unique_ips_mode",
    "user_max_unique_ips_window_secs",
    "replay_check_len",
    "replay_window_secs",
    "ignore_time_skew",
];

const RATE_LIMIT_BPS_CONFIG_KEYS: &[&str] = &["up_bps", "down_bps"];

const UPSTREAM_CONFIG_KEYS: &[&str] = &[
    "type",
    "interface",
    "bind_addresses",
    "bindtodevice",
    "force_bind",
    "address",
    "user_id",
    "username",
    "password",
    "url",
    "weight",
    "enabled",
    "scopes",
    "ipv4",
    "ipv6",
];

const PROXY_MODES_CONFIG_KEYS: &[&str] = &["classic", "secure", "tls"];
const TELEMETRY_CONFIG_KEYS: &[&str] = &["core_enabled", "user_enabled", "me_level"];
const LINKS_CONFIG_KEYS: &[&str] = &["show", "public_host", "public_port"];
const LOGGING_CONFIG_KEYS: &[&str] = &[
    "destination",
    "path",
    "rotation",
    "max_size_bytes",
    "max_files",
    "max_age_secs",
];

#[derive(Debug)]
struct UnknownConfigKey {
    path: String,
    suggestion: Option<String>,
}

fn table_at<'a>(value: &'a toml::Value, path: &[&str]) -> Option<&'a toml::Table> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current.as_table()
}

fn is_strict_config(parsed_toml: &toml::Value) -> bool {
    table_at(parsed_toml, &["general"])
        .and_then(|table| table.get("config_strict"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false)
}

fn known_config_keys_for_suggestion() -> Vec<&'static str> {
    let mut keys = Vec::new();
    for group in [
        TOP_LEVEL_CONFIG_KEYS,
        GENERAL_CONFIG_KEYS,
        NETWORK_CONFIG_KEYS,
        SERVER_CONFIG_KEYS,
        API_CONFIG_KEYS,
        CONNTRACK_CONTROL_CONFIG_KEYS,
        LISTENER_CONFIG_KEYS,
        TIMEOUTS_CONFIG_KEYS,
        CENSORSHIP_CONFIG_KEYS,
        TLS_FETCH_CONFIG_KEYS,
        HTTP_MASK_CONFIG_KEYS,
        ACCESS_CONFIG_KEYS,
        RATE_LIMIT_BPS_CONFIG_KEYS,
        UPSTREAM_CONFIG_KEYS,
        PROXY_MODES_CONFIG_KEYS,
        TELEMETRY_CONFIG_KEYS,
        LINKS_CONFIG_KEYS,
        LOGGING_CONFIG_KEYS,
    ] {
        keys.extend_from_slice(group);
    }
    keys
}

fn levenshtein_distance(a: &str, b: &str) -> usize {
    let b_chars: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b_chars.len()).collect();
    let mut curr = vec![0usize; b_chars.len() + 1];

    for (i, ca) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b_chars.iter().enumerate() {
            let replace = if ca == *cb { prev[j] } else { prev[j] + 1 };
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(replace);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b_chars.len()]
}

fn unknown_key_suggestion(key: &str, known_keys: &[&'static str]) -> Option<String> {
    let normalized = key.to_ascii_lowercase();
    let mut best: Option<(&str, usize)> = None;
    for known in known_keys {
        let distance = levenshtein_distance(&normalized, known);
        let is_better = match best {
            Some((_, best_distance)) => distance < best_distance,
            None => true,
        };
        if distance <= 4 && is_better {
            best = Some((known, distance));
        }
    }
    best.map(|(known, _)| known.to_string())
}

fn push_unknown_keys(
    unknown: &mut Vec<UnknownConfigKey>,
    known_for_suggestion: &[&'static str],
    path: &str,
    table: &toml::Table,
    allowed: &[&str],
) {
    for key in table.keys() {
        if !allowed.contains(&key.as_str()) {
            let full_path = if path.is_empty() {
                key.clone()
            } else {
                format!("{path}.{key}")
            };
            unknown.push(UnknownConfigKey {
                path: full_path,
                suggestion: unknown_key_suggestion(key, known_for_suggestion),
            });
        }
    }
}

fn check_known_table(
    parsed_toml: &toml::Value,
    unknown: &mut Vec<UnknownConfigKey>,
    known_for_suggestion: &[&'static str],
    path: &[&str],
    allowed: &[&str],
) {
    if let Some(table) = table_at(parsed_toml, path) {
        push_unknown_keys(
            unknown,
            known_for_suggestion,
            &path.join("."),
            table,
            allowed,
        );
    }
}

fn check_nested_table_value(
    unknown: &mut Vec<UnknownConfigKey>,
    known_for_suggestion: &[&'static str],
    path: String,
    value: &toml::Value,
    allowed: &[&str],
) {
    if let Some(table) = value.as_table() {
        push_unknown_keys(unknown, known_for_suggestion, &path, table, allowed);
    }
}

fn collect_unknown_config_keys(parsed_toml: &toml::Value) -> Vec<UnknownConfigKey> {
    let known_for_suggestion = known_config_keys_for_suggestion();
    let mut unknown = Vec::new();

    if let Some(root) = parsed_toml.as_table() {
        push_unknown_keys(
            &mut unknown,
            &known_for_suggestion,
            "",
            root,
            TOP_LEVEL_CONFIG_KEYS,
        );
    }

    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["general"],
        GENERAL_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["general", "modes"],
        PROXY_MODES_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["general", "telemetry"],
        TELEMETRY_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["general", "links"],
        LINKS_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["logging"],
        LOGGING_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["network"],
        NETWORK_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["server"],
        SERVER_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["server", "api"],
        API_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["server", "admin_api"],
        API_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["server", "conntrack_control"],
        CONNTRACK_CONTROL_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["timeouts"],
        TIMEOUTS_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["censorship"],
        CENSORSHIP_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["censorship", "tls_fetch"],
        TLS_FETCH_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["censorship", "http_mask"],
        HTTP_MASK_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["access"],
        ACCESS_CONFIG_KEYS,
    );

    if let Some(listeners) = table_at(parsed_toml, &["server"])
        .and_then(|table| table.get("listeners"))
        .and_then(toml::Value::as_array)
    {
        for (idx, listener) in listeners.iter().enumerate() {
            check_nested_table_value(
                &mut unknown,
                &known_for_suggestion,
                format!("server.listeners[{idx}]"),
                listener,
                LISTENER_CONFIG_KEYS,
            );
        }
    }

    if let Some(upstreams) = parsed_toml.get("upstreams").and_then(toml::Value::as_array) {
        for (idx, upstream) in upstreams.iter().enumerate() {
            check_nested_table_value(
                &mut unknown,
                &known_for_suggestion,
                format!("upstreams[{idx}]"),
                upstream,
                UPSTREAM_CONFIG_KEYS,
            );
        }
    }

    for access_map in ["user_rate_limits", "cidr_rate_limits"] {
        if let Some(table) = table_at(parsed_toml, &["access"])
            .and_then(|access| access.get(access_map))
            .and_then(toml::Value::as_table)
        {
            for (entry_name, value) in table {
                check_nested_table_value(
                    &mut unknown,
                    &known_for_suggestion,
                    format!("access.{access_map}.{entry_name}"),
                    value,
                    RATE_LIMIT_BPS_CONFIG_KEYS,
                );
            }
        }
    }

    unknown
}

fn handle_unknown_config_keys(parsed_toml: &toml::Value) -> Result<()> {
    let unknown = collect_unknown_config_keys(parsed_toml);
    if unknown.is_empty() {
        return Ok(());
    }

    for item in &unknown {
        if let Some(suggestion) = item.suggestion.as_deref() {
            warn!(
                key = %item.path,
                suggestion = %suggestion,
                "Unknown config key ignored; did you mean the suggested key?"
            );
        } else {
            warn!(key = %item.path, "Unknown config key ignored");
        }
    }

    if is_strict_config(parsed_toml) {
        let mut paths = Vec::with_capacity(unknown.len());
        for item in unknown {
            if let Some(suggestion) = item.suggestion {
                paths.push(format!("{} (did you mean `{}`?)", item.path, suggestion));
            } else {
                paths.push(item.path);
            }
        }
        return Err(ProxyError::Config(format!(
            "unknown config keys are not allowed when general.config_strict=true: {}",
            paths.join(", ")
        )));
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct LoadedConfig {
    pub(crate) config: ProxyConfig,
    pub(crate) source_files: Vec<PathBuf>,
    pub(crate) rendered_hash: u64,
}

/// Precomputed, immutable user authentication data used by handshake hot paths.
#[derive(Debug, Clone, Default)]
pub(crate) struct UserAuthSnapshot {
    entries: Vec<UserAuthEntry>,
    by_name: HashMap<String, u32>,
    sni_index: HashMap<u64, Vec<u32>>,
    sni_initial_index: HashMap<u8, Vec<u32>>,
}

#[derive(Debug, Clone)]
pub(crate) struct UserAuthEntry {
    pub(crate) user: String,
    pub(crate) secret: [u8; ACCESS_SECRET_BYTES],
}

impl UserAuthSnapshot {
    fn from_users(users: &HashMap<String, String>) -> Result<Self> {
        let mut entries = Vec::with_capacity(users.len());
        let mut by_name = HashMap::with_capacity(users.len());
        let mut sni_index = HashMap::with_capacity(users.len());
        let mut sni_initial_index = HashMap::with_capacity(users.len());

        for (user, secret_hex) in users {
            let decoded = hex::decode(secret_hex).map_err(|_| ProxyError::InvalidSecret {
                user: user.clone(),
                reason: "Must be 32 hex characters".to_string(),
            })?;
            if decoded.len() != ACCESS_SECRET_BYTES {
                return Err(ProxyError::InvalidSecret {
                    user: user.clone(),
                    reason: "Must be 32 hex characters".to_string(),
                });
            }

            let user_id = u32::try_from(entries.len()).map_err(|_| {
                ProxyError::Config("Too many users for runtime auth snapshot".to_string())
            })?;

            let mut secret = [0u8; ACCESS_SECRET_BYTES];
            secret.copy_from_slice(&decoded);
            entries.push(UserAuthEntry {
                user: user.clone(),
                secret,
            });
            by_name.insert(user.clone(), user_id);
            sni_index
                .entry(Self::sni_lookup_hash(user))
                .or_insert_with(Vec::new)
                .push(user_id);
            if let Some(initial) = user
                .as_bytes()
                .first()
                .map(|byte| byte.to_ascii_lowercase())
            {
                sni_initial_index
                    .entry(initial)
                    .or_insert_with(Vec::new)
                    .push(user_id);
            }
        }

        Ok(Self {
            entries,
            by_name,
            sni_index,
            sni_initial_index,
        })
    }

    pub(crate) fn entries(&self) -> &[UserAuthEntry] {
        &self.entries
    }

    pub(crate) fn user_id_by_name(&self, user: &str) -> Option<u32> {
        self.by_name.get(user).copied()
    }

    pub(crate) fn entry_by_id(&self, user_id: u32) -> Option<&UserAuthEntry> {
        let idx = usize::try_from(user_id).ok()?;
        self.entries.get(idx)
    }

    pub(crate) fn sni_candidates(&self, sni: &str) -> Option<&[u32]> {
        self.sni_index
            .get(&Self::sni_lookup_hash(sni))
            .map(Vec::as_slice)
    }

    pub(crate) fn sni_initial_candidates(&self, sni: &str) -> Option<&[u32]> {
        let initial = sni
            .as_bytes()
            .first()
            .map(|byte| byte.to_ascii_lowercase())?;
        self.sni_initial_index.get(&initial).map(Vec::as_slice)
    }

    fn sni_lookup_hash(value: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        for byte in value.bytes() {
            hasher.write_u8(byte.to_ascii_lowercase());
        }
        hasher.finish()
    }
}

fn normalize_config_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        }
    })
}

fn hash_rendered_snapshot(rendered: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    rendered.hash(&mut hasher);
    hasher.finish()
}

fn preprocess_includes(
    content: &str,
    base_dir: &Path,
    depth: u8,
    source_files: &mut BTreeSet<PathBuf>,
) -> Result<String> {
    if depth > 10 {
        return Err(ProxyError::Config("Include depth > 10".into()));
    }
    let mut output = String::with_capacity(content.len());
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("include") {
            let rest = rest.trim();
            if let Some(rest) = rest.strip_prefix('=') {
                let path_str = rest.trim().trim_matches('"');
                let resolved = base_dir.join(path_str);
                source_files.insert(normalize_config_path(&resolved));
                let included = std::fs::read_to_string(&resolved)
                    .map_err(|e| ProxyError::Config(e.to_string()))?;
                let included_dir = resolved.parent().unwrap_or(base_dir);
                output.push_str(&preprocess_includes(
                    &included,
                    included_dir,
                    depth + 1,
                    source_files,
                )?);
                output.push('\n');
                continue;
            }
        }
        output.push_str(line);
        output.push('\n');
    }
    Ok(output)
}

fn validate_network_cfg(net: &mut NetworkConfig) -> Result<()> {
    if !net.ipv4 && matches!(net.ipv6, Some(false)) {
        return Err(ProxyError::Config(
            "Both ipv4 and ipv6 are disabled in [network]".to_string(),
        ));
    }

    if net.prefer != 4 && net.prefer != 6 {
        return Err(ProxyError::Config(
            "network.prefer must be 4 or 6".to_string(),
        ));
    }

    if !net.ipv4 && net.prefer == 4 {
        warn!("prefer=4 but ipv4=false; forcing prefer=6");
        net.prefer = 6;
    }

    if matches!(net.ipv6, Some(false)) && net.prefer == 6 {
        warn!("prefer=6 but ipv6=false; forcing prefer=4");
        net.prefer = 4;
    }

    Ok(())
}

fn push_unique_nonempty(target: &mut Vec<String>, value: String) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }
    if !target.iter().any(|existing| existing == trimmed) {
        target.push(trimmed.to_string());
    }
}

fn is_valid_ad_tag(tag: &str) -> bool {
    tag.len() == 32 && tag.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn sanitize_ad_tag(ad_tag: &mut Option<String>) {
    let Some(tag) = ad_tag.as_ref() else {
        return;
    };

    if !is_valid_ad_tag(tag) {
        warn!("Invalid general.ad_tag value, expected exactly 32 hex chars; ad_tag is disabled");
        *ad_tag = None;
    }
}

fn validate_logging_config(logging: &LoggingConfig) -> Result<()> {
    if let Some(path) = logging.path.as_ref()
        && path.trim().is_empty()
    {
        return Err(ProxyError::Config(
            "logging.path cannot be empty when provided".to_string(),
        ));
    }

    if matches!(logging.destination, LoggingDestination::File) && logging.path.is_none() {
        return Err(ProxyError::Config(
            "logging.path must be set when logging.destination=\"file\"".to_string(),
        ));
    }

    Ok(())
}

fn validate_upstreams(config: &ProxyConfig) -> Result<()> {
    let has_enabled_shadowsocks = config.upstreams.iter().any(|upstream| {
        upstream.enabled && matches!(upstream.upstream_type, UpstreamType::Shadowsocks { .. })
    });

    if has_enabled_shadowsocks && config.general.use_middle_proxy {
        return Err(ProxyError::Config(
            "shadowsocks upstreams require general.use_middle_proxy = false".to_string(),
        ));
    }

    for upstream in &config.upstreams {
        if matches!(upstream.ipv4, Some(false)) && matches!(upstream.ipv6, Some(false)) {
            return Err(ProxyError::Config(
                "upstream.ipv4 and upstream.ipv6 cannot both be false".to_string(),
            ));
        }
        if let Some(prefer) = upstream.prefer
            && prefer != 4
            && prefer != 6
        {
            return Err(ProxyError::Config(
                "upstream.prefer must be 4 or 6".to_string(),
            ));
        }

        if let UpstreamType::Shadowsocks { url, .. } = &upstream.upstream_type {
            let parsed = ShadowsocksServerConfig::from_url(url)
                .map_err(|error| ProxyError::Config(format!("invalid shadowsocks url: {error}")))?;
            if parsed.plugin().is_some() {
                return Err(ProxyError::Config(
                    "shadowsocks plugins are not supported".to_string(),
                ));
            }
        }
    }

    Ok(())
}

fn normalize_upstream_family_policy(config: &mut ProxyConfig) {
    for (idx, upstream) in config.upstreams.iter_mut().enumerate() {
        if matches!(upstream.ipv4, Some(false)) && upstream.prefer == Some(4) {
            warn!(
                upstream = idx,
                "upstream.prefer=4 but upstream.ipv4=false; forcing prefer=6"
            );
            upstream.prefer = Some(6);
        }

        if matches!(upstream.ipv6, Some(false)) && upstream.prefer == Some(6) {
            warn!(
                upstream = idx,
                "upstream.prefer=6 but upstream.ipv6=false; forcing prefer=4"
            );
            upstream.prefer = Some(4);
        }
    }
}

// Main runtime configuration loaded from TOML.

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyConfig {
    #[serde(default)]
    pub general: GeneralConfig,

    /// Runtime logging destination, rotation, and retention configuration.
    #[serde(default)]
    pub logging: LoggingConfig,

    #[serde(default)]
    pub network: NetworkConfig,

    #[serde(default)]
    pub server: ServerConfig,

    #[serde(default)]
    pub timeouts: TimeoutsConfig,

    #[serde(default)]
    pub censorship: AntiCensorshipConfig,

    #[serde(default)]
    pub access: AccessConfig,

    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,

    #[serde(default)]
    pub show_link: ShowLink,

    /// DC address overrides for non-standard DCs (CDN, media, test, etc.)
    /// Keys are DC indices as strings, values are one or more "ip:port" addresses.
    /// Matches the C implementation's `proxy_for <dc_id> <ip>:<port>` config directive.
    /// Example in config.toml:
    ///   [dc_overrides]
    ///   "203" = ["149.154.175.100:443", "91.105.192.100:443"]
    #[serde(default, deserialize_with = "deserialize_dc_overrides")]
    pub dc_overrides: HashMap<String, Vec<String>>,

    /// Default DC index (1-5) for unmapped non-standard DCs.
    /// Matches the C implementation's `default <dc_id>` config directive.
    /// If not set, defaults to 2 (matching Telegram's official `default 2;` in proxy-multi.conf).
    #[serde(default)]
    pub default_dc: Option<u8>,

    /// Precomputed authentication snapshot for handshake hot paths.
    #[serde(skip)]
    pub(crate) runtime_user_auth: Option<Arc<UserAuthSnapshot>>,
}

impl ProxyConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::load_with_metadata(path).map(|loaded| loaded.config)
    }

    pub(crate) fn load_with_metadata<P: AsRef<Path>>(path: P) -> Result<LoadedConfig> {
        let path = path.as_ref();
        let content =
            std::fs::read_to_string(path).map_err(|e| ProxyError::Config(e.to_string()))?;
        let base_dir = path.parent().unwrap_or(Path::new("."));
        let mut source_files = BTreeSet::new();
        source_files.insert(normalize_config_path(path));
        let processed = preprocess_includes(&content, base_dir, 0, &mut source_files)?;

        let parsed_toml: toml::Value =
            toml::from_str(&processed).map_err(|e| ProxyError::Config(e.to_string()))?;
        handle_unknown_config_keys(&parsed_toml)?;
        let general_table = parsed_toml
            .get("general")
            .and_then(|value| value.as_table());
        let network_table = parsed_toml
            .get("network")
            .and_then(|value| value.as_table());
        let server_table = parsed_toml.get("server").and_then(|value| value.as_table());
        let conntrack_control_table = server_table
            .and_then(|table| table.get("conntrack_control"))
            .and_then(|value| value.as_table());
        let update_every_is_explicit = general_table
            .map(|table| table.contains_key("update_every"))
            .unwrap_or(false);
        let beobachten_is_explicit = general_table
            .map(|table| table.contains_key("beobachten"))
            .unwrap_or(false);
        let beobachten_minutes_is_explicit = general_table
            .map(|table| table.contains_key("beobachten_minutes"))
            .unwrap_or(false);
        let beobachten_flush_secs_is_explicit = general_table
            .map(|table| table.contains_key("beobachten_flush_secs"))
            .unwrap_or(false);
        let beobachten_file_is_explicit = general_table
            .map(|table| table.contains_key("beobachten_file"))
            .unwrap_or(false);
        let legacy_secret_is_explicit = general_table
            .map(|table| table.contains_key("proxy_secret_auto_reload_secs"))
            .unwrap_or(false);
        let legacy_config_is_explicit = general_table
            .map(|table| table.contains_key("proxy_config_auto_reload_secs"))
            .unwrap_or(false);
        let legacy_top_level_beobachten = parsed_toml.get("beobachten").cloned();
        let legacy_top_level_beobachten_minutes = parsed_toml.get("beobachten_minutes").cloned();
        let legacy_top_level_beobachten_flush_secs =
            parsed_toml.get("beobachten_flush_secs").cloned();
        let legacy_top_level_beobachten_file = parsed_toml.get("beobachten_file").cloned();
        let stun_servers_is_explicit = network_table
            .map(|table| table.contains_key("stun_servers"))
            .unwrap_or(false);
        let inline_conntrack_control_is_explicit = conntrack_control_table
            .map(|table| table.contains_key("inline_conntrack_control"))
            .unwrap_or(false);

        let mut config: ProxyConfig = parsed_toml
            .try_into()
            .map_err(|e| ProxyError::Config(e.to_string()))?;
        config
            .server
            .conntrack_control
            .inline_conntrack_control_explicit = inline_conntrack_control_is_explicit;

        if !update_every_is_explicit && (legacy_secret_is_explicit || legacy_config_is_explicit) {
            config.general.update_every = None;
        }

        // Backward compatibility: legacy top-level beobachten* keys.
        // Prefer `[general].*` when both are present.
        let mut legacy_beobachten_applied = false;
        if !beobachten_is_explicit && let Some(value) = legacy_top_level_beobachten.as_ref() {
            let parsed = value.as_bool().ok_or_else(|| {
                ProxyError::Config("beobachten (top-level) must be a boolean".to_string())
            })?;
            config.general.beobachten = parsed;
            legacy_beobachten_applied = true;
        }
        if !beobachten_minutes_is_explicit
            && let Some(value) = legacy_top_level_beobachten_minutes.as_ref()
        {
            let raw = value.as_integer().ok_or_else(|| {
                ProxyError::Config("beobachten_minutes (top-level) must be an integer".to_string())
            })?;
            let parsed = u64::try_from(raw).map_err(|_| {
                ProxyError::Config(
                    "beobachten_minutes (top-level) must be within u64 range".to_string(),
                )
            })?;
            config.general.beobachten_minutes = parsed;
            legacy_beobachten_applied = true;
        }
        if !beobachten_flush_secs_is_explicit
            && let Some(value) = legacy_top_level_beobachten_flush_secs.as_ref()
        {
            let raw = value.as_integer().ok_or_else(|| {
                ProxyError::Config(
                    "beobachten_flush_secs (top-level) must be an integer".to_string(),
                )
            })?;
            let parsed = u64::try_from(raw).map_err(|_| {
                ProxyError::Config(
                    "beobachten_flush_secs (top-level) must be within u64 range".to_string(),
                )
            })?;
            config.general.beobachten_flush_secs = parsed;
            legacy_beobachten_applied = true;
        }
        if !beobachten_file_is_explicit
            && let Some(value) = legacy_top_level_beobachten_file.as_ref()
        {
            let parsed = value.as_str().ok_or_else(|| {
                ProxyError::Config("beobachten_file (top-level) must be a string".to_string())
            })?;
            config.general.beobachten_file = parsed.to_string();
            legacy_beobachten_applied = true;
        }
        if legacy_beobachten_applied {
            warn!("top-level beobachten* keys are deprecated; use general.beobachten* instead");
        }

        let legacy_nat_stun = config.general.middle_proxy_nat_stun.take();
        let legacy_nat_stun_servers =
            std::mem::take(&mut config.general.middle_proxy_nat_stun_servers);
        let legacy_nat_stun_used = legacy_nat_stun.is_some() || !legacy_nat_stun_servers.is_empty();
        if stun_servers_is_explicit {
            let mut explicit_stun_servers = Vec::new();
            for stun in std::mem::take(&mut config.network.stun_servers) {
                push_unique_nonempty(&mut explicit_stun_servers, stun);
            }
            config.network.stun_servers = explicit_stun_servers;

            if legacy_nat_stun_used {
                warn!(
                    "general.middle_proxy_nat_stun and general.middle_proxy_nat_stun_servers are ignored because network.stun_servers is explicitly set"
                );
            }
        } else {
            // Keep the default STUN pool unless network.stun_servers is explicitly overridden.
            let mut unified_stun_servers = default_stun_servers();
            if let Some(stun) = legacy_nat_stun {
                push_unique_nonempty(&mut unified_stun_servers, stun);
            }
            for stun in legacy_nat_stun_servers {
                push_unique_nonempty(&mut unified_stun_servers, stun);
            }

            config.network.stun_servers = unified_stun_servers;

            if legacy_nat_stun_used {
                warn!(
                    "general.middle_proxy_nat_stun and general.middle_proxy_nat_stun_servers are deprecated; use network.stun_servers"
                );
            }
        }

        sanitize_ad_tag(&mut config.general.ad_tag);

        if let Some(path) = &config.general.proxy_config_v4_cache_path
            && path.trim().is_empty()
        {
            return Err(ProxyError::Config(
                "general.proxy_config_v4_cache_path cannot be empty when provided".to_string(),
            ));
        }

        if let Some(path) = &config.general.proxy_config_v6_cache_path
            && path.trim().is_empty()
        {
            return Err(ProxyError::Config(
                "general.proxy_config_v6_cache_path cannot be empty when provided".to_string(),
            ));
        }

        if let Some(update_every) = config.general.update_every {
            if update_every == 0 {
                return Err(ProxyError::Config(
                    "general.update_every must be > 0".to_string(),
                ));
            }
        } else {
            let legacy_secret = config.general.proxy_secret_auto_reload_secs;
            let legacy_config = config.general.proxy_config_auto_reload_secs;
            let effective = legacy_secret.min(legacy_config);
            if effective == 0 {
                return Err(ProxyError::Config(
                    "legacy proxy_*_auto_reload_secs values must be > 0 when general.update_every is not set".to_string(),
                ));
            }

            if legacy_secret != default_proxy_secret_reload_secs()
                || legacy_config != default_proxy_config_reload_secs()
            {
                warn!(
                    proxy_secret_auto_reload_secs = legacy_secret,
                    proxy_config_auto_reload_secs = legacy_config,
                    effective_update_every_secs = effective,
                    "proxy_*_auto_reload_secs are deprecated; set general.update_every"
                );
            }
        }

        if config.general.stun_nat_probe_concurrency == 0 {
            return Err(ProxyError::Config(
                "general.stun_nat_probe_concurrency must be > 0".to_string(),
            ));
        }

        if config.general.me_init_retry_attempts > 1_000_000 {
            return Err(ProxyError::Config(
                "general.me_init_retry_attempts must be within [0, 1000000]".to_string(),
            ));
        }

        if config.general.upstream_connect_retry_attempts == 0 {
            return Err(ProxyError::Config(
                "general.upstream_connect_retry_attempts must be > 0".to_string(),
            ));
        }

        if config.general.upstream_connect_budget_ms == 0 {
            return Err(ProxyError::Config(
                "general.upstream_connect_budget_ms must be > 0".to_string(),
            ));
        }

        if config.general.tg_connect == 0 {
            return Err(ProxyError::Config(
                "general.tg_connect must be > 0".to_string(),
            ));
        }

        if config.general.upstream_unhealthy_fail_threshold == 0 {
            return Err(ProxyError::Config(
                "general.upstream_unhealthy_fail_threshold must be > 0".to_string(),
            ));
        }

        if config.general.rpc_proxy_req_every != 0
            && !(10..=300).contains(&config.general.rpc_proxy_req_every)
        {
            return Err(ProxyError::Config(
                "general.rpc_proxy_req_every must be 0 or within [10, 300]".to_string(),
            ));
        }

        if config.timeouts.client_handshake == 0 {
            return Err(ProxyError::Config(
                "timeouts.client_handshake must be > 0".to_string(),
            ));
        }

        let handshake_timeout_ms = config
            .timeouts
            .client_handshake
            .checked_mul(1000)
            .ok_or_else(|| {
                ProxyError::Config(
                    "timeouts.client_handshake is too large to validate milliseconds budget"
                        .to_string(),
                )
            })?;

        if config.censorship.server_hello_delay_max_ms >= handshake_timeout_ms {
            return Err(ProxyError::Config(
                "censorship.server_hello_delay_max_ms must be < timeouts.client_handshake * 1000"
                    .to_string(),
            ));
        }

        if config.censorship.mask_shape_bucket_floor_bytes == 0 {
            return Err(ProxyError::Config(
                "censorship.mask_shape_bucket_floor_bytes must be > 0".to_string(),
            ));
        }

        if config.censorship.mask_shape_bucket_cap_bytes
            < config.censorship.mask_shape_bucket_floor_bytes
        {
            return Err(ProxyError::Config(
                "censorship.mask_shape_bucket_cap_bytes must be >= censorship.mask_shape_bucket_floor_bytes"
                    .to_string(),
            ));
        }

        if config.censorship.mask_shape_above_cap_blur && !config.censorship.mask_shape_hardening {
            return Err(ProxyError::Config(
                "censorship.mask_shape_above_cap_blur requires censorship.mask_shape_hardening = true"
                    .to_string(),
            ));
        }

        if config.censorship.mask_shape_hardening_aggressive_mode
            && !config.censorship.mask_shape_hardening
        {
            return Err(ProxyError::Config(
                "censorship.mask_shape_hardening_aggressive_mode requires censorship.mask_shape_hardening = true"
                    .to_string(),
            ));
        }

        if config.censorship.mask_shape_above_cap_blur
            && config.censorship.mask_shape_above_cap_blur_max_bytes == 0
        {
            return Err(ProxyError::Config(
                "censorship.mask_shape_above_cap_blur_max_bytes must be > 0 when censorship.mask_shape_above_cap_blur is enabled"
                    .to_string(),
            ));
        }

        if config.censorship.mask_shape_above_cap_blur_max_bytes > 1_048_576 {
            return Err(ProxyError::Config(
                "censorship.mask_shape_above_cap_blur_max_bytes must be <= 1048576".to_string(),
            ));
        }

        if config.censorship.mask_relay_max_bytes > 67_108_864 {
            return Err(ProxyError::Config(
                "censorship.mask_relay_max_bytes must be <= 67108864".to_string(),
            ));
        }

        if !(5..=50).contains(&config.censorship.mask_classifier_prefetch_timeout_ms) {
            return Err(ProxyError::Config(
                "censorship.mask_classifier_prefetch_timeout_ms must be within [5, 50]".to_string(),
            ));
        }

        if config.censorship.http_mask.enabled {
            let http_mask = &config.censorship.http_mask;
            if http_mask.cert_file.as_deref().unwrap_or_default().trim().is_empty() {
                return Err(ProxyError::Config(
                    "censorship.http_mask.cert_file must be set when censorship.http_mask.enabled = true"
                        .to_string(),
                ));
            }
            if http_mask.key_file.as_deref().unwrap_or_default().trim().is_empty() {
                return Err(ProxyError::Config(
                    "censorship.http_mask.key_file must be set when censorship.http_mask.enabled = true"
                        .to_string(),
                ));
            }
            let upstream = http_mask.upstream.as_deref().unwrap_or_default().trim();
            if upstream.is_empty() {
                return Err(ProxyError::Config(
                    "censorship.http_mask.upstream must be set when censorship.http_mask.enabled = true"
                        .to_string(),
                ));
            }
            if !(upstream.starts_with("http://") || !upstream.contains("://")) {
                return Err(ProxyError::Config(
                    "censorship.http_mask.upstream must be a plain HTTP upstream, for example http://chat:3000"
                        .to_string(),
                ));
            }
            if http_mask.alpn.iter().any(|alpn| alpn.trim().is_empty()) {
                return Err(ProxyError::Config(
                    "censorship.http_mask.alpn entries must not be empty".to_string(),
                ));
            }
        }

        if config.censorship.mask_timing_normalization_ceiling_ms
            < config.censorship.mask_timing_normalization_floor_ms
        {
            return Err(ProxyError::Config(
                "censorship.mask_timing_normalization_ceiling_ms must be >= censorship.mask_timing_normalization_floor_ms"
                    .to_string(),
            ));
        }

        if config.censorship.mask_timing_normalization_enabled
            && config.censorship.mask_timing_normalization_floor_ms == 0
        {
            return Err(ProxyError::Config(
                "censorship.mask_timing_normalization_floor_ms must be > 0 when censorship.mask_timing_normalization_enabled is true"
                    .to_string(),
            ));
        }

        if config.censorship.mask_timing_normalization_ceiling_ms > 60_000 {
            return Err(ProxyError::Config(
                "censorship.mask_timing_normalization_ceiling_ms must be <= 60000".to_string(),
            ));
        }

        if config.timeouts.relay_client_idle_soft_secs == 0 {
            return Err(ProxyError::Config(
                "timeouts.relay_client_idle_soft_secs must be > 0".to_string(),
            ));
        }

        if config.timeouts.relay_client_idle_hard_secs == 0 {
            return Err(ProxyError::Config(
                "timeouts.relay_client_idle_hard_secs must be > 0".to_string(),
            ));
        }

        if config.timeouts.relay_client_idle_hard_secs < config.timeouts.relay_client_idle_soft_secs
        {
            return Err(ProxyError::Config(
                "timeouts.relay_client_idle_hard_secs must be >= timeouts.relay_client_idle_soft_secs"
                    .to_string(),
            ));
        }

        if config
            .timeouts
            .relay_idle_grace_after_downstream_activity_secs
            > config.timeouts.relay_client_idle_hard_secs
        {
            return Err(ProxyError::Config(
                "timeouts.relay_idle_grace_after_downstream_activity_secs must be <= timeouts.relay_client_idle_hard_secs"
                    .to_string(),
            ));
        }

        if config.general.me_writer_cmd_channel_capacity == 0 {
            return Err(ProxyError::Config(
                "general.me_writer_cmd_channel_capacity must be > 0".to_string(),
            ));
        }
        if config.general.me_writer_cmd_channel_capacity > MAX_ME_WRITER_CMD_CHANNEL_CAPACITY {
            return Err(ProxyError::Config(format!(
                "general.me_writer_cmd_channel_capacity must be within [1, {MAX_ME_WRITER_CMD_CHANNEL_CAPACITY}]"
            )));
        }

        if config.general.me_route_channel_capacity == 0 {
            return Err(ProxyError::Config(
                "general.me_route_channel_capacity must be > 0".to_string(),
            ));
        }
        if config.general.me_route_channel_capacity > MAX_ME_ROUTE_CHANNEL_CAPACITY {
            return Err(ProxyError::Config(format!(
                "general.me_route_channel_capacity must be within [1, {MAX_ME_ROUTE_CHANNEL_CAPACITY}]"
            )));
        }

        if config.general.me_c2me_channel_capacity == 0 {
            return Err(ProxyError::Config(
                "general.me_c2me_channel_capacity must be > 0".to_string(),
            ));
        }
        if config.general.me_c2me_channel_capacity > MAX_ME_C2ME_CHANNEL_CAPACITY {
            return Err(ProxyError::Config(format!(
                "general.me_c2me_channel_capacity must be within [1, {MAX_ME_C2ME_CHANNEL_CAPACITY}]"
            )));
        }

        if !(MIN_MAX_CLIENT_FRAME_BYTES..=MAX_MAX_CLIENT_FRAME_BYTES)
            .contains(&config.general.max_client_frame)
        {
            return Err(ProxyError::Config(format!(
                "general.max_client_frame must be within [{MIN_MAX_CLIENT_FRAME_BYTES}, {MAX_MAX_CLIENT_FRAME_BYTES}]"
            )));
        }

        if config.general.me_c2me_send_timeout_ms > 60_000 {
            return Err(ProxyError::Config(
                "general.me_c2me_send_timeout_ms must be within [0, 60000]".to_string(),
            ));
        }

        if config.general.me_reader_route_data_wait_ms > 20 {
            return Err(ProxyError::Config(
                "general.me_reader_route_data_wait_ms must be within [0, 20]".to_string(),
            ));
        }

        if !(1..=512).contains(&config.general.me_d2c_flush_batch_max_frames) {
            return Err(ProxyError::Config(
                "general.me_d2c_flush_batch_max_frames must be within [1, 512]".to_string(),
            ));
        }

        if !(4096..=2 * 1024 * 1024).contains(&config.general.me_d2c_flush_batch_max_bytes) {
            return Err(ProxyError::Config(
                "general.me_d2c_flush_batch_max_bytes must be within [4096, 2097152]".to_string(),
            ));
        }

        if config.general.me_d2c_flush_batch_max_delay_us > 5000 {
            return Err(ProxyError::Config(
                "general.me_d2c_flush_batch_max_delay_us must be within [0, 5000]".to_string(),
            ));
        }

        if config.general.me_quota_soft_overshoot_bytes > 16 * 1024 * 1024 {
            return Err(ProxyError::Config(
                "general.me_quota_soft_overshoot_bytes must be within [0, 16777216]".to_string(),
            ));
        }

        if !(4096..=16 * 1024 * 1024)
            .contains(&config.general.me_d2c_frame_buf_shrink_threshold_bytes)
        {
            return Err(ProxyError::Config(
                "general.me_d2c_frame_buf_shrink_threshold_bytes must be within [4096, 16777216]"
                    .to_string(),
            ));
        }

        if !(4096..=1024 * 1024).contains(&config.general.direct_relay_copy_buf_c2s_bytes) {
            return Err(ProxyError::Config(
                "general.direct_relay_copy_buf_c2s_bytes must be within [4096, 1048576]"
                    .to_string(),
            ));
        }

        if !(8192..=2 * 1024 * 1024).contains(&config.general.direct_relay_copy_buf_s2c_bytes) {
            return Err(ProxyError::Config(
                "general.direct_relay_copy_buf_s2c_bytes must be within [8192, 2097152]"
                    .to_string(),
            ));
        }

        if config.general.me_health_interval_ms_unhealthy == 0 {
            return Err(ProxyError::Config(
                "general.me_health_interval_ms_unhealthy must be > 0".to_string(),
            ));
        }

        if config.general.me_health_interval_ms_healthy == 0 {
            return Err(ProxyError::Config(
                "general.me_health_interval_ms_healthy must be > 0".to_string(),
            ));
        }

        if config.general.me_admission_poll_ms == 0 {
            return Err(ProxyError::Config(
                "general.me_admission_poll_ms must be > 0".to_string(),
            ));
        }

        if config.general.me_warn_rate_limit_ms == 0 {
            return Err(ProxyError::Config(
                "general.me_warn_rate_limit_ms must be > 0".to_string(),
            ));
        }

        if config.general.me_pool_drain_soft_evict_grace_secs > 3600 {
            return Err(ProxyError::Config(
                "general.me_pool_drain_soft_evict_grace_secs must be within [0, 3600]".to_string(),
            ));
        }

        if config.general.me_pool_drain_soft_evict_per_writer == 0
            || config.general.me_pool_drain_soft_evict_per_writer > 16
        {
            return Err(ProxyError::Config(
                "general.me_pool_drain_soft_evict_per_writer must be within [1, 16]".to_string(),
            ));
        }

        if config.general.me_pool_drain_soft_evict_budget_per_core == 0
            || config.general.me_pool_drain_soft_evict_budget_per_core > 64
        {
            return Err(ProxyError::Config(
                "general.me_pool_drain_soft_evict_budget_per_core must be within [1, 64]"
                    .to_string(),
            ));
        }

        if config.general.me_pool_drain_soft_evict_cooldown_ms == 0 {
            return Err(ProxyError::Config(
                "general.me_pool_drain_soft_evict_cooldown_ms must be > 0".to_string(),
            ));
        }

        if config.access.user_max_unique_ips_window_secs == 0 {
            return Err(ProxyError::Config(
                "access.user_max_unique_ips_window_secs must be > 0".to_string(),
            ));
        }

        for (user, limit) in &config.access.user_rate_limits {
            if limit.up_bps == 0 && limit.down_bps == 0 {
                return Err(ProxyError::Config(format!(
                    "access.user_rate_limits.{user} must set at least one non-zero direction"
                )));
            }
        }

        for (cidr, limit) in &config.access.cidr_rate_limits {
            if limit.up_bps == 0 && limit.down_bps == 0 {
                return Err(ProxyError::Config(format!(
                    "access.cidr_rate_limits.{cidr} must set at least one non-zero direction"
                )));
            }
        }

        if config.general.me_reinit_every_secs == 0 {
            return Err(ProxyError::Config(
                "general.me_reinit_every_secs must be > 0".to_string(),
            ));
        }

        if config.general.me_single_endpoint_shadow_writers > 32 {
            return Err(ProxyError::Config(
                "general.me_single_endpoint_shadow_writers must be within [0, 32]".to_string(),
            ));
        }

        if config.general.me_adaptive_floor_min_writers_single_endpoint == 0
            || config.general.me_adaptive_floor_min_writers_single_endpoint > 32
        {
            return Err(ProxyError::Config(
                "general.me_adaptive_floor_min_writers_single_endpoint must be within [1, 32]"
                    .to_string(),
            ));
        }

        if config.general.me_adaptive_floor_min_writers_multi_endpoint == 0
            || config.general.me_adaptive_floor_min_writers_multi_endpoint > 32
        {
            return Err(ProxyError::Config(
                "general.me_adaptive_floor_min_writers_multi_endpoint must be within [1, 32]"
                    .to_string(),
            ));
        }

        if config.general.me_adaptive_floor_writers_per_core_total == 0 {
            return Err(ProxyError::Config(
                "general.me_adaptive_floor_writers_per_core_total must be > 0".to_string(),
            ));
        }

        if config.general.me_adaptive_floor_max_active_writers_per_core == 0 {
            return Err(ProxyError::Config(
                "general.me_adaptive_floor_max_active_writers_per_core must be > 0".to_string(),
            ));
        }

        if config.general.me_adaptive_floor_max_warm_writers_per_core == 0 {
            return Err(ProxyError::Config(
                "general.me_adaptive_floor_max_warm_writers_per_core must be > 0".to_string(),
            ));
        }

        if config.general.me_adaptive_floor_max_active_writers_global == 0 {
            return Err(ProxyError::Config(
                "general.me_adaptive_floor_max_active_writers_global must be > 0".to_string(),
            ));
        }

        if config.general.me_adaptive_floor_max_warm_writers_global == 0 {
            return Err(ProxyError::Config(
                "general.me_adaptive_floor_max_warm_writers_global must be > 0".to_string(),
            ));
        }

        if config.general.me_single_endpoint_outage_backoff_min_ms == 0 {
            return Err(ProxyError::Config(
                "general.me_single_endpoint_outage_backoff_min_ms must be > 0".to_string(),
            ));
        }

        if config.general.me_single_endpoint_outage_backoff_max_ms == 0 {
            return Err(ProxyError::Config(
                "general.me_single_endpoint_outage_backoff_max_ms must be > 0".to_string(),
            ));
        }

        if config.general.me_single_endpoint_outage_backoff_min_ms
            > config.general.me_single_endpoint_outage_backoff_max_ms
        {
            return Err(ProxyError::Config(
                "general.me_single_endpoint_outage_backoff_min_ms must be <= general.me_single_endpoint_outage_backoff_max_ms".to_string(),
            ));
        }

        if config.general.beobachten_minutes == 0 {
            return Err(ProxyError::Config(
                "general.beobachten_minutes must be > 0".to_string(),
            ));
        }

        if config.general.beobachten_flush_secs == 0 {
            return Err(ProxyError::Config(
                "general.beobachten_flush_secs must be > 0".to_string(),
            ));
        }

        if config.general.beobachten_file.trim().is_empty() {
            return Err(ProxyError::Config(
                "general.beobachten_file cannot be empty".to_string(),
            ));
        }

        if config.general.me_hardswap_warmup_delay_max_ms == 0 {
            return Err(ProxyError::Config(
                "general.me_hardswap_warmup_delay_max_ms must be > 0".to_string(),
            ));
        }

        if config.general.me_hardswap_warmup_delay_min_ms
            > config.general.me_hardswap_warmup_delay_max_ms
        {
            return Err(ProxyError::Config(
                "general.me_hardswap_warmup_delay_min_ms must be <= general.me_hardswap_warmup_delay_max_ms".to_string(),
            ));
        }

        if config.general.me_hardswap_warmup_extra_passes > 10 {
            return Err(ProxyError::Config(
                "general.me_hardswap_warmup_extra_passes must be within [0, 10]".to_string(),
            ));
        }

        if config.general.me_hardswap_warmup_pass_backoff_base_ms == 0 {
            return Err(ProxyError::Config(
                "general.me_hardswap_warmup_pass_backoff_base_ms must be > 0".to_string(),
            ));
        }

        if config.general.me_config_stable_snapshots == 0 {
            return Err(ProxyError::Config(
                "general.me_config_stable_snapshots must be > 0".to_string(),
            ));
        }

        if config.general.me_snapshot_min_proxy_for_lines == 0 {
            return Err(ProxyError::Config(
                "general.me_snapshot_min_proxy_for_lines must be > 0".to_string(),
            ));
        }

        if config.general.proxy_secret_stable_snapshots == 0 {
            return Err(ProxyError::Config(
                "general.proxy_secret_stable_snapshots must be > 0".to_string(),
            ));
        }

        if config.general.me_reinit_trigger_channel == 0 {
            return Err(ProxyError::Config(
                "general.me_reinit_trigger_channel must be > 0".to_string(),
            ));
        }

        if !(32..=4096).contains(&config.general.proxy_secret_len_max) {
            return Err(ProxyError::Config(
                "general.proxy_secret_len_max must be within [32, 4096]".to_string(),
            ));
        }

        if !(0.0..=1.0).contains(&config.general.me_pool_min_fresh_ratio) {
            return Err(ProxyError::Config(
                "general.me_pool_min_fresh_ratio must be within [0.0, 1.0]".to_string(),
            ));
        }

        if config.general.me_route_backpressure_base_timeout_ms == 0 {
            return Err(ProxyError::Config(
                "general.me_route_backpressure_base_timeout_ms must be > 0".to_string(),
            ));
        }
        if config.general.me_route_backpressure_base_timeout_ms > 5000 {
            return Err(ProxyError::Config(
                "general.me_route_backpressure_base_timeout_ms must be within [1, 5000]"
                    .to_string(),
            ));
        }

        if config.general.me_route_backpressure_high_timeout_ms
            < config.general.me_route_backpressure_base_timeout_ms
        {
            return Err(ProxyError::Config(
                "general.me_route_backpressure_high_timeout_ms must be >= general.me_route_backpressure_base_timeout_ms".to_string(),
            ));
        }
        if config.general.me_route_backpressure_high_timeout_ms > 5000 {
            return Err(ProxyError::Config(
                "general.me_route_backpressure_high_timeout_ms must be within [1, 5000]"
                    .to_string(),
            ));
        }

        if !(1..=100).contains(&config.general.me_route_backpressure_high_watermark_pct) {
            return Err(ProxyError::Config(
                "general.me_route_backpressure_high_watermark_pct must be within [1, 100]"
                    .to_string(),
            ));
        }

        if !(10..=5000).contains(&config.general.me_route_no_writer_wait_ms) {
            return Err(ProxyError::Config(
                "general.me_route_no_writer_wait_ms must be within [10, 5000]".to_string(),
            ));
        }

        if !(50..=60_000).contains(&config.general.me_route_hybrid_max_wait_ms) {
            return Err(ProxyError::Config(
                "general.me_route_hybrid_max_wait_ms must be within [50, 60000]".to_string(),
            ));
        }

        if !(1..=5000).contains(&config.general.me_route_blocking_send_timeout_ms) {
            return Err(ProxyError::Config(
                "general.me_route_blocking_send_timeout_ms must be within [1, 5000]".to_string(),
            ));
        }

        if !(2..=4).contains(&config.general.me_writer_pick_sample_size) {
            return Err(ProxyError::Config(
                "general.me_writer_pick_sample_size must be within [2, 4]".to_string(),
            ));
        }

        if config.general.me_route_inline_recovery_attempts == 0 {
            return Err(ProxyError::Config(
                "general.me_route_inline_recovery_attempts must be > 0".to_string(),
            ));
        }

        if !(10..=30000).contains(&config.general.me_route_inline_recovery_wait_ms) {
            return Err(ProxyError::Config(
                "general.me_route_inline_recovery_wait_ms must be within [10, 30000]".to_string(),
            ));
        }

        if !(1..=MAX_API_REQUEST_BODY_LIMIT_BYTES)
            .contains(&config.server.api.request_body_limit_bytes)
        {
            return Err(ProxyError::Config(
                "server.api.request_body_limit_bytes must be within [1, 1048576]".to_string(),
            ));
        }

        if config.server.api.minimal_runtime_cache_ttl_ms > 60_000 {
            return Err(ProxyError::Config(
                "server.api.minimal_runtime_cache_ttl_ms must be within [0, 60000]".to_string(),
            ));
        }

        if config.server.api.runtime_edge_cache_ttl_ms > 60_000 {
            return Err(ProxyError::Config(
                "server.api.runtime_edge_cache_ttl_ms must be within [0, 60000]".to_string(),
            ));
        }

        if !(1..=1000).contains(&config.server.api.runtime_edge_top_n) {
            return Err(ProxyError::Config(
                "server.api.runtime_edge_top_n must be within [1, 1000]".to_string(),
            ));
        }

        if !(16..=4096).contains(&config.server.api.runtime_edge_events_capacity) {
            return Err(ProxyError::Config(
                "server.api.runtime_edge_events_capacity must be within [16, 4096]".to_string(),
            ));
        }

        if config.server.api.listen.parse::<SocketAddr>().is_err() {
            return Err(ProxyError::Config(
                "server.api.listen must be in IP:PORT format".to_string(),
            ));
        }

        if config.server.proxy_protocol_header_timeout_ms == 0 {
            return Err(ProxyError::Config(
                "server.proxy_protocol_header_timeout_ms must be > 0".to_string(),
            ));
        }

        if config.server.listen_backlog == 0 || config.server.listen_backlog > i32::MAX as u32 {
            return Err(ProxyError::Config(format!(
                "server.listen_backlog must be within [1, {}]",
                i32::MAX
            )));
        }

        config
            .server
            .client_mss_value()
            .map_err(|error| ProxyError::Config(format!("server.client_mss {error}")))?;
        for (idx, listener) in config.server.listeners.iter().enumerate() {
            if listener.client_mss.is_some() {
                listener
                    .effective_client_mss(&config.server)
                    .map_err(|error| {
                        ProxyError::Config(format!("server.listeners[{idx}].client_mss {error}"))
                    })?;
            }
            if listener.synlimit_seconds == 0 {
                return Err(ProxyError::Config(format!(
                    "server.listeners[{idx}].synlimit_seconds must be > 0"
                )));
            }
            if listener.synlimit_hitcount == 0 {
                return Err(ProxyError::Config(format!(
                    "server.listeners[{idx}].synlimit_hitcount must be > 0"
                )));
            }
            if listener.synlimit_burst == 0 {
                return Err(ProxyError::Config(format!(
                    "server.listeners[{idx}].synlimit_burst must be > 0"
                )));
            }
        }

        if config.server.accept_permit_timeout_ms > 60_000 {
            return Err(ProxyError::Config(
                "server.accept_permit_timeout_ms must be within [0, 60000]".to_string(),
            ));
        }

        if config.server.conntrack_control.pressure_high_watermark_pct == 0
            || config.server.conntrack_control.pressure_high_watermark_pct > 100
        {
            return Err(ProxyError::Config(
                "server.conntrack_control.pressure_high_watermark_pct must be within [1, 100]"
                    .to_string(),
            ));
        }

        if config.server.conntrack_control.pressure_low_watermark_pct
            >= config.server.conntrack_control.pressure_high_watermark_pct
        {
            return Err(ProxyError::Config(
                "server.conntrack_control.pressure_low_watermark_pct must be < pressure_high_watermark_pct"
                    .to_string(),
            ));
        }

        if config.server.conntrack_control.delete_budget_per_sec == 0 {
            return Err(ProxyError::Config(
                "server.conntrack_control.delete_budget_per_sec must be > 0".to_string(),
            ));
        }

        if matches!(config.server.conntrack_control.mode, ConntrackMode::Hybrid)
            && config
                .server
                .conntrack_control
                .hybrid_listener_ips
                .is_empty()
        {
            return Err(ProxyError::Config(
                "server.conntrack_control.hybrid_listener_ips must be non-empty in mode=hybrid"
                    .to_string(),
            ));
        }

        if config.general.effective_me_pool_force_close_secs() > 0
            && config.general.effective_me_pool_force_close_secs()
                < config.general.me_pool_drain_ttl_secs
        {
            warn!(
                me_pool_drain_ttl_secs = config.general.me_pool_drain_ttl_secs,
                me_reinit_drain_timeout_secs = config.general.effective_me_pool_force_close_secs(),
                "force-close timeout is lower than drain TTL; bumping force-close timeout to TTL"
            );
            config.general.me_reinit_drain_timeout_secs = config.general.me_pool_drain_ttl_secs;
        }

        // Validate secrets.
        for (user, secret) in &config.access.users {
            if !secret.chars().all(|c| c.is_ascii_hexdigit()) || secret.len() != 32 {
                return Err(ProxyError::InvalidSecret {
                    user: user.clone(),
                    reason: "Must be 32 hex characters".to_string(),
                });
            }
        }

        config.censorship.tls_domain =
            normalize_domain_to_ascii(&config.censorship.tls_domain, "censorship.tls_domain")?;

        // Validate mask_unix_sock.
        if let Some(ref sock_path) = config.censorship.mask_unix_sock {
            if sock_path.is_empty() {
                return Err(ProxyError::Config(
                    "mask_unix_sock cannot be empty".to_string(),
                ));
            }
            #[cfg(unix)]
            if sock_path.len() > 107 {
                return Err(ProxyError::Config(format!(
                    "mask_unix_sock path too long: {} bytes (max 107)",
                    sock_path.len()
                )));
            }
            #[cfg(not(unix))]
            return Err(ProxyError::Config(
                "mask_unix_sock is only supported on Unix platforms".to_string(),
            ));

            if config.censorship.mask_host.is_some() {
                return Err(ProxyError::Config(
                    "mask_unix_sock and mask_host are mutually exclusive".to_string(),
                ));
            }
        }

        if let Some(mask_host) = config.censorship.mask_host.as_mut() {
            *mask_host = normalize_mask_host_to_ascii(mask_host, "censorship.mask_host")?;
        }

        for (domain, target) in &config.censorship.exclusive_mask {
            if !is_valid_tls_domain_name(domain) {
                return Err(ProxyError::Config(format!(
                    "Invalid censorship.exclusive_mask domain: '{}'. Must be a valid domain name",
                    domain
                )));
            }
            if parse_exclusive_mask_target(target).is_none() {
                return Err(ProxyError::Config(format!(
                    "Invalid censorship.exclusive_mask target for '{}': '{}'. Expected host:port with port > 0",
                    domain, target
                )));
            }
        }

        // Normalize optional TLS fetch scope: whitespace-only values disable scoped routing.
        config.censorship.tls_fetch_scope = config.censorship.tls_fetch_scope.trim().to_string();

        if config.censorship.tls_fetch.profiles.is_empty() {
            config.censorship.tls_fetch.profiles = TlsFetchConfig::default().profiles;
        } else {
            let mut seen = HashSet::new();
            config
                .censorship
                .tls_fetch
                .profiles
                .retain(|profile| seen.insert(*profile));
        }

        if config.censorship.tls_fetch.attempt_timeout_ms == 0 {
            return Err(ProxyError::Config(
                "censorship.tls_fetch.attempt_timeout_ms must be > 0".to_string(),
            ));
        }
        if config.censorship.tls_fetch.total_budget_ms == 0 {
            return Err(ProxyError::Config(
                "censorship.tls_fetch.total_budget_ms must be > 0".to_string(),
            ));
        }

        // Merge primary + extra TLS domains, deduplicate (primary always first).
        if !config.censorship.tls_domains.is_empty() {
            let mut all = Vec::with_capacity(1 + config.censorship.tls_domains.len());
            all.push(config.censorship.tls_domain.clone());
            for d in std::mem::take(&mut config.censorship.tls_domains) {
                if !d.is_empty() {
                    let domain = normalize_domain_to_ascii(&d, "censorship.tls_domains entry")?;
                    if !all.contains(&domain) {
                        all.push(domain);
                    }
                }
            }
            // keep primary as tls_domain; store remaining back to tls_domains
            if all.len() > 1 {
                config.censorship.tls_domains = all[1..].to_vec();
            }
        }

        let mut exclusive_mask = HashMap::with_capacity(config.censorship.exclusive_mask.len());
        let mut exclusive_mask_targets =
            HashMap::with_capacity(config.censorship.exclusive_mask.len());
        for (domain, target) in std::mem::take(&mut config.censorship.exclusive_mask) {
            let domain = normalize_domain_to_ascii(&domain, "censorship.exclusive_mask domain")?;
            let target =
                normalize_exclusive_mask_target(&target, "censorship.exclusive_mask target")?;
            let Some((host, port)) = parse_exclusive_mask_target(&target) else {
                return Err(ProxyError::Config(format!(
                    "Invalid censorship.exclusive_mask target for '{}': '{}'. Expected host:port with port > 0",
                    domain, target
                )));
            };
            exclusive_mask_targets.insert(
                domain.clone(),
                ExclusiveMaskTarget {
                    host: host.to_string(),
                    port,
                },
            );
            exclusive_mask.insert(domain, target);
        }
        config.censorship.exclusive_mask = exclusive_mask;
        config.censorship.exclusive_mask_targets = exclusive_mask_targets;

        // Migration: prefer_ipv6 -> network.prefer.
        if config.general.prefer_ipv6 {
            if config.network.prefer == 4 {
                config.network.prefer = 6;
            }
            warn!("prefer_ipv6 is deprecated, use [network].prefer = 6");
        }

        if config.general.use_middle_proxy && !config.general.me_secret_atomic_snapshot {
            config.general.me_secret_atomic_snapshot = true;
            warn!(
                "Auto-enabled me_secret_atomic_snapshot for middle proxy mode to keep KDF key_selector/secret coherent"
            );
        }

        validate_network_cfg(&mut config.network)?;
        crate::network::dns_overrides::validate_entries(&config.network.dns_overrides)?;

        if config.general.use_middle_proxy && config.network.ipv6 == Some(true) {
            warn!(
                "IPv6 with Middle Proxy is experimental and may cause KDF address mismatch; consider disabling IPv6 or ME"
            );
        }

        // Random fake_cert_len only when default is in use.
        if !config.censorship.tls_emulation
            && config.censorship.fake_cert_len == default_fake_cert_len()
        {
            config.censorship.fake_cert_len = rand::rng().random_range(1024..4096);
        }

        // Resolve listen_tcp: explicit value wins, otherwise auto-detect.
        // If unix socket is set → TCP only when listen_addr_ipv4 or listeners are explicitly provided.
        // If no unix socket → TCP always (backward compat).
        let listen_tcp = config.server.listen_tcp.unwrap_or_else(|| {
            if config.server.listen_unix_sock.is_some() {
                // Unix socket present: TCP only if user explicitly set addresses or listeners.
                config.server.listen_addr_ipv4.is_some() || !config.server.listeners.is_empty()
            } else {
                true
            }
        });

        // Migration: Populate listeners if empty (skip when listen_tcp = false).
        if config.server.listeners.is_empty() && listen_tcp {
            let ipv4_str = config
                .server
                .listen_addr_ipv4
                .as_deref()
                .unwrap_or("0.0.0.0");
            if let Ok(ipv4) = ipv4_str.parse::<IpAddr>() {
                config.server.listeners.push(ListenerConfig {
                    ip: ipv4,
                    port: Some(config.server.port),
                    client_mss: None,
                    synlimit: SynLimitMode::default(),
                    synlimit_seconds: default_synlimit_seconds(),
                    synlimit_hitcount: default_synlimit_hitcount(),
                    synlimit_burst: default_synlimit_burst(),
                    announce: None,
                    announce_ip: None,
                    proxy_protocol: None,
                    reuse_allow: false,
                });
            }
            if let Some(ipv6_str) = &config.server.listen_addr_ipv6
                && let Ok(ipv6) = ipv6_str.parse::<IpAddr>()
            {
                config.server.listeners.push(ListenerConfig {
                    ip: ipv6,
                    port: Some(config.server.port),
                    client_mss: None,
                    synlimit: SynLimitMode::default(),
                    synlimit_seconds: default_synlimit_seconds(),
                    synlimit_hitcount: default_synlimit_hitcount(),
                    synlimit_burst: default_synlimit_burst(),
                    announce: None,
                    announce_ip: None,
                    proxy_protocol: None,
                    reuse_allow: false,
                });
            }
        }

        // Migration: listeners[].port fallback to legacy server.port.
        for listener in &mut config.server.listeners {
            if listener.port.is_none() {
                listener.port = Some(config.server.port);
            }
        }

        // Migration: announce_ip → announce for each listener.
        for listener in &mut config.server.listeners {
            if listener.announce.is_none()
                && let Some(ip) = listener.announce_ip.take()
            {
                listener.announce = Some(ip.to_string());
            }
        }

        // Migration: show_link (top-level) → general.links.show.
        if !config.show_link.is_empty() && config.general.links.show.is_empty() {
            config.general.links.show = config.show_link.clone();
        }

        // Migration: Populate upstreams if empty (Default Direct).
        if config.upstreams.is_empty() {
            config.upstreams.push(UpstreamConfig {
                upstream_type: UpstreamType::Direct {
                    interface: None,
                    bind_addresses: None,
                    bindtodevice: None,
                },
                weight: 1,
                enabled: true,
                scopes: String::new(),
                selected_scope: String::new(),
                ipv4: None,
                ipv6: None,
                prefer: None,
            });
        }
        normalize_upstream_family_policy(&mut config);

        // Ensure default DC203 override is present.
        config
            .dc_overrides
            .entry("203".to_string())
            .or_insert_with(|| vec!["91.105.192.100:443".to_string()]);

        validate_logging_config(&config.logging)?;
        validate_upstreams(&config)?;
        config.rebuild_runtime_user_auth()?;

        Ok(LoadedConfig {
            config,
            source_files: source_files.into_iter().collect(),
            rendered_hash: hash_rendered_snapshot(&processed),
        })
    }

    pub(crate) fn rebuild_runtime_user_auth(&mut self) -> Result<()> {
        let snapshot = UserAuthSnapshot::from_users(&self.access.users)?;
        self.runtime_user_auth = Some(Arc::new(snapshot));
        Ok(())
    }

    pub(crate) fn runtime_user_auth(&self) -> Option<&UserAuthSnapshot> {
        self.runtime_user_auth.as_deref()
    }

    pub fn validate(&self) -> Result<()> {
        if self.access.users.is_empty() {
            return Err(ProxyError::Config("No users configured".to_string()));
        }

        validate_logging_config(&self.logging)?;

        if !self.general.modes.classic && !self.general.modes.secure && !self.general.modes.tls {
            return Err(ProxyError::Config("No modes enabled".to_string()));
        }

        if !is_valid_tls_domain_name(&self.censorship.tls_domain) {
            return Err(ProxyError::Config(format!(
                "Invalid tls_domain: '{}'. Must be a valid domain name",
                self.censorship.tls_domain
            )));
        }

        for domain in &self.censorship.tls_domains {
            if !is_valid_tls_domain_name(domain) {
                return Err(ProxyError::Config(format!(
                    "Invalid tls_domains entry: '{}'. Must be a valid domain name",
                    domain
                )));
            }
        }

        for (domain, target) in &self.censorship.exclusive_mask {
            if !is_valid_tls_domain_name(domain) {
                return Err(ProxyError::Config(format!(
                    "Invalid censorship.exclusive_mask domain: '{}'. Must be a valid domain name",
                    domain
                )));
            }
            if parse_exclusive_mask_target(target).is_none() {
                return Err(ProxyError::Config(format!(
                    "Invalid censorship.exclusive_mask target for '{}': '{}'. Expected host:port with port > 0",
                    domain, target
                )));
            }
        }

        for (user, tag) in &self.access.user_ad_tags {
            let zeros = "00000000000000000000000000000000";
            if !is_valid_ad_tag(tag) {
                return Err(ProxyError::Config(format!(
                    "access.user_ad_tags['{}'] must be exactly 32 hex characters",
                    user
                )));
            }
            if tag == zeros {
                warn!(user = %user, "user ad_tag is all zeros; register a valid proxy tag via @MTProxybot to enable sponsored channel");
            }
        }

        crate::network::dns_overrides::validate_entries(&self.network.dns_overrides)?;

        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/load_idle_policy_tests.rs"]
mod load_idle_policy_tests;

#[cfg(test)]
#[path = "tests/load_security_tests.rs"]
mod load_security_tests;

#[cfg(test)]
#[path = "tests/load_mask_shape_security_tests.rs"]
mod load_mask_shape_security_tests;

#[cfg(test)]
#[path = "tests/load_mask_classifier_prefetch_timeout_security_tests.rs"]
mod load_mask_classifier_prefetch_timeout_security_tests;

#[cfg(test)]
#[path = "tests/load_memory_envelope_tests.rs"]
mod load_memory_envelope_tests;

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SHADOWSOCKS_URL: &str =
        "ss://2022-blake3-aes-256-gcm:MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=@127.0.0.1:8388";

    fn load_config_from_temp_toml(toml: &str) -> ProxyConfig {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("telemt_load_cfg_{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(dir);
        cfg
    }

    fn load_config_error_from_temp_toml(toml: &str) -> String {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("telemt_load_cfg_error_{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, toml).unwrap();
        let error = ProxyConfig::load(&path).unwrap_err().to_string();
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(dir);
        error
    }

    #[test]
    fn serde_defaults_remain_unchanged_for_present_sections() {
        let toml = r#"
            [network]
            [general]
            [server]
            [access]
        "#;
        let cfg: ProxyConfig = toml::from_str(toml).unwrap();

        assert_eq!(cfg.logging, LoggingConfig::default());
        assert_eq!(cfg.network.ipv6, default_network_ipv6());
        assert_eq!(cfg.network.stun_use, default_true());
        assert_eq!(cfg.network.stun_tcp_fallback, default_stun_tcp_fallback());
        assert_eq!(
            cfg.general.middle_proxy_warm_standby,
            default_middle_proxy_warm_standby()
        );
        assert_eq!(
            cfg.general.me_reconnect_max_concurrent_per_dc,
            default_me_reconnect_max_concurrent_per_dc()
        );
        assert_eq!(
            cfg.general.me_reconnect_fast_retry_count,
            default_me_reconnect_fast_retry_count()
        );
        assert_eq!(
            cfg.general.me_init_retry_attempts,
            default_me_init_retry_attempts()
        );
        assert_eq!(cfg.general.me2dc_fallback, default_me2dc_fallback());
        assert_eq!(cfg.general.me2dc_fast, default_me2dc_fast());
        assert_eq!(
            cfg.general.proxy_config_v4_cache_path,
            default_proxy_config_v4_cache_path()
        );
        assert_eq!(
            cfg.general.proxy_config_v6_cache_path,
            default_proxy_config_v6_cache_path()
        );
        assert_eq!(
            cfg.general.me_single_endpoint_shadow_writers,
            default_me_single_endpoint_shadow_writers()
        );
        assert_eq!(
            cfg.general.me_single_endpoint_outage_mode_enabled,
            default_me_single_endpoint_outage_mode_enabled()
        );
        assert_eq!(
            cfg.general.me_single_endpoint_outage_disable_quarantine,
            default_me_single_endpoint_outage_disable_quarantine()
        );
        assert_eq!(
            cfg.general.me_single_endpoint_outage_backoff_min_ms,
            default_me_single_endpoint_outage_backoff_min_ms()
        );
        assert_eq!(
            cfg.general.me_single_endpoint_outage_backoff_max_ms,
            default_me_single_endpoint_outage_backoff_max_ms()
        );
        assert_eq!(
            cfg.general.me_single_endpoint_shadow_rotate_every_secs,
            default_me_single_endpoint_shadow_rotate_every_secs()
        );
        assert_eq!(cfg.general.me_floor_mode, MeFloorMode::default());
        assert_eq!(
            cfg.general.me_adaptive_floor_idle_secs,
            default_me_adaptive_floor_idle_secs()
        );
        assert_eq!(
            cfg.general.me_adaptive_floor_min_writers_single_endpoint,
            default_me_adaptive_floor_min_writers_single_endpoint()
        );
        assert_eq!(
            cfg.general.me_adaptive_floor_recover_grace_secs,
            default_me_adaptive_floor_recover_grace_secs()
        );
        assert_eq!(
            cfg.general.upstream_connect_retry_attempts,
            default_upstream_connect_retry_attempts()
        );
        assert_eq!(
            cfg.general.upstream_connect_retry_backoff_ms,
            default_upstream_connect_retry_backoff_ms()
        );
        assert_eq!(
            cfg.general.upstream_unhealthy_fail_threshold,
            default_upstream_unhealthy_fail_threshold()
        );
        assert_eq!(
            cfg.general.upstream_connect_failfast_hard_errors,
            default_upstream_connect_failfast_hard_errors()
        );
        assert_eq!(
            cfg.general.rpc_proxy_req_every,
            default_rpc_proxy_req_every()
        );
        assert_eq!(cfg.general.beobachten_file, default_beobachten_file());
        assert_eq!(cfg.general.update_every, default_update_every());
        assert_eq!(cfg.server.listen_addr_ipv4, default_listen_addr_ipv4());
        assert_eq!(cfg.server.listen_addr_ipv6, default_listen_addr_ipv6_opt());
        assert_eq!(cfg.server.client_mss_value(), Ok(None));
        assert_eq!(
            cfg.server.proxy_protocol_trusted_cidrs,
            default_proxy_protocol_trusted_cidrs()
        );
        assert_eq!(cfg.censorship.unknown_sni_action, UnknownSniAction::Drop);
        assert_eq!(cfg.server.api.listen, default_api_listen());
        assert_eq!(cfg.server.api.whitelist, default_api_whitelist());
        assert_eq!(cfg.server.api.gray_action, ApiGrayAction::Drop);
        assert_eq!(
            cfg.server.api.request_body_limit_bytes,
            default_api_request_body_limit_bytes()
        );
        assert_eq!(
            cfg.server.api.minimal_runtime_enabled,
            default_api_minimal_runtime_enabled()
        );
        assert_eq!(
            cfg.server.api.minimal_runtime_cache_ttl_ms,
            default_api_minimal_runtime_cache_ttl_ms()
        );
        assert_eq!(
            cfg.server.api.runtime_edge_enabled,
            default_api_runtime_edge_enabled()
        );
        assert_eq!(
            cfg.server.api.runtime_edge_cache_ttl_ms,
            default_api_runtime_edge_cache_ttl_ms()
        );
        assert_eq!(
            cfg.server.api.runtime_edge_top_n,
            default_api_runtime_edge_top_n()
        );
        assert_eq!(
            cfg.server.api.runtime_edge_events_capacity,
            default_api_runtime_edge_events_capacity()
        );
        assert_eq!(
            cfg.server.conntrack_control.inline_conntrack_control,
            default_conntrack_control_enabled()
        );
        assert_eq!(cfg.server.conntrack_control.mode, ConntrackMode::default());
        assert_eq!(
            cfg.server.conntrack_control.backend,
            ConntrackBackend::default()
        );
        assert_eq!(
            cfg.server.conntrack_control.profile,
            ConntrackPressureProfile::default()
        );
        assert_eq!(
            cfg.server.conntrack_control.pressure_high_watermark_pct,
            default_conntrack_pressure_high_watermark_pct()
        );
        assert_eq!(
            cfg.server.conntrack_control.pressure_low_watermark_pct,
            default_conntrack_pressure_low_watermark_pct()
        );
        assert_eq!(
            cfg.server.conntrack_control.delete_budget_per_sec,
            default_conntrack_delete_budget_per_sec()
        );
        assert_eq!(cfg.access.users, default_access_users());
        assert_eq!(
            cfg.access.user_max_tcp_conns_global_each,
            default_user_max_tcp_conns_global_each()
        );
        assert_eq!(
            cfg.access.user_max_unique_ips_mode,
            UserMaxUniqueIpsMode::default()
        );
        assert_eq!(
            cfg.access.user_max_unique_ips_window_secs,
            default_user_max_unique_ips_window_secs()
        );
    }

    #[test]
    fn logging_config_is_loaded_from_strict_config() {
        let cfg = load_config_from_temp_toml(
            r#"
                [general]
                config_strict = true

                [general.modes]
                classic = false
                secure = false
                tls = true

                [logging]
                destination = "file"
                path = "/tmp/telemt.log"
                rotation = "daily"
                max_size_bytes = 1024
                max_files = 3
                max_age_secs = 60

                [censorship]
                tls_domain = "example.com"

                [access.users]
                user = "00000000000000000000000000000000"
            "#,
        );

        assert_eq!(cfg.logging.destination, LoggingDestination::File);
        assert_eq!(cfg.logging.path.as_deref(), Some("/tmp/telemt.log"));
        assert_eq!(cfg.logging.rotation, LogRotation::Daily);
        assert_eq!(cfg.logging.max_size_bytes, 1024);
        assert_eq!(cfg.logging.max_files, 3);
        assert_eq!(cfg.logging.max_age_secs, 60);
    }

    #[test]
    fn file_logging_requires_path() {
        let error = load_config_error_from_temp_toml(
            r#"
                [general.modes]
                classic = false
                secure = false
                tls = true

                [logging]
                destination = "file"

                [censorship]
                tls_domain = "example.com"

                [access.users]
                user = "00000000000000000000000000000000"
            "#,
        );

        assert!(error.contains("logging.path must be set"));
    }

    #[test]
    fn impl_defaults_are_sourced_from_default_helpers() {
        let network = NetworkConfig::default();
        assert_eq!(network.ipv6, default_network_ipv6());
        assert_eq!(network.stun_use, default_true());
        assert_eq!(network.stun_tcp_fallback, default_stun_tcp_fallback());

        let general = GeneralConfig::default();
        assert_eq!(
            general.middle_proxy_warm_standby,
            default_middle_proxy_warm_standby()
        );
        assert_eq!(
            general.me_reconnect_max_concurrent_per_dc,
            default_me_reconnect_max_concurrent_per_dc()
        );
        assert_eq!(
            general.me_reconnect_fast_retry_count,
            default_me_reconnect_fast_retry_count()
        );
        assert_eq!(
            general.me_init_retry_attempts,
            default_me_init_retry_attempts()
        );
        assert_eq!(general.me2dc_fallback, default_me2dc_fallback());
        assert_eq!(general.me2dc_fast, default_me2dc_fast());
        assert_eq!(
            general.proxy_config_v4_cache_path,
            default_proxy_config_v4_cache_path()
        );
        assert_eq!(
            general.proxy_config_v6_cache_path,
            default_proxy_config_v6_cache_path()
        );
        assert_eq!(
            general.me_single_endpoint_shadow_writers,
            default_me_single_endpoint_shadow_writers()
        );
        assert_eq!(
            general.me_single_endpoint_outage_mode_enabled,
            default_me_single_endpoint_outage_mode_enabled()
        );
        assert_eq!(
            general.me_single_endpoint_outage_disable_quarantine,
            default_me_single_endpoint_outage_disable_quarantine()
        );
        assert_eq!(
            general.me_single_endpoint_outage_backoff_min_ms,
            default_me_single_endpoint_outage_backoff_min_ms()
        );
        assert_eq!(
            general.me_single_endpoint_outage_backoff_max_ms,
            default_me_single_endpoint_outage_backoff_max_ms()
        );
        assert_eq!(
            general.me_single_endpoint_shadow_rotate_every_secs,
            default_me_single_endpoint_shadow_rotate_every_secs()
        );
        assert_eq!(general.me_floor_mode, MeFloorMode::default());
        assert_eq!(
            general.me_adaptive_floor_idle_secs,
            default_me_adaptive_floor_idle_secs()
        );
        assert_eq!(
            general.me_adaptive_floor_min_writers_single_endpoint,
            default_me_adaptive_floor_min_writers_single_endpoint()
        );
        assert_eq!(
            general.me_adaptive_floor_recover_grace_secs,
            default_me_adaptive_floor_recover_grace_secs()
        );
        assert_eq!(
            general.upstream_connect_retry_attempts,
            default_upstream_connect_retry_attempts()
        );
        assert_eq!(
            general.upstream_connect_retry_backoff_ms,
            default_upstream_connect_retry_backoff_ms()
        );
        assert_eq!(
            general.upstream_unhealthy_fail_threshold,
            default_upstream_unhealthy_fail_threshold()
        );
        assert_eq!(
            general.upstream_connect_failfast_hard_errors,
            default_upstream_connect_failfast_hard_errors()
        );
        assert_eq!(general.rpc_proxy_req_every, default_rpc_proxy_req_every());
        assert_eq!(general.beobachten_file, default_beobachten_file());
        assert_eq!(general.update_every, default_update_every());

        let server = ServerConfig::default();
        assert_eq!(server.listen_addr_ipv6, Some(default_listen_addr_ipv6()));
        assert_eq!(
            server.proxy_protocol_trusted_cidrs,
            default_proxy_protocol_trusted_cidrs()
        );
        assert_eq!(
            AntiCensorshipConfig::default().unknown_sni_action,
            UnknownSniAction::Drop
        );
        assert_eq!(server.api.listen, default_api_listen());
        assert_eq!(server.api.whitelist, default_api_whitelist());
        assert_eq!(server.api.gray_action, ApiGrayAction::Drop);
        assert_eq!(
            server.api.request_body_limit_bytes,
            default_api_request_body_limit_bytes()
        );
        assert_eq!(
            server.api.minimal_runtime_enabled,
            default_api_minimal_runtime_enabled()
        );
        assert_eq!(
            server.api.minimal_runtime_cache_ttl_ms,
            default_api_minimal_runtime_cache_ttl_ms()
        );
        assert_eq!(
            server.api.runtime_edge_enabled,
            default_api_runtime_edge_enabled()
        );
        assert_eq!(
            server.api.runtime_edge_cache_ttl_ms,
            default_api_runtime_edge_cache_ttl_ms()
        );
        assert_eq!(
            server.api.runtime_edge_top_n,
            default_api_runtime_edge_top_n()
        );
        assert_eq!(
            server.api.runtime_edge_events_capacity,
            default_api_runtime_edge_events_capacity()
        );
        assert_eq!(
            server.conntrack_control.inline_conntrack_control,
            default_conntrack_control_enabled()
        );
        assert_eq!(server.conntrack_control.mode, ConntrackMode::default());
        assert_eq!(
            server.conntrack_control.backend,
            ConntrackBackend::default()
        );
        assert_eq!(
            server.conntrack_control.profile,
            ConntrackPressureProfile::default()
        );
        assert_eq!(
            server.conntrack_control.pressure_high_watermark_pct,
            default_conntrack_pressure_high_watermark_pct()
        );
        assert_eq!(
            server.conntrack_control.pressure_low_watermark_pct,
            default_conntrack_pressure_low_watermark_pct()
        );
        assert_eq!(
            server.conntrack_control.delete_budget_per_sec,
            default_conntrack_delete_budget_per_sec()
        );

        let access = AccessConfig::default();
        assert_eq!(access.users, default_access_users());
        assert_eq!(
            access.user_max_tcp_conns_global_each,
            default_user_max_tcp_conns_global_each()
        );
    }

    #[test]
    fn proxy_protocol_trusted_cidrs_missing_uses_trust_all_but_explicit_empty_stays_empty() {
        let cfg_missing: ProxyConfig = toml::from_str(
            r#"
            [server]
            [general]
            [network]
            [access]
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg_missing.server.proxy_protocol_trusted_cidrs,
            default_proxy_protocol_trusted_cidrs()
        );

        let cfg_explicit_empty: ProxyConfig = toml::from_str(
            r#"
            [server]
            proxy_protocol_trusted_cidrs = []

            [general]
            [network]
            [access]
            "#,
        )
        .unwrap();
        assert!(
            cfg_explicit_empty
                .server
                .proxy_protocol_trusted_cidrs
                .is_empty()
        );
    }

    #[test]
    fn conntrack_inline_explicit_flag_is_false_when_omitted() {
        let cfg = load_config_from_temp_toml(
            r#"
            [general]
            [network]
            [server]
            [server.conntrack_control]
            [access]
            "#,
        );
        assert!(
            !cfg.server
                .conntrack_control
                .inline_conntrack_control_explicit
        );
    }

    #[test]
    fn conntrack_inline_explicit_flag_is_true_when_present() {
        let cfg = load_config_from_temp_toml(
            r#"
            [general]
            [network]
            [server]
            [server.conntrack_control]
            inline_conntrack_control = true
            [access]
            "#,
        );
        assert!(
            cfg.server
                .conntrack_control
                .inline_conntrack_control_explicit
        );
    }

    #[test]
    fn unknown_sni_action_parses_and_defaults_to_drop() {
        let cfg_default: ProxyConfig = toml::from_str(
            r#"
            [server]
            [general]
            [network]
            [access]
            [censorship]
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg_default.censorship.unknown_sni_action,
            UnknownSniAction::Drop
        );

        let cfg_mask: ProxyConfig = toml::from_str(
            r#"
            [server]
            [general]
            [network]
            [access]
            [censorship]
            unknown_sni_action = "mask"
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg_mask.censorship.unknown_sni_action,
            UnknownSniAction::Mask
        );

        let cfg_accept: ProxyConfig = toml::from_str(
            r#"
            [server]
            [general]
            [network]
            [access]
            [censorship]
            unknown_sni_action = "accept"
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg_accept.censorship.unknown_sni_action,
            UnknownSniAction::Accept
        );

        let cfg_reject: ProxyConfig = toml::from_str(
            r#"
            [server]
            [general]
            [network]
            [access]
            [censorship]
            unknown_sni_action = "reject_handshake"
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg_reject.censorship.unknown_sni_action,
            UnknownSniAction::RejectHandshake
        );
    }

    #[test]
    fn exclusive_mask_parses_domain_target_map() {
        let cfg = load_config_from_temp_toml(
            r#"
            [general]
            [network]
            [server]
            [access]
            [censorship]
            tls_domain = "weißbiergärten.de"
            tls_domains = ["bürgeramt.de"]
            [censorship.exclusive_mask]
            "bürgeramt.de" = "rindfleischetikettierungsüberwachungsaufgabenübertragungsgesetz.de:443"
            "ipv6.example" = "[::1]:443"
            "#,
        );

        assert!(cfg.censorship.tls_domain.is_ascii());
        assert!(cfg.censorship.tls_domain.contains("xn--"));
        assert_eq!(cfg.censorship.tls_domains.len(), 1);
        let normalized_extra = &cfg.censorship.tls_domains[0];
        assert!(normalized_extra.is_ascii());
        assert!(normalized_extra.contains("xn--"));

        let normalized_target = cfg
            .censorship
            .exclusive_mask
            .get(normalized_extra)
            .expect("exclusive_mask key must match normalized tls_domains entry");
        assert!(normalized_target.is_ascii());
        assert!(normalized_target.contains("xn--"));
        assert!(normalized_target.ends_with(":443"));
        assert_eq!(
            cfg.censorship.exclusive_mask.get("ipv6.example"),
            Some(&"[::1]:443".to_string())
        );
    }

    #[test]
    fn api_gray_action_parses_and_defaults_to_drop() {
        let cfg_default: ProxyConfig = toml::from_str(
            r#"
            [server]
            [general]
            [network]
            [access]
            "#,
        )
        .unwrap();
        assert_eq!(cfg_default.server.api.gray_action, ApiGrayAction::Drop);

        let cfg_api: ProxyConfig = toml::from_str(
            r#"
            [server]
            [general]
            [network]
            [access]
            [server.api]
            gray_action = "api"
            "#,
        )
        .unwrap();
        assert_eq!(cfg_api.server.api.gray_action, ApiGrayAction::Api);

        let cfg_200: ProxyConfig = toml::from_str(
            r#"
            [server]
            [general]
            [network]
            [access]
            [server.api]
            gray_action = "200"
            "#,
        )
        .unwrap();
        assert_eq!(cfg_200.server.api.gray_action, ApiGrayAction::Ok200);

        let cfg_drop: ProxyConfig = toml::from_str(
            r#"
            [server]
            [general]
            [network]
            [access]
            [server.api]
            gray_action = "drop"
            "#,
        )
        .unwrap();
        assert_eq!(cfg_drop.server.api.gray_action, ApiGrayAction::Drop);
    }

    #[test]
    fn top_level_beobachten_keys_migrate_to_general_when_general_not_explicit() {
        let cfg = load_config_from_temp_toml(
            r#"
            beobachten = false
            beobachten_minutes = 7
            beobachten_flush_secs = 3
            beobachten_file = "tmp/legacy-beob.txt"

            [server]
            [general]
            [network]
            [access]
            "#,
        );

        assert!(!cfg.general.beobachten);
        assert_eq!(cfg.general.beobachten_minutes, 7);
        assert_eq!(cfg.general.beobachten_flush_secs, 3);
        assert_eq!(cfg.general.beobachten_file, "tmp/legacy-beob.txt");
    }

    #[test]
    fn general_beobachten_keys_have_priority_over_legacy_top_level() {
        let cfg = load_config_from_temp_toml(
            r#"
            beobachten = true
            beobachten_minutes = 30
            beobachten_flush_secs = 30
            beobachten_file = "tmp/legacy-beob.txt"

            [server]
            [general]
            beobachten = false
            beobachten_minutes = 5
            beobachten_flush_secs = 2
            beobachten_file = "tmp/general-beob.txt"
            [network]
            [access]
            "#,
        );

        assert!(!cfg.general.beobachten);
        assert_eq!(cfg.general.beobachten_minutes, 5);
        assert_eq!(cfg.general.beobachten_flush_secs, 2);
        assert_eq!(cfg.general.beobachten_file, "tmp/general-beob.txt");
    }

    #[test]
    fn dc_overrides_allow_string_and_array() {
        let toml = r#"
            [dc_overrides]
            "201" = "149.154.175.50:443"
            "202" = ["149.154.167.51:443", "149.154.175.100:443"]
        "#;
        let cfg: ProxyConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.dc_overrides["201"], vec!["149.154.175.50:443"]);
        assert_eq!(
            cfg.dc_overrides["202"],
            vec!["149.154.167.51:443", "149.154.175.100:443"]
        );
    }

    #[test]
    fn load_with_metadata_collects_include_files() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("telemt_load_metadata_{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        let main_path = dir.join("config.toml");
        let include_path = dir.join("included.toml");

        std::fs::write(
            &include_path,
            r#"
                [access.users]
                user = "00000000000000000000000000000000"
            "#,
        )
        .unwrap();
        std::fs::write(
            &main_path,
            r#"
                include = "included.toml"

                [censorship]
                tls_domain = "example.com"
            "#,
        )
        .unwrap();

        let loaded = ProxyConfig::load_with_metadata(&main_path).unwrap();
        let main_normalized = normalize_config_path(&main_path);
        let include_normalized = normalize_config_path(&include_path);

        assert!(loaded.source_files.contains(&main_normalized));
        assert!(loaded.source_files.contains(&include_normalized));

        let _ = std::fs::remove_file(main_path);
        let _ = std::fs::remove_file(include_path);
        let _ = std::fs::remove_dir(dir);
    }

    #[test]
    fn dc_overrides_inject_dc203_default() {
        let toml = r#"
            [general]
            use_middle_proxy = false

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_dc_override_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert!(
            cfg.dc_overrides
                .get("203")
                .map(|v| v.contains(&"91.105.192.100:443".to_string()))
                .unwrap_or(false)
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn update_every_overrides_legacy_fields() {
        let toml = r#"
            [general]
            update_every = 123
            proxy_secret_auto_reload_secs = 700
            proxy_config_auto_reload_secs = 800

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_update_every_override_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(cfg.general.effective_update_every_secs(), 123);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn update_every_fallback_to_legacy_min() {
        let toml = r#"
            [general]
            proxy_secret_auto_reload_secs = 600
            proxy_config_auto_reload_secs = 120

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_update_every_legacy_min_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(cfg.general.update_every, None);
        assert_eq!(cfg.general.effective_update_every_secs(), 120);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn update_every_zero_is_rejected() {
        let toml = r#"
            [general]
            update_every = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_update_every_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.update_every must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn stun_nat_probe_concurrency_zero_is_rejected() {
        let toml = r#"
            [general]
            stun_nat_probe_concurrency = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_stun_nat_probe_concurrency_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.stun_nat_probe_concurrency must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_reinit_every_default_is_set() {
        let toml = r#"
            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_reinit_every_default_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(
            cfg.general.me_reinit_every_secs,
            default_me_reinit_every_secs()
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_reinit_every_zero_is_rejected() {
        let toml = r#"
            [general]
            me_reinit_every_secs = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_reinit_every_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_reinit_every_secs must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_single_endpoint_outage_backoff_range_is_validated() {
        let toml = r#"
            [general]
            me_single_endpoint_outage_backoff_min_ms = 4000
            me_single_endpoint_outage_backoff_max_ms = 3000

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_single_endpoint_outage_backoff_range_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains(
            "general.me_single_endpoint_outage_backoff_min_ms must be <= general.me_single_endpoint_outage_backoff_max_ms"
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_single_endpoint_shadow_writers_too_large_is_rejected() {
        let toml = r#"
            [general]
            me_single_endpoint_shadow_writers = 33

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_single_endpoint_shadow_writers_limit_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_single_endpoint_shadow_writers must be within [0, 32]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_adaptive_floor_min_writers_out_of_range_is_rejected() {
        let toml = r#"
            [general]
            me_adaptive_floor_min_writers_single_endpoint = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_adaptive_floor_min_writers_out_of_range_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains(
            "general.me_adaptive_floor_min_writers_single_endpoint must be within [1, 32]"
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_floor_mode_adaptive_is_parsed() {
        let toml = r#"
            [general]
            me_floor_mode = "adaptive"

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_floor_mode_adaptive_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(cfg.general.me_floor_mode, MeFloorMode::Adaptive);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_adaptive_floor_max_active_writers_per_core_zero_is_rejected() {
        let toml = r#"
            [general]
            me_adaptive_floor_max_active_writers_per_core = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_adaptive_floor_max_active_per_core_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_adaptive_floor_max_active_writers_per_core must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_adaptive_floor_max_warm_writers_global_zero_is_rejected() {
        let toml = r#"
            [general]
            me_adaptive_floor_max_warm_writers_global = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_adaptive_floor_max_warm_global_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_adaptive_floor_max_warm_writers_global must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn upstream_connect_retry_attempts_zero_is_rejected() {
        let toml = r#"
            [general]
            upstream_connect_retry_attempts = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_upstream_connect_retry_attempts_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.upstream_connect_retry_attempts must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn upstream_unhealthy_fail_threshold_zero_is_rejected() {
        let toml = r#"
            [general]
            upstream_unhealthy_fail_threshold = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_upstream_unhealthy_fail_threshold_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.upstream_unhealthy_fail_threshold must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tg_connect_zero_is_rejected() {
        let toml = r#"
            [general]
            tg_connect = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_tg_connect_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.tg_connect must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rpc_proxy_req_every_out_of_range_is_rejected() {
        let toml = r#"
            [general]
            rpc_proxy_req_every = 9

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_rpc_proxy_req_every_out_of_range_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.rpc_proxy_req_every must be 0 or within [10, 300]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rpc_proxy_req_every_zero_and_valid_range_are_accepted() {
        let toml_zero = r#"
            [general]
            rpc_proxy_req_every = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path_zero = dir.join("telemt_rpc_proxy_req_every_zero_ok_test.toml");
        std::fs::write(&path_zero, toml_zero).unwrap();
        let cfg_zero = ProxyConfig::load(&path_zero).unwrap();
        assert_eq!(cfg_zero.general.rpc_proxy_req_every, 0);
        let _ = std::fs::remove_file(path_zero);

        let toml_valid = r#"
            [general]
            rpc_proxy_req_every = 40

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let path_valid = dir.join("telemt_rpc_proxy_req_every_valid_ok_test.toml");
        std::fs::write(&path_valid, toml_valid).unwrap();
        let cfg_valid = ProxyConfig::load(&path_valid).unwrap();
        assert_eq!(cfg_valid.general.rpc_proxy_req_every, 40);
        let _ = std::fs::remove_file(path_valid);
    }

    #[test]
    fn me_route_backpressure_base_timeout_ms_out_of_range_is_rejected() {
        let toml = r#"
            [general]
            me_route_backpressure_base_timeout_ms = 5001

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_route_backpressure_base_timeout_ms_out_of_range_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("general.me_route_backpressure_base_timeout_ms must be within [1, 5000]")
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_route_backpressure_high_timeout_ms_out_of_range_is_rejected() {
        let toml = r#"
            [general]
            me_route_backpressure_base_timeout_ms = 100
            me_route_backpressure_high_timeout_ms = 5001

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_route_backpressure_high_timeout_ms_out_of_range_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("general.me_route_backpressure_high_timeout_ms must be within [1, 5000]")
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_route_no_writer_wait_ms_out_of_range_is_rejected() {
        let toml = r#"
            [general]
            me_route_no_writer_wait_ms = 5

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_route_no_writer_wait_ms_out_of_range_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_route_no_writer_wait_ms must be within [10, 5000]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_route_blocking_send_timeout_ms_zero_is_rejected() {
        let toml = r#"
            [general]
            me_route_blocking_send_timeout_ms = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_route_blocking_send_timeout_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_route_blocking_send_timeout_ms must be within [1, 5000]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_route_no_writer_mode_is_parsed() {
        let toml = r#"
            [general]
            me_route_no_writer_mode = "inline_recovery_legacy"

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_route_no_writer_mode_parse_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(
            cfg.general.me_route_no_writer_mode,
            crate::config::MeRouteNoWriterMode::InlineRecoveryLegacy
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn proxy_config_cache_paths_empty_are_rejected() {
        let toml = r#"
            [general]
            proxy_config_v4_cache_path = "   "

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_proxy_config_v4_cache_path_empty_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.proxy_config_v4_cache_path cannot be empty"));
        let _ = std::fs::remove_file(path);

        let toml_v6 = r#"
            [general]
            proxy_config_v6_cache_path = ""

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let path_v6 = dir.join("telemt_proxy_config_v6_cache_path_empty_test.toml");
        std::fs::write(&path_v6, toml_v6).unwrap();
        let err_v6 = ProxyConfig::load(&path_v6).unwrap_err().to_string();
        assert!(err_v6.contains("general.proxy_config_v6_cache_path cannot be empty"));
        let _ = std::fs::remove_file(path_v6);
    }

    #[test]
    fn me_hardswap_warmup_defaults_are_set() {
        let toml = r#"
            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_hardswap_warmup_defaults_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(
            cfg.general.me_hardswap_warmup_delay_min_ms,
            default_me_hardswap_warmup_delay_min_ms()
        );
        assert_eq!(
            cfg.general.me_hardswap_warmup_delay_max_ms,
            default_me_hardswap_warmup_delay_max_ms()
        );
        assert_eq!(
            cfg.general.me_hardswap_warmup_extra_passes,
            default_me_hardswap_warmup_extra_passes()
        );
        assert_eq!(
            cfg.general.me_hardswap_warmup_pass_backoff_base_ms,
            default_me_hardswap_warmup_pass_backoff_base_ms()
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_hardswap_warmup_delay_range_is_validated() {
        let toml = r#"
            [general]
            me_hardswap_warmup_delay_min_ms = 2001
            me_hardswap_warmup_delay_max_ms = 2000

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_hardswap_warmup_delay_range_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains(
            "general.me_hardswap_warmup_delay_min_ms must be <= general.me_hardswap_warmup_delay_max_ms"
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_hardswap_warmup_delay_max_zero_is_rejected() {
        let toml = r#"
            [general]
            me_hardswap_warmup_delay_max_ms = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_hardswap_warmup_delay_max_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_hardswap_warmup_delay_max_ms must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_hardswap_warmup_extra_passes_out_of_range_is_rejected() {
        let toml = r#"
            [general]
            me_hardswap_warmup_extra_passes = 11

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_hardswap_warmup_extra_passes_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_hardswap_warmup_extra_passes must be within [0, 10]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_hardswap_warmup_pass_backoff_zero_is_rejected() {
        let toml = r#"
            [general]
            me_hardswap_warmup_pass_backoff_base_ms = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_hardswap_warmup_backoff_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_hardswap_warmup_pass_backoff_base_ms must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_config_stable_snapshots_zero_is_rejected() {
        let toml = r#"
            [general]
            me_config_stable_snapshots = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_config_stable_snapshots_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_config_stable_snapshots must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn proxy_secret_stable_snapshots_zero_is_rejected() {
        let toml = r#"
            [general]
            proxy_secret_stable_snapshots = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_proxy_secret_stable_snapshots_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.proxy_secret_stable_snapshots must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn proxy_secret_len_max_out_of_range_is_rejected() {
        let toml = r#"
            [general]
            proxy_secret_len_max = 16

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_proxy_secret_len_max_out_of_range_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.proxy_secret_len_max must be within [32, 4096]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn me_pool_min_fresh_ratio_out_of_range_is_rejected() {
        let toml = r#"
            [general]
            me_pool_min_fresh_ratio = 1.5

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_me_pool_min_ratio_invalid_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("general.me_pool_min_fresh_ratio must be within [0.0, 1.0]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn api_minimal_runtime_cache_ttl_out_of_range_is_rejected() {
        let toml = r#"
            [server.api]
            enabled = true
            listen = "127.0.0.1:9091"
            minimal_runtime_cache_ttl_ms = 70000

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_api_minimal_runtime_cache_ttl_invalid_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("server.api.minimal_runtime_cache_ttl_ms must be within [0, 60000]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn client_mss_presets_and_listener_override_are_resolved() {
        let toml = r#"
            [server]
            client_mss = "tspu"

            [[server.listeners]]
            ip = "127.0.0.1"
            port = 1443

            [[server.listeners]]
            ip = "127.0.0.2"
            port = 1444
            client_mss = "2in8"

            [[server.listeners]]
            ip = "127.0.0.3"
            port = 1445
            client_mss = ""

            [[server.listeners]]
            ip = "127.0.0.4"
            port = 1446
            client_mss = "extreme-low"

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_client_mss_valid_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();

        assert_eq!(cfg.server.client_mss_value(), Ok(Some(92)));
        assert_eq!(
            cfg.server.listeners[0].effective_client_mss(&cfg.server),
            Ok(Some(92))
        );
        assert_eq!(
            cfg.server.listeners[1].effective_client_mss(&cfg.server),
            Ok(Some(256))
        );
        assert_eq!(
            cfg.server.listeners[2].effective_client_mss(&cfg.server),
            Ok(None)
        );
        assert_eq!(
            cfg.server.listeners[3].effective_client_mss(&cfg.server),
            Ok(Some(88))
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn client_mss_custom_value_is_accepted() {
        let toml = r#"
            [server]
            client_mss = "4096"

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_client_mss_custom_valid_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();

        assert_eq!(cfg.server.client_mss_value(), Ok(Some(4096)));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn client_mss_out_of_range_is_rejected() {
        for value in ["87", "4097"] {
            let toml = format!(
                r#"
                [server]
                client_mss = "{value}"

                [censorship]
                tls_domain = "example.com"

                [access.users]
                user = "00000000000000000000000000000000"
            "#
            );
            let dir = std::env::temp_dir();
            let path = dir.join(format!("telemt_client_mss_out_of_range_{value}_test.toml"));
            std::fs::write(&path, toml).unwrap();
            let err = ProxyConfig::load(&path).unwrap_err().to_string();

            assert!(err.contains("server.client_mss custom value must be within [88, 4096]"));
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn client_mss_unquoted_number_is_rejected() {
        let toml = r#"
            [server]
            client_mss = 256

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_client_mss_unquoted_number_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();

        assert!(err.contains("client_mss"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn listener_client_mss_invalid_preset_is_rejected() {
        let toml = r#"
            [[server.listeners]]
            ip = "127.0.0.1"
            port = 1443
            client_mss = "tiny"

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_listener_client_mss_invalid_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();

        assert!(err.contains("server.listeners[0].client_mss"));
        assert!(err.contains("must be \"\", extreme-low, tspu, 2in8"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn api_runtime_edge_cache_ttl_out_of_range_is_rejected() {
        let toml = r#"
            [server.api]
            enabled = true
            listen = "127.0.0.1:9091"
            runtime_edge_cache_ttl_ms = 70000

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_api_runtime_edge_cache_ttl_invalid_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("server.api.runtime_edge_cache_ttl_ms must be within [0, 60000]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn api_runtime_edge_top_n_out_of_range_is_rejected() {
        let toml = r#"
            [server.api]
            enabled = true
            listen = "127.0.0.1:9091"
            runtime_edge_top_n = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_api_runtime_edge_top_n_invalid_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("server.api.runtime_edge_top_n must be within [1, 1000]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn api_runtime_edge_events_capacity_out_of_range_is_rejected() {
        let toml = r#"
            [server.api]
            enabled = true
            listen = "127.0.0.1:9091"
            runtime_edge_events_capacity = 8

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_api_runtime_edge_events_capacity_invalid_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("server.api.runtime_edge_events_capacity must be within [16, 4096]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn conntrack_pressure_high_watermark_out_of_range_is_rejected() {
        let toml = r#"
            [server.conntrack_control]
            pressure_high_watermark_pct = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_conntrack_high_watermark_invalid_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains(
            "server.conntrack_control.pressure_high_watermark_pct must be within [1, 100]"
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn conntrack_pressure_low_watermark_must_be_below_high() {
        let toml = r#"
            [server.conntrack_control]
            pressure_high_watermark_pct = 50
            pressure_low_watermark_pct = 50

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_conntrack_low_watermark_invalid_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(
            err.contains(
                "server.conntrack_control.pressure_low_watermark_pct must be < pressure_high_watermark_pct"
            )
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn conntrack_delete_budget_zero_is_rejected() {
        let toml = r#"
            [server.conntrack_control]
            delete_budget_per_sec = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_conntrack_delete_budget_invalid_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("server.conntrack_control.delete_budget_per_sec must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn conntrack_hybrid_mode_requires_listener_allow_list() {
        let toml = r#"
            [server.conntrack_control]
            mode = "hybrid"

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_conntrack_hybrid_requires_ips_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains(
            "server.conntrack_control.hybrid_listener_ips must be non-empty in mode=hybrid"
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn conntrack_profile_is_loaded_from_config() {
        let toml = r#"
            [server.conntrack_control]
            profile = "aggressive"

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_conntrack_profile_parse_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(
            cfg.server.conntrack_control.profile,
            ConntrackPressureProfile::Aggressive
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn force_close_default_matches_drain_ttl() {
        let toml = r#"
            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_force_close_default_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(cfg.general.me_reinit_drain_timeout_secs, 90);
        assert_eq!(cfg.general.effective_me_pool_force_close_secs(), 90);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn force_close_zero_uses_runtime_safety_fallback() {
        let toml = r#"
            [general]
            me_reinit_drain_timeout_secs = 0

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_force_close_zero_fallback_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(cfg.general.me_reinit_drain_timeout_secs, 0);
        assert_eq!(cfg.general.effective_me_pool_force_close_secs(), 300);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn force_close_bumped_when_below_drain_ttl() {
        let toml = r#"
            [general]
            me_pool_drain_ttl_secs = 90
            me_reinit_drain_timeout_secs = 30

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_force_close_bump_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(cfg.general.me_reinit_drain_timeout_secs, 90);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tls_fetch_scope_default_is_empty() {
        let toml = r#"
            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_tls_fetch_scope_default_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert!(cfg.censorship.tls_fetch_scope.is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tls_fetch_scope_is_trimmed_during_load() {
        let toml = r#"
            [censorship]
            tls_domain = "example.com"
            tls_fetch_scope = "  me  "

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_tls_fetch_scope_trim_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(cfg.censorship.tls_fetch_scope, "me");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tls_fetch_scope_whitespace_becomes_empty() {
        let toml = r#"
            [censorship]
            tls_domain = "example.com"
            tls_fetch_scope = "   "

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_tls_fetch_scope_blank_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert!(cfg.censorship.tls_fetch_scope.is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tls_fetch_defaults_are_applied() {
        let toml = r#"
            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_tls_fetch_defaults_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(
            cfg.censorship.tls_fetch.profiles,
            TlsFetchConfig::default().profiles
        );
        assert!(cfg.censorship.tls_fetch.strict_route);
        assert_eq!(cfg.censorship.tls_fetch.attempt_timeout_ms, 5_000);
        assert_eq!(cfg.censorship.tls_fetch.total_budget_ms, 15_000);
        assert_eq!(cfg.censorship.tls_fetch.profile_cache_ttl_secs, 600);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tls_fetch_profiles_are_deduplicated_preserving_order() {
        let toml = r#"
            [censorship]
            tls_domain = "example.com"
            [censorship.tls_fetch]
            profiles = ["compat_tls12", "modern_chrome_like", "compat_tls12", "legacy_minimal"]

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_tls_fetch_profiles_dedup_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(
            cfg.censorship.tls_fetch.profiles,
            vec![
                TlsFetchProfile::CompatTls12,
                TlsFetchProfile::ModernChromeLike,
                TlsFetchProfile::LegacyMinimal
            ]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tls_fetch_attempt_timeout_zero_is_rejected() {
        let toml = r#"
            [censorship]
            tls_domain = "example.com"
            [censorship.tls_fetch]
            attempt_timeout_ms = 0

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_tls_fetch_attempt_timeout_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("censorship.tls_fetch.attempt_timeout_ms must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tls_fetch_total_budget_zero_is_rejected() {
        let toml = r#"
            [censorship]
            tls_domain = "example.com"
            [censorship.tls_fetch]
            total_budget_ms = 0

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_tls_fetch_total_budget_zero_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("censorship.tls_fetch.total_budget_ms must be > 0"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn invalid_ad_tag_is_disabled_during_load() {
        let toml = r#"
            [general]
            ad_tag = "not_hex"

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_invalid_ad_tag_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert!(cfg.general.ad_tag.is_none());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn valid_ad_tag_is_preserved_during_load() {
        let toml = r#"
            [general]
            ad_tag = "00112233445566778899aabbccddeeff"

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_valid_ad_tag_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(
            cfg.general.ad_tag.as_deref(),
            Some("00112233445566778899aabbccddeeff")
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn shadowsocks_upstream_url_loads_successfully() {
        let toml = format!(
            r#"
            [general]
            use_middle_proxy = false

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"

            [[upstreams]]
            type = "shadowsocks"
            url = "{url}"
            interface = "127.0.0.2"
            "#,
            url = TEST_SHADOWSOCKS_URL,
        );
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_shadowsocks_valid_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();

        assert!(matches!(
            &cfg.upstreams[0].upstream_type,
            UpstreamType::Shadowsocks { url, interface }
                if url == TEST_SHADOWSOCKS_URL && interface.as_deref() == Some("127.0.0.2")
        ));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn shadowsocks_requires_direct_mode() {
        let toml = format!(
            r#"
            [general]
            use_middle_proxy = true

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"

            [[upstreams]]
            type = "shadowsocks"
            url = "{url}"
            "#,
            url = TEST_SHADOWSOCKS_URL,
        );
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_shadowsocks_me_reject_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();

        assert!(err.contains("shadowsocks upstreams require general.use_middle_proxy = false"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn invalid_shadowsocks_url_is_rejected() {
        let toml = r#"
            [general]
            use_middle_proxy = false

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"

            [[upstreams]]
            type = "shadowsocks"
            url = "not-a-valid-ss-url"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_shadowsocks_invalid_url_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();

        assert!(err.contains("invalid shadowsocks url"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn shadowsocks_plugins_are_rejected() {
        let toml = format!(
            r#"
            [general]
            use_middle_proxy = false

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"

            [[upstreams]]
            type = "shadowsocks"
            url = "{url}?plugin=obfs-local%3Bobfs%3Dhttp"
            "#,
            url = TEST_SHADOWSOCKS_URL,
        );
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_shadowsocks_plugin_reject_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();

        assert!(err.contains("shadowsocks plugins are not supported"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn invalid_user_ad_tag_reports_access_user_ad_tags_key() {
        let toml = r#"
            [censorship]
            tls_domain = "example.com"

            [access.users]
            alice = "00000000000000000000000000000000"

            [access.user_ad_tags]
            alice = "not_hex"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_invalid_user_ad_tag_message_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("access.user_ad_tags['alice'] must be exactly 32 hex characters"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn invalid_dns_override_is_rejected() {
        let toml = r#"
            [network]
            dns_overrides = ["example.com:443:2001:db8::10"]

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_invalid_dns_override_test.toml");
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("must be bracketed"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn valid_dns_override_is_accepted() {
        let toml = r#"
            [network]
            dns_overrides = ["example.com:443:127.0.0.1", "example.net:443:[2001:db8::10]"]

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#;
        let dir = std::env::temp_dir();
        let path = dir.join("telemt_valid_dns_override_test.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = ProxyConfig::load(&path).unwrap();
        assert_eq!(cfg.network.dns_overrides.len(), 2);
        let _ = std::fs::remove_file(path);
    }
}
