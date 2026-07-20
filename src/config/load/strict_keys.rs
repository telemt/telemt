use tracing::warn;

use crate::error::{ProxyError, Result};

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
    "me_writer_byte_budget_bytes",
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
    "direct_relay_buffer_budget_max_bytes",
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
    "synlimit_ios_seconds",
    "synlimit_ios_hitcount",
    "synlimit_ios_burst",
    "synlimit_hashlimit_expire_ms",
    "synlimit_hashlimit_size",
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

const TLS_FETCH_CONFIG_KEYS: &[&str] = &[
    "profiles",
    "strict_route",
    "attempt_timeout_ms",
    "total_budget_ms",
    "grease_enabled",
    "deterministic",
    "profile_cache_ttl_secs",
];

const HTTP_MASK_CONFIG_KEYS: &[&str] = &["enabled", "cert_file", "key_file", "upstream", "alpn"];

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

pub(super) fn handle_unknown_config_keys(parsed_toml: &toml::Value) -> Result<()> {
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
