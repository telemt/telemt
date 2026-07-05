use super::*;
use crate::config::CidrRateLimitKey;

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
fn synlimit_synfix_defaults_are_loaded_for_listener() {
    let cfg = load_config_from_temp_toml(
        r#"
            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"

            [[server.listeners]]
            ip = "0.0.0.0"
            port = 443
            synlimit = "iptables"
        "#,
    );

    let listener = &cfg.server.listeners[0];
    assert_eq!(listener.synlimit_seconds, 60);
    assert_eq!(listener.synlimit_hitcount, 48);
    assert_eq!(listener.synlimit_burst, 1);
    assert_eq!(listener.synlimit_ios_seconds, 1);
    assert_eq!(listener.synlimit_ios_hitcount, 12);
    assert_eq!(listener.synlimit_ios_burst, 24);
    assert_eq!(listener.synlimit_hashlimit_expire_ms, 60_000);
    assert_eq!(listener.synlimit_hashlimit_size, 32_768);
}

#[test]
fn synlimit_synfix_zero_values_are_rejected() {
    for (field, expected) in [
        (
            "synlimit_ios_seconds",
            "server.listeners[0].synlimit_ios_seconds must be > 0",
        ),
        (
            "synlimit_ios_hitcount",
            "server.listeners[0].synlimit_ios_hitcount must be > 0",
        ),
        (
            "synlimit_ios_burst",
            "server.listeners[0].synlimit_ios_burst must be > 0",
        ),
        (
            "synlimit_hashlimit_expire_ms",
            "server.listeners[0].synlimit_hashlimit_expire_ms must be > 0",
        ),
        (
            "synlimit_hashlimit_size",
            "server.listeners[0].synlimit_hashlimit_size must be > 0",
        ),
    ] {
        let toml = format!(
            r#"
                [censorship]
                tls_domain = "example.com"

                [access.users]
                user = "00000000000000000000000000000000"

                [[server.listeners]]
                ip = "0.0.0.0"
                port = 443
                synlimit = "iptables"
                {field} = 0
            "#
        );
        let error = load_config_error_from_temp_toml(&toml);
        assert!(error.contains(expected), "{field}: {error}");
    }
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
fn cidr_rate_limits_accept_auto_templates_in_strict_config() {
    let cfg = load_config_from_temp_toml(
        r#"
            [general]
            config_strict = true

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"

            [access.cidr_rate_limits]
            "*/24" = { up_bps = 1024, down_bps = 0 }
            "*4/30" = { up_bps = 0, down_bps = 2048 }
            "*6/64" = { up_bps = 4096, down_bps = 0 }
        "#,
    );

    assert!(cfg.access.cidr_rate_limits.contains_key(&CidrRateLimitKey::AutoDual(24)));
    assert!(cfg.access.cidr_rate_limits.contains_key(&CidrRateLimitKey::AutoV4(30)));
    assert!(cfg.access.cidr_rate_limits.contains_key(&CidrRateLimitKey::AutoV6(64)));
}

#[test]
fn cidr_rate_limits_reject_invalid_auto_template_prefix() {
    let error = load_config_error_from_temp_toml(
        r#"
            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"

            [access.cidr_rate_limits]
            "*4/33" = { up_bps = 1024, down_bps = 0 }
        "#,
    );

    assert!(error.contains("prefix must be within 0..=32"));
}

#[test]
fn cidr_rate_limits_reject_duplicate_normalized_auto_templates() {
    let error = load_config_error_from_temp_toml(
        r#"
            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"

            [access.cidr_rate_limits]
            "*/32" = { up_bps = 1024, down_bps = 0 }
            "*6/128" = { up_bps = 2048, down_bps = 0 }
        "#,
    );

    assert!(error.contains("duplicates normalized auto-template *6/128"));
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
    assert!(
        err.contains(
            "general.me_adaptive_floor_min_writers_single_endpoint must be within [1, 32]"
        )
    );
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
    assert!(err.contains("general.me_route_backpressure_base_timeout_ms must be within [1, 5000]"));
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
    assert!(err.contains("general.me_route_backpressure_high_timeout_ms must be within [1, 5000]"));
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
        client_mss_bulk = "1400"

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
    assert_eq!(cfg.server.client_mss_bulk_value(), Ok(Some(1400)));
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
fn client_mss_bulk_out_of_range_is_rejected() {
    for value in ["87", "4097"] {
        let toml = format!(
            r#"
            [server]
            client_mss_bulk = "{value}"

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#
        );
        let dir = std::env::temp_dir();
        let path = dir.join(format!("telemt_client_mss_bulk_out_of_range_{value}_test.toml"));
        std::fs::write(&path, toml).unwrap();
        let err = ProxyConfig::load(&path).unwrap_err().to_string();

        assert!(err.contains("server.client_mss_bulk custom value must be within [88, 4096]"));
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
    assert!(
        err.contains(
            "server.conntrack_control.pressure_high_watermark_pct must be within [1, 100]"
        )
    );
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
    assert!(err.contains(
        "server.conntrack_control.pressure_low_watermark_pct must be < pressure_high_watermark_pct"
    ));
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
    assert!(
        err.contains(
            "server.conntrack_control.hybrid_listener_ips must be non-empty in mode=hybrid"
        )
    );
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
