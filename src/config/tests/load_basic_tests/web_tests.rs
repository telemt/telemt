use super::*;

const WEB_CONFIG: &str = r#"
[access.users]
alice = "000102030405060708090a0b0c0d0e0f"

[[server.listeners]]
ip = "127.0.0.1"
port = 18080
transport = "web"
proxy_protocol = false
web_client_ip_source = "x_forwarded_for"
web_trusted_proxy_cidrs = ["127.0.0.1/32"]

[web]
enabled = true
carrier = "https-lanes"

[[web.vhosts]]
host = "Proxy.Example.COM"
public_addr = "203.0.113.10:443"

[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://127.0.0.1:18081"

[[web.vhosts.profiles]]
user = "alice"
secret_mode = "dd"
max_sessions = 4
max_streams = 64
max_streams_per_session = 16
"#;

#[test]
fn web_config_builds_canonical_runtime_snapshot() {
    let config = load_config_from_temp_toml(WEB_CONFIG);
    let runtime = config.web.runtime.expect("WEB runtime snapshot");
    let vhost = runtime
        .vhosts
        .get("proxy.example.com")
        .expect("canonical WEB vhost");
    assert_eq!(vhost.profiles.len(), 1);
    assert_eq!(vhost.profiles[0].user, "alice");
    assert_eq!(vhost.profiles[0].secret_mode, WebSecretMode::Dd);
    assert_eq!(vhost.profiles[0].carrier, WebCarrier::HttpsLanes);
    assert_eq!(vhost.profiles[0].max_sessions, 4);
    assert_eq!(vhost.profiles[0].max_streams, 64);
    assert_eq!(vhost.profiles[0].max_streams_per_session, 16);
    assert_eq!(vhost.profiles[0].key_fingerprint.len(), 16);
    assert_ne!(vhost.profiles[0].key_fingerprint, "0001020304050607");
    assert!(!vhost.profiles[0].carrier_negotiation_enabled);
    assert_eq!(
        vhost.profiles[0].carriers.as_ref(),
        [WebCarrier::HttpsLanes]
    );
}

#[test]
fn web_http_connection_capacity_policy_is_bounded_and_configurable() {
    let configured = WEB_CONFIG
        .replace(
            "carrier = \"https-lanes\"",
            "carrier = \"https-lanes\"\nhttp_connection_capacity_action = \"wait\"",
        )
        .replace(
            "[[web.vhosts]]",
            "[web.limits]\nmax_http_overload_connections = 23\n\n[web.timeouts]\nhttp_overload_timeout_ms = 731\n\n[[web.vhosts]]",
        );
    let config = load_config_from_temp_toml(&configured);

    assert_eq!(
        config.web.http_connection_capacity_action,
        WebHttpConnectionCapacityAction::Wait
    );
    assert_eq!(config.web.limits.max_http_overload_connections, 23);
    assert_eq!(config.web.timeouts.http_overload_timeout_ms, 731);

    let defaults = ProxyConfig::default();
    assert_eq!(
        defaults.web.http_connection_capacity_action,
        WebHttpConnectionCapacityAction::Drop
    );
    assert_eq!(defaults.web.limits.max_http_overload_connections, 64);
    assert_eq!(defaults.web.timeouts.http_overload_timeout_ms, 250);
}

#[test]
fn web_http_connection_capacity_policy_rejects_unknown_or_unbounded_values() {
    let unknown = WEB_CONFIG.replace(
        "carrier = \"https-lanes\"",
        "carrier = \"https-lanes\"\nhttp_connection_capacity_action = \"queue\"",
    );
    assert!(load_config_error_from_temp_toml(&unknown).contains("http_connection_capacity_action"));

    for timeout in [0, 60_001] {
        let invalid = WEB_CONFIG.replace(
            "[[web.vhosts]]",
            &format!("[web.timeouts]\nhttp_overload_timeout_ms = {timeout}\n\n[[web.vhosts]]"),
        );
        assert!(
            load_config_error_from_temp_toml(&invalid)
                .contains("web.timeouts.http_overload_timeout_ms")
        );
    }

    let no_overload_slots = WEB_CONFIG.replace(
        "[[web.vhosts]]",
        "[web.limits]\nmax_http_overload_connections = 0\n\n[[web.vhosts]]",
    );
    assert!(
        load_config_error_from_temp_toml(&no_overload_slots)
            .contains("web.limits.max_http_overload_connections")
    );
}

#[test]
fn web_decoy_rejects_direct_and_wildcard_listener_loops() {
    let direct = WEB_CONFIG.replace("http://127.0.0.1:18081", "http://127.0.0.1:18080");
    assert!(
        load_config_error_from_temp_toml(&direct).contains("decoy upstream overlaps WEB listener")
    );

    let wildcard = direct.replace("ip = \"127.0.0.1\"", "ip = \"0.0.0.0\"");
    assert!(
        load_config_error_from_temp_toml(&wildcard)
            .contains("decoy upstream overlaps WEB listener")
    );
}

#[test]
fn web_profile_user_labels_are_bounded_for_runtime_status() {
    let user = "a".repeat(65);
    let invalid = WEB_CONFIG.replace("alice", &user);

    assert!(
        load_config_error_from_temp_toml(&invalid)
            .contains("web.vhosts[0].profiles[0].user must contain 1..64 bytes")
    );
}

#[test]
fn web_carriers_missing_or_false_disable_negotiation() {
    let missing = load_config_from_temp_toml(WEB_CONFIG);
    assert!(!missing.web.carrier_negotiation_enabled());
    assert!(!missing.web.runtime.unwrap().profiles[0].carrier_learning);

    let disabled = WEB_CONFIG.replace(
        "carrier = \"https-lanes\"",
        "carrier = \"https-lanes\"\ncarriers = false",
    );
    let disabled = load_config_from_temp_toml(&disabled);
    assert!(!disabled.web.carrier_negotiation_enabled());
    assert!(!disabled.web.runtime.as_ref().unwrap().profiles[0].carrier_learning);
    assert_eq!(
        disabled.web.runtime.unwrap().profiles[0].carriers.as_ref(),
        [WebCarrier::HttpsLanes]
    );
}

#[test]
fn web_carrier_array_enables_ordered_negotiation_and_appends_fallback() {
    let configured = WEB_CONFIG.replace(
        "carrier = \"https-lanes\"",
        "carrier = \"https-lanes\"\ncarriers = [\"websocket\", \"https\"]\ncarrier_learning = false",
    );
    let config = load_config_from_temp_toml(&configured);
    assert!(config.web.carrier_negotiation_enabled());
    assert!(!config.web.carrier_learning);
    let profile = &config.web.runtime.unwrap().profiles[0];
    assert_eq!(
        profile.carriers.as_ref(),
        [
            WebCarrier::Websocket,
            WebCarrier::Https,
            WebCarrier::HttpsLanes
        ]
    );
    assert!(!profile.carrier_learning);
}

#[test]
fn web_carriers_reject_true_empty_and_duplicates() {
    for value in ["true", "[]", "[\"https\", \"https\"]"] {
        let invalid = WEB_CONFIG.replace(
            "carrier = \"https-lanes\"",
            &format!("carrier = \"https-lanes\"\ncarriers = {value}"),
        );
        assert!(load_config_error_from_temp_toml(&invalid).contains("web.carriers"));
    }
}

#[test]
fn web_carrier_and_bridge_deadlines_are_configurable() {
    let configured = WEB_CONFIG.replace(
        "[[web.vhosts]]",
        "[web.timeouts]\ncarrier_negotiation_deadlines_secs = [1, 2, 4, 9]\ncarrier_learning_secs = 30\nbridge_request_secs = 7\nbridge_retry_secs = 41\ncarrier_probe_coalesce_ms = 4\n\n[[web.vhosts]]",
    );
    let config = load_config_from_temp_toml(&configured);
    assert_eq!(
        config.web.timeouts.carrier_negotiation_deadlines_secs,
        [1, 2, 4, 9]
    );
    assert_eq!(config.web.timeouts.carrier_learning_secs, 30);
    assert_eq!(config.web.timeouts.bridge_request_secs, 7);
    assert_eq!(config.web.timeouts.bridge_retry_secs, 41);
    assert_eq!(config.web.timeouts.carrier_probe_coalesce_ms, 4);
}

#[test]
fn web_bridge_deadlines_are_known_in_strict_mode() {
    let configured = WEB_CONFIG.replace(
        "[[web.vhosts]]",
        "[web.timeouts]\nbridge_request_secs = 7\nbridge_retry_secs = 41\ncarrier_probe_coalesce_ms = 4\n\n[[web.vhosts]]",
    );
    let configured = format!("[general]\nconfig_strict = true\n{configured}");
    let config = load_config_from_temp_toml(&configured);

    assert_eq!(config.web.timeouts.bridge_request_secs, 7);
    assert_eq!(config.web.timeouts.bridge_retry_secs, 41);
    assert_eq!(config.web.timeouts.carrier_probe_coalesce_ms, 4);
}

#[test]
fn web_bridge_deadlines_are_bounded_and_ordered() {
    for (field, value) in [
        ("bridge_request_secs", "0"),
        ("bridge_request_secs", "61"),
        ("bridge_retry_secs", "0"),
        ("bridge_retry_secs", "301"),
        ("carrier_probe_coalesce_ms", "11"),
    ] {
        let invalid = WEB_CONFIG.replace(
            "[[web.vhosts]]",
            &format!("[web.timeouts]\n{field} = {value}\n\n[[web.vhosts]]"),
        );
        assert!(
            load_config_error_from_temp_toml(&invalid).contains(&format!("web.timeouts.{field}"))
        );
    }

    let reversed = WEB_CONFIG.replace(
        "[[web.vhosts]]",
        "[web.timeouts]\nbridge_request_secs = 20\nbridge_retry_secs = 10\n\n[[web.vhosts]]",
    );
    assert!(
        load_config_error_from_temp_toml(&reversed)
            .contains("bridge_request_secs must not exceed bridge_retry_secs")
    );
}

#[test]
fn web_carrier_learning_capacity_must_remain_nonzero() {
    let invalid = WEB_CONFIG.replace(
        "[[web.vhosts]]",
        "[web.limits]\nmax_carrier_learning_entries = 0\n\n[[web.vhosts]]",
    );
    assert!(
        load_config_error_from_temp_toml(&invalid)
            .contains("web.limits.max_carrier_learning_entries")
    );
}

#[test]
fn web_debug_table_uses_debug_name_and_bounded_defaults() {
    let configured = WEB_CONFIG.replace(
        "[[web.vhosts]]",
        "[web.debug]\nenabled = true\nbody_capture = \"prefix\"\nbody_prefix_bytes = 2048\ndefault_window_secs = 180\nmax_window_secs = 900\n\n[[web.vhosts]]",
    );
    let config = load_config_from_temp_toml(&configured);
    assert!(config.web.debug.enabled);
    assert_eq!(config.web.debug.body_capture, WebDebugBodyCapture::Prefix);
    assert_eq!(config.web.debug.body_prefix_bytes, 2048);
    assert_eq!(config.web.debug.default_window_secs, 180);
    assert_eq!(config.web.debug.max_window_secs, 900);

    let old_name = format!(
        "[general]\nconfig_strict = true\n{}",
        WEB_CONFIG.replace(
            "[[web.vhosts]]",
            "[web.trace]\nenabled = true\n\n[[web.vhosts]]",
        )
    );
    let error = load_config_error_from_temp_toml(&old_name);
    assert!(error.contains("web.trace"));
}

#[test]
fn web_debug_prefix_and_window_validation_fail_closed() {
    let oversized_prefix = WEB_CONFIG.replace(
        "[[web.vhosts]]",
        "[web.debug]\nenabled = true\nbody_prefix_bytes = 2097153\n\n[[web.vhosts]]",
    );
    let error = load_config_error_from_temp_toml(&oversized_prefix);
    assert!(error.contains("web.debug.body_prefix_bytes"));

    let reversed_window = WEB_CONFIG.replace(
        "[[web.vhosts]]",
        "[web.debug]\nenabled = true\ndefault_window_secs = 181\nmax_window_secs = 180\n\n[[web.vhosts]]",
    );
    let error = load_config_error_from_temp_toml(&reversed_window);
    assert!(error.contains("web.debug windows"));

    let undersized_store = WEB_CONFIG.replace(
        "carrier = \"https-lanes\"",
        "carrier = \"https-lanes\"\n\n[web.limits]\ndebug_bytes_global = 4095",
    );
    let error = load_config_error_from_temp_toml(&undersized_store);
    assert!(error.contains("debug_bytes_global must be at least 4096"));
}

#[test]
fn https_lanes_requires_separate_poll_and_control_handler_capacity() {
    let invalid = WEB_CONFIG.replace(
        "carrier = \"https-lanes\"",
        "carrier = \"https-lanes\"\n\n[web.limits]\nmax_http_handlers = 1\nmax_body_readers = 1",
    );
    let error = load_config_error_from_temp_toml(&invalid);
    assert!(error.contains("WEB https-lanes candidates require"));
}

#[test]
fn web_listener_requires_an_explicit_trusted_proxy() {
    let invalid = WEB_CONFIG.replace(
        "web_trusted_proxy_cidrs = [\"127.0.0.1/32\"]",
        "web_trusted_proxy_cidrs = []",
    );
    let error = load_config_error_from_temp_toml(&invalid);
    assert!(error.contains("web_trusted_proxy_cidrs must be non-empty"));
}

#[test]
fn web_queue_limits_preserve_control_and_uplink_progress() {
    let invalid = WEB_CONFIG.replace(
        "carrier = \"https-lanes\"",
        "carrier = \"https-lanes\"\n\n[web.limits]\ncontrol_bytes_per_session = 1",
    );
    let error = load_config_error_from_temp_toml(&invalid);
    assert!(error.contains("control reserves must cover bounded control frames"));
}

#[test]
fn web_semaphore_limits_are_rejected_before_runtime_construction() {
    let invalid = WEB_CONFIG.replace(
        "carrier = \"https-lanes\"",
        &format!(
            "carrier = \"https-lanes\"\n\n[web.limits]\nmax_http_connections = {}",
            tokio::sync::Semaphore::MAX_PERMITS + 1,
        ),
    );
    let error = load_config_error_from_temp_toml(&invalid);
    assert!(error.contains("exceeds Tokio semaphore capacity"));
}

#[test]
fn web_ipv6_decoy_uses_a_valid_http_authority() {
    let ipv6 = WEB_CONFIG.replace("http://127.0.0.1:18081", "http://[::1]:18081");
    let config = load_config_from_temp_toml(&ipv6);
    let runtime = config.web.runtime.expect("WEB runtime snapshot");
    let vhost = runtime.vhosts.get("proxy.example.com").unwrap();
    let WebRuntimeDecoy::HttpUpstream { authority, .. } = &vhost.decoy else {
        panic!("expected HTTP decoy");
    };
    assert_eq!(authority, "[::1]:18081");
}

#[test]
fn websocket_carriers_build_runtime_profiles_with_bounded_defaults() {
    for (name, carrier) in [
        ("websocket", WebCarrier::Websocket),
        ("websocket-lanes", WebCarrier::WebsocketLanes),
    ] {
        let configured = WEB_CONFIG.replace("https-lanes", name);
        let config = load_config_from_temp_toml(&configured);
        let profile = &config.web.runtime.unwrap().profiles[0];
        assert_eq!(profile.carrier, carrier);
        assert_eq!(config.web.limits.websocket_bytes_global, 256 * 1024 * 1024);
        assert_eq!(config.web.limits.websocket_admission_watermark_pct, 75);
        assert_eq!(config.web.limits.websocket_eviction_watermark_pct, 90);
        assert_eq!(config.web.limits.websocket_http_connection_reserve, 64);
        assert_eq!(config.web.timeouts.websocket_write_secs, 30);
        assert_eq!(config.web.timeouts.websocket_backpressure_secs, 30);
        assert_eq!(config.web.timeouts.websocket_eviction_secs, 1);
    }
}

#[test]
fn websocket_limits_reject_ambiguous_or_nonprogressing_policy() {
    let reversed_watermarks = WEB_CONFIG.replace(
        "carrier = \"https-lanes\"",
        "carrier = \"websocket\"\n\n[web.limits]\nwebsocket_admission_watermark_pct = 90\nwebsocket_eviction_watermark_pct = 75",
    );
    assert!(
        load_config_error_from_temp_toml(&reversed_watermarks).contains("WebSocket watermarks")
    );

    let no_http_reserve = WEB_CONFIG.replace(
        "carrier = \"https-lanes\"",
        "carrier = \"websocket\"\n\n[web.limits]\nwebsocket_http_connection_reserve = 0",
    );
    assert!(
        load_config_error_from_temp_toml(&no_http_reserve)
            .contains("websocket_http_connection_reserve")
    );

    let oversized_batch = WEB_CONFIG.replace(
        "carrier = \"https-lanes\"",
        "carrier = \"websocket\"\n\n[web.limits]\nmax_body_bytes = 4194304\ncarrier_batch_bytes = 4194304\nmax_body_readers = 16",
    );
    assert!(
        load_config_error_from_temp_toml(&oversized_batch)
            .contains("carrier_batch_bytes <= 2097152")
    );
}
