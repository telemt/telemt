use super::*;

fn test_listener(port: u16) -> crate::config::ListenerConfig {
    crate::config::ListenerConfig {
        ip: "127.0.0.1".parse().unwrap(),
        transport: crate::config::ListenerTransport::Mtproxy,
        port: Some(port),
        client_mss: None,
        synlimit: crate::config::SynLimitMode::Off,
        synlimit_seconds: 60,
        synlimit_hitcount: 48,
        synlimit_burst: 24,
        synlimit_ios_seconds: 1,
        synlimit_ios_hitcount: 12,
        synlimit_ios_burst: 24,
        synlimit_hashlimit_expire_ms: 60_000,
        synlimit_hashlimit_size: 32_768,
        announce: None,
        announce_ip: None,
        proxy_protocol: None,
        reuse_allow: false,
        web_client_ip_source: crate::config::WebClientIpSource::XForwardedFor,
        web_trusted_proxy_cidrs: Vec::new(),
    }
}

#[test]
fn process_socket_and_logging_changes_are_deferred() {
    let old = ProxyConfig::default();
    let mut new = old.clone();
    new.server.listen_backlog = new.server.listen_backlog.saturating_add(1);
    new.general.disable_colors = !new.general.disable_colors;

    let fields = deferred_process_fields(&old, &new);
    assert!(fields.contains(&"server.listeners".to_string()));
    assert!(fields.contains(&"general.disable_colors".to_string()));
}

#[test]
fn global_mss_profiles_are_deferred_with_the_listener_socket_group() {
    let old = ProxyConfig::default();
    let mut desired = old.clone();
    desired.server.client_mss = Some("92".to_string());
    desired.server.client_mss_bulk = Some("1400".to_string());

    let resolved = resolve_reload_config(&old, &desired);

    assert_eq!(
        resolved.deferred_process_fields,
        vec!["server.listeners".to_string()]
    );
    assert_eq!(resolved.effective.server.client_mss, old.server.client_mss);
    assert_eq!(
        resolved.effective.server.client_mss_bulk,
        old.server.client_mss_bulk
    );
    assert!(!resolved.runtime_changed);
}

#[test]
fn mixed_reload_retains_process_state_and_applies_runtime_state() {
    let old = ProxyConfig::default();
    let mut desired = old.clone();
    desired.server.client_mss = Some("92".to_string());
    desired.censorship.tls_domain = "reload.example".to_string();

    let resolved = resolve_reload_config(&old, &desired);

    assert_eq!(resolved.effective.server.client_mss, old.server.client_mss);
    assert_eq!(
        resolved.effective.censorship.tls_domain,
        desired.censorship.tls_domain
    );
    assert!(resolved.runtime_changed);
    assert_eq!(
        resolved.deferred_process_fields,
        vec!["server.listeners".to_string()]
    );
}

#[test]
fn listener_announcement_is_runtime_owned_when_bind_identity_is_stable() {
    let mut old = ProxyConfig::default();
    old.server.listeners.push(crate::config::ListenerConfig {
        ip: "0.0.0.0".parse().unwrap(),
        transport: crate::config::ListenerTransport::Mtproxy,
        port: Some(443),
        client_mss: None,
        synlimit: crate::config::SynLimitMode::Off,
        synlimit_seconds: 60,
        synlimit_hitcount: 48,
        synlimit_burst: 24,
        synlimit_ios_seconds: 1,
        synlimit_ios_hitcount: 12,
        synlimit_ios_burst: 24,
        synlimit_hashlimit_expire_ms: 60_000,
        synlimit_hashlimit_size: 32_768,
        announce: None,
        announce_ip: None,
        proxy_protocol: None,
        reuse_allow: false,
        web_client_ip_source: crate::config::WebClientIpSource::XForwardedFor,
        web_trusted_proxy_cidrs: Vec::new(),
    });
    let mut desired = old.clone();
    desired.server.listeners[0].announce = Some("proxy.example".to_string());

    let resolved = resolve_reload_config(&old, &desired);

    assert!(resolved.deferred_process_fields.is_empty());
    assert_eq!(
        resolved.effective.server.listeners[0].announce.as_deref(),
        Some("proxy.example")
    );
    assert!(resolved.runtime_changed);
}

#[test]
fn process_field_labels_are_stable_ordered_and_unique() {
    let old = ProxyConfig::default();
    let mut desired = old.clone();
    desired.server.listen_backlog = desired.server.listen_backlog.saturating_add(1);
    desired.server.api.enabled = !desired.server.api.enabled;
    desired.server.api.runtime_edge_events_capacity = desired
        .server
        .api
        .runtime_edge_events_capacity
        .saturating_add(1);
    desired.general.disable_colors = !desired.general.disable_colors;

    let resolved = resolve_reload_config(&old, &desired);

    assert_eq!(
        resolved.deferred_process_fields,
        vec![
            "server.listeners".to_string(),
            "server.api.listen".to_string(),
            "server.api.runtime_edge_events_capacity".to_string(),
            "general.disable_colors".to_string(),
        ]
    );
}

#[test]
fn runtime_only_change_does_not_require_process_rebind() {
    let old = ProxyConfig::default();
    let mut new = old.clone();
    new.censorship.tls_domain = "reload.example".to_string();
    assert!(deferred_process_fields(&old, &new).is_empty());
}

#[test]
fn web_allocation_limits_are_deferred_until_restart() {
    let mut old = ProxyConfig::default();
    old.rebuild_runtime_user_auth().unwrap();
    old.rebuild_runtime_web().unwrap();
    let mut desired = old.clone();
    desired.web.limits.max_sessions_global += 1;

    let resolved = resolve_reload_config(&old, &desired);

    assert_eq!(
        resolved.deferred_process_fields,
        vec!["web.limits".to_string()]
    );
    assert_eq!(
        resolved.effective.web.limits.max_sessions_global,
        old.web.limits.max_sessions_global
    );
    assert!(!resolved.runtime_changed);
}

#[test]
fn web_debug_prefix_dependent_on_new_capacity_is_deferred_with_limits() {
    let mut old = ProxyConfig::default();
    old.rebuild_runtime_user_auth().unwrap();
    old.rebuild_runtime_web().unwrap();
    let mut desired = old.clone();
    desired.web.limits.max_body_bytes = 4 * 1024 * 1024;
    desired.web.debug.body_prefix_bytes = 3 * 1024 * 1024;

    let resolved = resolve_reload_config(&old, &desired);

    assert_eq!(
        resolved.deferred_process_fields,
        vec!["web.limits".to_string(), "web.debug".to_string()]
    );
    assert_eq!(
        resolved.effective.web.debug.body_prefix_bytes,
        old.web.debug.body_prefix_bytes
    );
}

#[test]
fn strict_middle_proxy_requires_a_prepared_pool() {
    assert!(strict_middle_proxy_unavailable(true, false, false));
    assert!(!strict_middle_proxy_unavailable(true, false, true));
    assert!(!strict_middle_proxy_unavailable(true, true, false));
    assert!(!strict_middle_proxy_unavailable(false, false, false));
}

#[test]
fn endpoint_only_listener_move_is_runtime_rebindable() {
    let mut old = ProxyConfig::default();
    old.server.listeners = vec![test_listener(443)];
    let mut desired = old.clone();
    desired.server.listeners[0].port = Some(8443);

    let resolved = resolve_reload_config(&old, &desired);

    assert!(resolved.deferred_process_fields.is_empty());
    assert_eq!(resolved.effective.server.listeners[0].port, Some(8443));
    assert!(resolved.runtime_changed);
}

#[test]
fn synlimited_endpoint_move_remains_restart_only() {
    let mut old = ProxyConfig::default();
    old.server.listeners = vec![test_listener(443)];
    old.server.listeners[0].synlimit = crate::config::SynLimitMode::Nftables;
    let mut desired = old.clone();
    desired.server.listeners[0].port = Some(8443);

    let resolved = resolve_reload_config(&old, &desired);

    assert_eq!(
        resolved.deferred_process_fields,
        vec!["server.listeners".to_string()]
    );
    assert_eq!(resolved.effective.server.listeners[0].port, Some(443));
    assert!(!resolved.runtime_changed);
}

#[test]
fn deferred_listener_identity_cannot_create_an_effective_decoy_loop() {
    let mut old = ProxyConfig::default();
    old.server.listeners = vec![test_listener(18080)];
    old.server.listeners[0].transport = crate::config::ListenerTransport::Web;
    let mut desired = old.clone();
    desired.server.listeners[0].port = Some(18081);
    desired.server.listen_backlog = desired.server.listen_backlog.saturating_add(1);
    desired.web.vhosts = vec![
        serde_json::from_value(serde_json::json!({
            "host": "proxy.example",
            "public_addr": "203.0.113.10:443",
            "decoy": {
                "mode": "http_upstream",
                "upstream": "http://127.0.0.1:18080"
            },
            "profiles": []
        }))
        .unwrap(),
    ];

    assert!(desired.validate_web_decoy_listener_separation().is_ok());
    let resolved = resolve_reload_config(&old, &desired);
    assert!(
        resolved
            .effective
            .validate_web_decoy_listener_separation()
            .is_err()
    );
}
