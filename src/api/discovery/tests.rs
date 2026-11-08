use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::*;
use crate::api::allowed_methods_for_path;

fn unavailable() -> Availability {
    Availability {
        me_pool: Some(false),
        web_read: false,
        web_control: false,
    }
}

fn operation<'a>(data: &'a Value, id: &str) -> &'a Value {
    data["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == id)
        .unwrap()
}

#[test]
fn discovery_distinguishes_disabled_unavailable_and_read_only() {
    let mut config = ProxyConfig::default();
    config.server.api.read_only = true;
    config.server.api.minimal_runtime_enabled = false;
    config.server.api.runtime_edge_enabled = false;
    let data = serde_json::to_value(build_capabilities(&config, unavailable()).unwrap()).unwrap();
    let disabled = operation(&data, "stats_me_writers");
    assert_eq!(disabled["supported"], true);
    assert_eq!(disabled["enabled"], false);
    assert_eq!(disabled["disabled_reason"], "feature_disabled");
    assert_eq!(
        operation(&data, "runtime_upstream_quality")["enabled"],
        true
    );
    assert_eq!(operation(&data, "web_sessions")["enabled"], true);
    assert_eq!(operation(&data, "web_sessions")["available"], false);
    assert_eq!(operation(&data, "web_status")["available"], true);
    assert_eq!(operation(&data, "users_patch")["mutable"], false);
    assert_eq!(
        operation(&data, "users_patch")["mutation_blocked_reason"],
        "read_only"
    );
    assert_eq!(operation(&data, "config_schema")["available"], true);

    config.server.api.read_only = false;
    config.server.api.minimal_runtime_enabled = true;
    config.server.api.runtime_edge_enabled = true;
    let available = Availability {
        me_pool: Some(true),
        web_read: true,
        web_control: false,
    };
    let data = serde_json::to_value(build_capabilities(&config, available).unwrap()).unwrap();
    assert_eq!(operation(&data, "stats_me_writers")["available"], true);
    assert_eq!(operation(&data, "web_sessions")["available"], true);
    assert_eq!(operation(&data, "web_drain")["available"], false);
    assert_eq!(operation(&data, "web_drain")["mutable"], true);
    assert_eq!(operation(&data, "users_patch")["mutable"], true);
    assert_eq!(operation(&data, "users_get")["mutable"], false);
}

#[test]
fn busy_or_unsampled_sources_are_not_reported_as_healthy() {
    let config = ProxyConfig::default();
    let data = serde_json::to_value(
        build_capabilities(
            &config,
            Availability {
                me_pool: None,
                ..unavailable()
            },
        )
        .unwrap(),
    )
    .unwrap();
    assert!(operation(&data, "runtime_me_quality")["available"].is_null());
    assert_eq!(
        operation(&data, "runtime_me_quality")["unavailable_reason"],
        "snapshot_busy"
    );
    assert!(operation(&data, "stats_upstreams")["available"].is_null());
    assert_eq!(
        operation(&data, "stats_upstreams")["unavailable_reason"],
        "availability_not_sampled"
    );
}

#[test]
fn discovery_does_not_serialize_configured_credentials_or_addresses() {
    let mut config = ProxyConfig::default();
    config.server.api.auth_header = "private-auth-sentinel".into();
    config.general.proxy_secret_url = Some("https://private-url-sentinel/secret".into());
    config.access.users.insert(
        "private-user-sentinel".into(),
        "private-secret-sentinel".into(),
    );
    config.upstreams = serde_json::from_value(json!([
        {"type":"socks5", "address":"private-address-sentinel:1080", "password":"private-password-sentinel"}
    ])).unwrap();
    let caps = serde_json::to_string(&build_capabilities(&config, unavailable()).unwrap()).unwrap();
    let schema = serde_json::to_string(config_schema().unwrap()).unwrap();
    assert!(!caps.contains("sentinel"));
    assert!(!schema.contains("sentinel"));
    for secret in ProxyConfig::default().access.users.values() {
        assert!(!schema.contains(secret));
    }
    assert!(schema.len() < 1024 * 1024);
    assert!(caps.len() < 128 * 1024);
}

fn example_path(path: &str) -> String {
    path.replace("{username}", "alice")
        .replace("{id}", "42")
        .replace(
            "{session_ref}",
            "ws1.00000000000000000000000000000000.0000000000000001",
        )
        .replace(
            "{operation_id}",
            "wo1.00000000000000000000000000000000.0000000000000001",
        )
}

#[test]
fn operation_catalog_matches_routing_methods() {
    let mut paths = BTreeMap::<String, BTreeSet<String>>::new();
    let mut ids = BTreeSet::new();
    for operation in operations().unwrap() {
        assert!(
            ids.insert(&operation.id),
            "duplicate operation: {}",
            operation.id
        );
        for path in std::iter::once(&operation.path).chain(&operation.aliases) {
            assert!(
                paths
                    .entry(path.clone())
                    .or_default()
                    .insert(operation.method.clone())
            );
            let allowed = allowed_methods_for_path(&example_path(path))
                .unwrap_or_else(|| panic!("missing route: {path}"));
            assert!(
                allowed.split(", ").any(|method| method == operation.method),
                "{path}: {allowed}"
            );
        }
    }
    for (path, methods) in &paths {
        let allowed = allowed_methods_for_path(&example_path(path)).unwrap();
        assert_eq!(
            methods,
            &allowed.split(", ").map(str::to_owned).collect(),
            "{path}"
        );
    }
    // Both tables are independent: a newly dispatched fixed route cannot silently
    // disappear from discovery because a maintainer omitted its catalog entry.
    for source in [
        include_str!("../mod.rs"),
        include_str!("../handler.rs"),
        include_str!("../handler/read_routes.rs"),
        include_str!("../handler/fixed_routes.rs"),
        include_str!("../web_runtime.rs"),
    ] {
        let pattern = regex::Regex::new(r#""(/v1/[^"{}]*|/web-status)""#).unwrap();
        for matched in pattern.captures_iter(source) {
            let path = &matched[1];
            if path.ends_with('/') || path.contains('*') {
                continue;
            }
            assert!(paths.contains_key(path), "unclassified route: {path}");
        }
    }
    assert_eq!(allowed_methods_for_path("/v1/config/schema"), Some("GET"));
    assert_eq!(allowed_methods_for_path("/v1/capabilities"), Some("GET"));
    assert!(reject_query(None).is_ok());
    assert!(reject_query(Some("include_secrets=true")).is_err());
}
