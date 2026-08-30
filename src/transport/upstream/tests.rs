use super::*;
use std::sync::Arc;

use crate::stats::Stats;

const TEST_SHADOWSOCKS_URL: &str =
    "ss://2022-blake3-aes-256-gcm:MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=@127.0.0.1:8388";

fn manager_with_dns(entries: &[String]) -> UpstreamManager {
    UpstreamManager::new(Vec::new(), 1, 1, 1, 1, 1, false, Arc::new(Stats::new()))
        .with_dns_overrides(entries)
        .unwrap()
}

#[tokio::test]
async fn generation_local_dns_overrides_are_isolated_and_case_insensitive() {
    let active = manager_with_dns(&["Front.Example:443:192.0.2.10".to_string()]);
    let candidate = manager_with_dns(&["front.example:443:[2001:db8::10]".to_string()]);

    assert_eq!(
        active.resolve_hostname("front.example", 443).await.unwrap(),
        "192.0.2.10:443".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        candidate
            .resolve_hostname("FRONT.EXAMPLE", 443)
            .await
            .unwrap(),
        "[2001:db8::10]:443".parse::<SocketAddr>().unwrap()
    );

    candidate
        .update_dns_overrides(&["front.example:443:192.0.2.20".to_string()])
        .unwrap();
    assert_eq!(
        active.resolve_hostname("FRONT.EXAMPLE", 443).await.unwrap(),
        "192.0.2.10:443".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        candidate
            .resolve_hostname("front.example", 443)
            .await
            .unwrap(),
        "192.0.2.20:443".parse::<SocketAddr>().unwrap()
    );
}

#[test]
fn required_healthy_group_count_applies_three_group_threshold() {
    assert_eq!(UpstreamManager::required_healthy_group_count(0), 0);
    assert_eq!(UpstreamManager::required_healthy_group_count(1), 1);
    assert_eq!(UpstreamManager::required_healthy_group_count(2), 2);
    assert_eq!(UpstreamManager::required_healthy_group_count(3), 3);
    assert_eq!(UpstreamManager::required_healthy_group_count(5), 3);
}

#[test]
fn build_health_check_groups_merges_family_endpoints_with_preference() {
    let mut overrides = HashMap::new();
    overrides.insert(
        "2".to_string(),
        vec![
            "203.0.113.10:443".to_string(),
            "203.0.113.11:443".to_string(),
            "[2001:db8::10]:443".to_string(),
        ],
    );

    let groups = UpstreamManager::build_health_check_groups(true, true, &overrides);
    let dc2 = groups
        .iter()
        .find(|g| g.dc_idx == 2)
        .expect("dc2 must be present");

    assert!(dc2.v6_endpoints.iter().all(|addr| addr.is_ipv6()));
    assert!(dc2.v4_endpoints.iter().all(|addr| addr.is_ipv4()));
    assert!(
        dc2.v6_endpoints
            .contains(&"[2001:db8::10]:443".parse::<SocketAddr>().unwrap())
    );
    assert!(
        dc2.v4_endpoints
            .contains(&"203.0.113.10:443".parse::<SocketAddr>().unwrap())
    );
    assert!(
        dc2.v4_endpoints
            .contains(&"203.0.113.11:443".parse::<SocketAddr>().unwrap())
    );

    let ordered = UpstreamManager::health_check_endpoint_order(dc2, true);
    assert!(ordered[0].1.iter().all(|addr| addr.is_ipv6()));
    assert!(ordered[1].1.iter().all(|addr| addr.is_ipv4()));
}

#[test]
fn build_health_check_groups_keeps_multiple_endpoints_per_group() {
    let mut overrides = HashMap::new();
    overrides.insert(
        "9".to_string(),
        vec![
            "198.51.100.1:443".to_string(),
            "198.51.100.2:443".to_string(),
            "198.51.100.1:443".to_string(),
        ],
    );

    let groups = UpstreamManager::build_health_check_groups(true, false, &overrides);
    let dc9 = groups
        .iter()
        .find(|g| g.dc_idx == 9)
        .expect("override-only dc group must be present");

    assert_eq!(dc9.v4_endpoints.len(), 2);
    assert!(
        dc9.v4_endpoints
            .contains(&"198.51.100.1:443".parse::<SocketAddr>().unwrap())
    );
    assert!(
        dc9.v4_endpoints
            .contains(&"198.51.100.2:443".parse::<SocketAddr>().unwrap())
    );
    assert!(dc9.v6_endpoints.is_empty());
}

#[test]
fn hard_connect_error_classification_detects_connection_refused() {
    let error = ProxyError::ConnectionRefused {
        addr: "127.0.0.1:443".to_string(),
    };
    assert!(UpstreamManager::is_hard_connect_error(&error));
}

#[test]
fn hard_connect_error_classification_skips_timeouts() {
    let error = ProxyError::ConnectionTimeout {
        addr: "127.0.0.1:443".to_string(),
    };
    assert!(!UpstreamManager::is_hard_connect_error(&error));
}

#[test]
fn unscoped_selection_detects_default_route_upstream() {
    let mut upstream = UpstreamConfig {
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
    };

    assert!(UpstreamManager::is_unscoped_upstream(&upstream));
    upstream.scopes = "local".to_string();
    assert!(!UpstreamManager::is_unscoped_upstream(&upstream));
    assert!(!UpstreamManager::should_check_in_default_dc_connectivity(
        true, &upstream
    ));
    assert!(UpstreamManager::should_check_in_default_dc_connectivity(
        false, &upstream
    ));
}

#[test]
fn resolve_bind_address_prefers_explicit_bind_ip() {
    let target = "203.0.113.10:443".parse::<SocketAddr>().unwrap();
    let bind = UpstreamManager::resolve_bind_address(
        &Some("198.51.100.20".to_string()),
        &Some(vec!["198.51.100.10".to_string()]),
        target,
        None,
        true,
    );

    assert_eq!(bind, Some("198.51.100.10".parse::<IpAddr>().unwrap()));
}

#[test]
fn resolve_bind_address_does_not_fallback_to_interface_when_bind_addresses_present() {
    let target = "203.0.113.10:443".parse::<SocketAddr>().unwrap();
    let bind = UpstreamManager::resolve_bind_address(
        &Some("198.51.100.20".to_string()),
        &Some(vec!["2001:db8::10".to_string()]),
        target,
        None,
        true,
    );

    assert_eq!(bind, None);
}

#[test]
fn api_snapshot_reports_shadowsocks_as_sanitized_route() {
    let manager = UpstreamManager::new(
        vec![UpstreamConfig {
            upstream_type: UpstreamType::Shadowsocks {
                url: TEST_SHADOWSOCKS_URL.to_string(),
                interface: None,
            },
            weight: 2,
            enabled: true,
            scopes: String::new(),
            selected_scope: String::new(),
            ipv4: None,
            ipv6: None,
            prefer: None,
        }],
        1,
        100,
        1000,
        10,
        1,
        false,
        Arc::new(Stats::new()),
    );

    let snapshot = manager.try_api_snapshot().expect("snapshot");
    assert_eq!(snapshot.summary.configured_total, 1);
    assert_eq!(snapshot.summary.shadowsocks_total, 1);
    assert_eq!(snapshot.upstreams.len(), 1);
    assert_eq!(
        snapshot.upstreams[0].route_kind,
        UpstreamRouteKind::Shadowsocks
    );
    assert_eq!(snapshot.upstreams[0].address, "127.0.0.1:8388");
}
