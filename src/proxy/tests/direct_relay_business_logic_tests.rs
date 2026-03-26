use super::*;
use crate::protocol::constants::{TG_DATACENTER_PORT, TG_DATACENTERS_V4, TG_DATACENTERS_V6};
use std::net::SocketAddr;

#[test]
fn business_scope_hint_accepts_exact_boundary_length() {
    let value = format!("scope_{}", "a".repeat(MAX_SCOPE_HINT_LEN));
    assert_eq!(
        validated_scope_hint(&value),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
}

#[test]
fn business_scope_hint_rejects_missing_prefix_even_when_charset_is_valid() {
    assert_eq!(validated_scope_hint("alpha-01"), None);
}

#[test]
fn business_known_dc_uses_ipv4_table_by_default() {
    let cfg = ProxyConfig::default();
    let resolved = get_dc_addr_static(2, &cfg).expect("known dc must resolve");
    let expected = SocketAddr::new(TG_DATACENTERS_V4[1], TG_DATACENTER_PORT);
    assert_eq!(resolved, expected);
}

#[test]
fn business_negative_dc_maps_by_absolute_value() {
    let cfg = ProxyConfig::default();
    let resolved =
        get_dc_addr_static(-3, &cfg).expect("negative dc index must map by absolute value");
    let expected = SocketAddr::new(TG_DATACENTERS_V4[2], TG_DATACENTER_PORT);
    assert_eq!(resolved, expected);
}

#[test]
fn business_known_dc_uses_ipv6_table_when_preferred_and_enabled() {
    let mut cfg = ProxyConfig::default();
    cfg.network.prefer = 6;
    cfg.network.ipv6 = Some(true);

    let resolved = get_dc_addr_static(1, &cfg).expect("known dc must resolve on ipv6 path");
    let expected = SocketAddr::new(TG_DATACENTERS_V6[0], TG_DATACENTER_PORT);
    assert_eq!(resolved, expected);
}

#[test]
fn business_unknown_dc_uses_configured_default_dc_when_in_range() {
    let mut cfg = ProxyConfig::default();
    cfg.default_dc = Some(4);

    let resolved =
        get_dc_addr_static(29_999, &cfg).expect("unknown dc must resolve to configured default");
    let expected = SocketAddr::new(TG_DATACENTERS_V4[3], TG_DATACENTER_PORT);
    assert_eq!(resolved, expected);
}
