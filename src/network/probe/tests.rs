use super::*;
use crate::config::NetworkConfig;

#[test]
fn manual_nat_ip_enables_ipv4_me_without_reflection() {
    let config = NetworkConfig {
        ipv4: true,
        ..Default::default()
    };
    let probe = NetworkProbe {
        detected_ipv4: Some(Ipv4Addr::new(10, 0, 0, 10)),
        ipv4_is_bogon: true,
        ..Default::default()
    };

    let decision =
        decide_network_capabilities(&config, &probe, Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));

    assert!(decision.ipv4_me);
}

#[test]
fn manual_nat_ip_does_not_enable_other_family() {
    let config = NetworkConfig {
        ipv4: true,
        ipv6: Some(true),
        ..Default::default()
    };
    let probe = NetworkProbe {
        detected_ipv4: Some(Ipv4Addr::new(10, 0, 0, 10)),
        detected_ipv6: Some(Ipv6Addr::LOCALHOST),
        ipv4_is_bogon: true,
        ipv6_is_bogon: true,
        ..Default::default()
    };

    let decision =
        decide_network_capabilities(&config, &probe, Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));

    assert!(decision.ipv4_me);
    assert!(!decision.ipv6_me);
}
