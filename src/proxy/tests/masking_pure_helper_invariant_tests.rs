use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// ---------------------------------------------------------------------------
// parse_mask_host_ip_literal
// ---------------------------------------------------------------------------

#[test]
fn parse_ip_literal_plain_ipv4() {
    let ip = parse_mask_host_ip_literal("192.168.1.1").unwrap();
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
}

#[test]
fn parse_ip_literal_localhost() {
    let ip = parse_mask_host_ip_literal("127.0.0.1").unwrap();
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
}

#[test]
fn parse_ip_literal_zero_address() {
    let ip = parse_mask_host_ip_literal("0.0.0.0").unwrap();
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
}

#[test]
fn parse_ip_literal_ipv6_in_brackets() {
    let ip = parse_mask_host_ip_literal("[::1]").unwrap();
    assert_eq!(ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
}

#[test]
fn parse_ip_literal_ipv6_full_in_brackets() {
    let ip = parse_mask_host_ip_literal("[2001:db8::1]").unwrap();
    assert!(ip.is_ipv6());
}

#[test]
fn parse_ip_literal_ipv4_mapped_ipv6_in_brackets() {
    let ip = parse_mask_host_ip_literal("[::ffff:192.168.0.1]").unwrap();
    assert!(ip.is_ipv6());
}

#[test]
fn parse_ip_literal_hostname_returns_none() {
    assert!(parse_mask_host_ip_literal("example.com").is_none());
}

#[test]
fn parse_ip_literal_empty_returns_none() {
    assert!(parse_mask_host_ip_literal("").is_none());
}

#[test]
fn parse_ip_literal_bare_ipv6_is_accepted() {
    let ip = parse_mask_host_ip_literal("::1").unwrap();
    assert_eq!(ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
}

#[test]
fn parse_ip_literal_open_bracket_only_returns_none() {
    assert!(parse_mask_host_ip_literal("[").is_none());
}

#[test]
fn parse_ip_literal_close_bracket_only_returns_none() {
    assert!(parse_mask_host_ip_literal("]").is_none());
}

#[test]
fn parse_ip_literal_empty_brackets_returns_none() {
    assert!(parse_mask_host_ip_literal("[]").is_none());
}

#[test]
fn parse_ip_literal_garbage_returns_none() {
    assert!(parse_mask_host_ip_literal("not!an!ip").is_none());
}

#[test]
fn parse_ip_literal_ipv4_with_port_returns_none() {
    assert!(parse_mask_host_ip_literal("192.168.1.1:443").is_none());
}

// ---------------------------------------------------------------------------
// canonical_ip
// ---------------------------------------------------------------------------

#[test]
fn canonical_ipv4_stays_ipv4() {
    let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    assert!(canonical_ip(v4).is_ipv4());
    assert_eq!(canonical_ip(v4), v4);
}

#[test]
fn canonical_ipv6_non_mapped_stays_ipv6() {
    let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    assert!(canonical_ip(v6).is_ipv6());
    assert_eq!(canonical_ip(v6), v6);
}

#[test]
fn canonical_ipv6_link_local_stays_ipv6() {
    let v6 = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    assert!(canonical_ip(v6).is_ipv6());
}

#[test]
fn canonical_ipv4_mapped_ipv6_becomes_ipv4() {
    let mapped = IpAddr::V6(Ipv6Addr::new(
        0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x101,
    ));
    let result = canonical_ip(mapped);
    assert!(result.is_ipv4(), "::ffff:192.168.1.1 must canonicalize to IPv4");
    assert_eq!(
        result,
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
    );
}

#[test]
fn canonical_ipv4_mapped_loopback_becomes_v4() {
    let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x1));
    let result = canonical_ip(mapped);
    assert!(result.is_ipv4());
    assert_eq!(result, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
}

// ---------------------------------------------------------------------------
// is_http_probe — adversarial fixtures
// ---------------------------------------------------------------------------

#[test]
fn http_probe_tls_client_hello_first_bytes_not_http() {
    let tls_hello: &[u8] = &[0x16, 0x03, 0x01, 0x00, 0xA5];
    assert!(!is_http_probe(tls_hello));
}

#[test]
fn http_probe_tls_1_2_first_bytes_not_http() {
    let tls12: &[u8] = &[0x16, 0x03, 0x03, 0x00, 0x80];
    assert!(!is_http_probe(tls12));
}

#[test]
fn http_probe_tls_1_3_first_bytes_not_http() {
    let tls13: &[u8] = &[0x16, 0x03, 0x01, 0x00];
    assert!(!is_http_probe(tls13));
}

#[test]
fn http_probe_http2_full_preface() {
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    assert!(is_http_probe(preface));
}

#[test]
fn http_probe_http2_preface_partial_pri_space() {
    assert!(is_http_probe(b"PRI "));
}

#[test]
fn http_probe_all_zeros_16_bytes_not_http() {
    let zeros = [0u8; 16];
    assert!(!is_http_probe(&zeros));
}

#[test]
fn http_probe_all_zeros_4_bytes_not_http() {
    let zeros = [0u8; 4];
    assert!(!is_http_probe(&zeros));
}

#[test]
fn http_probe_random_garbage_non_ascii_not_http() {
    let garbage: Vec<u8> = (0x80..=0x9F).collect();
    assert!(!is_http_probe(&garbage));
}

#[test]
fn http_probe_two_byte_partial_matches_http_prefix() {
    assert!(is_http_probe(b"GE"));
    assert!(is_http_probe(b"PO"));
    assert!(is_http_probe(b"HE"));
    assert!(is_http_probe(b"PU"));
    assert!(is_http_probe(b"DE"));
    assert!(is_http_probe(b"OP"));
    assert!(is_http_probe(b"CO"));
    assert!(is_http_probe(b"TR"));
    assert!(is_http_probe(b"PA"));
    assert!(is_http_probe(b"PR"));
}

#[test]
fn http_probe_single_byte_not_classified() {
    assert!(!is_http_probe(b"G"));
    assert!(!is_http_probe(b"P"));
    assert!(!is_http_probe(b"Z"));
}

#[test]
fn http_probe_two_byte_partial_co_matches() {
    assert!(is_http_probe(b"CO"));
    assert!(is_http_probe(b"TR"));
    assert!(is_http_probe(b"PA"));
}

#[test]
fn http_probe_three_byte_partial_con_matches() {
    assert!(is_http_probe(b"CON"));
    assert!(is_http_probe(b"TRA"));
    assert!(is_http_probe(b"PAT"));
}

#[test]
fn http_probe_delete_method_recognized() {
    assert!(is_http_probe(b"DELETE / HTTP/1.1\r\n"));
}

#[test]
fn http_probe_options_method_recognized() {
    assert!(is_http_probe(b"OPTIONS * HTTP/1.1\r\n"));
}

#[test]
fn http_probe_extended_16_byte_window_all_http_methods() {
    let methods: &[&[u8]] = &[
        b"GET /index.html HTTP/1.",
        b"POST /api HTTP/1.1\n",
        b"HEAD / HTTP/1.1\nHost:",
        b"PUT /resource HTTP/1.1",
        b"DELETE /item HTTP/1.1",
    ];
    for method in methods {
        assert!(is_http_probe(method), "must classify: {:?}", method);
    }
}

// ---------------------------------------------------------------------------
// detect_client_type — adversarial fixtures
// ---------------------------------------------------------------------------

#[test]
fn detect_tls_1_0_scanner_label() {
    assert_eq!(detect_client_type(&[0x16, 0x03, 0x01, 0x00, 0xA5]), "TLS-scanner");
}

#[test]
fn detect_tls_1_2_scanner_label() {
    assert_eq!(detect_client_type(&[0x16, 0x03, 0x03, 0x00, 0x80]), "TLS-scanner");
}

#[test]
fn detect_tls_1_1_scanner_label() {
    assert_eq!(detect_client_type(&[0x16, 0x03, 0x02, 0x00, 0x10]), "TLS-scanner");
}

#[test]
fn detect_ssh_prefix() {
    assert_eq!(detect_client_type(b"SSH-2.0-OpenSSH_9.0\r\n"), "SSH");
}

#[test]
fn detect_port_scanner_short_data() {
    assert_eq!(detect_client_type(b"\x00\x01"), "port-scanner");
}

#[test]
fn detect_port_scanner_nine_bytes() {
    let data = [0xAA; 9];
    assert_eq!(detect_client_type(&data), "port-scanner");
}

#[test]
fn detect_unknown_for_ten_bytes_non_matching() {
    let data = [0xBB; 10];
    assert_eq!(detect_client_type(&data), "unknown");
}

#[test]
fn detect_unknown_for_long_non_matching() {
    let data = vec![0xCC; 100];
    assert_eq!(detect_client_type(&data), "unknown");
}

#[test]
fn detect_http_get_over_tls_prefix() {
    assert_eq!(detect_client_type(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"), "HTTP");
}

#[test]
fn detect_empty_data() {
    assert_eq!(detect_client_type(b""), "port-scanner");
}

// ---------------------------------------------------------------------------
// next_mask_shape_bucket — additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn shape_bucket_total_zero_returns_zero() {
    assert_eq!(next_mask_shape_bucket(0, 64, 4096), 0);
}

#[test]
fn shape_bucket_floor_zero_returns_total() {
    assert_eq!(next_mask_shape_bucket(100, 0, 4096), 100);
}

#[test]
fn shape_bucket_cap_less_than_floor_returns_total() {
    assert_eq!(next_mask_shape_bucket(100, 512, 64), 100);
}

#[test]
fn shape_bucket_total_equals_floor_returns_floor() {
    assert_eq!(next_mask_shape_bucket(64, 64, 4096), 64);
}

#[test]
fn shape_bucket_total_above_cap_returns_total() {
    assert_eq!(next_mask_shape_bucket(8192, 64, 4096), 8192);
}

#[test]
fn shape_bucket_total_equals_cap_returns_total() {
    assert_eq!(next_mask_shape_bucket(4096, 64, 4096), 4096);
}

#[test]
fn shape_bucket_doubles_from_floor() {
    assert_eq!(next_mask_shape_bucket(65, 64, 4096), 128);
    assert_eq!(next_mask_shape_bucket(129, 64, 4096), 256);
    assert_eq!(next_mask_shape_bucket(257, 64, 4096), 512);
}

#[test]
fn shape_bucket_clamps_at_cap() {
    assert_eq!(next_mask_shape_bucket(3000, 64, 4096), 4096);
}

#[test]
fn shape_bucket_very_large_total_no_overflow() {
    let total = usize::MAX / 2;
    assert_eq!(next_mask_shape_bucket(total, 64, 4096), total);
}

#[test]
fn shape_bucket_total_below_floor_eq_cap_returns_floor() {
    assert_eq!(next_mask_shape_bucket(50, 64, 64), 64);
}

// ---------------------------------------------------------------------------
// masking_beobachten_ttl — boundary cases
// ---------------------------------------------------------------------------

#[test]
fn beobachten_ttl_clamps_below_minimum() {
    let mut config = ProxyConfig::default();
    config.general.beobachten_minutes = 0;
    let ttl = masking_beobachten_ttl(&config);
    assert_eq!(ttl, Duration::from_secs(60));
}

#[test]
fn beobachten_ttl_at_minimum_one_minute() {
    let mut config = ProxyConfig::default();
    config.general.beobachten_minutes = 1;
    let ttl = masking_beobachten_ttl(&config);
    assert_eq!(ttl, Duration::from_secs(60));
}

#[test]
fn beobachten_ttl_clamps_above_24h() {
    let mut config = ProxyConfig::default();
    config.general.beobachten_minutes = 2000;
    let ttl = masking_beobachten_ttl(&config);
    assert_eq!(ttl, Duration::from_secs(24 * 60 * 60));
}

#[test]
fn beobachten_ttl_typical_value() {
    let mut config = ProxyConfig::default();
    config.general.beobachten_minutes = 5;
    let ttl = masking_beobachten_ttl(&config);
    assert_eq!(ttl, Duration::from_secs(300));
}

// ---------------------------------------------------------------------------
// build_mask_proxy_header — edge cases
// ---------------------------------------------------------------------------

#[test]
fn proxy_header_version_zero_returns_none() {
    let peer: SocketAddr = "192.168.1.1:12345".parse().unwrap();
    let local: SocketAddr = "10.0.0.1:443".parse().unwrap();
    assert!(build_mask_proxy_header(0, peer, local).is_none());
}

#[test]
fn proxy_header_version_two_returns_proxy_protocol_v2() {
    let peer: SocketAddr = "192.168.1.1:12345".parse().unwrap();
    let local: SocketAddr = "10.0.0.1:443".parse().unwrap();
    let header = build_mask_proxy_header(2, peer, local).unwrap();
    assert!(header.starts_with(&[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]),
        "Proxy Protocol v2 must start with the 12-byte signature");
}

#[test]
fn proxy_header_version_one_tcp4_returns_text_header() {
    let peer: SocketAddr = "192.168.1.1:12345".parse().unwrap();
    let local: SocketAddr = "10.0.0.1:443".parse().unwrap();
    let header = build_mask_proxy_header(1, peer, local).unwrap();
    let text = String::from_utf8(header).unwrap();
    assert!(text.starts_with("PROXY TCP4 "));
}

#[test]
fn proxy_header_version_one_tcp6_returns_text_header() {
    let peer: SocketAddr = "[2001:db8::1]:12345".parse().unwrap();
    let local: SocketAddr = "[::1]:443".parse().unwrap();
    let header = build_mask_proxy_header(1, peer, local).unwrap();
    let text = String::from_utf8(header).unwrap();
    assert!(text.starts_with("PROXY TCP6 "));
}

#[test]
fn proxy_header_version_one_mixed_family_returns_unknown() {
    let peer: SocketAddr = "192.168.1.1:12345".parse().unwrap();
    let local: SocketAddr = "[::1]:443".parse().unwrap();
    let header = build_mask_proxy_header(1, peer, local).unwrap();
    let text = String::from_utf8(header).unwrap();
    assert!(text.starts_with("PROXY UNKNOWN"));
}
