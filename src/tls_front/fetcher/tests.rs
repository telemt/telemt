use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::{
    MLKEM768_CLIENT_ENCAPSULATION_KEY_LEN, ProfileCacheValue, TLS_NAMED_GROUP_X25519,
    TLS_NAMED_GROUP_X25519MLKEM768, TlsFetchStrategy, X25519_KEY_SHARE_LEN, build_client_hello,
    build_tls_fetch_proxy_header, derive_behavior_profile, encode_tls13_certificate_message,
    fetch_via_rustls_stream, order_profiles, profile_alpn, profile_cache, profile_cache_key,
};
use crate::config::TlsFetchProfile;
use crate::crypto::SecureRandom;
use crate::protocol::constants::{
    TLS_RECORD_APPLICATION, TLS_RECORD_CHANGE_CIPHER, TLS_RECORD_HANDSHAKE,
};
use crate::tls_front::types::TlsProfileSource;
use tokio::io::AsyncReadExt;

struct ParsedClientHelloForTest {
    session_id: Vec<u8>,
    extensions: Vec<(u16, Vec<u8>)>,
}

fn read_u24(bytes: &[u8]) -> usize {
    ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | (bytes[2] as usize)
}

fn parse_client_hello_for_test(record: &[u8]) -> ParsedClientHelloForTest {
    assert!(record.len() >= 9, "record too short");
    assert_eq!(record[0], TLS_RECORD_HANDSHAKE, "not a handshake record");
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    assert_eq!(record.len(), 5 + record_len, "record length mismatch");

    let handshake = &record[5..];
    assert_eq!(handshake[0], 0x01, "not a ClientHello handshake");
    let hello_len = read_u24(&handshake[1..4]);
    assert_eq!(handshake.len(), 4 + hello_len, "handshake length mismatch");
    let hello = &handshake[4..];

    let mut pos = 0usize;
    pos += 2;
    pos += 32;

    let session_len = hello[pos] as usize;
    pos += 1;
    let session_id = hello[pos..pos + session_len].to_vec();
    pos += session_len;

    let cipher_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2 + cipher_len;

    let compression_len = hello[pos] as usize;
    pos += 1 + compression_len;

    let ext_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    assert_eq!(ext_end, hello.len(), "extensions length mismatch");

    let mut extensions = Vec::new();
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
        let data_len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
        pos += 4;
        let data = hello[pos..pos + data_len].to_vec();
        pos += data_len;
        extensions.push((ext_type, data));
    }
    assert_eq!(pos, ext_end, "extension parse did not consume all bytes");

    ParsedClientHelloForTest {
        session_id,
        extensions,
    }
}

fn parse_alpn_protocols(data: &[u8]) -> Vec<Vec<u8>> {
    assert!(data.len() >= 2, "ALPN extension is too short");
    let protocols_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    assert_eq!(protocols_len + 2, data.len(), "ALPN list length mismatch");
    let mut pos = 2usize;
    let mut out = Vec::new();
    while pos < data.len() {
        let len = data[pos] as usize;
        pos += 1;
        out.push(data[pos..pos + len].to_vec());
        pos += len;
    }
    out
}

async fn capture_rustls_client_hello_record(alpn_protocols: &'static [&'static [u8]]) -> Vec<u8> {
    let (client, mut server) = tokio::io::duplex(32 * 1024);
    let fetch_task = tokio::spawn(async move {
        fetch_via_rustls_stream(client, "example.com", "example.com", None, alpn_protocols).await
    });

    let mut header = [0u8; 5];
    server
        .read_exact(&mut header)
        .await
        .expect("must read client hello record header");
    let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; body_len];
    server
        .read_exact(&mut body)
        .await
        .expect("must read client hello record body");
    drop(server);

    let result = fetch_task.await.expect("fetch task must join");
    assert!(
        result.is_err(),
        "capture task should end with handshake error"
    );

    let mut record = Vec::with_capacity(5 + body_len);
    record.extend_from_slice(&header);
    record.extend_from_slice(&body);
    record
}

#[test]
fn test_encode_tls13_certificate_message_single_cert() {
    let cert = vec![0x30, 0x03, 0x02, 0x01, 0x01];
    let message = encode_tls13_certificate_message(std::slice::from_ref(&cert)).expect("message");

    assert_eq!(message[0], 0x0b);
    assert_eq!(read_u24(&message[1..4]), message.len() - 4);
    assert_eq!(message[4], 0x00);

    let cert_list_len = read_u24(&message[5..8]);
    assert_eq!(cert_list_len, cert.len() + 5);

    let cert_len = read_u24(&message[8..11]);
    assert_eq!(cert_len, cert.len());
    assert_eq!(&message[11..11 + cert.len()], cert.as_slice());
    assert_eq!(&message[11 + cert.len()..13 + cert.len()], &[0x00, 0x00]);
}

#[test]
fn test_encode_tls13_certificate_message_empty_chain() {
    assert!(encode_tls13_certificate_message(&[]).is_none());
}

#[test]
fn test_derive_behavior_profile_splits_ticket_like_tail_records() {
    let profile = derive_behavior_profile(&[
        (TLS_RECORD_HANDSHAKE, vec![0u8; 90]),
        (TLS_RECORD_CHANGE_CIPHER, vec![0x01]),
        (TLS_RECORD_APPLICATION, vec![0u8; 1400]),
        (TLS_RECORD_APPLICATION, vec![0u8; 220]),
        (TLS_RECORD_APPLICATION, vec![0u8; 180]),
    ]);

    assert_eq!(profile.change_cipher_spec_count, 1);
    assert_eq!(profile.app_data_record_sizes, vec![1400]);
    assert_eq!(profile.ticket_record_sizes, vec![220, 180]);
    assert_eq!(profile.source, TlsProfileSource::Raw);
}

#[test]
fn test_order_profiles_prioritizes_fresh_cached_winner() {
    let strategy = TlsFetchStrategy {
        profiles: vec![
            TlsFetchProfile::ModernChromeLike,
            TlsFetchProfile::CompatTls12,
            TlsFetchProfile::LegacyMinimal,
        ],
        strict_route: true,
        attempt_timeout: Duration::from_secs(1),
        total_budget: Duration::from_secs(2),
        grease_enabled: false,
        deterministic: false,
        profile_cache_ttl: Duration::from_secs(60),
    };
    let cache_key = profile_cache_key(
        "mask.example",
        443,
        "tls.example",
        None,
        Some("tls"),
        0,
        None,
    );
    profile_cache().remove(&cache_key);
    profile_cache().insert(
        cache_key.clone(),
        ProfileCacheValue {
            profile: TlsFetchProfile::CompatTls12,
            updated_at: Instant::now(),
        },
    );

    let ordered = order_profiles(&strategy, Some(&cache_key), Instant::now());
    assert_eq!(ordered[0], TlsFetchProfile::CompatTls12);
    profile_cache().remove(&cache_key);
}

#[test]
fn test_order_profiles_drops_expired_cached_winner() {
    let strategy = TlsFetchStrategy {
        profiles: vec![
            TlsFetchProfile::ModernFirefoxLike,
            TlsFetchProfile::CompatTls12,
        ],
        strict_route: true,
        attempt_timeout: Duration::from_secs(1),
        total_budget: Duration::from_secs(2),
        grease_enabled: false,
        deterministic: false,
        profile_cache_ttl: Duration::from_secs(5),
    };
    let cache_key = profile_cache_key("mask2.example", 443, "tls2.example", None, None, 0, None);
    profile_cache().remove(&cache_key);
    profile_cache().insert(
        cache_key.clone(),
        ProfileCacheValue {
            profile: TlsFetchProfile::CompatTls12,
            updated_at: Instant::now() - Duration::from_secs(6),
        },
    );

    let ordered = order_profiles(&strategy, Some(&cache_key), Instant::now());
    assert_eq!(ordered[0], TlsFetchProfile::ModernFirefoxLike);
    assert!(profile_cache().get(&cache_key).is_none());
}

#[test]
fn test_deterministic_client_hello_is_stable() {
    let rng = SecureRandom::new();
    let first = build_client_hello(
        "stable.example",
        &rng,
        TlsFetchProfile::ModernChromeLike,
        true,
        true,
    );
    let second = build_client_hello(
        "stable.example",
        &rng,
        TlsFetchProfile::ModernChromeLike,
        true,
        true,
    );

    assert_eq!(first, second);
}

#[test]
fn test_raw_client_hello_alpn_matches_profile() {
    let rng = SecureRandom::new();
    for profile in [
        TlsFetchProfile::ModernChromeLike,
        TlsFetchProfile::ModernFirefoxLike,
        TlsFetchProfile::CompatTls12,
        TlsFetchProfile::LegacyMinimal,
    ] {
        let hello = build_client_hello("alpn.example", &rng, profile, false, true);
        let parsed = parse_client_hello_for_test(&hello);
        let alpn_ext = parsed
            .extensions
            .iter()
            .find(|(ext_type, _)| *ext_type == 0x0010)
            .expect("ALPN extension must exist");
        let parsed_alpn = parse_alpn_protocols(&alpn_ext.1);
        let expected_alpn = profile_alpn(profile)
            .iter()
            .map(|proto| proto.to_vec())
            .collect::<Vec<_>>();
        assert_eq!(
            parsed_alpn,
            expected_alpn,
            "ALPN mismatch for {}",
            profile.as_str()
        );
    }
}

#[test]
fn test_modern_chrome_like_browser_extension_layout() {
    let rng = SecureRandom::new();
    let hello = build_client_hello(
        "chrome.example",
        &rng,
        TlsFetchProfile::ModernChromeLike,
        false,
        true,
    );
    let parsed = parse_client_hello_for_test(&hello);
    assert_eq!(
        parsed.session_id.len(),
        32,
        "modern chrome must use non-empty session id"
    );

    let extension_ids = parsed
        .extensions
        .iter()
        .map(|(ext_type, _)| *ext_type)
        .collect::<Vec<_>>();
    let expected_prefix = [
        0x0000, 0x000b, 0x000a, 0x0023, 0x000d, 0x002b, 0x002d, 0x0033, 0x0010,
    ];
    assert!(
        extension_ids.as_slice().starts_with(&expected_prefix),
        "unexpected extension order: {extension_ids:?}"
    );
    assert!(
        extension_ids.contains(&0x0015),
        "modern chrome profile should include padding extension"
    );

    let key_share = parsed
        .extensions
        .iter()
        .find(|(ext_type, _)| *ext_type == 0x0033)
        .expect("key_share extension must exist");
    let key_share_data = &key_share.1;
    assert!(
        key_share_data.len() >= 2 + 4 + 32,
        "key_share payload is too short"
    );
    let entry_len = u16::from_be_bytes([key_share_data[0], key_share_data[1]]) as usize;
    assert_eq!(
        entry_len,
        key_share_data.len() - 2,
        "key_share list length mismatch"
    );
    let mut pos = 2usize;
    let hybrid_group = u16::from_be_bytes([key_share_data[pos], key_share_data[pos + 1]]);
    let hybrid_len =
        u16::from_be_bytes([key_share_data[pos + 2], key_share_data[pos + 3]]) as usize;
    pos += 4;
    let hybrid_key = &key_share_data[pos..pos + hybrid_len];
    pos += hybrid_len;
    assert_eq!(
        hybrid_group, TLS_NAMED_GROUP_X25519MLKEM768,
        "first key_share group must be X25519MLKEM768"
    );
    assert_eq!(
        hybrid_len,
        MLKEM768_CLIENT_ENCAPSULATION_KEY_LEN + X25519_KEY_SHARE_LEN,
        "hybrid key length must match X25519MLKEM768"
    );
    assert!(
        hybrid_key.iter().any(|b| *b != 0),
        "hybrid key must not be all zero"
    );

    let group = u16::from_be_bytes([key_share_data[pos], key_share_data[pos + 1]]);
    let key_len = u16::from_be_bytes([key_share_data[pos + 2], key_share_data[pos + 3]]) as usize;
    pos += 4;
    let key = &key_share_data[pos..pos + key_len];
    assert_eq!(
        group, TLS_NAMED_GROUP_X25519,
        "second key_share group must be x25519"
    );
    assert_eq!(
        key_len, X25519_KEY_SHARE_LEN,
        "x25519 key length must be 32"
    );
    assert!(
        key.iter().any(|b| *b != 0),
        "x25519 key must not be all zero"
    );
}

#[test]
fn test_fallback_profiles_keep_compat_extension_set() {
    let rng = SecureRandom::new();
    for profile in [
        TlsFetchProfile::ModernFirefoxLike,
        TlsFetchProfile::CompatTls12,
        TlsFetchProfile::LegacyMinimal,
    ] {
        let hello = build_client_hello("fallback.example", &rng, profile, false, true);
        let parsed = parse_client_hello_for_test(&hello);
        let extension_ids = parsed
            .extensions
            .iter()
            .map(|(ext_type, _)| *ext_type)
            .collect::<Vec<_>>();

        assert!(extension_ids.contains(&0x0000), "SNI extension must exist");
        assert!(
            extension_ids.contains(&0x000a),
            "supported_groups extension must exist"
        );
        assert!(
            extension_ids.contains(&0x000d),
            "signature_algorithms extension must exist"
        );
        assert!(
            extension_ids.contains(&0x002b),
            "supported_versions extension must exist"
        );
        assert!(
            extension_ids.contains(&0x0033),
            "key_share extension must exist"
        );
        assert!(extension_ids.contains(&0x0010), "ALPN extension must exist");
        assert!(
            !extension_ids.contains(&0x000b),
            "ec_point_formats must stay chrome-only"
        );
        assert!(
            !extension_ids.contains(&0x0023),
            "session_ticket must stay chrome-only"
        );
        assert!(
            !extension_ids.contains(&0x002d),
            "psk_key_exchange_modes must stay chrome-only"
        );

        let expected_session_len = if matches!(profile, TlsFetchProfile::ModernFirefoxLike) {
            32
        } else {
            0
        };
        assert_eq!(
            parsed.session_id.len(),
            expected_session_len,
            "unexpected session id length for {}",
            profile.as_str()
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn test_rustls_client_hello_alpn_matches_selected_profile() {
    for profile in [
        TlsFetchProfile::ModernChromeLike,
        TlsFetchProfile::CompatTls12,
        TlsFetchProfile::LegacyMinimal,
    ] {
        let record = capture_rustls_client_hello_record(profile_alpn(profile)).await;
        let parsed = parse_client_hello_for_test(&record);
        let alpn_ext = parsed
            .extensions
            .iter()
            .find(|(ext_type, _)| *ext_type == 0x0010)
            .expect("ALPN extension must exist");
        let parsed_alpn = parse_alpn_protocols(&alpn_ext.1);
        let expected_alpn = profile_alpn(profile)
            .iter()
            .map(|proto| proto.to_vec())
            .collect::<Vec<_>>();
        assert_eq!(
            parsed_alpn,
            expected_alpn,
            "rustls ALPN mismatch for {}",
            profile.as_str()
        );
    }
}

#[test]
fn test_build_tls_fetch_proxy_header_v2_with_tcp_addrs() {
    let src: SocketAddr = "198.51.100.10:42000".parse().expect("valid src");
    let dst: SocketAddr = "203.0.113.20:443".parse().expect("valid dst");
    let header = build_tls_fetch_proxy_header(2, Some(src), Some(dst)).expect("header");

    assert_eq!(
        &header[..12],
        &[
            0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a
        ]
    );
    assert_eq!(header[12], 0x21);
    assert_eq!(header[13], 0x11);
    assert_eq!(u16::from_be_bytes([header[14], header[15]]), 12);
    assert_eq!(&header[16..20], &[198, 51, 100, 10]);
    assert_eq!(&header[20..24], &[203, 0, 113, 20]);
    assert_eq!(u16::from_be_bytes([header[24], header[25]]), 42000);
    assert_eq!(u16::from_be_bytes([header[26], header[27]]), 443);
}

#[test]
fn test_build_tls_fetch_proxy_header_v2_mixed_family_falls_back_to_local_command() {
    let src: SocketAddr = "198.51.100.10:42000".parse().expect("valid src");
    let dst: SocketAddr = "[2001:db8::20]:443".parse().expect("valid dst");
    let header = build_tls_fetch_proxy_header(2, Some(src), Some(dst)).expect("header");

    assert_eq!(header[12], 0x20);
    assert_eq!(header[13], 0x00);
    assert_eq!(u16::from_be_bytes([header[14], header[15]]), 0);
}

#[test]
fn test_build_tls_fetch_proxy_header_v1_with_tcp_addrs() {
    let src: SocketAddr = "198.51.100.10:42000".parse().expect("valid src");
    let dst: SocketAddr = "203.0.113.20:443".parse().expect("valid dst");
    let header = build_tls_fetch_proxy_header(1, Some(src), Some(dst)).expect("header");

    assert_eq!(
        header,
        b"PROXY TCP4 198.51.100.10 203.0.113.20 42000 443\r\n"
    );
}
