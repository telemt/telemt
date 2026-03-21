use std::time::SystemTime;

use crate::crypto::SecureRandom;
use crate::protocol::constants::{
    TLS_RECORD_APPLICATION, TLS_RECORD_CHANGE_CIPHER, TLS_RECORD_HANDSHAKE,
};
use crate::tls_front::emulator::build_emulated_server_hello;
use crate::tls_front::types::{
    CachedTlsData, ParsedServerHello, TlsBehaviorProfile, TlsCertPayload, TlsProfileSource,
};

fn make_cached(cert_payload: Option<crate::tls_front::types::TlsCertPayload>) -> CachedTlsData {
    CachedTlsData {
        server_hello_template: ParsedServerHello {
            version: [0x03, 0x03],
            random: [0u8; 32],
            session_id: Vec::new(),
            cipher_suite: [0x13, 0x01],
            compression: 0,
            extensions: Vec::new(),
        },
        cert_info: None,
        cert_payload,
        app_data_records_sizes: vec![64],
        total_app_data_len: 64,
        behavior_profile: TlsBehaviorProfile {
            change_cipher_spec_count: 1,
            app_data_record_sizes: vec![64],
            ticket_record_sizes: Vec::new(),
            source: TlsProfileSource::Default,
        },
        fetched_at: SystemTime::now(),
        domain: "example.com".to_string(),
    }
}

fn first_app_data_payload(response: &[u8]) -> &[u8] {
    let hello_len = u16::from_be_bytes([response[3], response[4]]) as usize;
    let ccs_start = 5 + hello_len;
    let ccs_len = u16::from_be_bytes([response[ccs_start + 3], response[ccs_start + 4]]) as usize;
    let app_start = ccs_start + 5 + ccs_len;
    let app_len = u16::from_be_bytes([response[app_start + 3], response[app_start + 4]]) as usize;
    &response[app_start + 5..app_start + 5 + app_len]
}

#[test]
fn emulated_server_hello_ignores_oversized_alpn_when_marker_would_not_fit() {
    let cached = make_cached(None);
    let rng = SecureRandom::new();
    let oversized_alpn = vec![0xAB; u8::MAX as usize + 1];

    let response = build_emulated_server_hello(
        b"secret",
        &[0x11; 32],
        &[0x22; 16],
        &cached,
        true,
        &rng,
        Some(oversized_alpn),
        0,
    );

    assert_eq!(response[0], TLS_RECORD_HANDSHAKE);
    let hello_len = u16::from_be_bytes([response[3], response[4]]) as usize;
    let ccs_start = 5 + hello_len;
    assert_eq!(response[ccs_start], TLS_RECORD_CHANGE_CIPHER);
    let app_start = ccs_start + 6;
    assert_eq!(response[app_start], TLS_RECORD_APPLICATION);

    let payload = first_app_data_payload(&response);
    let mut marker_prefix = Vec::new();
    marker_prefix.extend_from_slice(&0x0010u16.to_be_bytes());
    marker_prefix.extend_from_slice(&0x0102u16.to_be_bytes());
    marker_prefix.extend_from_slice(&0x0100u16.to_be_bytes());
    marker_prefix.push(0xff);
    marker_prefix.extend_from_slice(&[0xab; 8]);
    assert!(
        !payload.starts_with(&marker_prefix),
        "oversized ALPN must not be partially embedded into the emulated first application record"
    );
}

#[test]
fn emulated_server_hello_embeds_full_alpn_marker_when_body_can_fit() {
    let cached = make_cached(None);
    let rng = SecureRandom::new();

    let response = build_emulated_server_hello(
        b"secret",
        &[0x31; 32],
        &[0x41; 16],
        &cached,
        true,
        &rng,
        Some(b"h2".to_vec()),
        0,
    );

    let payload = first_app_data_payload(&response);
    let expected = [0x00u8, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2'];
    assert!(
        payload.starts_with(&expected),
        "when body has enough capacity, emulated first application record must include full ALPN marker"
    );
}

#[test]
fn emulated_server_hello_prefers_cert_payload_over_alpn_marker() {
    let cert_msg = vec![0x0b, 0x00, 0x00, 0x05, 0x00, 0xaa, 0xbb, 0xcc, 0xdd];
    let cached = make_cached(Some(TlsCertPayload {
        cert_chain_der: vec![vec![0x30, 0x01, 0x00]],
        certificate_message: cert_msg.clone(),
    }));
    let rng = SecureRandom::new();

    let response = build_emulated_server_hello(
        b"secret",
        &[0x32; 32],
        &[0x42; 16],
        &cached,
        true,
        &rng,
        Some(b"h2".to_vec()),
        0,
    );

    let payload = first_app_data_payload(&response);
    let alpn_marker = [0x00u8, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2'];

    assert!(
        payload.starts_with(&cert_msg),
        "when certificate payload is available, first record must start with cert payload bytes"
    );
    assert!(
        !payload.starts_with(&alpn_marker),
        "ALPN marker must not displace selected certificate payload"
    );
}
