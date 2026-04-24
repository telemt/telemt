use std::time::SystemTime;

use crate::crypto::SecureRandom;
use crate::protocol::constants::{
    TLS_RECORD_APPLICATION, TLS_RECORD_CHANGE_CIPHER, TLS_RECORD_HANDSHAKE,
};
use crate::protocol::tls::ClientHelloTlsVersion;
use crate::tls_front::emulator::build_emulated_server_hello;
use crate::tls_front::types::{
    CachedTlsData, ParsedServerHello, TlsBehaviorProfile, TlsProfileSource,
};

fn make_cached() -> CachedTlsData {
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
        cert_payload: None,
        app_data_records_sizes: vec![1200, 900, 220, 180],
        total_app_data_len: 2500,
        behavior_profile: TlsBehaviorProfile {
            change_cipher_spec_count: 2,
            app_data_record_sizes: vec![1200, 900],
            ticket_record_sizes: vec![220, 180],
            source: TlsProfileSource::Merged,
        },
        fetched_at: SystemTime::now(),
        domain: "example.com".to_string(),
    }
}

fn record_lengths_by_type(response: &[u8], wanted_type: u8) -> Vec<usize> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 5 <= response.len() {
        let record_type = response[pos];
        let record_len = u16::from_be_bytes([response[pos + 3], response[pos + 4]]) as usize;
        if pos + 5 + record_len > response.len() {
            break;
        }
        if record_type == wanted_type {
            out.push(record_len);
        }
        pos += 5 + record_len;
    }
    out
}

#[test]
fn emulated_server_hello_keeps_single_change_cipher_spec_for_client_compatibility() {
    let cached = make_cached();
    let rng = SecureRandom::new();

    let response = build_emulated_server_hello(
        b"secret",
        &[0x71; 32],
        &[0x72; 16],
        &cached,
        false,
        true,
        ClientHelloTlsVersion::Tls13,
        &rng,
        None,
        0,
    );

    assert_eq!(response[0], TLS_RECORD_HANDSHAKE);
    let ccs_records = record_lengths_by_type(&response, TLS_RECORD_CHANGE_CIPHER);
    assert_eq!(ccs_records.len(), 1);
    assert!(ccs_records.iter().all(|len| *len == 1));
}

#[test]
fn emulated_server_hello_does_not_emit_profile_ticket_tail_when_disabled() {
    let cached = make_cached();
    let rng = SecureRandom::new();

    let response = build_emulated_server_hello(
        b"secret",
        &[0x81; 32],
        &[0x82; 16],
        &cached,
        false,
        true,
        ClientHelloTlsVersion::Tls13,
        &rng,
        None,
        0,
    );

    let app_records = record_lengths_by_type(&response, TLS_RECORD_APPLICATION);
    assert_eq!(app_records, vec![1200]);
}

#[test]
fn emulated_server_hello_uses_profile_ticket_lengths_when_enabled() {
    let cached = make_cached();
    let rng = SecureRandom::new();

    let response = build_emulated_server_hello(
        b"secret",
        &[0x91; 32],
        &[0x92; 16],
        &cached,
        false,
        true,
        ClientHelloTlsVersion::Tls13,
        &rng,
        None,
        2,
    );

    let app_records = record_lengths_by_type(&response, TLS_RECORD_APPLICATION);
    assert_eq!(app_records, vec![1200, 220, 180]);
}
