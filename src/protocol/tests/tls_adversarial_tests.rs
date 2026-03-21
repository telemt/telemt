use super::*;
use crate::crypto::sha256_hmac;
use std::time::Instant;

/// Helper to create a byte vector of specific length.
fn make_garbage(len: usize) -> Vec<u8> {
    vec![0x42u8; len]
}

/// Helper to create a valid-looking HMAC digest for test.
fn make_digest(secret: &[u8], msg: &[u8], ts: u32) -> [u8; 32] {
    let mut hmac = sha256_hmac(secret, msg);
    let ts_bytes = ts.to_le_bytes();
    for i in 0..4 {
        hmac[28 + i] ^= ts_bytes[i];
    }
    hmac
}

fn make_valid_tls_handshake_with_session_id(
    secret: &[u8],
    timestamp: u32,
    session_id: &[u8],
) -> Vec<u8> {
    let session_id_len = session_id.len();
    let len = TLS_DIGEST_POS + TLS_DIGEST_LEN + 1 + session_id_len;
    let mut handshake = vec![0x42u8; len];

    handshake[TLS_DIGEST_POS + TLS_DIGEST_LEN] = session_id_len as u8;
    let sid_start = TLS_DIGEST_POS + TLS_DIGEST_LEN + 1;
    handshake[sid_start..sid_start + session_id_len].copy_from_slice(session_id);
    handshake[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN].fill(0);

    let digest = make_digest(secret, &handshake, timestamp);

    handshake[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN].copy_from_slice(&digest);
    handshake
}

fn make_valid_tls_handshake(secret: &[u8], timestamp: u32) -> Vec<u8> {
    make_valid_tls_handshake_with_session_id(secret, timestamp, &[0x42; 32])
}

// ------------------------------------------------------------------
// Truncated Packet Tests (OWASP ASVS 5.1.4, 5.1.5)
// ------------------------------------------------------------------

#[test]
fn validate_tls_handshake_truncated_10_bytes_rejected() {
    let secrets = vec![("user".to_string(), b"secret".to_vec())];
    let truncated = make_garbage(10);
    assert!(validate_tls_handshake(&truncated, &secrets, true).is_none());
}

#[test]
fn validate_tls_handshake_truncated_at_digest_start_rejected() {
    let secrets = vec![("user".to_string(), b"secret".to_vec())];
    // TLS_DIGEST_POS = 11. 11 bytes should be rejected.
    let truncated = make_garbage(TLS_DIGEST_POS);
    assert!(validate_tls_handshake(&truncated, &secrets, true).is_none());
}

#[test]
fn validate_tls_handshake_truncated_inside_digest_rejected() {
    let secrets = vec![("user".to_string(), b"secret".to_vec())];
    // TLS_DIGEST_POS + 16 (half digest)
    let truncated = make_garbage(TLS_DIGEST_POS + 16);
    assert!(validate_tls_handshake(&truncated, &secrets, true).is_none());
}

#[test]
fn extract_sni_truncated_at_record_header_rejected() {
    let truncated = make_garbage(3);
    assert!(extract_sni_from_client_hello(&truncated).is_none());
}

#[test]
fn extract_sni_truncated_at_handshake_header_rejected() {
    let mut truncated = vec![TLS_RECORD_HANDSHAKE, 0x03, 0x03, 0x00, 0x05];
    truncated.extend_from_slice(&[0x01, 0x00]); // ClientHello type but truncated length
    assert!(extract_sni_from_client_hello(&truncated).is_none());
}

// ------------------------------------------------------------------
// Malformed Extension Parsing Tests
// ------------------------------------------------------------------

#[test]
fn extract_sni_with_overlapping_extension_lengths_rejected() {
    let mut h = vec![0x16, 0x03, 0x03, 0x00, 0x60]; // Record header
    h.push(0x01); // Handshake type: ClientHello
    h.extend_from_slice(&[0x00, 0x00, 0x5C]); // Length: 92
    h.extend_from_slice(&[0x03, 0x03]); // Version
    h.extend_from_slice(&[0u8; 32]); // Random
    h.push(0); // Session ID length: 0
    h.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // Cipher suites
    h.extend_from_slice(&[0x01, 0x00]); // Compression

    // Extensions start
    h.extend_from_slice(&[0x00, 0x20]); // Total Extensions length: 32

    // Extension 1: SNI (type 0)
    h.extend_from_slice(&[0x00, 0x00]);
    h.extend_from_slice(&[0x00, 0x40]); // Claimed len: 64 (OVERFLOWS total extensions len 32)
    h.extend_from_slice(&[0u8; 64]);

    assert!(extract_sni_from_client_hello(&h).is_none());
}

#[test]
fn extract_sni_with_infinite_loop_potential_extension_rejected() {
    let mut h = vec![0x16, 0x03, 0x03, 0x00, 0x60]; // Record header
    h.push(0x01); // Handshake type: ClientHello
    h.extend_from_slice(&[0x00, 0x00, 0x5C]); // Length: 92
    h.extend_from_slice(&[0x03, 0x03]); // Version
    h.extend_from_slice(&[0u8; 32]); // Random
    h.push(0); // Session ID length: 0
    h.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // Cipher suites
    h.extend_from_slice(&[0x01, 0x00]); // Compression

    // Extensions start
    h.extend_from_slice(&[0x00, 0x10]); // Total Extensions length: 16

    // Extension: zero length but claims more?
    // If our parser didn't advance, it might loop.
    // Telemt uses `pos += 4 + elen;` so it always advances.
    h.extend_from_slice(&[0x12, 0x34]); // Unknown type
    h.extend_from_slice(&[0x00, 0x00]); // Length 0

    // Fill the rest with garbage
    h.extend_from_slice(&[0x42; 12]);

    // We expect it to finish without SNI found
    assert!(extract_sni_from_client_hello(&h).is_none());
}

#[test]
fn extract_sni_with_invalid_hostname_rejected() {
    let host = b"invalid_host!%^";
    let mut sni = Vec::new();
    sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni.extend_from_slice(host);

    let mut h = vec![0x16, 0x03, 0x03, 0x00, 0x60]; // Record header
    h.push(0x01); // ClientHello
    h.extend_from_slice(&[0x00, 0x00, 0x5C]);
    h.extend_from_slice(&[0x03, 0x03]);
    h.extend_from_slice(&[0u8; 32]);
    h.push(0);
    h.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    h.extend_from_slice(&[0x01, 0x00]);

    let mut ext = Vec::new();
    ext.extend_from_slice(&0x0000u16.to_be_bytes());
    ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni);

    h.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    h.extend_from_slice(&ext);

    assert!(
        extract_sni_from_client_hello(&h).is_none(),
        "Invalid SNI hostname must be rejected"
    );
}

// ------------------------------------------------------------------
// Timing Neutrality Tests (OWASP ASVS 5.1.7)
// ------------------------------------------------------------------

#[test]
fn validate_tls_handshake_timing_neutrality() {
    let secret = b"timing_test_secret_32_bytes_long_";
    let secrets = vec![("u".to_string(), secret.to_vec())];

    let mut base = vec![0x42u8; 100];
    base[TLS_DIGEST_POS + TLS_DIGEST_LEN] = 32;

    const ITER: usize = 600;
    const ROUNDS: usize = 7;

    let mut per_round_avg_diff_ns = Vec::with_capacity(ROUNDS);

    for round in 0..ROUNDS {
        let mut success_h = base.clone();
        let mut fail_h = base.clone();

        let start_success = Instant::now();
        for _ in 0..ITER {
            let digest = make_digest(secret, &success_h, 0);
            success_h[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN].copy_from_slice(&digest);
            let _ = validate_tls_handshake_at_time(&success_h, &secrets, true, 0);
        }
        let success_elapsed = start_success.elapsed();

        let start_fail = Instant::now();
        for i in 0..ITER {
            let mut digest = make_digest(secret, &fail_h, 0);
            let flip_idx = (i + round) % (TLS_DIGEST_LEN - 4);
            digest[flip_idx] ^= 0xFF;
            fail_h[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN].copy_from_slice(&digest);
            let _ = validate_tls_handshake_at_time(&fail_h, &secrets, true, 0);
        }
        let fail_elapsed = start_fail.elapsed();

        let diff = if success_elapsed > fail_elapsed {
            success_elapsed - fail_elapsed
        } else {
            fail_elapsed - success_elapsed
        };
        per_round_avg_diff_ns.push(diff.as_nanos() as f64 / ITER as f64);
    }

    per_round_avg_diff_ns.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median_avg_diff_ns = per_round_avg_diff_ns[ROUNDS / 2];

    // Keep this as a coarse side-channel guard only; noisy shared CI hosts can
    // introduce microsecond-level jitter that should not fail deterministic suites.
    assert!(
        median_avg_diff_ns < 50_000.0,
        "Median timing delta too large: {} ns/iter",
        median_avg_diff_ns
    );
}

// ------------------------------------------------------------------
// Adversarial Fingerprinting / Active Probing Tests
// ------------------------------------------------------------------

#[test]
fn is_tls_handshake_robustness_against_probing() {
    // Valid TLS 1.0 ClientHello
    assert!(is_tls_handshake(&[0x16, 0x03, 0x01]));
    // Valid TLS 1.2/1.3 ClientHello (Legacy Record Layer)
    assert!(is_tls_handshake(&[0x16, 0x03, 0x03]));

    // Invalid record type but matching version
    assert!(!is_tls_handshake(&[0x17, 0x03, 0x03]));
    // Plaintext HTTP request
    assert!(!is_tls_handshake(b"GET / HTTP/1.1"));
    // Short garbage
    assert!(!is_tls_handshake(&[0x16, 0x03]));
}

#[test]
fn validate_tls_handshake_at_time_strict_boundary() {
    let secret = b"strict_boundary_secret_32_bytes_";
    let secrets = vec![("u".to_string(), secret.to_vec())];
    let now: i64 = 1_000_000_000;

    // Boundary: exactly TIME_SKEW_MAX (120s past)
    let ts_past = (now - TIME_SKEW_MAX) as u32;
    let h = make_valid_tls_handshake_with_session_id(secret, ts_past, &[0x42; 32]);
    assert!(validate_tls_handshake_at_time(&h, &secrets, false, now).is_some());

    // Boundary + 1s: should be rejected
    let ts_too_past = (now - TIME_SKEW_MAX - 1) as u32;
    let h2 = make_valid_tls_handshake_with_session_id(secret, ts_too_past, &[0x42; 32]);
    assert!(validate_tls_handshake_at_time(&h2, &secrets, false, now).is_none());
}

#[test]
fn extract_sni_with_duplicate_extensions_rejected() {
    // Construct a ClientHello with TWO SNI extensions
    let host1 = b"first.com";
    let mut sni1 = Vec::new();
    sni1.extend_from_slice(&((host1.len() + 3) as u16).to_be_bytes());
    sni1.push(0);
    sni1.extend_from_slice(&(host1.len() as u16).to_be_bytes());
    sni1.extend_from_slice(host1);

    let host2 = b"second.com";
    let mut sni2 = Vec::new();
    sni2.extend_from_slice(&((host2.len() + 3) as u16).to_be_bytes());
    sni2.push(0);
    sni2.extend_from_slice(&(host2.len() as u16).to_be_bytes());
    sni2.extend_from_slice(host2);

    let mut ext = Vec::new();
    // Ext 1: SNI
    ext.extend_from_slice(&0x0000u16.to_be_bytes());
    ext.extend_from_slice(&(sni1.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni1);
    // Ext 2: SNI again
    ext.extend_from_slice(&0x0000u16.to_be_bytes());
    ext.extend_from_slice(&(sni2.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni2);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    let body_len = (body.len() as u32).to_be_bytes();
    handshake.extend_from_slice(&body_len[1..4]);
    handshake.extend_from_slice(&body);

    let mut h = Vec::new();
    h.push(0x16);
    h.extend_from_slice(&[0x03, 0x03]);
    h.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    h.extend_from_slice(&handshake);

    // Duplicate SNI extensions are ambiguous and must fail closed.
    assert!(extract_sni_from_client_hello(&h).is_none());
}

#[test]
fn extract_alpn_with_malformed_list_rejected() {
    let mut alpn_payload = Vec::new();
    alpn_payload.extend_from_slice(&0x0005u16.to_be_bytes()); // Total len 5
    alpn_payload.push(10); // Labeled len 10 (OVERFLOWS total 5)
    alpn_payload.extend_from_slice(b"h2");

    let mut ext = Vec::new();
    ext.extend_from_slice(&0x0010u16.to_be_bytes()); // Type: ALPN (16)
    ext.extend_from_slice(&(alpn_payload.len() as u16).to_be_bytes());
    ext.extend_from_slice(&alpn_payload);

    let mut h = vec![
        0x16, 0x03, 0x03, 0x00, 0x40, 0x01, 0x00, 0x00, 0x3C, 0x03, 0x03,
    ];
    h.extend_from_slice(&[0u8; 32]);
    h.push(0);
    h.extend_from_slice(&[0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
    h.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    h.extend_from_slice(&ext);

    let res = extract_alpn_from_client_hello(&h);
    assert!(
        res.is_empty(),
        "Malformed ALPN list must return empty or fail"
    );
}

#[test]
fn extract_sni_with_huge_extension_header_rejected() {
    let mut h = vec![0x16, 0x03, 0x03, 0x00, 0x00]; // Record header
    h.push(0x01); // ClientHello
    h.extend_from_slice(&[0x00, 0xFF, 0xFF]); // Huge length (65535) - overflows record
    h.extend_from_slice(&[0x03, 0x03]);
    h.extend_from_slice(&[0u8; 32]);
    h.push(0);
    h.extend_from_slice(&[0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);

    // Extensions start
    h.extend_from_slice(&[0xFF, 0xFF]); // Total extensions: 65535 (OVERFLOWS everything)

    assert!(extract_sni_from_client_hello(&h).is_none());
}
