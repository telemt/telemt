use super::*;
use crate::crypto::sha256_hmac;
use std::panic::catch_unwind;

fn make_valid_tls_handshake_with_session_id(
    secret: &[u8],
    timestamp: u32,
    session_id: &[u8],
) -> Vec<u8> {
    let session_id_len = session_id.len();
    assert!(session_id_len <= u8::MAX as usize);

    let len = TLS_DIGEST_POS + TLS_DIGEST_LEN + 1 + session_id_len;
    let mut handshake = vec![0x42u8; len];
    handshake[TLS_DIGEST_POS + TLS_DIGEST_LEN] = session_id_len as u8;
    let sid_start = TLS_DIGEST_POS + TLS_DIGEST_LEN + 1;
    handshake[sid_start..sid_start + session_id_len].copy_from_slice(session_id);
    handshake[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN].fill(0);

    let mut digest = sha256_hmac(secret, &handshake);
    let ts = timestamp.to_le_bytes();
    for idx in 0..4 {
        digest[28 + idx] ^= ts[idx];
    }

    handshake[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN].copy_from_slice(&digest);
    handshake
}

fn make_valid_client_hello_record(host: &str, alpn_protocols: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&TLS_VERSION);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
    body.push(0);

    let mut ext_blob = Vec::new();

    let host_bytes = host.as_bytes();
    let mut sni_payload = Vec::new();
    sni_payload.extend_from_slice(&((host_bytes.len() + 3) as u16).to_be_bytes());
    sni_payload.push(0);
    sni_payload.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    sni_payload.extend_from_slice(host_bytes);
    ext_blob.extend_from_slice(&0x0000u16.to_be_bytes());
    ext_blob.extend_from_slice(&(sni_payload.len() as u16).to_be_bytes());
    ext_blob.extend_from_slice(&sni_payload);

    if !alpn_protocols.is_empty() {
        let mut alpn_list = Vec::new();
        for proto in alpn_protocols {
            alpn_list.push(proto.len() as u8);
            alpn_list.extend_from_slice(proto);
        }
        let mut alpn_data = Vec::new();
        alpn_data.extend_from_slice(&(alpn_list.len() as u16).to_be_bytes());
        alpn_data.extend_from_slice(&alpn_list);

        ext_blob.extend_from_slice(&0x0010u16.to_be_bytes());
        ext_blob.extend_from_slice(&(alpn_data.len() as u16).to_be_bytes());
        ext_blob.extend_from_slice(&alpn_data);
    }

    body.extend_from_slice(&(ext_blob.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_blob);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    let body_len = (body.len() as u32).to_be_bytes();
    handshake.extend_from_slice(&body_len[1..4]);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(TLS_RECORD_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[test]
fn client_hello_fuzz_corpus_never_panics_or_accepts_corruption() {
    let valid = make_valid_client_hello_record("example.com", &[b"h2", b"http/1.1"]);
    assert_eq!(extract_sni_from_client_hello(&valid).as_deref(), Some("example.com"));
    assert_eq!(
        extract_alpn_from_client_hello(&valid),
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    assert!(
        extract_sni_from_client_hello(&make_valid_client_hello_record("127.0.0.1", &[])).is_none(),
        "literal IP hostnames must be rejected"
    );

    let mut corpus = vec![
        Vec::new(),
        vec![0x16, 0x03, 0x03],
        valid[..9].to_vec(),
        valid[..valid.len() - 1].to_vec(),
    ];

    let mut wrong_type = valid.clone();
    wrong_type[0] = 0x15;
    corpus.push(wrong_type);

    let mut wrong_handshake = valid.clone();
    wrong_handshake[5] = 0x02;
    corpus.push(wrong_handshake);

    let mut wrong_length = valid.clone();
    wrong_length[3] ^= 0x7f;
    corpus.push(wrong_length);

    for (idx, input) in corpus.iter().enumerate() {
        assert!(catch_unwind(|| extract_sni_from_client_hello(input)).is_ok());
        assert!(catch_unwind(|| extract_alpn_from_client_hello(input)).is_ok());

        if idx == 0 {
            continue;
        }

        assert!(extract_sni_from_client_hello(input).is_none(), "corpus item {idx} must fail closed for SNI");
        assert!(extract_alpn_from_client_hello(input).is_empty(), "corpus item {idx} must fail closed for ALPN");
    }
}

#[test]
fn tls_handshake_fuzz_corpus_never_panics_and_rejects_digest_mutations() {
    let secret = b"tls_fuzz_security_secret";
    let now: i64 = 1_700_000_000;
    let base = make_valid_tls_handshake_with_session_id(secret, now as u32, &[0x42; 32]);
    let secrets = vec![("fuzz-user".to_string(), secret.to_vec())];

    assert!(validate_tls_handshake_at_time(&base, &secrets, false, now).is_some());

    let mut corpus = Vec::new();

    let mut truncated = base.clone();
    truncated.truncate(TLS_DIGEST_POS + 16);
    corpus.push(truncated);

    let mut digest_flip = base.clone();
    digest_flip[TLS_DIGEST_POS + 7] ^= 0x80;
    corpus.push(digest_flip);

    let mut session_id_len_overflow = base.clone();
    session_id_len_overflow[TLS_DIGEST_POS + TLS_DIGEST_LEN] = 33;
    corpus.push(session_id_len_overflow);

    let mut timestamp_far_past = base.clone();
    timestamp_far_past[TLS_DIGEST_POS + 28..TLS_DIGEST_POS + 32]
        .copy_from_slice(&((now - i64::from(TIME_SKEW_MAX) - 1) as u32).to_le_bytes());
    corpus.push(timestamp_far_past);

    let mut timestamp_far_future = base.clone();
    timestamp_far_future[TLS_DIGEST_POS + 28..TLS_DIGEST_POS + 32]
        .copy_from_slice(&((now - TIME_SKEW_MIN + 1) as u32).to_le_bytes());
    corpus.push(timestamp_far_future);

    let mut seed = 0xA5A5_5A5A_F00D_BAAD_u64;
    for _ in 0..32 {
        let mut mutated = base.clone();
        for _ in 0..2 {
            seed = seed.wrapping_mul(2862933555777941757).wrapping_add(3037000493);
            let idx = TLS_DIGEST_POS + (seed as usize % TLS_DIGEST_LEN);
            mutated[idx] ^= ((seed >> 17) as u8).wrapping_add(1);
        }
        corpus.push(mutated);
    }

    for (idx, handshake) in corpus.iter().enumerate() {
        let result = catch_unwind(|| validate_tls_handshake_at_time(handshake, &secrets, false, now));
        assert!(result.is_ok(), "corpus item {idx} must not panic");
        assert!(result.unwrap().is_none(), "corpus item {idx} must fail closed");
    }
}

#[test]
fn tls_boot_time_acceptance_is_capped_by_replay_window() {
    let secret = b"tls_boot_time_cap_secret";
    let secrets = vec![("boot-user".to_string(), secret.to_vec())];
    let boot_ts = 1u32;
    let handshake = make_valid_tls_handshake_with_session_id(secret, boot_ts, &[0x42; 32]);

    assert!(
        validate_tls_handshake_with_replay_window(&handshake, &secrets, false, 300).is_some(),
        "boot-time timestamp should be accepted while replay window permits it"
    );
    assert!(
        validate_tls_handshake_with_replay_window(&handshake, &secrets, false, 0).is_none(),
        "boot-time timestamp must be rejected when replay window disables the bypass"
    );
}
