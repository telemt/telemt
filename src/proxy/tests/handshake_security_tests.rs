use super::*;
use crate::crypto::{sha256, sha256_hmac};
use dashmap::DashMap;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::sync::Barrier;

fn make_valid_tls_handshake(secret: &[u8], timestamp: u32) -> Vec<u8> {
    let session_id_len: usize = 32;
    let len = tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 + session_id_len;
    let mut handshake = vec![0x42u8; len];

    handshake[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN] = session_id_len as u8;
    handshake[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN].fill(0);

    let computed = sha256_hmac(secret, &handshake);
    let mut digest = computed;
    let ts = timestamp.to_le_bytes();
    for i in 0..4 {
        digest[28 + i] ^= ts[i];
    }

    handshake[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN]
        .copy_from_slice(&digest);
    handshake
}

fn make_valid_tls_client_hello_with_alpn(
    secret: &[u8],
    timestamp: u32,
    alpn_protocols: &[&[u8]],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&TLS_VERSION);
    body.extend_from_slice(&[0u8; 32]);
    body.push(32);
    body.extend_from_slice(&[0x42u8; 32]);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
    body.push(0);

    let mut ext_blob = Vec::new();
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

    record[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN].fill(0);
    let computed = sha256_hmac(secret, &record);
    let mut digest = computed;
    let ts = timestamp.to_le_bytes();
    for i in 0..4 {
        digest[28 + i] ^= ts[i];
    }
    record[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN].copy_from_slice(&digest);

    record
}

fn make_valid_tls_client_hello_with_sni_and_alpn(
    secret: &[u8],
    timestamp: u32,
    sni_host: &str,
    alpn_protocols: &[&[u8]],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&TLS_VERSION);
    body.extend_from_slice(&[0u8; 32]);
    body.push(32);
    body.extend_from_slice(&[0x42u8; 32]);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
    body.push(0);

    let mut ext_blob = Vec::new();

    let host_bytes = sni_host.as_bytes();
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

    record[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN].fill(0);
    let computed = sha256_hmac(secret, &record);
    let mut digest = computed;
    let ts = timestamp.to_le_bytes();
    for i in 0..4 {
        digest[28 + i] ^= ts[i];
    }
    record[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN].copy_from_slice(&digest);

    record
}

fn test_config_with_secret_hex(secret_hex: &str) -> ProxyConfig {
    let mut cfg = ProxyConfig::default();
    cfg.access.users.clear();
    cfg.access
        .users
        .insert("user".to_string(), secret_hex.to_string());
    cfg.access.ignore_time_skew = true;
    cfg
}

fn make_valid_mtproto_handshake(
    secret_hex: &str,
    proto_tag: ProtoTag,
    dc_idx: i16,
) -> [u8; HANDSHAKE_LEN] {
    let secret = hex::decode(secret_hex).expect("secret hex must decode for mtproto test helper");

    let mut handshake = [0x5Au8; HANDSHAKE_LEN];
    for (idx, b) in handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]
        .iter_mut()
        .enumerate()
    {
        *b = (idx as u8).wrapping_add(1);
    }

    let dec_prekey = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
    let dec_iv_bytes = &handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];

    let mut dec_key_input = Vec::with_capacity(PREKEY_LEN + secret.len());
    dec_key_input.extend_from_slice(dec_prekey);
    dec_key_input.extend_from_slice(&secret);
    let dec_key = sha256(&dec_key_input);

    let mut dec_iv_arr = [0u8; IV_LEN];
    dec_iv_arr.copy_from_slice(dec_iv_bytes);
    let dec_iv = u128::from_be_bytes(dec_iv_arr);

    let mut stream = AesCtr::new(&dec_key, dec_iv);
    let keystream = stream.encrypt(&[0u8; HANDSHAKE_LEN]);

    let mut target_plain = [0u8; HANDSHAKE_LEN];
    target_plain[PROTO_TAG_POS..PROTO_TAG_POS + 4].copy_from_slice(&proto_tag.to_bytes());
    target_plain[DC_IDX_POS..DC_IDX_POS + 2].copy_from_slice(&dc_idx.to_le_bytes());

    for idx in PROTO_TAG_POS..HANDSHAKE_LEN {
        handshake[idx] = target_plain[idx] ^ keystream[idx];
    }

    handshake
}

#[test]
fn test_generate_tg_nonce() {
    let client_enc_key = [0x24u8; 32];
    let client_enc_iv = 54321u128;

    let rng = SecureRandom::new();
    let (nonce, _tg_enc_key, _tg_enc_iv, _tg_dec_key, _tg_dec_iv) = generate_tg_nonce(
        ProtoTag::Secure,
        2,
        &client_enc_key,
        client_enc_iv,
        &rng,
        false,
    );

    assert_eq!(nonce.len(), HANDSHAKE_LEN);

    let tag_bytes: [u8; 4] = nonce[PROTO_TAG_POS..PROTO_TAG_POS + 4].try_into().unwrap();
    assert_eq!(ProtoTag::from_bytes(tag_bytes), Some(ProtoTag::Secure));
}

#[test]
fn test_encrypt_tg_nonce() {
    let client_enc_key = [0x24u8; 32];
    let client_enc_iv = 54321u128;

    let rng = SecureRandom::new();
    let (nonce, _, _, _, _) = generate_tg_nonce(
        ProtoTag::Secure,
        2,
        &client_enc_key,
        client_enc_iv,
        &rng,
        false,
    );

    let encrypted = encrypt_tg_nonce(&nonce);

    assert_eq!(encrypted.len(), HANDSHAKE_LEN);
    assert_eq!(&encrypted[..PROTO_TAG_POS], &nonce[..PROTO_TAG_POS]);
    assert_ne!(&encrypted[PROTO_TAG_POS..], &nonce[PROTO_TAG_POS..]);
}

#[test]
fn test_handshake_success_drop_does_not_panic() {
    let success = HandshakeSuccess {
        user: "test".to_string(),
        dc_idx: 2,
        proto_tag: ProtoTag::Secure,
        dec_key: [0xAA; 32],
        dec_iv: 0xBBBBBBBB,
        enc_key: [0xCC; 32],
        enc_iv: 0xDDDDDDDD,
        peer: "198.51.100.10:1234".parse().unwrap(),
        is_tls: true,
    };

    assert_eq!(success.dec_key, [0xAA; 32]);
    assert_eq!(success.enc_key, [0xCC; 32]);

    drop(success);
}

#[test]
fn test_generate_tg_nonce_enc_dec_material_is_consistent() {
    let client_enc_key = [0x34u8; 32];
    let client_enc_iv = 0xffeeddccbbaa00998877665544332211u128;
    let rng = SecureRandom::new();

    let (nonce, tg_enc_key, tg_enc_iv, tg_dec_key, tg_dec_iv) = generate_tg_nonce(
        ProtoTag::Secure,
        7,
        &client_enc_key,
        client_enc_iv,
        &rng,
        false,
    );

    let enc_key_iv = &nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN];
    let dec_key_iv: Vec<u8> = enc_key_iv.iter().rev().copied().collect();

    let mut expected_tg_enc_key = [0u8; 32];
    expected_tg_enc_key.copy_from_slice(&enc_key_iv[..KEY_LEN]);
    let mut expected_tg_enc_iv_arr = [0u8; IV_LEN];
    expected_tg_enc_iv_arr.copy_from_slice(&enc_key_iv[KEY_LEN..]);
    let expected_tg_enc_iv = u128::from_be_bytes(expected_tg_enc_iv_arr);

    let mut expected_tg_dec_key = [0u8; 32];
    expected_tg_dec_key.copy_from_slice(&dec_key_iv[..KEY_LEN]);
    let mut expected_tg_dec_iv_arr = [0u8; IV_LEN];
    expected_tg_dec_iv_arr.copy_from_slice(&dec_key_iv[KEY_LEN..]);
    let expected_tg_dec_iv = u128::from_be_bytes(expected_tg_dec_iv_arr);

    assert_eq!(tg_enc_key, expected_tg_enc_key);
    assert_eq!(tg_enc_iv, expected_tg_enc_iv);
    assert_eq!(tg_dec_key, expected_tg_dec_key);
    assert_eq!(tg_dec_iv, expected_tg_dec_iv);
    assert_eq!(
        i16::from_le_bytes([nonce[DC_IDX_POS], nonce[DC_IDX_POS + 1]]),
        7,
        "Generated nonce must keep target dc index in protocol slot"
    );
}

#[test]
fn test_generate_tg_nonce_fast_mode_embeds_reversed_client_enc_material() {
    let client_enc_key = [0xABu8; 32];
    let client_enc_iv = 0x11223344556677889900aabbccddeeffu128;
    let rng = SecureRandom::new();

    let (nonce, _, _, _, _) = generate_tg_nonce(
        ProtoTag::Secure,
        9,
        &client_enc_key,
        client_enc_iv,
        &rng,
        true,
    );

    let mut expected = Vec::with_capacity(KEY_LEN + IV_LEN);
    expected.extend_from_slice(&client_enc_key);
    expected.extend_from_slice(&client_enc_iv.to_be_bytes());
    expected.reverse();

    assert_eq!(
        &nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN],
        expected.as_slice()
    );
}

#[test]
fn test_encrypt_tg_nonce_with_ciphers_matches_manual_suffix_encryption() {
    let client_enc_key = [0x24u8; 32];
    let client_enc_iv = 54321u128;

    let rng = SecureRandom::new();
    let (nonce, _, _, _, _) = generate_tg_nonce(
        ProtoTag::Secure,
        2,
        &client_enc_key,
        client_enc_iv,
        &rng,
        false,
    );

    let (encrypted, _, _) = encrypt_tg_nonce_with_ciphers(&nonce);

    let enc_key_iv = &nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN];
    let mut expected_enc_key = [0u8; 32];
    expected_enc_key.copy_from_slice(&enc_key_iv[..KEY_LEN]);
    let mut expected_enc_iv_arr = [0u8; IV_LEN];
    expected_enc_iv_arr.copy_from_slice(&enc_key_iv[KEY_LEN..]);
    let expected_enc_iv = u128::from_be_bytes(expected_enc_iv_arr);

    let mut manual_encryptor = AesCtr::new(&expected_enc_key, expected_enc_iv);
    let manual = manual_encryptor.encrypt(&nonce);

    assert_eq!(encrypted.len(), HANDSHAKE_LEN);
    assert_eq!(&encrypted[..PROTO_TAG_POS], &nonce[..PROTO_TAG_POS]);
    assert_eq!(
        &encrypted[PROTO_TAG_POS..],
        &manual[PROTO_TAG_POS..],
        "Encrypted nonce suffix must match AES-CTR output with derived enc key/iv"
    );
}

#[tokio::test]
async fn tls_replay_second_identical_handshake_is_rejected() {
    let secret = [0x11u8; 16];
    let config = test_config_with_secret_hex("11111111111111111111111111111111");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.21:44321".parse().unwrap();
    let handshake = make_valid_tls_handshake(&secret, 0);

    let first = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;
    assert!(matches!(first, HandshakeResult::Success(_)));

    let second = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;
    assert!(matches!(second, HandshakeResult::BadClient { .. }));
}

#[tokio::test]
async fn tls_replay_with_ignore_time_skew_and_small_boot_timestamp_is_still_blocked() {
    let secret = [0x19u8; 16];
    let config = test_config_with_secret_hex("19191919191919191919191919191919");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.121:44321".parse().unwrap();
    let handshake = make_valid_tls_handshake(&secret, 1);

    let first = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;
    assert!(matches!(first, HandshakeResult::Success(_)));

    let replay = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;
    assert!(
        matches!(replay, HandshakeResult::BadClient { .. }),
        "ignore_time_skew must not weaken replay rejection for small boot timestamps"
    );
}

#[tokio::test]
async fn tls_replay_concurrent_identical_handshake_allows_exactly_one_success() {
    let secret = [0x77u8; 16];
    let config = Arc::new(test_config_with_secret_hex(
        "77777777777777777777777777777777",
    ));
    let replay_checker = Arc::new(ReplayChecker::new(4096, Duration::from_secs(60)));
    let rng = Arc::new(SecureRandom::new());
    let handshake = Arc::new(make_valid_tls_handshake(&secret, 0));

    let mut tasks = Vec::new();
    for _ in 0..50 {
        let config = config.clone();
        let replay_checker = replay_checker.clone();
        let rng = rng.clone();
        let handshake = handshake.clone();
        tasks.push(tokio::spawn(async move {
            handle_tls_handshake(
                &handshake,
                tokio::io::empty(),
                tokio::io::sink(),
                "198.51.100.22:45000".parse().unwrap(),
                &config,
                &replay_checker,
                &rng,
                None,
            )
            .await
        }));
    }

    let mut success_count = 0usize;
    for task in tasks {
        let result = task.await.unwrap();
        if matches!(result, HandshakeResult::Success(_)) {
            success_count += 1;
        } else {
            assert!(matches!(result, HandshakeResult::BadClient { .. }));
        }
    }

    assert_eq!(
        success_count, 1,
        "Concurrent replay attempts must allow exactly one successful handshake"
    );
}

#[tokio::test]
async fn tls_replay_matrix_rotating_peers_first_accept_then_rejects() {
    let secret = [0x52u8; 16];
    let config = test_config_with_secret_hex("52525252525252525252525252525252");
    let replay_checker = ReplayChecker::new(4096, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let handshake = make_valid_tls_handshake(&secret, 17);

    let first_peer: SocketAddr = "198.51.100.31:44001".parse().unwrap();
    let first = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        first_peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;
    assert!(matches!(first, HandshakeResult::Success(_)));

    for i in 0..128u16 {
        let peer = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, ((i % 250) + 1) as u8)),
            45000 + i,
        );
        let replay = handle_tls_handshake(
            &handshake,
            tokio::io::empty(),
            tokio::io::sink(),
            peer,
            &config,
            &replay_checker,
            &rng,
            None,
        )
        .await;
        assert!(
            matches!(replay, HandshakeResult::BadClient { .. }),
            "replay digest must be rejected regardless of source peer rotation"
        );
    }
}

#[tokio::test]
async fn adversarial_tls_replay_churn_allows_only_unique_digests() {
    let secret = [0x5Au8; 16];
    let mut config = test_config_with_secret_hex("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
    config.access.ignore_time_skew = true;
    let config = Arc::new(config);
    let replay_checker = Arc::new(ReplayChecker::new(8192, Duration::from_secs(60)));
    let rng = Arc::new(SecureRandom::new());

    let make_tagged_handshake = |timestamp: u32, tag: u8| {
        let session_id_len: usize = 32;
        let len = tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 + session_id_len;
        let mut handshake = vec![tag; len];

        handshake[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN] = session_id_len as u8;
        handshake[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN].fill(0);
        let computed = sha256_hmac(&secret, &handshake);
        let mut digest = computed;
        let ts = timestamp.to_le_bytes();
        for i in 0..4 {
            digest[28 + i] ^= ts[i];
        }

        handshake[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN]
            .copy_from_slice(&digest);
        handshake
    };

    let mut tasks = Vec::new();

    // 128 exact duplicates: only one should pass.
    let duplicated = Arc::new(make_valid_tls_handshake(&secret, 999));
    for i in 0..128u16 {
        let config = Arc::clone(&config);
        let replay_checker = Arc::clone(&replay_checker);
        let rng = Arc::clone(&rng);
        let duplicated = Arc::clone(&duplicated);
        tasks.push(tokio::spawn(async move {
            let peer = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, ((i % 250) + 1) as u8)),
                46000 + i,
            );
            handle_tls_handshake(
                &duplicated,
                tokio::io::empty(),
                tokio::io::sink(),
                peer,
                &config,
                &replay_checker,
                &rng,
                None,
            )
            .await
        }));
    }

    // 128 unique timestamps: all should pass because HMAC digest differs.
    for i in 0..128u16 {
        let config = Arc::clone(&config);
        let replay_checker = Arc::clone(&replay_checker);
        let rng = Arc::clone(&rng);
        let handshake = make_tagged_handshake(10_000 + i as u32, (i as u8).wrapping_add(0x80));
        tasks.push(tokio::spawn(async move {
            let peer = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 18, 0, ((i % 250) + 1) as u8)),
                47000 + i,
            );
            handle_tls_handshake(
                &handshake,
                tokio::io::empty(),
                tokio::io::sink(),
                peer,
                &config,
                &replay_checker,
                &rng,
                None,
            )
            .await
        }));
    }

    let mut duplicate_success = 0usize;
    let mut duplicate_reject = 0usize;
    let mut unique_success = 0usize;
    let mut unique_reject = 0usize;

    for (idx, task) in tasks.into_iter().enumerate() {
        let result = task.await.unwrap();
        let is_duplicate_group = idx < 128;
        match result {
            HandshakeResult::Success(_) => {
                if is_duplicate_group {
                    duplicate_success += 1;
                } else {
                    unique_success += 1;
                }
            }
            HandshakeResult::BadClient { .. } => {
                if is_duplicate_group {
                    duplicate_reject += 1;
                } else {
                    unique_reject += 1;
                }
            }
            HandshakeResult::Error(e) => panic!("unexpected handshake error in churn test: {e}"),
        }
    }

    assert_eq!(
        duplicate_success, 1,
        "duplicate replay group must allow exactly one successful handshake"
    );
    assert_eq!(
        duplicate_reject, 127,
        "duplicate replay group must reject all remaining replays"
    );
    assert_eq!(
        unique_success, 128,
        "unique digest group must fully pass under replay churn"
    );
    assert_eq!(
        unique_reject, 0,
        "unique digest group must not be falsely rejected as replay"
    );
}

#[tokio::test]
async fn invalid_tls_probe_does_not_pollute_replay_cache() {
    let config = test_config_with_secret_hex("11111111111111111111111111111111");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.23:44322".parse().unwrap();

    let mut invalid = vec![0x42u8; tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 + 32];
    invalid[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN] = 32;

    let before = replay_checker.stats();

    let result = handle_tls_handshake(
        &invalid,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;
    let after = replay_checker.stats();

    assert!(matches!(result, HandshakeResult::BadClient { .. }));
    assert_eq!(before.total_additions, after.total_additions);
    assert_eq!(before.total_hits, after.total_hits);
}

#[tokio::test]
async fn empty_decoded_secret_is_rejected() {
    let shared = ProxySharedState::new();
    clear_warned_secrets_for_testing_in_shared(shared.as_ref());
    let config = test_config_with_secret_hex("");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.24:44323".parse().unwrap();
    let handshake = make_valid_tls_handshake(&[], 0);

    let result = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(result, HandshakeResult::BadClient { .. }));
}

#[tokio::test]
async fn wrong_length_decoded_secret_is_rejected() {
    let shared = ProxySharedState::new();
    clear_warned_secrets_for_testing_in_shared(shared.as_ref());
    let config = test_config_with_secret_hex("aa");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.25:44324".parse().unwrap();
    let handshake = make_valid_tls_handshake(&[0xaau8], 0);

    let result = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(result, HandshakeResult::BadClient { .. }));
}

#[tokio::test]
async fn invalid_mtproto_probe_does_not_pollute_replay_cache() {
    let config = test_config_with_secret_hex("11111111111111111111111111111111");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let peer: SocketAddr = "198.51.100.26:44325".parse().unwrap();
    let handshake = [0u8; HANDSHAKE_LEN];

    let before = replay_checker.stats();
    let result = handle_mtproto_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        false,
        None,
    )
    .await;
    let after = replay_checker.stats();

    assert!(matches!(result, HandshakeResult::BadClient { .. }));
    assert_eq!(before.total_additions, after.total_additions);
    assert_eq!(before.total_hits, after.total_hits);
}

#[tokio::test]
async fn mixed_secret_lengths_keep_valid_user_authenticating() {
    let shared = ProxySharedState::new();
    let shared = ProxySharedState::new();
    clear_warned_secrets_for_testing_in_shared(shared.as_ref());
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());
    let good_secret = [0x22u8; 16];
    let mut config = ProxyConfig::default();
    config.access.users.clear();
    config
        .access
        .users
        .insert("broken_user".to_string(), "aa".to_string());
    config.access.users.insert(
        "valid_user".to_string(),
        "22222222222222222222222222222222".to_string(),
    );
    config.access.ignore_time_skew = true;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.27:44326".parse().unwrap();
    let handshake = make_valid_tls_handshake(&good_secret, 0);

    let result = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(result, HandshakeResult::Success(_)));
}

#[tokio::test]
async fn tls_sni_preferred_user_hint_selects_matching_identity_first() {
    let shared_secret = [0x3Bu8; 16];
    let mut config = ProxyConfig::default();
    config.access.users.clear();
    config.access.users.insert(
        "user-a".to_string(),
        "3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b".to_string(),
    );
    config.access.users.insert(
        "user-b".to_string(),
        "3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b".to_string(),
    );
    config.access.ignore_time_skew = true;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.188:44326".parse().unwrap();
    let handshake =
        make_valid_tls_client_hello_with_sni_and_alpn(&shared_secret, 0, "user-b", &[b"h2"]);

    let result = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    match result {
        HandshakeResult::Success((_, _, user)) => {
            assert_eq!(
                user, "user-b",
                "TLS SNI preferred-user hint must select matching identity before equivalent decoys"
            );
        }
        _ => panic!("TLS handshake must succeed for valid shared-secret SNI case"),
    }
}

#[test]
fn stress_decode_user_secrets_keeps_preferred_user_first_in_large_set() {
    let shared = ProxySharedState::new();
    let mut config = ProxyConfig::default();
    config.access.users.clear();

    let preferred_user = "target-user.example".to_string();
    let secret_hex = "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f".to_string();

    for i in 0..4096usize {
        config
            .access
            .users
            .insert(format!("decoy-{i:04}.example"), secret_hex.clone());
    }
    config
        .access
        .users
        .insert(preferred_user.clone(), secret_hex.clone());

    let decoded = decode_user_secrets_in(shared.as_ref(), &config, Some(preferred_user.as_str()));
    assert_eq!(
        decoded.len(),
        config.access.users.len(),
        "decoded secret set must preserve full user cardinality under stress"
    );
    assert_eq!(
        decoded.first().map(|(name, _)| name.as_str()),
        Some(preferred_user.as_str()),
        "preferred user must be first even under adversarial large user sets"
    );
    assert_eq!(
        decoded
            .iter()
            .filter(|(name, _)| name == &preferred_user)
            .count(),
        1,
        "preferred user must appear exactly once in decoded list"
    );
}

#[tokio::test]
async fn stress_tls_sni_preferred_user_hint_scales_to_large_user_set() {
    let shared_secret = [0x7Fu8; 16];
    let mut config = ProxyConfig::default();
    config.access.users.clear();
    config.access.ignore_time_skew = true;

    let preferred_user = "target-user.example".to_string();
    let secret_hex = "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f".to_string();

    for i in 0..4096usize {
        config
            .access
            .users
            .insert(format!("decoy-{i:04}.example"), secret_hex.clone());
    }
    config
        .access
        .users
        .insert(preferred_user.clone(), secret_hex);

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.189:44326".parse().unwrap();
    let handshake = make_valid_tls_client_hello_with_sni_and_alpn(
        &shared_secret,
        0,
        preferred_user.as_str(),
        &[b"h2"],
    );

    let result = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    match result {
        HandshakeResult::Success((_, _, user)) => {
            assert_eq!(
                user, preferred_user,
                "SNI preferred-user hint must remain stable under large user cardinality"
            );
        }
        _ => panic!("TLS handshake must succeed for valid preferred-user stress case"),
    }
}

#[tokio::test]
async fn tls_unknown_sni_drop_policy_returns_hard_error() {
    let secret = [0x48u8; 16];
    let mut config = test_config_with_secret_hex("48484848484848484848484848484848");
    config.censorship.unknown_sni_action = UnknownSniAction::Drop;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.190:44326".parse().unwrap();
    let handshake =
        make_valid_tls_client_hello_with_sni_and_alpn(&secret, 0, "unknown.example", &[b"h2"]);

    let result = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(
        result,
        HandshakeResult::Error(ProxyError::UnknownTlsSni)
    ));
}

#[tokio::test]
async fn tls_unknown_sni_mask_policy_falls_back_to_bad_client() {
    let secret = [0x49u8; 16];
    let mut config = test_config_with_secret_hex("49494949494949494949494949494949");
    config.censorship.unknown_sni_action = UnknownSniAction::Mask;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.191:44326".parse().unwrap();
    let handshake =
        make_valid_tls_client_hello_with_sni_and_alpn(&secret, 0, "unknown.example", &[b"h2"]);

    let result = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(result, HandshakeResult::BadClient { .. }));
}

#[tokio::test]
async fn tls_unknown_sni_reject_handshake_policy_emits_unrecognized_name_alert() {
    use tokio::io::{AsyncReadExt, duplex};

    let secret = [0x4Au8; 16];
    let mut config = test_config_with_secret_hex("4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a");
    config.censorship.unknown_sni_action = UnknownSniAction::RejectHandshake;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.192:44326".parse().unwrap();
    let handshake =
        make_valid_tls_client_hello_with_sni_and_alpn(&secret, 0, "unknown.example", &[b"h2"]);

    // Wire up a duplex so we can inspect what the server writes towards the
    // client. We own the "peer side" half to read from it.
    let (server_side, mut peer_side) = duplex(1024);
    let (server_read, server_write) = tokio::io::split(server_side);

    let result = handle_tls_handshake(
        &handshake,
        server_read,
        server_write,
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(
        result,
        HandshakeResult::Error(ProxyError::UnknownTlsSni)
    ));

    // Drain what the server wrote. We expect exactly one TLS alert record:
    //   0x15 0x03 0x03 0x00 0x02 0x02 0x70
    // (ContentType.alert, TLS 1.2, length=2, fatal, unrecognized_name)
    drop(result); // drops the server-side writer so peer_side sees EOF
    let mut buf = Vec::new();
    peer_side.read_to_end(&mut buf).await.unwrap();
    assert_eq!(
        buf,
        [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70],
        "reject_handshake must emit a fatal unrecognized_name TLS alert"
    );
}

#[tokio::test]
async fn tls_unknown_sni_accept_policy_continues_auth_path() {
    let secret = [0x4Bu8; 16];
    let mut config = test_config_with_secret_hex("4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b");
    config.censorship.unknown_sni_action = UnknownSniAction::Accept;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.210:44326".parse().unwrap();
    let handshake =
        make_valid_tls_client_hello_with_sni_and_alpn(&secret, 0, "unknown.example", &[b"h2"]);

    let result = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(result, HandshakeResult::Success(_)));
}

#[tokio::test]
async fn tls_unknown_sni_accept_policy_still_requires_valid_secret() {
    let mut config = test_config_with_secret_hex("4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c");
    config.censorship.unknown_sni_action = UnknownSniAction::Accept;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.211:44326".parse().unwrap();
    let attacker_secret = [0x4Du8; 16];
    let handshake = make_valid_tls_client_hello_with_sni_and_alpn(
        &attacker_secret,
        0,
        "unknown.example",
        &[b"h2"],
    );

    let result = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(result, HandshakeResult::BadClient { .. }));
}

#[tokio::test]
async fn tls_missing_sni_keeps_legacy_auth_path() {
    let secret = [0x4Au8; 16];
    let mut config = test_config_with_secret_hex("4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a");
    config.censorship.unknown_sni_action = UnknownSniAction::Drop;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.192:44326".parse().unwrap();
    let handshake = make_valid_tls_handshake(&secret, 0);

    let result = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(result, HandshakeResult::Success(_)));
}

#[tokio::test]
async fn tls_runtime_snapshot_updates_sticky_and_recent_hints() {
    let secret = [0x5Au8; 16];
    let mut config = test_config_with_secret_hex("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
    config.rebuild_runtime_user_auth().unwrap();

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let shared = ProxySharedState::new();
    let peer: SocketAddr = "198.51.100.212:44326".parse().unwrap();
    let handshake = make_valid_tls_client_hello_with_sni_and_alpn(&secret, 0, "user", &[b"h2"]);

    let result = handle_tls_handshake_with_shared(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
        shared.as_ref(),
    )
    .await;

    assert!(matches!(result, HandshakeResult::Success(_)));
    assert_eq!(
        shared
            .handshake
            .sticky_user_by_ip
            .get(&peer.ip())
            .map(|entry| *entry),
        Some(0),
        "successful runtime-snapshot auth must seed sticky ip cache"
    );
    assert_eq!(
        shared.handshake.sticky_user_by_ip_prefix.len(),
        1,
        "successful runtime-snapshot auth must seed sticky prefix cache"
    );
    assert!(
        shared
            .handshake
            .auth_expensive_checks_total
            .load(Ordering::Relaxed)
            >= 1,
        "runtime-snapshot path must account expensive candidate checks"
    );
}

#[tokio::test]
async fn tls_overload_budget_limits_candidate_scan_depth() {
    let mut config = ProxyConfig::default();
    config.access.users.clear();
    config.access.ignore_time_skew = true;
    for idx in 0..32u8 {
        config.access.users.insert(
            format!("user-{idx}"),
            format!("{:032x}", u128::from(idx) + 1),
        );
    }
    config.rebuild_runtime_user_auth().unwrap();

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let shared = ProxySharedState::new();
    let now = Instant::now();
    {
        let mut saturation = shared.handshake.auth_probe_saturation.lock().unwrap();
        *saturation = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_millis(200),
            last_seen: now,
        });
    }

    let peer: SocketAddr = "198.51.100.213:44326".parse().unwrap();
    let attacker_secret = [0xEFu8; 16];
    let handshake = make_valid_tls_handshake(&attacker_secret, 0);

    let result = handle_tls_handshake_with_shared(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
        shared.as_ref(),
    )
    .await;

    assert!(matches!(result, HandshakeResult::BadClient { .. }));
    assert_eq!(
        shared
            .handshake
            .auth_budget_exhausted_total
            .load(Ordering::Relaxed),
        1,
        "overload mode must account budget exhaustion when scan is capped"
    );
    assert_eq!(
        shared
            .handshake
            .auth_expensive_checks_total
            .load(Ordering::Relaxed),
        OVERLOAD_CANDIDATE_BUDGET_UNHINTED as u64,
        "overload scan depth must stay within capped candidate budget"
    );
}

#[tokio::test]
async fn tls_expensive_invalid_scan_activates_saturation_budget() {
    let mut config = ProxyConfig::default();
    config.access.users.clear();
    config.access.ignore_time_skew = true;
    for idx in 0..80u8 {
        config.access.users.insert(
            format!("user-{idx}"),
            format!("{:032x}", u128::from(idx) + 1),
        );
    }
    config.rebuild_runtime_user_auth().unwrap();

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let shared = ProxySharedState::new();
    let attacker_secret = [0xEFu8; 16];
    let handshake = make_valid_tls_handshake(&attacker_secret, 0);

    let first_peer: SocketAddr = "198.51.100.214:44326".parse().unwrap();
    let first = handle_tls_handshake_with_shared(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        first_peer,
        &config,
        &replay_checker,
        &rng,
        None,
        shared.as_ref(),
    )
    .await;

    assert!(matches!(first, HandshakeResult::BadClient { .. }));
    assert!(
        auth_probe_saturation_state_for_testing_in_shared(shared.as_ref())
            .lock()
            .unwrap()
            .is_some(),
        "expensive invalid scan must activate global saturation"
    );
    assert_eq!(
        shared
            .handshake
            .auth_expensive_checks_total
            .load(Ordering::Relaxed),
        80,
        "first invalid probe preserves full first-hit compatibility before enabling saturation"
    );

    {
        let mut saturation = auth_probe_saturation_state_for_testing_in_shared(shared.as_ref())
            .lock()
            .unwrap();
        let state = saturation.as_mut().expect("saturation must be present");
        state.blocked_until = Instant::now() + Duration::from_millis(200);
    }

    let second_peer: SocketAddr = "198.51.100.215:44326".parse().unwrap();
    let second = handle_tls_handshake_with_shared(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        second_peer,
        &config,
        &replay_checker,
        &rng,
        None,
        shared.as_ref(),
    )
    .await;

    assert!(matches!(second, HandshakeResult::BadClient { .. }));
    assert_eq!(
        shared
            .handshake
            .auth_budget_exhausted_total
            .load(Ordering::Relaxed),
        1,
        "second invalid probe must be capped by overload budget"
    );
    assert_eq!(
        shared
            .handshake
            .auth_expensive_checks_total
            .load(Ordering::Relaxed),
        80 + OVERLOAD_CANDIDATE_BUDGET_UNHINTED as u64,
        "saturation budget must bound follow-up invalid scans"
    );
}

#[tokio::test]
async fn mtproto_runtime_snapshot_prefers_preferred_user_hint() {
    let mut config = ProxyConfig::default();
    config.general.modes.secure = true;
    config.access.users.clear();
    config.access.ignore_time_skew = true;
    config.access.users.insert(
        "alpha".to_string(),
        "11111111111111111111111111111111".to_string(),
    );
    config.access.users.insert(
        "beta".to_string(),
        "22222222222222222222222222222222".to_string(),
    );
    config.rebuild_runtime_user_auth().unwrap();

    let handshake =
        make_valid_mtproto_handshake("22222222222222222222222222222222", ProtoTag::Secure, 2);
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let peer: SocketAddr = "198.51.100.214:44326".parse().unwrap();
    let shared = ProxySharedState::new();

    let result = handle_mtproto_handshake_with_shared(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        false,
        Some("beta"),
        shared.as_ref(),
    )
    .await;

    match result {
        HandshakeResult::Success((_, _, success)) => {
            assert_eq!(success.user, "beta");
        }
        _ => panic!("mtproto runtime snapshot auth must succeed for preferred user"),
    }

    assert_eq!(
        shared
            .handshake
            .auth_expensive_checks_total
            .load(Ordering::Relaxed),
        1,
        "preferred user hint must produce single-candidate success in snapshot path"
    );
}

#[tokio::test]
async fn alpn_enforce_rejects_unsupported_client_alpn() {
    let secret = [0x33u8; 16];
    let mut config = test_config_with_secret_hex("33333333333333333333333333333333");
    config.censorship.alpn_enforce = true;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.28:44327".parse().unwrap();
    let handshake = make_valid_tls_client_hello_with_alpn(&secret, 0, &[b"h3"]);

    let result = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(result, HandshakeResult::BadClient { .. }));
}

#[tokio::test]
async fn alpn_enforce_accepts_h2() {
    let secret = [0x44u8; 16];
    let mut config = test_config_with_secret_hex("44444444444444444444444444444444");
    config.censorship.alpn_enforce = true;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.29:44328".parse().unwrap();
    let handshake = make_valid_tls_client_hello_with_alpn(&secret, 0, &[b"h2", b"h3"]);

    let result = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(result, HandshakeResult::Success(_)));
}

#[tokio::test]
async fn malformed_tls_classes_complete_within_bounded_time() {
    let secret = [0x55u8; 16];
    let mut config = test_config_with_secret_hex("55555555555555555555555555555555");
    config.censorship.alpn_enforce = true;

    let replay_checker = ReplayChecker::new(512, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.30:44329".parse().unwrap();

    let too_short = vec![0x16, 0x03, 0x01];

    let mut bad_hmac = make_valid_tls_handshake(&secret, 0);
    bad_hmac[tls::TLS_DIGEST_POS] ^= 0x01;

    let alpn_mismatch = make_valid_tls_client_hello_with_alpn(&secret, 0, &[b"h3"]);

    for probe in [too_short, bad_hmac, alpn_mismatch] {
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            handle_tls_handshake(
                &probe,
                tokio::io::empty(),
                tokio::io::sink(),
                peer,
                &config,
                &replay_checker,
                &rng,
                None,
            ),
        )
        .await
        .expect("Malformed TLS classes must be rejected within bounded time");

        assert!(matches!(result, HandshakeResult::BadClient { .. }));
    }
}

#[tokio::test]
async fn tls_invalid_hmac_respects_configured_anti_fingerprint_delay() {
    let secret = [0x5Au8; 16];
    let mut config = test_config_with_secret_hex("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
    config.censorship.server_hello_delay_min_ms = 20;
    config.censorship.server_hello_delay_max_ms = 20;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.32:44331".parse().unwrap();
    let mut bad_hmac = make_valid_tls_handshake(&secret, 0);
    bad_hmac[tls::TLS_DIGEST_POS] ^= 0x01;

    let started = Instant::now();
    let result = handle_tls_handshake(
        &bad_hmac,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(result, HandshakeResult::BadClient { .. }));
    assert!(
        started.elapsed() >= Duration::from_millis(18),
        "configured anti-fingerprint delay must apply to invalid TLS handshakes"
    );
}

#[tokio::test]
async fn tls_alpn_mismatch_respects_configured_anti_fingerprint_delay() {
    let secret = [0x6Bu8; 16];
    let mut config = test_config_with_secret_hex("6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b");
    config.censorship.alpn_enforce = true;
    config.censorship.server_hello_delay_min_ms = 20;
    config.censorship.server_hello_delay_max_ms = 20;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.33:44332".parse().unwrap();
    let handshake = make_valid_tls_client_hello_with_alpn(&secret, 0, &[b"h3"]);

    let started = Instant::now();
    let result = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(result, HandshakeResult::BadClient { .. }));
    assert!(
        started.elapsed() >= Duration::from_millis(18),
        "configured anti-fingerprint delay must apply to ALPN-mismatch rejects"
    );
}

#[tokio::test]
#[ignore = "timing-sensitive; run manually on low-jitter hosts"]
async fn malformed_tls_classes_share_close_latency_buckets() {
    const ITER: usize = 24;
    const BUCKET_MS: u128 = 10;

    let secret = [0x99u8; 16];
    let mut config = test_config_with_secret_hex("99999999999999999999999999999999");
    config.censorship.alpn_enforce = true;

    let replay_checker = ReplayChecker::new(4096, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.31:44330".parse().unwrap();

    let too_short = vec![0x16, 0x03, 0x01];

    let mut bad_hmac = make_valid_tls_handshake(&secret, 0);
    bad_hmac[tls::TLS_DIGEST_POS + 1] ^= 0x01;

    let alpn_mismatch = make_valid_tls_client_hello_with_alpn(&secret, 0, &[b"h3"]);

    let mut class_means_ms = Vec::new();
    for probe in [too_short, bad_hmac, alpn_mismatch] {
        let mut sum_micros: u128 = 0;
        for _ in 0..ITER {
            let started = Instant::now();
            let result = handle_tls_handshake(
                &probe,
                tokio::io::empty(),
                tokio::io::sink(),
                peer,
                &config,
                &replay_checker,
                &rng,
                None,
            )
            .await;
            let elapsed = started.elapsed();
            assert!(matches!(result, HandshakeResult::BadClient { .. }));
            sum_micros += elapsed.as_micros();
        }

        class_means_ms.push(sum_micros / ITER as u128 / 1_000);
    }

    let min_bucket = class_means_ms
        .iter()
        .map(|ms| ms / BUCKET_MS)
        .min()
        .unwrap();
    let max_bucket = class_means_ms
        .iter()
        .map(|ms| ms / BUCKET_MS)
        .max()
        .unwrap();

    assert!(
        max_bucket <= min_bucket + 1,
        "Malformed TLS classes diverged across latency buckets: means_ms={:?}",
        class_means_ms
    );
}

#[tokio::test]
#[ignore = "timing matrix; run manually with --ignored --nocapture"]
async fn timing_matrix_tls_classes_under_fixed_delay_budget() {
    const ITER: usize = 48;
    const BUCKET_MS: u128 = 10;

    let shared = ProxySharedState::new();
    let secret = [0x77u8; 16];
    let mut config = test_config_with_secret_hex("77777777777777777777777777777777");
    config.censorship.alpn_enforce = true;
    config.censorship.server_hello_delay_min_ms = 20;
    config.censorship.server_hello_delay_max_ms = 20;

    let rng = SecureRandom::new();
    let base_ip = std::net::Ipv4Addr::new(198, 51, 100, 34);

    let too_short = vec![0x16, 0x03, 0x01];
    let mut bad_hmac = make_valid_tls_handshake(&secret, 0);
    bad_hmac[tls::TLS_DIGEST_POS + 1] ^= 0x01;
    let alpn_mismatch = make_valid_tls_client_hello_with_alpn(&secret, 0, &[b"h3"]);
    let valid_h2 = make_valid_tls_client_hello_with_alpn(&secret, 0, &[b"h2"]);

    let classes = vec![
        ("too_short", too_short),
        ("bad_hmac", bad_hmac),
        ("alpn_mismatch", alpn_mismatch),
        ("valid_h2", valid_h2),
    ];

    for (class, probe) in classes {
        let mut samples_ms = Vec::with_capacity(ITER);
        for idx in 0..ITER {
            clear_auth_probe_state_for_testing_in_shared(shared.as_ref());
            let replay_checker = ReplayChecker::new(4096, Duration::from_secs(60));
            let peer: SocketAddr = SocketAddr::from((base_ip, 44_000 + idx as u16));
            let started = Instant::now();
            let result = handle_tls_handshake(
                &probe,
                tokio::io::empty(),
                tokio::io::sink(),
                peer,
                &config,
                &replay_checker,
                &rng,
                None,
            )
            .await;
            let elapsed = started.elapsed();
            samples_ms.push(elapsed.as_millis());

            if class == "valid_h2" {
                assert!(matches!(result, HandshakeResult::Success(_)));
            } else {
                assert!(matches!(result, HandshakeResult::BadClient { .. }));
            }
        }

        samples_ms.sort_unstable();
        let sum: u128 = samples_ms.iter().copied().sum();
        let mean = sum as f64 / samples_ms.len() as f64;
        let min = samples_ms[0];
        let p95_idx = ((samples_ms.len() as f64) * 0.95).floor() as usize;
        let p95 = samples_ms[p95_idx.min(samples_ms.len() - 1)];
        let max = samples_ms[samples_ms.len() - 1];

        println!(
            "TIMING_MATRIX tls class={} mean_ms={:.2} min_ms={} p95_ms={} max_ms={} bucket_mean={}",
            class,
            mean,
            min,
            p95,
            max,
            (mean as u128) / BUCKET_MS
        );
    }
}

#[test]
fn secure_tag_requires_tls_mode_on_tls_transport() {
    let mut config = ProxyConfig::default();
    config.general.modes.classic = false;
    config.general.modes.secure = true;
    config.general.modes.tls = false;

    assert!(
        !mode_enabled_for_proto(&config, ProtoTag::Secure, true),
        "Secure tag over TLS must be rejected when tls mode is disabled"
    );

    config.general.modes.tls = true;
    assert!(
        mode_enabled_for_proto(&config, ProtoTag::Secure, true),
        "Secure tag over TLS must be accepted when tls mode is enabled"
    );
}

#[test]
fn secure_tag_requires_secure_mode_on_direct_transport() {
    let mut config = ProxyConfig::default();
    config.general.modes.classic = false;
    config.general.modes.secure = false;
    config.general.modes.tls = true;

    assert!(
        !mode_enabled_for_proto(&config, ProtoTag::Secure, false),
        "Secure tag without TLS must be rejected when secure mode is disabled"
    );

    config.general.modes.secure = true;
    assert!(
        mode_enabled_for_proto(&config, ProtoTag::Secure, false),
        "Secure tag without TLS must be accepted when secure mode is enabled"
    );
}

#[test]
fn mode_policy_matrix_is_stable_for_all_tag_transport_mode_combinations() {
    let tags = [ProtoTag::Secure, ProtoTag::Intermediate, ProtoTag::Abridged];

    for classic in [false, true] {
        for secure in [false, true] {
            for tls in [false, true] {
                let mut config = ProxyConfig::default();
                config.general.modes.classic = classic;
                config.general.modes.secure = secure;
                config.general.modes.tls = tls;

                for is_tls in [false, true] {
                    for tag in tags {
                        let expected = match (tag, is_tls) {
                            (ProtoTag::Secure, true) => tls,
                            (ProtoTag::Secure, false) => secure,
                            (ProtoTag::Intermediate | ProtoTag::Abridged, _) => classic,
                        };

                        assert_eq!(
                            mode_enabled_for_proto(&config, tag, is_tls),
                            expected,
                            "mode policy drifted for tag={:?}, transport_tls={}, modes=(classic={}, secure={}, tls={})",
                            tag,
                            is_tls,
                            classic,
                            secure,
                            tls
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn invalid_secret_warning_keys_do_not_collide_on_colon_boundaries() {
    let shared = ProxySharedState::new();
    clear_warned_secrets_for_testing_in_shared(shared.as_ref());

    warn_invalid_secret_once_in(shared.as_ref(), "a:b", "c", ACCESS_SECRET_BYTES, Some(1));
    warn_invalid_secret_once_in(shared.as_ref(), "a", "b:c", ACCESS_SECRET_BYTES, Some(2));

    let warned = warned_secrets_for_testing_in_shared(shared.as_ref());
    let guard = warned.lock().expect("warned set lock must be available");
    assert_eq!(
        guard.len(),
        2,
        "(name, reason) pairs that stringify to the same colon-joined key must remain distinct"
    );
}

#[test]
fn invalid_secret_warning_cache_is_bounded() {
    let shared = ProxySharedState::new();
    clear_warned_secrets_for_testing_in_shared(shared.as_ref());

    for idx in 0..(WARNED_SECRET_MAX_ENTRIES + 32) {
        let user = format!("warned_user_{idx}");
        warn_invalid_secret_once_in(
            shared.as_ref(),
            &user,
            "invalid_length",
            ACCESS_SECRET_BYTES,
            Some(idx),
        );
    }

    let warned = warned_secrets_for_testing_in_shared(shared.as_ref());
    let guard = warned.lock().expect("warned set lock must be available");
    assert_eq!(
        guard.len(),
        WARNED_SECRET_MAX_ENTRIES,
        "invalid-secret warning cache must remain bounded"
    );
}

#[tokio::test]
async fn repeated_invalid_tls_probes_trigger_pre_auth_throttle() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let config = test_config_with_secret_hex("11111111111111111111111111111111");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.61:44361".parse().unwrap();

    let mut invalid = vec![0x42u8; tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 + 32];
    invalid[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN] = 32;

    for _ in 0..AUTH_PROBE_BACKOFF_START_FAILS {
        let result = handle_tls_handshake_with_shared(
            &invalid,
            tokio::io::empty(),
            tokio::io::sink(),
            peer,
            &config,
            &replay_checker,
            &rng,
            None,
            shared.as_ref(),
        )
        .await;
        assert!(matches!(result, HandshakeResult::BadClient { .. }));
    }

    assert!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip())
            .is_some_and(|streak| streak >= AUTH_PROBE_BACKOFF_START_FAILS),
        "invalid probe burst must grow pre-auth failure streak to backoff threshold"
    );
}

#[tokio::test]
async fn successful_tls_handshake_clears_pre_auth_failure_streak() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let secret = [0x23u8; 16];
    let config = test_config_with_secret_hex("23232323232323232323232323232323");
    let replay_checker = ReplayChecker::new(256, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.62:44362".parse().unwrap();

    let mut invalid = vec![0x42u8; tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 + 32];
    invalid[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN] = 32;

    for expected in 1..AUTH_PROBE_BACKOFF_START_FAILS {
        let result = handle_tls_handshake_with_shared(
            &invalid,
            tokio::io::empty(),
            tokio::io::sink(),
            peer,
            &config,
            &replay_checker,
            &rng,
            None,
            shared.as_ref(),
        )
        .await;
        assert!(matches!(result, HandshakeResult::BadClient { .. }));
        assert_eq!(
            auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip()),
            Some(expected),
            "failure streak must grow before a successful authentication"
        );
    }

    let valid = make_valid_tls_handshake(&secret, 0);
    let success = handle_tls_handshake_with_shared(
        &valid,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
        shared.as_ref(),
    )
    .await;

    assert!(matches!(success, HandshakeResult::Success(_)));
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip()),
        None,
        "successful authentication must clear accumulated pre-auth failures"
    );
}

#[test]
fn auth_probe_capacity_prunes_stale_entries_for_new_ips() {
    let shared = ProxySharedState::new();
    let state = DashMap::new();
    let now = Instant::now();
    let stale_seen = now - Duration::from_secs(AUTH_PROBE_TRACK_RETENTION_SECS + 1);

    for idx in 0..AUTH_PROBE_TRACK_MAX_ENTRIES {
        let ip = IpAddr::V4(Ipv4Addr::new(
            10,
            1,
            ((idx >> 8) & 0xff) as u8,
            (idx & 0xff) as u8,
        ));
        state.insert(
            ip,
            AuthProbeState {
                fail_streak: 1,
                blocked_until: now,
                last_seen: stale_seen,
            },
        );
    }

    let newcomer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200));
    auth_probe_record_failure_with_state_in(shared.as_ref(), &state, newcomer, now);

    assert_eq!(
        state.get(&newcomer).map(|entry| entry.fail_streak),
        Some(1),
        "stale-entry pruning must admit and track a new probe source"
    );
    assert!(
        state.len() <= AUTH_PROBE_TRACK_MAX_ENTRIES,
        "auth probe map must remain bounded after stale pruning"
    );
}

#[test]
fn auth_probe_capacity_fresh_full_map_still_tracks_newcomer_with_bounded_eviction() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let state = DashMap::new();
    let now = Instant::now();

    for idx in 0..AUTH_PROBE_TRACK_MAX_ENTRIES {
        let ip = IpAddr::V4(Ipv4Addr::new(
            172,
            16,
            ((idx >> 8) & 0xff) as u8,
            (idx & 0xff) as u8,
        ));
        state.insert(
            ip,
            AuthProbeState {
                fail_streak: 1,
                blocked_until: now,
                last_seen: now + Duration::from_millis(idx as u64 + 1),
            },
        );
    }

    let oldest = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0));
    state.insert(
        oldest,
        AuthProbeState {
            fail_streak: 1,
            blocked_until: now,
            last_seen: now - Duration::from_secs(5),
        },
    );

    let newcomer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 55));
    auth_probe_record_failure_with_state_in(shared.as_ref(), &state, newcomer, now);

    assert!(
        state.get(&newcomer).is_some(),
        "fresh-at-cap auth probe map must still track a new source after bounded eviction"
    );
    assert!(
        state.get(&oldest).is_none(),
        "capacity eviction must remove the oldest tracked source first"
    );
    assert_eq!(
        state.len(),
        AUTH_PROBE_TRACK_MAX_ENTRIES,
        "auth probe map must stay at configured cap after bounded eviction"
    );
    assert!(
        auth_probe_saturation_is_throttled_at_for_testing_in_shared(shared.as_ref(), now),
        "capacity pressure should still activate coarse global pre-auth throttling"
    );
}

#[test]
fn unknown_sni_warn_cooldown_first_event_is_warn_and_repeated_events_are_info_until_window_expires()
{
    let shared = ProxySharedState::new();
    clear_unknown_sni_warn_state_for_testing_in_shared(shared.as_ref());

    let now = Instant::now();

    assert!(
        should_emit_unknown_sni_warn_for_testing_in_shared(shared.as_ref(), now),
        "first unknown SNI event must be eligible for WARN emission"
    );
    assert!(
        !should_emit_unknown_sni_warn_for_testing_in_shared(
            shared.as_ref(),
            now + Duration::from_secs(1)
        ),
        "events inside cooldown window must be demoted from WARN to INFO"
    );
    assert!(
        should_emit_unknown_sni_warn_for_testing_in_shared(
            shared.as_ref(),
            now + Duration::from_secs(UNKNOWN_SNI_WARN_COOLDOWN_SECS)
        ),
        "once cooldown expires, next unknown SNI event must be WARN-eligible again"
    );
}

#[test]
fn stress_auth_probe_full_map_churn_keeps_bound_and_tracks_newcomers() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let state = DashMap::new();
    let base_now = Instant::now();

    for idx in 0..AUTH_PROBE_TRACK_MAX_ENTRIES {
        let ip = IpAddr::V4(Ipv4Addr::new(
            10,
            2,
            ((idx >> 8) & 0xff) as u8,
            (idx & 0xff) as u8,
        ));
        state.insert(
            ip,
            AuthProbeState {
                fail_streak: 1,
                blocked_until: base_now,
                last_seen: base_now + Duration::from_millis((idx % 2048) as u64),
            },
        );
    }

    for step in 0..1024usize {
        let newcomer = IpAddr::V4(Ipv4Addr::new(
            203,
            0,
            ((step >> 8) & 0xff) as u8,
            (step & 0xff) as u8,
        ));
        let now = base_now + Duration::from_millis(10_000 + step as u64);
        auth_probe_record_failure_with_state_in(shared.as_ref(), &state, newcomer, now);

        assert!(
            state.get(&newcomer).is_some(),
            "new source must still be tracked under sustained at-capacity churn"
        );
        assert_eq!(
            state.len(),
            AUTH_PROBE_TRACK_MAX_ENTRIES,
            "auth probe map size must stay hard-bounded at capacity"
        );
    }
}

#[test]
fn auth_probe_over_cap_churn_still_tracks_newcomer_after_round_limit() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let state = DashMap::new();
    let now = Instant::now();
    let initial = AUTH_PROBE_TRACK_MAX_ENTRIES + 32;

    for idx in 0..initial {
        let ip = IpAddr::V4(Ipv4Addr::new(
            10,
            6,
            ((idx >> 8) & 0xff) as u8,
            (idx & 0xff) as u8,
        ));
        state.insert(
            ip,
            AuthProbeState {
                fail_streak: 1,
                blocked_until: now,
                last_seen: now + Duration::from_millis((idx % 1024) as u64),
            },
        );
    }

    let newcomer = IpAddr::V4(Ipv4Addr::new(203, 0, 114, 77));
    auth_probe_record_failure_with_state_in(
        shared.as_ref(),
        &state,
        newcomer,
        now + Duration::from_secs(1),
    );

    assert!(
        state.get(&newcomer).is_some(),
        "new probe source must still be tracked even when map starts above hard cap"
    );
    assert!(
        state.len() < initial + 1,
        "round-limited eviction path must still reclaim capacity under over-cap churn"
    );
}

#[test]
fn auth_probe_capacity_prefers_evicting_low_fail_streak_entries_first() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let state = DashMap::new();
    let now = Instant::now();

    // Fill map at capacity with mostly high fail streak entries.
    for idx in 0..AUTH_PROBE_TRACK_MAX_ENTRIES {
        let ip = IpAddr::V4(Ipv4Addr::new(
            172,
            20,
            ((idx >> 8) & 0xff) as u8,
            (idx & 0xff) as u8,
        ));
        state.insert(
            ip,
            AuthProbeState {
                fail_streak: 9,
                blocked_until: now,
                last_seen: now + Duration::from_millis(idx as u64 + 1),
            },
        );
    }

    let low_fail = IpAddr::V4(Ipv4Addr::new(172, 21, 0, 1));
    state.insert(
        low_fail,
        AuthProbeState {
            fail_streak: 1,
            blocked_until: now,
            last_seen: now + Duration::from_secs(30),
        },
    );

    let high_fail_old = IpAddr::V4(Ipv4Addr::new(172, 21, 0, 2));
    state.insert(
        high_fail_old,
        AuthProbeState {
            fail_streak: 12,
            blocked_until: now,
            last_seen: now - Duration::from_secs(10),
        },
    );

    let newcomer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 201));
    auth_probe_record_failure_with_state_in(shared.as_ref(), &state, newcomer, now);

    assert!(state.get(&newcomer).is_some(), "new source must be tracked");
    assert!(
        state.get(&low_fail).is_none(),
        "least-penalized entry should be evicted before high-penalty entries"
    );
    assert!(
        state.get(&high_fail_old).is_some(),
        "high fail-streak entry should be preserved under mixed-priority eviction"
    );
}

#[test]
fn auth_probe_capacity_tie_breaker_evicts_oldest_with_equal_fail_streak() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let state = DashMap::new();
    let now = Instant::now();

    for idx in 0..(AUTH_PROBE_TRACK_MAX_ENTRIES - 2) {
        let ip = IpAddr::V4(Ipv4Addr::new(
            172,
            30,
            ((idx >> 8) & 0xff) as u8,
            (idx & 0xff) as u8,
        ));
        state.insert(
            ip,
            AuthProbeState {
                fail_streak: 5,
                blocked_until: now,
                last_seen: now + Duration::from_millis(idx as u64 + 1),
            },
        );
    }

    let oldest = IpAddr::V4(Ipv4Addr::new(172, 31, 0, 1));
    let newer = IpAddr::V4(Ipv4Addr::new(172, 31, 0, 2));
    state.insert(
        oldest,
        AuthProbeState {
            fail_streak: 1,
            blocked_until: now,
            last_seen: now - Duration::from_secs(20),
        },
    );
    state.insert(
        newer,
        AuthProbeState {
            fail_streak: 1,
            blocked_until: now,
            last_seen: now - Duration::from_secs(5),
        },
    );

    let newcomer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 202));
    auth_probe_record_failure_with_state_in(shared.as_ref(), &state, newcomer, now);

    assert!(state.get(&newcomer).is_some(), "new source must be tracked");
    assert!(
        state.get(&oldest).is_none(),
        "among equal fail streak candidates, oldest entry must be evicted"
    );
    assert!(
        state.get(&newer).is_some(),
        "newer equal-priority entry should be retained"
    );
}

#[test]
fn stress_auth_probe_capacity_churn_preserves_high_fail_sentinels() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let state = DashMap::new();
    let base_now = Instant::now();

    let sentinel_a = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 250));
    let sentinel_b = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 251));

    state.insert(
        sentinel_a,
        AuthProbeState {
            fail_streak: 20,
            blocked_until: base_now,
            last_seen: base_now - Duration::from_secs(30),
        },
    );
    state.insert(
        sentinel_b,
        AuthProbeState {
            fail_streak: 21,
            blocked_until: base_now,
            last_seen: base_now - Duration::from_secs(31),
        },
    );

    for idx in 0..(AUTH_PROBE_TRACK_MAX_ENTRIES - 2) {
        let ip = IpAddr::V4(Ipv4Addr::new(
            10,
            4,
            ((idx >> 8) & 0xff) as u8,
            (idx & 0xff) as u8,
        ));
        state.insert(
            ip,
            AuthProbeState {
                fail_streak: 1,
                blocked_until: base_now,
                last_seen: base_now + Duration::from_millis((idx % 1024) as u64),
            },
        );
    }

    for step in 0..1024usize {
        let newcomer = IpAddr::V4(Ipv4Addr::new(
            203,
            1,
            ((step >> 8) & 0xff) as u8,
            (step & 0xff) as u8,
        ));
        let now = base_now + Duration::from_millis(10_000 + step as u64);
        auth_probe_record_failure_with_state_in(shared.as_ref(), &state, newcomer, now);

        assert_eq!(
            state.len(),
            AUTH_PROBE_TRACK_MAX_ENTRIES,
            "auth probe map must remain hard-bounded at capacity"
        );
        assert!(
            state.get(&sentinel_a).is_some() && state.get(&sentinel_b).is_some(),
            "high fail-streak sentinels should survive low-streak newcomer churn"
        );
    }
}

#[test]
fn auth_probe_ipv6_is_bucketed_by_prefix_64() {
    let shared = ProxySharedState::new();
    let state = DashMap::new();
    let now = Instant::now();

    let ip_a = IpAddr::V6("2001:db8:abcd:1234:1:2:3:4".parse().unwrap());
    let ip_b = IpAddr::V6("2001:db8:abcd:1234:ffff:eeee:dddd:cccc".parse().unwrap());

    auth_probe_record_failure_with_state_in(
        shared.as_ref(),
        &state,
        normalize_auth_probe_ip(ip_a),
        now,
    );
    auth_probe_record_failure_with_state_in(
        shared.as_ref(),
        &state,
        normalize_auth_probe_ip(ip_b),
        now,
    );

    let normalized = normalize_auth_probe_ip(ip_a);
    assert_eq!(
        state.len(),
        1,
        "IPv6 sources in the same /64 must share one pre-auth throttle bucket"
    );
    assert_eq!(
        state.get(&normalized).map(|entry| entry.fail_streak),
        Some(2),
        "failures from the same /64 must accumulate in one throttle state"
    );
}

#[test]
fn auth_probe_ipv6_different_prefixes_use_distinct_buckets() {
    let shared = ProxySharedState::new();
    let state = DashMap::new();
    let now = Instant::now();

    let ip_a = IpAddr::V6("2001:db8:1111:2222:1:2:3:4".parse().unwrap());
    let ip_b = IpAddr::V6("2001:db8:1111:3333:1:2:3:4".parse().unwrap());

    auth_probe_record_failure_with_state_in(
        shared.as_ref(),
        &state,
        normalize_auth_probe_ip(ip_a),
        now,
    );
    auth_probe_record_failure_with_state_in(
        shared.as_ref(),
        &state,
        normalize_auth_probe_ip(ip_b),
        now,
    );

    assert_eq!(
        state.len(),
        2,
        "different IPv6 /64 prefixes must not share throttle buckets"
    );
    assert_eq!(
        state
            .get(&normalize_auth_probe_ip(ip_a))
            .map(|entry| entry.fail_streak),
        Some(1)
    );
    assert_eq!(
        state
            .get(&normalize_auth_probe_ip(ip_b))
            .map(|entry| entry.fail_streak),
        Some(1)
    );
}

#[test]
fn auth_probe_success_clears_whole_ipv6_prefix_bucket() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let now = Instant::now();
    let ip_fail = IpAddr::V6("2001:db8:aaaa:bbbb:1:2:3:4".parse().unwrap());
    let ip_success = IpAddr::V6("2001:db8:aaaa:bbbb:ffff:eeee:dddd:cccc".parse().unwrap());

    auth_probe_record_failure_in(shared.as_ref(), ip_fail, now);
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), ip_fail),
        Some(1),
        "precondition: normalized prefix bucket must exist"
    );

    auth_probe_record_success_in(shared.as_ref(), ip_success);
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), ip_fail),
        None,
        "success from the same /64 must clear the shared bucket"
    );
}

#[test]
fn auth_probe_eviction_offset_varies_with_input() {
    let shared = ProxySharedState::new();
    let now = Instant::now();
    let ip1 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    let ip2 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11));

    let a = auth_probe_eviction_offset_in(shared.as_ref(), ip1, now);
    let b = auth_probe_eviction_offset_in(shared.as_ref(), ip1, now);
    let c = auth_probe_eviction_offset_in(shared.as_ref(), ip2, now);

    assert_eq!(a, b, "same input must yield deterministic offset");
    assert_ne!(a, c, "different peer IPs should not collapse to one offset");
}

#[test]
fn auth_probe_eviction_offset_changes_with_time_component() {
    let shared = ProxySharedState::new();
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
    let now = Instant::now();
    let later = now + Duration::from_millis(1);

    let a = auth_probe_eviction_offset_in(shared.as_ref(), ip, now);
    let b = auth_probe_eviction_offset_in(shared.as_ref(), ip, later);

    assert_ne!(
        a, b,
        "eviction offset must incorporate timestamp entropy and not only peer IP"
    );
}

#[test]
fn auth_probe_round_limited_overcap_eviction_marks_saturation_and_keeps_newcomer_trackable() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let state = DashMap::new();
    let now = Instant::now();
    let initial = AUTH_PROBE_TRACK_MAX_ENTRIES + 64;

    let sentinel = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 250));
    state.insert(
        sentinel,
        AuthProbeState {
            fail_streak: 25,
            blocked_until: now,
            last_seen: now - Duration::from_secs(30),
        },
    );

    for idx in 0..(initial - 1) {
        let ip = IpAddr::V4(Ipv4Addr::new(
            10,
            20,
            ((idx >> 8) & 0xff) as u8,
            (idx & 0xff) as u8,
        ));
        state.insert(
            ip,
            AuthProbeState {
                fail_streak: 1,
                blocked_until: now,
                last_seen: now + Duration::from_millis((idx % 1024) as u64),
            },
        );
    }

    let newcomer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 40));
    auth_probe_record_failure_with_state_in(
        shared.as_ref(),
        &state,
        newcomer,
        now + Duration::from_millis(1),
    );

    assert!(
        state.get(&newcomer).is_some(),
        "newcomer must still be tracked under over-cap pressure"
    );
    assert!(
        state.get(&sentinel).is_some(),
        "high fail-streak sentinel must survive round-limited eviction"
    );
    assert!(
        auth_probe_saturation_is_throttled_at_for_testing_in_shared(
            shared.as_ref(),
            now + Duration::from_millis(1)
        ),
        "round-limited over-cap path must activate saturation throttle marker"
    );
}

#[tokio::test]
async fn gap_t01_short_tls_probe_burst_is_throttled() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let config = test_config_with_secret_hex("11111111111111111111111111111111");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.171:44361".parse().unwrap();

    let too_short = vec![0x16, 0x03, 0x01];

    for _ in 0..AUTH_PROBE_BACKOFF_START_FAILS {
        let result = handle_tls_handshake_with_shared(
            &too_short,
            tokio::io::empty(),
            tokio::io::sink(),
            peer,
            &config,
            &replay_checker,
            &rng,
            None,
            shared.as_ref(),
        )
        .await;
        assert!(matches!(result, HandshakeResult::BadClient { .. }));
    }

    assert!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip())
            .is_some_and(|streak| streak >= AUTH_PROBE_BACKOFF_START_FAILS),
        "short TLS probe bursts must increase auth-probe fail streak"
    );
}

#[test]
fn stress_auth_probe_overcap_churn_does_not_starve_high_threat_sentinel_bucket() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let state = DashMap::new();
    let base_now = Instant::now();

    let sentinel = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200));
    state.insert(
        sentinel,
        AuthProbeState {
            fail_streak: 30,
            blocked_until: base_now,
            last_seen: base_now - Duration::from_secs(60),
        },
    );

    for idx in 0..(AUTH_PROBE_TRACK_MAX_ENTRIES + 80) {
        let ip = IpAddr::V4(Ipv4Addr::new(
            172,
            22,
            ((idx >> 8) & 0xff) as u8,
            (idx & 0xff) as u8,
        ));
        state.insert(
            ip,
            AuthProbeState {
                fail_streak: 1,
                blocked_until: base_now,
                last_seen: base_now + Duration::from_millis((idx % 2048) as u64),
            },
        );
    }

    for step in 0..512usize {
        let newcomer = IpAddr::V4(Ipv4Addr::new(
            203,
            2,
            ((step >> 8) & 0xff) as u8,
            (step & 0xff) as u8,
        ));
        auth_probe_record_failure_with_state_in(
            shared.as_ref(),
            &state,
            newcomer,
            base_now + Duration::from_millis(step as u64 + 1),
        );

        assert!(
            state.get(&sentinel).is_some(),
            "step {step}: high-threat sentinel must not be starved by newcomer churn"
        );
        assert!(
            state.get(&newcomer).is_some(),
            "step {step}: newcomer must be tracked"
        );
    }
}

#[test]
fn light_fuzz_auth_probe_overcap_eviction_prefers_less_threatening_entries() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let now = Instant::now();
    let mut s: u64 = 0xBADC_0FFE_EE11_2233;

    for round in 0..128usize {
        let state = DashMap::new();
        let sentinel = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 180));
        state.insert(
            sentinel,
            AuthProbeState {
                fail_streak: 18,
                blocked_until: now,
                last_seen: now - Duration::from_secs(5),
            },
        );

        for idx in 0..AUTH_PROBE_TRACK_MAX_ENTRIES {
            s ^= s << 7;
            s ^= s >> 9;
            s ^= s << 8;
            let ip = IpAddr::V4(Ipv4Addr::new(
                10,
                ((idx >> 8) & 0xff) as u8,
                (idx & 0xff) as u8,
                (s & 0xff) as u8,
            ));
            state.insert(
                ip,
                AuthProbeState {
                    fail_streak: 1,
                    blocked_until: now,
                    last_seen: now + Duration::from_millis((s & 1023) as u64),
                },
            );
        }

        let newcomer = IpAddr::V4(Ipv4Addr::new(
            203,
            10,
            ((round >> 8) & 0xff) as u8,
            (round & 0xff) as u8,
        ));
        auth_probe_record_failure_with_state_in(
            shared.as_ref(),
            &state,
            newcomer,
            now + Duration::from_millis(round as u64 + 1),
        );

        assert!(
            state.get(&newcomer).is_some(),
            "round {round}: newcomer should be tracked"
        );
        assert!(
            state.get(&sentinel).is_some(),
            "round {round}: high fail-streak sentinel should survive mixed low-threat pool"
        );
    }
}
#[test]
fn light_fuzz_auth_probe_eviction_offset_is_deterministic_per_input_pair() {
    let shared = ProxySharedState::new();
    let mut rng = StdRng::seed_from_u64(0xA11CE5EED);
    let base = Instant::now();

    for _ in 0..4096usize {
        let ip = IpAddr::V4(Ipv4Addr::new(
            rng.random(),
            rng.random(),
            rng.random(),
            rng.random(),
        ));
        let offset_ns = rng.random_range(0_u64..2_000_000);
        let when = base + Duration::from_nanos(offset_ns);

        let first = auth_probe_eviction_offset_in(shared.as_ref(), ip, when);
        let second = auth_probe_eviction_offset_in(shared.as_ref(), ip, when);
        assert_eq!(
            first, second,
            "eviction offset must be stable for identical (ip, now) pairs"
        );
    }
}

#[test]
fn adversarial_eviction_offset_spread_avoids_single_bucket_collapse() {
    let shared = ProxySharedState::new();
    let modulus = AUTH_PROBE_TRACK_MAX_ENTRIES;
    let mut bucket_hits = vec![0usize; modulus];
    let now = Instant::now();

    for idx in 0..8192usize {
        let ip = IpAddr::V4(Ipv4Addr::new(
            100,
            ((idx >> 8) & 0xff) as u8,
            (idx & 0xff) as u8,
            ((idx.wrapping_mul(37)) & 0xff) as u8,
        ));
        let bucket = auth_probe_eviction_offset_in(shared.as_ref(), ip, now) % modulus;
        bucket_hits[bucket] += 1;
    }

    let non_empty_buckets = bucket_hits.iter().filter(|&&hits| hits > 0).count();
    assert!(
        non_empty_buckets >= modulus / 2,
        "adversarial sequential input should cover a broad bucket set (covered {non_empty_buckets}/{modulus})"
    );

    let max_hits = bucket_hits.iter().copied().max().unwrap_or(0);
    let min_non_zero_hits = bucket_hits
        .iter()
        .copied()
        .filter(|&hits| hits > 0)
        .min()
        .unwrap_or(0);
    assert!(
        max_hits <= min_non_zero_hits.saturating_mul(32).max(1),
        "bucket skew is unexpectedly extreme for keyed hasher spread (max={max_hits}, min_non_zero={min_non_zero_hits})"
    );
}

#[test]
fn stress_auth_probe_eviction_offset_high_volume_uniqueness_sanity() {
    let shared = ProxySharedState::new();
    let now = Instant::now();
    let mut seen = std::collections::HashSet::new();

    for idx in 0..50_000usize {
        let ip = IpAddr::V4(Ipv4Addr::new(
            198,
            ((idx >> 16) & 0xff) as u8,
            ((idx >> 8) & 0xff) as u8,
            (idx & 0xff) as u8,
        ));
        seen.insert(auth_probe_eviction_offset_in(shared.as_ref(), ip, now));
    }

    assert!(
        seen.len() >= 40_000,
        "high-volume eviction offsets should not collapse excessively under keyed hashing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_probe_concurrent_failures_do_not_lose_fail_streak_updates() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let peer_ip: IpAddr = "198.51.100.90".parse().unwrap();
    let tasks = 128usize;
    let barrier = Arc::new(Barrier::new(tasks));
    let mut handles = Vec::with_capacity(tasks);

    for _ in 0..tasks {
        let barrier = barrier.clone();
        let shared = shared.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            auth_probe_record_failure_in(shared.as_ref(), peer_ip, Instant::now());
        }));
    }

    for handle in handles {
        handle
            .await
            .expect("concurrent failure recording task must not panic");
    }

    let streak = auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer_ip)
        .expect("tracked peer must exist after concurrent failure burst");
    assert_eq!(
        streak as usize, tasks,
        "concurrent failures for one source must account every attempt"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_probe_noise_from_other_ips_does_not_break_valid_tls_handshake() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let secret = [0x31u8; 16];
    let config = Arc::new(test_config_with_secret_hex(
        "31313131313131313131313131313131",
    ));
    let replay_checker = Arc::new(ReplayChecker::new(4096, Duration::from_secs(60)));
    let rng = Arc::new(SecureRandom::new());
    let victim_peer: SocketAddr = "198.51.100.91:44391".parse().unwrap();
    let valid = Arc::new(make_valid_tls_handshake(&secret, 0));

    let mut invalid = vec![0x42u8; tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 + 32];
    invalid[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN] = 32;
    let invalid = Arc::new(invalid);

    let mut noise_tasks = Vec::new();
    for idx in 0..96u16 {
        let config = config.clone();
        let replay_checker = replay_checker.clone();
        let rng = rng.clone();
        let invalid = invalid.clone();
        noise_tasks.push(tokio::spawn(async move {
            let octet = ((idx % 200) + 1) as u8;
            let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, octet)), 45000 + idx);
            let result = handle_tls_handshake(
                &invalid,
                tokio::io::empty(),
                tokio::io::sink(),
                peer,
                &config,
                &replay_checker,
                &rng,
                None,
            )
            .await;
            assert!(matches!(result, HandshakeResult::BadClient { .. }));
        }));
    }

    let victim_config = config.clone();
    let victim_replay_checker = replay_checker.clone();
    let victim_rng = rng.clone();
    let victim_valid = valid.clone();
    let victim_task = tokio::spawn(async move {
        handle_tls_handshake(
            &victim_valid,
            tokio::io::empty(),
            tokio::io::sink(),
            victim_peer,
            &victim_config,
            &victim_replay_checker,
            &victim_rng,
            None,
        )
        .await
    });

    for task in noise_tasks {
        task.await.expect("noise task must not panic");
    }

    let victim_result = victim_task
        .await
        .expect("victim handshake task must not panic");
    assert!(
        matches!(victim_result, HandshakeResult::Success(_)),
        "invalid probe noise from other IPs must not block a valid victim handshake"
    );
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), victim_peer.ip()),
        None,
        "successful victim handshake must not retain pre-auth failure streak"
    );
}

#[test]
fn auth_probe_saturation_state_expires_after_retention_window() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let now = Instant::now();
    let saturation = auth_probe_saturation_state_for_testing_in_shared(shared.as_ref());
    {
        let mut guard = saturation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(30),
            last_seen: now - Duration::from_secs(AUTH_PROBE_TRACK_RETENTION_SECS + 1),
        });
    }

    assert!(
        !auth_probe_saturation_is_throttled_for_testing_in_shared(shared.as_ref()),
        "expired saturation state must stop throttling and self-clear"
    );

    let guard = saturation
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(guard.is_none(), "expired saturation state must be removed");
}

#[tokio::test]
async fn global_saturation_marker_does_not_block_valid_tls_handshake() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let secret = [0x41u8; 16];
    let config = test_config_with_secret_hex("41414141414141414141414141414141");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.101:45101".parse().unwrap();

    let now = Instant::now();
    let saturation = auth_probe_saturation_state_for_testing_in_shared(shared.as_ref());
    {
        let mut guard = saturation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(5),
            last_seen: now,
        });
    }

    let valid = make_valid_tls_handshake(&secret, 0);
    let result = handle_tls_handshake_with_shared(
        &valid,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
        shared.as_ref(),
    )
    .await;

    assert!(
        matches!(result, HandshakeResult::Success(_)),
        "global saturation marker must not block valid authenticated TLS handshakes"
    );
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip()),
        None,
        "successful handshake under saturation marker must not retain per-ip probe failures"
    );
}

#[tokio::test]
async fn expired_global_saturation_allows_valid_tls_handshake() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let secret = [0x55u8; 16];
    let config = test_config_with_secret_hex("55555555555555555555555555555555");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.102:45102".parse().unwrap();

    let now = Instant::now();
    let saturation = auth_probe_saturation_state_for_testing_in_shared(shared.as_ref());
    {
        let mut guard = saturation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(5),
            last_seen: now - Duration::from_secs(AUTH_PROBE_TRACK_RETENTION_SECS + 1),
        });
    }

    let valid = make_valid_tls_handshake(&secret, 0);
    let result = handle_tls_handshake_with_shared(
        &valid,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
        shared.as_ref(),
    )
    .await;

    assert!(
        matches!(result, HandshakeResult::Success(_)),
        "expired saturation marker must not block valid handshake"
    );
}

#[tokio::test]
async fn valid_tls_is_blocked_by_per_ip_preauth_throttle_without_saturation() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let secret = [0x61u8; 16];
    let config = test_config_with_secret_hex("61616161616161616161616161616161");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.103:45103".parse().unwrap();

    auth_probe_state_for_testing_in_shared(shared.as_ref()).insert(
        normalize_auth_probe_ip(peer.ip()),
        AuthProbeState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: Instant::now() + Duration::from_secs(5),
            last_seen: Instant::now(),
        },
    );

    let valid = make_valid_tls_handshake(&secret, 0);
    let result = handle_tls_handshake_with_shared(
        &valid,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
        shared.as_ref(),
    )
    .await;

    assert!(matches!(result, HandshakeResult::BadClient { .. }));
}

#[tokio::test]
async fn saturation_allows_valid_tls_even_when_peer_ip_is_currently_throttled() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let secret = [0x62u8; 16];
    let config = test_config_with_secret_hex("62626262626262626262626262626262");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.104:45104".parse().unwrap();
    let now = Instant::now();

    auth_probe_state_for_testing_in_shared(shared.as_ref()).insert(
        normalize_auth_probe_ip(peer.ip()),
        AuthProbeState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(5),
            last_seen: now,
        },
    );
    {
        let mut guard = auth_probe_saturation_state_for_testing_in_shared(shared.as_ref())
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(5),
            last_seen: now,
        });
    }

    let valid = make_valid_tls_handshake(&secret, 0);
    let result = handle_tls_handshake_with_shared(
        &valid,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
        shared.as_ref(),
    )
    .await;

    assert!(matches!(result, HandshakeResult::Success(_)));
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip()),
        None,
        "successful auth under saturation must clear the peer's throttled state"
    );
}

#[tokio::test]
async fn saturation_still_rejects_invalid_tls_probe_and_records_failure() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let config = test_config_with_secret_hex("63636363636363636363636363636363");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.105:45105".parse().unwrap();
    let now = Instant::now();
    {
        let mut guard = auth_probe_saturation_state_for_testing_in_shared(shared.as_ref())
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(5),
            last_seen: now,
        });
    }

    let mut invalid = vec![0x42u8; tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 + 32];
    invalid[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN] = 32;

    let result = handle_tls_handshake_with_shared(
        &invalid,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
        shared.as_ref(),
    )
    .await;

    assert!(matches!(result, HandshakeResult::BadClient { .. }));
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip()),
        Some(1),
        "invalid TLS during saturation must still increment per-ip failure tracking"
    );
}

#[tokio::test]
async fn saturation_grace_exhaustion_preauth_throttles_repeated_invalid_tls_probe() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let config = test_config_with_secret_hex("63636363636363636363636363636363");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.205:45205".parse().unwrap();
    let now = Instant::now();
    auth_probe_state_for_testing_in_shared(shared.as_ref()).insert(
        normalize_auth_probe_ip(peer.ip()),
        AuthProbeState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS,
            blocked_until: now + Duration::from_secs(1),
            last_seen: now,
        },
    );
    {
        let mut guard = auth_probe_saturation_state_for_testing_in_shared(shared.as_ref())
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(1),
            last_seen: now,
        });
    }

    let mut invalid = vec![0x42u8; tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 + 32];
    invalid[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN] = 32;

    let result = handle_tls_handshake(
        &invalid,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(result, HandshakeResult::BadClient { .. }));
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip()),
        Some(AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS),
        "pre-auth throttle under exhausted saturation grace must reject without re-processing invalid TLS"
    );
}

#[tokio::test]
async fn saturation_allows_valid_mtproto_even_when_peer_ip_is_currently_throttled() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let secret_hex = "64646464646464646464646464646464";
    let mut config = test_config_with_secret_hex(secret_hex);
    config.general.modes.secure = true;
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let peer: SocketAddr = "198.51.100.106:45106".parse().unwrap();
    let now = Instant::now();

    auth_probe_state_for_testing_in_shared(shared.as_ref()).insert(
        normalize_auth_probe_ip(peer.ip()),
        AuthProbeState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(5),
            last_seen: now,
        },
    );
    {
        let mut guard = auth_probe_saturation_state_for_testing_in_shared(shared.as_ref())
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(5),
            last_seen: now,
        });
    }

    let valid = make_valid_mtproto_handshake(secret_hex, ProtoTag::Secure, 2);
    let result = handle_mtproto_handshake_with_shared(
        &valid,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        false,
        None,
        shared.as_ref(),
    )
    .await;

    assert!(matches!(result, HandshakeResult::Success(_)));
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip()),
        None,
        "successful mtproto auth under saturation must clear the peer's throttled state"
    );
}

#[tokio::test]
async fn saturation_still_rejects_invalid_mtproto_probe_and_records_failure() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let config = test_config_with_secret_hex("65656565656565656565656565656565");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let peer: SocketAddr = "198.51.100.107:45107".parse().unwrap();
    let now = Instant::now();
    {
        let mut guard = auth_probe_saturation_state_for_testing_in_shared(shared.as_ref())
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(5),
            last_seen: now,
        });
    }

    let invalid = [0u8; HANDSHAKE_LEN];

    let result = handle_mtproto_handshake_with_shared(
        &invalid,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        false,
        None,
        shared.as_ref(),
    )
    .await;

    assert!(matches!(result, HandshakeResult::BadClient { .. }));
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip()),
        Some(1),
        "invalid mtproto during saturation must still increment per-ip failure tracking"
    );
}

#[tokio::test]
async fn saturation_grace_exhaustion_preauth_throttles_repeated_invalid_mtproto_probe() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let config = test_config_with_secret_hex("65656565656565656565656565656565");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let peer: SocketAddr = "198.51.100.206:45206".parse().unwrap();
    let now = Instant::now();
    auth_probe_state_for_testing_in_shared(shared.as_ref()).insert(
        normalize_auth_probe_ip(peer.ip()),
        AuthProbeState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS,
            blocked_until: now + Duration::from_secs(1),
            last_seen: now,
        },
    );
    {
        let mut guard = auth_probe_saturation_state_for_testing_in_shared(shared.as_ref())
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(1),
            last_seen: now,
        });
    }

    let invalid = [0u8; HANDSHAKE_LEN];
    let result = handle_mtproto_handshake(
        &invalid,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        false,
        None,
    )
    .await;

    assert!(matches!(result, HandshakeResult::BadClient { .. }));
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip()),
        Some(AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS),
        "pre-auth throttle under exhausted saturation grace must reject without re-processing invalid MTProto"
    );
}

#[tokio::test]
async fn saturation_grace_progression_tls_reaches_cap_then_stops_incrementing() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let config = test_config_with_secret_hex("70707070707070707070707070707070");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.207:45207".parse().unwrap();
    let now = Instant::now();
    auth_probe_state_for_testing_in_shared(shared.as_ref()).insert(
        normalize_auth_probe_ip(peer.ip()),
        AuthProbeState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(1),
            last_seen: now,
        },
    );
    {
        let mut guard = auth_probe_saturation_state_for_testing_in_shared(shared.as_ref())
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(1),
            last_seen: now,
        });
    }

    let mut invalid = vec![0x42u8; tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 + 32];
    invalid[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN] = 32;

    for expected in [
        AUTH_PROBE_BACKOFF_START_FAILS + 1,
        AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS,
    ] {
        let result = handle_tls_handshake_with_shared(
            &invalid,
            tokio::io::empty(),
            tokio::io::sink(),
            peer,
            &config,
            &replay_checker,
            &rng,
            None,
            shared.as_ref(),
        )
        .await;
        assert!(matches!(result, HandshakeResult::BadClient { .. }));
        assert_eq!(
            auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip()),
            Some(expected)
        );
    }

    {
        let mut entry = auth_probe_state_for_testing_in_shared(shared.as_ref())
            .get_mut(&normalize_auth_probe_ip(peer.ip()))
            .expect("peer state must exist before exhaustion recheck");
        entry.fail_streak = AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS;
        entry.blocked_until = Instant::now() + Duration::from_secs(1);
        entry.last_seen = Instant::now();
    }

    let result = handle_tls_handshake_with_shared(
        &invalid,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
        shared.as_ref(),
    )
    .await;
    assert!(matches!(result, HandshakeResult::BadClient { .. }));
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip()),
        Some(AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS),
        "once grace is exhausted, repeated invalid TLS must be pre-auth throttled without further fail-streak growth"
    );
}

#[tokio::test]
async fn saturation_grace_progression_mtproto_reaches_cap_then_stops_incrementing() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let config = test_config_with_secret_hex("71717171717171717171717171717171");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let peer: SocketAddr = "198.51.100.208:45208".parse().unwrap();
    let now = Instant::now();
    auth_probe_state_for_testing_in_shared(shared.as_ref()).insert(
        normalize_auth_probe_ip(peer.ip()),
        AuthProbeState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(1),
            last_seen: now,
        },
    );
    {
        let mut guard = auth_probe_saturation_state_for_testing_in_shared(shared.as_ref())
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(1),
            last_seen: now,
        });
    }

    let invalid = [0u8; HANDSHAKE_LEN];

    for expected in [
        AUTH_PROBE_BACKOFF_START_FAILS + 1,
        AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS,
    ] {
        let result = handle_mtproto_handshake_with_shared(
            &invalid,
            tokio::io::empty(),
            tokio::io::sink(),
            peer,
            &config,
            &replay_checker,
            false,
            None,
            shared.as_ref(),
        )
        .await;
        assert!(matches!(result, HandshakeResult::BadClient { .. }));
        assert_eq!(
            auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip()),
            Some(expected)
        );
    }

    {
        let mut entry = auth_probe_state_for_testing_in_shared(shared.as_ref())
            .get_mut(&normalize_auth_probe_ip(peer.ip()))
            .expect("peer state must exist before exhaustion recheck");
        entry.fail_streak = AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS;
        entry.blocked_until = Instant::now() + Duration::from_secs(1);
        entry.last_seen = Instant::now();
    }

    let result = handle_mtproto_handshake_with_shared(
        &invalid,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        false,
        None,
        shared.as_ref(),
    )
    .await;
    assert!(matches!(result, HandshakeResult::BadClient { .. }));
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip()),
        Some(AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS),
        "once grace is exhausted, repeated invalid MTProto must be pre-auth throttled without further fail-streak growth"
    );
}

#[tokio::test]
async fn saturation_grace_boundary_still_admits_valid_tls_before_exhaustion() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let secret = [0x72u8; 16];
    let config = test_config_with_secret_hex("72727272727272727272727272727272");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.209:45209".parse().unwrap();
    let now = Instant::now();
    auth_probe_state_for_testing_in_shared(shared.as_ref()).insert(
        normalize_auth_probe_ip(peer.ip()),
        AuthProbeState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS - 1,
            blocked_until: now + Duration::from_secs(1),
            last_seen: now,
        },
    );
    {
        let mut guard = auth_probe_saturation_state_for_testing_in_shared(shared.as_ref())
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(1),
            last_seen: now,
        });
    }

    let valid = make_valid_tls_handshake(&secret, 0);
    let result = handle_tls_handshake_with_shared(
        &valid,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
        shared.as_ref(),
    )
    .await;

    assert!(
        matches!(result, HandshakeResult::Success(_)),
        "valid TLS should still pass while peer remains within saturation grace budget"
    );
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip()),
        None
    );
}

#[tokio::test]
async fn saturation_grace_exhaustion_blocks_valid_tls_until_backoff_expires() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let secret = [0x73u8; 16];
    let config = test_config_with_secret_hex("73737373737373737373737373737373");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.210:45210".parse().unwrap();
    let now = Instant::now();
    auth_probe_state_for_testing_in_shared(shared.as_ref()).insert(
        normalize_auth_probe_ip(peer.ip()),
        AuthProbeState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS,
            blocked_until: now + Duration::from_millis(200),
            last_seen: now,
        },
    );
    {
        let mut guard = auth_probe_saturation_state_for_testing_in_shared(shared.as_ref())
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(1),
            last_seen: now,
        });
    }

    let valid = make_valid_tls_handshake(&secret, 0);
    let blocked = handle_tls_handshake_with_shared(
        &valid,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
        shared.as_ref(),
    )
    .await;
    assert!(matches!(blocked, HandshakeResult::BadClient { .. }));

    tokio::time::sleep(Duration::from_millis(230)).await;

    let allowed = handle_tls_handshake_with_shared(
        &valid,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
        shared.as_ref(),
    )
    .await;
    assert!(
        matches!(allowed, HandshakeResult::Success(_)),
        "valid TLS should recover after peer-specific pre-auth backoff has elapsed"
    );
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip()),
        None
    );
}

#[tokio::test]
async fn saturation_grace_exhaustion_is_shared_across_tls_and_mtproto_for_same_peer() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let config = test_config_with_secret_hex("74747474747474747474747474747474");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.211:45211".parse().unwrap();
    let now = Instant::now();
    auth_probe_state_for_testing_in_shared(shared.as_ref()).insert(
        normalize_auth_probe_ip(peer.ip()),
        AuthProbeState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS,
            blocked_until: now + Duration::from_secs(1),
            last_seen: now,
        },
    );
    {
        let mut guard = auth_probe_saturation_state_for_testing_in_shared(shared.as_ref())
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(1),
            last_seen: now,
        });
    }

    let mut invalid_tls = vec![0x42u8; tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 + 32];
    invalid_tls[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN] = 32;
    let invalid_mtproto = [0u8; HANDSHAKE_LEN];

    let tls_result = handle_tls_handshake(
        &invalid_tls,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;
    assert!(matches!(tls_result, HandshakeResult::BadClient { .. }));

    let mtproto_result = handle_mtproto_handshake(
        &invalid_mtproto,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        false,
        None,
    )
    .await;
    assert!(matches!(mtproto_result, HandshakeResult::BadClient { .. }));

    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip()),
        Some(AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS),
        "saturation grace exhaustion must gate both TLS and MTProto pre-auth paths for one peer"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adversarial_same_peer_invalid_tls_storm_does_not_bypass_saturation_grace_cap() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let config = Arc::new(test_config_with_secret_hex(
        "75757575757575757575757575757575",
    ));
    let replay_checker = Arc::new(ReplayChecker::new(1024, Duration::from_secs(60)));
    let rng = Arc::new(SecureRandom::new());
    let peer: SocketAddr = "198.51.100.212:45212".parse().unwrap();
    let now = Instant::now();
    auth_probe_state_for_testing_in_shared(shared.as_ref()).insert(
        normalize_auth_probe_ip(peer.ip()),
        AuthProbeState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS,
            blocked_until: now + Duration::from_secs(1),
            last_seen: now,
        },
    );
    {
        let mut guard = auth_probe_saturation_state_for_testing_in_shared(shared.as_ref())
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(1),
            last_seen: now,
        });
    }

    let mut invalid_tls = vec![0x42u8; tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 + 32];
    invalid_tls[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN] = 32;
    let invalid_tls = Arc::new(invalid_tls);

    let mut tasks = Vec::new();
    for _ in 0..64usize {
        let config = config.clone();
        let replay_checker = replay_checker.clone();
        let rng = rng.clone();
        let invalid_tls = invalid_tls.clone();
        tasks.push(tokio::spawn(async move {
            handle_tls_handshake(
                &invalid_tls,
                tokio::io::empty(),
                tokio::io::sink(),
                peer,
                &config,
                &replay_checker,
                &rng,
                None,
            )
            .await
        }));
    }

    for task in tasks {
        let result = task.await.unwrap();
        assert!(matches!(result, HandshakeResult::BadClient { .. }));
    }

    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip()),
        Some(AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS),
        "same-peer invalid storm under exhausted grace must stay pre-auth throttled without fail-streak growth"
    );
}

#[tokio::test]
async fn light_fuzz_saturation_grace_tls_invalid_inputs_never_authenticate_or_panic() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let config = test_config_with_secret_hex("76767676767676767676767676767676");
    let replay_checker = ReplayChecker::new(2048, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.213:45213".parse().unwrap();
    let now = Instant::now();
    auth_probe_state_for_testing_in_shared(shared.as_ref()).insert(
        normalize_auth_probe_ip(peer.ip()),
        AuthProbeState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS,
            blocked_until: now + Duration::from_secs(1),
            last_seen: now,
        },
    );
    {
        let mut guard = auth_probe_saturation_state_for_testing_in_shared(shared.as_ref())
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(1),
            last_seen: now,
        });
    }

    let mut seeded = StdRng::seed_from_u64(0xD15EA5E5_u64);
    for _ in 0..128usize {
        let len = seeded.random_range(0usize..96usize);
        let mut probe = vec![0u8; len];
        seeded.fill(&mut probe[..]);

        let result = handle_tls_handshake(
            &probe,
            tokio::io::empty(),
            tokio::io::sink(),
            peer,
            &config,
            &replay_checker,
            &rng,
            None,
        )
        .await;
        assert!(matches!(result, HandshakeResult::BadClient { .. }));
    }

    let streak = auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip())
        .expect("peer should remain tracked after repeated invalid fuzz probes");
    assert!(
        streak >= AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS,
        "fuzzed invalid TLS probes under saturation must not reduce fail-streak below exhaustion threshold"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adversarial_saturation_burst_only_admits_valid_tls_and_mtproto_handshakes() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let secret_hex = "66666666666666666666666666666666";
    let secret = [0x66u8; 16];
    let mut cfg = test_config_with_secret_hex(secret_hex);
    cfg.general.modes.secure = true;
    let config = Arc::new(cfg);
    let replay_checker = Arc::new(ReplayChecker::new(4096, Duration::from_secs(60)));
    let rng = Arc::new(SecureRandom::new());
    let now = Instant::now();

    {
        let mut guard = auth_probe_saturation_state_for_testing_in_shared(shared.as_ref())
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(5),
            last_seen: now,
        });
    }

    let valid_tls = Arc::new(make_valid_tls_handshake(&secret, 0));
    let valid_mtproto = Arc::new(make_valid_mtproto_handshake(
        secret_hex,
        ProtoTag::Secure,
        3,
    ));
    let mut invalid_tls = vec![0x42u8; tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 + 32];
    invalid_tls[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN] = 32;
    let invalid_tls = Arc::new(invalid_tls);

    let mut invalid_tls_tasks = Vec::new();
    for idx in 0..48u16 {
        let config = config.clone();
        let replay_checker = replay_checker.clone();
        let rng = rng.clone();
        let invalid_tls = invalid_tls.clone();
        invalid_tls_tasks.push(tokio::spawn(async move {
            let octet = ((idx % 200) + 1) as u8;
            let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, octet)), 46000 + idx);
            handle_tls_handshake(
                &invalid_tls,
                tokio::io::empty(),
                tokio::io::sink(),
                peer,
                &config,
                &replay_checker,
                &rng,
                None,
            )
            .await
        }));
    }

    let valid_tls_task = {
        let config = config.clone();
        let replay_checker = replay_checker.clone();
        let rng = rng.clone();
        let valid_tls = valid_tls.clone();
        tokio::spawn(async move {
            handle_tls_handshake(
                &valid_tls,
                tokio::io::empty(),
                tokio::io::sink(),
                "198.51.100.108:45108".parse().unwrap(),
                &config,
                &replay_checker,
                &rng,
                None,
            )
            .await
        })
    };

    let valid_mtproto_task = {
        let config = config.clone();
        let replay_checker = replay_checker.clone();
        let valid_mtproto = valid_mtproto.clone();
        tokio::spawn(async move {
            handle_mtproto_handshake(
                &valid_mtproto,
                tokio::io::empty(),
                tokio::io::sink(),
                "198.51.100.109:45109".parse().unwrap(),
                &config,
                &replay_checker,
                false,
                None,
            )
            .await
        })
    };

    let mut bad_clients = 0usize;
    for task in invalid_tls_tasks {
        match task.await.unwrap() {
            HandshakeResult::BadClient { .. } => bad_clients += 1,
            HandshakeResult::Success(_) => panic!("invalid TLS probe unexpectedly authenticated"),
            HandshakeResult::Error(err) => {
                panic!("unexpected error in invalid TLS saturation burst test: {err}")
            }
        }
    }

    let valid_tls_result = valid_tls_task.await.unwrap();
    assert!(
        matches!(valid_tls_result, HandshakeResult::Success(_)),
        "valid TLS probe must authenticate during saturation burst"
    );

    let valid_mtproto_result = valid_mtproto_task.await.unwrap();
    assert!(
        matches!(valid_mtproto_result, HandshakeResult::Success(_)),
        "valid MTProto probe must authenticate during saturation burst"
    );

    assert_eq!(
        bad_clients, 48,
        "all invalid TLS probes in mixed saturation burst must be rejected"
    );
}

#[tokio::test]
async fn expired_saturation_keeps_per_ip_throttle_enforced_for_valid_tls() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let secret = [0x67u8; 16];
    let config = test_config_with_secret_hex("67676767676767676767676767676767");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.110:45110".parse().unwrap();
    let now = Instant::now();

    auth_probe_state_for_testing_in_shared(shared.as_ref()).insert(
        normalize_auth_probe_ip(peer.ip()),
        AuthProbeState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(5),
            last_seen: now,
        },
    );
    {
        let mut guard = auth_probe_saturation_state_for_testing_in_shared(shared.as_ref())
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(5),
            last_seen: now - Duration::from_secs(AUTH_PROBE_TRACK_RETENTION_SECS + 1),
        });
    }

    let valid = make_valid_tls_handshake(&secret, 0);
    let result = handle_tls_handshake_with_shared(
        &valid,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
        shared.as_ref(),
    )
    .await;

    assert!(
        matches!(result, HandshakeResult::BadClient { .. }),
        "expired saturation marker must not disable per-ip pre-auth throttle"
    );
}
