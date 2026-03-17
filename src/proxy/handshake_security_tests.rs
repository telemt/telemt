use super::*;
use crate::crypto::sha256_hmac;
use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    record[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN]
        .copy_from_slice(&digest);

    record
}

fn test_config_with_secret_hex(secret_hex: &str) -> ProxyConfig {
    clear_auth_probe_state_for_testing();
    let mut cfg = ProxyConfig::default();
    cfg.access.users.clear();
    cfg.access
        .users
        .insert("user".to_string(), secret_hex.to_string());
    cfg.access.ignore_time_skew = true;
    cfg
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

    assert_eq!(&nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN], expected.as_slice());
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
async fn tls_replay_concurrent_identical_handshake_allows_exactly_one_success() {
    let secret = [0x77u8; 16];
    let config = Arc::new(test_config_with_secret_hex("77777777777777777777777777777777"));
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
    clear_warned_secrets_for_testing();
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
    clear_warned_secrets_for_testing();
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
    clear_warned_secrets_for_testing();
    clear_auth_probe_state_for_testing();
    let good_secret = [0x22u8; 16];
    let mut config = ProxyConfig::default();
    config.access.users.clear();
    config
        .access
        .users
        .insert("broken_user".to_string(), "aa".to_string());
    config
        .access
        .users
        .insert("valid_user".to_string(), "22222222222222222222222222222222".to_string());
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
    clear_warned_secrets_for_testing();

    warn_invalid_secret_once("a:b", "c", ACCESS_SECRET_BYTES, Some(1));
    warn_invalid_secret_once("a", "b:c", ACCESS_SECRET_BYTES, Some(2));

    let warned = INVALID_SECRET_WARNED
        .get()
        .expect("warned set must be initialized");
    let guard = warned.lock().expect("warned set lock must be available");
    assert_eq!(
        guard.len(),
        2,
        "(name, reason) pairs that stringify to the same colon-joined key must remain distinct"
    );
}

#[tokio::test]
async fn repeated_invalid_tls_probes_trigger_pre_auth_throttle() {
    let _guard = auth_probe_test_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    clear_auth_probe_state_for_testing();

    let config = test_config_with_secret_hex("11111111111111111111111111111111");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.61:44361".parse().unwrap();

    let mut invalid = vec![0x42u8; tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 + 32];
    invalid[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN] = 32;

    for _ in 0..AUTH_PROBE_BACKOFF_START_FAILS {
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
    }

    assert!(
        auth_probe_is_throttled_for_testing(peer.ip()),
        "invalid probe burst must activate per-IP pre-auth throttle"
    );
}

#[tokio::test]
async fn successful_tls_handshake_clears_pre_auth_failure_streak() {
    let _guard = auth_probe_test_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    clear_auth_probe_state_for_testing();

    let secret = [0x23u8; 16];
    let config = test_config_with_secret_hex("23232323232323232323232323232323");
    let replay_checker = ReplayChecker::new(256, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.62:44362".parse().unwrap();

    let mut invalid = vec![0x42u8; tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 + 32];
    invalid[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN] = 32;

    for expected in 1..AUTH_PROBE_BACKOFF_START_FAILS {
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
            auth_probe_fail_streak_for_testing(peer.ip()),
            Some(expected),
            "failure streak must grow before a successful authentication"
        );
    }

    let valid = make_valid_tls_handshake(&secret, 0);
    let success = handle_tls_handshake(
        &valid,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(success, HandshakeResult::Success(_)));
    assert_eq!(
        auth_probe_fail_streak_for_testing(peer.ip()),
        None,
        "successful authentication must clear accumulated pre-auth failures"
    );
}

#[test]
fn auth_probe_capacity_prunes_stale_entries_for_new_ips() {
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
    auth_probe_record_failure_with_state(&state, newcomer, now);

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
fn auth_probe_capacity_stays_fail_closed_when_map_is_fresh_and_full() {
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
                last_seen: now,
            },
        );
    }

    let newcomer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 55));
    auth_probe_record_failure_with_state(&state, newcomer, now);

    assert!(
        state.get(&newcomer).is_none(),
        "when all entries are fresh and full, new probes must not be admitted"
    );
    assert_eq!(
        state.len(),
        AUTH_PROBE_TRACK_MAX_ENTRIES,
        "auth probe map must stay at the configured cap"
    );
}
