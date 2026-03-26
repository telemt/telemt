use super::*;
use crate::crypto::{AesCtr, sha256, sha256_hmac};
use crate::protocol::constants::{ProtoTag, RESERVED_NONCE_BEGINNINGS, RESERVED_NONCE_FIRST_BYTES};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

// --- Helpers ---

fn auth_probe_test_guard() -> std::sync::MutexGuard<'static, ()> {
    auth_probe_test_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn test_config_with_secret_hex(secret_hex: &str) -> ProxyConfig {
    let mut cfg = ProxyConfig::default();
    cfg.access.users.clear();
    cfg.access
        .users
        .insert("user".to_string(), secret_hex.to_string());
    cfg.access.ignore_time_skew = true;
    cfg.general.modes.secure = true;
    cfg.general.modes.classic = true;
    cfg.general.modes.tls = true;
    cfg
}

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

fn make_valid_mtproto_handshake(
    secret_hex: &str,
    proto_tag: ProtoTag,
    dc_idx: i16,
) -> [u8; HANDSHAKE_LEN] {
    let secret = hex::decode(secret_hex).expect("secret hex must decode");
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

// --- Category 1: Edge Cases & Protocol Boundaries ---

#[tokio::test]
async fn tls_minimum_viable_length_boundary() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret = [0x11u8; 16];
    let config = test_config_with_secret_hex("11111111111111111111111111111111");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "192.0.2.1:12345".parse().unwrap();

    let min_len = tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1;
    let mut exact_min_handshake = vec![0x42u8; min_len];
    exact_min_handshake[min_len - 1] = 0;
    exact_min_handshake[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN].fill(0);
    let digest = sha256_hmac(&secret, &exact_min_handshake);
    exact_min_handshake[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN]
        .copy_from_slice(&digest);

    let res = handle_tls_handshake(
        &exact_min_handshake,
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
        matches!(res, HandshakeResult::Success(_)),
        "Exact minimum length TLS handshake must succeed"
    );

    let short_handshake = vec![0x42u8; min_len - 1];
    let res_short = handle_tls_handshake(
        &short_handshake,
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
        matches!(res_short, HandshakeResult::BadClient { .. }),
        "Handshake 1 byte shorter than minimum must fail closed"
    );
}

#[tokio::test]
async fn mtproto_extreme_dc_index_serialization() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret_hex = "22222222222222222222222222222222";
    let config = test_config_with_secret_hex(secret_hex);
    for (idx, extreme_dc) in [i16::MIN, i16::MAX, -1, 0].into_iter().enumerate() {
        // Keep replay state independent per case so we validate dc_idx encoding,
        // not duplicate-handshake rejection behavior.
        let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 12345 + idx as u16);
        let handshake = make_valid_mtproto_handshake(secret_hex, ProtoTag::Secure, extreme_dc);
        let res = handle_mtproto_handshake(
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

        match res {
            HandshakeResult::Success((_, _, success)) => {
                assert_eq!(
                    success.dc_idx, extreme_dc,
                    "Extreme DC index {} must serialize/deserialize perfectly",
                    extreme_dc
                );
            }
            _ => panic!(
                "MTProto handshake with extreme DC index {} failed",
                extreme_dc
            ),
        }
    }
}

#[tokio::test]
async fn alpn_strict_case_and_padding_rejection() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret = [0x33u8; 16];
    let mut config = test_config_with_secret_hex("33333333333333333333333333333333");
    config.censorship.alpn_enforce = true;
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "192.0.2.3:12345".parse().unwrap();

    let bad_alpns: &[&[u8]] = &[b"H2", b"h2\0", b" http/1.1", b"http/1.1\n"];

    for bad_alpn in bad_alpns {
        let handshake = make_valid_tls_client_hello_with_alpn(&secret, 0, &[*bad_alpn]);
        let res = handle_tls_handshake(
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
            matches!(res, HandshakeResult::BadClient { .. }),
            "ALPN strict enforcement must reject {:?}",
            bad_alpn
        );
    }
}

#[test]
fn ipv4_mapped_ipv6_bucketing_anomaly() {
    let ipv4_mapped_1 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201));
    let ipv4_mapped_2 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc633, 0x6402));

    let norm_1 = normalize_auth_probe_ip(ipv4_mapped_1);
    let norm_2 = normalize_auth_probe_ip(ipv4_mapped_2);

    assert_eq!(
        norm_1, norm_2,
        "IPv4-mapped IPv6 addresses must collapse into the same /64 bucket (::0)"
    );
    assert_eq!(
        norm_1,
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
        "The bucket must be exactly ::0"
    );
}

// --- Category 2: Adversarial & Black Hat ---

#[tokio::test]
async fn mtproto_invalid_ciphertext_does_not_poison_replay_cache() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret_hex = "55555555555555555555555555555555";
    let config = test_config_with_secret_hex(secret_hex);
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let peer: SocketAddr = "192.0.2.5:12345".parse().unwrap();

    let valid_handshake = make_valid_mtproto_handshake(secret_hex, ProtoTag::Secure, 1);
    let mut invalid_handshake = valid_handshake;
    invalid_handshake[SKIP_LEN + PREKEY_LEN + IV_LEN + 1] ^= 0xFF;

    let res_invalid = handle_mtproto_handshake(
        &invalid_handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        false,
        None,
    )
    .await;
    assert!(matches!(res_invalid, HandshakeResult::BadClient { .. }));

    let res_valid = handle_mtproto_handshake(
        &valid_handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        false,
        None,
    )
    .await;
    assert!(
        matches!(res_valid, HandshakeResult::Success(_)),
        "Invalid MTProto ciphertext must not poison the replay cache"
    );
}

#[tokio::test]
async fn tls_invalid_session_does_not_poison_replay_cache() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret = [0x66u8; 16];
    let config = test_config_with_secret_hex("66666666666666666666666666666666");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "192.0.2.6:12345".parse().unwrap();

    let valid_handshake = make_valid_tls_handshake(&secret, 0);
    let mut invalid_handshake = valid_handshake.clone();
    let session_idx = tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1;
    invalid_handshake[session_idx] ^= 0xFF;

    let res_invalid = handle_tls_handshake(
        &invalid_handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;
    assert!(matches!(res_invalid, HandshakeResult::BadClient { .. }));

    let res_valid = handle_tls_handshake(
        &valid_handshake,
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
        matches!(res_valid, HandshakeResult::Success(_)),
        "Invalid TLS payload must not poison the replay cache"
    );
}

#[tokio::test]
async fn server_hello_delay_timing_neutrality_on_hmac_failure() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret = [0x77u8; 16];
    let mut config = test_config_with_secret_hex("77777777777777777777777777777777");
    config.censorship.server_hello_delay_min_ms = 50;
    config.censorship.server_hello_delay_max_ms = 50;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "192.0.2.7:12345".parse().unwrap();

    let mut invalid_handshake = make_valid_tls_handshake(&secret, 0);
    invalid_handshake[tls::TLS_DIGEST_POS] ^= 0xFF;

    let start = Instant::now();
    let res = handle_tls_handshake(
        &invalid_handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;
    let elapsed = start.elapsed();

    assert!(matches!(res, HandshakeResult::BadClient { .. }));
    assert!(
        elapsed >= Duration::from_millis(45),
        "Invalid HMAC must still incur the configured ServerHello delay to prevent timing side-channels"
    );
}

#[tokio::test]
async fn server_hello_delay_inversion_resilience() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret = [0x88u8; 16];
    let mut config = test_config_with_secret_hex("88888888888888888888888888888888");
    config.censorship.server_hello_delay_min_ms = 100;
    config.censorship.server_hello_delay_max_ms = 10;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "192.0.2.8:12345".parse().unwrap();

    let valid_handshake = make_valid_tls_handshake(&secret, 0);

    let start = Instant::now();
    let res = handle_tls_handshake(
        &valid_handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;
    let elapsed = start.elapsed();

    assert!(matches!(res, HandshakeResult::Success(_)));
    assert!(
        elapsed >= Duration::from_millis(90),
        "Delay logic must gracefully handle min > max inversions via max.max(min)"
    );
}

#[tokio::test]
async fn mixed_valid_and_invalid_user_secrets_configuration() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();
    let _warn_guard = warned_secrets_test_lock().lock().unwrap();
    clear_warned_secrets_for_testing();

    let mut config = ProxyConfig::default();
    config.access.ignore_time_skew = true;

    for i in 0..9 {
        let bad_secret = if i % 2 == 0 { "badhex!" } else { "1122" };
        config
            .access
            .users
            .insert(format!("bad_user_{}", i), bad_secret.to_string());
    }
    let valid_secret_hex = "99999999999999999999999999999999";
    config
        .access
        .users
        .insert("good_user".to_string(), valid_secret_hex.to_string());
    config.general.modes.secure = true;
    config.general.modes.classic = true;
    config.general.modes.tls = true;

    let secret = [0x99u8; 16];
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "192.0.2.9:12345".parse().unwrap();

    let valid_handshake = make_valid_tls_handshake(&secret, 0);

    let res = handle_tls_handshake(
        &valid_handshake,
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
        matches!(res, HandshakeResult::Success(_)),
        "Proxy must gracefully skip invalid secrets and authenticate the valid one"
    );
}

#[tokio::test]
async fn tls_emulation_fallback_when_cache_missing() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret = [0xAAu8; 16];
    let mut config = test_config_with_secret_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    config.censorship.tls_emulation = true;
    config.general.modes.tls = true;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "192.0.2.10:12345".parse().unwrap();

    let valid_handshake = make_valid_tls_handshake(&secret, 0);

    let res = handle_tls_handshake(
        &valid_handshake,
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
        matches!(res, HandshakeResult::Success(_)),
        "TLS emulation must gracefully fall back to standard ServerHello if cache is missing"
    );
}

#[tokio::test]
async fn classic_mode_over_tls_transport_protocol_confusion() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let mut config = test_config_with_secret_hex(secret_hex);
    config.general.modes.classic = true;
    config.general.modes.tls = true;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let peer: SocketAddr = "192.0.2.11:12345".parse().unwrap();

    let handshake = make_valid_mtproto_handshake(secret_hex, ProtoTag::Intermediate, 1);

    let res = handle_mtproto_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        true,
        None,
    )
    .await;

    assert!(
        matches!(res, HandshakeResult::Success(_)),
        "Intermediate tag over TLS must succeed if classic mode is enabled, locking in cross-transport behavior"
    );
}

#[test]
fn generate_tg_nonce_never_emits_reserved_bytes() {
    let client_enc_key = [0xCCu8; 32];
    let client_enc_iv = 123456789u128;
    let rng = SecureRandom::new();

    for _ in 0..10_000 {
        let (nonce, _, _, _, _) = generate_tg_nonce(
            ProtoTag::Secure,
            1,
            &client_enc_key,
            client_enc_iv,
            &rng,
            false,
        );

        assert!(
            !RESERVED_NONCE_FIRST_BYTES.contains(&nonce[0]),
            "Nonce must never start with reserved bytes"
        );
        let first_four: [u8; 4] = [nonce[0], nonce[1], nonce[2], nonce[3]];
        assert!(
            !RESERVED_NONCE_BEGINNINGS.contains(&first_four),
            "Nonce must never match reserved 4-byte beginnings"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dashmap_concurrent_saturation_stress() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let ip_a: IpAddr = "192.0.2.13".parse().unwrap();
    let ip_b: IpAddr = "198.51.100.13".parse().unwrap();
    let mut tasks = Vec::new();

    for i in 0..100 {
        let target_ip = if i % 2 == 0 { ip_a } else { ip_b };
        tasks.push(tokio::spawn(async move {
            for _ in 0..50 {
                auth_probe_record_failure(target_ip, Instant::now());
            }
        }));
    }

    for task in tasks {
        task.await
            .expect("Task panicked during concurrent DashMap stress");
    }

    assert!(
        auth_probe_is_throttled_for_testing(ip_a),
        "IP A must be throttled after concurrent stress"
    );
    assert!(
        auth_probe_is_throttled_for_testing(ip_b),
        "IP B must be throttled after concurrent stress"
    );
}

#[test]
fn prototag_invalid_bytes_fail_closed() {
    let invalid_tags: [[u8; 4]; 5] = [
        [0, 0, 0, 0],
        [0xFF, 0xFF, 0xFF, 0xFF],
        [0xDE, 0xAD, 0xBE, 0xEF],
        [0xDD, 0xDD, 0xDD, 0xDE],
        [0x11, 0x22, 0x33, 0x44],
    ];

    for tag in invalid_tags {
        assert_eq!(
            ProtoTag::from_bytes(tag),
            None,
            "Invalid ProtoTag bytes {:?} must fail closed",
            tag
        );
    }
}

#[test]
fn auth_probe_eviction_hash_collision_stress() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let state = auth_probe_state_map();
    let now = Instant::now();

    for i in 0..10_000u32 {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, (i >> 8) as u8, (i & 0xFF) as u8));
        auth_probe_record_failure_with_state(state, ip, now);
    }

    assert!(
        state.len() <= AUTH_PROBE_TRACK_MAX_ENTRIES,
        "Eviction logic must successfully bound the map size under heavy insertion stress"
    );
}

#[test]
fn encrypt_tg_nonce_with_ciphers_advances_counter_correctly() {
    let client_enc_key = [0xDDu8; 32];
    let client_enc_iv = 987654321u128;
    let rng = SecureRandom::new();

    let (nonce, _, _, _, _) = generate_tg_nonce(
        ProtoTag::Secure,
        2,
        &client_enc_key,
        client_enc_iv,
        &rng,
        false,
    );

    let (_, mut returned_encryptor, _) = encrypt_tg_nonce_with_ciphers(&nonce);
    let zeros = [0u8; 64];
    let returned_keystream = returned_encryptor.encrypt(&zeros);

    let enc_key_iv = &nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN];
    let mut expected_enc_key = [0u8; 32];
    expected_enc_key.copy_from_slice(&enc_key_iv[..KEY_LEN]);
    let mut expected_enc_iv_arr = [0u8; IV_LEN];
    expected_enc_iv_arr.copy_from_slice(&enc_key_iv[KEY_LEN..]);
    let expected_enc_iv = u128::from_be_bytes(expected_enc_iv_arr);

    let mut manual_encryptor = AesCtr::new(&expected_enc_key, expected_enc_iv);

    let mut manual_input = Vec::new();
    manual_input.extend_from_slice(&nonce);
    manual_input.extend_from_slice(&zeros);
    let manual_output = manual_encryptor.encrypt(&manual_input);

    assert_eq!(
        returned_keystream,
        &manual_output[64..128],
        "encrypt_tg_nonce_with_ciphers must correctly advance the AES-CTR counter by exactly the nonce length"
    );
}
