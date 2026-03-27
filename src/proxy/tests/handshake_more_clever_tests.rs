use super::*;
use crate::crypto::{AesCtr, sha256, sha256_hmac};
use crate::protocol::constants::{ProtoTag, RESERVED_NONCE_BEGINNINGS, RESERVED_NONCE_FIRST_BYTES};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Barrier;

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

// --- Category 1: Timing & Delay Invariants ---

#[tokio::test]
async fn server_hello_delay_bypassed_if_max_is_zero_despite_high_min() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret = [0x1Au8; 16];
    let mut config = test_config_with_secret_hex("1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a");
    config.censorship.server_hello_delay_min_ms = 5000;
    config.censorship.server_hello_delay_max_ms = 0;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "192.0.2.101:12345".parse().unwrap();

    let mut invalid_handshake = make_valid_tls_handshake(&secret, 0);
    invalid_handshake[tls::TLS_DIGEST_POS] ^= 0xFF;

    let fut = handle_tls_handshake(
        &invalid_handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    );

    // Deterministic assertion: with max_ms == 0 there must be no sleep path,
    // so the handshake should complete promptly under a generous timeout budget.
    let res = tokio::time::timeout(Duration::from_millis(250), fut)
        .await
        .expect("max_ms=0 should bypass artificial delay and complete quickly");

    assert!(matches!(res, HandshakeResult::BadClient { .. }));
}

#[test]
fn auth_probe_backoff_extreme_fail_streak_clamps_safely() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let state = auth_probe_state_map();
    let peer_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99));
    let now = Instant::now();

    state.insert(
        peer_ip,
        AuthProbeState {
            fail_streak: u32::MAX - 1,
            blocked_until: now,
            last_seen: now,
        },
    );

    auth_probe_record_failure_with_state(&state, peer_ip, now);

    let updated = state.get(&peer_ip).unwrap();
    assert_eq!(updated.fail_streak, u32::MAX);

    let expected_blocked_until = now + Duration::from_millis(AUTH_PROBE_BACKOFF_MAX_MS);
    assert_eq!(
        updated.blocked_until, expected_blocked_until,
        "Extreme fail streak must clamp cleanly to AUTH_PROBE_BACKOFF_MAX_MS"
    );
}

#[test]
fn generate_tg_nonce_cryptographic_uniqueness_and_entropy() {
    let client_enc_key = [0x2Bu8; 32];
    let client_enc_iv = 1337u128;
    let rng = SecureRandom::new();

    let mut nonces = HashSet::new();
    let mut total_set_bits = 0usize;
    let iterations = 5_000;

    for _ in 0..iterations {
        let (nonce, _, _, _, _) = generate_tg_nonce(
            ProtoTag::Secure,
            2,
            &client_enc_key,
            client_enc_iv,
            &rng,
            false,
        );

        for byte in nonce.iter() {
            total_set_bits += byte.count_ones() as usize;
        }

        assert!(
            nonces.insert(nonce),
            "generate_tg_nonce emitted a duplicate nonce! RNG is stuck."
        );
    }

    let total_bits = iterations * HANDSHAKE_LEN * 8;
    let ratio = (total_set_bits as f64) / (total_bits as f64);
    assert!(
        ratio > 0.48 && ratio < 0.52,
        "Nonce entropy is degraded. Set bit ratio: {}",
        ratio
    );
}

#[tokio::test]
async fn mtproto_multi_user_decryption_isolation() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let mut config = ProxyConfig::default();
    config.general.modes.secure = true;
    config.access.ignore_time_skew = true;

    config.access.users.insert(
        "user_a".to_string(),
        "11111111111111111111111111111111".to_string(),
    );
    config.access.users.insert(
        "user_b".to_string(),
        "22222222222222222222222222222222".to_string(),
    );
    let good_secret_hex = "33333333333333333333333333333333";
    config
        .access
        .users
        .insert("user_c".to_string(), good_secret_hex.to_string());

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let peer: SocketAddr = "192.0.2.104:12345".parse().unwrap();

    let valid_handshake = make_valid_mtproto_handshake(good_secret_hex, ProtoTag::Secure, 1);

    let res = handle_mtproto_handshake(
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

    match res {
        HandshakeResult::Success((_, _, success)) => {
            assert_eq!(
                success.user, "user_c",
                "Decryption attempts on previous users must not corrupt the handshake buffer for the valid user"
            );
        }
        _ => panic!(
            "Multi-user MTProto handshake failed. Decryption buffer might be mutating in place."
        ),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_secret_warning_lock_contention_and_bound() {
    let _guard = warned_secrets_test_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    clear_warned_secrets_for_testing();

    let tasks = 50;
    let iterations_per_task = 100;
    let barrier = Arc::new(Barrier::new(tasks));
    let mut handles = Vec::new();

    for t in 0..tasks {
        let b = barrier.clone();
        handles.push(tokio::spawn(async move {
            b.wait().await;
            for i in 0..iterations_per_task {
                let user_name = format!("contention_user_{}_{}", t, i);
                warn_invalid_secret_once(&user_name, "invalid_hex", ACCESS_SECRET_BYTES, None);
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let warned = INVALID_SECRET_WARNED.get().unwrap();
    let guard = warned
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    assert_eq!(
        guard.len(),
        WARNED_SECRET_MAX_ENTRIES,
        "Concurrent spam of invalid secrets must strictly bound the HashSet memory to WARNED_SECRET_MAX_ENTRIES"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mtproto_strict_concurrent_replay_race_condition() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret_hex = "4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A";
    let config = Arc::new(test_config_with_secret_hex(secret_hex));
    let replay_checker = Arc::new(ReplayChecker::new(4096, Duration::from_secs(60)));
    let valid_handshake = Arc::new(make_valid_mtproto_handshake(
        secret_hex,
        ProtoTag::Secure,
        1,
    ));

    let tasks = 100;
    let barrier = Arc::new(Barrier::new(tasks));
    let mut handles = Vec::new();

    for i in 0..tasks {
        let b = barrier.clone();
        let cfg = config.clone();
        let rc = replay_checker.clone();
        let hs = valid_handshake.clone();

        handles.push(tokio::spawn(async move {
            let peer = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, (i % 250) as u8)),
                10000 + i as u16,
            );
            b.wait().await;
            handle_mtproto_handshake(
                &hs,
                tokio::io::empty(),
                tokio::io::sink(),
                peer,
                &cfg,
                &rc,
                false,
                None,
            )
            .await
        }));
    }

    let mut successes = 0;
    let mut failures = 0;

    for handle in handles {
        match handle.await.unwrap() {
            HandshakeResult::Success(_) => successes += 1,
            HandshakeResult::BadClient { .. } => failures += 1,
            _ => panic!("Unexpected error result in concurrent MTProto replay test"),
        }
    }

    assert_eq!(
        successes, 1,
        "Replay cache race condition allowed multiple identical MTProto handshakes to succeed"
    );
    assert_eq!(
        failures,
        tasks - 1,
        "Replay cache failed to forcefully reject concurrent duplicates"
    );
}

#[tokio::test]
async fn tls_alpn_zero_length_protocol_handled_safely() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret = [0x5Bu8; 16];
    let mut config = test_config_with_secret_hex("5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b");
    config.censorship.alpn_enforce = true;
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "192.0.2.107:12345".parse().unwrap();

    let handshake =
        make_valid_tls_client_hello_with_sni_and_alpn(&secret, 0, "example.com", &[b""]);

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
        "0-length ALPN must be safely rejected without panicking"
    );
}

#[tokio::test]
async fn tls_sni_massive_hostname_does_not_panic() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret = [0x6Cu8; 16];
    let config = test_config_with_secret_hex("6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "192.0.2.108:12345".parse().unwrap();

    let massive_hostname = String::from_utf8(vec![b'a'; 65000]).unwrap();
    let handshake =
        make_valid_tls_client_hello_with_sni_and_alpn(&secret, 0, &massive_hostname, &[]);

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
        matches!(
            res,
            HandshakeResult::Success(_) | HandshakeResult::BadClient { .. }
        ),
        "Massive SNI hostname must be processed or ignored without stack overflow or panic"
    );
}

#[tokio::test]
async fn tls_progressive_truncation_fuzzing_no_panics() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret = [0x7Du8; 16];
    let config = test_config_with_secret_hex("7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "192.0.2.109:12345".parse().unwrap();

    let valid_handshake =
        make_valid_tls_client_hello_with_sni_and_alpn(&secret, 0, "example.com", &[b"h2"]);
    let full_len = valid_handshake.len();

    // Truncated corpus only: full_len is a valid baseline and should not be
    // asserted as BadClient in a truncation-specific test.
    for i in (0..full_len).rev() {
        let truncated = &valid_handshake[..i];
        let res = handle_tls_handshake(
            truncated,
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
            "Truncated TLS handshake at len {} must fail safely without panicking",
            i
        );
    }
}

#[tokio::test]
async fn mtproto_pure_entropy_fuzzing_no_panics() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let config = test_config_with_secret_hex("8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let peer: SocketAddr = "192.0.2.110:12345".parse().unwrap();

    let mut seeded = StdRng::seed_from_u64(0xDEADBEEFCAFE);

    for _ in 0..10_000 {
        let mut noise = [0u8; HANDSHAKE_LEN];
        seeded.fill_bytes(&mut noise);

        let res = handle_mtproto_handshake(
            &noise,
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
            matches!(res, HandshakeResult::BadClient { .. }),
            "Pure entropy MTProto payload must fail closed and never panic"
        );
    }
}

#[test]
fn decode_user_secret_odd_length_hex_rejection() {
    let _guard = warned_secrets_test_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    clear_warned_secrets_for_testing();

    let mut config = ProxyConfig::default();
    config.access.users.clear();
    config.access.users.insert(
        "odd_user".to_string(),
        "1234567890123456789012345678901".to_string(),
    );

    let decoded = decode_user_secrets(&config, None);
    assert!(
        decoded.is_empty(),
        "Odd-length hex string must be gracefully rejected by hex::decode without unwrapping"
    );
}

#[test]
fn saturation_grace_pre_existing_high_fail_streak_immediate_throttle() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let state = auth_probe_state_map();
    let peer_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 112));
    let now = Instant::now();

    let extreme_streak = AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS + 5;
    state.insert(
        peer_ip,
        AuthProbeState {
            fail_streak: extreme_streak,
            blocked_until: now + Duration::from_secs(5),
            last_seen: now,
        },
    );

    {
        let mut guard = auth_probe_saturation_state_lock();
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(5),
            last_seen: now,
        });
    }

    let is_throttled = auth_probe_should_apply_preauth_throttle(peer_ip, now);
    assert!(
        is_throttled,
        "A peer with a pre-existing high fail streak must be immediately throttled when saturation begins, receiving no unearned grace period"
    );
}

#[test]
fn auth_probe_saturation_note_resets_retention_window() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let base_time = Instant::now();

    auth_probe_note_saturation(base_time);
    let later = base_time + Duration::from_secs(AUTH_PROBE_TRACK_RETENTION_SECS - 1);
    auth_probe_note_saturation(later);

    let check_time = base_time + Duration::from_secs(AUTH_PROBE_TRACK_RETENTION_SECS + 5);

    // This call may return false if backoff has elapsed, but it must not clear
    // the saturation state because `later` refreshed last_seen.
    let _ = auth_probe_saturation_is_throttled_at_for_testing(check_time);
    let guard = auth_probe_saturation_state_lock();
    assert!(
        guard.is_some(),
        "Ongoing saturation notes must refresh last_seen so saturation state remains retained past the original window"
    );
}

#[test]
fn mtproto_classic_tags_rejected_when_only_secure_mode_enabled() {
    let mut config = ProxyConfig::default();
    config.general.modes.classic = false;
    config.general.modes.secure = true;
    config.general.modes.tls = false;

    assert!(!mode_enabled_for_proto(&config, ProtoTag::Abridged, false));
    assert!(!mode_enabled_for_proto(
        &config,
        ProtoTag::Intermediate,
        false
    ));
}

#[test]
fn mtproto_secure_tag_rejected_when_only_classic_mode_enabled() {
    let mut config = ProxyConfig::default();
    config.general.modes.classic = true;
    config.general.modes.secure = false;
    config.general.modes.tls = false;

    assert!(!mode_enabled_for_proto(&config, ProtoTag::Secure, false));
}

#[test]
fn ipv6_localhost_and_unspecified_normalization() {
    let localhost = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    let unspecified = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));

    let norm_local = normalize_auth_probe_ip(localhost);
    let norm_unspec = normalize_auth_probe_ip(unspecified);

    let expected_bucket = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));

    assert_eq!(norm_local, expected_bucket);
    assert_eq!(norm_unspec, expected_bucket);
}
