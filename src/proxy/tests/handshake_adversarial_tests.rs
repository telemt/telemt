use super::*;
use crate::crypto::sha256;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    cfg
}

// ------------------------------------------------------------------
// Mutational Bit-Flipping Tests (OWASP ASVS 5.1.4)
// ------------------------------------------------------------------

#[tokio::test]
async fn mtproto_handshake_bit_flip_anywhere_rejected() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret_hex = "11223344556677889900aabbccddeeff";
    let base = make_valid_mtproto_handshake(secret_hex, ProtoTag::Secure, 2);
    let config = test_config_with_secret_hex(secret_hex);
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let peer: SocketAddr = "192.0.2.1:12345".parse().unwrap();

    // Baseline check
    let res = handle_mtproto_handshake(
        &base,
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
        HandshakeResult::Success(_) => {}
        _ => panic!("Baseline failed: expected Success"),
    }

    // Flip bits in the encrypted part (beyond the key material)
    for byte_pos in SKIP_LEN..HANDSHAKE_LEN {
        let mut h = base;
        h[byte_pos] ^= 0x01; // Flip 1 bit
        let res = handle_mtproto_handshake(
            &h,
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
            "Flip at byte {byte_pos} bit 0 must be rejected"
        );
    }
}

// ------------------------------------------------------------------
// Adversarial Probing / Timing Neutrality (OWASP ASVS 5.1.7)
// ------------------------------------------------------------------

#[tokio::test]
async fn mtproto_handshake_timing_neutrality_mocked() {
    let secret_hex = "00112233445566778899aabbccddeeff";
    let base = make_valid_mtproto_handshake(secret_hex, ProtoTag::Secure, 1);
    let config = test_config_with_secret_hex(secret_hex);
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let peer: SocketAddr = "192.0.2.2:54321".parse().unwrap();

    const ITER: usize = 50;

    let mut start = Instant::now();
    for _ in 0..ITER {
        let _ = handle_mtproto_handshake(
            &base,
            tokio::io::empty(),
            tokio::io::sink(),
            peer,
            &config,
            &replay_checker,
            false,
            None,
        )
        .await;
    }
    let duration_success = start.elapsed();

    start = Instant::now();
    for i in 0..ITER {
        let mut h = base;
        h[SKIP_LEN + (i % 48)] ^= 0xFF;
        let _ = handle_mtproto_handshake(
            &h,
            tokio::io::empty(),
            tokio::io::sink(),
            peer,
            &config,
            &replay_checker,
            false,
            None,
        )
        .await;
    }
    let duration_fail = start.elapsed();

    let avg_diff_ms = (duration_success.as_millis() as f64 - duration_fail.as_millis() as f64)
        .abs()
        / ITER as f64;

    // Threshold (loose for CI)
    assert!(
        avg_diff_ms < 100.0,
        "Timing difference too large: {} ms/iter",
        avg_diff_ms
    );
}

// ------------------------------------------------------------------
// Stress Tests (OWASP ASVS 5.1.6)
// ------------------------------------------------------------------

#[tokio::test]
async fn auth_probe_throttle_saturation_stress() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let now = Instant::now();

    // Record enough failures for one IP to trigger backoff
    let target_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    for _ in 0..AUTH_PROBE_BACKOFF_START_FAILS {
        auth_probe_record_failure(target_ip, now);
    }

    assert!(auth_probe_is_throttled(target_ip, now));

    // Stress test with many unique IPs
    for i in 0..500u32 {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, (i % 256) as u8));
        auth_probe_record_failure(ip, now);
    }

    let tracked = AUTH_PROBE_STATE.get().map(|state| state.len()).unwrap_or(0);
    assert!(
        tracked <= AUTH_PROBE_TRACK_MAX_ENTRIES,
        "auth probe state grew past hard cap: {tracked} > {AUTH_PROBE_TRACK_MAX_ENTRIES}"
    );
}

#[tokio::test]
async fn mtproto_handshake_abridged_prefix_rejected() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let mut handshake = [0x5Au8; HANDSHAKE_LEN];
    handshake[0] = 0xef; // Abridged prefix
    let config = ProxyConfig::default();
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let peer: SocketAddr = "192.0.2.3:12345".parse().unwrap();

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
    // MTProxy stops immediately on 0xef
    assert!(matches!(res, HandshakeResult::BadClient { .. }));
}

#[tokio::test]
async fn mtproto_handshake_preferred_user_mismatch_continues() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret1_hex = "11111111111111111111111111111111";
    let secret2_hex = "22222222222222222222222222222222";

    let base = make_valid_mtproto_handshake(secret2_hex, ProtoTag::Secure, 1);
    let mut config = ProxyConfig::default();
    config
        .access
        .users
        .insert("user1".to_string(), secret1_hex.to_string());
    config
        .access
        .users
        .insert("user2".to_string(), secret2_hex.to_string());
    config.access.ignore_time_skew = true;
    config.general.modes.secure = true;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let peer: SocketAddr = "192.0.2.4:12345".parse().unwrap();

    // Even if we prefer user1, if user2 matches, it should succeed.
    let res = handle_mtproto_handshake(
        &base,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        false,
        Some("user1"),
    )
    .await;
    if let HandshakeResult::Success((_, _, success)) = res {
        assert_eq!(success.user, "user2");
    } else {
        panic!("Handshake failed even though user2 matched");
    }
}

#[tokio::test]
async fn mtproto_handshake_concurrent_flood_stability() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret_hex = "00112233445566778899aabbccddeeff";
    let base = make_valid_mtproto_handshake(secret_hex, ProtoTag::Secure, 1);
    let mut config = test_config_with_secret_hex(secret_hex);
    config.access.ignore_time_skew = true;
    let replay_checker = Arc::new(ReplayChecker::new(1024, Duration::from_secs(60)));
    let config = Arc::new(config);

    let mut tasks = Vec::new();
    for i in 0..50 {
        let base = base;
        let config = Arc::clone(&config);
        let replay_checker = Arc::clone(&replay_checker);
        let peer: SocketAddr = format!("192.0.2.{}:12345", (i % 254) + 1).parse().unwrap();

        tasks.push(tokio::spawn(async move {
            let res = handle_mtproto_handshake(
                &base,
                tokio::io::empty(),
                tokio::io::sink(),
                peer,
                &config,
                &replay_checker,
                false,
                None,
            )
            .await;
            matches!(res, HandshakeResult::Success(_))
        }));
    }

    // We don't necessarily care if they all succeed (some might fail due to replay if they hit the same chunk),
    // but the system must not panic or hang.
    for task in tasks {
        let _ = task.await.unwrap();
    }
}

#[tokio::test]
async fn mtproto_replay_is_rejected_across_distinct_peers() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret_hex = "0123456789abcdeffedcba9876543210";
    let handshake = make_valid_mtproto_handshake(secret_hex, ProtoTag::Secure, 2);
    let config = test_config_with_secret_hex(secret_hex);
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));

    let first_peer: SocketAddr = "198.51.100.10:41001".parse().unwrap();
    let second_peer: SocketAddr = "198.51.100.11:41002".parse().unwrap();

    let first = handle_mtproto_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        first_peer,
        &config,
        &replay_checker,
        false,
        None,
    )
    .await;
    assert!(matches!(first, HandshakeResult::Success(_)));

    let replay = handle_mtproto_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        second_peer,
        &config,
        &replay_checker,
        false,
        None,
    )
    .await;
    assert!(matches!(replay, HandshakeResult::BadClient { .. }));
}

#[tokio::test]
async fn mtproto_blackhat_mutation_corpus_never_panics_and_stays_fail_closed() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret_hex = "89abcdef012345670123456789abcdef";
    let base = make_valid_mtproto_handshake(secret_hex, ProtoTag::Secure, 2);
    let config = test_config_with_secret_hex(secret_hex);
    let replay_checker = ReplayChecker::new(8192, Duration::from_secs(60));

    for i in 0..512usize {
        let mut mutated = base;
        let pos = (SKIP_LEN + (i * 31) % (HANDSHAKE_LEN - SKIP_LEN)).min(HANDSHAKE_LEN - 1);
        mutated[pos] ^= ((i as u8) | 1).rotate_left((i % 8) as u32);
        let peer: SocketAddr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(198, 18, (i / 254) as u8, (i % 254 + 1) as u8)),
            42000 + (i % 1000) as u16,
        );

        let res = tokio::time::timeout(
            Duration::from_millis(250),
            handle_mtproto_handshake(
                &mutated,
                tokio::io::empty(),
                tokio::io::sink(),
                peer,
                &config,
                &replay_checker,
                false,
                None,
            ),
        )
        .await
        .expect("fuzzed mutation must complete in bounded time");

        assert!(
            matches!(
                res,
                HandshakeResult::BadClient { .. } | HandshakeResult::Success(_)
            ),
            "mutation corpus must stay within explicit handshake outcomes"
        );
    }
}

#[tokio::test]
async fn auth_probe_success_clears_throttled_peer_state() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let target_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 90));
    let now = Instant::now();
    for _ in 0..AUTH_PROBE_BACKOFF_START_FAILS {
        auth_probe_record_failure(target_ip, now);
    }
    assert!(auth_probe_is_throttled(target_ip, now));

    auth_probe_record_success(target_ip);
    assert!(
        !auth_probe_is_throttled(target_ip, now + Duration::from_millis(1)),
        "successful auth must clear per-peer throttle state"
    );
}

#[tokio::test]
async fn mtproto_invalid_storm_over_cap_keeps_probe_map_hard_bounded() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret_hex = "00112233445566778899aabbccddeeff";
    let mut invalid = make_valid_mtproto_handshake(secret_hex, ProtoTag::Secure, 2);
    invalid[SKIP_LEN + 3] ^= 0xff;

    let config = test_config_with_secret_hex(secret_hex);
    let replay_checker = ReplayChecker::new(64, Duration::from_secs(60));

    for i in 0..(AUTH_PROBE_TRACK_MAX_ENTRIES + 512) {
        let peer: SocketAddr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                10,
                (i / 65535) as u8,
                ((i / 255) % 255) as u8,
                (i % 255 + 1) as u8,
            )),
            43000 + (i % 20000) as u16,
        );
        let res = handle_mtproto_handshake(
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
        assert!(matches!(res, HandshakeResult::BadClient { .. }));
    }

    let tracked = AUTH_PROBE_STATE.get().map(|state| state.len()).unwrap_or(0);
    assert!(
        tracked <= AUTH_PROBE_TRACK_MAX_ENTRIES,
        "probe map must remain bounded under invalid storm: {tracked}"
    );
}

#[tokio::test]
async fn mtproto_property_style_multi_bit_mutations_fail_closed_or_auth_only() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret_hex = "f0e1d2c3b4a5968778695a4b3c2d1e0f";
    let base = make_valid_mtproto_handshake(secret_hex, ProtoTag::Secure, 2);
    let config = test_config_with_secret_hex(secret_hex);
    let replay_checker = ReplayChecker::new(10_000, Duration::from_secs(60));

    let mut seed: u64 = 0xC0FF_EE12_3456_789A;
    for i in 0..2_048usize {
        let mut mutated = base;
        for _ in 0..4 {
            seed ^= seed << 7;
            seed ^= seed >> 9;
            seed ^= seed << 8;
            let idx = SKIP_LEN + (seed as usize % (HANDSHAKE_LEN - SKIP_LEN));
            mutated[idx] ^= ((seed >> 11) as u8).wrapping_add(1);
        }

        let peer: SocketAddr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 123, (i / 254) as u8, (i % 254 + 1) as u8)),
            45000 + (i % 2000) as u16,
        );

        let outcome = tokio::time::timeout(
            Duration::from_millis(250),
            handle_mtproto_handshake(
                &mutated,
                tokio::io::empty(),
                tokio::io::sink(),
                peer,
                &config,
                &replay_checker,
                false,
                None,
            ),
        )
        .await
        .expect("mutation iteration must complete in bounded time");

        assert!(
            matches!(
                outcome,
                HandshakeResult::BadClient { .. } | HandshakeResult::Success(_)
            ),
            "mutations must remain fail-closed/auth-only"
        );
    }
}

#[tokio::test]
#[ignore = "heavy soak; run manually"]
async fn mtproto_blackhat_20k_mutation_soak_never_panics() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let base = make_valid_mtproto_handshake(secret_hex, ProtoTag::Secure, 2);
    let config = test_config_with_secret_hex(secret_hex);
    let replay_checker = ReplayChecker::new(50_000, Duration::from_secs(120));

    let mut seed: u64 = 0xA5A5_5A5A_DEAD_BEEF;
    for i in 0..20_000usize {
        let mut mutated = base;
        for _ in 0..3 {
            seed ^= seed << 7;
            seed ^= seed >> 9;
            seed ^= seed << 8;
            let idx = SKIP_LEN + (seed as usize % (HANDSHAKE_LEN - SKIP_LEN));
            mutated[idx] ^= ((seed >> 19) as u8).wrapping_add(1);
        }

        let peer: SocketAddr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(172, 31, (i / 254) as u8, (i % 254 + 1) as u8)),
            47000 + (i % 15000) as u16,
        );

        let _ = tokio::time::timeout(
            Duration::from_millis(250),
            handle_mtproto_handshake(
                &mutated,
                tokio::io::empty(),
                tokio::io::sink(),
                peer,
                &config,
                &replay_checker,
                false,
                None,
            ),
        )
        .await
        .expect("soak mutation must complete in bounded time");
    }
}
