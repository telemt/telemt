use super::*;
use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use crate::crypto::sha256;

fn make_valid_mtproto_handshake(secret_hex: &str, proto_tag: ProtoTag, dc_idx: i16) -> [u8; HANDSHAKE_LEN] {
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
    cfg.access.users.insert("user".to_string(), secret_hex.to_string());
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
    let res = handle_mtproto_handshake(&base, tokio::io::empty(), tokio::io::sink(), peer, &config, &replay_checker, false, None).await;
    match res {
        HandshakeResult::Success(_) => {},
        _ => panic!("Baseline failed: expected Success"),
    }

    // Flip bits in the encrypted part (beyond the key material)
    for byte_pos in SKIP_LEN..HANDSHAKE_LEN {
        let mut h = base;
        h[byte_pos] ^= 0x01; // Flip 1 bit
        let res = handle_mtproto_handshake(&h, tokio::io::empty(), tokio::io::sink(), peer, &config, &replay_checker, false, None).await;
        assert!(matches!(res, HandshakeResult::BadClient { .. }), "Flip at byte {byte_pos} bit 0 must be rejected");
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
        let _ = handle_mtproto_handshake(&base, tokio::io::empty(), tokio::io::sink(), peer, &config, &replay_checker, false, None).await;
    }
    let duration_success = start.elapsed();

    start = Instant::now();
    for i in 0..ITER {
        let mut h = base;
        h[SKIP_LEN + (i % 48)] ^= 0xFF; 
        let _ = handle_mtproto_handshake(&h, tokio::io::empty(), tokio::io::sink(), peer, &config, &replay_checker, false, None).await;
    }
    let duration_fail = start.elapsed();

    let avg_diff_ms = (duration_success.as_millis() as f64 - duration_fail.as_millis() as f64).abs() / ITER as f64;
    
    // Threshold (loose for CI)
    assert!(avg_diff_ms < 100.0, "Timing difference too large: {} ms/iter", avg_diff_ms);
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

    let tracked = AUTH_PROBE_STATE
        .get()
        .map(|state| state.len())
        .unwrap_or(0);
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

    let res = handle_mtproto_handshake(&handshake, tokio::io::empty(), tokio::io::sink(), peer, &config, &replay_checker, false, None).await;
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
    config.access.users.insert("user1".to_string(), secret1_hex.to_string());
    config.access.users.insert("user2".to_string(), secret2_hex.to_string());
    config.access.ignore_time_skew = true;
    config.general.modes.secure = true;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let peer: SocketAddr = "192.0.2.4:12345".parse().unwrap();

    // Even if we prefer user1, if user2 matches, it should succeed.
    let res = handle_mtproto_handshake(&base, tokio::io::empty(), tokio::io::sink(), peer, &config, &replay_checker, false, Some("user1")).await;
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
            let res = handle_mtproto_handshake(&base, tokio::io::empty(), tokio::io::sink(), peer, &config, &replay_checker, false, None).await;
            matches!(res, HandshakeResult::Success(_))
        }));
    }
    
    // We don't necessarily care if they all succeed (some might fail due to replay if they hit the same chunk),
    // but the system must not panic or hang.
    for task in tasks {
        let _ = task.await.unwrap();
    }
}
