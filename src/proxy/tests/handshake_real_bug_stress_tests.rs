use super::*;
use crate::crypto::{AesCtr, SecureRandom, sha256, sha256_hmac};
use crate::protocol::constants::{ProtoTag, TLS_RECORD_HANDSHAKE, TLS_VERSION};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Barrier;

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

#[tokio::test]
async fn tls_alpn_reject_does_not_pollute_replay_cache() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret = [0x11u8; 16];
    let mut config = test_config_with_secret_hex("11111111111111111111111111111111");
    config.censorship.alpn_enforce = true;

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "192.0.2.201:12345".parse().unwrap();

    let handshake = make_valid_tls_client_hello_with_alpn(&secret, 0, &[b"h3"]);
    let before = replay_checker.stats();

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

    let after = replay_checker.stats();

    assert!(matches!(res, HandshakeResult::BadClient { .. }));
    assert_eq!(
        before.total_additions, after.total_additions,
        "ALPN policy reject must not add TLS digest into replay cache"
    );
}

#[tokio::test]
async fn tls_truncated_session_id_len_fails_closed_without_panic() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let config = test_config_with_secret_hex("33333333333333333333333333333333");
    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "192.0.2.203:12345".parse().unwrap();

    let min_len = tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1;
    let mut malicious = vec![0x42u8; min_len];
    malicious[min_len - 1] = u8::MAX;

    let res = handle_tls_handshake(
        &malicious,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &config,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(res, HandshakeResult::BadClient { .. }));
}

#[test]
fn auth_probe_eviction_identical_timestamps_keeps_map_bounded() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let state = auth_probe_state_map();
    let same = Instant::now();

    for i in 0..AUTH_PROBE_TRACK_MAX_ENTRIES {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 1, (i >> 8) as u8, (i & 0xFF) as u8));
        state.insert(
            ip,
            AuthProbeState {
                fail_streak: 7,
                blocked_until: same,
                last_seen: same,
            },
        );
    }

    let new_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 21, 21));
    auth_probe_record_failure_with_state(state, new_ip, same + Duration::from_millis(1));

    assert_eq!(state.len(), AUTH_PROBE_TRACK_MAX_ENTRIES);
    assert!(state.contains_key(&new_ip));
}

#[test]
fn clear_auth_probe_state_recovers_from_poisoned_saturation_lock() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let saturation = auth_probe_saturation_state();
    let poison_thread = std::thread::spawn(move || {
        let _hold = saturation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        panic!("intentional poison for regression coverage");
    });
    let _ = poison_thread.join();

    clear_auth_probe_state_for_testing();

    let guard = auth_probe_saturation_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(guard.is_none());
}

#[tokio::test]
async fn mtproto_invalid_length_secret_is_ignored_and_valid_user_still_auths() {
    let _probe_guard = auth_probe_test_guard();
    let _warn_guard = warned_secrets_test_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    clear_auth_probe_state_for_testing();
    clear_warned_secrets_for_testing();

    let mut config = ProxyConfig::default();
    config.general.modes.secure = true;
    config.access.ignore_time_skew = true;

    config.access.users.insert(
        "short_user".to_string(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
    );

    let valid_secret_hex = "77777777777777777777777777777777";
    config
        .access
        .users
        .insert("good_user".to_string(), valid_secret_hex.to_string());

    let replay_checker = ReplayChecker::new(128, Duration::from_secs(60));
    let peer: SocketAddr = "192.0.2.207:12345".parse().unwrap();
    let handshake = make_valid_mtproto_handshake(valid_secret_hex, ProtoTag::Secure, 1);

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

    assert!(matches!(res, HandshakeResult::Success(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saturation_grace_exhaustion_under_concurrency_keeps_peer_throttled() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let peer_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 80));
    let now = Instant::now();

    {
        let mut guard = auth_probe_saturation_state()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: now + Duration::from_secs(5),
            last_seen: now,
        });
    }

    let state = auth_probe_state_map();
    state.insert(
        peer_ip,
        AuthProbeState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS - 1,
            blocked_until: now,
            last_seen: now,
        },
    );

    let tasks = 32;
    let barrier = Arc::new(Barrier::new(tasks));
    let mut handles = Vec::new();

    for _ in 0..tasks {
        let b = barrier.clone();
        handles.push(tokio::spawn(async move {
            b.wait().await;
            auth_probe_record_failure(peer_ip, Instant::now());
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let final_state = state.get(&peer_ip).expect("state must exist");
    assert!(
        final_state.fail_streak
            >= AUTH_PROBE_BACKOFF_START_FAILS + AUTH_PROBE_SATURATION_GRACE_FAILS
    );
    assert!(auth_probe_should_apply_preauth_throttle(
        peer_ip,
        Instant::now()
    ));
}
