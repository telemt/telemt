use super::*;
use crate::crypto::{AesCtr, SecureRandom, sha256, sha256_hmac};
use crate::protocol::constants::{ProtoTag, TLS_RECORD_HANDSHAKE, TLS_VERSION};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

fn auth_probe_test_guard() -> std::sync::MutexGuard<'static, ()> {
    auth_probe_test_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn make_valid_mtproto_handshake(
    secret_hex: &str,
    proto_tag: ProtoTag,
    dc_idx: i16,
    salt: u8,
) -> [u8; HANDSHAKE_LEN] {
    let secret = hex::decode(secret_hex).expect("secret hex must decode");
    let mut handshake = [0x5Au8; HANDSHAKE_LEN];

    for (idx, b) in handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]
        .iter_mut()
        .enumerate()
    {
        *b = (idx as u8).wrapping_add(1).wrapping_add(salt);
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

fn median_ns(samples: &mut [u128]) -> u128 {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

#[tokio::test]
#[ignore = "manual benchmark: timing-sensitive and host-dependent"]
async fn mtproto_user_scan_timing_manual_benchmark() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    const DECOY_USERS: usize = 8_000;
    const ITERATIONS: usize = 250;

    let preferred_user = "target_user";
    let target_secret_hex = "dededededededededededededededede";

    let mut config = ProxyConfig::default();
    config.general.modes.secure = true;
    config.access.ignore_time_skew = true;

    for i in 0..DECOY_USERS {
        config.access.users.insert(
            format!("decoy_{i}"),
            "00000000000000000000000000000000".to_string(),
        );
    }

    config
        .access
        .users
        .insert(preferred_user.to_string(), target_secret_hex.to_string());

    let replay_checker_preferred = ReplayChecker::new(65_536, Duration::from_secs(60));
    let replay_checker_full_scan = ReplayChecker::new(65_536, Duration::from_secs(60));
    let peer_a: SocketAddr = "192.0.2.241:12345".parse().unwrap();
    let peer_b: SocketAddr = "192.0.2.242:12345".parse().unwrap();

    let mut preferred_samples = Vec::with_capacity(ITERATIONS);
    let mut full_scan_samples = Vec::with_capacity(ITERATIONS);

    for i in 0..ITERATIONS {
        let handshake = make_valid_mtproto_handshake(
            target_secret_hex,
            ProtoTag::Secure,
            1 + i as i16,
            (i % 251) as u8,
        );

        let started_preferred = Instant::now();
        let preferred = handle_mtproto_handshake(
            &handshake,
            tokio::io::empty(),
            tokio::io::sink(),
            peer_a,
            &config,
            &replay_checker_preferred,
            false,
            Some(preferred_user),
        )
        .await;
        preferred_samples.push(started_preferred.elapsed().as_nanos());
        assert!(matches!(preferred, HandshakeResult::Success(_)));

        let started_scan = Instant::now();
        let full_scan = handle_mtproto_handshake(
            &handshake,
            tokio::io::empty(),
            tokio::io::sink(),
            peer_b,
            &config,
            &replay_checker_full_scan,
            false,
            None,
        )
        .await;
        full_scan_samples.push(started_scan.elapsed().as_nanos());
        assert!(matches!(full_scan, HandshakeResult::Success(_)));
    }

    let preferred_median = median_ns(&mut preferred_samples);
    let full_scan_median = median_ns(&mut full_scan_samples);

    let ratio = if preferred_median == 0 {
        0.0
    } else {
        full_scan_median as f64 / preferred_median as f64
    };

    println!(
        "manual timing benchmark: decoys={DECOY_USERS}, iters={ITERATIONS}, preferred_median_ns={preferred_median}, full_scan_median_ns={full_scan_median}, ratio={ratio:.3}"
    );

    assert!(
        full_scan_median >= preferred_median,
        "full user scan should not be faster than preferred-user path in this benchmark"
    );
}

#[tokio::test]
#[ignore = "manual benchmark: timing-sensitive and host-dependent"]
async fn tls_sni_preferred_vs_no_sni_fallback_manual_benchmark() {
    let _guard = auth_probe_test_guard();

    const DECOY_USERS: usize = 8_000;
    const ITERATIONS: usize = 250;

    let preferred_user = "user-b";
    let target_secret_hex = "abababababababababababababababab";
    let target_secret = [0xABu8; 16];

    let mut config = ProxyConfig::default();
    config.general.modes.tls = true;
    config.access.ignore_time_skew = true;

    for i in 0..DECOY_USERS {
        config.access.users.insert(
            format!("decoy_{i}"),
            "00000000000000000000000000000000".to_string(),
        );
    }

    config
        .access
        .users
        .insert(preferred_user.to_string(), target_secret_hex.to_string());

    let mut sni_samples = Vec::with_capacity(ITERATIONS);
    let mut no_sni_samples = Vec::with_capacity(ITERATIONS);

    for i in 0..ITERATIONS {
        let with_sni = make_valid_tls_client_hello_with_sni_and_alpn(
            &target_secret,
            i as u32,
            preferred_user,
            &[b"h2"],
        );
        let no_sni = make_valid_tls_handshake(&target_secret, (i as u32).wrapping_add(10_000));

        let started_sni = Instant::now();
        let sni_secrets = decode_user_secrets(&config, Some(preferred_user));
        let sni_result = tls::validate_tls_handshake_with_replay_window(
            &with_sni,
            &sni_secrets,
            config.access.ignore_time_skew,
            config.access.replay_window_secs,
        );
        sni_samples.push(started_sni.elapsed().as_nanos());
        assert!(sni_result.is_some());

        let started_no_sni = Instant::now();
        let no_sni_secrets = decode_user_secrets(&config, None);
        let no_sni_result = tls::validate_tls_handshake_with_replay_window(
            &no_sni,
            &no_sni_secrets,
            config.access.ignore_time_skew,
            config.access.replay_window_secs,
        );
        no_sni_samples.push(started_no_sni.elapsed().as_nanos());
        assert!(no_sni_result.is_some());
    }

    let sni_median = median_ns(&mut sni_samples);
    let no_sni_median = median_ns(&mut no_sni_samples);

    let ratio = if sni_median == 0 {
        0.0
    } else {
        no_sni_median as f64 / sni_median as f64
    };

    println!(
        "manual tls benchmark: decoys={DECOY_USERS}, iters={ITERATIONS}, sni_median_ns={sni_median}, no_sni_median_ns={no_sni_median}, ratio_no_sni_over_sni={ratio:.3}"
    );
}
