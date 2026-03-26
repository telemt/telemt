use super::*;
use crate::config::ProxyConfig;
use crate::crypto::AesCtr;
use crate::crypto::sha256;
use crate::protocol::constants::ProtoTag;
use crate::stats::ReplayChecker;
use std::net::SocketAddr;
use std::sync::MutexGuard;
use tokio::time::{Duration as TokioDuration, timeout};

fn make_mtproto_handshake_with_proto_bytes(
    secret_hex: &str,
    proto_bytes: [u8; 4],
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
    target_plain[PROTO_TAG_POS..PROTO_TAG_POS + 4].copy_from_slice(&proto_bytes);
    target_plain[DC_IDX_POS..DC_IDX_POS + 2].copy_from_slice(&dc_idx.to_le_bytes());

    for idx in PROTO_TAG_POS..HANDSHAKE_LEN {
        handshake[idx] = target_plain[idx] ^ keystream[idx];
    }

    handshake
}

fn make_valid_mtproto_handshake(
    secret_hex: &str,
    proto_tag: ProtoTag,
    dc_idx: i16,
) -> [u8; HANDSHAKE_LEN] {
    make_mtproto_handshake_with_proto_bytes(secret_hex, proto_tag.to_bytes(), dc_idx)
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

fn auth_probe_test_guard() -> MutexGuard<'static, ()> {
    auth_probe_test_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[tokio::test]
async fn mtproto_handshake_duplicate_digest_is_replayed_on_second_attempt() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret_hex = "11223344556677889900aabbccddeeff";
    let base = make_valid_mtproto_handshake(secret_hex, ProtoTag::Secure, 2);
    let config = test_config_with_secret_hex(secret_hex);
    let replay_checker = ReplayChecker::new(128, TokioDuration::from_secs(60));
    let peer: SocketAddr = "192.0.2.1:12345".parse().unwrap();

    let first = handle_mtproto_handshake(
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
    assert!(matches!(first, HandshakeResult::Success(_)));

    let second = handle_mtproto_handshake(
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
    assert!(matches!(second, HandshakeResult::BadClient { .. }));

    clear_auth_probe_state_for_testing();
}

#[tokio::test]
async fn mtproto_handshake_fuzz_corpus_never_panics_and_stays_fail_closed() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret_hex = "00112233445566778899aabbccddeeff";
    let base = make_valid_mtproto_handshake(secret_hex, ProtoTag::Secure, 1);
    let config = test_config_with_secret_hex(secret_hex);
    let replay_checker = ReplayChecker::new(128, TokioDuration::from_secs(60));
    let peer: SocketAddr = "192.0.2.2:54321".parse().unwrap();

    let mut corpus = Vec::<[u8; HANDSHAKE_LEN]>::new();

    corpus.push(make_mtproto_handshake_with_proto_bytes(
        secret_hex,
        [0x00, 0x00, 0x00, 0x00],
        1,
    ));
    corpus.push(make_mtproto_handshake_with_proto_bytes(
        secret_hex,
        [0xff, 0xff, 0xff, 0xff],
        1,
    ));
    corpus.push(make_valid_mtproto_handshake(
        "ffeeddccbbaa99887766554433221100",
        ProtoTag::Secure,
        1,
    ));

    let mut seed = 0xF0F0_F00D_BAAD_CAFEu64;
    for _ in 0..32 {
        let mut mutated = base;
        for _ in 0..4 {
            seed = seed
                .wrapping_mul(2862933555777941757)
                .wrapping_add(3037000493);
            let idx = SKIP_LEN + (seed as usize % (PREKEY_LEN + IV_LEN));
            mutated[idx] ^= ((seed >> 19) as u8).wrapping_add(1);
        }
        corpus.push(mutated);
    }

    for (idx, input) in corpus.into_iter().enumerate() {
        let result = timeout(
            TokioDuration::from_secs(1),
            handle_mtproto_handshake(
                &input,
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
        .expect("fuzzed handshake must complete in time");

        assert!(
            matches!(result, HandshakeResult::BadClient { .. }),
            "corpus item {idx} must fail closed"
        );
    }

    clear_auth_probe_state_for_testing();
}

#[tokio::test]
async fn mtproto_handshake_mixed_corpus_never_panics_and_exact_duplicates_are_rejected() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let secret_hex = "99887766554433221100ffeeddccbbaa";
    let base = make_valid_mtproto_handshake(secret_hex, ProtoTag::Secure, 4);
    let config = test_config_with_secret_hex(secret_hex);
    let replay_checker = ReplayChecker::new(256, TokioDuration::from_secs(60));
    let peer: SocketAddr = "192.0.2.44:45444".parse().unwrap();

    let first = timeout(
        TokioDuration::from_secs(1),
        handle_mtproto_handshake(
            &base,
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
    .expect("base handshake must not hang");
    assert!(matches!(first, HandshakeResult::Success(_)));

    let replay = timeout(
        TokioDuration::from_secs(1),
        handle_mtproto_handshake(
            &base,
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
    .expect("duplicate handshake must not hang");
    assert!(matches!(replay, HandshakeResult::BadClient { .. }));

    let mut corpus = Vec::<[u8; HANDSHAKE_LEN]>::new();

    let mut prekey_flip = base;
    prekey_flip[SKIP_LEN] ^= 0x80;
    corpus.push(prekey_flip);

    let mut iv_flip = base;
    iv_flip[SKIP_LEN + PREKEY_LEN] ^= 0x01;
    corpus.push(iv_flip);

    let mut tail_flip = base;
    tail_flip[SKIP_LEN + PREKEY_LEN + IV_LEN - 1] ^= 0x40;
    corpus.push(tail_flip);

    let mut seed = 0xBADC_0FFE_EE11_4242u64;
    for _ in 0..24 {
        let mut mutated = base;
        for _ in 0..3 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let idx = SKIP_LEN + (seed as usize % (PREKEY_LEN + IV_LEN));
            mutated[idx] ^= ((seed >> 16) as u8).wrapping_add(1);
        }
        corpus.push(mutated);
    }

    for (idx, input) in corpus.iter().enumerate() {
        let result = timeout(
            TokioDuration::from_secs(1),
            handle_mtproto_handshake(
                input,
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
        .expect("fuzzed handshake must complete in time");

        assert!(
            matches!(result, HandshakeResult::BadClient { .. }),
            "mixed corpus item {idx} must fail closed"
        );
    }

    clear_auth_probe_state_for_testing();
}
