use super::*;
use crate::crypto::AesCtr;
use crate::crypto::SecureRandom;
use crate::stats::Stats;
use crate::stream::{BufferPool, PooledBuffer};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::io::duplex;
use tokio::sync::mpsc;
use tokio::time::{Duration as TokioDuration, timeout};

fn make_pooled_payload(data: &[u8]) -> PooledBuffer {
    let pool = Arc::new(BufferPool::with_config(data.len().max(1), 4));
    let mut payload = pool.get();
    payload.resize(data.len(), 0);
    payload[..data.len()].copy_from_slice(data);
    payload
}

#[tokio::test]
async fn write_client_payload_abridged_short_quickack_sets_flag_and_preserves_payload() {
    let (mut read_side, write_side) = duplex(4096);
    let key = [0u8; 32];
    let iv = 0u128;

    let mut writer = CryptoWriter::new(write_side, AesCtr::new(&key, iv), 8 * 1024);
    let mut decryptor = AesCtr::new(&key, iv);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();
    let payload = vec![0xA1, 0xB2, 0xC3, 0xD4, 0x10, 0x20, 0x30, 0x40];

    write_client_payload(
        &mut writer,
        ProtoTag::Abridged,
        RPC_FLAG_QUICKACK,
        &payload,
        &rng,
        &mut frame_buf,
    )
    .await
    .expect("abridged quickack payload should serialize");
    writer.flush().await.expect("flush must succeed");

    let mut encrypted = vec![0u8; 1 + payload.len()];
    read_side
        .read_exact(&mut encrypted)
        .await
        .expect("must read serialized abridged frame");
    let plaintext = decryptor.decrypt(&encrypted);

    assert_eq!(plaintext[0], 0x80 | ((payload.len() / 4) as u8));
    assert_eq!(&plaintext[1..], payload.as_slice());
}

#[tokio::test]
async fn write_client_payload_abridged_extended_header_is_encoded_correctly() {
    let (mut read_side, write_side) = duplex(16 * 1024);
    let key = [0u8; 32];
    let iv = 0u128;

    let mut writer = CryptoWriter::new(write_side, AesCtr::new(&key, iv), 8 * 1024);
    let mut decryptor = AesCtr::new(&key, iv);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();

    // Boundary where abridged switches to extended length encoding.
    let payload = vec![0x5Au8; 0x7f * 4];

    write_client_payload(
        &mut writer,
        ProtoTag::Abridged,
        RPC_FLAG_QUICKACK,
        &payload,
        &rng,
        &mut frame_buf,
    )
    .await
    .expect("extended abridged payload should serialize");
    writer.flush().await.expect("flush must succeed");

    let mut encrypted = vec![0u8; 4 + payload.len()];
    read_side
        .read_exact(&mut encrypted)
        .await
        .expect("must read serialized extended abridged frame");
    let plaintext = decryptor.decrypt(&encrypted);

    assert_eq!(plaintext[0], 0xff, "0x7f with quickack bit must be set");
    assert_eq!(&plaintext[1..4], &[0x7f, 0x00, 0x00]);
    assert_eq!(&plaintext[4..], payload.as_slice());
}

#[tokio::test]
async fn write_client_payload_abridged_misaligned_is_rejected_fail_closed() {
    let (_read_side, write_side) = duplex(1024);
    let key = [0u8; 32];
    let iv = 0u128;

    let mut writer = CryptoWriter::new(write_side, AesCtr::new(&key, iv), 8 * 1024);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();

    let err = write_client_payload(
        &mut writer,
        ProtoTag::Abridged,
        0,
        &[1, 2, 3],
        &rng,
        &mut frame_buf,
    )
    .await
    .expect_err("misaligned abridged payload must be rejected");

    let msg = format!("{err}");
    assert!(
        msg.contains("4-byte aligned"),
        "error should explain alignment contract, got: {msg}"
    );
}

#[tokio::test]
async fn write_client_payload_secure_misaligned_is_rejected_fail_closed() {
    let (_read_side, write_side) = duplex(1024);
    let key = [0u8; 32];
    let iv = 0u128;

    let mut writer = CryptoWriter::new(write_side, AesCtr::new(&key, iv), 8 * 1024);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();

    let err = write_client_payload(
        &mut writer,
        ProtoTag::Secure,
        0,
        &[9, 8, 7, 6, 5],
        &rng,
        &mut frame_buf,
    )
    .await
    .expect_err("misaligned secure payload must be rejected");

    let msg = format!("{err}");
    assert!(
        msg.contains("Secure payload must be 4-byte aligned"),
        "error should be explicit for fail-closed triage, got: {msg}"
    );
}

#[tokio::test]
async fn write_client_payload_intermediate_quickack_sets_length_msb() {
    let (mut read_side, write_side) = duplex(4096);
    let key = [0u8; 32];
    let iv = 0u128;

    let mut writer = CryptoWriter::new(write_side, AesCtr::new(&key, iv), 8 * 1024);
    let mut decryptor = AesCtr::new(&key, iv);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();
    let payload = b"hello-middle-relay";

    write_client_payload(
        &mut writer,
        ProtoTag::Intermediate,
        RPC_FLAG_QUICKACK,
        payload,
        &rng,
        &mut frame_buf,
    )
    .await
    .expect("intermediate quickack payload should serialize");
    writer.flush().await.expect("flush must succeed");

    let mut encrypted = vec![0u8; 4 + payload.len()];
    read_side
        .read_exact(&mut encrypted)
        .await
        .expect("must read intermediate frame");
    let plaintext = decryptor.decrypt(&encrypted);

    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&plaintext[..4]);
    let len_with_flags = u32::from_le_bytes(len_bytes);
    assert_ne!(len_with_flags & 0x8000_0000, 0, "quickack bit must be set");
    assert_eq!((len_with_flags & 0x7fff_ffff) as usize, payload.len());
    assert_eq!(&plaintext[4..], payload);
}

#[tokio::test]
async fn write_client_payload_secure_quickack_prefix_and_padding_bounds_hold() {
    let (mut read_side, write_side) = duplex(4096);
    let key = [0u8; 32];
    let iv = 0u128;

    let mut writer = CryptoWriter::new(write_side, AesCtr::new(&key, iv), 8 * 1024);
    let mut decryptor = AesCtr::new(&key, iv);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();
    let payload = vec![0x33u8; 100]; // 4-byte aligned as required by secure mode.

    write_client_payload(
        &mut writer,
        ProtoTag::Secure,
        RPC_FLAG_QUICKACK,
        &payload,
        &rng,
        &mut frame_buf,
    )
    .await
    .expect("secure quickack payload should serialize");
    writer.flush().await.expect("flush must succeed");

    // Secure mode adds 1..=3 bytes of randomized tail padding.
    let mut encrypted_header = [0u8; 4];
    read_side
        .read_exact(&mut encrypted_header)
        .await
        .expect("must read secure header");
    let decrypted_header = decryptor.decrypt(&encrypted_header);
    let header: [u8; 4] = decrypted_header
        .try_into()
        .expect("decrypted secure header must be 4 bytes");
    let wire_len_raw = u32::from_le_bytes(header);

    assert_ne!(
        wire_len_raw & 0x8000_0000,
        0,
        "secure quickack bit must be set"
    );

    let wire_len = (wire_len_raw & 0x7fff_ffff) as usize;
    assert!(wire_len >= payload.len());
    let padding_len = wire_len - payload.len();
    assert!(
        (1..=3).contains(&padding_len),
        "secure writer must add bounded random tail padding, got {padding_len}"
    );

    let mut encrypted_body = vec![0u8; wire_len];
    read_side
        .read_exact(&mut encrypted_body)
        .await
        .expect("must read secure body");
    let decrypted_body = decryptor.decrypt(&encrypted_body);
    assert_eq!(&decrypted_body[..payload.len()], payload.as_slice());
}

#[tokio::test]
#[ignore = "heavy: allocates >64MiB to validate abridged too-large fail-closed branch"]
async fn write_client_payload_abridged_too_large_is_rejected_fail_closed() {
    let (_read_side, write_side) = duplex(1024);
    let key = [0u8; 32];
    let iv = 0u128;

    let mut writer = CryptoWriter::new(write_side, AesCtr::new(&key, iv), 8 * 1024);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();

    // Exactly one 4-byte word above the encodable 24-bit abridged length range.
    let payload = vec![0x00u8; (1 << 24) * 4];
    let err = write_client_payload(
        &mut writer,
        ProtoTag::Abridged,
        0,
        &payload,
        &rng,
        &mut frame_buf,
    )
    .await
    .expect_err("oversized abridged payload must be rejected");

    let msg = format!("{err}");
    assert!(
        msg.contains("Abridged frame too large"),
        "error must clearly indicate oversize fail-close path, got: {msg}"
    );
}

#[tokio::test]
async fn write_client_ack_intermediate_is_little_endian() {
    let (mut read_side, write_side) = duplex(1024);
    let key = [0u8; 32];
    let iv = 0u128;
    let mut writer = CryptoWriter::new(write_side, AesCtr::new(&key, iv), 8 * 1024);
    let mut decryptor = AesCtr::new(&key, iv);

    write_client_ack(&mut writer, ProtoTag::Intermediate, 0x11_22_33_44)
        .await
        .expect("ack serialization should succeed");
    writer.flush().await.expect("flush must succeed");

    let mut encrypted = [0u8; 4];
    read_side
        .read_exact(&mut encrypted)
        .await
        .expect("must read ack bytes");
    let plain = decryptor.decrypt(&encrypted);
    assert_eq!(plain.as_slice(), &0x11_22_33_44u32.to_le_bytes());
}

#[tokio::test]
async fn write_client_ack_abridged_is_big_endian() {
    let (mut read_side, write_side) = duplex(1024);
    let key = [0u8; 32];
    let iv = 0u128;
    let mut writer = CryptoWriter::new(write_side, AesCtr::new(&key, iv), 8 * 1024);
    let mut decryptor = AesCtr::new(&key, iv);

    write_client_ack(&mut writer, ProtoTag::Abridged, 0xDE_AD_BE_EF)
        .await
        .expect("ack serialization should succeed");
    writer.flush().await.expect("flush must succeed");

    let mut encrypted = [0u8; 4];
    read_side
        .read_exact(&mut encrypted)
        .await
        .expect("must read ack bytes");
    let plain = decryptor.decrypt(&encrypted);
    assert_eq!(plain.as_slice(), &0xDE_AD_BE_EFu32.to_be_bytes());
}

#[tokio::test]
async fn write_client_payload_abridged_short_boundary_0x7e_is_single_byte_header() {
    let (mut read_side, write_side) = duplex(1024 * 1024);
    let key = [0u8; 32];
    let iv = 0u128;
    let mut writer = CryptoWriter::new(write_side, AesCtr::new(&key, iv), 8 * 1024);
    let mut decryptor = AesCtr::new(&key, iv);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();
    let payload = vec![0xABu8; 0x7e * 4];

    write_client_payload(
        &mut writer,
        ProtoTag::Abridged,
        0,
        &payload,
        &rng,
        &mut frame_buf,
    )
    .await
    .expect("boundary payload should serialize");
    writer.flush().await.expect("flush must succeed");

    let mut encrypted = vec![0u8; 1 + payload.len()];
    read_side.read_exact(&mut encrypted).await.unwrap();
    let plain = decryptor.decrypt(&encrypted);
    assert_eq!(plain[0], 0x7e);
    assert_eq!(&plain[1..], payload.as_slice());
}

#[tokio::test]
async fn write_client_payload_abridged_extended_without_quickack_has_clean_prefix() {
    let (mut read_side, write_side) = duplex(16 * 1024);
    let key = [0u8; 32];
    let iv = 0u128;
    let mut writer = CryptoWriter::new(write_side, AesCtr::new(&key, iv), 8 * 1024);
    let mut decryptor = AesCtr::new(&key, iv);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();
    let payload = vec![0x42u8; 0x80 * 4];

    write_client_payload(
        &mut writer,
        ProtoTag::Abridged,
        0,
        &payload,
        &rng,
        &mut frame_buf,
    )
    .await
    .expect("extended payload should serialize");
    writer.flush().await.expect("flush must succeed");

    let mut encrypted = vec![0u8; 4 + payload.len()];
    read_side.read_exact(&mut encrypted).await.unwrap();
    let plain = decryptor.decrypt(&encrypted);
    assert_eq!(plain[0], 0x7f);
    assert_eq!(&plain[1..4], &[0x80, 0x00, 0x00]);
    assert_eq!(&plain[4..], payload.as_slice());
}

#[tokio::test]
async fn write_client_payload_intermediate_zero_length_emits_header_only() {
    let (mut read_side, write_side) = duplex(1024);
    let key = [0u8; 32];
    let iv = 0u128;
    let mut writer = CryptoWriter::new(write_side, AesCtr::new(&key, iv), 8 * 1024);
    let mut decryptor = AesCtr::new(&key, iv);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();

    write_client_payload(
        &mut writer,
        ProtoTag::Intermediate,
        0,
        &[],
        &rng,
        &mut frame_buf,
    )
    .await
    .expect("zero-length intermediate payload should serialize");
    writer.flush().await.expect("flush must succeed");

    let mut encrypted = [0u8; 4];
    read_side.read_exact(&mut encrypted).await.unwrap();
    let plain = decryptor.decrypt(&encrypted);
    assert_eq!(plain.as_slice(), &[0, 0, 0, 0]);
}

#[tokio::test]
async fn write_client_payload_intermediate_ignores_unrelated_flags() {
    let (mut read_side, write_side) = duplex(1024);
    let key = [0u8; 32];
    let iv = 0u128;
    let mut writer = CryptoWriter::new(write_side, AesCtr::new(&key, iv), 8 * 1024);
    let mut decryptor = AesCtr::new(&key, iv);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();
    let payload = [7u8; 12];

    write_client_payload(
        &mut writer,
        ProtoTag::Intermediate,
        0x4000_0000,
        &payload,
        &rng,
        &mut frame_buf,
    )
    .await
    .expect("payload should serialize");
    writer.flush().await.expect("flush must succeed");

    let mut encrypted = [0u8; 16];
    read_side.read_exact(&mut encrypted).await.unwrap();
    let plain = decryptor.decrypt(&encrypted);
    let len = u32::from_le_bytes(plain[0..4].try_into().unwrap());
    assert_eq!(len, payload.len() as u32, "only quickack bit may affect header");
    assert_eq!(&plain[4..], payload.as_slice());
}

#[tokio::test]
async fn write_client_payload_secure_without_quickack_keeps_msb_clear() {
    let (mut read_side, write_side) = duplex(4096);
    let key = [0u8; 32];
    let iv = 0u128;
    let mut writer = CryptoWriter::new(write_side, AesCtr::new(&key, iv), 8 * 1024);
    let mut decryptor = AesCtr::new(&key, iv);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();
    let payload = [0x1Du8; 64];

    write_client_payload(
        &mut writer,
        ProtoTag::Secure,
        0,
        &payload,
        &rng,
        &mut frame_buf,
    )
    .await
    .expect("payload should serialize");
    writer.flush().await.expect("flush must succeed");

    let mut encrypted_header = [0u8; 4];
    read_side.read_exact(&mut encrypted_header).await.unwrap();
    let plain_header = decryptor.decrypt(&encrypted_header);
    let h: [u8; 4] = plain_header.as_slice().try_into().unwrap();
    let wire_len_raw = u32::from_le_bytes(h);
    assert_eq!(wire_len_raw & 0x8000_0000, 0, "quickack bit must stay clear");
}

#[tokio::test]
async fn secure_padding_light_fuzz_distribution_has_multiple_outcomes() {
    let (mut read_side, write_side) = duplex(256 * 1024);
    let key = [0u8; 32];
    let iv = 0u128;
    let mut writer = CryptoWriter::new(write_side, AesCtr::new(&key, iv), 8 * 1024);
    let mut decryptor = AesCtr::new(&key, iv);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();
    let payload = [0x55u8; 100];
    let mut seen = [false; 4];

    for _ in 0..96 {
        write_client_payload(
            &mut writer,
            ProtoTag::Secure,
            0,
            &payload,
            &rng,
            &mut frame_buf,
        )
        .await
        .expect("secure payload should serialize");
        writer.flush().await.expect("flush must succeed");

        let mut encrypted_header = [0u8; 4];
        read_side.read_exact(&mut encrypted_header).await.unwrap();
        let plain_header = decryptor.decrypt(&encrypted_header);
        let h: [u8; 4] = plain_header.as_slice().try_into().unwrap();
        let wire_len = (u32::from_le_bytes(h) & 0x7fff_ffff) as usize;
        let padding_len = wire_len - payload.len();
        assert!((1..=3).contains(&padding_len));
        seen[padding_len] = true;

        let mut encrypted_body = vec![0u8; wire_len];
        read_side.read_exact(&mut encrypted_body).await.unwrap();
        let _ = decryptor.decrypt(&encrypted_body);
    }

    let distinct = (1..=3).filter(|idx| seen[*idx]).count();
    assert!(
        distinct >= 2,
        "padding generator should not collapse to a single outcome under campaign"
    );
}

#[tokio::test]
async fn write_client_payload_mixed_proto_sequence_preserves_stream_sync() {
    let (mut read_side, write_side) = duplex(128 * 1024);
    let key = [0u8; 32];
    let iv = 0u128;
    let mut writer = CryptoWriter::new(write_side, AesCtr::new(&key, iv), 8 * 1024);
    let mut decryptor = AesCtr::new(&key, iv);
    let rng = SecureRandom::new();
    let mut frame_buf = Vec::new();

    let p1 = vec![1u8; 8];
    let p2 = vec![2u8; 16];
    let p3 = vec![3u8; 20];

    write_client_payload(&mut writer, ProtoTag::Abridged, 0, &p1, &rng, &mut frame_buf)
        .await
        .unwrap();
    write_client_payload(
        &mut writer,
        ProtoTag::Intermediate,
        RPC_FLAG_QUICKACK,
        &p2,
        &rng,
        &mut frame_buf,
    )
    .await
    .unwrap();
    write_client_payload(&mut writer, ProtoTag::Secure, 0, &p3, &rng, &mut frame_buf)
        .await
        .unwrap();
    writer.flush().await.unwrap();

    // Frame 1: abridged short.
    let mut e1 = vec![0u8; 1 + p1.len()];
    read_side.read_exact(&mut e1).await.unwrap();
    let d1 = decryptor.decrypt(&e1);
    assert_eq!(d1[0], (p1.len() / 4) as u8);
    assert_eq!(&d1[1..], p1.as_slice());

    // Frame 2: intermediate with quickack.
    let mut e2 = vec![0u8; 4 + p2.len()];
    read_side.read_exact(&mut e2).await.unwrap();
    let d2 = decryptor.decrypt(&e2);
    let l2 = u32::from_le_bytes(d2[0..4].try_into().unwrap());
    assert_ne!(l2 & 0x8000_0000, 0);
    assert_eq!((l2 & 0x7fff_ffff) as usize, p2.len());
    assert_eq!(&d2[4..], p2.as_slice());

    // Frame 3: secure with bounded tail.
    let mut e3h = [0u8; 4];
    read_side.read_exact(&mut e3h).await.unwrap();
    let d3h = decryptor.decrypt(&e3h);
    let l3 = (u32::from_le_bytes(d3h.as_slice().try_into().unwrap()) & 0x7fff_ffff) as usize;
    assert!(l3 >= p3.len());
    assert!((1..=3).contains(&(l3 - p3.len())));
    let mut e3b = vec![0u8; l3];
    read_side.read_exact(&mut e3b).await.unwrap();
    let d3b = decryptor.decrypt(&e3b);
    assert_eq!(&d3b[..p3.len()], p3.as_slice());
}

#[test]
fn should_yield_sender_boundary_matrix_blackhat() {
    assert!(!should_yield_c2me_sender(0, false));
    assert!(!should_yield_c2me_sender(0, true));
    assert!(!should_yield_c2me_sender(C2ME_SENDER_FAIRNESS_BUDGET - 1, true));
    assert!(!should_yield_c2me_sender(C2ME_SENDER_FAIRNESS_BUDGET, false));
    assert!(should_yield_c2me_sender(C2ME_SENDER_FAIRNESS_BUDGET, true));
    assert!(should_yield_c2me_sender(
        C2ME_SENDER_FAIRNESS_BUDGET.saturating_add(1024),
        true
    ));
}

#[test]
fn should_yield_sender_light_fuzz_matches_oracle() {
    let mut s: u64 = 0xD00D_BAAD_F00D_CAFE;
    for _ in 0..5000 {
        s ^= s << 7;
        s ^= s >> 9;
        s ^= s << 8;
        let sent = (s as usize) & 0x1fff;
        let backlog = (s & 1) != 0;

        let expected = backlog && sent >= C2ME_SENDER_FAIRNESS_BUDGET;
        assert_eq!(should_yield_c2me_sender(sent, backlog), expected);
    }
}

#[test]
fn quota_would_be_exceeded_exact_remaining_one_byte() {
    let stats = Stats::new();
    let user = "quota-edge";
    let quota = 100u64;
    stats.add_user_octets_to(user, 99);

    assert!(
        !quota_would_be_exceeded_for_user(&stats, user, Some(quota), 1),
        "exactly remaining budget should be allowed"
    );
    assert!(
        quota_would_be_exceeded_for_user(&stats, user, Some(quota), 2),
        "one byte beyond remaining budget must be rejected"
    );
}

#[test]
fn quota_would_be_exceeded_saturating_edge_remains_fail_closed() {
    let stats = Stats::new();
    let user = "quota-saturating-edge";
    let quota = u64::MAX - 3;
    stats.add_user_octets_to(user, u64::MAX - 4);

    assert!(
        quota_would_be_exceeded_for_user(&stats, user, Some(quota), 2),
        "saturating arithmetic edge must stay fail-closed"
    );
}

#[test]
fn quota_exceeded_boundary_is_inclusive() {
    let stats = Stats::new();
    let user = "quota-inclusive-boundary";
    stats.add_user_octets_to(user, 50);

    assert!(quota_exceeded_for_user(&stats, user, Some(50)));
    assert!(!quota_exceeded_for_user(&stats, user, Some(51)));
}

#[tokio::test]
async fn enqueue_c2me_close_fast_path_succeeds_without_backpressure() {
    let (tx, mut rx) = mpsc::channel::<C2MeCommand>(4);
    enqueue_c2me_command(&tx, C2MeCommand::Close)
        .await
        .expect("close should enqueue on fast path");

    let recv = timeout(TokioDuration::from_millis(50), rx.recv())
        .await
        .expect("must receive close command")
        .expect("close command should be present");
    assert!(matches!(recv, C2MeCommand::Close));
}

#[tokio::test]
async fn enqueue_c2me_data_full_then_drain_preserves_order() {
    let (tx, mut rx) = mpsc::channel::<C2MeCommand>(1);
    tx.send(C2MeCommand::Data {
        payload: make_pooled_payload(&[1]),
        flags: 10,
    })
    .await
    .unwrap();

    let tx2 = tx.clone();
    let producer = tokio::spawn(async move {
        enqueue_c2me_command(
            &tx2,
            C2MeCommand::Data {
                payload: make_pooled_payload(&[2, 2]),
                flags: 20,
            },
        )
        .await
    });

    tokio::time::sleep(TokioDuration::from_millis(10)).await;

    let first = rx.recv().await.expect("first item should exist");
    match first {
        C2MeCommand::Data { payload, flags } => {
            assert_eq!(payload.as_ref(), &[1]);
            assert_eq!(flags, 10);
        }
        C2MeCommand::Close => panic!("unexpected close as first item"),
    }

    producer.await.unwrap().expect("producer should complete");

    let second = timeout(TokioDuration::from_millis(100), rx.recv())
        .await
        .unwrap()
        .expect("second item should exist");
    match second {
        C2MeCommand::Data { payload, flags } => {
            assert_eq!(payload.as_ref(), &[2, 2]);
            assert_eq!(flags, 20);
        }
        C2MeCommand::Close => panic!("unexpected close as second item"),
    }
}
