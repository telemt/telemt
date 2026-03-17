use super::*;
use crate::crypto::AesCtr;
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tokio::io::AsyncWriteExt;
use tokio::io::duplex;
use tokio::time::{Duration as TokioDuration, timeout};

#[test]
fn should_yield_sender_only_on_budget_with_backlog() {
    assert!(!should_yield_c2me_sender(0, true));
    assert!(!should_yield_c2me_sender(C2ME_SENDER_FAIRNESS_BUDGET - 1, true));
    assert!(!should_yield_c2me_sender(C2ME_SENDER_FAIRNESS_BUDGET, false));
    assert!(should_yield_c2me_sender(C2ME_SENDER_FAIRNESS_BUDGET, true));
}

#[tokio::test]
async fn enqueue_c2me_command_uses_try_send_fast_path() {
    let (tx, mut rx) = mpsc::channel::<C2MeCommand>(2);
    enqueue_c2me_command(
        &tx,
        C2MeCommand::Data {
            payload: Bytes::from_static(&[1, 2, 3]),
            flags: 0,
        },
    )
    .await
    .unwrap();

    let recv = timeout(TokioDuration::from_millis(50), rx.recv())
        .await
        .unwrap()
        .unwrap();
    match recv {
        C2MeCommand::Data { payload, flags } => {
            assert_eq!(payload.as_ref(), &[1, 2, 3]);
            assert_eq!(flags, 0);
        }
        C2MeCommand::Close => panic!("unexpected close command"),
    }
}

#[tokio::test]
async fn enqueue_c2me_command_falls_back_to_send_when_queue_is_full() {
    let (tx, mut rx) = mpsc::channel::<C2MeCommand>(1);
    tx.send(C2MeCommand::Data {
        payload: Bytes::from_static(&[9]),
        flags: 9,
    })
    .await
    .unwrap();

    let tx2 = tx.clone();
    let producer = tokio::spawn(async move {
        enqueue_c2me_command(
            &tx2,
            C2MeCommand::Data {
                payload: Bytes::from_static(&[7, 7]),
                flags: 7,
            },
        )
        .await
        .unwrap();
    });

    let _ = timeout(TokioDuration::from_millis(100), rx.recv())
        .await
        .unwrap();
    producer.await.unwrap();

    let recv = timeout(TokioDuration::from_millis(100), rx.recv())
        .await
        .unwrap()
        .unwrap();
    match recv {
        C2MeCommand::Data { payload, flags } => {
            assert_eq!(payload.as_ref(), &[7, 7]);
            assert_eq!(flags, 7);
        }
        C2MeCommand::Close => panic!("unexpected close command"),
    }
}

#[test]
fn desync_dedup_cache_is_bounded() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let now = Instant::now();
    for key in 0..DESYNC_DEDUP_MAX_ENTRIES as u64 {
        assert!(
            should_emit_full_desync(key, false, now),
            "unique keys up to cap must be tracked"
        );
    }

    assert!(
        !should_emit_full_desync(u64::MAX, false, now),
        "new key above cap must be suppressed to bound memory"
    );

    assert!(
        !should_emit_full_desync(7, false, now),
        "already tracked key inside dedup window must stay suppressed"
    );
}

fn make_forensics_state() -> RelayForensicsState {
    RelayForensicsState {
        trace_id: 1,
        conn_id: 2,
        user: "test-user".to_string(),
        peer: "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
        peer_hash: 3,
        started_at: Instant::now(),
        bytes_c2me: 0,
        bytes_me2c: Arc::new(AtomicU64::new(0)),
        desync_all_full: false,
    }
}

fn make_crypto_reader(reader: tokio::io::DuplexStream) -> CryptoReader<tokio::io::DuplexStream> {
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoReader::new(reader, AesCtr::new(&key, iv))
}

fn encrypt_for_reader(plaintext: &[u8]) -> Vec<u8> {
    let key = [0u8; 32];
    let iv = 0u128;
    let mut cipher = AesCtr::new(&key, iv);
    cipher.encrypt(plaintext)
}

#[tokio::test]
async fn read_client_payload_times_out_on_header_stall() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");
    let (reader, _writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let result = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        1024,
        TokioDuration::from_millis(25),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::Io(ref e)) if e.kind() == std::io::ErrorKind::TimedOut),
        "stalled header read must time out"
    );
}

#[tokio::test]
async fn read_client_payload_times_out_on_payload_stall() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");
    let (reader, mut writer) = duplex(1024);
    let encrypted_len = encrypt_for_reader(&[8, 0, 0, 0]);
    writer.write_all(&encrypted_len).await.unwrap();

    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let result = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        1024,
        TokioDuration::from_millis(25),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::Io(ref e)) if e.kind() == std::io::ErrorKind::TimedOut),
        "stalled payload body read must time out"
    );
}
