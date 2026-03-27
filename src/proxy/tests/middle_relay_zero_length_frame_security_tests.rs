use super::*;
use crate::crypto::AesCtr;
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWriteExt, duplex};

fn make_crypto_reader<T>(reader: T) -> CryptoReader<T>
where
    T: AsyncRead + Unpin + Send + 'static,
{
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

fn make_forensics(conn_id: u64, started_at: Instant) -> RelayForensicsState {
    RelayForensicsState {
        trace_id: 0xB000_0000 + conn_id,
        conn_id,
        user: format!("zero-len-test-user-{conn_id}"),
        peer: "127.0.0.1:50000".parse().expect("peer parse must succeed"),
        peer_hash: hash_ip("127.0.0.1".parse().expect("ip parse must succeed")),
        started_at,
        bytes_c2me: 0,
        bytes_me2c: Arc::new(AtomicU64::new(0)),
        desync_all_full: false,
    }
}

#[tokio::test]
async fn adversarial_legacy_zero_length_flood_is_fail_closed() {
    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(1, session_started_at);
    let mut frame_counter = 0u64;

    let flood_plaintext = vec![0u8; 128];
    let flood_encrypted = encrypt_for_reader(&flood_plaintext);
    writer
        .write_all(&flood_encrypted)
        .await
        .expect("zero-length flood bytes must be writable");
    drop(writer);

    let result = read_client_payload_legacy(
        &mut crypto_reader,
        ProtoTag::Abridged,
        1024,
        Duration::from_millis(30),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await;

    match result {
        Err(ProxyError::Proxy(msg)) => {
            assert!(
                msg.contains("Excessive zero-length"),
                "legacy mode must close flood with explicit zero-length reason, got: {msg}"
            );
        }
        Ok(None) => panic!("legacy zero-length flood must not be accepted as EOF"),
        Ok(Some(_)) => panic!("legacy zero-length flood must not produce a data frame"),
        Err(err) => panic!("legacy zero-length flood must be a Proxy error, got: {err}"),
    }
}

#[tokio::test]
async fn business_abridged_nonzero_frame_still_passes() {
    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(2, session_started_at);
    let mut frame_counter = 0u64;

    let payload = [1u8, 2, 3, 4];
    let mut plaintext = Vec::with_capacity(1 + payload.len());
    plaintext.push(0x01);
    plaintext.extend_from_slice(&payload);

    let encrypted = encrypt_for_reader(&plaintext);
    writer
        .write_all(&encrypted)
        .await
        .expect("nonzero abridged frame must be writable");

    let result = read_client_payload_legacy(
        &mut crypto_reader,
        ProtoTag::Abridged,
        1024,
        Duration::from_millis(30),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await
    .expect("valid abridged frame should decode")
    .expect("valid abridged frame should return payload");

    assert_eq!(result.0.as_ref(), &payload);
    assert!(!result.1, "quickack flag must remain false");
    assert_eq!(frame_counter, 1);
}
