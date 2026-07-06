use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;

use super::*;
use crate::crypto::AesCtr;
use crate::protocol::framing::INTERMEDIATE_WIRE_LEN_MASK;

#[derive(Clone, Default)]
struct RecordingWriter {
    writes: Arc<Mutex<Vec<u8>>>,
    flushes: Arc<AtomicUsize>,
}

impl RecordingWriter {
    fn captured(&self) -> Vec<u8> {
        self.writes
            .lock()
            .expect("test writer capture lock must not be poisoned")
            .clone()
    }
}

impl AsyncWrite for RecordingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes
            .lock()
            .expect("test writer capture lock must not be poisoned")
            .extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flushes.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn crypto_writer(inner: RecordingWriter) -> CryptoWriter<RecordingWriter> {
    let key = [0u8; 32];
    CryptoWriter::new(inner, AesCtr::new(&key, 0), 8 * 1024 * 1024)
}

fn decrypt_capture(mut encrypted: Vec<u8>) -> Vec<u8> {
    let key = [0u8; 32];
    let mut cipher = AesCtr::new(&key, 0);
    cipher.apply(&mut encrypted);
    encrypted
}

fn secure_wire_len(cleartext: &[u8]) -> usize {
    let header = cleartext
        .get(..4)
        .expect("secure frame must include an intermediate header");
    (u32::from_le_bytes(
        header
            .try_into()
            .expect("secure frame header must be four bytes"),
    ) & INTERMEDIATE_WIRE_LEN_MASK) as usize
}

async fn write_secure_payload(payload_len: usize) -> (MeD2cWriteMode, Vec<u8>) {
    let inner = RecordingWriter::default();
    let capture = inner.clone();
    let mut writer = crypto_writer(inner);
    let payload = vec![0xa5; payload_len];
    let mut frame_buf = Vec::new();
    let cancel = CancellationToken::new();
    let rng = SecureRandom::new();

    let mode = write_client_payload(
        &mut writer,
        ProtoTag::Secure,
        0,
        &payload,
        &rng,
        &mut frame_buf,
        &cancel,
    )
    .await
    .expect("secure payload write must succeed");
    flush_client_or_cancel(&mut writer, &cancel)
        .await
        .expect("secure payload flush must succeed");

    (mode, decrypt_capture(capture.captured()))
}

fn assert_secure_payload_with_tail_padding(cleartext: &[u8], payload_len: usize) {
    let wire_len = secure_wire_len(cleartext);
    assert_eq!(cleartext.len(), 4 + wire_len);
    assert!(
        cleartext[4..4 + payload_len]
            .iter()
            .all(|byte| *byte == 0xa5)
    );

    let padding_len = wire_len
        .checked_sub(payload_len)
        .expect("secure wire length must include payload bytes");
    assert!((1..=3).contains(&padding_len));
    assert_ne!(wire_len % 4, 0);
}

#[tokio::test]
async fn queue_drain_flush_reason_performs_physical_client_flush() {
    let inner = RecordingWriter::default();
    let flushes = inner.flushes.clone();
    let mut writer = crypto_writer(inner);
    let cancel = CancellationToken::new();

    assert!(me_d2c_flush_reason_requires_client_flush(
        MeD2cFlushReason::QueueDrain
    ));
    flush_client_or_cancel(&mut writer, &cancel)
        .await
        .expect("client flush must succeed");

    assert_eq!(flushes.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn secure_payload_coalesced_path_keeps_tail_padding() {
    let payload_len = 8;
    let (mode, cleartext) = write_secure_payload(payload_len).await;

    assert!(matches!(mode, MeD2cWriteMode::Coalesced));
    assert_secure_payload_with_tail_padding(&cleartext, payload_len);
}

#[tokio::test]
async fn secure_payload_split_path_keeps_tail_padding() {
    let payload_len = ME_D2C_SINGLE_WRITE_COALESCE_MAX_BYTES;
    let (mode, cleartext) = write_secure_payload(payload_len).await;

    assert!(matches!(mode, MeD2cWriteMode::Split));
    assert_secure_payload_with_tail_padding(&cleartext, payload_len);
}
