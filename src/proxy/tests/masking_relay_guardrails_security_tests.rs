use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex, sink};
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn relay_to_mask_enforces_masking_session_byte_cap() {
    let initial = vec![0x16, 0x03, 0x01, 0x00, 0x01];
    let extra = vec![0xAB; 96 * 1024];

    let (client_reader, mut client_writer) = duplex(128 * 1024);
    let (mask_read, _mask_read_peer) = duplex(1024);
    let (mut mask_observer, mask_write) = duplex(256 * 1024);
    let initial_for_task = initial.clone();

    let relay = tokio::spawn(async move {
        relay_to_mask(
            client_reader,
            sink(),
            mask_read,
            mask_write,
            &initial_for_task,
            false,
            512,
            4096,
            false,
            0,
            false,
            32 * 1024,
        )
        .await;
    });

    client_writer.write_all(&extra).await.unwrap();
    client_writer.shutdown().await.unwrap();

    timeout(Duration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap();

    let mut observed = Vec::new();
    timeout(
        Duration::from_secs(2),
        mask_observer.read_to_end(&mut observed),
    )
    .await
    .unwrap()
    .unwrap();

    // In this deterministic test, relay must stop exactly at the configured cap.
    assert_eq!(
        observed.len(),
        initial.len() + (32 * 1024),
        "masked relay must forward exactly up to the cap (observed={} initial={} cap={})",
        observed.len(),
        initial.len(),
        32 * 1024
    );
}

#[tokio::test]
async fn relay_to_mask_propagates_client_half_close_without_waiting_for_other_direction_timeout() {
    let initial = b"GET /half-close HTTP/1.1\r\n".to_vec();

    let (client_reader, mut client_writer) = duplex(8 * 1024);
    let (mask_read, _mask_read_peer) = duplex(8 * 1024);
    let (mut mask_observer, mask_write) = duplex(8 * 1024);
    let initial_for_task = initial.clone();

    let relay = tokio::spawn(async move {
        relay_to_mask(
            client_reader,
            sink(),
            mask_read,
            mask_write,
            &initial_for_task,
            false,
            512,
            4096,
            false,
            0,
            false,
            32 * 1024,
        )
        .await;
    });

    client_writer.shutdown().await.unwrap();

    let mut observed = Vec::new();
    timeout(
        Duration::from_millis(80),
        mask_observer.read_to_end(&mut observed),
    )
    .await
    .expect("mask backend write side should be half-closed promptly")
    .unwrap();

    assert_eq!(&observed[..initial.len()], initial.as_slice());

    timeout(Duration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap();
}
