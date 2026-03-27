use super::*;
use crate::error::ProxyError;
use crate::stats::Stats;
use crate::stream::BufferPool;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::{Duration, Instant, timeout};

// ------------------------------------------------------------------
// Priority 3: Async Relay HOL Blocking Prevention (OWASP ASVS 5.1.5)
// ------------------------------------------------------------------

#[tokio::test]
async fn relay_hol_blocking_prevention_regression() {
    let stats = Arc::new(Stats::new());
    let user = "hol-user";

    let (client_peer, relay_client) = duplex(65536);
    let (relay_server, server_peer) = duplex(65536);

    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);
    let (mut cp_reader, mut cp_writer) = tokio::io::split(client_peer);
    let (mut sp_reader, mut sp_writer) = tokio::io::split(server_peer);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        8192,
        8192,
        user,
        Arc::clone(&stats),
        None,
        Arc::new(BufferPool::new()),
    ));

    let payload_size = 1024 * 10;
    let s2c_payload = vec![0x41; payload_size];
    let c2s_payload = vec![0x42; payload_size];

    let s2c_handle = tokio::spawn(async move {
        sp_writer.write_all(&s2c_payload).await.unwrap();

        let mut total_read = 0;
        let mut buf = [0u8; 10];
        while total_read < payload_size {
            let n = cp_reader.read(&mut buf).await.unwrap();
            total_read += n;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    let start = Instant::now();
    cp_writer.write_all(&c2s_payload).await.unwrap();

    let mut server_buf = vec![0u8; payload_size];
    sp_reader.read_exact(&mut server_buf).await.unwrap();
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(1000),
        "C->S must not be blocked by slow S->C (HOL blocking): {:?}",
        elapsed
    );
    assert_eq!(server_buf, c2s_payload);

    s2c_handle.abort();
    relay_task.abort();
}

// ------------------------------------------------------------------
// Priority 3: Data Quota Mid-Session Cutoff (OWASP ASVS 5.1.6)
// ------------------------------------------------------------------

#[tokio::test]
async fn relay_quota_mid_session_cutoff() {
    let stats = Arc::new(Stats::new());
    let user = "quota-mid-user";
    let quota = 5000u64;
    let c2s_buf_size = 1024usize;

    let (client_peer, relay_client) = duplex(8192);
    let (relay_server, server_peer) = duplex(8192);

    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);
    let (mut _cp_reader, mut cp_writer) = tokio::io::split(client_peer);
    let (mut sp_reader, _sp_writer) = tokio::io::split(server_peer);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        c2s_buf_size,
        1024,
        user,
        Arc::clone(&stats),
        Some(quota),
        Arc::new(BufferPool::new()),
    ));

    // Send 4000 bytes (Ok)
    let buf1 = vec![0x42; 4000];
    cp_writer.write_all(&buf1).await.unwrap();
    let mut server_recv = vec![0u8; 4000];
    sp_reader.read_exact(&mut server_recv).await.unwrap();

    // Send another 2000 bytes (Total 6000 > 5000)
    let buf2 = vec![0x42; 2000];
    let _ = cp_writer.write_all(&buf2).await;

    let relay_res = timeout(Duration::from_secs(1), relay_task).await.unwrap();

    match relay_res {
        Ok(Err(ProxyError::DataQuotaExceeded { .. })) => {
            // Expected
        }
        other => panic!("Expected DataQuotaExceeded error, got: {:?}", other),
    }

    let mut overshoot_bytes = 0usize;
    let mut buf = [0u8; 256];
    loop {
        match timeout(Duration::from_millis(20), sp_reader.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => overshoot_bytes = overshoot_bytes.saturating_add(n),
            Ok(Err(e)) => panic!("server read must not fail after relay cutoff: {e}"),
            Err(_) => break,
        }
    }

    assert!(
        overshoot_bytes <= c2s_buf_size,
        "post-write cutoff may leak at most one C->S chunk after boundary, got {overshoot_bytes}"
    );
    assert!(
        stats.get_user_quota_used(user) <= quota.saturating_add(c2s_buf_size as u64),
        "accounted quota must remain bounded by one in-flight chunk overshoot"
    );
}

#[tokio::test]
async fn relay_chaos_half_close_crossfire_terminates_without_hang() {
    let stats = Arc::new(Stats::new());

    let (mut client_peer, relay_client) = duplex(8192);
    let (relay_server, mut server_peer) = duplex(8192);

    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        1024,
        1024,
        "half-close-crossfire",
        Arc::clone(&stats),
        None,
        Arc::new(BufferPool::new()),
    ));

    client_peer.write_all(b"c2s-pre-half-close").await.unwrap();
    server_peer.write_all(b"s2c-pre-half-close").await.unwrap();

    client_peer.shutdown().await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    server_peer.shutdown().await.unwrap();

    let done = timeout(Duration::from_secs(1), relay_task)
        .await
        .expect("relay must terminate after bilateral half-close")
        .expect("relay task must not panic");
    assert!(
        done.is_ok(),
        "relay must terminate cleanly under half-close crossfire"
    );
}

#[tokio::test]
#[ignore = "heavy soak; run manually"]
async fn relay_soak_bidirectional_temporal_jitter_5k_rounds() {
    let stats = Arc::new(Stats::new());

    let (mut client_peer, relay_client) = duplex(65536);
    let (relay_server, mut server_peer) = duplex(65536);

    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        4096,
        4096,
        "soak-jitter-user",
        Arc::clone(&stats),
        None,
        Arc::new(BufferPool::new()),
    ));

    for i in 0..5_000u32 {
        let c = [((i as u8).wrapping_mul(13)).wrapping_add(1); 17];
        client_peer.write_all(&c).await.unwrap();
        let mut c_seen = [0u8; 17];
        server_peer.read_exact(&mut c_seen).await.unwrap();
        assert_eq!(c_seen, c);

        let s = [((i as u8).wrapping_mul(7)).wrapping_add(3); 23];
        server_peer.write_all(&s).await.unwrap();
        let mut s_seen = [0u8; 23];
        client_peer.read_exact(&mut s_seen).await.unwrap();
        assert_eq!(s_seen, s);

        if i % 10 == 0 {
            tokio::time::sleep(Duration::from_millis((i % 3) as u64)).await;
        }
    }

    drop(client_peer);
    drop(server_peer);
    let done = timeout(Duration::from_secs(2), relay_task)
        .await
        .expect("relay must stop after soak peers close")
        .expect("relay task must not panic");
    assert!(done.is_ok());
}
