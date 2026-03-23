use super::relay_bidirectional;
use crate::error::ProxyError;
use crate::stats::Stats;
use crate::stream::BufferPool;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::{Duration, timeout};

async fn read_available<R: AsyncRead + Unpin>(reader: &mut R, budget_ms: u64) -> usize {
    let mut total = 0usize;
    loop {
        let mut buf = [0u8; 64];
        match timeout(Duration::from_millis(budget_ms), reader.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => total = total.saturating_add(n),
            Ok(Err(_)) | Err(_) => break,
        }
    }
    total
}

fn preload_user_quota(stats: &Stats, user: &str, bytes: u64) {
    let user_stats = stats.get_or_create_user_stats_handle(user);
    stats.quota_charge_post_write(user_stats.as_ref(), bytes);
}

#[tokio::test]
async fn regression_client_chunk_larger_than_remaining_quota_does_not_overshoot_accounting() {
    let stats = Arc::new(Stats::new());
    let user = "quota-overflow-regression-client-chunk";
    let quota = 10u64;
    let preloaded = 9u64;
    let attempted_chunk = [0x11, 0x22, 0x33, 0x44];
    let max_post_write_overshoot = attempted_chunk.len() as u64;

    // Leave only 1 byte remaining under quota.
    preload_user_quota(stats.as_ref(), user, preloaded);

    let (mut client_peer, relay_client) = duplex(2048);
    let (relay_server, mut server_peer) = duplex(2048);
    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        512,
        512,
        user,
        Arc::clone(&stats),
        Some(quota),
        Arc::new(BufferPool::new()),
    ));

    // Single chunk attempts to cross remaining budget (4 > 1).
    client_peer.write_all(&attempted_chunk).await.unwrap();
    client_peer.shutdown().await.unwrap();

    let forwarded = read_available(&mut server_peer, 60).await;

    let relay_result = timeout(Duration::from_secs(2), relay)
        .await
        .expect("relay must terminate after quota overflow attempt")
        .expect("relay task must not panic");

    assert!(
        forwarded <= attempted_chunk.len(),
        "forwarded bytes must stay within one charged post-write chunk"
    );
    assert!(matches!(
        relay_result,
        Err(ProxyError::DataQuotaExceeded { .. })
    ));
    assert!(
        stats.get_user_quota_used(user) <= quota + max_post_write_overshoot,
        "accounted bytes must stay within bounded post-write overshoot"
    );
}

#[tokio::test]
async fn regression_client_exact_remaining_quota_forwards_once_then_hard_cuts_off() {
    let stats = Arc::new(Stats::new());
    let user = "quota-overflow-regression-boundary";

    // Leave exactly 4 bytes remaining.
    preload_user_quota(stats.as_ref(), user, 6);

    let (mut client_peer, relay_client) = duplex(2048);
    let (relay_server, mut server_peer) = duplex(2048);
    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        256,
        256,
        user,
        Arc::clone(&stats),
        Some(10),
        Arc::new(BufferPool::new()),
    ));

    // Exact boundary write should pass once.
    client_peer
        .write_all(&[0xAA, 0xBB, 0xCC, 0xDD])
        .await
        .unwrap();

    let mut exact = [0u8; 4];
    timeout(Duration::from_secs(1), server_peer.read_exact(&mut exact))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exact, [0xAA, 0xBB, 0xCC, 0xDD]);

    // Any extra byte after boundary should be rejected/cut off.
    let _ = client_peer.write_all(&[0xEE]).await;
    client_peer.shutdown().await.unwrap();

    let leaked_after = read_available(&mut server_peer, 60).await;

    let relay_result = timeout(Duration::from_secs(2), relay)
        .await
        .expect("relay must terminate at quota boundary")
        .expect("relay task must not panic");

    assert_eq!(
        leaked_after, 0,
        "no bytes may pass after exact boundary is consumed"
    );
    assert!(matches!(
        relay_result,
        Err(ProxyError::DataQuotaExceeded { .. })
    ));
    assert!(stats.get_user_quota_used(user) <= 10);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_parallel_relays_same_user_quota_overflow_never_exceeds_cap() {
    let stats = Arc::new(Stats::new());
    let user = "quota-overflow-regression-stress";
    let quota = 12u64;
    const WORKERS: usize = 4;
    const BURST_LEN: usize = 64;
    let max_parallel_post_write_overshoot = (WORKERS * BURST_LEN) as u64;

    let mut handles = Vec::new();
    for _ in 0..WORKERS {
        let stats = Arc::clone(&stats);
        let user = user.to_string();

        handles.push(tokio::spawn(async move {
            let (mut client_peer, relay_client) = duplex(4096);
            let (relay_server, mut server_peer) = duplex(4096);
            let (client_reader, client_writer) = tokio::io::split(relay_client);
            let (server_reader, server_writer) = tokio::io::split(relay_server);

            let relay_user = user.clone();
            let relay_stats = Arc::clone(&stats);
            let relay = tokio::spawn(async move {
                relay_bidirectional(
                    client_reader,
                    client_writer,
                    server_reader,
                    server_writer,
                    192,
                    192,
                    &relay_user,
                    relay_stats,
                    Some(quota),
                    Arc::new(BufferPool::new()),
                )
                .await
            });

            // Aggressive sender tries to overflow shared user quota.
            let burst = vec![0x5Au8; BURST_LEN];
            let _ = client_peer.write_all(&burst).await;
            let _ = client_peer.shutdown().await;

            let mut forwarded = 0usize;
            forwarded = forwarded.saturating_add(read_available(&mut server_peer, 40).await);

            let relay_result = timeout(Duration::from_secs(2), relay)
                .await
                .expect("stress relay must terminate")
                .expect("stress relay task must not panic");

            assert!(
                relay_result.is_ok()
                    || matches!(relay_result, Err(ProxyError::DataQuotaExceeded { .. })),
                "stress relay must finish cleanly or with typed quota error"
            );
            forwarded
        }));
    }

    let mut forwarded_sum = 0usize;
    for handle in handles {
        forwarded_sum = forwarded_sum.saturating_add(handle.await.expect("worker must not panic"));
    }

    assert!(
        forwarded_sum as u64 <= quota + max_parallel_post_write_overshoot,
        "aggregate forwarded bytes must stay within bounded post-write overshoot window"
    );
    assert!(
        stats.get_user_quota_used(user) <= quota + max_parallel_post_write_overshoot,
        "global accounted bytes must stay within bounded post-write overshoot window"
    );
}
