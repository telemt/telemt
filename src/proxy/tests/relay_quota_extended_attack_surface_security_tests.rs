use super::relay_bidirectional;
use crate::error::ProxyError;
use crate::stats::Stats;
use crate::stream::BufferPool;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::{Duration, timeout};

async fn read_available<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    budget: Duration,
) -> usize {
    let start = tokio::time::Instant::now();
    let mut total = 0usize;
    let mut buf = [0u8; 128];

    loop {
        let elapsed = start.elapsed();
        if elapsed >= budget {
            break;
        }
        let remaining = budget.saturating_sub(elapsed);
        match timeout(remaining, reader.read(&mut buf)).await {
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
async fn positive_quota_path_forwards_both_directions_within_limit() {
    let stats = Arc::new(Stats::new());
    let user = "quota-extended-positive-user";

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
        Some(16),
        Arc::new(BufferPool::new()),
    ));

    client_peer
        .write_all(&[0xAA, 0xBB, 0xCC, 0xDD])
        .await
        .unwrap();
    server_peer.read_exact(&mut [0u8; 4]).await.unwrap();

    server_peer
        .write_all(&[0x11, 0x22, 0x33, 0x44])
        .await
        .unwrap();
    client_peer.read_exact(&mut [0u8; 4]).await.unwrap();

    drop(client_peer);
    drop(server_peer);

    let relay_result = timeout(Duration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap();
    assert!(relay_result.is_ok());
    assert!(stats.get_user_quota_used(user) <= 16);
}

#[tokio::test]
async fn negative_preloaded_quota_forbids_any_forwarding() {
    let stats = Arc::new(Stats::new());
    let user = "quota-extended-negative-user";
    preload_user_quota(stats.as_ref(), user, 8);

    let (mut client_peer, relay_client) = duplex(1024);
    let (relay_server, mut server_peer) = duplex(1024);
    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        128,
        128,
        user,
        Arc::clone(&stats),
        Some(8),
        Arc::new(BufferPool::new()),
    ));

    client_peer.write_all(&[0xAA]).await.unwrap();
    server_peer.write_all(&[0xBB]).await.unwrap();

    assert_eq!(
        read_available(&mut server_peer, Duration::from_millis(120)).await,
        0
    );
    assert_eq!(
        read_available(&mut client_peer, Duration::from_millis(120)).await,
        0
    );

    let relay_result = timeout(Duration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        relay_result,
        Err(ProxyError::DataQuotaExceeded { .. })
    ));
    assert!(stats.get_user_quota_used(user) <= 8);
}

#[tokio::test]
async fn edge_quota_one_ensures_at_most_one_byte_across_directions() {
    let stats = Arc::new(Stats::new());
    let user = "quota-extended-edge-user";

    let (mut client_peer, relay_client) = duplex(1024);
    let (relay_server, mut server_peer) = duplex(1024);
    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        128,
        128,
        user,
        Arc::clone(&stats),
        Some(1),
        Arc::new(BufferPool::new()),
    ));

    let _ = tokio::join!(
        client_peer.write_all(&[0xFE]),
        server_peer.write_all(&[0xEF]),
    );

    let mut buf = [0u8; 1];
    let delivered_s2c = timeout(Duration::from_millis(120), client_peer.read(&mut buf))
        .await
        .unwrap()
        .unwrap_or(0);
    let delivered_c2s = timeout(Duration::from_millis(120), server_peer.read(&mut buf))
        .await
        .unwrap()
        .unwrap_or(0);

    assert!(delivered_s2c + delivered_c2s <= 1);

    let relay_result = timeout(Duration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        relay_result,
        Err(ProxyError::DataQuotaExceeded { .. })
    ));
}

#[tokio::test]
async fn adversarial_blackhat_alternating_jitter_does_not_overshoot_quota() {
    let stats = Arc::new(Stats::new());
    let user = "quota-extended-blackhat-user";
    let quota = 24u64;

    let (mut client_peer, relay_client) = duplex(4096);
    let (relay_server, mut server_peer) = duplex(4096);
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
        Some(quota),
        Arc::new(BufferPool::new()),
    ));

    let mut total_forwarded = 0usize;

    for i in 0..256usize {
        if relay.is_finished() {
            break;
        }
        if (i & 1) == 0 {
            let _ = client_peer.write_all(&[(i as u8) ^ 0x57]).await;
            let mut one = [0u8; 1];
            if let Ok(Ok(n)) = timeout(Duration::from_millis(6), server_peer.read(&mut one)).await {
                total_forwarded += n;
            }
        } else {
            let _ = server_peer.write_all(&[(i as u8) ^ 0xA8]).await;
            let mut one = [0u8; 1];
            if let Ok(Ok(n)) = timeout(Duration::from_millis(6), client_peer.read(&mut one)).await {
                total_forwarded += n;
            }
        }

        tokio::time::sleep(Duration::from_millis(((i % 3) + 1) as u64)).await;
    }

    let relay_result = timeout(Duration::from_secs(3), relay)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        relay_result,
        Err(ProxyError::DataQuotaExceeded { .. })
    ));
    assert!(total_forwarded <= quota as usize);
    assert!(stats.get_user_quota_used(user) <= quota);
}

#[tokio::test]
async fn light_fuzz_random_quota_schedule_preserves_quota_invariants() {
    let mut rng = StdRng::seed_from_u64(0xBEEF_C0DE);

    for case in 0..32u64 {
        let stats = Arc::new(Stats::new());
        let user = format!("quota-extended-fuzz-{case}");
        let quota = rng.random_range(1u64..=35u64);

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
                256,
                256,
                &relay_user,
                Arc::clone(&relay_stats),
                Some(quota),
                Arc::new(BufferPool::new()),
            )
            .await
        });

        let mut total_forwarded = 0usize;

        for _ in 0..96usize {
            if relay.is_finished() {
                break;
            }

            if rng.random::<bool>() {
                let _ = client_peer.write_all(&[rng.random::<u8>()]).await;
                let mut one = [0u8; 1];
                if let Ok(Ok(n)) =
                    timeout(Duration::from_millis(4), server_peer.read(&mut one)).await
                {
                    total_forwarded += n;
                }
            } else {
                let _ = server_peer.write_all(&[rng.random::<u8>()]).await;
                let mut one = [0u8; 1];
                if let Ok(Ok(n)) =
                    timeout(Duration::from_millis(4), client_peer.read(&mut one)).await
                {
                    total_forwarded += n;
                }
            }
        }

        drop(client_peer);
        drop(server_peer);

        let relay_result = timeout(Duration::from_secs(2), relay)
            .await
            .unwrap()
            .unwrap();
        assert!(
            relay_result.is_ok()
                || matches!(relay_result, Err(ProxyError::DataQuotaExceeded { .. }))
        );
        assert!(total_forwarded <= quota as usize);
        assert!(stats.get_user_quota_used(&user) <= quota);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_parallel_relays_for_one_user_obey_global_quota() {
    let stats = Arc::new(Stats::new());
    let user = "quota-extended-stress-user".to_string();
    let quota = 64u64;

    let mut tasks = Vec::new();

    for worker in 0..4u8 {
        let stats = Arc::clone(&stats);
        let user = user.clone();

        tasks.push(tokio::spawn(async move {
            let (mut client_peer, relay_client) = duplex(2048);
            let (relay_server, mut server_peer) = duplex(2048);
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
                    128,
                    128,
                    &relay_user,
                    Arc::clone(&relay_stats),
                    Some(quota),
                    Arc::new(BufferPool::new()),
                )
                .await
            });

            let mut total = 0usize;
            for step in 0..64u8 {
                if relay.is_finished() {
                    break;
                }
                if (step as usize + worker as usize) % 2 == 0 {
                    let _ = client_peer.write_all(&[(step ^ 0x5A)]).await;
                    let mut one = [0u8; 1];
                    if let Ok(Ok(n)) =
                        timeout(Duration::from_millis(6), server_peer.read(&mut one)).await
                    {
                        total += n;
                    }
                } else {
                    let _ = server_peer.write_all(&[(step ^ 0xA5)]).await;
                    let mut one = [0u8; 1];
                    if let Ok(Ok(n)) =
                        timeout(Duration::from_millis(6), client_peer.read(&mut one)).await
                    {
                        total += n;
                    }
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }

            drop(client_peer);
            drop(server_peer);

            let relay_result = timeout(Duration::from_secs(2), relay)
                .await
                .unwrap()
                .unwrap();
            assert!(
                relay_result.is_ok()
                    || matches!(relay_result, Err(ProxyError::DataQuotaExceeded { .. }))
            );
            total
        }));
    }

    let mut delivered = 0usize;
    for task in tasks {
        delivered += task.await.unwrap();
    }

    assert!(stats.get_user_quota_used(&user) <= quota);
    assert!(delivered <= quota as usize);
}
