use super::relay_bidirectional;
use crate::error::ProxyError;
use crate::stats::Stats;
use crate::stream::BufferPool;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::{Duration, Instant, timeout};

async fn read_available<R: AsyncRead + Unpin>(reader: &mut R, budget: Duration) -> usize {
    let start = Instant::now();
    let mut total = 0usize;
    let mut buf = [0u8; 256];

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
async fn integration_full_duplex_exact_budget_then_hard_cutoff() {
    let stats = Arc::new(Stats::new());
    let user = "quota-full-duplex-boundary-user";

    let (mut client_peer, relay_client) = duplex(4096);
    let (relay_server, mut server_peer) = duplex(4096);
    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        1024,
        1024,
        user,
        Arc::clone(&stats),
        Some(10),
        Arc::new(BufferPool::new()),
    ));

    client_peer
        .write_all(&[0x10, 0x11, 0x12, 0x13])
        .await
        .unwrap();
    let mut c2s = [0u8; 4];
    server_peer.read_exact(&mut c2s).await.unwrap();
    assert_eq!(c2s, [0x10, 0x11, 0x12, 0x13]);

    server_peer
        .write_all(&[0x20, 0x21, 0x22, 0x23, 0x24, 0x25])
        .await
        .unwrap();
    let mut s2c = [0u8; 6];
    client_peer.read_exact(&mut s2c).await.unwrap();
    assert_eq!(s2c, [0x20, 0x21, 0x22, 0x23, 0x24, 0x25]);

    let _ = client_peer.write_all(&[0x99]).await;
    let _ = server_peer.write_all(&[0x88]).await;

    let mut probe_server = [0u8; 1];
    let mut probe_client = [0u8; 1];
    let leaked_to_server = timeout(
        Duration::from_millis(120),
        server_peer.read(&mut probe_server),
    )
    .await;
    let leaked_to_client = timeout(
        Duration::from_millis(120),
        client_peer.read(&mut probe_client),
    )
    .await;

    assert!(
        !matches!(leaked_to_server, Ok(Ok(n)) if n > 0),
        "once quota is exhausted, no extra client byte must be forwarded"
    );
    assert!(
        !matches!(leaked_to_client, Ok(Ok(n)) if n > 0),
        "once quota is exhausted, no extra server byte must be forwarded"
    );

    let relay_result = timeout(Duration::from_secs(2), relay)
        .await
        .expect("relay must terminate under quota cutoff")
        .expect("relay task must not panic");

    assert!(matches!(
        relay_result,
        Err(ProxyError::DataQuotaExceeded { ref user }) if user == "quota-full-duplex-boundary-user"
    ));
    assert!(stats.get_user_quota_used(user) <= 10);
}

#[tokio::test]
async fn negative_preloaded_quota_blocks_both_directions_immediately() {
    let stats = Arc::new(Stats::new());
    let user = "quota-preloaded-cutoff-user";
    preload_user_quota(stats.as_ref(), user, 5);

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
        Some(5),
        Arc::new(BufferPool::new()),
    ));

    let _ = tokio::join!(
        client_peer.write_all(&[0x41, 0x42]),
        server_peer.write_all(&[0x51, 0x52]),
    );

    let leaked_to_server = read_available(&mut server_peer, Duration::from_millis(120)).await;
    let leaked_to_client = read_available(&mut client_peer, Duration::from_millis(120)).await;

    assert_eq!(
        leaked_to_server, 0,
        "preloaded limit must block C->S immediately"
    );
    assert_eq!(
        leaked_to_client, 0,
        "preloaded limit must block S->C immediately"
    );

    let relay_result = timeout(Duration::from_secs(2), relay)
        .await
        .expect("relay must terminate under preloaded cutoff")
        .expect("relay task must not panic");
    assert!(matches!(
        relay_result,
        Err(ProxyError::DataQuotaExceeded { .. })
    ));
    assert!(stats.get_user_quota_used(user) <= 5);
}

#[tokio::test]
async fn edge_quota_one_bidirectional_race_allows_at_most_one_forwarded_octet() {
    let stats = Arc::new(Stats::new());
    let user = "quota-one-race-user";

    let (mut client_peer, relay_client) = duplex(1024);
    let (relay_server, mut server_peer) = duplex(1024);
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
        Some(1),
        Arc::new(BufferPool::new()),
    ));

    let _ = tokio::join!(
        client_peer.write_all(&[0xAA]),
        server_peer.write_all(&[0xBB])
    );

    let mut to_server = [0u8; 1];
    let mut to_client = [0u8; 1];

    let delivered_server =
        match timeout(Duration::from_millis(120), server_peer.read(&mut to_server)).await {
            Ok(Ok(n)) => n,
            _ => 0,
        };
    let delivered_client =
        match timeout(Duration::from_millis(120), client_peer.read(&mut to_client)).await {
            Ok(Ok(n)) => n,
            _ => 0,
        };

    assert!(
        delivered_server + delivered_client <= 1,
        "quota=1 must not allow >1 forwarded byte across both directions"
    );

    let relay_result = timeout(Duration::from_secs(2), relay)
        .await
        .expect("relay must terminate under quota=1")
        .expect("relay task must not panic");
    assert!(matches!(
        relay_result,
        Err(ProxyError::DataQuotaExceeded { .. })
    ));
    assert!(stats.get_user_quota_used(user) <= 1);
}

#[tokio::test]
async fn adversarial_blackhat_alternating_fragmented_jitter_never_overshoots_global_quota() {
    let stats = Arc::new(Stats::new());
    let user = "quota-blackhat-jitter-user";
    let quota = 32u64;

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

    let mut delivered_to_server = 0usize;
    let mut delivered_to_client = 0usize;

    for i in 0..256usize {
        if relay.is_finished() {
            break;
        }

        if (i & 1) == 0 {
            let _ = client_peer.write_all(&[(i as u8) ^ 0x5A]).await;
            let mut one = [0u8; 1];
            if let Ok(Ok(n)) = timeout(Duration::from_millis(4), server_peer.read(&mut one)).await {
                delivered_to_server = delivered_to_server.saturating_add(n);
            }
        } else {
            let _ = server_peer.write_all(&[(i as u8) ^ 0xA5]).await;
            let mut one = [0u8; 1];
            if let Ok(Ok(n)) = timeout(Duration::from_millis(4), client_peer.read(&mut one)).await {
                delivered_to_client = delivered_to_client.saturating_add(n);
            }
        }

        tokio::time::sleep(Duration::from_millis(((i % 3) + 1) as u64)).await;
    }

    let relay_result = timeout(Duration::from_secs(2), relay)
        .await
        .expect("relay must terminate under black-hat jitter attack")
        .expect("relay task must not panic");

    assert!(matches!(
        relay_result,
        Err(ProxyError::DataQuotaExceeded { .. })
    ));
    assert!(
        delivered_to_server + delivered_to_client <= quota as usize,
        "combined forwarded bytes must never exceed configured quota"
    );
    assert!(stats.get_user_quota_used(user) <= quota);
}

#[tokio::test]
async fn light_fuzz_randomized_schedule_preserves_quota_and_forwarded_byte_invariants() {
    let mut rng = StdRng::seed_from_u64(0xD15C_A11E_F00D_BAAD);

    for case in 0..48u64 {
        let stats = Arc::new(Stats::new());
        let user = format!("quota-fuzz-schedule-{case}");
        let quota = rng.random_range(1u64..=32u64);

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

        let mut delivered_total = 0usize;

        for _ in 0..96usize {
            if relay.is_finished() {
                break;
            }

            if rng.random::<bool>() {
                let _ = client_peer.write_all(&[rng.random::<u8>()]).await;
                let mut one = [0u8; 1];
                if let Ok(Ok(n)) =
                    timeout(Duration::from_millis(3), server_peer.read(&mut one)).await
                {
                    delivered_total = delivered_total.saturating_add(n);
                }
            } else {
                let _ = server_peer.write_all(&[rng.random::<u8>()]).await;
                let mut one = [0u8; 1];
                if let Ok(Ok(n)) =
                    timeout(Duration::from_millis(3), client_peer.read(&mut one)).await
                {
                    delivered_total = delivered_total.saturating_add(n);
                }
            }
        }

        drop(client_peer);
        drop(server_peer);

        let relay_result = timeout(Duration::from_secs(2), relay)
            .await
            .expect("fuzz relay must terminate")
            .expect("fuzz relay task must not panic");

        assert!(
            relay_result.is_ok()
                || matches!(relay_result, Err(ProxyError::DataQuotaExceeded { .. })),
            "relay must either close cleanly or terminate via typed quota error"
        );
        assert!(
            delivered_total <= quota as usize,
            "fuzz case {case}: forwarded bytes must not exceed quota"
        );
        assert!(
            stats.get_user_quota_used(&user) <= quota,
            "fuzz case {case}: accounted bytes must not exceed quota"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_multi_relay_same_user_mixed_direction_jitter_respects_global_quota() {
    let stats = Arc::new(Stats::new());
    let user = "quota-stress-multi-relay-user";
    let quota = 64u64;

    let mut workers = Vec::new();

    for worker_id in 0..4u8 {
        let stats = Arc::clone(&stats);
        let user = user.to_string();

        workers.push(tokio::spawn(async move {
            let (mut client_peer, relay_client) = duplex(4096);
            let (relay_server, mut server_peer) = duplex(4096);
            let (client_reader, client_writer) = tokio::io::split(relay_client);
            let (server_reader, server_writer) = tokio::io::split(relay_server);

            let relay_user = user.clone();
            let relay = tokio::spawn(async move {
                relay_bidirectional(
                    client_reader,
                    client_writer,
                    server_reader,
                    server_writer,
                    256,
                    256,
                    &relay_user,
                    Arc::clone(&stats),
                    Some(quota),
                    Arc::new(BufferPool::new()),
                )
                .await
            });

            let mut delivered = 0usize;

            for step in 0..96u8 {
                if relay.is_finished() {
                    break;
                }

                if ((step as usize + worker_id as usize) & 1) == 0 {
                    let _ = client_peer.write_all(&[step ^ 0x3C]).await;
                    let mut one = [0u8; 1];
                    if let Ok(Ok(n)) =
                        timeout(Duration::from_millis(3), server_peer.read(&mut one)).await
                    {
                        delivered = delivered.saturating_add(n);
                    }
                } else {
                    let _ = server_peer.write_all(&[step ^ 0xC3]).await;
                    let mut one = [0u8; 1];
                    if let Ok(Ok(n)) =
                        timeout(Duration::from_millis(3), client_peer.read(&mut one)).await
                    {
                        delivered = delivered.saturating_add(n);
                    }
                }

                tokio::time::sleep(Duration::from_millis(
                    (((worker_id as u64) + (step as u64)) % 3) + 1,
                ))
                .await;
            }

            drop(client_peer);
            drop(server_peer);
            let relay_result = timeout(Duration::from_secs(2), relay)
                .await
                .expect("stress relay must terminate")
                .expect("stress relay task must not panic");

            assert!(
                relay_result.is_ok()
                    || matches!(relay_result, Err(ProxyError::DataQuotaExceeded { .. })),
                "stress relay must either close cleanly or terminate via typed quota error"
            );
            delivered
        }));
    }

    let mut delivered_sum = 0usize;
    for worker in workers {
        delivered_sum =
            delivered_sum.saturating_add(worker.await.expect("stress worker must not panic"));
    }

    assert!(
        stats.get_user_quota_used(user) <= quota,
        "global per-user quota must hold under concurrent mixed-direction relay stress"
    );
    assert!(
        delivered_sum <= quota as usize,
        "combined delivered bytes across relays must stay within global quota"
    );
}
