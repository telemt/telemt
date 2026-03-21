use super::relay_bidirectional;
use crate::error::ProxyError;
use crate::stats::Stats;
use crate::stream::BufferPool;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, duplex};
use tokio::sync::Barrier;
use tokio::time::{Duration, timeout};

fn assert_is_prefix(received: &[u8], sent: &[u8], direction: &str) {
    assert!(
        sent.starts_with(received),
        "{direction} stream corruption: received={} sent={} (received must be prefix of sent)",
        received.len(),
        sent.len()
    );
}

async fn drain_available<R: AsyncRead + Unpin>(reader: &mut R, out: &mut Vec<u8>, rounds: usize) {
    for _ in 0..rounds {
        let mut buf = [0u8; 64];
        match timeout(Duration::from_millis(2), reader.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Ok(Err(_)) | Err(_) => break,
        }
    }
}

#[tokio::test]
async fn model_fuzz_bidirectional_schedule_preserves_prefixes_and_quota_budget() {
    let mut rng = StdRng::seed_from_u64(0xC0DE_CAFE_D15C_F00D);

    for case in 0..64u64 {
        let stats = Arc::new(Stats::new());
        let user = format!("quota-model-fuzz-{case}");
        let quota = rng.random_range(1u64..=64u64);

        let (mut client_peer, relay_client) = duplex(8192);
        let (relay_server, mut server_peer) = duplex(8192);
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
                relay_stats,
                Some(quota),
                Arc::new(BufferPool::new()),
            )
            .await
        });

        let mut sent_c2s = Vec::new();
        let mut sent_s2c = Vec::new();
        let mut recv_at_server = Vec::new();
        let mut recv_at_client = Vec::new();

        for _ in 0..96usize {
            if relay.is_finished() {
                break;
            }

            let do_c2s = rng.random::<bool>();
            let chunk_len = rng.random_range(1usize..=12usize);
            let mut chunk = vec![0u8; chunk_len];
            for b in &mut chunk {
                *b = rng.random::<u8>();
            }

            if do_c2s {
                if client_peer.write_all(&chunk).await.is_ok() {
                    sent_c2s.extend_from_slice(&chunk);
                }
            } else if server_peer.write_all(&chunk).await.is_ok() {
                sent_s2c.extend_from_slice(&chunk);
            }

            drain_available(&mut server_peer, &mut recv_at_server, 2).await;
            drain_available(&mut client_peer, &mut recv_at_client, 2).await;

            assert_is_prefix(&recv_at_server, &sent_c2s, "C->S");
            assert_is_prefix(&recv_at_client, &sent_s2c, "S->C");
            assert!(
                recv_at_server.len() + recv_at_client.len() <= quota as usize,
                "fuzz case {case}: delivered bytes exceed quota"
            );
            assert!(
                stats.get_user_total_octets(&user) <= quota,
                "fuzz case {case}: accounted bytes exceed quota"
            );
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
            "fuzz case {case}: relay must end cleanly or with typed quota error"
        );

        assert_is_prefix(&recv_at_server, &sent_c2s, "C->S final");
        assert_is_prefix(&recv_at_client, &sent_s2c, "S->C final");
        assert!(recv_at_server.len() + recv_at_client.len() <= quota as usize);
        assert!(stats.get_user_total_octets(&user) <= quota);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adversarial_dual_direction_cutoff_race_allows_at_most_one_forwarded_byte() {
    let stats = Arc::new(Stats::new());
    let user = "quota-dual-race-user";

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

    let gate = Arc::new(Barrier::new(3));

    let writer_c2s = {
        let gate = Arc::clone(&gate);
        tokio::spawn(async move {
            gate.wait().await;
            let _ = client_peer.write_all(&[0xA1]).await;
            client_peer
        })
    };

    let writer_s2c = {
        let gate = Arc::clone(&gate);
        tokio::spawn(async move {
            gate.wait().await;
            let _ = server_peer.write_all(&[0xB2]).await;
            server_peer
        })
    };

    gate.wait().await;

    let mut client_peer = writer_c2s.await.expect("c2s writer must not panic");
    let mut server_peer = writer_s2c.await.expect("s2c writer must not panic");

    let mut got_at_server = [0u8; 1];
    let mut got_at_client = [0u8; 1];

    let n_server = match timeout(
        Duration::from_millis(120),
        server_peer.read(&mut got_at_server),
    )
    .await
    {
        Ok(Ok(n)) => n,
        _ => 0,
    };
    let n_client = match timeout(
        Duration::from_millis(120),
        client_peer.read(&mut got_at_client),
    )
    .await
    {
        Ok(Ok(n)) => n,
        _ => 0,
    };

    assert!(
        n_server + n_client <= 1,
        "quota=1 race must not forward both concurrent direction bytes"
    );

    drop(client_peer);
    drop(server_peer);

    let relay_result = timeout(Duration::from_secs(2), relay)
        .await
        .expect("quota race relay must terminate")
        .expect("quota race relay task must not panic");

    assert!(matches!(
        relay_result,
        Err(ProxyError::DataQuotaExceeded { .. })
    ));
    assert!(stats.get_user_total_octets(user) <= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_shared_user_multi_relay_global_quota_never_overshoots_under_model_load() {
    let stats = Arc::new(Stats::new());
    let user = "quota-model-stress-user";
    let quota = 96u64;

    let mut workers = Vec::new();
    for worker_id in 0..6u64 {
        let stats = Arc::clone(&stats);
        let user = user.to_string();

        workers.push(tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(0x9E37_79B9_7F4A_7C15 ^ worker_id);

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

            let mut sent_c2s = Vec::new();
            let mut sent_s2c = Vec::new();
            let mut recv_at_server = Vec::new();
            let mut recv_at_client = Vec::new();

            for _ in 0..64usize {
                if relay.is_finished() {
                    break;
                }

                let choose_c2s = rng.random::<bool>();
                let len = rng.random_range(1usize..=10usize);
                let mut payload = vec![0u8; len];
                for b in &mut payload {
                    *b = rng.random::<u8>();
                }

                if choose_c2s {
                    if client_peer.write_all(&payload).await.is_ok() {
                        sent_c2s.extend_from_slice(&payload);
                    }
                } else if server_peer.write_all(&payload).await.is_ok() {
                    sent_s2c.extend_from_slice(&payload);
                }

                drain_available(&mut server_peer, &mut recv_at_server, 2).await;
                drain_available(&mut client_peer, &mut recv_at_client, 2).await;

                assert_is_prefix(&recv_at_server, &sent_c2s, "stress C->S");
                assert_is_prefix(&recv_at_client, &sent_s2c, "stress S->C");
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
                "stress relay must end cleanly or with typed quota error"
            );

            recv_at_server.len() + recv_at_client.len()
        }));
    }

    let mut delivered_sum = 0usize;
    for worker in workers {
        delivered_sum = delivered_sum.saturating_add(worker.await.expect("worker must not panic"));
    }

    assert!(
        stats.get_user_total_octets(user) <= quota,
        "global per-user quota must never overshoot under concurrent multi-relay model load"
    );
    assert!(
        delivered_sum <= quota as usize,
        "aggregate delivered bytes across relays must remain within global quota"
    );
}
