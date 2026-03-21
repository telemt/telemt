use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::TcpListener;
use tokio::time::{Duration, Instant};

fn new_upstream_manager(stats: Arc<Stats>) -> Arc<UpstreamManager> {
    Arc::new(UpstreamManager::new(
        vec![UpstreamConfig {
            upstream_type: UpstreamType::Direct {
                interface: None,
                bind_addresses: None,
            },
            weight: 1,
            enabled: true,
            scopes: String::new(),
            selected_scope: String::new(),
        }],
        1,
        1,
        1,
        1,
        false,
        stats,
    ))
}

fn percentile_ms(mut values: Vec<u128>, p_num: usize, p_den: usize) -> u128 {
    values.sort_unstable();
    if values.is_empty() {
        return 0;
    }
    let idx = ((values.len() - 1) * p_num) / p_den;
    values[idx]
}

async fn measure_reject_duration_ms(body_sent: usize) -> u128 {
    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = 1;
    cfg.timeouts.client_handshake = 1;
    cfg.censorship.server_hello_delay_min_ms = 700;
    cfg.censorship.server_hello_delay_max_ms = 700;

    let (server_side, mut client_side) = duplex(65536);
    let started = Instant::now();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.170:56170".parse().unwrap(),
        Arc::new(cfg),
        Arc::new(Stats::new()),
        new_upstream_manager(Arc::new(Stats::new())),
        Arc::new(ReplayChecker::new(256, Duration::from_secs(60))),
        Arc::new(BufferPool::new()),
        Arc::new(SecureRandom::new()),
        None,
        Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        None,
        Arc::new(UserIpTracker::new()),
        Arc::new(BeobachtenStore::new()),
        false,
    ));

    let mut probe = vec![0u8; 5 + body_sent];
    probe[0] = 0x16;
    probe[1] = 0x03;
    probe[2] = 0x01;
    probe[3..5].copy_from_slice(&600u16.to_be_bytes());
    probe[5..].fill(0xA7);

    client_side.write_all(&probe).await.unwrap();
    client_side.shutdown().await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(4), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());

    started.elapsed().as_millis()
}

async fn capture_forwarded_len(body_sent: usize) -> usize {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_shape_hardening = false;
    cfg.timeouts.client_handshake = 1;

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut got)).await;
        got.len()
    });

    let (server_side, mut client_side) = duplex(65536);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.171:56171".parse().unwrap(),
        Arc::new(cfg),
        Arc::new(Stats::new()),
        new_upstream_manager(Arc::new(Stats::new())),
        Arc::new(ReplayChecker::new(256, Duration::from_secs(60))),
        Arc::new(BufferPool::new()),
        Arc::new(SecureRandom::new()),
        None,
        Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        None,
        Arc::new(UserIpTracker::new()),
        Arc::new(BeobachtenStore::new()),
        false,
    ));

    let mut probe = vec![0u8; 5 + body_sent];
    probe[0] = 0x16;
    probe[1] = 0x03;
    probe[2] = 0x01;
    probe[3..5].copy_from_slice(&600u16.to_be_bytes());
    probe[5..].fill(0xB4);

    client_side.write_all(&probe).await.unwrap();
    client_side.shutdown().await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(4), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());

    tokio::time::timeout(Duration::from_secs(4), accept_task)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn diagnostic_timing_profiles_are_within_realistic_guardrails() {
    let classes = [17usize, 511usize, 1023usize, 4095usize];
    for class in classes {
        let mut samples = Vec::new();
        for _ in 0..8 {
            samples.push(measure_reject_duration_ms(class).await);
        }

        let p50 = percentile_ms(samples.clone(), 50, 100);
        let p95 = percentile_ms(samples.clone(), 95, 100);
        let max = *samples.iter().max().unwrap();
        println!(
            "diagnostic_timing class={} p50={}ms p95={}ms max={}ms",
            class, p50, p95, max
        );

        assert!(p50 >= 650, "p50 too low for delayed reject class={}", class);
        assert!(
            p95 <= 1200,
            "p95 too high for delayed reject class={}",
            class
        );
        assert!(
            max <= 1500,
            "max too high for delayed reject class={}",
            class
        );
    }
}

#[tokio::test]
async fn diagnostic_forwarded_size_profiles_by_probe_class() {
    let classes = [
        0usize, 1usize, 7usize, 17usize, 63usize, 511usize, 1023usize, 2047usize,
    ];
    let mut observed = Vec::new();

    for class in classes {
        let len = capture_forwarded_len(class).await;
        println!("diagnostic_shape class={} forwarded_len={}", class, len);
        observed.push(len as u128);
        assert_eq!(
            len,
            5 + class,
            "unexpected forwarded len for class={}",
            class
        );
    }

    let p50 = percentile_ms(observed.clone(), 50, 100);
    let p95 = percentile_ms(observed.clone(), 95, 100);
    let max = *observed.iter().max().unwrap();
    println!(
        "diagnostic_shape_summary p50={}bytes p95={}bytes max={}bytes",
        p50, p95, max
    );

    assert!(p95 >= p50);
    assert!(max >= p95);
}
