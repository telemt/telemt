use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::TcpListener;
use tokio::time::Duration;

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

fn expected_bucket(total: usize, floor: usize, cap: usize) -> usize {
    if total == 0 || floor == 0 || cap < floor {
        return total;
    }

    if total >= cap {
        return total;
    }

    let mut bucket = floor;
    while bucket < total {
        match bucket.checked_mul(2) {
            Some(next) => bucket = next,
            None => return total,
        }
        if bucket > cap {
            return cap;
        }
    }
    bucket
}

async fn run_probe_capture(
    body_sent: usize,
    tls_len: u16,
    enable_shape_hardening: bool,
    floor: usize,
    cap: usize,
) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_shape_hardening = enable_shape_hardening;
    cfg.censorship.mask_shape_bucket_floor_bytes = floor;
    cfg.censorship.mask_shape_bucket_cap_bytes = cap;

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut got)).await;
        got
    });

    let (server_side, mut client_side) = duplex(65536);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.199:56999".parse().unwrap(),
        Arc::new(cfg),
        Arc::new(Stats::new()),
        new_upstream_manager(Arc::new(Stats::new())),
        Arc::new(ReplayChecker::new(128, Duration::from_secs(60))),
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
    probe[3..5].copy_from_slice(&tls_len.to_be_bytes());
    probe[5..].fill(0x66);

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
async fn shape_hardening_non_power_of_two_cap_collapses_probe_classes() {
    let floor = 1000usize;
    let cap = 1500usize;

    let low = run_probe_capture(1195, 700, true, floor, cap).await;
    let high = run_probe_capture(1494, 700, true, floor, cap).await;

    assert_eq!(low.len(), 1500);
    assert_eq!(high.len(), 1500);
}

#[tokio::test]
async fn shape_hardening_disabled_keeps_non_power_of_two_cap_lengths_distinct() {
    let floor = 1000usize;
    let cap = 1500usize;

    let low = run_probe_capture(1195, 700, false, floor, cap).await;
    let high = run_probe_capture(1494, 700, false, floor, cap).await;

    assert_eq!(low.len(), 1200);
    assert_eq!(high.len(), 1499);
}

#[tokio::test]
async fn shape_hardening_parallel_stress_collapses_sub_cap_probes() {
    let floor = 1000usize;
    let cap = 1500usize;
    let mut tasks = Vec::new();

    for idx in 0..24usize {
        let body = 1001 + (idx * 19 % 480);
        tasks.push(tokio::spawn(async move {
            run_probe_capture(body, 1200, true, floor, cap).await.len()
        }));
    }

    for task in tasks {
        let observed = task.await.unwrap();
        assert_eq!(observed, 1500);
    }
}

#[tokio::test]
async fn shape_hardening_light_fuzz_matches_bucket_oracle() {
    let floor = 512usize;
    let cap = 4096usize;

    for step in 1usize..=36usize {
        let total = 1 + (((step * 313) ^ (step << 7)) % (cap + 300));
        let body = total.saturating_sub(5);

        let got = run_probe_capture(body, 650, true, floor, cap).await;
        let expected = expected_bucket(total, floor, cap);
        assert_eq!(
            got.len(),
            expected,
            "step={step} total={total} expected={expected} got={} ",
            got.len()
        );
    }
}
