use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use std::sync::Arc;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
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
        "198.51.100.211:57011".parse().unwrap(),
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

    let _ = tokio::time::timeout(Duration::from_secs(4), handler)
        .await
        .unwrap()
        .unwrap();

    tokio::time::timeout(Duration::from_secs(4), accept_task)
        .await
        .unwrap()
        .unwrap()
}

async fn measure_reject_ms(body_sent: usize) -> u128 {
    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.timeouts.client_handshake = 1;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = 1;
    cfg.censorship.server_hello_delay_min_ms = 700;
    cfg.censorship.server_hello_delay_max_ms = 700;

    let (server_side, mut client_side) = duplex(65536);
    let started = Instant::now();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.212:57012".parse().unwrap(),
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
    probe[3..5].copy_from_slice(&600u16.to_be_bytes());
    probe[5..].fill(0x44);

    client_side.write_all(&probe).await.unwrap();
    client_side.shutdown().await.unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(4), handler)
        .await
        .unwrap()
        .unwrap();

    started.elapsed().as_millis()
}

#[tokio::test]
#[ignore = "red-team expected-fail: above-cap exact length still leaks classifier signal"]
async fn redteam_shape_01_above_cap_flows_should_collapse_to_single_class() {
    let floor = 512usize;
    let cap = 4096usize;

    let a = run_probe_capture(5000, 7000, true, floor, cap).await;
    let b = run_probe_capture(6000, 7000, true, floor, cap).await;

    assert_eq!(
        a.len(),
        b.len(),
        "strict anti-classifier model expects same backend length class above cap"
    );
}

#[tokio::test]
#[ignore = "red-team expected-fail: current padding bytes are deterministic zeros"]
async fn redteam_shape_02_padding_tail_must_be_non_deterministic() {
    let floor = 512usize;
    let cap = 4096usize;
    let got = run_probe_capture(17, 600, true, floor, cap).await;

    assert!(
        got.len() > 22,
        "test requires padding tail to exist"
    );

    let tail = &got[22..];
    assert!(
        tail.iter().any(|b| *b != 0),
        "padding tail is fully zeroed and thus deterministic"
    );
}

#[tokio::test]
#[ignore = "red-team expected-fail: exact-floor probes still expose boundary class"]
async fn redteam_shape_03_exact_floor_input_should_not_be_fixed_point() {
    let floor = 512usize;
    let cap = 4096usize;
    let got = run_probe_capture(507, 600, true, floor, cap).await;

    assert!(
        got.len() > floor,
        "strict model expects extra blur even when input lands exactly on floor"
    );
}

#[tokio::test]
#[ignore = "red-team expected-fail: strict one-bucket collapse hypothesis"]
async fn redteam_shape_04_all_sub_cap_sizes_should_collapse_to_single_size() {
    let floor = 512usize;
    let cap = 4096usize;
    let classes = [17usize, 63usize, 255usize, 511usize, 1023usize, 2047usize, 3071usize];

    let mut observed = Vec::new();
    for body in classes {
        observed.push(run_probe_capture(body, 1200, true, floor, cap).await.len());
    }

    let first = observed[0];
    for v in observed {
        assert_eq!(v, first, "strict model expects one collapsed class across all sub-cap probes");
    }
}

#[tokio::test]
#[ignore = "red-team expected-fail: over-strict micro-timing invariance"]
async fn redteam_shape_05_reject_timing_spread_should_be_under_2ms() {
    let classes = [17usize, 511usize, 1023usize, 2047usize, 4095usize];
    let mut values = Vec::new();

    for class in classes {
        values.push(measure_reject_ms(class).await);
    }

    let min = *values.iter().min().unwrap();
    let max = *values.iter().max().unwrap();
    assert!(
        min == 700 && max == 700,
        "strict model requires exact 700ms for every malformed class: min={min}ms max={max}ms"
    );
}

#[test]
#[ignore = "red-team expected-fail: secure-by-default hypothesis"]
fn redteam_shape_06_shape_hardening_should_be_secure_by_default() {
    let cfg = ProxyConfig::default();
    assert!(
        cfg.censorship.mask_shape_hardening,
        "strict model expects shape hardening enabled by default"
    );
}
