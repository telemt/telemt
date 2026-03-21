//! Differential timing-profile adversarial tests.
//! Compare malformed in-range TLS truncation probes with plain web baselines,
//! ensuring masking behavior stays in similar latency buckets.

use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use crate::protocol::constants::MIN_TLS_CLIENT_HELLO_SIZE;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::{TcpListener, TcpStream};

const REPLY_404: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

#[derive(Clone, Copy, Debug)]
enum ProbeClass {
    MalformedTlsTruncation,
    PlainWebBaseline,
}

fn make_test_upstream_manager(stats: Arc<Stats>) -> Arc<UpstreamManager> {
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

fn malformed_tls_probe() -> Vec<u8> {
    vec![
        0x16,
        0x03,
        0x03,
        ((MIN_TLS_CLIENT_HELLO_SIZE >> 8) & 0xff) as u8,
        (MIN_TLS_CLIENT_HELLO_SIZE & 0xff) as u8,
        0x41,
    ]
}

fn plain_web_probe() -> Vec<u8> {
    b"GET /timing-profile HTTP/1.1\r\nHost: front.example\r\n\r\n".to_vec()
}

fn summarize(samples_ms: &[u128]) -> (f64, u128, u128, u128) {
    let mut sorted = samples_ms.to_vec();
    sorted.sort_unstable();
    let sum: u128 = sorted.iter().copied().sum();
    let mean = sum as f64 / sorted.len() as f64;
    let min = sorted[0];
    let p95_idx = ((sorted.len() as f64) * 0.95).floor() as usize;
    let p95 = sorted[p95_idx.min(sorted.len() - 1)];
    let max = sorted[sorted.len() - 1];
    (mean, min, p95, max)
}

async fn run_generic_once(class: ProbeClass) -> u128 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let backend_reply = REPLY_404.to_vec();

    let accept_task = tokio::spawn({
        let backend_reply = backend_reply.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&backend_reply).await.unwrap();
        }
    });

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.timeouts.client_handshake = 1;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_proxy_protocol = 0;

    if matches!(class, ProbeClass::PlainWebBaseline) {
        cfg.general.modes.classic = false;
        cfg.general.modes.secure = false;
    }

    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());
    let upstream_manager = make_test_upstream_manager(stats.clone());
    let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let ip_tracker = Arc::new(UserIpTracker::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(4096);
    let peer: SocketAddr = "203.0.113.210:55110".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        config,
        stats,
        upstream_manager,
        replay_checker,
        buffer_pool,
        rng,
        None,
        route_runtime,
        None,
        ip_tracker,
        beobachten,
        false,
    ));

    let probe = match class {
        ProbeClass::MalformedTlsTruncation => malformed_tls_probe(),
        ProbeClass::PlainWebBaseline => plain_web_probe(),
    };

    let started = Instant::now();
    client_side.write_all(&probe).await.unwrap();
    client_side.shutdown().await.unwrap();

    let mut observed = vec![0u8; REPLY_404.len()];
    tokio::time::timeout(
        Duration::from_secs(2),
        client_side.read_exact(&mut observed),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(observed, REPLY_404);

    tokio::time::timeout(Duration::from_secs(2), accept_task)
        .await
        .unwrap()
        .unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(2), handler)
        .await
        .unwrap()
        .unwrap();

    started.elapsed().as_millis()
}

async fn run_client_handler_once(class: ProbeClass) -> u128 {
    let mask_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = mask_listener.local_addr().unwrap();

    let front_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front_listener.local_addr().unwrap();

    let backend_reply = REPLY_404.to_vec();
    let mask_accept_task = tokio::spawn({
        let backend_reply = backend_reply.clone();
        async move {
            let (mut stream, _) = mask_listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&backend_reply).await.unwrap();
        }
    });

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.timeouts.client_handshake = 1;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_proxy_protocol = 0;

    if matches!(class, ProbeClass::PlainWebBaseline) {
        cfg.general.modes.classic = false;
        cfg.general.modes.secure = false;
    }

    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());
    let upstream_manager = make_test_upstream_manager(stats.clone());
    let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
    let buffer_pool = Arc::new(BufferPool::new());
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let ip_tracker = Arc::new(UserIpTracker::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let server_task = {
        let config = config.clone();
        let stats = stats.clone();
        let upstream_manager = upstream_manager.clone();
        let replay_checker = replay_checker.clone();
        let buffer_pool = buffer_pool.clone();
        let rng = rng.clone();
        let route_runtime = route_runtime.clone();
        let ip_tracker = ip_tracker.clone();
        let beobachten = beobachten.clone();

        tokio::spawn(async move {
            let (stream, peer) = front_listener.accept().await.unwrap();
            let real_peer_report = Arc::new(std::sync::Mutex::new(None));
            ClientHandler::new(
                stream,
                peer,
                config,
                stats,
                upstream_manager,
                replay_checker,
                buffer_pool,
                rng,
                None,
                route_runtime,
                None,
                ip_tracker,
                beobachten,
                false,
                real_peer_report,
            )
            .run()
            .await
        })
    };

    let probe = match class {
        ProbeClass::MalformedTlsTruncation => malformed_tls_probe(),
        ProbeClass::PlainWebBaseline => plain_web_probe(),
    };

    let mut client = TcpStream::connect(front_addr).await.unwrap();
    let started = Instant::now();
    client.write_all(&probe).await.unwrap();
    client.shutdown().await.unwrap();

    let mut observed = vec![0u8; REPLY_404.len()];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut observed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observed, REPLY_404);

    tokio::time::timeout(Duration::from_secs(2), mask_accept_task)
        .await
        .unwrap()
        .unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .unwrap()
        .unwrap();

    started.elapsed().as_millis()
}

#[tokio::test]
async fn differential_timing_generic_malformed_tls_vs_plain_web_mask_profile_similar() {
    const ITER: usize = 24;
    const BUCKET_MS: u128 = 20;

    let mut malformed = Vec::with_capacity(ITER);
    let mut plain = Vec::with_capacity(ITER);

    for _ in 0..ITER {
        malformed.push(run_generic_once(ProbeClass::MalformedTlsTruncation).await);
        plain.push(run_generic_once(ProbeClass::PlainWebBaseline).await);
    }

    let (m_mean, m_min, m_p95, m_max) = summarize(&malformed);
    let (p_mean, p_min, p_p95, p_max) = summarize(&plain);

    println!(
        "TIMING_DIFF generic class=malformed mean_ms={:.2} min_ms={} p95_ms={} max_ms={} bucket_mean={} bucket_p95={}",
        m_mean,
        m_min,
        m_p95,
        m_max,
        (m_mean as u128) / BUCKET_MS,
        m_p95 / BUCKET_MS
    );
    println!(
        "TIMING_DIFF generic class=plain_web mean_ms={:.2} min_ms={} p95_ms={} max_ms={} bucket_mean={} bucket_p95={}",
        p_mean,
        p_min,
        p_p95,
        p_max,
        (p_mean as u128) / BUCKET_MS,
        p_p95 / BUCKET_MS
    );

    let mean_bucket_delta = ((m_mean as i128) - (p_mean as i128)).abs() / (BUCKET_MS as i128);
    let p95_bucket_delta = ((m_p95 as i128) - (p_p95 as i128)).abs() / (BUCKET_MS as i128);

    assert!(
        mean_bucket_delta <= 1,
        "generic timing mean diverged: malformed_mean_ms={:.2}, plain_mean_ms={:.2}",
        m_mean,
        p_mean
    );
    assert!(
        p95_bucket_delta <= 2,
        "generic timing p95 diverged: malformed_p95_ms={}, plain_p95_ms={}",
        m_p95,
        p_p95
    );
}

#[tokio::test]
async fn differential_timing_client_handler_malformed_tls_vs_plain_web_mask_profile_similar() {
    const ITER: usize = 16;
    const BUCKET_MS: u128 = 20;

    let mut malformed = Vec::with_capacity(ITER);
    let mut plain = Vec::with_capacity(ITER);

    for _ in 0..ITER {
        malformed.push(run_client_handler_once(ProbeClass::MalformedTlsTruncation).await);
        plain.push(run_client_handler_once(ProbeClass::PlainWebBaseline).await);
    }

    let (m_mean, m_min, m_p95, m_max) = summarize(&malformed);
    let (p_mean, p_min, p_p95, p_max) = summarize(&plain);

    println!(
        "TIMING_DIFF handler class=malformed mean_ms={:.2} min_ms={} p95_ms={} max_ms={} bucket_mean={} bucket_p95={}",
        m_mean,
        m_min,
        m_p95,
        m_max,
        (m_mean as u128) / BUCKET_MS,
        m_p95 / BUCKET_MS
    );
    println!(
        "TIMING_DIFF handler class=plain_web mean_ms={:.2} min_ms={} p95_ms={} max_ms={} bucket_mean={} bucket_p95={}",
        p_mean,
        p_min,
        p_p95,
        p_max,
        (p_mean as u128) / BUCKET_MS,
        p_p95 / BUCKET_MS
    );

    let mean_bucket_delta = ((m_mean as i128) - (p_mean as i128)).abs() / (BUCKET_MS as i128);
    let p95_bucket_delta = ((m_p95 as i128) - (p_p95 as i128)).abs() / (BUCKET_MS as i128);

    assert!(
        mean_bucket_delta <= 1,
        "handler timing mean diverged: malformed_mean_ms={:.2}, plain_mean_ms={:.2}",
        m_mean,
        p_mean
    );
    assert!(
        p95_bucket_delta <= 2,
        "handler timing p95 diverged: malformed_p95_ms={}, plain_p95_ms={}",
        m_p95,
        p_p95
    );
}
