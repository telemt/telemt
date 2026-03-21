use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::{TcpListener, TcpStream};

const REPLY_404: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

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

fn masking_config(mask_port: u16) -> Arc<ProxyConfig> {
    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.timeouts.client_handshake = 1;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = mask_port;
    cfg.censorship.mask_proxy_protocol = 0;
    Arc::new(cfg)
}

async fn run_generic_probe_and_capture_prefix(payload: Vec<u8>, expected_prefix: Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let reply = REPLY_404.to_vec();
    let prefix_len = expected_prefix.len();

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = vec![0u8; prefix_len];
        stream.read_exact(&mut got).await.unwrap();
        stream.write_all(&reply).await.unwrap();
        got
    });

    let config = masking_config(backend_addr.port());
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

    client_side.write_all(&payload).await.unwrap();
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

    let got = tokio::time::timeout(Duration::from_secs(2), accept_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, expected_prefix);

    let result = tokio::time::timeout(Duration::from_secs(2), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
}

async fn read_http_probe_header(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    let mut one = [0u8; 1];

    loop {
        stream.read_exact(&mut one).await.unwrap();
        out.push(one[0]);
        if out.ends_with(b"\r\n\r\n") {
            break;
        }
        assert!(
            out.len() <= 512,
            "probe header exceeded sane limit while waiting for terminator"
        );
    }

    out
}

#[tokio::test]
async fn blackhat_fragmented_plain_http_probe_masks_and_preserves_prefix() {
    let payload = b"GET /probe-evasion HTTP/1.1\r\nHost: front.example\r\n\r\n".to_vec();
    run_generic_probe_and_capture_prefix(payload.clone(), payload).await;
}

#[tokio::test]
async fn blackhat_invalid_tls_like_probe_masks_and_preserves_header_prefix() {
    let payload = vec![0x16, 0x03, 0x03, 0x00, 0x64, 0x01, 0x00];
    run_generic_probe_and_capture_prefix(payload.clone(), payload).await;
}

#[tokio::test]
async fn integration_client_handler_plain_probe_masks_and_preserves_prefix() {
    let mask_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = mask_listener.local_addr().unwrap();

    let front_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front_listener.local_addr().unwrap();

    let payload = b"GET /integration-probe HTTP/1.1\r\nHost: a.example\r\n\r\n".to_vec();
    let expected_prefix = payload.clone();

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = mask_listener.accept().await.unwrap();
        let mut got = vec![0u8; expected_prefix.len()];
        stream.read_exact(&mut got).await.unwrap();
        stream.write_all(REPLY_404).await.unwrap();
        got
    });

    let config = masking_config(backend_addr.port());
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

    let mut client = TcpStream::connect(front_addr).await.unwrap();
    client.write_all(&payload).await.unwrap();
    client.shutdown().await.unwrap();

    let mut observed = vec![0u8; REPLY_404.len()];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut observed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observed, REPLY_404);

    let got = tokio::time::timeout(Duration::from_secs(2), accept_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, payload);

    let result = tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
}

#[tokio::test]
async fn light_fuzz_small_probe_variants_always_mask_and_preserve_declared_prefix() {
    let mut rng = StdRng::seed_from_u64(0xA11E_5EED_F0F0_CAFE);

    for i in 0..24usize {
        let mut payload = if rng.random::<bool>() {
            b"GET /fuzz HTTP/1.1\r\nHost: fuzz.example\r\n\r\n".to_vec()
        } else {
            vec![0x16, 0x03, 0x03, 0x00, 0x64]
        };

        let tail_len = rng.random_range(0..=8usize);
        for _ in 0..tail_len {
            payload.push(rng.random::<u8>());
        }

        let expected_prefix = payload.clone();
        run_generic_probe_and_capture_prefix(payload, expected_prefix).await;

        if i % 6 == 0 {
            tokio::task::yield_now().await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_parallel_probe_mix_masks_all_sessions_without_cross_leakage() {
    let session_count = 12usize;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut expected = std::collections::HashSet::new();
    for idx in 0..session_count {
        let probe =
            format!("GET /stress-{idx} HTTP/1.1\r\nHost: s{idx}.example\r\n\r\n").into_bytes();
        expected.insert(probe);
    }

    let accept_task = tokio::spawn(async move {
        let mut remaining = expected;
        for _ in 0..session_count {
            let (mut stream, _) = listener.accept().await.unwrap();
            let head = read_http_probe_header(&mut stream).await;
            stream.write_all(REPLY_404).await.unwrap();
            assert!(
                remaining.remove(&head),
                "backend received unexpected or duplicated probe prefix"
            );
        }
        assert!(
            remaining.is_empty(),
            "all session prefixes must be observed exactly once"
        );
    });

    let mut tasks = Vec::with_capacity(session_count);
    for idx in 0..session_count {
        let config = masking_config(backend_addr.port());
        let stats = Arc::new(Stats::new());
        let upstream_manager = make_test_upstream_manager(stats.clone());
        let replay_checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(60)));
        let buffer_pool = Arc::new(BufferPool::new());
        let rng = Arc::new(SecureRandom::new());
        let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
        let ip_tracker = Arc::new(UserIpTracker::new());
        let beobachten = Arc::new(BeobachtenStore::new());

        let probe =
            format!("GET /stress-{idx} HTTP/1.1\r\nHost: s{idx}.example\r\n\r\n").into_bytes();
        let peer: SocketAddr = format!("203.0.113.{}:{}", 30 + idx, 56000 + idx)
            .parse()
            .unwrap();

        tasks.push(tokio::spawn(async move {
            let (server_side, mut client_side) = duplex(4096);
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

            let result = tokio::time::timeout(Duration::from_secs(2), handler)
                .await
                .unwrap()
                .unwrap();
            assert!(result.is_ok());
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }

    tokio::time::timeout(Duration::from_secs(4), accept_task)
        .await
        .unwrap()
        .unwrap();
}
