//! Black-hat adversarial tests for truncated in-range TLS ClientHello probes.
//! These tests encode a strict anti-probing expectation: malformed TLS traffic
//! should still be masked as a legitimate website response.

use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use crate::protocol::constants::MIN_TLS_CLIENT_HELLO_SIZE;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

fn in_range_probe_header() -> [u8; 5] {
    [
        0x16,
        0x03,
        0x03,
        ((MIN_TLS_CLIENT_HELLO_SIZE >> 8) & 0xff) as u8,
        (MIN_TLS_CLIENT_HELLO_SIZE & 0xff) as u8,
    ]
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

fn truncated_in_range_record(actual_body_len: usize) -> Vec<u8> {
    let mut out = in_range_probe_header().to_vec();
    out.extend(std::iter::repeat_n(0x41, actual_body_len));
    out
}

async fn write_fragmented<W: AsyncWriteExt + Unpin>(writer: &mut W, bytes: &[u8], chunks: &[usize], delay_ms: u64) {
    let mut offset = 0usize;
    for &chunk in chunks {
        if offset >= bytes.len() {
            break;
        }
        let end = (offset + chunk).min(bytes.len());
        writer.write_all(&bytes[offset..end]).await.unwrap();
        offset = end;
        if delay_ms > 0 {
            sleep(Duration::from_millis(delay_ms)).await;
        }
    }
    if offset < bytes.len() {
        writer.write_all(&bytes[offset..]).await.unwrap();
    }
}

async fn run_blackhat_generic_fragmented_probe_should_mask(
    payload: Vec<u8>,
    chunks: &[usize],
    delay_ms: u64,
    backend_reply: Vec<u8>,
) {
    let mask_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mask_addr = mask_listener.local_addr().unwrap();
    let probe_header = in_range_probe_header();

    let mask_accept_task = tokio::spawn({
        let backend_reply = backend_reply.clone();
        async move {
            let (mut stream, _) = mask_listener.accept().await.unwrap();
            let mut got = [0u8; 5];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, probe_header);
            stream.write_all(&backend_reply).await.unwrap();
        }
    });

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.timeouts.client_handshake = 1;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = mask_addr.port();
    cfg.censorship.mask_proxy_protocol = 0;

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
    let peer: SocketAddr = "203.0.113.202:55002".parse().unwrap();

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

    write_fragmented(&mut client_side, &payload, chunks, delay_ms).await;
    client_side.shutdown().await.unwrap();

    let mut observed = vec![0u8; backend_reply.len()];
    tokio::time::timeout(Duration::from_secs(2), client_side.read_exact(&mut observed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observed, backend_reply);

    tokio::time::timeout(Duration::from_secs(2), mask_accept_task)
        .await
        .unwrap()
        .unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(2), handler)
        .await
        .unwrap()
        .unwrap();
}

async fn run_blackhat_client_handler_fragmented_probe_should_mask(
    payload: Vec<u8>,
    chunks: &[usize],
    delay_ms: u64,
    backend_reply: Vec<u8>,
) {
    let mask_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mask_addr = mask_listener.local_addr().unwrap();

    let front_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front_listener.local_addr().unwrap();

    let probe_header = in_range_probe_header();
    let mask_accept_task = tokio::spawn({
        let backend_reply = backend_reply.clone();
        async move {
            let (mut stream, _) = mask_listener.accept().await.unwrap();
            let mut got = [0u8; 5];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, probe_header);
            stream.write_all(&backend_reply).await.unwrap();
        }
    });

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.timeouts.client_handshake = 1;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = mask_addr.port();
    cfg.censorship.mask_proxy_protocol = 0;

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

    let mut client = TcpStream::connect(front_addr).await.unwrap();
    write_fragmented(&mut client, &payload, chunks, delay_ms).await;
    client.shutdown().await.unwrap();

    let mut observed = vec![0u8; backend_reply.len()];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut observed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observed, backend_reply);

    tokio::time::timeout(Duration::from_secs(2), mask_accept_task)
        .await
        .unwrap()
        .unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn blackhat_truncated_in_range_clienthello_generic_stream_should_mask() {
    let mask_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mask_addr = mask_listener.local_addr().unwrap();
    let backend_reply = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec();
    let probe = in_range_probe_header();

    let mask_accept_task = tokio::spawn({
        let backend_reply = backend_reply.clone();
        async move {
            let (mut stream, _) = mask_listener.accept().await.unwrap();
            let mut got = [0u8; 5];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, probe);
            stream.write_all(&backend_reply).await.unwrap();
        }
    });

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.timeouts.client_handshake = 1;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = mask_addr.port();
    cfg.censorship.mask_proxy_protocol = 0;

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
    let peer: SocketAddr = "203.0.113.201:55001".parse().unwrap();

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

    // Security expectation: even malformed in-range TLS should be masked.
    // This invariant must hold to avoid probe-distinguishable EOF/timeout behavior.
    let mut observed = vec![0u8; backend_reply.len()];
    tokio::time::timeout(Duration::from_secs(2), client_side.read_exact(&mut observed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observed, backend_reply);

    tokio::time::timeout(Duration::from_secs(2), mask_accept_task)
        .await
        .unwrap()
        .unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(2), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn blackhat_truncated_in_range_clienthello_client_handler_should_mask() {
    let mask_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mask_addr = mask_listener.local_addr().unwrap();

    let front_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front_listener.local_addr().unwrap();

    let backend_reply = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec();
    let probe = in_range_probe_header();

    let mask_accept_task = tokio::spawn({
        let backend_reply = backend_reply.clone();
        async move {
            let (mut stream, _) = mask_listener.accept().await.unwrap();
            let mut got = [0u8; 5];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, probe);
            stream.write_all(&backend_reply).await.unwrap();
        }
    });

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.timeouts.client_handshake = 1;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = mask_addr.port();
    cfg.censorship.mask_proxy_protocol = 0;

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

    let mut client = TcpStream::connect(front_addr).await.unwrap();
    client.write_all(&probe).await.unwrap();
    client.shutdown().await.unwrap();

    // Security expectation: malformed in-range TLS should still be masked.
    let mut observed = vec![0u8; backend_reply.len()];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut observed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observed, backend_reply);

    tokio::time::timeout(Duration::from_secs(2), mask_accept_task)
        .await
        .unwrap()
        .unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn blackhat_generic_truncated_min_body_1_should_mask() {
    run_blackhat_generic_fragmented_probe_should_mask(
        truncated_in_range_record(1),
        &[6],
        0,
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
    )
    .await;
}

#[tokio::test]
async fn blackhat_generic_truncated_min_body_8_should_mask() {
    run_blackhat_generic_fragmented_probe_should_mask(
        truncated_in_range_record(8),
        &[13],
        0,
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
    )
    .await;
}

#[tokio::test]
async fn blackhat_generic_truncated_min_body_99_should_mask() {
    run_blackhat_generic_fragmented_probe_should_mask(
        truncated_in_range_record(MIN_TLS_CLIENT_HELLO_SIZE - 1),
        &[5, MIN_TLS_CLIENT_HELLO_SIZE - 1],
        0,
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
    )
    .await;
}

#[tokio::test]
async fn blackhat_generic_fragmented_header_then_close_should_mask() {
    run_blackhat_generic_fragmented_probe_should_mask(
        truncated_in_range_record(0),
        &[1, 1, 1, 1, 1],
        0,
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
    )
    .await;
}

#[tokio::test]
async fn blackhat_generic_fragmented_header_plus_partial_body_should_mask() {
    run_blackhat_generic_fragmented_probe_should_mask(
        truncated_in_range_record(5),
        &[1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        0,
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
    )
    .await;
}

#[tokio::test]
async fn blackhat_generic_slowloris_fragmented_min_probe_should_mask_but_times_out() {
    run_blackhat_generic_fragmented_probe_should_mask(
        truncated_in_range_record(1),
        &[1, 1, 1, 1, 1, 1],
        250,
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
    )
    .await;
}

#[tokio::test]
async fn blackhat_client_handler_truncated_min_body_1_should_mask() {
    run_blackhat_client_handler_fragmented_probe_should_mask(
        truncated_in_range_record(1),
        &[6],
        0,
        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec(),
    )
    .await;
}

#[tokio::test]
async fn blackhat_client_handler_truncated_min_body_8_should_mask() {
    run_blackhat_client_handler_fragmented_probe_should_mask(
        truncated_in_range_record(8),
        &[13],
        0,
        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec(),
    )
    .await;
}

#[tokio::test]
async fn blackhat_client_handler_truncated_min_body_99_should_mask() {
    run_blackhat_client_handler_fragmented_probe_should_mask(
        truncated_in_range_record(MIN_TLS_CLIENT_HELLO_SIZE - 1),
        &[5, MIN_TLS_CLIENT_HELLO_SIZE - 1],
        0,
        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec(),
    )
    .await;
}

#[tokio::test]
async fn blackhat_client_handler_fragmented_header_then_close_should_mask() {
    run_blackhat_client_handler_fragmented_probe_should_mask(
        truncated_in_range_record(0),
        &[1, 1, 1, 1, 1],
        0,
        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec(),
    )
    .await;
}

#[tokio::test]
async fn blackhat_client_handler_fragmented_header_plus_partial_body_should_mask() {
    run_blackhat_client_handler_fragmented_probe_should_mask(
        truncated_in_range_record(5),
        &[1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        0,
        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec(),
    )
    .await;
}

#[tokio::test]
async fn blackhat_client_handler_slowloris_fragmented_min_probe_should_mask_but_times_out() {
    run_blackhat_client_handler_fragmented_probe_should_mask(
        truncated_in_range_record(1),
        &[1, 1, 1, 1, 1, 1],
        250,
        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec(),
    )
    .await;
}
