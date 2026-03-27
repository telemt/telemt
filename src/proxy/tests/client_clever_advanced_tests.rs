use super::*;
use crate::config::{ProxyConfig, UpstreamConfig, UpstreamType};
use crate::protocol::constants::{MAX_TLS_PLAINTEXT_SIZE, MIN_TLS_CLIENT_HELLO_SIZE};
use crate::stats::Stats;
use crate::transport::UpstreamManager;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf, duplex};
use tokio::net::TcpListener;

#[test]
fn edge_mask_reject_delay_min_greater_than_max_does_not_panic() {
    let mut config = ProxyConfig::default();
    config.censorship.server_hello_delay_min_ms = 5000;
    config.censorship.server_hello_delay_max_ms = 1000;

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let start = std::time::Instant::now();
        maybe_apply_mask_reject_delay(&config).await;
        let elapsed = start.elapsed();

        assert!(elapsed >= Duration::from_millis(1000));
        assert!(elapsed < Duration::from_millis(1500));
    });
}

#[test]
fn edge_handshake_timeout_with_mask_grace_saturating_add_prevents_overflow() {
    let mut config = ProxyConfig::default();
    config.timeouts.client_handshake = u64::MAX;
    config.censorship.mask = true;

    let timeout = handshake_timeout_with_mask_grace(&config);
    assert_eq!(timeout.as_secs(), u64::MAX);
}

#[test]
fn edge_tls_clienthello_len_in_bounds_exact_boundaries() {
    assert!(tls_clienthello_len_in_bounds(MIN_TLS_CLIENT_HELLO_SIZE));
    assert!(!tls_clienthello_len_in_bounds(
        MIN_TLS_CLIENT_HELLO_SIZE - 1
    ));
    assert!(tls_clienthello_len_in_bounds(MAX_TLS_PLAINTEXT_SIZE));
    assert!(!tls_clienthello_len_in_bounds(MAX_TLS_PLAINTEXT_SIZE + 1));
}

#[test]
fn edge_synthetic_local_addr_boundaries() {
    assert_eq!(synthetic_local_addr(0).port(), 0);
    assert_eq!(synthetic_local_addr(80).port(), 80);
    assert_eq!(synthetic_local_addr(u16::MAX).port(), u16::MAX);
}

#[test]
fn edge_beobachten_record_handshake_failure_class_stream_error_eof() {
    let beobachten = BeobachtenStore::new();
    let mut config = ProxyConfig::default();
    config.general.beobachten = true;
    config.general.beobachten_minutes = 1;

    let eof_err = ProxyError::Stream(crate::error::StreamError::UnexpectedEof);
    let peer_ip: IpAddr = "198.51.100.100".parse().unwrap();

    record_handshake_failure_class(&beobachten, &config, peer_ip, &eof_err);

    let snapshot = beobachten.snapshot_text(Duration::from_secs(60));
    assert!(snapshot.contains("[expected_64_got_0]"));
}

#[tokio::test]
async fn adversarial_tls_handshake_timeout_during_masking_delay() {
    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.timeouts.client_handshake = 1;
    cfg.censorship.mask = true;
    cfg.censorship.server_hello_delay_min_ms = 3000;
    cfg.censorship.server_hello_delay_max_ms = 3000;

    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());
    let (server_side, mut client_side) = duplex(4096);

    let handle = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.1:55000".parse().unwrap(),
        config,
        stats.clone(),
        Arc::new(UpstreamManager::new(
            vec![],
            1,
            1,
            1,
            1,
            false,
            stats.clone(),
        )),
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

    client_side
        .write_all(&[0x16, 0x03, 0x01, 0xFF, 0xFF])
        .await
        .unwrap();

    let result = tokio::time::timeout(Duration::from_secs(4), handle)
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(result, Err(ProxyError::TgHandshakeTimeout)));
    assert_eq!(stats.get_handshake_timeouts(), 1);
}

#[tokio::test]
async fn blackhat_proxy_protocol_slowloris_timeout() {
    let mut cfg = ProxyConfig::default();
    cfg.server.proxy_protocol_header_timeout_ms = 200;
    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());

    let (server_side, mut client_side) = duplex(4096);
    let handle = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.2:55000".parse().unwrap(),
        config,
        stats.clone(),
        Arc::new(UpstreamManager::new(
            vec![],
            1,
            1,
            1,
            1,
            false,
            stats.clone(),
        )),
        Arc::new(ReplayChecker::new(128, Duration::from_secs(60))),
        Arc::new(BufferPool::new()),
        Arc::new(SecureRandom::new()),
        None,
        Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        None,
        Arc::new(UserIpTracker::new()),
        Arc::new(BeobachtenStore::new()),
        true,
    ));

    client_side.write_all(b"PROXY TCP4 192.").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let result = tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(result, Err(ProxyError::InvalidProxyProtocol)));
    assert_eq!(stats.get_connects_bad(), 1);
}

#[test]
fn blackhat_ipv4_mapped_ipv6_proxy_source_bypass_attempt() {
    let trusted = vec!["192.0.2.0/24".parse().unwrap()];
    let peer_ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201));
    assert!(!is_trusted_proxy_source(peer_ip, &trusted));
}

#[tokio::test]
async fn negative_proxy_protocol_enabled_but_client_sends_tls_hello() {
    let mut cfg = ProxyConfig::default();
    cfg.server.proxy_protocol_header_timeout_ms = 500;
    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());

    let (server_side, mut client_side) = duplex(4096);
    let handle = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.3:55000".parse().unwrap(),
        config,
        stats.clone(),
        Arc::new(UpstreamManager::new(
            vec![],
            1,
            1,
            1,
            1,
            false,
            stats.clone(),
        )),
        Arc::new(ReplayChecker::new(128, Duration::from_secs(60))),
        Arc::new(BufferPool::new()),
        Arc::new(SecureRandom::new()),
        None,
        Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        None,
        Arc::new(UserIpTracker::new()),
        Arc::new(BeobachtenStore::new()),
        true,
    ));

    client_side
        .write_all(&[0x16, 0x03, 0x01, 0x02, 0x00])
        .await
        .unwrap();

    let result = tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(result, Err(ProxyError::InvalidProxyProtocol)));
    assert_eq!(stats.get_connects_bad(), 1);
}

#[tokio::test]
async fn edge_client_stream_exactly_4_bytes_eof() {
    let config = Arc::new(ProxyConfig::default());
    let stats = Arc::new(Stats::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(4096);
    let handle = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.4:55000".parse().unwrap(),
        config,
        stats.clone(),
        Arc::new(UpstreamManager::new(
            vec![],
            1,
            1,
            1,
            1,
            false,
            stats.clone(),
        )),
        Arc::new(ReplayChecker::new(128, Duration::from_secs(60))),
        Arc::new(BufferPool::new()),
        Arc::new(SecureRandom::new()),
        None,
        Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        None,
        Arc::new(UserIpTracker::new()),
        beobachten.clone(),
        false,
    ));

    client_side
        .write_all(&[0x16, 0x03, 0x01, 0x00])
        .await
        .unwrap();
    client_side.shutdown().await.unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;

    let snapshot = beobachten.snapshot_text(Duration::from_secs(60));
    assert!(snapshot.contains("[expected_64_got_0]"));
}

#[tokio::test]
async fn edge_client_stream_tls_header_valid_but_body_1_byte_short_eof() {
    let config = Arc::new(ProxyConfig::default());
    let stats = Arc::new(Stats::new());

    let (server_side, mut client_side) = duplex(4096);
    let handle = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.5:55000".parse().unwrap(),
        config,
        stats.clone(),
        Arc::new(UpstreamManager::new(
            vec![],
            1,
            1,
            1,
            1,
            false,
            stats.clone(),
        )),
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

    client_side
        .write_all(&[0x16, 0x03, 0x01, 0x00, 100])
        .await
        .unwrap();
    client_side.write_all(&vec![0x41; 99]).await.unwrap();
    client_side.shutdown().await.unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    assert_eq!(stats.get_connects_bad(), 1);
}

#[tokio::test]
async fn integration_non_tls_modes_disabled_immediately_masks() {
    let mut cfg = ProxyConfig::default();
    cfg.general.modes.classic = false;
    cfg.general.modes.secure = false;
    cfg.censorship.mask = true;
    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());

    let (server_side, mut client_side) = duplex(4096);
    let handle = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.6:55000".parse().unwrap(),
        config,
        stats.clone(),
        Arc::new(UpstreamManager::new(
            vec![],
            1,
            1,
            1,
            1,
            false,
            stats.clone(),
        )),
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

    client_side.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    assert_eq!(stats.get_connects_bad(), 1);
}

struct YieldingReader {
    data: Vec<u8>,
    pos: usize,
    yields_left: usize,
}

impl AsyncRead for YieldingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.yields_left > 0 {
            this.yields_left -= 1;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if this.pos >= this.data.len() {
            return Poll::Ready(Ok(()));
        }
        buf.put_slice(&this.data[this.pos..this.pos + 1]);
        this.pos += 1;
        this.yields_left = 2;
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn fuzz_read_with_progress_heavy_yielding() {
    let expected_data = b"HEAVY_YIELD_TEST_DATA".to_vec();
    let mut reader = YieldingReader {
        data: expected_data.clone(),
        pos: 0,
        yields_left: 2,
    };

    let mut buf = vec![0u8; expected_data.len()];
    let read_bytes = read_with_progress(&mut reader, &mut buf).await.unwrap();

    assert_eq!(read_bytes, expected_data.len());
    assert_eq!(buf, expected_data);
}

#[test]
fn edge_wrap_tls_application_record_exactly_u16_max() {
    let payload = vec![0u8; 65535];
    let wrapped = wrap_tls_application_record(&payload);
    assert_eq!(wrapped.len(), 65540);
    assert_eq!(wrapped[0], TLS_RECORD_APPLICATION);
    assert_eq!(&wrapped[3..5], &65535u16.to_be_bytes());
}

#[test]
fn fuzz_wrap_tls_application_record_lengths() {
    let lengths = [0, 1, 65534, 65535, 65536, 131070, 131071, 131072];
    for len in lengths {
        let payload = vec![0u8; len];
        let wrapped = wrap_tls_application_record(&payload);
        let expected_chunks = len.div_ceil(65535).max(1);
        assert_eq!(wrapped.len(), len + 5 * expected_chunks);
    }
}

#[tokio::test]
async fn stress_user_connection_reservation_concurrent_same_ip_exhaustion() {
    let user = "stress-same-ip-user";
    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 5);

    let config = Arc::new(config);
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 10).await;

    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)), 55000);

    let mut tasks = tokio::task::JoinSet::new();
    let mut reservations = Vec::new();

    for _ in 0..10 {
        let config = config.clone();
        let stats = stats.clone();
        let ip_tracker = ip_tracker.clone();
        tasks.spawn(async move {
            RunningClientHandler::acquire_user_connection_reservation_static(
                user, &config, stats, peer, ip_tracker,
            )
            .await
        });
    }

    let mut successes = 0;
    let mut failures = 0;

    while let Some(res) = tasks.join_next().await {
        match res.unwrap() {
            Ok(r) => {
                successes += 1;
                reservations.push(r);
            }
            Err(_) => failures += 1,
        }
    }

    assert_eq!(successes, 5);
    assert_eq!(failures, 5);
    assert_eq!(stats.get_user_curr_connects(user), 5);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 1);

    for reservation in reservations {
        reservation.release().await;
    }

    assert_eq!(stats.get_user_curr_connects(user), 0);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0);
}
