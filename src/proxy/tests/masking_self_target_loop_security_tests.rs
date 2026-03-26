use super::*;
use std::net::SocketAddr;
use std::net::TcpListener as StdTcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::TcpListener;
use tokio::time::{Duration, Instant, timeout};

fn closed_local_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

#[tokio::test]
async fn self_target_detection_matches_literal_ipv4_listener() {
    let local: SocketAddr = "198.51.100.40:443".parse().unwrap();
    assert!(is_mask_target_local_listener_async("198.51.100.40", 443, local, None,).await);
}

#[tokio::test]
async fn self_target_detection_matches_bracketed_ipv6_listener() {
    let local: SocketAddr = "[2001:db8::44]:8443".parse().unwrap();
    assert!(is_mask_target_local_listener_async("[2001:db8::44]", 8443, local, None,).await);
}

#[tokio::test]
async fn self_target_detection_keeps_same_ip_different_port_forwardable() {
    let local: SocketAddr = "203.0.113.44:443".parse().unwrap();
    assert!(!is_mask_target_local_listener_async("203.0.113.44", 8443, local, None,).await);
}

#[tokio::test]
async fn self_target_detection_normalizes_ipv4_mapped_ipv6_literal() {
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();
    assert!(is_mask_target_local_listener_async("::ffff:127.0.0.1", 443, local, None,).await);
}

#[tokio::test]
async fn self_target_detection_unspecified_bind_blocks_loopback_target() {
    let local: SocketAddr = "0.0.0.0:443".parse().unwrap();
    assert!(is_mask_target_local_listener_async("127.0.0.1", 443, local, None,).await);
}

#[tokio::test]
async fn self_target_detection_unspecified_bind_keeps_remote_target_forwardable() {
    let local: SocketAddr = "0.0.0.0:443".parse().unwrap();
    let remote: SocketAddr = "198.51.100.44:443".parse().unwrap();
    assert!(!is_mask_target_local_listener_async("mask.example", 443, local, Some(remote),).await);
}

#[tokio::test]
async fn self_target_fallback_refuses_recursive_loopback_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let accept_task = tokio::spawn(async move {
        timeout(Duration::from_millis(120), listener.accept())
            .await
            .is_ok()
    });

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_host = Some(local_addr.ip().to_string());
    config.censorship.mask_port = local_addr.port();
    config.censorship.mask_proxy_protocol = 0;

    let peer: SocketAddr = "203.0.113.90:55090".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    handle_bad_client(
        tokio::io::empty(),
        tokio::io::sink(),
        b"GET /",
        peer,
        local_addr,
        &config,
        &beobachten,
    )
    .await;

    let accepted = accept_task.await.unwrap();
    assert!(
        !accepted,
        "self-target masking must fail closed without connecting to local listener"
    );
}

#[tokio::test]
async fn same_ip_different_port_still_forwards_to_mask_backend() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let probe = b"GET /".to_vec();
    let accept_task = tokio::spawn({
        let expected = probe.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut got = vec![0u8; expected.len()];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected);
        }
    });

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_proxy_protocol = 0;

    let peer: SocketAddr = "203.0.113.91:55091".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    handle_bad_client(
        tokio::io::empty(),
        tokio::io::sink(),
        &probe,
        peer,
        local_addr,
        &config,
        &beobachten,
    )
    .await;

    timeout(Duration::from_secs(2), accept_task)
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn detect_client_type_http_boundary_get_and_post() {
    assert_eq!(detect_client_type(b"GET "), "HTTP");
    assert_eq!(detect_client_type(b"GET /"), "HTTP");

    assert_eq!(detect_client_type(b"POST"), "HTTP");
    assert_eq!(detect_client_type(b"POST "), "HTTP");
    assert_eq!(detect_client_type(b"POSTX"), "HTTP");
}

#[test]
fn detect_client_type_tls_and_length_boundaries() {
    assert_eq!(detect_client_type(b"\x16\x03\x01"), "port-scanner");
    assert_eq!(detect_client_type(b"\x16\x03\x01\x00"), "TLS-scanner");

    assert_eq!(detect_client_type(b"123456789"), "port-scanner");
    assert_eq!(detect_client_type(b"1234567890"), "unknown");
}

#[test]
fn build_mask_proxy_header_v1_cross_family_falls_back_to_unknown() {
    let peer: SocketAddr = "192.168.1.5:12345".parse().unwrap();
    let local: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    let header = build_mask_proxy_header(1, peer, local).unwrap();
    assert_eq!(header, b"PROXY UNKNOWN\r\n");
}

#[test]
fn next_mask_shape_bucket_checked_mul_overflow_fails_closed() {
    let floor = usize::MAX / 2 + 1;
    let cap = usize::MAX;
    let total = floor + 1;
    assert_eq!(next_mask_shape_bucket(total, floor, cap), total);
}

#[tokio::test]
async fn self_target_reject_path_keeps_timing_budget() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = 443;

    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let peer: SocketAddr = "203.0.113.92:55092".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let (client, server) = duplex(1024);
    drop(client);

    let started = Instant::now();
    handle_bad_client(
        server,
        tokio::io::sink(),
        b"GET / HTTP/1.1\r\n",
        peer,
        local_addr,
        &config,
        &beobachten,
    )
    .await;

    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(40) && elapsed < Duration::from_millis(250),
        "self-target reject path must keep coarse timing budget without stalling"
    );
}

#[tokio::test]
async fn relay_path_idle_timeout_eviction_remains_effective() {
    let (client_read, mut client_write) = duplex(1024);
    let (mask_read, mask_write) = duplex(1024);

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        client_write.write_all(b"a").await.unwrap();
        tokio::time::sleep(Duration::from_millis(180)).await;
        let _ = client_write.write_all(b"b").await;
    });

    let started = Instant::now();
    relay_to_mask(
        client_read,
        tokio::io::sink(),
        mask_read,
        mask_write,
        b"init",
        false,
        0,
        0,
        false,
        0,
        false,
        5 * 1024 * 1024,
    )
    .await;

    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(90) && elapsed < Duration::from_millis(180),
        "idle-timeout eviction must occur before late trickle write"
    );
}

#[tokio::test]
async fn offline_mask_target_refusal_respects_timing_normalization_budget() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = closed_local_port();
    config.censorship.mask_timing_normalization_enabled = true;
    config.censorship.mask_timing_normalization_floor_ms = 120;
    config.censorship.mask_timing_normalization_ceiling_ms = 120;

    let peer: SocketAddr = "203.0.113.93:55093".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let (mut client, server) = duplex(1024);
    let started = Instant::now();
    let task = tokio::spawn(async move {
        handle_bad_client(
            server,
            tokio::io::sink(),
            b"GET / HTTP/1.1\r\n\r\n",
            peer,
            local_addr,
            &config,
            &beobachten,
        )
        .await;
    });

    client.shutdown().await.unwrap();
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    let elapsed = started.elapsed();

    assert!(
        elapsed >= Duration::from_millis(110) && elapsed < Duration::from_millis(220),
        "offline-refusal path must honor normalization budget without unbounded drift"
    );
}

#[tokio::test]
async fn offline_mask_target_refusal_with_idle_client_is_bounded_by_consume_timeout() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = closed_local_port();
    config.censorship.mask_timing_normalization_enabled = false;

    let peer: SocketAddr = "203.0.113.94:55094".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let (mut client, server) = duplex(1024);
    let started = Instant::now();
    let task = tokio::spawn(async move {
        handle_bad_client(
            server,
            tokio::io::sink(),
            b"GET / HTTP/1.1\r\n\r\n",
            peer,
            local_addr,
            &config,
            &beobachten,
        )
        .await;
    });

    tokio::time::sleep(Duration::from_millis(120)).await;
    client
        .write_all(b"still-open-before-timeout")
        .await
        .expect("connection should still be open before consume timeout expires");

    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    let elapsed = started.elapsed();

    assert!(
        elapsed >= Duration::from_millis(190) && elapsed < Duration::from_millis(350),
        "offline-refusal path must not retain idle client indefinitely"
    );
}
