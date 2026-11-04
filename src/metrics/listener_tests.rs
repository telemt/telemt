use super::*;
use std::io;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

async fn scrape(listen: &str, source: &str, whitelist: &[&str]) -> Vec<u8> {
    let bound = bind(0, Some(listen.to_string()), 128).unwrap();
    let port = bound.listeners[0].0.local_addr().unwrap().port();
    let source: IpAddr = source.parse().unwrap();
    let target: IpAddr = if source.is_ipv4() { "127.0.0.1" } else { "::1" }
        .parse()
        .unwrap();
    let mut config = ProxyConfig::default();
    config.server.metrics_whitelist = whitelist.iter().map(|cidr| cidr.parse().unwrap()).collect();
    let runtime = crate::maestro::generation::test_runtime_generation(1, config);
    runtime.stats.increment_connects_all();
    let control_plane = ProcessControlPlane::new();
    let web_control = crate::web::control::WebRuntimeControl::new();
    serve(
        bound,
        Arc::new(ArcSwap::from(runtime)),
        web_control.subscribe(),
        Arc::new(TlsFullCertBudget::new()),
        control_plane.clone(),
    );
    let result = timeout(Duration::from_secs(5), async {
        let socket = if source.is_ipv4() {
            TcpSocket::new_v4().unwrap()
        } else {
            TcpSocket::new_v6().unwrap()
        };
        socket.bind(SocketAddr::new(source, 0)).unwrap();
        let mut stream = socket.connect(SocketAddr::new(target, port)).await.unwrap();
        let mut response = Vec::new();
        // Admission must depend on the socket peer, never on claimed forwarding headers.
        let request = b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nX-Forwarded-For: 127.0.0.1\r\nForwarded: for=127.0.0.1\r\n\r\n";
        match stream.write_all(request).await {
            Ok(()) => {}
            Err(error) if matches!(error.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset) => {
                return response;
            }
            Err(error) => panic!("metrics request write failed: {error}"),
        }
        match stream.read_to_end(&mut response).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            Err(error) => panic!("metrics response read failed: {error}"),
        }
        response
    })
    .await;
    assert!(control_plane.shutdown(Duration::from_secs(2)).await);
    result.expect("metrics socket must respond or reject within the test deadline")
}

fn assert_metrics(response: &[u8]) {
    let response = std::str::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response:?}");
    assert!(
        response.contains("telemt_connections_total 1"),
        "{response}"
    );
}

#[tokio::test]
async fn dual_stack_listener_accepts_ipv4_whitelist() {
    assert_metrics(&scrape("[::]:0", "127.0.0.1", &["127.0.0.1/32"]).await);
    assert_metrics(&scrape("[::]:0", "127.0.0.2", &["127.0.0.0/8"]).await);
}

#[tokio::test]
async fn dual_stack_listener_preserves_ipv6_whitelist_semantics() {
    assert_metrics(&scrape("[::]:0", "127.0.0.2", &["::ffff:127.0.0.0/104"]).await);
    assert_metrics(&scrape("[::]:0", "127.0.0.1", &["::/0"]).await);
    assert_metrics(&scrape("[::]:0", "::1", &["::1/128"]).await);
}

#[tokio::test]
async fn dual_stack_listener_rejects_unlisted_peers_and_forwarded_headers() {
    for (source, whitelist) in [
        ("127.0.0.2", "127.0.0.1/32"),
        ("127.0.0.1", "::1/128"),
        ("::1", "127.0.0.0/8"),
        ("::1", "2001:db8::/32"),
    ] {
        assert!(scrape("[::]:0", source, &[whitelist]).await.is_empty());
    }
}

#[tokio::test]
async fn explicit_ipv4_listener_and_empty_whitelist_still_work() {
    assert_metrics(&scrape("0.0.0.0:0", "127.0.0.1", &["127.0.0.1/32"]).await);
    assert!(
        scrape("0.0.0.0:0", "127.0.0.2", &["127.0.0.1/32"])
            .await
            .is_empty()
    );
    assert_metrics(&scrape("[::]:0", "127.0.0.1", &[]).await);
    assert_metrics(&scrape("[::]:0", "::1", &[]).await);
}

#[tokio::test]
async fn metrics_port_defaults_to_loopback_not_all_interfaces() {
    let bound = bind(0, None, 128).unwrap();
    assert!(!bound.listeners.is_empty());
    for (listener, _) in &bound.listeners {
        let address = listener.local_addr().unwrap();
        assert!(address.ip().is_loopback());
        if address.is_ipv4() {
            let other = SocketAddr::new("127.0.0.2".parse().unwrap(), address.port());
            let error = timeout(Duration::from_secs(2), TcpStream::connect(other))
                .await
                .expect("unbound interface must reject promptly")
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        }
    }
}

#[tokio::test]
async fn explicit_metrics_listen_overrides_port_and_accepts_other_interfaces() {
    let bound = bind(1, Some("0.0.0.0:0".to_string()), 128).unwrap();
    assert_eq!(bound.listeners.len(), 1);
    let address = bound.listeners[0].0.local_addr().unwrap();
    assert!(address.ip().is_unspecified());
    assert_ne!(address.port(), 1);
    let other = SocketAddr::new("127.0.0.2".parse().unwrap(), address.port());
    let client = timeout(Duration::from_secs(2), TcpStream::connect(other))
        .await
        .unwrap()
        .unwrap();
    let (accepted, _) = timeout(Duration::from_secs(2), bound.listeners[0].0.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.local_addr().unwrap().ip(), other.ip());
    drop(client);
}
