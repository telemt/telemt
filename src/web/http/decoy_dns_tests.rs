use super::*;

use arc_swap::ArcSwap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::config::WebCarrier;
use crate::maestro::generation::test_runtime_generation;
use crate::web::http::tests::{request, runtime_config};

#[tokio::test]
async fn decoy_dns_pinned_socket_keeps_configured_hostname_in_actual_http_request() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = runtime_config([17; 32], WebCarrier::Https);
    let snapshot = Arc::get_mut(config.web.runtime.as_mut().unwrap()).unwrap();
    let vhost = Arc::get_mut(snapshot.vhosts.get_mut("proxy.example.com").unwrap()).unwrap();
    // A public hostname deliberately paired with a loopback socket proves no request-time lookup.
    vhost.decoy = Arc::new(WebRuntimeDecoy::HttpUpstream {
        addr: origin.local_addr().unwrap(),
        authority: "bsi.bund.de:8080".to_string(),
    });
    let generation = test_runtime_generation(1, config);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(generation.clone())));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let receive = async {
        let (mut socket, _) = origin.accept().await.unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0; 1024];
        while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
            let count = socket.read(&mut buf).await.unwrap();
            assert_ne!(count, 0);
            bytes.extend_from_slice(&buf[..count]);
        }
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await
            .unwrap();
        String::from_utf8(bytes).unwrap()
    };
    let (response, upstream) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(request(&listener, &runtime, b"GET /site?q=1 HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nConnection: close\r\n\r\n".to_vec()), receive)
    }).await.unwrap();
    assert!(upstream.starts_with("GET /site?q=1 HTTP/1.1\r\n"));
    assert!(
        upstream
            .to_ascii_lowercase()
            .contains("\r\nhost: bsi.bund.de:8080\r\n")
    );
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(response.ends_with(b"OK"));
    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}
