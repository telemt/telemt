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

#[tokio::test]
async fn fragmented_connect_probe_is_classified_as_http_via_prefetch_window() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.unwrap();
        got
    });

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = true;
    cfg.general.beobachten_minutes = 1;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.general.modes.classic = false;
    cfg.general.modes.secure = false;

    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(4096);
    let peer: SocketAddr = "198.51.100.251:57501".parse().unwrap();

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        config,
        stats.clone(),
        new_upstream_manager(stats),
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

    client_side.write_all(b"CONNE").await.unwrap();
    client_side
        .write_all(b"CT example.org:443 HTTP/1.1\r\nHost: example.org\r\n\r\n")
        .await
        .unwrap();
    client_side.shutdown().await.unwrap();

    let forwarded = tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();
    assert!(
        forwarded.starts_with(b"CONNECT example.org:443 HTTP/1.1"),
        "mask backend must receive the full fragmented CONNECT probe"
    );

    let result = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());

    let snapshot = beobachten.snapshot_text(Duration::from_secs(60));
    assert!(snapshot.contains("[HTTP]"));
    assert!(snapshot.contains("198.51.100.251-1"));
}
