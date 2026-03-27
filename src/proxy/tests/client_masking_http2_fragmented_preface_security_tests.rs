use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::TcpListener;
use tokio::time::{Duration, sleep};

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

async fn run_http2_fragment_case(split_at: usize, delay_ms: u64, peer: SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();

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

    let first = split_at.min(preface.len());
    client_side.write_all(&preface[..first]).await.unwrap();
    if first < preface.len() {
        sleep(Duration::from_millis(delay_ms)).await;
        client_side.write_all(&preface[first..]).await.unwrap();
    }
    client_side.shutdown().await.unwrap();

    let forwarded = tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();
    assert!(
        forwarded.starts_with(&preface),
        "mask backend must receive an intact HTTP/2 preface prefix"
    );

    let result = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());

    let snapshot = beobachten.snapshot_text(Duration::from_secs(60));
    assert!(snapshot.contains("[HTTP]"));
    assert!(snapshot.contains(&format!("{}-1", peer.ip())));
}

#[tokio::test]
async fn http2_preface_fragmentation_matrix_is_classified_and_forwarded() {
    let cases = [(2usize, 0u64), (3, 0), (4, 0), (2, 7), (3, 7), (8, 1)];

    for (i, (split_at, delay_ms)) in cases.into_iter().enumerate() {
        let peer: SocketAddr = format!("198.51.100.{}:58{}", 140 + i, 100 + i)
            .parse()
            .unwrap();
        run_http2_fragment_case(split_at, delay_ms, peer).await;
    }
}

#[tokio::test]
async fn http2_preface_splitpoint_light_fuzz_classifies_http() {
    for split_at in 2usize..=12 {
        let delay_ms = if split_at % 3 == 0 { 7 } else { 1 };
        let peer: SocketAddr = format!("198.51.101.{}:59{}", split_at, 10 + split_at)
            .parse()
            .unwrap();
        run_http2_fragment_case(split_at, delay_ms, peer).await;
    }
}
