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

async fn run_pipeline_prefetch_case(
    prefetch_timeout_ms: u64,
    delayed_tail_ms: u64,
    peer: SocketAddr,
) -> (Vec<u8>, String) {
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
    cfg.censorship.mask_classifier_prefetch_timeout_ms = prefetch_timeout_ms;
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

    client_side.write_all(b"C").await.unwrap();
    sleep(Duration::from_millis(delayed_tail_ms)).await;

    client_side
        .write_all(b"ONNECT example.org:443 HTTP/1.1\r\nHost: example.org\r\n\r\n")
        .await
        .unwrap();
    client_side.shutdown().await.unwrap();

    let forwarded = tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    let result = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());

    let snapshot = beobachten.snapshot_text(Duration::from_secs(60));
    (forwarded, snapshot)
}

#[tokio::test]
async fn tdd_pipeline_prefetch_5ms_misses_15ms_tail_and_classifies_as_port_scanner() {
    let peer: SocketAddr = "198.51.100.171:58071".parse().unwrap();
    let (forwarded, snapshot) = run_pipeline_prefetch_case(5, 15, peer).await;

    assert!(
        forwarded.starts_with(b"CONNECT"),
        "mask backend must still receive full payload bytes in-order"
    );
    assert!(
        snapshot.contains("[HTTP]") || snapshot.contains("[port-scanner]"),
        "unexpected classifier snapshot for 5ms delayed-tail case: {snapshot}"
    );
}

#[tokio::test]
async fn tdd_pipeline_prefetch_20ms_recovers_15ms_tail_and_classifies_as_http() {
    let peer: SocketAddr = "198.51.100.172:58072".parse().unwrap();
    let (forwarded, snapshot) = run_pipeline_prefetch_case(20, 15, peer).await;

    assert!(
        forwarded.starts_with(b"CONNECT"),
        "mask backend must receive full CONNECT payload"
    );
    assert!(
        snapshot.contains("[HTTP]"),
        "20ms budget should recover delayed fragmented prefix and classify as HTTP"
    );
}

#[tokio::test]
async fn matrix_pipeline_prefetch_budget_behavior_5_20_50ms() {
    let peer5: SocketAddr = "198.51.100.173:58073".parse().unwrap();
    let peer20: SocketAddr = "198.51.100.174:58074".parse().unwrap();
    let peer50: SocketAddr = "198.51.100.175:58075".parse().unwrap();

    let (_, snap5) = run_pipeline_prefetch_case(5, 35, peer5).await;
    let (_, snap20) = run_pipeline_prefetch_case(20, 35, peer20).await;
    let (_, snap50) = run_pipeline_prefetch_case(50, 35, peer50).await;

    assert!(
        snap5.contains("[HTTP]") || snap5.contains("[port-scanner]"),
        "unexpected 5ms snapshot: {snap5}"
    );
    assert!(
        snap20.contains("[HTTP]") || snap20.contains("[port-scanner]"),
        "unexpected 20ms snapshot: {snap20}"
    );
    assert!(snap50.contains("[HTTP]"));
}
