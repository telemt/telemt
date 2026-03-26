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

async fn run_probe_capture(
    body_sent: usize,
    tls_len: u16,
    enable_shape_hardening: bool,
    floor: usize,
    cap: usize,
) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = backend_addr.port();
    cfg.censorship.mask_shape_hardening = enable_shape_hardening;
    cfg.censorship.mask_shape_bucket_floor_bytes = floor;
    cfg.censorship.mask_shape_bucket_cap_bytes = cap;

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut got)).await;
        got
    });

    let (server_side, mut client_side) = duplex(65536);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.188:56888".parse().unwrap(),
        Arc::new(cfg),
        Arc::new(Stats::new()),
        new_upstream_manager(Arc::new(Stats::new())),
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

    let mut probe = vec![0u8; 5 + body_sent];
    probe[0] = 0x16;
    probe[1] = 0x03;
    probe[2] = 0x01;
    probe[3..5].copy_from_slice(&tls_len.to_be_bytes());
    probe[5..].fill(0x66);

    client_side.write_all(&probe).await.unwrap();
    client_side.shutdown().await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(4), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());

    tokio::time::timeout(Duration::from_secs(4), accept_task)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn shape_hardening_disabled_keeps_original_probe_length() {
    let got = run_probe_capture(17, 600, false, 512, 4096).await;
    assert_eq!(got.len(), 22);
    assert_eq!(&got[..5], &[0x16, 0x03, 0x01, 0x02, 0x58]);
}

#[tokio::test]
async fn shape_hardening_enabled_pads_small_probe_to_floor_bucket() {
    let got = run_probe_capture(17, 600, true, 512, 4096).await;
    assert_eq!(got.len(), 512);
    assert_eq!(&got[..5], &[0x16, 0x03, 0x01, 0x02, 0x58]);
}

#[tokio::test]
async fn shape_hardening_enabled_pads_mid_probe_to_next_bucket() {
    let got = run_probe_capture(511, 600, true, 512, 4096).await;
    assert_eq!(got.len(), 1024);
    assert_eq!(&got[..5], &[0x16, 0x03, 0x01, 0x02, 0x58]);
}

#[tokio::test]
async fn shape_hardening_respects_cap_and_avoids_padding_above_cap() {
    let got = run_probe_capture(5000, 7000, true, 512, 4096).await;
    assert_eq!(got.len(), 5005);
    assert_eq!(&got[..5], &[0x16, 0x03, 0x01, 0x1b, 0x58]);
}
