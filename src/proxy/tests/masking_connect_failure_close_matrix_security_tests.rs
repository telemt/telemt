use super::*;
use crate::network::dns_overrides::install_entries;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::{Duration, Instant, timeout};

async fn run_connect_failure_case(
    host: &str,
    port: u16,
    timing_normalization_enabled: bool,
    peer: SocketAddr,
) -> Duration {
    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_host = Some(host.to_string());
    config.censorship.mask_port = port;
    config.censorship.mask_timing_normalization_enabled = timing_normalization_enabled;
    config.censorship.mask_timing_normalization_floor_ms = 120;
    config.censorship.mask_timing_normalization_ceiling_ms = 120;

    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();
    let probe = b"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org\r\n\r\n";

    let (mut client_writer, client_reader) = duplex(1024);
    let (mut client_visible_reader, client_visible_writer) = duplex(1024);

    let started = Instant::now();
    let task = tokio::spawn(async move {
        handle_bad_client(
            client_reader,
            client_visible_writer,
            probe,
            peer,
            local_addr,
            &config,
            &beobachten,
        )
        .await;
    });

    client_writer.shutdown().await.unwrap();

    timeout(Duration::from_secs(4), task)
        .await
        .unwrap()
        .unwrap();

    let mut buf = [0u8; 1];
    let n = timeout(Duration::from_secs(1), client_visible_reader.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        n, 0,
        "connect-failure path must close client-visible writer"
    );

    started.elapsed()
}

#[tokio::test]
async fn connect_failure_refusal_close_behavior_matrix() {
    let temp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unused_port = temp_listener.local_addr().unwrap().port();
    drop(temp_listener);

    for (idx, timing_normalization_enabled) in [false, true].into_iter().enumerate() {
        let peer: SocketAddr = format!("203.0.113.210:{}", 54100 + idx as u16)
            .parse()
            .unwrap();
        let elapsed =
            run_connect_failure_case("127.0.0.1", unused_port, timing_normalization_enabled, peer)
                .await;

        if timing_normalization_enabled {
            assert!(
                elapsed >= Duration::from_millis(110) && elapsed < Duration::from_millis(250),
                "normalized refusal path must honor configured timing envelope without stalling"
            );
        } else {
            assert!(
                elapsed >= Duration::from_millis(40) && elapsed < Duration::from_millis(150),
                "non-normalized refusal path must honor baseline connect budget without stalling"
            );
        }
    }
}

#[tokio::test]
async fn connect_failure_overridden_hostname_close_behavior_matrix() {
    let temp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unused_port = temp_listener.local_addr().unwrap().port();
    drop(temp_listener);

    // Make hostname resolution deterministic in tests so timing ceilings are meaningful.
    install_entries(&[format!("mask.invalid:{}:127.0.0.1", unused_port)]).unwrap();

    for (idx, timing_normalization_enabled) in [false, true].into_iter().enumerate() {
        let peer: SocketAddr = format!("203.0.113.220:{}", 54200 + idx as u16)
            .parse()
            .unwrap();
        let elapsed = run_connect_failure_case(
            "mask.invalid",
            unused_port,
            timing_normalization_enabled,
            peer,
        )
        .await;

        if timing_normalization_enabled {
            assert!(
                elapsed >= Duration::from_millis(110) && elapsed < Duration::from_millis(250),
                "normalized overridden-host path must honor configured timing envelope without stalling"
            );
        } else {
            assert!(
                elapsed >= Duration::from_millis(40) && elapsed < Duration::from_millis(150),
                "non-normalized overridden-host path must honor baseline connect budget without stalling"
            );
        }
    }

    install_entries(&[]).unwrap();
}
