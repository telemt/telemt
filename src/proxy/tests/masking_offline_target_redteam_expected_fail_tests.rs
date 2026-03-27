use super::*;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use tokio::io::{AsyncWriteExt, duplex};
use tokio::time::{Duration, Instant};

fn closed_local_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

#[tokio::test]
#[ignore = "red-team expected-fail: offline mask target keeps bad-client socket alive before consume timeout boundary"]
async fn redteam_offline_target_should_drop_idle_client_early() {
    let (client_read, mut client_write) = duplex(1024);

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = closed_local_port();
    cfg.censorship.mask_timing_normalization_enabled = false;

    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let peer_addr: SocketAddr = "192.0.2.50:5000".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let handler = tokio::spawn(async move {
        handle_bad_client(
            client_read,
            tokio::io::sink(),
            b"GET / HTTP/1.1\r\n\r\n",
            peer_addr,
            local_addr,
            &cfg,
            &beobachten,
        )
        .await;
    });

    tokio::time::sleep(Duration::from_millis(150)).await;
    let write_res = client_write.write_all(b"probe-should-be-closed").await;
    assert!(
        write_res.is_err(),
        "offline target path still keeps client writable before consume timeout"
    );

    handler.abort();
}

#[tokio::test]
#[ignore = "red-team expected-fail: proxy should mimic immediate RST-like close when target is offline"]
async fn redteam_offline_target_should_not_sleep_to_mask_refusal() {
    let (client_read, mut client_write) = duplex(1024);

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = closed_local_port();
    cfg.censorship.mask_timing_normalization_enabled = false;

    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let peer_addr: SocketAddr = "192.0.2.51:5000".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let started = Instant::now();
    let handler = tokio::spawn(async move {
        handle_bad_client(
            client_read,
            tokio::io::sink(),
            b"\x16\x03\x01\x00\x05hello",
            peer_addr,
            local_addr,
            &cfg,
            &beobachten,
        )
        .await;
    });

    client_write.shutdown().await.unwrap();
    let _ = handler.await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_millis(10),
        "offline target path still applies coarse masking sleep and is fingerprintable"
    );
}

#[tokio::test]
#[ignore = "red-team expected-fail: refusal path should remain below strict latency envelope under burst"]
async fn redteam_offline_refusal_burst_timing_spread_should_be_tight() {
    let mut samples = Vec::new();

    for i in 0..12u16 {
        let (client_read, mut client_write) = duplex(1024);
        let mut cfg = ProxyConfig::default();
        cfg.general.beobachten = false;
        cfg.censorship.mask = true;
        cfg.censorship.mask_unix_sock = None;
        cfg.censorship.mask_host = Some("127.0.0.1".to_string());
        cfg.censorship.mask_port = closed_local_port();
        cfg.censorship.mask_timing_normalization_enabled = false;

        let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let peer_addr: SocketAddr = format!("192.0.2.52:{}", 5100 + i).parse().unwrap();
        let beobachten = BeobachtenStore::new();

        let started = Instant::now();
        let handler = tokio::spawn(async move {
            handle_bad_client(
                client_read,
                tokio::io::sink(),
                b"GET / HTTP/1.1\r\n\r\n",
                peer_addr,
                local_addr,
                &cfg,
                &beobachten,
            )
            .await;
        });

        client_write.shutdown().await.unwrap();
        let _ = handler.await;
        samples.push(started.elapsed());
    }

    let min = samples.iter().copied().min().unwrap_or_default();
    let max = samples.iter().copied().max().unwrap_or_default();
    let spread = max.saturating_sub(min);

    assert!(
        spread <= Duration::from_millis(5),
        "offline refusal timing spread too wide for strict red-team envelope: {:?}",
        spread
    );
}

#[tokio::test]
#[ignore = "manual red-team: host resolver failure should complete without panic"]
async fn redteam_dns_resolution_failure_must_not_panic() {
    let (client_read, mut client_write) = duplex(1024);

    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("this.domain.definitely.does.not.exist.invalid".to_string());
    cfg.censorship.mask_port = 443;

    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let peer_addr: SocketAddr = "192.0.2.99:5999".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let handler = tokio::spawn(async move {
        handle_bad_client(
            client_read,
            tokio::io::sink(),
            b"GET / HTTP/1.1\r\n\r\n",
            peer_addr,
            local_addr,
            &cfg,
            &beobachten,
        )
        .await;
    });

    client_write.shutdown().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), handler).await;
    assert!(
        result.is_ok(),
        "dns failure path stalled or panicked instead of terminating"
    );
}
