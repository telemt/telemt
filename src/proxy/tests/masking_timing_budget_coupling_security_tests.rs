#![cfg(unix)]

use super::*;
use tokio::io::{AsyncWriteExt, duplex};
use tokio::time::{Duration, Instant, timeout};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adversarial_delayed_interface_lookup_does_not_consume_outcome_floor_budget() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = 443;
    config.censorship.mask_timing_normalization_enabled = true;
    config.censorship.mask_timing_normalization_floor_ms = 120;
    config.censorship.mask_timing_normalization_ceiling_ms = 120;

    let peer: SocketAddr = "203.0.113.151:55151".parse().expect("valid peer");
    let local_addr: SocketAddr = "0.0.0.0:443".parse().expect("valid local addr");
    let beobachten = BeobachtenStore::new();

    let refresh_lock = LOCAL_INTERFACE_REFRESH_LOCK.get_or_init(|| AsyncMutex::new(()));
    let held_refresh_guard = refresh_lock.lock().await;

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

    tokio::time::sleep(Duration::from_millis(80)).await;
    drop(held_refresh_guard);
    client
        .shutdown()
        .await
        .expect("client shutdown must succeed");

    timeout(Duration::from_secs(2), task)
        .await
        .expect("task must finish in bounded time")
        .expect("task must not panic");
    let elapsed = started.elapsed();

    assert!(
        elapsed >= Duration::from_millis(180) && elapsed < Duration::from_millis(350),
        "timing normalization floor must start after pre-outcome self-target checks"
    );
}
