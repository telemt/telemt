use super::*;
use tokio::io::duplex;
use tokio::net::TcpListener;
use tokio::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum MaskPath {
    ConnectFail,
    ConnectSuccess,
    SlowBackend,
}

async fn measure_bad_client_duration_ms(path: MaskPath, floor_ms: u64, ceiling_ms: u64) -> u128 {
    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_timing_normalization_enabled = true;
    config.censorship.mask_timing_normalization_floor_ms = floor_ms;
    config.censorship.mask_timing_normalization_ceiling_ms = ceiling_ms;

    let accept_task = match path {
        MaskPath::ConnectFail => {
            config.censorship.mask_host = Some("127.0.0.1".to_string());
            config.censorship.mask_port = 1;
            None
        }
        MaskPath::ConnectSuccess => {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let backend_addr = listener.local_addr().unwrap();
            config.censorship.mask_host = Some("127.0.0.1".to_string());
            config.censorship.mask_port = backend_addr.port();
            Some(tokio::spawn(async move {
                let (_stream, _) = listener.accept().await.unwrap();
            }))
        }
        MaskPath::SlowBackend => {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let backend_addr = listener.local_addr().unwrap();
            config.censorship.mask_host = Some("127.0.0.1".to_string());
            config.censorship.mask_port = backend_addr.port();
            Some(tokio::spawn(async move {
                let (_stream, _) = listener.accept().await.unwrap();
                tokio::time::sleep(Duration::from_millis(320)).await;
            }))
        }
    };

    let (client_reader, _client_writer) = duplex(1024);
    let (_client_visible_reader, client_visible_writer) = duplex(1024);

    let peer: SocketAddr = "198.51.100.221:57121".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let started = Instant::now();
    handle_bad_client(
        client_reader,
        client_visible_writer,
        b"GET /timing-normalize HTTP/1.1\r\nHost: x\r\n\r\n",
        peer,
        local,
        &config,
        &beobachten,
    )
    .await;

    if let Some(task) = accept_task {
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    started.elapsed().as_millis()
}

#[tokio::test]
async fn timing_normalization_envelope_applies_to_connect_fail_and_success() {
    let floor = 160u64;
    let ceiling = 180u64;

    let fail = measure_bad_client_duration_ms(MaskPath::ConnectFail, floor, ceiling).await;
    let success = measure_bad_client_duration_ms(MaskPath::ConnectSuccess, floor, ceiling).await;

    assert!(
        fail >= floor as u128,
        "connect-fail duration below floor: {fail}ms < {floor}ms"
    );
    assert!(
        fail <= (ceiling + 60) as u128,
        "connect-fail duration exceeded relaxed ceiling: {fail}ms > {}ms",
        ceiling + 60
    );

    assert!(
        success >= floor as u128,
        "connect-success duration below floor: {success}ms < {floor}ms"
    );
    assert!(
        success <= (ceiling + 60) as u128,
        "connect-success duration exceeded relaxed ceiling: {success}ms > {}ms",
        ceiling + 60
    );

    let delta = fail.abs_diff(success);
    assert!(
        delta <= 80,
        "timing normalization should reduce path divergence (delta={}ms)",
        delta
    );
}

#[tokio::test]
async fn timing_normalization_does_not_sleep_if_path_already_exceeds_ceiling() {
    let floor = 120u64;
    let ceiling = 150u64;

    let slow = measure_bad_client_duration_ms(MaskPath::SlowBackend, floor, ceiling).await;

    assert!(
        slow >= 280,
        "slow backend path should remain slow (got {slow}ms)"
    );
    assert!(
        slow <= 520,
        "slow backend path should remain bounded in tests (got {slow}ms)"
    );
}
