use super::*;
use tokio::io::{AsyncWriteExt, duplex};
use tokio::time::{Duration, Instant, timeout};

fn make_self_target_config(
    timing_normalization_enabled: bool,
    floor_ms: u64,
    ceiling_ms: u64,
    beobachten_enabled: bool,
) -> ProxyConfig {
    let mut config = ProxyConfig::default();
    config.general.beobachten = beobachten_enabled;
    config.general.beobachten_minutes = 5;
    config.censorship.mask = true;
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = 443;
    config.censorship.mask_timing_normalization_enabled = timing_normalization_enabled;
    config.censorship.mask_timing_normalization_floor_ms = floor_ms;
    config.censorship.mask_timing_normalization_ceiling_ms = ceiling_ms;
    config
}

async fn run_self_target_refusal(
    config: ProxyConfig,
    peer: SocketAddr,
    initial: &'static [u8],
) -> Duration {
    let beobachten = BeobachtenStore::new();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().expect("valid local addr");

    let (mut client, server) = duplex(1024);
    let started = Instant::now();
    let task = tokio::spawn(async move {
        handle_bad_client(
            server,
            tokio::io::sink(),
            initial,
            peer,
            local_addr,
            &config,
            &beobachten,
        )
        .await;
    });

    client
        .shutdown()
        .await
        .expect("client shutdown must succeed");

    timeout(Duration::from_secs(3), task)
        .await
        .expect("self-target refusal must complete in bounded time")
        .expect("self-target refusal task must not panic");

    started.elapsed()
}

#[tokio::test]
async fn positive_self_target_refusal_honors_normalization_floor() {
    let config = make_self_target_config(true, 120, 120, false);
    let peer: SocketAddr = "203.0.113.41:54041".parse().expect("valid peer");

    let elapsed = run_self_target_refusal(config, peer, b"GET / HTTP/1.1\r\n\r\n").await;

    assert!(
        elapsed >= Duration::from_millis(110) && elapsed < Duration::from_millis(260),
        "normalized self-target refusal must stay within expected envelope"
    );
}

#[tokio::test]
async fn negative_non_normalized_refusal_does_not_sleep_to_large_floor() {
    let config = make_self_target_config(false, 240, 240, false);
    let peer: SocketAddr = "203.0.113.42:54042".parse().expect("valid peer");

    let elapsed = run_self_target_refusal(config, peer, b"GET / HTTP/1.1\r\n\r\n").await;

    assert!(
        elapsed < Duration::from_millis(180),
        "non-normalized path must not inherit normalization floor delays"
    );
}

#[tokio::test]
async fn edge_ceiling_below_floor_uses_floor_fail_closed() {
    let config = make_self_target_config(true, 140, 80, false);
    let peer: SocketAddr = "203.0.113.43:54043".parse().expect("valid peer");

    let elapsed = run_self_target_refusal(config, peer, b"GET / HTTP/1.1\r\n\r\n").await;

    assert!(
        elapsed >= Duration::from_millis(130) && elapsed < Duration::from_millis(280),
        "ceiling<floor must clamp to floor to preserve deterministic normalization"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adversarial_blackhat_parallel_probes_remain_bounded_and_uniform() {
    let workers = 24usize;
    let mut tasks = Vec::with_capacity(workers);

    for idx in 0..workers {
        tasks.push(tokio::spawn(async move {
            let cfg = make_self_target_config(true, 110, 140, false);
            let peer: SocketAddr = format!("203.0.113.50:{}", 54100 + idx as u16)
                .parse()
                .expect("valid peer");
            run_self_target_refusal(cfg, peer, b"GET /x HTTP/1.1\r\n\r\n").await
        }));
    }

    let mut min = Duration::from_secs(60);
    let mut max = Duration::from_millis(0);
    for task in tasks {
        let elapsed = task.await.expect("probe task must not panic");
        if elapsed < min {
            min = elapsed;
        }
        if elapsed > max {
            max = elapsed;
        }
        assert!(
            elapsed >= Duration::from_millis(100) && elapsed < Duration::from_millis(320),
            "parallel probe latency must stay bounded under normalization"
        );
    }

    assert!(
        max.saturating_sub(min) <= Duration::from_millis(130),
        "normalization should limit path variance across adversarial parallel probes"
    );
}

#[tokio::test]
async fn integration_beobachten_records_probe_classification_on_refusal() {
    let config = make_self_target_config(false, 0, 0, true);
    let peer: SocketAddr = "198.51.100.71:55071".parse().expect("valid peer");
    let local_addr: SocketAddr = "127.0.0.1:443".parse().expect("valid local addr");
    let beobachten = BeobachtenStore::new();

    let (mut client, server) = duplex(1024);
    let task = tokio::spawn(async move {
        handle_bad_client(
            server,
            tokio::io::sink(),
            b"GET /classified HTTP/1.1\r\nHost: demo\r\n\r\n",
            peer,
            local_addr,
            &config,
            &beobachten,
        )
        .await;

        beobachten.snapshot_text(Duration::from_secs(60))
    });

    client
        .shutdown()
        .await
        .expect("client shutdown must succeed");

    let snapshot = timeout(Duration::from_secs(3), task)
        .await
        .expect("integration task must complete")
        .expect("integration task must not panic");

    assert!(snapshot.contains("[HTTP]"));
    assert!(snapshot.contains("198.51.100.71-1"));
}

#[tokio::test]
async fn light_fuzz_timing_configuration_matrix_is_bounded() {
    let mut seed = 0xA17E_55AA_2026_0323u64;

    for case in 0..48u64 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let enabled = (seed & 1) == 0;
        let floor = (seed >> 8) % 180;
        let ceiling = (seed >> 24) % 180;
        let config = make_self_target_config(enabled, floor, ceiling, false);
        let peer: SocketAddr = format!("203.0.113.90:{}", 56000 + (case as u16))
            .parse()
            .expect("valid peer");

        let elapsed = run_self_target_refusal(config, peer, b"HEAD /h HTTP/1.1\r\n\r\n").await;

        assert!(
            elapsed < Duration::from_millis(420),
            "fuzz case must stay bounded and never hang"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_high_fanout_self_target_refusal_no_deadlock_or_timeout() {
    let workers = 64usize;
    let mut tasks = Vec::with_capacity(workers);

    for idx in 0..workers {
        tasks.push(tokio::spawn(async move {
            let config = make_self_target_config(false, 0, 0, false);
            let peer: SocketAddr = format!("198.51.100.200:{}", 57000 + idx as u16)
                .parse()
                .expect("valid peer");
            run_self_target_refusal(config, peer, b"GET /stress HTTP/1.1\r\n\r\n").await
        }));
    }

    timeout(Duration::from_secs(5), async {
        for task in tasks {
            let elapsed = task.await.expect("stress task must not panic");
            assert!(
                elapsed < Duration::from_millis(260),
                "stress refusal must remain bounded without normalization"
            );
        }
    })
    .await
    .expect("high-fanout refusal workload must complete without deadlock");
}
