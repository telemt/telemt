use super::*;
use tokio::io::duplex;
use tokio::net::TcpListener;
use tokio::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum TimingPath {
    ConnectFail,
    ConnectSuccess,
    SlowBackend,
}

async fn measure_path_duration_ms(path: TimingPath) -> u128 {
    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_unix_sock = None;

    let maybe_accept = match path {
        TimingPath::ConnectFail => {
            config.censorship.mask_host = Some("127.0.0.1".to_string());
            config.censorship.mask_port = 1;
            None
        }
        TimingPath::ConnectSuccess => {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let backend_addr = listener.local_addr().unwrap();
            config.censorship.mask_host = Some("127.0.0.1".to_string());
            config.censorship.mask_port = backend_addr.port();
            Some(tokio::spawn(async move {
                let (_stream, _) = listener.accept().await.unwrap();
            }))
        }
        TimingPath::SlowBackend => {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let backend_addr = listener.local_addr().unwrap();
            config.censorship.mask_host = Some("127.0.0.1".to_string());
            config.censorship.mask_port = backend_addr.port();
            Some(tokio::spawn(async move {
                let (_stream, _) = listener.accept().await.unwrap();
                tokio::time::sleep(Duration::from_millis(350)).await;
            }))
        }
    };

    let peer: SocketAddr = "198.51.100.213:57013".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let (client_reader, _client_writer) = duplex(1024);
    let (_client_visible_reader, client_visible_writer) = duplex(1024);

    let started = Instant::now();
    handle_bad_client(
        client_reader,
        client_visible_writer,
        b"GET /timing HTTP/1.1\r\nHost: x\r\n\r\n",
        peer,
        local,
        &config,
        &beobachten,
    )
    .await;

    if let Some(task) = maybe_accept {
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    started.elapsed().as_millis()
}

fn summarize(values: &[u128]) -> (u128, u128, f64) {
    let min = *values.iter().min().unwrap_or(&0);
    let max = *values.iter().max().unwrap_or(&0);
    let sum: u128 = values.iter().copied().sum();
    let mean = if values.is_empty() {
        0.0
    } else {
        sum as f64 / values.len() as f64
    };
    (min, max, mean)
}

#[tokio::test]
#[ignore = "red-team expected-fail: strict path-indistinguishability target"]
async fn redteam_timing_01_connect_fail_success_slow_backend_must_be_within_10ms() {
    const ITER: usize = 8;

    let mut fail = Vec::with_capacity(ITER);
    let mut success = Vec::with_capacity(ITER);
    let mut slow = Vec::with_capacity(ITER);

    for _ in 0..ITER {
        fail.push(measure_path_duration_ms(TimingPath::ConnectFail).await);
        success.push(measure_path_duration_ms(TimingPath::ConnectSuccess).await);
        slow.push(measure_path_duration_ms(TimingPath::SlowBackend).await);
    }

    let (_, fail_max, fail_mean) = summarize(&fail);
    let (_, success_max, success_mean) = summarize(&success);
    let (_, slow_max, slow_mean) = summarize(&slow);

    let global_min = *fail
        .iter()
        .chain(success.iter())
        .chain(slow.iter())
        .min()
        .unwrap();
    let global_max = *fail
        .iter()
        .chain(success.iter())
        .chain(slow.iter())
        .max()
        .unwrap();

    println!(
        "redteam_timing path=connect_fail mean_ms={:.2} max_ms={}",
        fail_mean, fail_max
    );
    println!(
        "redteam_timing path=connect_success mean_ms={:.2} max_ms={}",
        success_mean, success_max
    );
    println!(
        "redteam_timing path=slow_backend mean_ms={:.2} max_ms={}",
        slow_mean, slow_max
    );

    assert!(
        global_max.saturating_sub(global_min) <= 10,
        "strict model expects all masking outcomes in one 10ms bucket: min={global_min} max={global_max}"
    );
}

#[tokio::test]
#[ignore = "red-team expected-fail: strict classifier-separability target"]
async fn redteam_timing_02_path_classifier_centroid_accuracy_must_be_below_40pct() {
    const ITER: usize = 12;

    let mut fail = Vec::with_capacity(ITER);
    let mut success = Vec::with_capacity(ITER);
    let mut slow = Vec::with_capacity(ITER);

    for _ in 0..ITER {
        fail.push(measure_path_duration_ms(TimingPath::ConnectFail).await as f64);
        success.push(measure_path_duration_ms(TimingPath::ConnectSuccess).await as f64);
        slow.push(measure_path_duration_ms(TimingPath::SlowBackend).await as f64);
    }

    let mean = |v: &Vec<f64>| -> f64 { v.iter().sum::<f64>() / v.len() as f64 };
    let c_fail = mean(&fail);
    let c_success = mean(&success);
    let c_slow = mean(&slow);

    let mut correct = 0usize;
    let mut total = 0usize;

    let classify = |x: f64, c0: f64, c1: f64, c2: f64| -> usize {
        let d0 = (x - c0).abs();
        let d1 = (x - c1).abs();
        let d2 = (x - c2).abs();
        if d0 <= d1 && d0 <= d2 {
            0
        } else if d1 <= d0 && d1 <= d2 {
            1
        } else {
            2
        }
    };

    for &x in &fail {
        total += 1;
        if classify(x, c_fail, c_success, c_slow) == 0 {
            correct += 1;
        }
    }
    for &x in &success {
        total += 1;
        if classify(x, c_fail, c_success, c_slow) == 1 {
            correct += 1;
        }
    }
    for &x in &slow {
        total += 1;
        if classify(x, c_fail, c_success, c_slow) == 2 {
            correct += 1;
        }
    }

    let accuracy = correct as f64 / total as f64;
    println!(
        "redteam_timing_classifier accuracy={:.3} c_fail={:.2} c_success={:.2} c_slow={:.2}",
        accuracy, c_fail, c_success, c_slow
    );

    assert!(
        accuracy <= 0.40,
        "strict model expects poor classifier; observed accuracy={accuracy:.3}"
    );
}
