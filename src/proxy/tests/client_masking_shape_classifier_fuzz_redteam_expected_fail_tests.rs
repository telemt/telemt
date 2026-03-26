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
) -> usize {
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
        got.len()
    });

    let (server_side, mut client_side) = duplex(65536);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.214:57014".parse().unwrap(),
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

    let _ = tokio::time::timeout(Duration::from_secs(4), handler)
        .await
        .unwrap()
        .unwrap();

    tokio::time::timeout(Duration::from_secs(4), accept_task)
        .await
        .unwrap()
        .unwrap()
}

fn pearson_corr(xs: &[f64], ys: &[f64]) -> f64 {
    if xs.len() != ys.len() || xs.is_empty() {
        return 0.0;
    }

    let n = xs.len() as f64;
    let mean_x = xs.iter().sum::<f64>() / n;
    let mean_y = ys.iter().sum::<f64>() / n;

    let mut cov = 0.0;
    let mut var_x = 0.0;
    let mut var_y = 0.0;

    for (&x, &y) in xs.iter().zip(ys.iter()) {
        let dx = x - mean_x;
        let dy = y - mean_y;
        cov += dx * dy;
        var_x += dx * dx;
        var_y += dy * dy;
    }

    if var_x == 0.0 || var_y == 0.0 {
        return 0.0;
    }

    cov / (var_x.sqrt() * var_y.sqrt())
}

fn lcg_sizes(count: usize, floor: usize, cap: usize) -> Vec<usize> {
    let mut x = 0x9E3779B97F4A7C15u64;
    let span = cap.saturating_mul(3);
    let mut out = Vec::with_capacity(count + 8);

    for _ in 0..count {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let v = (x as usize) % span.max(1);
        out.push(v);
    }

    // Inject edge and boundary-heavy probes.
    out.extend_from_slice(&[
        0,
        floor.saturating_sub(1),
        floor,
        floor.saturating_add(1),
        cap.saturating_sub(1),
        cap,
        cap.saturating_add(1),
        cap.saturating_mul(2),
    ]);
    out
}

async fn collect_distribution(
    sizes: &[usize],
    hardening: bool,
    floor: usize,
    cap: usize,
) -> Vec<usize> {
    let mut out = Vec::with_capacity(sizes.len());
    for &body in sizes {
        out.push(run_probe_capture(body, 1200, hardening, floor, cap).await);
    }
    out
}

#[tokio::test]
#[ignore = "red-team expected-fail: strict decorrelation target for hardened output lengths"]
async fn redteam_fuzz_01_hardened_output_length_correlation_should_be_below_0_2() {
    let floor = 512usize;
    let cap = 4096usize;
    let sizes = lcg_sizes(24, floor, cap);

    let hardened = collect_distribution(&sizes, true, floor, cap).await;
    let x: Vec<f64> = sizes.iter().map(|v| *v as f64).collect();
    let y_hard: Vec<f64> = hardened.iter().map(|v| *v as f64).collect();

    let corr_hard = pearson_corr(&x, &y_hard).abs();
    println!(
        "redteam_fuzz corr_hardened={corr_hard:.4} samples={}",
        sizes.len()
    );

    assert!(
        corr_hard < 0.2,
        "strict model expects near-zero size correlation; observed corr={corr_hard:.4}"
    );
}

#[tokio::test]
#[ignore = "red-team expected-fail: strict class-collapse ratio target"]
async fn redteam_fuzz_02_hardened_unique_output_ratio_should_be_below_5pct() {
    let floor = 512usize;
    let cap = 4096usize;
    let sizes = lcg_sizes(24, floor, cap);

    let hardened = collect_distribution(&sizes, true, floor, cap).await;

    let in_unique = {
        let mut s = std::collections::BTreeSet::new();
        for v in &sizes {
            s.insert(*v);
        }
        s.len()
    };

    let out_unique = {
        let mut s = std::collections::BTreeSet::new();
        for v in &hardened {
            s.insert(*v);
        }
        s.len()
    };

    let ratio = out_unique as f64 / in_unique as f64;
    println!(
        "redteam_fuzz unique_ratio_hardened={ratio:.4} out_unique={} in_unique={}",
        out_unique, in_unique
    );

    assert!(
        ratio <= 0.05,
        "strict model expects near-total collapse; observed ratio={ratio:.4}"
    );
}

#[tokio::test]
#[ignore = "red-team expected-fail: strict separability improvement target"]
async fn redteam_fuzz_03_hardened_signal_must_be_10x_lower_than_plain() {
    let floor = 512usize;
    let cap = 4096usize;
    let sizes = lcg_sizes(24, floor, cap);

    let plain = collect_distribution(&sizes, false, floor, cap).await;
    let hardened = collect_distribution(&sizes, true, floor, cap).await;

    let x: Vec<f64> = sizes.iter().map(|v| *v as f64).collect();
    let y_plain: Vec<f64> = plain.iter().map(|v| *v as f64).collect();
    let y_hard: Vec<f64> = hardened.iter().map(|v| *v as f64).collect();

    let corr_plain = pearson_corr(&x, &y_plain).abs();
    let corr_hard = pearson_corr(&x, &y_hard).abs();

    println!("redteam_fuzz corr_plain={corr_plain:.4} corr_hardened={corr_hard:.4}");

    assert!(
        corr_hard <= corr_plain * 0.1,
        "strict model expects 10x suppression; plain={corr_plain:.4} hardened={corr_hard:.4}"
    );
}
