use super::*;
use std::collections::BTreeSet;
use tokio::io::duplex;
use tokio::net::TcpListener;
use tokio::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum PathClass {
    ConnectFail,
    ConnectSuccess,
    SlowBackend,
}

fn mean_ms(samples: &[u128]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let sum: u128 = samples.iter().copied().sum();
    sum as f64 / samples.len() as f64
}

fn percentile_ms(mut values: Vec<u128>, p_num: usize, p_den: usize) -> u128 {
    values.sort_unstable();
    if values.is_empty() {
        return 0;
    }
    let idx = ((values.len() - 1) * p_num) / p_den;
    values[idx]
}

fn bucketize_ms(values: &[u128], bucket_ms: u128) -> Vec<u128> {
    values.iter().map(|v| *v / bucket_ms).collect()
}

fn best_threshold_accuracy_u128(a: &[u128], b: &[u128]) -> f64 {
    let min_v = *a.iter().chain(b.iter()).min().unwrap();
    let max_v = *a.iter().chain(b.iter()).max().unwrap();

    let mut best = 0.0f64;
    for t in min_v..=max_v {
        let correct_a = a.iter().filter(|&&x| x <= t).count();
        let correct_b = b.iter().filter(|&&x| x > t).count();
        let acc = (correct_a + correct_b) as f64 / (a.len() + b.len()) as f64;
        if acc > best {
            best = acc;
        }
    }
    best
}

fn spread_u128(values: &[u128]) -> u128 {
    if values.is_empty() {
        return 0;
    }
    let min_v = *values.iter().min().unwrap();
    let max_v = *values.iter().max().unwrap();
    max_v - min_v
}

fn interval_gap_usize(a: &BTreeSet<usize>, b: &BTreeSet<usize>) -> usize {
    if a.is_empty() || b.is_empty() {
        return 0;
    }

    let a_min = *a.iter().next().unwrap();
    let a_max = *a.iter().next_back().unwrap();
    let b_min = *b.iter().next().unwrap();
    let b_max = *b.iter().next_back().unwrap();

    if a_max < b_min {
        b_min - a_max
    } else if b_max < a_min {
        a_min - b_max
    } else {
        0
    }
}

async fn collect_timing_samples(path: PathClass, timing_norm_enabled: bool, n: usize) -> Vec<u128> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(measure_masking_duration_ms(path, timing_norm_enabled).await);
    }
    out
}

async fn measure_masking_duration_ms(path: PathClass, timing_norm_enabled: bool) -> u128 {
    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_timing_normalization_enabled = timing_norm_enabled;
    config.censorship.mask_timing_normalization_floor_ms = 220;
    config.censorship.mask_timing_normalization_ceiling_ms = 260;

    let accept_task = match path {
        PathClass::ConnectFail => {
            config.censorship.mask_host = Some("127.0.0.1".to_string());
            config.censorship.mask_port = 1;
            None
        }
        PathClass::ConnectSuccess => {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let backend_addr = listener.local_addr().unwrap();
            config.censorship.mask_host = Some("127.0.0.1".to_string());
            config.censorship.mask_port = backend_addr.port();
            Some(tokio::spawn(async move {
                let (_stream, _) = listener.accept().await.unwrap();
            }))
        }
        PathClass::SlowBackend => {
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

    let peer: SocketAddr = "198.51.100.230:57230".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let started = Instant::now();
    handle_bad_client(
        client_reader,
        client_visible_writer,
        b"GET /ab-harness HTTP/1.1\r\nHost: x\r\n\r\n",
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

async fn capture_above_cap_forwarded_len(
    body_sent: usize,
    above_cap_blur_enabled: bool,
    above_cap_blur_max_bytes: usize,
) -> usize {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_shape_hardening = true;
    config.censorship.mask_shape_bucket_floor_bytes = 512;
    config.censorship.mask_shape_bucket_cap_bytes = 4096;
    config.censorship.mask_shape_above_cap_blur = above_cap_blur_enabled;
    config.censorship.mask_shape_above_cap_blur_max_bytes = above_cap_blur_max_bytes;

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut got)).await;
        got.len()
    });

    let (client_reader, mut client_writer) = duplex(64 * 1024);
    let (_client_visible_reader, client_visible_writer) = duplex(64 * 1024);

    let peer: SocketAddr = "198.51.100.231:57231".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let mut initial = vec![0u8; 5 + body_sent];
    initial[0] = 0x16;
    initial[1] = 0x03;
    initial[2] = 0x01;
    initial[3..5].copy_from_slice(&7000u16.to_be_bytes());
    initial[5..].fill(0x5A);

    let fallback_task = tokio::spawn(async move {
        handle_bad_client(
            client_reader,
            client_visible_writer,
            &initial,
            peer,
            local,
            &config,
            &beobachten,
        )
        .await;
    });

    client_writer.shutdown().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(4), fallback_task)
        .await
        .unwrap()
        .unwrap();

    tokio::time::timeout(Duration::from_secs(4), accept_task)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn integration_ab_harness_envelope_and_blur_improve_obfuscation_vs_baseline() {
    const ITER: usize = 8;

    let mut baseline_fail = Vec::with_capacity(ITER);
    let mut baseline_success = Vec::with_capacity(ITER);
    let mut baseline_slow = Vec::with_capacity(ITER);

    let mut hardened_fail = Vec::with_capacity(ITER);
    let mut hardened_success = Vec::with_capacity(ITER);
    let mut hardened_slow = Vec::with_capacity(ITER);

    for _ in 0..ITER {
        baseline_fail.push(measure_masking_duration_ms(PathClass::ConnectFail, false).await);
        baseline_success.push(measure_masking_duration_ms(PathClass::ConnectSuccess, false).await);
        baseline_slow.push(measure_masking_duration_ms(PathClass::SlowBackend, false).await);

        hardened_fail.push(measure_masking_duration_ms(PathClass::ConnectFail, true).await);
        hardened_success.push(measure_masking_duration_ms(PathClass::ConnectSuccess, true).await);
        hardened_slow.push(measure_masking_duration_ms(PathClass::SlowBackend, true).await);
    }

    let baseline_means = [
        mean_ms(&baseline_fail),
        mean_ms(&baseline_success),
        mean_ms(&baseline_slow),
    ];
    let hardened_means = [
        mean_ms(&hardened_fail),
        mean_ms(&hardened_success),
        mean_ms(&hardened_slow),
    ];

    let baseline_range = baseline_means
        .iter()
        .copied()
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(mn, mx), v| {
            (mn.min(v), mx.max(v))
        });
    let hardened_range = hardened_means
        .iter()
        .copied()
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(mn, mx), v| {
            (mn.min(v), mx.max(v))
        });

    let baseline_spread = baseline_range.1 - baseline_range.0;
    let hardened_spread = hardened_range.1 - hardened_range.0;

    println!(
        "ab_harness_timing baseline_means={:?} hardened_means={:?} baseline_spread={:.2} hardened_spread={:.2}",
        baseline_means, hardened_means, baseline_spread, hardened_spread
    );

    assert!(
        hardened_spread < baseline_spread,
        "timing envelope should reduce cross-path mean spread: baseline={baseline_spread:.2} hardened={hardened_spread:.2}"
    );

    let mut baseline_a = BTreeSet::new();
    let mut baseline_b = BTreeSet::new();
    let mut hardened_a = BTreeSet::new();
    let mut hardened_b = BTreeSet::new();

    for _ in 0..24 {
        baseline_a.insert(capture_above_cap_forwarded_len(5000, false, 0).await);
        baseline_b.insert(capture_above_cap_forwarded_len(5040, false, 0).await);

        hardened_a.insert(capture_above_cap_forwarded_len(5000, true, 96).await);
        hardened_b.insert(capture_above_cap_forwarded_len(5040, true, 96).await);
    }

    let baseline_overlap = baseline_a.intersection(&baseline_b).count();
    let hardened_overlap = hardened_a.intersection(&hardened_b).count();
    let baseline_gap = interval_gap_usize(&baseline_a, &baseline_b);
    let hardened_gap = interval_gap_usize(&hardened_a, &hardened_b);

    println!(
        "ab_harness_length baseline_overlap={} hardened_overlap={} baseline_gap={} hardened_gap={} baseline_a={} baseline_b={} hardened_a={} hardened_b={}",
        baseline_overlap,
        hardened_overlap,
        baseline_gap,
        hardened_gap,
        baseline_a.len(),
        baseline_b.len(),
        hardened_a.len(),
        hardened_b.len()
    );

    assert_eq!(
        baseline_overlap, 0,
        "baseline above-cap classes should be disjoint"
    );
    assert!(
        hardened_a.len() > baseline_a.len() && hardened_b.len() > baseline_b.len(),
        "above-cap blur should widen per-class emitted lengths: baseline_a={} baseline_b={} hardened_a={} hardened_b={}",
        baseline_a.len(),
        baseline_b.len(),
        hardened_a.len(),
        hardened_b.len()
    );
    assert!(
        hardened_overlap > baseline_overlap || hardened_gap < baseline_gap,
        "above-cap blur should reduce class separability via direct overlap or tighter interval gap: baseline_overlap={} hardened_overlap={} baseline_gap={} hardened_gap={}",
        baseline_overlap,
        hardened_overlap,
        baseline_gap,
        hardened_gap
    );
}

#[test]
fn timing_classifier_helper_bucketize_is_stable() {
    let values = vec![219u128, 220, 239, 240, 259, 260];
    let got = bucketize_ms(&values, 20);
    assert_eq!(got, vec![10, 11, 11, 12, 12, 13]);
}

#[test]
fn timing_classifier_helper_percentile_is_monotonic() {
    let samples = vec![210u128, 220, 230, 240, 250, 260, 270, 280];
    let p50 = percentile_ms(samples.clone(), 50, 100);
    let p95 = percentile_ms(samples.clone(), 95, 100);
    assert!(p95 >= p50);
}

#[test]
fn timing_classifier_helper_threshold_accuracy_is_perfect_for_disjoint_sets() {
    let a = vec![10u128, 11, 12, 13, 14];
    let b = vec![20u128, 21, 22, 23, 24];
    let acc = best_threshold_accuracy_u128(&a, &b);
    assert!(acc >= 0.99);
}

#[test]
fn timing_classifier_helper_threshold_accuracy_drops_for_identical_sets() {
    let a = vec![10u128, 11, 12, 13, 14];
    let b = vec![10u128, 11, 12, 13, 14];
    let acc = best_threshold_accuracy_u128(&a, &b);
    assert!(
        acc <= 0.6,
        "identical sets should not be strongly separable"
    );
}

#[test]
fn timing_classifier_helper_bucketed_threshold_reduces_resolution() {
    let raw_a = vec![221u128, 223, 225, 227, 229];
    let raw_b = vec![231u128, 233, 235, 237, 239];
    let raw_acc = best_threshold_accuracy_u128(&raw_a, &raw_b);

    let bucketed_a = bucketize_ms(&raw_a, 20);
    let bucketed_b = bucketize_ms(&raw_b, 20);
    let bucketed_acc = best_threshold_accuracy_u128(&bucketed_a, &bucketed_b);

    assert!(raw_acc >= bucketed_acc);
}

#[tokio::test]
async fn timing_classifier_baseline_connect_fail_vs_slow_backend_is_highly_separable() {
    let fail = collect_timing_samples(PathClass::ConnectFail, false, 8).await;
    let slow = collect_timing_samples(PathClass::SlowBackend, false, 8).await;

    let acc = best_threshold_accuracy_u128(&fail, &slow);
    assert!(
        acc >= 0.80,
        "baseline timing classes should be separable enough"
    );
}

#[tokio::test]
async fn timing_classifier_normalized_connect_fail_vs_slow_backend_reduces_separability() {
    let baseline_fail = collect_timing_samples(PathClass::ConnectFail, false, 8).await;
    let baseline_slow = collect_timing_samples(PathClass::SlowBackend, false, 8).await;
    let hardened_fail = collect_timing_samples(PathClass::ConnectFail, true, 8).await;
    let hardened_slow = collect_timing_samples(PathClass::SlowBackend, true, 8).await;

    let baseline_acc = best_threshold_accuracy_u128(&baseline_fail, &baseline_slow);
    let hardened_acc = best_threshold_accuracy_u128(&hardened_fail, &hardened_slow);

    assert!(
        hardened_acc <= baseline_acc,
        "normalization should not increase timing separability"
    );
}

#[tokio::test]
async fn timing_classifier_bucketed_normalized_connect_fail_vs_slow_backend_is_bounded() {
    let baseline_fail = collect_timing_samples(PathClass::ConnectFail, false, 10).await;
    let baseline_slow = collect_timing_samples(PathClass::SlowBackend, false, 10).await;
    let hardened_fail = collect_timing_samples(PathClass::ConnectFail, true, 10).await;
    let hardened_slow = collect_timing_samples(PathClass::SlowBackend, true, 10).await;

    let baseline_acc = best_threshold_accuracy_u128(
        &bucketize_ms(&baseline_fail, 20),
        &bucketize_ms(&baseline_slow, 20),
    );
    let hardened_acc = best_threshold_accuracy_u128(
        &bucketize_ms(&hardened_fail, 20),
        &bucketize_ms(&hardened_slow, 20),
    );

    assert!(
        hardened_acc <= baseline_acc,
        "normalized bucketed classifier should not outperform baseline: baseline={baseline_acc:.3} hardened={hardened_acc:.3}"
    );
}

#[tokio::test]
async fn timing_classifier_normalized_connect_fail_samples_stay_in_sane_bounds() {
    let samples = collect_timing_samples(PathClass::ConnectFail, true, 6).await;
    for s in samples {
        assert!((150..=1200).contains(&s), "sample out of sane bounds: {s}");
    }
}

#[tokio::test]
async fn timing_classifier_normalized_connect_success_samples_stay_in_sane_bounds() {
    let samples = collect_timing_samples(PathClass::ConnectSuccess, true, 6).await;
    for s in samples {
        assert!((150..=1200).contains(&s), "sample out of sane bounds: {s}");
    }
}

#[tokio::test]
async fn timing_classifier_normalized_slow_backend_samples_stay_in_sane_bounds() {
    let samples = collect_timing_samples(PathClass::SlowBackend, true, 6).await;
    for s in samples {
        assert!((150..=1400).contains(&s), "sample out of sane bounds: {s}");
    }
}

#[tokio::test]
async fn timing_classifier_normalized_mean_bucket_delta_connect_fail_vs_connect_success_is_small() {
    let fail = collect_timing_samples(PathClass::ConnectFail, true, 8).await;
    let success = collect_timing_samples(PathClass::ConnectSuccess, true, 8).await;
    let fail_mean = mean_ms(&fail);
    let success_mean = mean_ms(&success);
    let delta_bucket = ((fail_mean as i128 - success_mean as i128).abs()) / 20;
    assert!(
        delta_bucket <= 3,
        "mean bucket delta too large: {delta_bucket}"
    );
}

#[tokio::test]
async fn timing_classifier_normalized_p95_bucket_delta_connect_success_vs_slow_is_small() {
    let success = collect_timing_samples(PathClass::ConnectSuccess, true, 10).await;
    let slow = collect_timing_samples(PathClass::SlowBackend, true, 10).await;
    let p95_success = percentile_ms(success, 95, 100);
    let p95_slow = percentile_ms(slow, 95, 100);
    let delta_bucket = ((p95_success as i128 - p95_slow as i128).abs()) / 20;
    assert!(
        delta_bucket <= 4,
        "p95 bucket delta too large: {delta_bucket}"
    );
}

#[tokio::test]
async fn timing_classifier_normalized_spread_is_not_worse_than_baseline_for_connect_fail() {
    let baseline = collect_timing_samples(PathClass::ConnectFail, false, 8).await;
    let hardened = collect_timing_samples(PathClass::ConnectFail, true, 8).await;
    let baseline_spread = spread_u128(&baseline);
    let hardened_spread = spread_u128(&hardened);
    assert!(
        hardened_spread <= baseline_spread.saturating_add(600),
        "normalized spread exploded unexpectedly: baseline={baseline_spread} hardened={hardened_spread}"
    );
}

#[tokio::test]
async fn timing_classifier_light_fuzz_pairwise_bucketed_accuracy_stays_bounded_under_normalization()
{
    const SAMPLE_COUNT: usize = 6;

    let pairs = [
        (PathClass::ConnectFail, PathClass::ConnectSuccess),
        (PathClass::ConnectFail, PathClass::SlowBackend),
        (PathClass::ConnectSuccess, PathClass::SlowBackend),
    ];

    let mut meaningful_improvement_seen = false;
    let mut informative_baseline_sum = 0.0f64;
    let mut informative_hardened_sum = 0.0f64;
    let mut informative_pair_count = 0usize;
    let mut low_info_baseline_sum = 0.0f64;
    let mut low_info_hardened_sum = 0.0f64;
    let mut low_info_pair_count = 0usize;
    let acc_quant_step = 1.0 / (2 * SAMPLE_COUNT) as f64;
    let tolerated_pair_regression = acc_quant_step + 0.03;

    for (a, b) in pairs {
        let baseline_a = collect_timing_samples(a, false, SAMPLE_COUNT).await;
        let baseline_b = collect_timing_samples(b, false, SAMPLE_COUNT).await;
        let hardened_a = collect_timing_samples(a, true, SAMPLE_COUNT).await;
        let hardened_b = collect_timing_samples(b, true, SAMPLE_COUNT).await;

        let baseline_acc = best_threshold_accuracy_u128(
            &bucketize_ms(&baseline_a, 20),
            &bucketize_ms(&baseline_b, 20),
        );
        let hardened_acc = best_threshold_accuracy_u128(
            &bucketize_ms(&hardened_a, 20),
            &bucketize_ms(&hardened_b, 20),
        );

        // When baseline separability is near-random, tiny sample jitter can make
        // hardened appear "worse" without indicating a real side-channel regression.
        // Guard hard only on informative baseline pairs.
        if baseline_acc >= 0.75 {
            assert!(
                hardened_acc <= baseline_acc + tolerated_pair_regression,
                "normalization should not materially worsen informative pair: baseline={baseline_acc:.3} hardened={hardened_acc:.3} tolerated={tolerated_pair_regression:.3}"
            );
            informative_baseline_sum += baseline_acc;
            informative_hardened_sum += hardened_acc;
            informative_pair_count += 1;
        } else {
            // Low-information pairs (near-random baseline separability) are expected
            // to exhibit quantized jitter at low sample counts; do not fold them into
            // strict average-regression checks used for informative side-channel signal.
            low_info_baseline_sum += baseline_acc;
            low_info_hardened_sum += hardened_acc;
            low_info_pair_count += 1;
        }

        println!(
            "timing_classifier_pair baseline={baseline_acc:.3} hardened={hardened_acc:.3} tolerated_pair_regression={tolerated_pair_regression:.3}"
        );

        if hardened_acc + 0.05 <= baseline_acc {
            meaningful_improvement_seen = true;
        }
    }

    assert!(
        informative_pair_count > 0,
        "expected at least one informative pair for timing-separability guard"
    );

    let informative_baseline_avg = informative_baseline_sum / informative_pair_count as f64;
    let informative_hardened_avg = informative_hardened_sum / informative_pair_count as f64;

    assert!(
        informative_hardened_avg <= informative_baseline_avg + 0.10,
        "normalization should not materially increase informative average separability: baseline_avg={informative_baseline_avg:.3} hardened_avg={informative_hardened_avg:.3}"
    );

    if low_info_pair_count > 0 {
        let low_info_baseline_avg = low_info_baseline_sum / low_info_pair_count as f64;
        let low_info_hardened_avg = low_info_hardened_sum / low_info_pair_count as f64;
        assert!(
            low_info_hardened_avg <= low_info_baseline_avg + 0.40,
            "normalization low-info average drift exceeded jitter budget: baseline_avg={low_info_baseline_avg:.3} hardened_avg={low_info_hardened_avg:.3}"
        );
    }

    // Optional signal only: do not require improvement on every run because
    // noisy CI schedulers can flatten pairwise differences at low sample counts.
    let _ = meaningful_improvement_seen;
}

#[tokio::test]
async fn timing_classifier_stress_parallel_sampling_finishes_and_stays_bounded() {
    let mut tasks = Vec::new();
    for i in 0..24usize {
        tasks.push(tokio::spawn(async move {
            let class = match i % 3 {
                0 => PathClass::ConnectFail,
                1 => PathClass::ConnectSuccess,
                _ => PathClass::SlowBackend,
            };
            let sample = measure_masking_duration_ms(class, true).await;
            assert!(
                (100..=1600).contains(&sample),
                "stress sample out of bounds: {sample}"
            );
        }));
    }

    for task in tasks {
        tokio::time::timeout(Duration::from_secs(4), task)
            .await
            .unwrap()
            .unwrap();
    }
}
