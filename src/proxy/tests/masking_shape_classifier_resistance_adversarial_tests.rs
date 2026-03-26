use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::TcpListener;
use tokio::time::Duration;

async fn capture_forwarded_len(
    body_sent: usize,
    shape_hardening: bool,
    above_cap_blur: bool,
    above_cap_blur_max_bytes: usize,
) -> usize {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_shape_hardening = shape_hardening;
    config.censorship.mask_shape_bucket_floor_bytes = 512;
    config.censorship.mask_shape_bucket_cap_bytes = 4096;
    config.censorship.mask_shape_above_cap_blur = above_cap_blur;
    config.censorship.mask_shape_above_cap_blur_max_bytes = above_cap_blur_max_bytes;

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut got)).await;
        got.len()
    });

    let (client_reader, mut client_writer) = duplex(64 * 1024);
    let (_client_visible_reader, client_visible_writer) = duplex(64 * 1024);

    let mut initial = vec![0u8; 5 + body_sent];
    initial[0] = 0x16;
    initial[1] = 0x03;
    initial[2] = 0x01;
    initial[3..5].copy_from_slice(&7000u16.to_be_bytes());
    initial[5..].fill(0x5A);

    let peer: SocketAddr = "198.51.100.250:57450".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let fallback = tokio::spawn(async move {
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
    let _ = tokio::time::timeout(Duration::from_secs(3), fallback)
        .await
        .unwrap()
        .unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap()
}

fn best_threshold_accuracy(a: &[usize], b: &[usize]) -> f64 {
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

fn nearest_centroid_classifier_accuracy(
    samples_a: &[usize],
    samples_b: &[usize],
    samples_c: &[usize],
) -> f64 {
    let mean = |xs: &[usize]| -> f64 { xs.iter().copied().sum::<usize>() as f64 / xs.len() as f64 };

    let ca = mean(samples_a);
    let cb = mean(samples_b);
    let cc = mean(samples_c);

    let mut correct = 0usize;
    let mut total = 0usize;

    for &x in samples_a {
        total += 1;
        let xf = x as f64;
        let d = [(xf - ca).abs(), (xf - cb).abs(), (xf - cc).abs()];
        if d[0] <= d[1] && d[0] <= d[2] {
            correct += 1;
        }
    }

    for &x in samples_b {
        total += 1;
        let xf = x as f64;
        let d = [(xf - ca).abs(), (xf - cb).abs(), (xf - cc).abs()];
        if d[1] <= d[0] && d[1] <= d[2] {
            correct += 1;
        }
    }

    for &x in samples_c {
        total += 1;
        let xf = x as f64;
        let d = [(xf - ca).abs(), (xf - cb).abs(), (xf - cc).abs()];
        if d[2] <= d[0] && d[2] <= d[1] {
            correct += 1;
        }
    }

    correct as f64 / total as f64
}

#[tokio::test]
async fn masking_shape_classifier_resistance_blur_reduces_threshold_attack_accuracy() {
    const SAMPLES: usize = 120;
    const MAX_EXTRA: usize = 96;
    const CLASS_A_BODY: usize = 5000;
    const CLASS_B_BODY: usize = 5040;

    let mut baseline_a = Vec::with_capacity(SAMPLES);
    let mut baseline_b = Vec::with_capacity(SAMPLES);
    let mut hardened_a = Vec::with_capacity(SAMPLES);
    let mut hardened_b = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        baseline_a.push(capture_forwarded_len(CLASS_A_BODY, true, false, 0).await);
        baseline_b.push(capture_forwarded_len(CLASS_B_BODY, true, false, 0).await);
        hardened_a.push(capture_forwarded_len(CLASS_A_BODY, true, true, MAX_EXTRA).await);
        hardened_b.push(capture_forwarded_len(CLASS_B_BODY, true, true, MAX_EXTRA).await);
    }

    let baseline_acc = best_threshold_accuracy(&baseline_a, &baseline_b);
    let hardened_acc = best_threshold_accuracy(&hardened_a, &hardened_b);

    // Baseline classes are deterministic/non-overlapping -> near-perfect threshold attack.
    assert!(
        baseline_acc >= 0.99,
        "baseline separability unexpectedly low: {baseline_acc:.3}"
    );
    // Blur must materially reduce the best one-dimensional length classifier.
    assert!(
        hardened_acc <= 0.90,
        "blur should degrade threshold attack accuracy, got {hardened_acc:.3}"
    );
    assert!(
        hardened_acc <= baseline_acc - 0.08,
        "blur must reduce threshold accuracy by a meaningful margin: baseline={baseline_acc:.3}, hardened={hardened_acc:.3}"
    );
}

#[tokio::test]
async fn masking_shape_classifier_resistance_blur_increases_cross_class_overlap() {
    const SAMPLES: usize = 96;
    const MAX_EXTRA: usize = 96;
    const CLASS_A_BODY: usize = 5000;
    const CLASS_B_BODY: usize = 5040;

    let mut baseline_a = std::collections::BTreeSet::new();
    let mut baseline_b = std::collections::BTreeSet::new();
    let mut hardened_a = std::collections::BTreeSet::new();
    let mut hardened_b = std::collections::BTreeSet::new();

    for _ in 0..SAMPLES {
        baseline_a.insert(capture_forwarded_len(CLASS_A_BODY, true, false, 0).await);
        baseline_b.insert(capture_forwarded_len(CLASS_B_BODY, true, false, 0).await);
        hardened_a.insert(capture_forwarded_len(CLASS_A_BODY, true, true, MAX_EXTRA).await);
        hardened_b.insert(capture_forwarded_len(CLASS_B_BODY, true, true, MAX_EXTRA).await);
    }

    let baseline_overlap = baseline_a.intersection(&baseline_b).count();
    let hardened_overlap = hardened_a.intersection(&hardened_b).count();

    assert_eq!(baseline_overlap, 0, "baseline classes should not overlap");
    assert!(
        hardened_overlap >= 8,
        "blur should create meaningful overlap between classes, got overlap={hardened_overlap}"
    );
}

#[tokio::test]
async fn masking_shape_classifier_resistance_parallel_probe_campaign_keeps_blur_bounds() {
    const MAX_EXTRA: usize = 128;

    let mut tasks = Vec::new();
    for i in 0..64usize {
        tasks.push(tokio::spawn(async move {
            let body = 4300 + (i % 700);
            let observed = capture_forwarded_len(body, true, true, MAX_EXTRA).await;
            let base = 5 + body;
            assert!(
                observed >= base && observed <= base + MAX_EXTRA,
                "campaign bounds violated for i={i}: observed={observed} base={base}"
            );
        }));
    }

    for task in tasks {
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn masking_shape_classifier_resistance_edge_max_extra_one_has_two_point_support() {
    const BODY: usize = 5000;
    const BASE: usize = 5 + BODY;

    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..64 {
        let observed = capture_forwarded_len(BODY, true, true, 1).await;
        assert!(
            observed == BASE || observed == BASE + 1,
            "max_extra=1 must only produce two-point support"
        );
        seen.insert(observed);
    }

    assert_eq!(
        seen.len(),
        2,
        "both support points should appear under repeated sampling"
    );
}

#[tokio::test]
async fn masking_shape_classifier_resistance_negative_blur_without_shape_hardening_is_noop() {
    const BODY_A: usize = 5000;
    const BODY_B: usize = 5040;

    let mut as_observed = std::collections::BTreeSet::new();
    let mut bs_observed = std::collections::BTreeSet::new();
    for _ in 0..48 {
        as_observed.insert(capture_forwarded_len(BODY_A, false, true, 96).await);
        bs_observed.insert(capture_forwarded_len(BODY_B, false, true, 96).await);
    }

    assert_eq!(
        as_observed.len(),
        1,
        "without shape hardening class A must stay deterministic"
    );
    assert_eq!(
        bs_observed.len(),
        1,
        "without shape hardening class B must stay deterministic"
    );
    assert_ne!(
        as_observed, bs_observed,
        "distinct classes should remain separable without shaping"
    );
}

#[tokio::test]
async fn masking_shape_classifier_resistance_adversarial_three_class_centroid_attack_degrades_with_blur()
 {
    const SAMPLES: usize = 80;
    const MAX_EXTRA: usize = 96;
    const C1: usize = 5000;
    const C2: usize = 5040;
    const C3: usize = 5080;

    let mut base1 = Vec::with_capacity(SAMPLES);
    let mut base2 = Vec::with_capacity(SAMPLES);
    let mut base3 = Vec::with_capacity(SAMPLES);
    let mut hard1 = Vec::with_capacity(SAMPLES);
    let mut hard2 = Vec::with_capacity(SAMPLES);
    let mut hard3 = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        base1.push(capture_forwarded_len(C1, true, false, 0).await);
        base2.push(capture_forwarded_len(C2, true, false, 0).await);
        base3.push(capture_forwarded_len(C3, true, false, 0).await);

        hard1.push(capture_forwarded_len(C1, true, true, MAX_EXTRA).await);
        hard2.push(capture_forwarded_len(C2, true, true, MAX_EXTRA).await);
        hard3.push(capture_forwarded_len(C3, true, true, MAX_EXTRA).await);
    }

    let base_acc = nearest_centroid_classifier_accuracy(&base1, &base2, &base3);
    let hard_acc = nearest_centroid_classifier_accuracy(&hard1, &hard2, &hard3);

    assert!(
        base_acc >= 0.99,
        "baseline centroid separability should be near-perfect"
    );
    assert!(
        hard_acc <= 0.88,
        "blur should materially degrade 3-class centroid attack"
    );
    assert!(
        hard_acc <= base_acc - 0.1,
        "accuracy drop should be meaningful"
    );
}

#[tokio::test]
async fn masking_shape_classifier_resistance_light_fuzz_bounds_hold_for_randomized_above_cap_campaign()
 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    for _ in 0..96 {
        s ^= s << 7;
        s ^= s >> 9;
        s ^= s << 8;
        let body = 4097 + (s as usize % 2048);

        s ^= s << 7;
        s ^= s >> 9;
        s ^= s << 8;
        let max_extra = 1 + (s as usize % 128);

        let observed = capture_forwarded_len(body, true, true, max_extra).await;
        let base = 5 + body;
        assert!(
            observed >= base && observed <= base + max_extra,
            "fuzz bounds violated: body={body} observed={observed} max_extra={max_extra}"
        );
    }
}
