use super::*;
use tokio::io::AsyncReadExt;
use tokio::time::{Duration, timeout};

async fn collect_padding(
    total_sent: usize,
    enabled: bool,
    floor: usize,
    cap: usize,
    above_cap_blur: bool,
    blur_max: usize,
    aggressive: bool,
) -> Vec<u8> {
    let (mut tx, mut rx) = tokio::io::duplex(256 * 1024);

    maybe_write_shape_padding(
        &mut tx,
        total_sent,
        enabled,
        floor,
        cap,
        above_cap_blur,
        blur_max,
        aggressive,
    )
    .await;

    drop(tx);

    let mut output = Vec::new();
    timeout(Duration::from_secs(1), rx.read_to_end(&mut output))
        .await
        .expect("reading padded output timed out")
        .expect("failed reading padded output");
    output
}

#[tokio::test]
async fn padding_output_is_not_all_zero() {
    let output = collect_padding(1, true, 256, 4096, false, 0, false).await;

    assert!(
        output.len() >= 255,
        "expected at least 255 padding bytes, got {}",
        output.len()
    );

    let nonzero = output.iter().filter(|&&b| b != 0).count();
    // In 255 bytes of uniform randomness, the expected number of zero bytes is ~1.
    // A weak nonzero check can miss severe entropy collapse.
    assert!(
        nonzero >= 240,
        "RNG output entropy collapsed, too many zero bytes: {} nonzero out of {}",
        nonzero,
        output.len(),
    );
}

#[tokio::test]
async fn padding_reaches_first_bucket_boundary() {
    let output = collect_padding(1, true, 64, 4096, false, 0, false).await;
    assert_eq!(output.len(), 63);
}

#[tokio::test]
async fn disabled_padding_produces_no_output() {
    let output = collect_padding(0, false, 256, 4096, false, 0, false).await;
    assert!(output.is_empty());
}

#[tokio::test]
async fn at_cap_without_blur_produces_no_output() {
    let output = collect_padding(4096, true, 64, 4096, false, 0, false).await;
    assert!(output.is_empty());
}

#[tokio::test]
async fn above_cap_blur_is_positive_and_bounded_in_aggressive_mode() {
    let output = collect_padding(4096, true, 64, 4096, true, 128, true).await;
    assert!(!output.is_empty());
    assert!(output.len() <= 128, "blur exceeded max: {}", output.len());
}

#[tokio::test]
async fn stress_padding_runs_are_not_constant_pattern() {
    // Stress and sanity-check: repeated runs should not collapse to identical
    // first 16 bytes across all samples.
    let mut first_chunks = Vec::new();
    for _ in 0..64 {
        let out = collect_padding(1, true, 64, 4096, false, 0, false).await;
        first_chunks.push(out[..16].to_vec());
    }

    let first = &first_chunks[0];
    let all_same = first_chunks.iter().all(|chunk| chunk == first);
    assert!(
        !all_same,
        "all stress samples had identical prefix, rng output appears degenerate"
    );
}
