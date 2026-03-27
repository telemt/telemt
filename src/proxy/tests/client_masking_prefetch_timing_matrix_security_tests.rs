use super::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::{Duration, sleep, timeout};

async fn extend_masking_initial_window_with_budget<R>(
    reader: &mut R,
    initial_data: &mut Vec<u8>,
    prefetch_timeout: Duration,
) where
    R: AsyncRead + Unpin,
{
    if !should_prefetch_mask_classifier_window(initial_data) {
        return;
    }

    let need = 16usize.saturating_sub(initial_data.len());
    if need == 0 {
        return;
    }

    let mut extra = [0u8; 16];
    if let Ok(Ok(n)) = timeout(prefetch_timeout, reader.read(&mut extra[..need])).await
        && n > 0
    {
        initial_data.extend_from_slice(&extra[..n]);
    }
}

async fn run_prefetch_budget_case(prefetch_budget_ms: u64, delayed_tail_ms: u64) -> bool {
    let (mut reader, mut writer) = duplex(1024);

    let writer_task = tokio::spawn(async move {
        sleep(Duration::from_millis(delayed_tail_ms)).await;
        writer
            .write_all(b"ONNECT example.org:443 HTTP/1.1\r\n")
            .await
            .expect("tail bytes must be writable");
        writer
            .shutdown()
            .await
            .expect("writer shutdown must succeed");
    });

    let mut initial_data = b"C".to_vec();
    extend_masking_initial_window_with_budget(
        &mut reader,
        &mut initial_data,
        Duration::from_millis(prefetch_budget_ms),
    )
    .await;

    writer_task
        .await
        .expect("writer task must not panic during matrix case");

    initial_data.starts_with(b"CONNECT")
}

#[tokio::test]
async fn adversarial_prefetch_budget_matrix_5_20_50ms_for_fragmented_connect_tail() {
    let cases = [
        // (tail-delay-ms, expected CONNECT recovery for budgets [5, 20, 50])
        (2u64, [true, true, true]),
        (15u64, [false, true, true]),
        (35u64, [false, false, true]),
    ];

    for (tail_delay_ms, expected) in cases {
        let got_5 = run_prefetch_budget_case(5, tail_delay_ms).await;
        let got_20 = run_prefetch_budget_case(20, tail_delay_ms).await;
        let got_50 = run_prefetch_budget_case(50, tail_delay_ms).await;

        assert_eq!(
            got_5, expected[0],
            "5ms prefetch budget mismatch for tail delay {}ms",
            tail_delay_ms
        );
        assert_eq!(
            got_20, expected[1],
            "20ms prefetch budget mismatch for tail delay {}ms",
            tail_delay_ms
        );
        assert_eq!(
            got_50, expected[2],
            "50ms prefetch budget mismatch for tail delay {}ms",
            tail_delay_ms
        );
    }
}

#[tokio::test]
async fn control_current_runtime_prefetch_budget_is_5ms() {
    assert_eq!(
        MASK_CLASSIFIER_PREFETCH_TIMEOUT,
        Duration::from_millis(5),
        "matrix assumptions require current runtime prefetch budget to stay at 5ms"
    );
}
