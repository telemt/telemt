use super::*;
use tokio::io::{AsyncWriteExt, duplex};
use tokio::time::{Duration, advance, sleep};

async fn run_strict_prefetch_case(prefetch_ms: u64, tail_delay_ms: u64) -> Vec<u8> {
    let (mut reader, mut writer) = duplex(1024);

    let writer_task = tokio::spawn(async move {
        sleep(Duration::from_millis(tail_delay_ms)).await;
        let _ = writer
            .write_all(b"ONNECT example.org:443 HTTP/1.1\r\n")
            .await;
        let _ = writer.shutdown().await;
    });

    let mut initial_data = b"C".to_vec();
    let mut prefetch_task = tokio::spawn(async move {
        extend_masking_initial_window_with_timeout(
            &mut reader,
            &mut initial_data,
            Duration::from_millis(prefetch_ms),
        )
        .await;
        initial_data
    });

    tokio::task::yield_now().await;

    if tail_delay_ms > 0 {
        advance(Duration::from_millis(tail_delay_ms)).await;
        tokio::task::yield_now().await;
    }

    if prefetch_ms > tail_delay_ms {
        advance(Duration::from_millis(prefetch_ms - tail_delay_ms)).await;
        tokio::task::yield_now().await;
    }

    let result = prefetch_task.await.expect("prefetch task must not panic");
    writer_task.await.expect("writer task must not panic");
    result
}

#[tokio::test(start_paused = true)]
async fn strict_prefetch_5ms_misses_15ms_tail() {
    let got = run_strict_prefetch_case(5, 15).await;
    assert_eq!(got, b"C".to_vec());
}

#[tokio::test(start_paused = true)]
async fn strict_prefetch_20ms_recovers_15ms_tail() {
    let got = run_strict_prefetch_case(20, 15).await;
    assert!(got.starts_with(b"CONNECT"));
}

#[tokio::test(start_paused = true)]
async fn strict_prefetch_50ms_recovers_35ms_tail() {
    let got = run_strict_prefetch_case(50, 35).await;
    assert!(got.starts_with(b"CONNECT"));
}

#[tokio::test(start_paused = true)]
async fn strict_prefetch_equal_budget_and_delay_recovers_tail() {
    let got = run_strict_prefetch_case(20, 20).await;
    assert!(got.starts_with(b"CONNECT"));
}

#[tokio::test(start_paused = true)]
async fn strict_prefetch_one_ms_after_budget_misses_tail() {
    let got = run_strict_prefetch_case(20, 21).await;
    assert_eq!(got, b"C".to_vec());
}
