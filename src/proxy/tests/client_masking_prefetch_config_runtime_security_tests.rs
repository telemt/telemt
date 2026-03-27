use super::*;
use tokio::io::{AsyncWriteExt, duplex};
use tokio::time::{Duration, sleep};

#[test]
fn prefetch_timeout_budget_reads_from_config() {
    let mut cfg = ProxyConfig::default();
    assert_eq!(
        mask_classifier_prefetch_timeout(&cfg),
        Duration::from_millis(5),
        "default prefetch timeout budget must remain 5ms"
    );

    cfg.censorship.mask_classifier_prefetch_timeout_ms = 20;
    assert_eq!(
        mask_classifier_prefetch_timeout(&cfg),
        Duration::from_millis(20),
        "runtime prefetch timeout budget must follow configured value"
    );
}

#[tokio::test]
async fn configured_prefetch_budget_20ms_recovers_tail_delayed_15ms() {
    let (mut reader, mut writer) = duplex(1024);

    let writer_task = tokio::spawn(async move {
        sleep(Duration::from_millis(15)).await;
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
    extend_masking_initial_window_with_timeout(
        &mut reader,
        &mut initial_data,
        Duration::from_millis(20),
    )
    .await;

    writer_task
        .await
        .expect("writer task must not panic in runtime timeout test");

    assert!(
        initial_data.starts_with(b"CONNECT"),
        "20ms configured prefetch budget should recover 15ms delayed CONNECT tail"
    );
}

#[tokio::test]
async fn configured_prefetch_budget_5ms_misses_tail_delayed_15ms() {
    let (mut reader, mut writer) = duplex(1024);

    let writer_task = tokio::spawn(async move {
        sleep(Duration::from_millis(15)).await;
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
    extend_masking_initial_window_with_timeout(
        &mut reader,
        &mut initial_data,
        Duration::from_millis(5),
    )
    .await;

    writer_task
        .await
        .expect("writer task must not panic in runtime timeout test");

    assert!(
        !initial_data.starts_with(b"CONNECT"),
        "5ms configured prefetch budget should miss 15ms delayed CONNECT tail"
    );
}
