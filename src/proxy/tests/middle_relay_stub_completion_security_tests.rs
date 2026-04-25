use super::*;
use crate::stats::Stats;
use crate::stream::BufferPool;
use std::sync::Arc;
use tokio::time::{Duration as TokioDuration, timeout};

fn make_pooled_payload(data: &[u8]) -> PooledBuffer {
    let pool = Arc::new(BufferPool::with_config(data.len().max(1), 4));
    let mut payload = pool.get();
    payload.resize(data.len(), 0);
    payload[..data.len()].copy_from_slice(data);
    payload
}

fn make_c2me_permit() -> tokio::sync::OwnedSemaphorePermit {
    Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_many_owned(1)
        .expect("test permit must be available")
}

#[test]
#[ignore = "Tracking for M-04: Verify should_emit_full_desync returns true on first occurrence and false on duplicate within window"]
fn should_emit_full_desync_filters_duplicates() {
    let shared = ProxySharedState::new();
    clear_desync_dedup_for_testing_in_shared(shared.as_ref());

    let key = 0x4D04_0000_0000_0001_u64;
    let base = Instant::now();

    assert!(
        should_emit_full_desync_for_testing(shared.as_ref(), key, false, base),
        "first occurrence must emit full forensic record"
    );
    assert!(
        !should_emit_full_desync_for_testing(shared.as_ref(), key, false, base),
        "duplicate at same timestamp must be suppressed"
    );

    let within_window = base + DESYNC_DEDUP_WINDOW - TokioDuration::from_millis(1);
    assert!(
        !should_emit_full_desync_for_testing(shared.as_ref(), key, false, within_window),
        "duplicate strictly inside dedup window must stay suppressed"
    );

    let on_window_edge = base + DESYNC_DEDUP_WINDOW;
    assert!(
        should_emit_full_desync_for_testing(shared.as_ref(), key, false, on_window_edge),
        "duplicate at window boundary must re-emit and refresh"
    );
}

#[test]
#[ignore = "Tracking for M-04: Verify desync dedup eviction behaves correctly under map-full condition"]
fn desync_dedup_eviction_under_map_full_condition() {
    let shared = ProxySharedState::new();
    clear_desync_dedup_for_testing_in_shared(shared.as_ref());

    let base = Instant::now();
    for key in 0..DESYNC_DEDUP_MAX_ENTRIES as u64 {
        assert!(
            should_emit_full_desync_for_testing(shared.as_ref(), key, false, base),
            "unique key should be inserted while warming dedup cache"
        );
    }

    assert_eq!(
        desync_dedup_len_for_testing(shared.as_ref()),
        DESYNC_DEDUP_MAX_ENTRIES,
        "cache warm-up must reach exact hard cap"
    );

    let before_keys = desync_dedup_keys_for_testing(shared.as_ref());
    let newcomer_key = 0x4D04_FFFF_FFFF_0001_u64;

    assert!(
        should_emit_full_desync_for_testing(shared.as_ref(), newcomer_key, false, base),
        "first newcomer at map-full must emit under bounded full-cache gate"
    );

    let after_keys = desync_dedup_keys_for_testing(shared.as_ref());
    assert_eq!(
        desync_dedup_len_for_testing(shared.as_ref()),
        DESYNC_DEDUP_MAX_ENTRIES,
        "map-full insertion must preserve hard capacity bound"
    );
    assert!(
        after_keys.contains(&newcomer_key),
        "newcomer must be present after bounded eviction path"
    );

    let removed_count = before_keys.difference(&after_keys).count();
    let added_count = after_keys.difference(&before_keys).count();
    assert_eq!(
        removed_count, 1,
        "map-full insertion must evict exactly one prior key"
    );
    assert_eq!(
        added_count, 1,
        "map-full insertion must add exactly one newcomer key"
    );

    assert!(
        !should_emit_full_desync_for_testing(shared.as_ref(), newcomer_key, false, base),
        "immediate duplicate newcomer must remain suppressed"
    );
}

#[tokio::test]
#[ignore = "Tracking for M-05: Verify C2ME channel full path yields then sends under backpressure"]
async fn c2me_channel_full_path_yields_then_sends() {
    let (tx, mut rx) = mpsc::channel::<C2MeCommand>(1);

    tx.send(C2MeCommand::Data {
        payload: make_pooled_payload(&[0xAA]),
        flags: 1,
        _permit: make_c2me_permit(),
    })
    .await
    .expect("priming queue with one frame must succeed");

    let tx2 = tx.clone();
    let stats = Stats::default();
    let producer = tokio::spawn(async move {
        enqueue_c2me_command(
            &tx2,
            C2MeCommand::Data {
                payload: make_pooled_payload(&[0xBB, 0xCC]),
                flags: 2,
                _permit: make_c2me_permit(),
            },
            None,
            &stats,
        )
        .await
    });

    tokio::task::yield_now().await;
    tokio::time::sleep(TokioDuration::from_millis(10)).await;
    assert!(
        !producer.is_finished(),
        "producer should stay pending while queue is full"
    );

    let first = timeout(TokioDuration::from_millis(100), rx.recv())
        .await
        .expect("receiver should observe primed frame")
        .expect("first queued command must exist");
    match first {
        C2MeCommand::Data { payload, flags, .. } => {
            assert_eq!(payload.as_ref(), &[0xAA]);
            assert_eq!(flags, 1);
        }
        C2MeCommand::Close => panic!("unexpected close command as first item"),
    }

    producer
        .await
        .expect("producer task must not panic")
        .expect("blocked enqueue must succeed once receiver drains capacity");

    let second = timeout(TokioDuration::from_millis(100), rx.recv())
        .await
        .expect("receiver should observe backpressure-resumed frame")
        .expect("second queued command must exist");
    match second {
        C2MeCommand::Data { payload, flags, .. } => {
            assert_eq!(payload.as_ref(), &[0xBB, 0xCC]);
            assert_eq!(flags, 2);
        }
        C2MeCommand::Close => panic!("unexpected close command as second item"),
    }
}
