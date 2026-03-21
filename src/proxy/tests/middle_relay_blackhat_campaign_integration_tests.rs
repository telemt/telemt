use super::*;
use crate::stats::Stats;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Barrier;
use tokio::time::{Duration, timeout};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blackhat_campaign_saturation_quota_race_with_queue_pressure_stays_fail_closed() {
    let _guard = super::quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let mut retained = Vec::with_capacity(QUOTA_USER_LOCKS_MAX);
    for idx in 0..QUOTA_USER_LOCKS_MAX {
        retained.push(quota_user_lock(&format!(
            "middle-blackhat-held-{}-{idx}",
            std::process::id()
        )));
    }

    assert_eq!(
        map.len(),
        QUOTA_USER_LOCKS_MAX,
        "precondition: bounded lock cache must be saturated"
    );

    let (tx, _rx) = mpsc::channel::<C2MeCommand>(1);
    tx.send(C2MeCommand::Close)
        .await
        .expect("queue prefill should succeed");

    let pressure_seq_before = relay_pressure_event_seq();
    let pressure_errors = Arc::new(AtomicUsize::new(0));
    let mut pressure_workers = Vec::new();
    for _ in 0..16 {
        let tx = tx.clone();
        let pressure_errors = Arc::clone(&pressure_errors);
        pressure_workers.push(tokio::spawn(async move {
            if enqueue_c2me_command(&tx, C2MeCommand::Close).await.is_err() {
                pressure_errors.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    let stats = Arc::new(Stats::new());
    let user = format!("middle-blackhat-quota-race-{}", std::process::id());
    let gate = Arc::new(Barrier::new(16));

    let mut quota_workers = Vec::new();
    for _ in 0..16u8 {
        let stats = Arc::clone(&stats);
        let user = user.clone();
        let gate = Arc::clone(&gate);
        quota_workers.push(tokio::spawn(async move {
            gate.wait().await;
            let user_lock = quota_user_lock(&user);
            let _quota_guard = user_lock.lock().await;

            if quota_would_be_exceeded_for_user(&stats, &user, Some(1), 1) {
                return false;
            }
            stats.add_user_octets_to(&user, 1);
            true
        }));
    }

    let mut ok_count = 0usize;
    let mut denied_count = 0usize;
    for worker in quota_workers {
        let result = timeout(Duration::from_secs(2), worker)
            .await
            .expect("quota worker must finish")
            .expect("quota worker must not panic");
        if result {
            ok_count += 1;
        } else {
            denied_count += 1;
        }
    }

    for worker in pressure_workers {
        timeout(Duration::from_secs(2), worker)
            .await
            .expect("pressure worker must finish")
            .expect("pressure worker must not panic");
    }

    assert_eq!(
        stats.get_user_total_octets(&user),
        1,
        "black-hat campaign must not overshoot same-user quota under saturation"
    );
    assert!(ok_count <= 1, "at most one quota contender may succeed");
    assert!(
        denied_count >= 15,
        "all remaining contenders must be quota-denied"
    );

    let pressure_seq_after = relay_pressure_event_seq();
    assert!(
        pressure_seq_after > pressure_seq_before,
        "queue pressure leg must trigger pressure accounting"
    );
    assert!(
        pressure_errors.load(Ordering::Relaxed) >= 1,
        "at least one pressure worker should fail from persistent backpressure"
    );

    drop(retained);
}
