use super::*;
use crate::stats::Stats;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Barrier;
use tokio::time::{Duration, timeout};

fn saturate_lock_cache() -> Vec<Arc<std::sync::Mutex<()>>> {
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let mut retained = Vec::with_capacity(QUOTA_USER_LOCKS_MAX);
    for idx in 0..QUOTA_USER_LOCKS_MAX {
        retained.push(quota_user_lock(&format!("quota-liveness-saturated-{idx}")));
    }
    retained
}

fn quota_test_guard() -> impl Drop {
    super::quota_user_lock_test_scope()
}

#[tokio::test]
async fn positive_writer_progresses_after_contention_release_without_external_wake() {
    let _guard = quota_test_guard();

    let _retained = saturate_lock_cache();
    let user = "quota-liveness-writer-positive";
    let stats = Arc::new(Stats::new());

    let lock = quota_user_lock(user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold user quota lock before write");

    let counters = Arc::new(SharedCounters::new());
    let quota_exceeded = Arc::new(AtomicBool::new(false));
    let mut io = StatsIo::new(
        tokio::io::sink(),
        counters,
        Arc::clone(&stats),
        user.to_string(),
        Some(1024),
        quota_exceeded,
        tokio::time::Instant::now(),
    );

    let writer = tokio::spawn(async move { io.write_all(&[0x11]).await });

    // Let the initial deferred wake fire while contention is still active.
    tokio::time::sleep(Duration::from_millis(4)).await;

    drop(held_guard);

    let completed = timeout(Duration::from_millis(250), writer)
        .await
        .expect("writer must be re-polled and complete after lock release")
        .expect("writer task must not panic");
    assert!(completed.is_ok(), "writer must complete after lock release");
}

#[tokio::test]
async fn edge_reader_progresses_after_contention_release_without_external_wake() {
    let _guard = quota_test_guard();

    let _retained = saturate_lock_cache();
    let user = "quota-liveness-reader-edge";
    let stats = Arc::new(Stats::new());

    let lock = quota_user_lock(user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold user quota lock before read");

    let counters = Arc::new(SharedCounters::new());
    let quota_exceeded = Arc::new(AtomicBool::new(false));
    let mut io = StatsIo::new(
        tokio::io::empty(),
        counters,
        Arc::clone(&stats),
        user.to_string(),
        Some(1024),
        quota_exceeded,
        tokio::time::Instant::now(),
    );

    let reader = tokio::spawn(async move {
        let mut one = [0u8; 1];
        io.read(&mut one).await
    });

    tokio::time::sleep(Duration::from_millis(4)).await;
    drop(held_guard);

    let completed = timeout(Duration::from_millis(250), reader)
        .await
        .expect("reader must be re-polled and complete after lock release")
        .expect("reader task must not panic");
    assert!(completed.is_ok(), "reader must complete after lock release");
}

#[tokio::test]
async fn adversarial_early_deferred_wake_consumption_does_not_deadlock_writer() {
    let _guard = quota_test_guard();

    let _retained = saturate_lock_cache();
    let user = "quota-liveness-adversarial";
    let stats = Arc::new(Stats::new());

    let lock = quota_user_lock(user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold user quota lock before adversarial write");

    let counters = Arc::new(SharedCounters::new());
    let quota_exceeded = Arc::new(AtomicBool::new(false));
    let mut io = StatsIo::new(
        tokio::io::sink(),
        counters,
        Arc::clone(&stats),
        user.to_string(),
        Some(1024),
        quota_exceeded,
        tokio::time::Instant::now(),
    );

    let writer = tokio::spawn(async move { io.write_all(&[0x22]).await });

    // Force multiple scheduler rounds while lock remains held so the first
    // deferred wake has already been consumed under contention.
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }

    drop(held_guard);

    let completed = timeout(Duration::from_millis(300), writer)
        .await
        .expect("writer must not stay parked forever after release")
        .expect("writer task must not panic");
    assert!(completed.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integration_parallel_waiters_resume_after_single_release_event() {
    let _guard = quota_test_guard();

    let _retained = saturate_lock_cache();
    let user = format!("quota-liveness-integration-{}", std::process::id());
    let stats = Arc::new(Stats::new());
    let barrier = Arc::new(Barrier::new(13));

    let lock = quota_user_lock(&user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold user quota lock before launching waiters");

    let mut waiters = Vec::new();
    for _ in 0..12 {
        let stats = Arc::clone(&stats);
        let user = user.clone();
        let barrier = Arc::clone(&barrier);
        waiters.push(tokio::spawn(async move {
            let counters = Arc::new(SharedCounters::new());
            let quota_exceeded = Arc::new(AtomicBool::new(false));
            let mut io = StatsIo::new(
                tokio::io::sink(),
                counters,
                stats,
                user,
                Some(4096),
                quota_exceeded,
                tokio::time::Instant::now(),
            );
            barrier.wait().await;
            io.write_all(&[0x33]).await
        }));
    }

    barrier.wait().await;
    tokio::time::sleep(Duration::from_millis(4)).await;
    drop(held_guard);

    timeout(Duration::from_secs(1), async {
        for waiter in waiters {
            let outcome = waiter.await.expect("waiter must not panic");
            assert!(
                outcome.is_ok(),
                "waiter must resume and complete after release"
            );
        }
    })
    .await
    .expect("all waiters must complete in bounded time");
}

#[tokio::test]
async fn light_fuzz_release_timing_matrix_preserves_liveness() {
    let _guard = quota_test_guard();

    let _retained = saturate_lock_cache();
    let stats = Arc::new(Stats::new());

    let mut seed = 0xD1CE_F00D_0123_4567u64;
    for round in 0..64u32 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let delay_ms = 1 + (seed & 0x7) as u64;
        let user = format!("quota-liveness-fuzz-{}-{round}", std::process::id());

        let lock = quota_user_lock(&user);
        let held_guard = lock
            .try_lock()
            .expect("test must hold user quota lock in fuzz round");

        let counters = Arc::new(SharedCounters::new());
        let quota_exceeded = Arc::new(AtomicBool::new(false));
        let mut io = StatsIo::new(
            tokio::io::sink(),
            counters,
            Arc::clone(&stats),
            user,
            Some(2048),
            quota_exceeded,
            tokio::time::Instant::now(),
        );

        let writer = tokio::spawn(async move { io.write_all(&[0x44]).await });

        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        drop(held_guard);

        let done = timeout(Duration::from_millis(300), writer)
            .await
            .expect("fuzz round writer must complete")
            .expect("fuzz writer task must not panic");
        assert!(
            done.is_ok(),
            "fuzz round writer must not stall after release"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_repeated_contention_cycles_remain_live() {
    let _guard = quota_test_guard();

    let _retained = saturate_lock_cache();
    let stats = Arc::new(Stats::new());

    for cycle in 0..40u32 {
        let user = format!("quota-liveness-stress-{}-{cycle}", std::process::id());
        let lock = quota_user_lock(&user);
        let held_guard = lock
            .try_lock()
            .expect("test must hold lock before stress cycle");

        let mut tasks = Vec::new();
        for _ in 0..6 {
            let stats = Arc::clone(&stats);
            let user = user.clone();
            tasks.push(tokio::spawn(async move {
                let counters = Arc::new(SharedCounters::new());
                let quota_exceeded = Arc::new(AtomicBool::new(false));
                let mut io = StatsIo::new(
                    tokio::io::sink(),
                    counters,
                    stats,
                    user,
                    Some(2048),
                    quota_exceeded,
                    tokio::time::Instant::now(),
                );
                io.write_all(&[0x55]).await
            }));
        }

        tokio::task::yield_now().await;
        drop(held_guard);

        timeout(Duration::from_millis(700), async {
            for task in tasks {
                let outcome = task.await.expect("stress task must not panic");
                assert!(outcome.is_ok(), "stress writer must complete");
            }
        })
        .await
        .expect("stress cycle must finish in bounded time");
    }
}
