use super::*;
use crate::stats::Stats;
use dashmap::DashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Waker};
use tokio::io::{ReadBuf, AsyncWriteExt};
use tokio::time::{Duration, timeout};

#[derive(Default)]
struct WakeCounter {
    wakes: AtomicUsize,
}

impl std::task::Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::Relaxed);
    }
}

fn quota_test_guard() -> impl Drop {
    super::quota_user_lock_test_scope()
}

fn saturate_quota_user_locks() -> Vec<Arc<std::sync::Mutex<()>>> {
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let mut retained = Vec::with_capacity(QUOTA_USER_LOCKS_MAX);
    for idx in 0..QUOTA_USER_LOCKS_MAX {
        retained.push(quota_user_lock(&format!("quota-waker-saturate-{idx}")));
    }
    retained
}

#[tokio::test]
async fn positive_contended_writer_emits_deferred_wake_for_liveness() {
    let _guard = quota_test_guard();

    let _retained = saturate_quota_user_locks();
    let stats = Arc::new(Stats::new());
    let user = "quota-waker-positive-user";

    let lock = quota_user_lock(user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold overflow lock before polling writer");

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

    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);

    let pending = Pin::new(&mut io).poll_write(&mut cx, &[0xA1]);
    assert!(pending.is_pending());

    timeout(Duration::from_millis(100), async {
        loop {
            if wake_counter.wakes.load(Ordering::Relaxed) >= 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("contended writer must receive deferred wake");

    drop(held_guard);
    let ready = Pin::new(&mut io).poll_write(&mut cx, &[0xA2]);
    assert!(ready.is_ready(), "writer must progress after contention release");
}

#[tokio::test]
async fn adversarial_blackhat_writer_contention_does_not_create_waker_storm() {
    let _guard = quota_test_guard();

    let _retained = saturate_quota_user_locks();
    let stats = Arc::new(Stats::new());
    let user = "quota-waker-blackhat-writer";

    let lock = quota_user_lock(user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold overflow lock before polling writer");

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

    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);

    for _ in 0..512 {
        let poll = Pin::new(&mut io).poll_write(&mut cx, &[0xBE]);
        assert!(poll.is_pending(), "writer must stay pending while lock is held");
        tokio::task::yield_now().await;
    }

    let wakes = wake_counter.wakes.load(Ordering::Relaxed);
    assert!(
        wakes <= 128,
        "pending writer retries must not trigger wake storm; observed wakes={wakes}"
    );

    drop(held_guard);
    let ready = Pin::new(&mut io).poll_write(&mut cx, &[0xEF]);
    assert!(ready.is_ready());
}

#[tokio::test]
async fn edge_read_path_contention_keeps_wake_budget_bounded() {
    let _guard = quota_test_guard();

    let _retained = saturate_quota_user_locks();
    let stats = Arc::new(Stats::new());
    let user = "quota-waker-read-edge";

    let lock = quota_user_lock(user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold overflow lock before polling reader");

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

    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);
    let mut storage = [0u8; 1];

    for _ in 0..512 {
        let mut buf = ReadBuf::new(&mut storage);
        let poll = Pin::new(&mut io).poll_read(&mut cx, &mut buf);
        assert!(poll.is_pending());
        tokio::task::yield_now().await;
    }

    let wakes = wake_counter.wakes.load(Ordering::Relaxed);
    assert!(
        wakes <= 128,
        "pending reader retries must not trigger wake storm; observed wakes={wakes}"
    );

    drop(held_guard);
    let mut buf = ReadBuf::new(&mut storage);
    let ready = Pin::new(&mut io).poll_read(&mut cx, &mut buf);
    assert!(ready.is_ready());
}

#[tokio::test]
async fn light_fuzz_mixed_poll_schedule_under_contention_stays_bounded() {
    let _guard = quota_test_guard();

    let _retained = saturate_quota_user_locks();
    let stats = Arc::new(Stats::new());
    let user = "quota-waker-fuzz-user";

    let lock = quota_user_lock(user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold overflow lock before fuzz polling");

    let counters_w = Arc::new(SharedCounters::new());
    let mut writer_io = StatsIo::new(
        tokio::io::sink(),
        counters_w,
        Arc::clone(&stats),
        user.to_string(),
        Some(1024),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let counters_r = Arc::new(SharedCounters::new());
    let mut reader_io = StatsIo::new(
        tokio::io::empty(),
        counters_r,
        Arc::clone(&stats),
        user.to_string(),
        Some(1024),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);
    let mut seed = 0xBADC_0FFE_EE11_2211u64;
    let mut storage = [0u8; 1];

    for _ in 0..1024 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        if (seed & 1) == 0 {
            let poll = Pin::new(&mut writer_io).poll_write(&mut cx, &[0x44]);
            assert!(poll.is_pending());
        } else {
            let mut buf = ReadBuf::new(&mut storage);
            let poll = Pin::new(&mut reader_io).poll_read(&mut cx, &mut buf);
            assert!(poll.is_pending());
        }
        tokio::task::yield_now().await;
    }

    assert!(
        wake_counter.wakes.load(Ordering::Relaxed) <= 192,
        "mixed contention fuzz must keep deferred wake count tightly bounded"
    );

    drop(held_guard);
    let ready_w = Pin::new(&mut writer_io).poll_write(&mut cx, &[0x55]);
    assert!(ready_w.is_ready());

    let mut buf = ReadBuf::new(&mut storage);
    let ready_r = Pin::new(&mut reader_io).poll_read(&mut cx, &mut buf);
    assert!(ready_r.is_ready());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "red-team detector: reveals possible starvation if deferred wake fires before contention release"]
async fn stress_many_contended_writers_complete_after_release() {
    let _guard = quota_test_guard();

    let _retained = saturate_quota_user_locks();
    let user = "quota-waker-stress-user".to_string();
    let stats = Arc::new(Stats::new());

    let lock = quota_user_lock(&user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold overflow lock before launching contended tasks");

    let mut tasks = Vec::new();
    for _ in 0..32 {
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

            io.write_all(&[0xAA]).await
        }));
    }

    for _ in 0..8 {
        tokio::task::yield_now().await;
    }

    drop(held_guard);

    timeout(Duration::from_secs(2), async {
        for task in tasks {
            let result = task.await.expect("stress task must not panic");
            assert!(result.is_ok(), "task must complete after lock release");
        }
    })
    .await
    .expect("all contended writer tasks must finish in bounded time after release");
}
