use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;

struct DropSignal(Arc<Notify>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

#[tokio::test]
async fn scoped_supervisor_aborts_its_current_child() {
    let scope = RuntimeTaskScope::new();
    let dropped = Arc::new(Notify::new());
    let dropped_for_task = dropped.clone();
    scope.spawn(supervise_me_task("test", move || {
        let dropped = dropped_for_task.clone();
        async move {
            let _signal = DropSignal(dropped);
            std::future::pending::<()>().await;
        }
    }));
    tokio::task::yield_now().await;

    scope.stop().await;

    tokio::time::timeout(Duration::from_secs(1), dropped.notified())
        .await
        .unwrap();
}

#[tokio::test]
async fn supervisor_restarts_exited_child_and_stops_with_runtime_scope() {
    let scope = RuntimeTaskScope::new();
    let starts = Arc::new(AtomicUsize::new(0));
    let restarted = Arc::new(Notify::new());
    let starts_task = starts.clone();
    let restarted_task = restarted.clone();
    scope.spawn(supervise_me_task("restart_test", move || {
        let starts = starts_task.clone();
        let restarted = restarted_task.clone();
        async move {
            if starts.fetch_add(1, Ordering::AcqRel) + 1 >= 3 {
                restarted.notify_one();
            }
        }
    }));

    tokio::time::timeout(Duration::from_secs(1), restarted.notified())
        .await
        .unwrap();
    scope.stop().await;
    let stopped_at = starts.load(Ordering::Acquire);
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }

    assert!(stopped_at >= 3);
    assert_eq!(starts.load(Ordering::Acquire), stopped_at);
}
