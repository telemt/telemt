use super::*;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Barrier;

#[test]
fn direct_connection_lease_balances_on_drop() {
    let stats = Arc::new(Stats::new());
    assert_eq!(stats.get_current_connections_direct(), 0);

    {
        let _lease = stats.acquire_direct_connection_lease();
        assert_eq!(stats.get_current_connections_direct(), 1);
    }

    assert_eq!(stats.get_current_connections_direct(), 0);
}

#[test]
fn middle_connection_lease_balances_on_drop() {
    let stats = Arc::new(Stats::new());
    assert_eq!(stats.get_current_connections_me(), 0);

    {
        let _lease = stats.acquire_me_connection_lease();
        assert_eq!(stats.get_current_connections_me(), 1);
    }

    assert_eq!(stats.get_current_connections_me(), 0);
}

#[test]
fn connection_lease_disarm_prevents_double_release() {
    let stats = Arc::new(Stats::new());

    let mut lease = stats.acquire_direct_connection_lease();
    assert_eq!(stats.get_current_connections_direct(), 1);

    stats.decrement_current_connections_direct();
    assert_eq!(stats.get_current_connections_direct(), 0);

    lease.disarm();
    drop(lease);

    assert_eq!(stats.get_current_connections_direct(), 0);
}

#[test]
fn direct_connection_lease_balances_on_panic_unwind() {
    let stats = Arc::new(Stats::new());
    let stats_for_panic = stats.clone();

    let panic_result = panic::catch_unwind(AssertUnwindSafe(move || {
        let _lease = stats_for_panic.acquire_direct_connection_lease();
        panic!("intentional panic to verify lease drop path");
    }));

    assert!(
        panic_result.is_err(),
        "panic must propagate from test closure"
    );
    assert_eq!(
        stats.get_current_connections_direct(),
        0,
        "panic unwind must release direct route gauge"
    );
}

#[test]
fn middle_connection_lease_balances_on_panic_unwind() {
    let stats = Arc::new(Stats::new());
    let stats_for_panic = stats.clone();

    let panic_result = panic::catch_unwind(AssertUnwindSafe(move || {
        let _lease = stats_for_panic.acquire_me_connection_lease();
        panic!("intentional panic to verify middle lease drop path");
    }));

    assert!(
        panic_result.is_err(),
        "panic must propagate from test closure"
    );
    assert_eq!(
        stats.get_current_connections_me(),
        0,
        "panic unwind must release middle route gauge"
    );
}

#[tokio::test]
async fn concurrent_mixed_route_lease_churn_balances_to_zero() {
    const TASKS: usize = 48;
    const ITERATIONS_PER_TASK: usize = 256;

    let stats = Arc::new(Stats::new());
    let barrier = Arc::new(Barrier::new(TASKS));
    let mut workers = Vec::with_capacity(TASKS);

    for task_idx in 0..TASKS {
        let stats_for_task = stats.clone();
        let barrier_for_task = barrier.clone();
        workers.push(tokio::spawn(async move {
            barrier_for_task.wait().await;
            for iter in 0..ITERATIONS_PER_TASK {
                if (task_idx + iter) % 2 == 0 {
                    let _lease = stats_for_task.acquire_direct_connection_lease();
                    tokio::task::yield_now().await;
                } else {
                    let _lease = stats_for_task.acquire_me_connection_lease();
                    tokio::task::yield_now().await;
                }
            }
        }));
    }

    for worker in workers {
        worker.await.expect("lease churn worker must not panic");
    }

    assert_eq!(
        stats.get_current_connections_direct(),
        0,
        "direct route gauge must return to zero after concurrent lease churn"
    );
    assert_eq!(
        stats.get_current_connections_me(),
        0,
        "middle route gauge must return to zero after concurrent lease churn"
    );
}

#[tokio::test]
async fn abort_storm_mixed_route_leases_returns_all_gauges_to_zero() {
    const TASKS: usize = 64;

    let stats = Arc::new(Stats::new());
    let mut workers = Vec::with_capacity(TASKS);

    for task_idx in 0..TASKS {
        let stats_for_task = stats.clone();
        workers.push(tokio::spawn(async move {
            if task_idx % 2 == 0 {
                let _lease = stats_for_task.acquire_direct_connection_lease();
                tokio::time::sleep(Duration::from_secs(60)).await;
            } else {
                let _lease = stats_for_task.acquire_me_connection_lease();
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        }));
    }

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let total = stats.get_current_connections_direct() + stats.get_current_connections_me();
            if total == TASKS as u64 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("all storm tasks must acquire route leases before abort");

    for worker in &workers {
        worker.abort();
    }
    for worker in workers {
        let joined = worker.await;
        assert!(joined.is_err(), "aborted worker must return join error");
    }

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if stats.get_current_connections_direct() == 0
                && stats.get_current_connections_me() == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("all route gauges must drain to zero after abort storm");
}

#[test]
fn saturating_route_decrements_do_not_underflow_under_race() {
    const THREADS: usize = 16;
    const DECREMENTS_PER_THREAD: usize = 4096;

    let stats = Arc::new(Stats::new());
    let mut workers = Vec::with_capacity(THREADS);

    for _ in 0..THREADS {
        let stats_for_thread = stats.clone();
        workers.push(std::thread::spawn(move || {
            for _ in 0..DECREMENTS_PER_THREAD {
                stats_for_thread.decrement_current_connections_direct();
                stats_for_thread.decrement_current_connections_me();
            }
        }));
    }

    for worker in workers {
        worker.join().expect("decrement race worker must not panic");
    }

    assert_eq!(
        stats.get_current_connections_direct(),
        0,
        "direct route decrement races must never underflow"
    );
    assert_eq!(
        stats.get_current_connections_me(),
        0,
        "middle route decrement races must never underflow"
    );
}

#[tokio::test]
async fn direct_connection_lease_balances_on_task_abort() {
    let stats = Arc::new(Stats::new());
    let stats_for_task = stats.clone();

    let task = tokio::spawn(async move {
        let _lease = stats_for_task.acquire_direct_connection_lease();
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(stats.get_current_connections_direct(), 1);

    task.abort();
    let joined = task.await;
    assert!(joined.is_err(), "aborted task must return a join error");

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        stats.get_current_connections_direct(),
        0,
        "aborted task must release direct route gauge"
    );
}

#[tokio::test]
async fn middle_connection_lease_balances_on_task_abort() {
    let stats = Arc::new(Stats::new());
    let stats_for_task = stats.clone();

    let task = tokio::spawn(async move {
        let _lease = stats_for_task.acquire_me_connection_lease();
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(stats.get_current_connections_me(), 1);

    task.abort();
    let joined = task.await;
    assert!(joined.is_err(), "aborted task must return a join error");

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        stats.get_current_connections_me(),
        0,
        "aborted task must release middle route gauge"
    );
}
