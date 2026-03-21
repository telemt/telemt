use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use crate::config::UserMaxUniqueIpsMode;
use crate::ip_tracker::UserIpTracker;

fn ip_from_idx(idx: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, ((idx >> 16) & 0xff) as u8, ((idx >> 8) & 0xff) as u8, (idx & 0xff) as u8))
}

#[tokio::test]
async fn hotpath_empty_drain_is_idempotent() {
    let tracker = UserIpTracker::new();
    for _ in 0..128 {
        tracker.drain_cleanup_queue().await;
    }
    assert_eq!(tracker.get_active_ip_count("none").await, 0);
}

#[tokio::test]
async fn hotpath_batch_cleanup_drain_clears_all_active_entries() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("u", 100).await;

    for idx in 0..32 {
        let ip = ip_from_idx(idx);
        tracker.check_and_add("u", ip).await.unwrap();
        tracker.enqueue_cleanup("u".to_string(), ip);
    }

    tracker.drain_cleanup_queue().await;
    assert_eq!(tracker.get_active_ip_count("u").await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hotpath_parallel_enqueue_and_drain_does_not_deadlock() {
    let tracker = Arc::new(UserIpTracker::new());
    tracker.set_user_limit("p", 64).await;

    let mut tasks = Vec::new();
    for worker in 0..32u32 {
        let t = tracker.clone();
        tasks.push(tokio::spawn(async move {
            let ip = ip_from_idx(1_000 + worker);
            for _ in 0..64 {
                let _ = t.check_and_add("p", ip).await;
                t.enqueue_cleanup("p".to_string(), ip);
                t.drain_cleanup_queue().await;
            }
        }));
    }

    for task in tasks {
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .expect("worker must not deadlock")
            .expect("worker task must not panic");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hotpath_parallel_unique_ip_limit_never_exceeds_cap() {
    let tracker = Arc::new(UserIpTracker::new());
    tracker.set_user_limit("limit", 5).await;

    let mut tasks = Vec::new();
    for idx in 0..64u32 {
        let t = tracker.clone();
        tasks.push(tokio::spawn(async move { t.check_and_add("limit", ip_from_idx(idx)).await.is_ok() }));
    }

    let mut admitted = 0usize;
    for task in tasks {
        if task.await.expect("task must not panic") {
            admitted += 1;
        }
    }

    assert!(admitted <= 5, "admitted unique IPs must not exceed configured cap");
    assert!(tracker.get_active_ip_count("limit").await <= 5);
}

#[tokio::test]
async fn hotpath_repeated_same_ip_counter_balances_to_zero() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("same", 1).await;
    let ip = ip_from_idx(77);

    for _ in 0..512 {
        tracker.check_and_add("same", ip).await.unwrap();
    }
    for _ in 0..512 {
        tracker.remove_ip("same", ip).await;
    }

    assert_eq!(tracker.get_active_ip_count("same").await, 0);
}

#[tokio::test]
async fn hotpath_light_fuzz_mixed_operations_preserve_limit_invariants() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("fuzz", 4).await;

    let mut state: u64 = 0xA55A_5AA5_D15C_B00B;
    for _ in 0..4_000 {
        state ^= state << 7;
        state ^= state >> 9;
        state ^= state << 8;

        let ip = ip_from_idx((state as u32) % 8);
        match state & 0x3 {
            0 | 1 => {
                let _ = tracker.check_and_add("fuzz", ip).await;
            }
            _ => {
                tracker.remove_ip("fuzz", ip).await;
            }
        }

        assert!(
            tracker.get_active_ip_count("fuzz").await <= 4,
            "active count must stay within configured cap"
        );
    }
}

#[tokio::test]
async fn hotpath_multi_user_churn_keeps_isolation() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("u1", 2).await;
    tracker.set_user_limit("u2", 3).await;

    for idx in 0..200u32 {
        let ip1 = ip_from_idx(idx % 5);
        let ip2 = ip_from_idx(100 + (idx % 7));
        let _ = tracker.check_and_add("u1", ip1).await;
        let _ = tracker.check_and_add("u2", ip2).await;
        if idx % 2 == 0 {
            tracker.remove_ip("u1", ip1).await;
        }
        if idx % 3 == 0 {
            tracker.remove_ip("u2", ip2).await;
        }
    }

    assert!(tracker.get_active_ip_count("u1").await <= 2);
    assert!(tracker.get_active_ip_count("u2").await <= 3);
}

#[tokio::test]
async fn hotpath_time_window_expiry_allows_new_ip_after_window() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("tw", 1).await;
    tracker
        .set_limit_policy(UserMaxUniqueIpsMode::TimeWindow, 1)
        .await;

    let ip1 = ip_from_idx(901);
    let ip2 = ip_from_idx(902);

    tracker.check_and_add("tw", ip1).await.unwrap();
    tracker.remove_ip("tw", ip1).await;
    assert!(tracker.check_and_add("tw", ip2).await.is_err());

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert!(tracker.check_and_add("tw", ip2).await.is_ok());
}
