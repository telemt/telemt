use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use crate::config::UserMaxUniqueIpsMode;
use crate::ip_tracker::UserIpTracker;

fn ip_from_idx(idx: u32) -> IpAddr {
    let a = 10u8;
    let b = ((idx / 65_536) % 256) as u8;
    let c = ((idx / 256) % 256) as u8;
    let d = (idx % 256) as u8;
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[tokio::test]
async fn active_window_enforces_large_unique_ip_burst() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("burst_user", 64).await;
    tracker
        .set_limit_policy(UserMaxUniqueIpsMode::ActiveWindow, 30)
        .await;

    for idx in 0..64 {
        assert!(
            tracker
                .check_and_add("burst_user", ip_from_idx(idx))
                .await
                .is_ok()
        );
    }
    assert!(
        tracker
            .check_and_add("burst_user", ip_from_idx(9_999))
            .await
            .is_err()
    );
    assert_eq!(tracker.get_active_ip_count("burst_user").await, 64);
}

#[tokio::test]
async fn global_limit_applies_across_many_users() {
    let tracker = UserIpTracker::new();
    tracker.load_limits(3, &HashMap::new()).await;

    for user_idx in 0..150u32 {
        let user = format!("u{}", user_idx);
        assert!(
            tracker
                .check_and_add(&user, ip_from_idx(user_idx * 10))
                .await
                .is_ok()
        );
        assert!(
            tracker
                .check_and_add(&user, ip_from_idx(user_idx * 10 + 1))
                .await
                .is_ok()
        );
        assert!(
            tracker
                .check_and_add(&user, ip_from_idx(user_idx * 10 + 2))
                .await
                .is_ok()
        );
        assert!(
            tracker
                .check_and_add(&user, ip_from_idx(user_idx * 10 + 3))
                .await
                .is_err()
        );
    }

    assert_eq!(tracker.get_stats().await.len(), 150);
}

#[tokio::test]
async fn user_zero_override_falls_back_to_global_limit() {
    let tracker = UserIpTracker::new();
    let mut limits = HashMap::new();
    limits.insert("target".to_string(), 0);
    tracker.load_limits(2, &limits).await;

    assert!(
        tracker
            .check_and_add("target", ip_from_idx(1))
            .await
            .is_ok()
    );
    assert!(
        tracker
            .check_and_add("target", ip_from_idx(2))
            .await
            .is_ok()
    );
    assert!(
        tracker
            .check_and_add("target", ip_from_idx(3))
            .await
            .is_err()
    );
    assert_eq!(tracker.get_user_limit("target").await, Some(2));
}

#[tokio::test]
async fn remove_ip_is_idempotent_after_counter_reaches_zero() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("u", 2).await;
    let ip = ip_from_idx(42);

    tracker.check_and_add("u", ip).await.unwrap();
    tracker.remove_ip("u", ip).await;
    tracker.remove_ip("u", ip).await;
    tracker.remove_ip("u", ip).await;

    assert_eq!(tracker.get_active_ip_count("u").await, 0);
    assert!(!tracker.is_ip_active("u", ip).await);
}

#[tokio::test]
async fn clear_user_ips_resets_active_and_recent() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("u", 10).await;

    for idx in 0..6 {
        tracker.check_and_add("u", ip_from_idx(idx)).await.unwrap();
    }

    tracker.clear_user_ips("u").await;

    assert_eq!(tracker.get_active_ip_count("u").await, 0);
    let counts = tracker
        .get_recent_counts_for_users(&["u".to_string()])
        .await;
    assert_eq!(counts.get("u").copied().unwrap_or(0), 0);
}

#[tokio::test]
async fn clear_all_resets_multi_user_state() {
    let tracker = UserIpTracker::new();

    for user_idx in 0..80u32 {
        let user = format!("u{}", user_idx);
        for ip_idx in 0..3 {
            tracker
                .check_and_add(&user, ip_from_idx(user_idx * 100 + ip_idx))
                .await
                .unwrap();
        }
    }

    tracker.clear_all().await;

    assert!(tracker.get_stats().await.is_empty());
    let users = (0..80u32)
        .map(|idx| format!("u{}", idx))
        .collect::<Vec<_>>();
    let recent = tracker.get_recent_counts_for_users(&users).await;
    assert!(recent.values().all(|count| *count == 0));
}

#[tokio::test]
async fn get_active_ips_for_users_are_sorted() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("user", 10).await;

    tracker
        .check_and_add("user", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)))
        .await
        .unwrap();
    tracker
        .check_and_add("user", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        .await
        .unwrap();
    tracker
        .check_and_add("user", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))
        .await
        .unwrap();

    let map = tracker
        .get_active_ips_for_users(&["user".to_string()])
        .await;
    let ips = map.get("user").cloned().unwrap_or_default();

    assert_eq!(
        ips,
        vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
        ]
    );
}

#[tokio::test]
async fn get_recent_ips_for_users_are_sorted() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("user", 10).await;

    tracker
        .check_and_add("user", IpAddr::V4(Ipv4Addr::new(10, 1, 0, 9)))
        .await
        .unwrap();
    tracker
        .check_and_add("user", IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)))
        .await
        .unwrap();
    tracker
        .check_and_add("user", IpAddr::V4(Ipv4Addr::new(10, 1, 0, 5)))
        .await
        .unwrap();

    let map = tracker
        .get_recent_ips_for_users(&["user".to_string()])
        .await;
    let ips = map.get("user").cloned().unwrap_or_default();

    assert_eq!(
        ips,
        vec![
            IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 1, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 1, 0, 9)),
        ]
    );
}

#[tokio::test]
async fn time_window_expires_for_large_rotation() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("tw", 1).await;
    tracker
        .set_limit_policy(UserMaxUniqueIpsMode::TimeWindow, 1)
        .await;

    tracker.check_and_add("tw", ip_from_idx(1)).await.unwrap();
    tracker.remove_ip("tw", ip_from_idx(1)).await;
    assert!(tracker.check_and_add("tw", ip_from_idx(2)).await.is_err());

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert!(tracker.check_and_add("tw", ip_from_idx(2)).await.is_ok());
}

#[tokio::test]
async fn combined_mode_blocks_recent_after_disconnect() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("cmb", 1).await;
    tracker
        .set_limit_policy(UserMaxUniqueIpsMode::Combined, 2)
        .await;

    tracker.check_and_add("cmb", ip_from_idx(11)).await.unwrap();
    tracker.remove_ip("cmb", ip_from_idx(11)).await;

    assert!(tracker.check_and_add("cmb", ip_from_idx(12)).await.is_err());
}

#[tokio::test]
async fn load_limits_replaces_large_limit_map() {
    let tracker = UserIpTracker::new();
    let mut first = HashMap::new();
    let mut second = HashMap::new();

    for idx in 0..300usize {
        first.insert(format!("u{}", idx), 2usize);
    }
    for idx in 150..450usize {
        second.insert(format!("u{}", idx), 4usize);
    }

    tracker.load_limits(0, &first).await;
    tracker.load_limits(0, &second).await;

    assert_eq!(tracker.get_user_limit("u20").await, None);
    assert_eq!(tracker.get_user_limit("u200").await, Some(4));
    assert_eq!(tracker.get_user_limit("u420").await, Some(4));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_same_user_unique_ip_pressure_stays_bounded() {
    let tracker = Arc::new(UserIpTracker::new());
    tracker.set_user_limit("hot", 32).await;
    tracker
        .set_limit_policy(UserMaxUniqueIpsMode::ActiveWindow, 30)
        .await;

    let mut handles = Vec::new();
    for worker in 0..16u32 {
        let tracker_cloned = tracker.clone();
        handles.push(tokio::spawn(async move {
            let base = worker * 200;
            for step in 0..200u32 {
                let _ = tracker_cloned
                    .check_and_add("hot", ip_from_idx(base + step))
                    .await;
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    assert!(tracker.get_active_ip_count("hot").await <= 32);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_many_users_isolate_limits() {
    let tracker = Arc::new(UserIpTracker::new());
    tracker.load_limits(4, &HashMap::new()).await;

    let mut handles = Vec::new();
    for user_idx in 0..120u32 {
        let tracker_cloned = tracker.clone();
        handles.push(tokio::spawn(async move {
            let user = format!("u{}", user_idx);
            for ip_idx in 0..10u32 {
                let _ = tracker_cloned
                    .check_and_add(&user, ip_from_idx(user_idx * 1_000 + ip_idx))
                    .await;
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let stats = tracker.get_stats().await;
    assert_eq!(stats.len(), 120);
    assert!(
        stats
            .iter()
            .all(|(_, active, limit)| *active <= 4 && *limit == 4)
    );
}

#[tokio::test]
async fn same_ip_reconnect_high_frequency_keeps_single_unique() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("same", 2).await;
    let ip = ip_from_idx(9);

    for _ in 0..2_000 {
        tracker.check_and_add("same", ip).await.unwrap();
    }

    assert_eq!(tracker.get_active_ip_count("same").await, 1);
    assert!(tracker.is_ip_active("same", ip).await);
}

#[tokio::test]
async fn format_stats_contains_expected_limited_and_unlimited_markers() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("limited", 2).await;
    tracker
        .check_and_add("limited", ip_from_idx(1))
        .await
        .unwrap();
    tracker.check_and_add("open", ip_from_idx(2)).await.unwrap();

    let text = tracker.format_stats().await;

    assert!(text.contains("limited"));
    assert!(text.contains("open"));
    assert!(text.contains("unlimited"));
}

#[tokio::test]
async fn stats_report_global_default_for_users_without_override() {
    let tracker = UserIpTracker::new();
    tracker.load_limits(5, &HashMap::new()).await;

    tracker.check_and_add("a", ip_from_idx(1)).await.unwrap();
    tracker.check_and_add("b", ip_from_idx(2)).await.unwrap();

    let stats = tracker.get_stats().await;
    assert!(
        stats
            .iter()
            .any(|(user, _, limit)| user == "a" && *limit == 5)
    );
    assert!(
        stats
            .iter()
            .any(|(user, _, limit)| user == "b" && *limit == 5)
    );
}

#[tokio::test]
async fn stress_cycle_add_remove_clear_preserves_empty_end_state() {
    let tracker = UserIpTracker::new();

    for cycle in 0..50u32 {
        let user = format!("cycle{}", cycle);
        tracker.set_user_limit(&user, 128).await;

        for ip_idx in 0..128u32 {
            tracker
                .check_and_add(&user, ip_from_idx(cycle * 10_000 + ip_idx))
                .await
                .unwrap();
        }

        for ip_idx in 0..128u32 {
            tracker
                .remove_ip(&user, ip_from_idx(cycle * 10_000 + ip_idx))
                .await;
        }

        tracker.clear_user_ips(&user).await;
    }

    assert!(tracker.get_stats().await.is_empty());
}

#[tokio::test]
async fn remove_unknown_user_or_ip_does_not_corrupt_state() {
    let tracker = UserIpTracker::new();

    tracker.remove_ip("no_user", ip_from_idx(1)).await;
    tracker.check_and_add("x", ip_from_idx(2)).await.unwrap();
    tracker.remove_ip("x", ip_from_idx(3)).await;

    assert_eq!(tracker.get_active_ip_count("x").await, 1);
    assert!(tracker.is_ip_active("x", ip_from_idx(2)).await);
}

#[tokio::test]
async fn active_and_recent_views_match_after_mixed_workload() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("mix", 16).await;

    for ip_idx in 0..12u32 {
        tracker
            .check_and_add("mix", ip_from_idx(ip_idx))
            .await
            .unwrap();
    }
    for ip_idx in 0..6u32 {
        tracker.remove_ip("mix", ip_from_idx(ip_idx)).await;
    }

    let active = tracker
        .get_active_ips_for_users(&["mix".to_string()])
        .await
        .get("mix")
        .cloned()
        .unwrap_or_default();
    let recent_count = tracker
        .get_recent_counts_for_users(&["mix".to_string()])
        .await
        .get("mix")
        .copied()
        .unwrap_or(0);

    assert_eq!(active.len(), 6);
    assert!(recent_count >= active.len());
    assert!(recent_count <= 12);
}

#[tokio::test]
async fn global_limit_switch_updates_enforcement_immediately() {
    let tracker = UserIpTracker::new();
    tracker.load_limits(2, &HashMap::new()).await;

    assert!(tracker.check_and_add("u", ip_from_idx(1)).await.is_ok());
    assert!(tracker.check_and_add("u", ip_from_idx(2)).await.is_ok());
    assert!(tracker.check_and_add("u", ip_from_idx(3)).await.is_err());

    tracker.clear_user_ips("u").await;
    tracker.load_limits(4, &HashMap::new()).await;

    assert!(tracker.check_and_add("u", ip_from_idx(1)).await.is_ok());
    assert!(tracker.check_and_add("u", ip_from_idx(2)).await.is_ok());
    assert!(tracker.check_and_add("u", ip_from_idx(3)).await.is_ok());
    assert!(tracker.check_and_add("u", ip_from_idx(4)).await.is_ok());
    assert!(tracker.check_and_add("u", ip_from_idx(5)).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reconnect_and_disconnect_preserves_non_negative_counts() {
    let tracker = Arc::new(UserIpTracker::new());
    tracker.set_user_limit("cc", 8).await;

    let mut handles = Vec::new();
    for worker in 0..8u32 {
        let tracker_cloned = tracker.clone();
        handles.push(tokio::spawn(async move {
            let ip = ip_from_idx(50 + worker);
            for _ in 0..500u32 {
                let _ = tracker_cloned.check_and_add("cc", ip).await;
                tracker_cloned.remove_ip("cc", ip).await;
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    assert!(tracker.get_active_ip_count("cc").await <= 8);
}

#[tokio::test]
async fn enqueue_cleanup_recovers_from_poisoned_mutex() {
    let tracker = UserIpTracker::new();
    let ip = ip_from_idx(99);

    // Poison the lock by panicking while holding it
    let cleanup_queue = tracker.cleanup_queue_mutex_for_tests();
    let result = std::panic::catch_unwind(move || {
        let _guard = cleanup_queue.lock().unwrap();
        panic!("Intentional poison panic");
    });
    assert!(result.is_err(), "Expected panic to poison mutex");

    // Attempt to enqueue anyway; should hit the poison catch arm and still insert
    tracker.enqueue_cleanup("poison-user".to_string(), ip);

    tracker.drain_cleanup_queue().await;

    assert_eq!(tracker.get_active_ip_count("poison-user").await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mass_reconnect_sync_cleanup_prevents_temporary_reservation_bloat() {
    // Tests that synchronous M-01 drop mechanism protects against starvation
    let tracker = Arc::new(UserIpTracker::new());
    tracker.set_user_limit("mass", 5).await;

    let ip = ip_from_idx(42);
    let mut join_handles = Vec::new();

    // 10,000 rapid concurrent requests hitting the same IP limit
    for _ in 0..10_000 {
        let tracker_clone = tracker.clone();
        join_handles.push(tokio::spawn(async move {
            if tracker_clone.check_and_add("mass", ip).await.is_ok() {
                // Instantly enqueue cleanup, simulating synchronous reservation drop
                tracker_clone.enqueue_cleanup("mass".to_string(), ip);
                // The next caller will drain it before acquiring again
            }
        }));
    }

    for handle in join_handles {
        let _ = handle.await;
    }

    // Force flush
    tracker.drain_cleanup_queue().await;
    assert_eq!(
        tracker.get_active_ip_count("mass").await,
        0,
        "No leaked footprints"
    );
}

#[tokio::test]
async fn adversarial_drain_cleanup_queue_race_does_not_deadlock_or_exceed_limit() {
    let tracker = Arc::new(UserIpTracker::new());
    tracker.set_user_limit("racer", 1).await;
    let ip1 = ip_from_idx(1);
    let ip2 = ip_from_idx(2);

    // Initial state: add ip1
    tracker.check_and_add("racer", ip1).await.unwrap();

    // User disconnects from ip1, queuing it
    tracker.enqueue_cleanup("racer".to_string(), ip1);

    for _ in 0..100 {
        // Queue cleanup then race explicit drain and check-and-add on the alternative IP.
        tracker.enqueue_cleanup("racer".to_string(), ip1);
        let tracker_a = tracker.clone();
        let tracker_b = tracker.clone();

        let drain_handle = tokio::spawn(async move {
            tracker_a.drain_cleanup_queue().await;
        });
        let handle = tokio::spawn(async move { tracker_b.check_and_add("racer", ip2).await });

        tokio::time::timeout(Duration::from_secs(1), drain_handle)
            .await
            .expect("cleanup drain must not deadlock")
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("admission must not deadlock")
            .unwrap();

        assert!(tracker.get_active_ip_count("racer").await <= 1);
        tracker.drain_cleanup_queue().await;
        tracker.remove_ip("racer", ip2).await;
        tracker.remove_ip("racer", ip1).await;
        tracker.check_and_add("racer", ip1).await.unwrap();
    }
}

#[tokio::test]
async fn poisoned_cleanup_queue_still_releases_slot_for_next_ip() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("poison-slot", 1).await;
    let ip1 = ip_from_idx(7001);
    let ip2 = ip_from_idx(7002);

    tracker.check_and_add("poison-slot", ip1).await.unwrap();

    // Poison the queue lock as an adversarial condition.
    let cleanup_queue = tracker.cleanup_queue_mutex_for_tests();
    let _ = std::panic::catch_unwind(move || {
        let _guard = cleanup_queue.lock().unwrap();
        panic!("intentional queue poison");
    });

    // Disconnect path must still queue cleanup so the next IP can be admitted.
    tracker.enqueue_cleanup("poison-slot".to_string(), ip1);
    let admitted = tracker.check_and_add("poison-slot", ip2).await;
    assert!(
        admitted.is_ok(),
        "cleanup queue poison must not permanently block slot release for the next IP"
    );
}

#[tokio::test]
async fn duplicate_cleanup_entries_do_not_break_future_admission() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("dup-cleanup", 1).await;
    let ip1 = ip_from_idx(7101);
    let ip2 = ip_from_idx(7102);

    tracker.check_and_add("dup-cleanup", ip1).await.unwrap();
    tracker.enqueue_cleanup("dup-cleanup".to_string(), ip1);
    tracker.enqueue_cleanup("dup-cleanup".to_string(), ip1);
    tracker.enqueue_cleanup("dup-cleanup".to_string(), ip1);

    tracker.drain_cleanup_queue().await;

    assert_eq!(tracker.get_active_ip_count("dup-cleanup").await, 0);
    assert!(
        tracker.check_and_add("dup-cleanup", ip2).await.is_ok(),
        "extra queued cleanup entries must not leave user stuck in denied state"
    );
}

#[tokio::test]
async fn duplicate_cleanup_entries_are_coalesced_until_drain() {
    let tracker = UserIpTracker::new();
    let ip = ip_from_idx(7150);

    tracker.enqueue_cleanup("coalesced-cleanup".to_string(), ip);
    tracker.enqueue_cleanup("coalesced-cleanup".to_string(), ip);
    tracker.enqueue_cleanup("coalesced-cleanup".to_string(), ip);

    assert_eq!(
        tracker.cleanup_queue_len_for_tests(),
        1,
        "duplicate queued cleanup entries must retain one allocation slot"
    );

    tracker.drain_cleanup_queue().await;
    assert_eq!(tracker.cleanup_queue_len_for_tests(), 0);
}

#[tokio::test]
async fn stress_repeated_queue_poison_recovery_preserves_admission_progress() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("poison-stress", 1).await;
    let ip_primary = ip_from_idx(7201);
    let ip_alt = ip_from_idx(7202);

    tracker
        .check_and_add("poison-stress", ip_primary)
        .await
        .unwrap();

    for _ in 0..64 {
        let cleanup_queue = tracker.cleanup_queue_mutex_for_tests();
        let _ = std::panic::catch_unwind(move || {
            let _guard = cleanup_queue.lock().unwrap();
            panic!("intentional queue poison in stress loop");
        });

        tracker.enqueue_cleanup("poison-stress".to_string(), ip_primary);

        assert!(
            tracker.check_and_add("poison-stress", ip_alt).await.is_ok(),
            "poison recovery must preserve admission progress under repeated queue poisoning"
        );

        tracker.remove_ip("poison-stress", ip_alt).await;
        tracker
            .check_and_add("poison-stress", ip_primary)
            .await
            .unwrap();
    }
}
