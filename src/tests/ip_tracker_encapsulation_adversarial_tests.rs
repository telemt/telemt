use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use crate::ip_tracker::UserIpTracker;

fn ip_from_idx(idx: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(
        172,
        ((idx >> 16) & 0xff) as u8,
        ((idx >> 8) & 0xff) as u8,
        (idx & 0xff) as u8,
    ))
}

#[tokio::test]
async fn encapsulation_queue_len_helper_matches_enqueue_and_drain_lifecycle() {
    let tracker = UserIpTracker::new();
    let user = "encap-len-user";

    for idx in 0..32 {
        tracker.enqueue_cleanup(user.to_string(), ip_from_idx(idx));
    }

    assert_eq!(
        tracker.cleanup_queue_len_for_tests(),
        32,
        "test helper must reflect queued cleanup entries before drain"
    );

    tracker.drain_cleanup_queue().await;

    assert_eq!(
        tracker.cleanup_queue_len_for_tests(),
        0,
        "cleanup queue must be empty after drain"
    );
}

#[tokio::test]
async fn encapsulation_repeated_queue_poison_recovery_preserves_forward_progress() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("encap-poison", 1).await;

    let ip_primary = ip_from_idx(10_001);
    let ip_alt = ip_from_idx(10_002);

    tracker
        .check_and_add("encap-poison", ip_primary)
        .await
        .unwrap();

    for _ in 0..128 {
        let queue = tracker.cleanup_queue_mutex_for_tests();
        let _ = std::panic::catch_unwind(move || {
            let _guard = queue.lock().unwrap();
            panic!("intentional cleanup queue poison in encapsulation regression test");
        });

        tracker.enqueue_cleanup("encap-poison".to_string(), ip_primary);

        assert!(
            tracker.check_and_add("encap-poison", ip_alt).await.is_ok(),
            "poison recovery must not block admission progress"
        );

        tracker.remove_ip("encap-poison", ip_alt).await;
        tracker
            .check_and_add("encap-poison", ip_primary)
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn encapsulation_parallel_poison_and_churn_maintains_queue_and_limit_invariants() {
    let tracker = Arc::new(UserIpTracker::new());
    tracker.set_user_limit("encap-stress", 4).await;

    let mut tasks = Vec::new();
    for worker in 0..32u32 {
        let t = tracker.clone();
        tasks.push(tokio::spawn(async move {
            let user = "encap-stress";
            let ip = ip_from_idx(20_000 + worker);

            for iter in 0..64u32 {
                let _ = t.check_and_add(user, ip).await;
                t.enqueue_cleanup(user.to_string(), ip);

                if iter % 3 == 0 {
                    let queue = t.cleanup_queue_mutex_for_tests();
                    let _ = std::panic::catch_unwind(move || {
                        let _guard = queue.lock().unwrap();
                        panic!("intentional lock poison during parallel stress");
                    });
                }

                t.drain_cleanup_queue().await;
            }
        }));
    }

    for task in tasks {
        task.await.expect("stress worker must not panic");
    }

    tracker.drain_cleanup_queue().await;
    assert_eq!(
        tracker.cleanup_queue_len_for_tests(),
        0,
        "queue must converge to empty after stress drain"
    );
    assert!(
        tracker.get_active_ip_count("encap-stress").await <= 4,
        "active unique IP count must remain bounded by configured limit"
    );
}
