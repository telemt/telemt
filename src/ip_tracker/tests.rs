use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

fn test_ipv4(oct1: u8, oct2: u8, oct3: u8, oct4: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(oct1, oct2, oct3, oct4))
}

fn test_ipv6() -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
}

#[tokio::test]
async fn test_basic_ip_limit() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("test_user", 2).await;

    let ip1 = test_ipv4(192, 168, 1, 1);
    let ip2 = test_ipv4(192, 168, 1, 2);
    let ip3 = test_ipv4(192, 168, 1, 3);

    assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
    assert!(tracker.check_and_add("test_user", ip2).await.is_ok());
    assert!(tracker.check_and_add("test_user", ip3).await.is_err());

    assert_eq!(tracker.get_active_ip_count("test_user").await, 2);
}

#[tokio::test]
async fn test_active_window_rejects_new_ip_and_keeps_existing_session() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("test_user", 1).await;
    tracker
        .set_limit_policy(UserMaxUniqueIpsMode::ActiveWindow, 30)
        .await;

    let ip1 = test_ipv4(10, 10, 10, 1);
    let ip2 = test_ipv4(10, 10, 10, 2);

    assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
    assert!(tracker.is_ip_active("test_user", ip1).await);
    assert!(tracker.check_and_add("test_user", ip2).await.is_err());

    // Existing session remains active; only new unique IP is denied.
    assert!(tracker.is_ip_active("test_user", ip1).await);
    assert_eq!(tracker.get_active_ip_count("test_user").await, 1);
}

#[tokio::test]
async fn test_reconnection_from_same_ip() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("test_user", 2).await;

    let ip1 = test_ipv4(192, 168, 1, 1);

    assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
    assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
    assert_eq!(tracker.get_active_ip_count("test_user").await, 1);
}

#[tokio::test]
async fn test_same_ip_disconnect_keeps_active_while_other_session_alive() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("test_user", 2).await;

    let ip1 = test_ipv4(192, 168, 1, 1);

    assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
    assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
    assert_eq!(tracker.get_active_ip_count("test_user").await, 1);

    tracker.remove_ip("test_user", ip1).await;
    assert_eq!(tracker.get_active_ip_count("test_user").await, 1);

    tracker.remove_ip("test_user", ip1).await;
    assert_eq!(tracker.get_active_ip_count("test_user").await, 0);
}

#[tokio::test]
async fn test_ip_removal() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("test_user", 2).await;

    let ip1 = test_ipv4(192, 168, 1, 1);
    let ip2 = test_ipv4(192, 168, 1, 2);
    let ip3 = test_ipv4(192, 168, 1, 3);

    assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
    assert!(tracker.check_and_add("test_user", ip2).await.is_ok());
    assert!(tracker.check_and_add("test_user", ip3).await.is_err());

    tracker.remove_ip("test_user", ip1).await;

    assert!(tracker.check_and_add("test_user", ip3).await.is_ok());
    assert_eq!(tracker.get_active_ip_count("test_user").await, 2);
}

#[tokio::test]
async fn test_no_limit() {
    let tracker = UserIpTracker::new();

    let ip1 = test_ipv4(192, 168, 1, 1);
    let ip2 = test_ipv4(192, 168, 1, 2);
    let ip3 = test_ipv4(192, 168, 1, 3);

    assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
    assert!(tracker.check_and_add("test_user", ip2).await.is_ok());
    assert!(tracker.check_and_add("test_user", ip3).await.is_ok());

    assert_eq!(tracker.get_active_ip_count("test_user").await, 3);
}

#[tokio::test]
async fn test_multiple_users() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("user1", 2).await;
    tracker.set_user_limit("user2", 1).await;

    let ip1 = test_ipv4(192, 168, 1, 1);
    let ip2 = test_ipv4(192, 168, 1, 2);

    assert!(tracker.check_and_add("user1", ip1).await.is_ok());
    assert!(tracker.check_and_add("user1", ip2).await.is_ok());

    assert!(tracker.check_and_add("user2", ip1).await.is_ok());
    assert!(tracker.check_and_add("user2", ip2).await.is_err());
}

#[tokio::test]
async fn test_ipv6_support() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("test_user", 2).await;

    let ipv4 = test_ipv4(192, 168, 1, 1);
    let ipv6 = test_ipv6();

    assert!(tracker.check_and_add("test_user", ipv4).await.is_ok());
    assert!(tracker.check_and_add("test_user", ipv6).await.is_ok());

    assert_eq!(tracker.get_active_ip_count("test_user").await, 2);
}

#[tokio::test]
async fn test_get_active_ips() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("test_user", 3).await;

    let ip1 = test_ipv4(192, 168, 1, 1);
    let ip2 = test_ipv4(192, 168, 1, 2);

    tracker.check_and_add("test_user", ip1).await.unwrap();
    tracker.check_and_add("test_user", ip2).await.unwrap();

    let active_ips = tracker.get_active_ips("test_user").await;
    assert_eq!(active_ips.len(), 2);
    assert!(active_ips.contains(&ip1));
    assert!(active_ips.contains(&ip2));
}

#[tokio::test]
async fn test_stats() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("user1", 3).await;
    tracker.set_user_limit("user2", 2).await;

    let ip1 = test_ipv4(192, 168, 1, 1);
    let ip2 = test_ipv4(192, 168, 1, 2);

    tracker.check_and_add("user1", ip1).await.unwrap();
    tracker.check_and_add("user2", ip2).await.unwrap();

    let stats = tracker.get_stats().await;
    assert_eq!(stats.len(), 2);

    assert!(stats.iter().any(|(name, _, _)| name == "user1"));
    assert!(stats.iter().any(|(name, _, _)| name == "user2"));
}

#[tokio::test]
async fn test_clear_user_ips() {
    let tracker = UserIpTracker::new();
    let ip1 = test_ipv4(192, 168, 1, 1);

    tracker.check_and_add("test_user", ip1).await.unwrap();
    assert_eq!(tracker.get_active_ip_count("test_user").await, 1);

    tracker.clear_user_ips("test_user").await;
    assert_eq!(tracker.get_active_ip_count("test_user").await, 0);
}

#[tokio::test]
async fn test_is_ip_active() {
    let tracker = UserIpTracker::new();
    let ip1 = test_ipv4(192, 168, 1, 1);
    let ip2 = test_ipv4(192, 168, 1, 2);

    tracker.check_and_add("test_user", ip1).await.unwrap();

    assert!(tracker.is_ip_active("test_user", ip1).await);
    assert!(!tracker.is_ip_active("test_user", ip2).await);
}

#[tokio::test]
async fn test_load_limits_from_config() {
    let tracker = UserIpTracker::new();

    let mut config_limits = HashMap::new();
    config_limits.insert("user1".to_string(), 5);
    config_limits.insert("user2".to_string(), 3);

    tracker.load_limits(0, &config_limits).await;

    assert_eq!(tracker.get_user_limit("user1").await, Some(5));
    assert_eq!(tracker.get_user_limit("user2").await, Some(3));
    assert_eq!(tracker.get_user_limit("user3").await, None);
}

#[tokio::test]
async fn test_load_limits_replaces_previous_map() {
    let tracker = UserIpTracker::new();

    let mut first = HashMap::new();
    first.insert("user1".to_string(), 2);
    first.insert("user2".to_string(), 3);
    tracker.load_limits(0, &first).await;

    let mut second = HashMap::new();
    second.insert("user2".to_string(), 5);
    tracker.load_limits(0, &second).await;

    assert_eq!(tracker.get_user_limit("user1").await, None);
    assert_eq!(tracker.get_user_limit("user2").await, Some(5));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_policy_replacement_never_exposes_partial_limit_map() {
    const USER_COUNT: usize = 4_096;
    const REPLACEMENTS: usize = 32;

    let tracker = Arc::new(UserIpTracker::new());
    let first = (0..USER_COUNT)
        .map(|index| (format!("user-{index}"), 3usize))
        .collect::<HashMap<_, _>>();
    let second = (0..USER_COUNT)
        .map(|index| (format!("user-{index}"), 5usize))
        .collect::<HashMap<_, _>>();
    tracker.load_limits(7, &first).await;

    let running = Arc::new(AtomicBool::new(true));
    let writer_tracker = Arc::clone(&tracker);
    let writer_running = Arc::clone(&running);
    let writer = tokio::spawn(async move {
        for _ in 0..REPLACEMENTS {
            writer_tracker.load_limits(7, &second).await;
            tokio::task::yield_now().await;
            writer_tracker.load_limits(7, &first).await;
            tokio::task::yield_now().await;
        }
        writer_running.store(false, Ordering::Release);
    });

    let mut readers = Vec::new();
    for reader in 0..3usize {
        let reader_tracker = Arc::clone(&tracker);
        let reader_running = Arc::clone(&running);
        readers.push(tokio::spawn(async move {
            let mut index = reader;
            while reader_running.load(Ordering::Acquire) {
                let username = format!("user-{}", index % USER_COUNT);
                let limit = reader_tracker.get_user_limit(&username).await;
                assert!(matches!(limit, Some(3 | 5)), "partial policy: {limit:?}");
                index = index.wrapping_add(17);
                tokio::task::yield_now().await;
            }
        }));
    }

    writer.await.unwrap();
    for reader in readers {
        reader.await.unwrap();
    }
}

#[tokio::test]
async fn test_global_each_limit_applies_without_user_override() {
    let tracker = UserIpTracker::new();
    tracker.load_limits(2, &HashMap::new()).await;

    let ip1 = test_ipv4(172, 16, 0, 1);
    let ip2 = test_ipv4(172, 16, 0, 2);
    let ip3 = test_ipv4(172, 16, 0, 3);

    assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
    assert!(tracker.check_and_add("test_user", ip2).await.is_ok());
    assert!(tracker.check_and_add("test_user", ip3).await.is_err());
    assert_eq!(tracker.get_user_limit("test_user").await, Some(2));
}

#[tokio::test]
async fn test_user_override_wins_over_global_each_limit() {
    let tracker = UserIpTracker::new();
    let mut limits = HashMap::new();
    limits.insert("test_user".to_string(), 1);
    tracker.load_limits(3, &limits).await;

    let ip1 = test_ipv4(172, 17, 0, 1);
    let ip2 = test_ipv4(172, 17, 0, 2);

    assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
    assert!(tracker.check_and_add("test_user", ip2).await.is_err());
    assert_eq!(tracker.get_user_limit("test_user").await, Some(1));
}

#[tokio::test]
async fn test_time_window_mode_blocks_recent_ip_churn() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("test_user", 1).await;
    tracker
        .set_limit_policy(UserMaxUniqueIpsMode::TimeWindow, 30)
        .await;

    let ip1 = test_ipv4(10, 0, 0, 1);
    let ip2 = test_ipv4(10, 0, 0, 2);

    assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
    tracker.remove_ip("test_user", ip1).await;
    assert!(tracker.check_and_add("test_user", ip2).await.is_err());
}

#[tokio::test]
async fn test_combined_mode_enforces_active_and_recent_limits() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("test_user", 1).await;
    tracker
        .set_limit_policy(UserMaxUniqueIpsMode::Combined, 30)
        .await;

    let ip1 = test_ipv4(10, 0, 1, 1);
    let ip2 = test_ipv4(10, 0, 1, 2);

    assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
    assert!(tracker.check_and_add("test_user", ip2).await.is_err());

    tracker.remove_ip("test_user", ip1).await;
    assert!(tracker.check_and_add("test_user", ip2).await.is_err());
}

#[tokio::test]
async fn test_time_window_expires() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("test_user", 1).await;
    tracker
        .set_limit_policy(UserMaxUniqueIpsMode::TimeWindow, 1)
        .await;

    let ip1 = test_ipv4(10, 1, 0, 1);
    let ip2 = test_ipv4(10, 1, 0, 2);

    assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
    tracker.remove_ip("test_user", ip1).await;
    assert!(tracker.check_and_add("test_user", ip2).await.is_err());

    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(tracker.check_and_add("test_user", ip2).await.is_ok());
}

#[tokio::test]
async fn test_memory_stats_reports_queue_and_entry_counts() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("test_user", 4).await;
    let ip1 = test_ipv4(10, 2, 0, 1);
    let ip2 = test_ipv4(10, 2, 0, 2);

    tracker.check_and_add("test_user", ip1).await.unwrap();
    tracker.check_and_add("test_user", ip2).await.unwrap();
    tracker.enqueue_cleanup("test_user".to_string(), ip1);

    let snapshot = tracker.memory_stats().await;
    assert_eq!(snapshot.active_users, 1);
    assert_eq!(snapshot.recent_users, 1);
    assert_eq!(snapshot.active_entries, 2);
    assert_eq!(snapshot.recent_entries, 2);
    assert_eq!(snapshot.cleanup_queue_len, 1);
}

#[tokio::test]
async fn test_compact_prunes_stale_recent_entries() {
    let tracker = UserIpTracker::new();
    tracker
        .set_limit_policy(UserMaxUniqueIpsMode::TimeWindow, 1)
        .await;

    let stale_user = "stale-user".to_string();
    let stale_ip = test_ipv4(10, 3, 0, 1);
    {
        let shard_idx = UserIpTracker::shard_idx(&stale_user);
        let mut shard = tracker.shards[shard_idx].write().await;
        shard
            .recent_ips
            .entry(stale_user.clone())
            .or_insert_with(HashMap::new)
            .insert(stale_ip, Instant::now() - Duration::from_secs(5));
    }

    tracker.last_compact_epoch_secs.store(0, Ordering::Relaxed);
    tracker
        .check_and_add("trigger-user", test_ipv4(10, 3, 0, 2))
        .await
        .unwrap();

    let shard_idx = UserIpTracker::shard_idx(&stale_user);
    let shard = tracker.shards[shard_idx].read().await;
    let stale_exists = shard
        .recent_ips
        .get(&stale_user)
        .map(|ips| ips.contains_key(&stale_ip))
        .unwrap_or(false);
    assert!(!stale_exists);
}

#[tokio::test]
async fn test_time_window_allows_same_ip_reconnect() {
    let tracker = UserIpTracker::new();
    tracker.set_user_limit("test_user", 1).await;
    tracker
        .set_limit_policy(UserMaxUniqueIpsMode::TimeWindow, 1)
        .await;

    let ip1 = test_ipv4(10, 4, 0, 1);

    assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
    tracker.remove_ip("test_user", ip1).await;
    assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
}
