use super::*;
use crate::config::ProxyConfig;
use crate::error::ProxyError;
use crate::ip_tracker::UserIpTracker;
use crate::stats::Stats;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// ------------------------------------------------------------------
// Priority 3: Massive Concurrency Stress (OWASP ASVS 5.1.6)
// ------------------------------------------------------------------

#[tokio::test]
async fn client_stress_10k_connections_limit_strict() {
    let user = "stress-user";
    let limit = 512;

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert(user.to_string(), limit);

    let iterations = 1000;
    let mut tasks = Vec::new();

    for i in 0..iterations {
        let stats = Arc::clone(&stats);
        let ip_tracker = Arc::clone(&ip_tracker);
        let config = config.clone();
        let user_str = user.to_string();

        tasks.push(tokio::spawn(async move {
            let peer = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, (i % 254 + 1) as u8)),
                10000 + (i % 1000) as u16,
            );

            match RunningClientHandler::acquire_user_connection_reservation_static(
                &user_str, &config, stats, peer, ip_tracker,
            )
            .await
            {
                Ok(res) => Ok(res),
                Err(ProxyError::ConnectionLimitExceeded { .. }) => Err(()),
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        }));
    }

    let results = futures::future::join_all(tasks).await;
    let mut successes = 0;
    let mut failures = 0;
    let mut reservations = Vec::new();

    for res in results {
        match res.unwrap() {
            Ok(r) => {
                successes += 1;
                reservations.push(r);
            }
            Err(_) => failures += 1,
        }
    }

    assert_eq!(successes, limit, "Should allow exactly 'limit' connections");
    assert_eq!(
        failures,
        iterations - limit,
        "Should fail the rest with LimitExceeded"
    );
    assert_eq!(stats.get_user_curr_connects(user), limit as u64);

    drop(reservations);

    ip_tracker.drain_cleanup_queue().await;

    assert_eq!(
        stats.get_user_curr_connects(user),
        0,
        "Stats must converge to 0 after all drops"
    );
    assert_eq!(
        ip_tracker.get_active_ip_count(user).await,
        0,
        "IP tracker must converge to 0"
    );
}

// ------------------------------------------------------------------
// Priority 3: IP Tracker Race Stress
// ------------------------------------------------------------------

#[tokio::test]
async fn client_ip_tracker_race_condition_stress() {
    let user = "race-user";
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 100).await;

    let iterations = 1000;
    let mut tasks = Vec::new();

    for i in 0..iterations {
        let ip_tracker = Arc::clone(&ip_tracker);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, (i % 254 + 1) as u8));

        tasks.push(tokio::spawn(async move {
            for _ in 0..10 {
                if let Ok(()) = ip_tracker.check_and_add("race-user", ip).await {
                    ip_tracker.remove_ip("race-user", ip).await;
                }
            }
        }));
    }

    futures::future::join_all(tasks).await;

    assert_eq!(
        ip_tracker.get_active_ip_count(user).await,
        0,
        "IP count must be zero after balanced add/remove burst"
    );
}

#[tokio::test]
async fn client_limit_burst_peak_never_exceeds_cap() {
    let user = "peak-cap-user";
    let limit = 32;
    let attempts = 256;

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert(user.to_string(), limit);

    let peak = Arc::new(AtomicU64::new(0));
    let mut tasks = Vec::with_capacity(attempts);

    for i in 0..attempts {
        let stats = Arc::clone(&stats);
        let ip_tracker = Arc::clone(&ip_tracker);
        let config = config.clone();
        let peak = Arc::clone(&peak);

        tasks.push(tokio::spawn(async move {
            let peer = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, (i % 250 + 1) as u8)),
                20000 + i as u16,
            );

            let acquired = RunningClientHandler::acquire_user_connection_reservation_static(
                user,
                &config,
                stats.clone(),
                peer,
                ip_tracker,
            )
            .await;

            if let Ok(reservation) = acquired {
                let now = stats.get_user_curr_connects(user);
                loop {
                    let prev = peak.load(Ordering::Relaxed);
                    if now <= prev {
                        break;
                    }
                    if peak
                        .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                    {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
                drop(reservation);
            }
        }));
    }

    futures::future::join_all(tasks).await;
    ip_tracker.drain_cleanup_queue().await;

    assert!(
        peak.load(Ordering::Relaxed) <= limit as u64,
        "peak concurrent reservations must not exceed configured cap"
    );
    assert_eq!(stats.get_user_curr_connects(user), 0);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0);
}

#[tokio::test]
async fn client_quota_rejection_never_mutates_live_counters() {
    let user = "quota-reject-user";
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let mut config = ProxyConfig::default();
    config.access.user_data_quota.insert(user.to_string(), 0);

    let peer: SocketAddr = "198.51.100.201:31111".parse().unwrap();
    let res = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer,
        ip_tracker.clone(),
    )
    .await;

    assert!(matches!(res, Err(ProxyError::DataQuotaExceeded { .. })));
    assert_eq!(stats.get_user_curr_connects(user), 0);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0);
}

#[tokio::test]
async fn client_expiration_rejection_never_mutates_live_counters() {
    let user = "expired-user";
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let mut config = ProxyConfig::default();
    config.access.user_expirations.insert(
        user.to_string(),
        chrono::Utc::now() - chrono::Duration::seconds(1),
    );

    let peer: SocketAddr = "198.51.100.202:31112".parse().unwrap();
    let res = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer,
        ip_tracker.clone(),
    )
    .await;

    assert!(matches!(res, Err(ProxyError::UserExpired { .. })));
    assert_eq!(stats.get_user_curr_connects(user), 0);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0);
}

#[tokio::test]
async fn client_ip_limit_failure_rolls_back_counter_exactly() {
    let user = "ip-limit-rollback-user";
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 1).await;

    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert(user.to_string(), 16);

    let first_peer: SocketAddr = "198.51.100.203:31113".parse().unwrap();
    let first = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        first_peer,
        ip_tracker.clone(),
    )
    .await
    .unwrap();

    let second_peer: SocketAddr = "198.51.100.204:31114".parse().unwrap();
    let second = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        second_peer,
        ip_tracker.clone(),
    )
    .await;

    assert!(matches!(
        second,
        Err(ProxyError::ConnectionLimitExceeded { .. })
    ));
    assert_eq!(stats.get_user_curr_connects(user), 1);

    drop(first);
    ip_tracker.drain_cleanup_queue().await;

    assert_eq!(stats.get_user_curr_connects(user), 0);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0);
}

#[tokio::test]
async fn client_parallel_limit_checks_success_path_leaves_no_residue() {
    let user = "parallel-check-success-user";
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 128).await;

    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert(user.to_string(), 128);

    let mut tasks = Vec::new();
    for i in 0..128u16 {
        let stats = Arc::clone(&stats);
        let ip_tracker = Arc::clone(&ip_tracker);
        let config = config.clone();

        tasks.push(tokio::spawn(async move {
            let peer = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 10, (i / 255) as u8, (i % 255 + 1) as u8)),
                32000 + i,
            );
            RunningClientHandler::check_user_limits_static(user, &config, &stats, peer, &ip_tracker)
                .await
        }));
    }

    for result in futures::future::join_all(tasks).await {
        assert!(result.unwrap().is_ok());
    }

    assert_eq!(stats.get_user_curr_connects(user), 0);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0);
}

#[tokio::test]
async fn client_parallel_limit_checks_failure_path_leaves_no_residue() {
    let user = "parallel-check-failure-user";
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 0).await;

    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert(user.to_string(), 512);

    let mut tasks = Vec::new();
    for i in 0..64u16 {
        let stats = Arc::clone(&stats);
        let ip_tracker = Arc::clone(&ip_tracker);
        let config = config.clone();

        tasks.push(tokio::spawn(async move {
            let peer = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(172, 16, 0, (i % 250 + 1) as u8)),
                33000 + i,
            );
            RunningClientHandler::check_user_limits_static(user, &config, &stats, peer, &ip_tracker)
                .await
        }));
    }

    let mut _denied = 0usize;
    for result in futures::future::join_all(tasks).await {
        match result.unwrap() {
            Ok(()) => {}
            Err(ProxyError::ConnectionLimitExceeded { .. }) => _denied += 1,
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    assert_eq!(stats.get_user_curr_connects(user), 0);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0);
}

#[tokio::test]
async fn client_churn_mixed_success_failure_converges_to_zero_state() {
    let user = "mixed-churn-user";
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 4).await;

    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 8);

    let mut tasks = Vec::new();
    for i in 0..200u16 {
        let stats = Arc::clone(&stats);
        let ip_tracker = Arc::clone(&ip_tracker);
        let config = config.clone();

        tasks.push(tokio::spawn(async move {
            let peer = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, (i % 16 + 1) as u8)),
                34000 + (i % 32),
            );
            let maybe_res = RunningClientHandler::acquire_user_connection_reservation_static(
                user, &config, stats, peer, ip_tracker,
            )
            .await;

            if let Ok(reservation) = maybe_res {
                tokio::time::sleep(Duration::from_millis((i % 3) as u64)).await;
                drop(reservation);
            }
        }));
    }

    futures::future::join_all(tasks).await;
    ip_tracker.drain_cleanup_queue().await;

    assert_eq!(stats.get_user_curr_connects(user), 0);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0);
}

#[tokio::test]
async fn client_same_ip_parallel_attempts_allow_at_most_one_when_limit_is_one() {
    let user = "same-ip-user";
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 1).await;

    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 1);

    let peer: SocketAddr = "203.0.113.44:35555".parse().unwrap();
    let mut tasks = Vec::new();

    for _ in 0..64 {
        let stats = Arc::clone(&stats);
        let ip_tracker = Arc::clone(&ip_tracker);
        let config = config.clone();
        tasks.push(tokio::spawn(async move {
            RunningClientHandler::acquire_user_connection_reservation_static(
                user, &config, stats, peer, ip_tracker,
            )
            .await
        }));
    }

    let mut granted = 0usize;
    let mut reservations = Vec::new();
    for result in futures::future::join_all(tasks).await {
        match result.unwrap() {
            Ok(reservation) => {
                granted += 1;
                reservations.push(reservation);
            }
            Err(ProxyError::ConnectionLimitExceeded { .. }) => {}
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    assert_eq!(
        granted, 1,
        "only one reservation may be granted for same IP with limit=1"
    );
    drop(reservations);
    ip_tracker.drain_cleanup_queue().await;
    assert_eq!(stats.get_user_curr_connects(user), 0);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0);
}

#[tokio::test]
async fn client_repeat_acquire_release_cycles_never_accumulate_state() {
    let user = "repeat-cycle-user";
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 32).await;

    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert(user.to_string(), 32);

    for i in 0..500u16 {
        let peer = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(198, 18, (i / 250) as u8, (i % 250 + 1) as u8)),
            36000 + (i % 128),
        );
        let reservation = RunningClientHandler::acquire_user_connection_reservation_static(
            user,
            &config,
            stats.clone(),
            peer,
            ip_tracker.clone(),
        )
        .await
        .unwrap();
        drop(reservation);
    }

    ip_tracker.drain_cleanup_queue().await;
    assert_eq!(stats.get_user_curr_connects(user), 0);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0);
}

#[tokio::test]
async fn client_multi_user_isolation_under_parallel_limit_exhaustion() {
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert("u1".to_string(), 8);
    config.access.user_max_tcp_conns.insert("u2".to_string(), 8);

    let mut tasks = Vec::new();
    for i in 0..128u16 {
        let stats = Arc::clone(&stats);
        let ip_tracker = Arc::clone(&ip_tracker);
        let config = config.clone();
        tasks.push(tokio::spawn(async move {
            let user = if i % 2 == 0 { "u1" } else { "u2" };
            let peer = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(100, 64, (i / 64) as u8, (i % 64 + 1) as u8)),
                37000 + i,
            );
            RunningClientHandler::acquire_user_connection_reservation_static(
                user, &config, stats, peer, ip_tracker,
            )
            .await
        }));
    }

    let mut u1_success = 0usize;
    let mut u2_success = 0usize;
    let mut reservations = Vec::new();
    for (idx, result) in futures::future::join_all(tasks)
        .await
        .into_iter()
        .enumerate()
    {
        let user = if idx % 2 == 0 { "u1" } else { "u2" };
        match result.unwrap() {
            Ok(reservation) => {
                if user == "u1" {
                    u1_success += 1;
                } else {
                    u2_success += 1;
                }
                reservations.push(reservation);
            }
            Err(ProxyError::ConnectionLimitExceeded { .. }) => {}
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    assert_eq!(u1_success, 8, "u1 must get exactly its own configured cap");
    assert_eq!(u2_success, 8, "u2 must get exactly its own configured cap");

    drop(reservations);
    ip_tracker.drain_cleanup_queue().await;
    assert_eq!(stats.get_user_curr_connects("u1"), 0);
    assert_eq!(stats.get_user_curr_connects("u2"), 0);
}

#[tokio::test]
async fn client_limit_recovery_after_full_rejection_wave() {
    let user = "recover-user";
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 1).await;

    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 1);

    let first_peer: SocketAddr = "198.51.100.50:38001".parse().unwrap();
    let reservation = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        first_peer,
        ip_tracker.clone(),
    )
    .await
    .unwrap();

    for i in 0..64u16 {
        let peer = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, (i % 60 + 1) as u8)),
            38002 + i,
        );
        let denied = RunningClientHandler::acquire_user_connection_reservation_static(
            user,
            &config,
            stats.clone(),
            peer,
            ip_tracker.clone(),
        )
        .await;
        assert!(matches!(
            denied,
            Err(ProxyError::ConnectionLimitExceeded { .. })
        ));
    }

    drop(reservation);
    ip_tracker.drain_cleanup_queue().await;
    assert_eq!(stats.get_user_curr_connects(user), 0);

    let recovery_peer: SocketAddr = "198.51.100.200:38999".parse().unwrap();
    let recovered = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        recovery_peer,
        ip_tracker.clone(),
    )
    .await;
    assert!(
        recovered.is_ok(),
        "capacity must recover after prior holder drops"
    );
}

#[tokio::test]
async fn client_dual_limit_cross_product_never_leaks_on_reject() {
    let user = "dual-limit-user";
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 2).await;

    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 2);

    let p1: SocketAddr = "203.0.113.10:39001".parse().unwrap();
    let p2: SocketAddr = "203.0.113.11:39002".parse().unwrap();
    let r1 = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        p1,
        ip_tracker.clone(),
    )
    .await
    .unwrap();
    let r2 = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        p2,
        ip_tracker.clone(),
    )
    .await
    .unwrap();

    for i in 0..32u16 {
        let peer = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, (50 + i) as u8)),
            39010 + i,
        );
        let denied = RunningClientHandler::acquire_user_connection_reservation_static(
            user,
            &config,
            stats.clone(),
            peer,
            ip_tracker.clone(),
        )
        .await;
        assert!(matches!(
            denied,
            Err(ProxyError::ConnectionLimitExceeded { .. })
        ));
    }

    assert_eq!(stats.get_user_curr_connects(user), 2);
    drop((r1, r2));
    ip_tracker.drain_cleanup_queue().await;
    assert_eq!(stats.get_user_curr_connects(user), 0);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0);
}

#[tokio::test]
async fn client_check_user_limits_concurrent_churn_no_counter_drift() {
    let user = "check-drift-user";
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 64).await;

    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert(user.to_string(), 64);

    let mut tasks = Vec::new();
    for i in 0..512u16 {
        let stats = Arc::clone(&stats);
        let ip_tracker = Arc::clone(&ip_tracker);
        let config = config.clone();
        tasks.push(tokio::spawn(async move {
            let peer = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(172, 20, (i / 255) as u8, (i % 255 + 1) as u8)),
                40000 + (i % 500),
            );
            let _ = RunningClientHandler::check_user_limits_static(
                user,
                &config,
                &stats,
                peer,
                &ip_tracker,
            )
            .await;
        }));
    }

    for task in futures::future::join_all(tasks).await {
        task.unwrap();
    }

    assert_eq!(stats.get_user_curr_connects(user), 0);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0);
}
