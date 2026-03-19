use super::RunningClientHandler;
use crate::config::ProxyConfig;
use crate::error::ProxyError;
use crate::ip_tracker::UserIpTracker;
use crate::stats::Stats;
use std::sync::Arc;

fn peer(addr: &str) -> std::net::SocketAddr {
    addr.parse().expect("test socket addr must parse")
}

#[tokio::test]
async fn limits_check_accepts_under_quota_and_limits() {
    let user = "limits-ok-user";
    let config = ProxyConfig::default();
    let stats = Stats::new();
    let ip_tracker = UserIpTracker::new();

    let result = RunningClientHandler::check_user_limits_static(
        user,
        &config,
        &stats,
        peer("127.0.0.10:5000"),
        &ip_tracker,
    )
    .await;

    assert!(result.is_ok(), "healthy user must pass limit checks");
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 1);
    assert!(
        ip_tracker
            .is_ip_active(user, "127.0.0.10".parse().expect("ip must parse"))
            .await,
        "accepted check must reserve caller IP"
    );
}

#[tokio::test]
async fn tcp_limit_rejection_rolls_back_ip_and_increments_counter() {
    let user = "tcp-limit-user";
    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 1);

    let stats = Stats::new();
    stats.increment_user_curr_connects(user);
    let ip_tracker = UserIpTracker::new();

    let result = RunningClientHandler::check_user_limits_static(
        user,
        &config,
        &stats,
        peer("127.0.0.11:5001"),
        &ip_tracker,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::ConnectionLimitExceeded { user: u }) if u == user),
        "tcp limit overflow must fail with typed limit error"
    );
    assert_eq!(
        ip_tracker.get_active_ip_count(user).await,
        0,
        "rejected tcp-limit check must rollback temporary IP reservation"
    );
    assert_eq!(
        stats.get_ip_reservation_rollback_tcp_limit_total(),
        1,
        "tcp-limit rejection after temporary reservation must increment rollback counter"
    );
}

#[tokio::test]
async fn quota_limit_rejection_rolls_back_ip_and_increments_counter() {
    let user = "quota-limit-user";
    let mut config = ProxyConfig::default();
    config.access.user_data_quota.insert(user.to_string(), 1024);

    let stats = Stats::new();
    stats.add_user_octets_from(user, 1024);
    let ip_tracker = UserIpTracker::new();

    let result = RunningClientHandler::check_user_limits_static(
        user,
        &config,
        &stats,
        peer("127.0.0.12:5002"),
        &ip_tracker,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::DataQuotaExceeded { user: u }) if u == user),
        "quota overflow must fail with typed quota error"
    );
    assert_eq!(
        ip_tracker.get_active_ip_count(user).await,
        0,
        "rejected quota check must rollback temporary IP reservation"
    );
    assert_eq!(
        stats.get_ip_reservation_rollback_quota_limit_total(),
        1,
        "quota-limit rejection after temporary reservation must increment rollback counter"
    );
}

#[tokio::test]
async fn ip_limit_rejection_does_not_increment_rollback_counters() {
    let user = "ip-limit-user";
    let config = ProxyConfig::default();
    let stats = Stats::new();
    let ip_tracker = UserIpTracker::new();

    ip_tracker.set_user_limit(user, 1).await;
    ip_tracker
        .check_and_add(user, "127.0.0.21".parse().expect("ip must parse"))
        .await
        .expect("precondition: first unique ip must fit");

    let result = RunningClientHandler::check_user_limits_static(
        user,
        &config,
        &stats,
        peer("127.0.0.22:5003"),
        &ip_tracker,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::ConnectionLimitExceeded { user: u }) if u == user),
        "ip gate rejection must surface typed connection limit error"
    );
    assert_eq!(
        ip_tracker.get_active_ip_count(user).await,
        1,
        "failed ip-gate attempt must not mutate active ip footprint"
    );
    assert_eq!(
        stats.get_ip_reservation_rollback_tcp_limit_total(),
        0,
        "early ip-gate rejection must not increment tcp rollback counter"
    );
    assert_eq!(
        stats.get_ip_reservation_rollback_quota_limit_total(),
        0,
        "early ip-gate rejection must not increment quota rollback counter"
    );
}

#[tokio::test]
async fn same_ip_rechecks_do_not_expand_unique_ip_footprint() {
    let user = "same-ip-user";
    let config = ProxyConfig::default();
    let stats = Stats::new();
    let ip_tracker = UserIpTracker::new();

    ip_tracker.set_user_limit(user, 1).await;

    let first = RunningClientHandler::check_user_limits_static(
        user,
        &config,
        &stats,
        peer("127.0.0.30:5004"),
        &ip_tracker,
    )
    .await;
    let second = RunningClientHandler::check_user_limits_static(
        user,
        &config,
        &stats,
        peer("127.0.0.30:5005"),
        &ip_tracker,
    )
    .await;

    assert!(first.is_ok() && second.is_ok(), "same-ip rechecks under unique-ip cap must pass");
    assert_eq!(
        ip_tracker.get_active_ip_count(user).await,
        1,
        "same-ip rechecks must keep one unique active IP"
    );
}

#[tokio::test]
async fn mixed_limit_failures_keep_ip_tracker_consistent_under_concurrency() {
    let user = "concurrent-limits-user";
    let mut config = ProxyConfig::default();
    config.access.user_max_tcp_conns.insert(user.to_string(), 1);
    config.access.user_data_quota.insert(user.to_string(), 1);

    let config = Arc::new(config);
    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());

    // Force both limit checks to reject after tentative IP reservation.
    stats.increment_user_curr_connects(user);
    stats.add_user_octets_from(user, 1);

    let mut tasks = Vec::new();
    for idx in 0..32u16 {
        let config = Arc::clone(&config);
        let stats = Arc::clone(&stats);
        let ip_tracker = Arc::clone(&ip_tracker);
        let addr = format!("127.0.1.{}:{}", idx + 1, 6000 + idx);
        tasks.push(tokio::spawn(async move {
            RunningClientHandler::check_user_limits_static(
                user,
                &config,
                &stats,
                peer(&addr),
                &ip_tracker,
            )
            .await
        }));
    }

    for task in tasks {
        let result = task.await.expect("limit task must join");
        assert!(result.is_err(), "all constrained attempts must fail closed");
    }

    assert_eq!(
        ip_tracker.get_active_ip_count(user).await,
        0,
        "concurrent rejected attempts must not leave dangling active IP reservations"
    );
}
