use super::*;
use crate::config::ProxyConfig;
use crate::protocol::constants::MIN_TLS_CLIENT_HELLO_SIZE;
use crate::stats::Stats;
use crate::transport::UpstreamManager;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, duplex};

fn preload_user_quota(stats: &Stats, user: &str, bytes: u64) {
    let user_stats = stats.get_or_create_user_stats_handle(user);
    stats.quota_charge_post_write(user_stats.as_ref(), bytes);
}

#[test]
fn invariant_wrap_tls_application_record_exact_multiples() {
    let chunk_size = u16::MAX as usize;
    let payload = vec![0xAA; chunk_size * 2];

    let wrapped = wrap_tls_application_record(&payload);

    assert_eq!(wrapped.len(), 2 * (5 + chunk_size));
    assert_eq!(wrapped[0], TLS_RECORD_APPLICATION);
    assert_eq!(&wrapped[3..5], &65535u16.to_be_bytes());

    let second_header_idx = 5 + chunk_size;
    assert_eq!(wrapped[second_header_idx], TLS_RECORD_APPLICATION);
    assert_eq!(
        &wrapped[second_header_idx + 3..second_header_idx + 5],
        &65535u16.to_be_bytes()
    );
}

#[tokio::test]
async fn invariant_tls_clienthello_truncation_exact_boundary_triggers_masking() {
    let config = Arc::new(ProxyConfig::default());
    let stats = Arc::new(Stats::new());

    let (server_side, mut client_side) = duplex(4096);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.20:55000".parse().unwrap(),
        config,
        stats.clone(),
        Arc::new(UpstreamManager::new(
            vec![],
            1,
            1,
            1,
            1,
            false,
            stats.clone(),
        )),
        Arc::new(ReplayChecker::new(128, Duration::from_secs(60))),
        Arc::new(BufferPool::new()),
        Arc::new(SecureRandom::new()),
        None,
        Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        None,
        Arc::new(UserIpTracker::new()),
        Arc::new(BeobachtenStore::new()),
        false,
    ));

    let claimed_len = MIN_TLS_CLIENT_HELLO_SIZE as u16;
    let mut header = vec![0x16, 0x03, 0x01];
    header.extend_from_slice(&claimed_len.to_be_bytes());

    client_side.write_all(&header).await.unwrap();
    client_side
        .write_all(&vec![0x42; MIN_TLS_CLIENT_HELLO_SIZE - 1])
        .await
        .unwrap();
    client_side.shutdown().await.unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(2), handler)
        .await
        .unwrap();
    assert_eq!(stats.get_connects_bad(), 1);
}

#[tokio::test]
async fn invariant_acquire_reservation_ip_limit_rollback() {
    let user = "rollback-test-user";
    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert(user.to_string(), 10);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 1).await;

    let peer_a = "198.51.100.21:55000".parse().unwrap();
    let _res_a = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer_a,
        ip_tracker.clone(),
    )
    .await
    .unwrap();

    assert_eq!(stats.get_user_curr_connects(user), 1);

    let peer_b = "203.0.113.22:55000".parse().unwrap();
    let res_b = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer_b,
        ip_tracker.clone(),
    )
    .await;

    assert!(matches!(
        res_b,
        Err(ProxyError::ConnectionLimitExceeded { .. })
    ));
    assert_eq!(stats.get_user_curr_connects(user), 1);
}

#[tokio::test]
async fn invariant_quota_exact_boundary_inclusive() {
    let user = "quota-strict-user";
    let mut config = ProxyConfig::default();
    config.access.user_data_quota.insert(user.to_string(), 1000);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    let peer = "198.51.100.23:55000".parse().unwrap();

    preload_user_quota(stats.as_ref(), user, 999);
    let res1 = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer,
        ip_tracker.clone(),
    )
    .await;
    assert!(res1.is_ok());
    res1.unwrap().release().await;

    preload_user_quota(stats.as_ref(), user, 1);
    let res2 = RunningClientHandler::acquire_user_connection_reservation_static(
        user,
        &config,
        stats.clone(),
        peer,
        ip_tracker.clone(),
    )
    .await;
    assert!(matches!(res2, Err(ProxyError::DataQuotaExceeded { .. })));
}

#[tokio::test]
async fn invariant_direct_mode_partial_header_eof_is_error_not_bad_connect() {
    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = true;
    cfg.general.beobachten_minutes = 1;

    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(4096);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.25:55000".parse().unwrap(),
        config,
        stats.clone(),
        Arc::new(UpstreamManager::new(
            vec![],
            1,
            1,
            1,
            1,
            false,
            stats.clone(),
        )),
        Arc::new(ReplayChecker::new(128, Duration::from_secs(60))),
        Arc::new(BufferPool::new()),
        Arc::new(SecureRandom::new()),
        None,
        Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        None,
        Arc::new(UserIpTracker::new()),
        beobachten.clone(),
        false,
    ));

    client_side.write_all(&[0xEF, 0xEF, 0xEF]).await.unwrap();
    client_side.shutdown().await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(2), handler)
        .await
        .unwrap()
        .unwrap();

    assert!(result.is_err());
    assert_eq!(stats.get_connects_bad(), 0);
    let snapshot = beobachten.snapshot_text(Duration::from_secs(60));
    assert!(snapshot.contains("[expected_64_got_0]"));
}

#[tokio::test]
async fn invariant_route_mode_snapshot_picks_up_latest_mode() {
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    assert!(matches!(
        route_runtime.snapshot().mode,
        RelayRouteMode::Direct
    ));

    route_runtime.set_mode(RelayRouteMode::Middle);
    assert!(matches!(
        route_runtime.snapshot().mode,
        RelayRouteMode::Middle
    ));
}
