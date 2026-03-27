use super::*;
use crate::config::ProxyConfig;
use crate::stats::Stats;
use crate::transport::UpstreamManager;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

fn preload_user_quota(stats: &Stats, user: &str, bytes: u64) {
    let user_stats = stats.get_or_create_user_stats_handle(user);
    stats.quota_charge_post_write(user_stats.as_ref(), bytes);
}

#[tokio::test]
async fn edge_mask_delay_bypassed_if_max_is_zero() {
    let mut config = ProxyConfig::default();
    config.censorship.server_hello_delay_min_ms = 10_000;
    config.censorship.server_hello_delay_max_ms = 0;

    let start = std::time::Instant::now();
    maybe_apply_mask_reject_delay(&config).await;
    assert!(start.elapsed() < Duration::from_millis(50));
}

#[test]
fn edge_beobachten_ttl_clamps_exactly_to_24_hours() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = true;
    config.general.beobachten_minutes = 100_000;

    let ttl = beobachten_ttl(&config);
    assert_eq!(ttl.as_secs(), 24 * 60 * 60);
}

#[test]
fn edge_wrap_tls_application_record_empty_payload() {
    let wrapped = wrap_tls_application_record(&[]);
    assert_eq!(wrapped.len(), 5);
    assert_eq!(wrapped[0], TLS_RECORD_APPLICATION);
    assert_eq!(&wrapped[3..5], &[0, 0]);
}

#[tokio::test]
async fn boundary_user_data_quota_exact_match_rejects() {
    let user = "quota-boundary-user";
    let mut config = ProxyConfig::default();
    config.access.user_data_quota.insert(user.to_string(), 1024);

    let stats = Arc::new(Stats::new());
    preload_user_quota(stats.as_ref(), user, 1024);

    let ip_tracker = Arc::new(UserIpTracker::new());
    let peer = "198.51.100.10:55000".parse().unwrap();

    let result = RunningClientHandler::acquire_user_connection_reservation_static(
        user, &config, stats, peer, ip_tracker,
    )
    .await;

    assert!(matches!(result, Err(ProxyError::DataQuotaExceeded { .. })));
}

#[tokio::test]
async fn boundary_user_expiration_in_past_rejects() {
    let user = "expired-boundary-user";
    let mut config = ProxyConfig::default();
    let expired_time = chrono::Utc::now() - chrono::Duration::milliseconds(1);
    config
        .access
        .user_expirations
        .insert(user.to_string(), expired_time);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    let peer = "198.51.100.11:55000".parse().unwrap();

    let result = RunningClientHandler::acquire_user_connection_reservation_static(
        user, &config, stats, peer, ip_tracker,
    )
    .await;

    assert!(matches!(result, Err(ProxyError::UserExpired { .. })));
}

#[tokio::test]
async fn blackhat_proxy_protocol_massive_garbage_rejected_quickly() {
    let mut cfg = ProxyConfig::default();
    cfg.server.proxy_protocol_header_timeout_ms = 300;
    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());

    let (server_side, mut client_side) = duplex(4096);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.12:55000".parse().unwrap(),
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
        true,
    ));

    client_side.write_all(&vec![b'A'; 2000]).await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(2), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(ProxyError::InvalidProxyProtocol)));
    assert_eq!(stats.get_connects_bad(), 1);
}

#[tokio::test]
async fn edge_tls_body_immediate_eof_triggers_masking_and_bad_connect() {
    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = true;
    cfg.general.beobachten_minutes = 1;

    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(4096);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.13:55000".parse().unwrap(),
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

    client_side
        .write_all(&[0x16, 0x03, 0x01, 0x00, 100])
        .await
        .unwrap();
    client_side.shutdown().await.unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(2), handler)
        .await
        .unwrap();

    assert_eq!(stats.get_connects_bad(), 1);
}

#[tokio::test]
async fn security_classic_mode_disabled_masks_valid_length_payload() {
    let mut cfg = ProxyConfig::default();
    cfg.general.modes.classic = false;
    cfg.general.modes.secure = false;
    cfg.censorship.mask = true;

    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());

    let (server_side, mut client_side) = duplex(4096);
    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.15:55000".parse().unwrap(),
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

    client_side.write_all(&vec![0xEF; 64]).await.unwrap();
    client_side.shutdown().await.unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(2), handler)
        .await
        .unwrap();
    assert_eq!(stats.get_connects_bad(), 1);
}

#[tokio::test]
async fn concurrency_ip_tracker_strict_limit_one_rapid_churn() {
    let user = "rapid-churn-user";
    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_tcp_conns
        .insert(user.to_string(), 10);

    let stats = Arc::new(Stats::new());
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.set_user_limit(user, 1).await;

    let peer = "198.51.100.16:55000".parse().unwrap();

    for _ in 0..500 {
        let reservation = RunningClientHandler::acquire_user_connection_reservation_static(
            user,
            &config,
            stats.clone(),
            peer,
            ip_tracker.clone(),
        )
        .await
        .unwrap();
        reservation.release().await;
    }

    assert_eq!(stats.get_user_curr_connects(user), 0);
    assert_eq!(ip_tracker.get_active_ip_count(user).await, 0);
}

#[tokio::test]
async fn quirk_read_with_progress_zero_length_buffer_returns_zero_immediately() {
    let (mut server_side, _client_side) = duplex(4096);
    let mut empty_buf = &mut [][..];

    let result = tokio::time::timeout(
        Duration::from_millis(50),
        read_with_progress(&mut server_side, &mut empty_buf),
    )
    .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().unwrap(), 0);
}

#[tokio::test]
async fn stress_read_with_progress_cancellation_safety() {
    let (mut server_side, mut client_side) = duplex(4096);

    client_side.write_all(b"12345").await.unwrap();

    let mut buf = [0u8; 10];
    let result = tokio::time::timeout(
        Duration::from_millis(50),
        read_with_progress(&mut server_side, &mut buf),
    )
    .await;

    assert!(result.is_err());

    client_side.write_all(b"67890").await.unwrap();
    let mut buf2 = [0u8; 5];
    server_side.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, b"67890");
}
