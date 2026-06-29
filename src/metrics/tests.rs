use super::*;
use super::render::render_metrics;
use http_body_util::BodyExt;
use std::net::IpAddr;
use std::time::SystemTime;

use crate::tls_front::types::{
    CachedTlsData, ParsedServerHello, TlsBehaviorProfile, TlsCertPayload, TlsProfileSource,
};

#[tokio::test]
async fn test_render_metrics_format() {
    let stats = Arc::new(Stats::new());
    let shared_state = ProxySharedState::new();
    let tracker = UserIpTracker::new();
    let mut config = ProxyConfig::default();
    config
        .access
        .user_max_unique_ips
        .insert("alice".to_string(), 4);

    stats.increment_connects_all();
    stats.increment_connects_all();
    stats.increment_connects_bad_with_class("tls_handshake_bad_client");
    stats.increment_handshake_timeouts();
    stats.increment_handshake_failure_class("timeout");
    shared_state
        .handshake
        .auth_expensive_checks_total
        .fetch_add(9, std::sync::atomic::Ordering::Relaxed);
    shared_state
        .handshake
        .auth_budget_exhausted_total
        .fetch_add(2, std::sync::atomic::Ordering::Relaxed);
    stats.increment_upstream_connect_attempt_total();
    stats.increment_upstream_connect_attempt_total();
    stats.increment_upstream_connect_success_total();
    stats.increment_upstream_connect_fail_total();
    stats.increment_upstream_connect_failfast_hard_error_total();
    stats.observe_upstream_connect_attempts_per_request(2);
    stats.observe_upstream_connect_duration_ms(220, true);
    stats.observe_upstream_connect_duration_ms(1500, false);
    stats.increment_me_rpc_proxy_req_signal_sent_total();
    stats.increment_me_rpc_proxy_req_signal_failed_total();
    stats.increment_me_rpc_proxy_req_signal_skipped_no_meta_total();
    stats.increment_me_rpc_proxy_req_signal_response_total();
    stats.increment_me_rpc_proxy_req_signal_close_sent_total();
    stats.increment_me_idle_close_by_peer_total();
    stats.increment_relay_idle_soft_mark_total();
    stats.increment_relay_idle_hard_close_total();
    stats.increment_relay_pressure_evict_total();
    stats.increment_relay_protocol_desync_close_total();
    stats.increment_me_d2c_batches_total();
    stats.add_me_d2c_batch_frames_total(3);
    stats.add_me_d2c_batch_bytes_total(2048);
    stats.increment_me_d2c_flush_reason(crate::stats::MeD2cFlushReason::AckImmediate);
    stats.increment_me_d2c_data_frames_total();
    stats.increment_me_d2c_ack_frames_total();
    stats.add_me_d2c_payload_bytes_total(1800);
    stats.increment_me_d2c_write_mode(crate::stats::MeD2cWriteMode::Coalesced);
    stats.increment_me_d2c_quota_reject_total(crate::stats::MeD2cQuotaRejectStage::PostWrite);
    stats.observe_me_d2c_frame_buf_shrink(4096);
    stats.increment_me_endpoint_quarantine_total();
    stats.increment_me_endpoint_quarantine_unexpected_total();
    stats.increment_me_endpoint_quarantine_draining_suppressed_total();
    stats.increment_user_connects("alice");
    stats.increment_user_curr_connects("alice");
    stats.add_user_octets_from("alice", 1024);
    stats.add_user_octets_to("alice", 2048);
    stats.increment_user_msgs_from("alice");
    stats.increment_user_msgs_to("alice");
    stats.increment_user_msgs_to("alice");
    tracker
        .check_and_add("alice", "203.0.113.10".parse().unwrap())
        .await
        .unwrap();

    let output = render_metrics(&stats, shared_state.as_ref(), &config, &tracker, None).await;

    assert!(output.contains(&format!(
        "telemt_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    )));
    assert!(output.contains("telemt_connections_total 2"));
    assert!(output.contains("telemt_connections_bad_total 1"));
    assert!(output.contains(
        "telemt_connections_bad_by_class_total{class=\"tls_handshake_bad_client\"} 1"
    ));
    assert!(output.contains("telemt_handshake_timeouts_total 1"));
    assert!(output.contains("telemt_handshake_failures_by_class_total{class=\"timeout\"} 1"));
    assert!(output.contains("telemt_auth_expensive_checks_total 9"));
    assert!(output.contains("telemt_auth_budget_exhausted_total 2"));
    assert!(output.contains("telemt_upstream_connect_attempt_total 2"));
    assert!(output.contains("telemt_upstream_connect_success_total 1"));
    assert!(output.contains("telemt_upstream_connect_fail_total 1"));
    assert!(output.contains("telemt_upstream_connect_failfast_hard_error_total 1"));
    assert!(output.contains("telemt_upstream_connect_attempts_per_request{bucket=\"2\"} 1"));
    assert!(
        output
            .contains("telemt_upstream_connect_duration_success_total{bucket=\"101_500ms\"} 1")
    );
    assert!(
        output.contains("telemt_upstream_connect_duration_fail_total{bucket=\"gt_1000ms\"} 1")
    );
    assert!(output.contains("telemt_me_rpc_proxy_req_signal_sent_total 1"));
    assert!(output.contains("telemt_me_rpc_proxy_req_signal_failed_total 1"));
    assert!(output.contains("telemt_me_rpc_proxy_req_signal_skipped_no_meta_total 1"));
    assert!(output.contains("telemt_me_rpc_proxy_req_signal_response_total 1"));
    assert!(output.contains("telemt_me_rpc_proxy_req_signal_close_sent_total 1"));
    assert!(output.contains("telemt_me_idle_close_by_peer_total 1"));
    assert!(output.contains("telemt_relay_idle_soft_mark_total 1"));
    assert!(output.contains("telemt_relay_idle_hard_close_total 1"));
    assert!(output.contains("telemt_relay_pressure_evict_total 1"));
    assert!(output.contains("telemt_relay_protocol_desync_close_total 1"));
    assert!(output.contains("telemt_me_d2c_batches_total 1"));
    assert!(output.contains("telemt_me_d2c_batch_frames_total 3"));
    assert!(output.contains("telemt_me_d2c_batch_bytes_total 2048"));
    assert!(output.contains("telemt_me_d2c_flush_reason_total{reason=\"ack_immediate\"} 1"));
    assert!(output.contains("telemt_me_d2c_data_frames_total 1"));
    assert!(output.contains("telemt_me_d2c_ack_frames_total 1"));
    assert!(output.contains("telemt_me_d2c_payload_bytes_total 1800"));
    assert!(output.contains("telemt_me_d2c_write_mode_total{mode=\"coalesced\"} 1"));
    assert!(output.contains("telemt_me_d2c_quota_reject_total{stage=\"post_write\"} 1"));
    assert!(output.contains("telemt_me_d2c_frame_buf_shrink_total 1"));
    assert!(output.contains("telemt_me_d2c_frame_buf_shrink_bytes_total 4096"));
    assert!(output.contains("telemt_me_endpoint_quarantine_total 1"));
    assert!(output.contains("telemt_me_endpoint_quarantine_unexpected_total 1"));
    assert!(output.contains("telemt_me_endpoint_quarantine_draining_suppressed_total 1"));
    assert!(output.contains("telemt_user_connections_total{user=\"alice\"} 1"));
    assert!(output.contains("telemt_user_connections_current{user=\"alice\"} 1"));
    assert!(output.contains("telemt_user_octets_from_client{user=\"alice\"} 1024"));
    assert!(output.contains("telemt_user_octets_to_client{user=\"alice\"} 2048"));
    assert!(output.contains("telemt_user_msgs_from_client{user=\"alice\"} 1"));
    assert!(output.contains("telemt_user_msgs_to_client{user=\"alice\"} 2"));
    assert!(output.contains("telemt_user_unique_ips_current{user=\"alice\"} 1"));
    assert!(output.contains("telemt_user_unique_ips_recent_window{user=\"alice\"} 1"));
    assert!(output.contains("telemt_user_unique_ips_limit{user=\"alice\"} 4"));
    assert!(output.contains("telemt_user_unique_ips_utilization{user=\"alice\"} 0.250000"));
    assert!(output.contains("telemt_ip_tracker_users{scope=\"active\"} 1"));
    assert!(output.contains("telemt_ip_tracker_entries{scope=\"active\"} 1"));
    assert!(output.contains("telemt_ip_tracker_cleanup_queue_len 0"));
}

#[tokio::test]
async fn test_render_tls_front_profile_health() {
    let stats = Stats::new();
    let shared_state = ProxySharedState::new();
    let tracker = UserIpTracker::new();
    let mut config = ProxyConfig::default();
    config.censorship.tls_domain = "primary.example".to_string();
    config.censorship.tls_domains = vec!["fallback.example".to_string()];

    let cache = TlsFrontCache::new(
        &[
            "primary.example".to_string(),
            "fallback.example".to_string(),
        ],
        1024,
        "tlsfront-profile-health-test",
    );
    cache
        .set(
            "primary.example",
            CachedTlsData {
                server_hello_template: ParsedServerHello {
                    version: [0x03, 0x03],
                    random: [0u8; 32],
                    session_id: Vec::new(),
                    cipher_suite: [0x13, 0x01],
                    compression: 0,
                    extensions: {
                        let mut key_share = vec![0x00, 0x1d, 0x00, 0x20];
                        key_share.resize(36, 0x42);
                        vec![
                            crate::tls_front::types::TlsExtension {
                                ext_type: 0x002b,
                                data: vec![0x03, 0x04],
                            },
                            crate::tls_front::types::TlsExtension {
                                ext_type: 0x0033,
                                data: key_share,
                            },
                        ]
                    },
                },
                cert_info: None,
                cert_payload: Some(TlsCertPayload {
                    cert_chain_der: vec![vec![0x30, 0x01]],
                    certificate_message: vec![0x0b, 0x00, 0x00, 0x00],
                }),
                app_data_records_sizes: vec![1024, 512],
                total_app_data_len: 1536,
                behavior_profile: TlsBehaviorProfile {
                    change_cipher_spec_count: 1,
                    app_data_record_sizes: vec![1024, 512],
                    ticket_record_sizes: vec![69],
                    source: TlsProfileSource::Merged,
                    ..TlsBehaviorProfile::default()
                },
                fetched_at: SystemTime::now(),
                domain: "primary.example".to_string(),
            },
        )
        .await;

    let output = render_metrics(&stats, &shared_state, &config, &tracker, Some(&cache)).await;

    assert!(output.contains("telemt_tls_front_profile_domains{status=\"configured\"} 2"));
    assert!(output.contains("telemt_tls_front_profile_domains{status=\"emitted\"} 2"));
    assert!(output.contains("telemt_tls_front_profile_domains{status=\"suppressed\"} 0"));
    assert!(
        output.contains("telemt_tls_front_profile_info{domain=\"primary.example\",source=\"merged\",is_default=\"false\",has_cert_info=\"false\",has_cert_payload=\"true\"} 1")
    );
    assert!(
        output.contains("telemt_tls_front_profile_info{domain=\"fallback.example\",source=\"default\",is_default=\"true\",has_cert_info=\"false\",has_cert_payload=\"false\"} 1")
    );
    assert!(
        output.contains("telemt_tls_front_profile_quality_info{domain=\"primary.example\",quality=\"raw_strict\",key_share_group=\"x25519\"} 1")
    );
    assert!(
        output.contains("telemt_tls_front_profile_quality_info{domain=\"fallback.example\",quality=\"fallback\",key_share_group=\"none\"} 1")
    );
    assert!(output.contains(
        "telemt_tls_front_profile_server_hello_bytes{domain=\"primary.example\"} 90"
    ));
    assert!(output.contains(
        "telemt_tls_front_profile_server_hello_extensions{domain=\"primary.example\"} 2"
    ));
    assert!(
        output.contains(
            "telemt_tls_front_profile_app_data_records{domain=\"primary.example\"} 2"
        )
    );
    assert!(
        output
            .contains("telemt_tls_front_profile_ticket_records{domain=\"primary.example\"} 1")
    );
    assert!(output.contains(
        "telemt_tls_front_profile_change_cipher_spec_records{domain=\"primary.example\"} 1"
    ));
    assert!(
        output.contains(
            "telemt_tls_front_profile_app_data_bytes{domain=\"primary.example\"} 1536"
        )
    );
}

#[tokio::test]
async fn test_render_empty_stats() {
    let stats = Stats::new();
    let shared_state = ProxySharedState::new();
    let tracker = UserIpTracker::new();
    let config = ProxyConfig::default();
    let output = render_metrics(&stats, &shared_state, &config, &tracker, None).await;
    assert!(output.contains("telemt_connections_total 0"));
    assert!(output.contains("telemt_connections_bad_total 0"));
    assert!(output.contains("telemt_handshake_timeouts_total 0"));
    assert!(output.contains("telemt_auth_expensive_checks_total 0"));
    assert!(output.contains("telemt_auth_budget_exhausted_total 0"));
    assert!(output.contains("telemt_user_unique_ips_current{user="));
    assert!(output.contains("telemt_user_unique_ips_recent_window{user="));
}

#[tokio::test]
async fn test_render_uses_global_each_unique_ip_limit() {
    let stats = Stats::new();
    let shared_state = ProxySharedState::new();
    stats.increment_user_connects("alice");
    stats.increment_user_curr_connects("alice");
    let tracker = UserIpTracker::new();
    tracker
        .check_and_add("alice", "203.0.113.10".parse().unwrap())
        .await
        .unwrap();
    let mut config = ProxyConfig::default();
    config.access.user_max_unique_ips_global_each = 2;

    let output = render_metrics(&stats, &shared_state, &config, &tracker, None).await;

    assert!(output.contains("telemt_user_unique_ips_limit{user=\"alice\"} 2"));
    assert!(output.contains("telemt_user_unique_ips_utilization{user=\"alice\"} 0.500000"));
}

#[tokio::test]
async fn test_render_has_type_annotations() {
    let stats = Stats::new();
    let shared_state = ProxySharedState::new();
    let tracker = UserIpTracker::new();
    let config = ProxyConfig::default();
    let output = render_metrics(&stats, &shared_state, &config, &tracker, None).await;
    assert!(output.contains("# TYPE telemt_uptime_seconds gauge"));
    assert!(output.contains("# TYPE telemt_connections_total counter"));
    assert!(output.contains("# TYPE telemt_connections_bad_total counter"));
    assert!(output.contains("# TYPE telemt_connections_bad_by_class_total counter"));
    assert!(output.contains("# TYPE telemt_handshake_timeouts_total counter"));
    assert!(output.contains("# TYPE telemt_handshake_failures_by_class_total counter"));
    assert!(output.contains("# TYPE telemt_auth_expensive_checks_total counter"));
    assert!(output.contains("# TYPE telemt_auth_budget_exhausted_total counter"));
    assert!(output.contains("# TYPE telemt_upstream_connect_attempt_total counter"));
    assert!(output.contains("# TYPE telemt_me_rpc_proxy_req_signal_sent_total counter"));
    assert!(output.contains("# TYPE telemt_me_idle_close_by_peer_total counter"));
    assert!(output.contains("# TYPE telemt_relay_idle_soft_mark_total counter"));
    assert!(output.contains("# TYPE telemt_relay_idle_hard_close_total counter"));
    assert!(output.contains("# TYPE telemt_relay_pressure_evict_total counter"));
    assert!(output.contains("# TYPE telemt_relay_protocol_desync_close_total counter"));
    assert!(output.contains("# TYPE telemt_me_d2c_batches_total counter"));
    assert!(output.contains("# TYPE telemt_me_d2c_flush_reason_total counter"));
    assert!(output.contains("# TYPE telemt_me_d2c_write_mode_total counter"));
    assert!(output.contains("# TYPE telemt_me_d2c_batch_frames_bucket_total counter"));
    assert!(output.contains("# TYPE telemt_me_d2c_flush_duration_us_bucket_total counter"));
    assert!(output.contains("# TYPE telemt_me_endpoint_quarantine_total counter"));
    assert!(output.contains("# TYPE telemt_me_endpoint_quarantine_unexpected_total counter"));
    assert!(
        output.contains("# TYPE telemt_me_endpoint_quarantine_draining_suppressed_total counter")
    );
    assert!(output.contains("# TYPE telemt_me_writer_removed_total counter"));
    assert!(output.contains("# TYPE telemt_me_writer_removed_unexpected_minus_restored_total gauge"));
    assert!(output.contains("# TYPE telemt_user_unique_ips_current gauge"));
    assert!(output.contains("# TYPE telemt_user_unique_ips_recent_window gauge"));
    assert!(output.contains("# TYPE telemt_user_unique_ips_limit gauge"));
    assert!(output.contains("# TYPE telemt_user_unique_ips_utilization gauge"));
    assert!(output.contains("# TYPE telemt_stats_user_entries gauge"));
    assert!(output.contains("# TYPE telemt_telemetry_user_series_users gauge"));
    assert!(output.contains("# TYPE telemt_ip_tracker_users gauge"));
    assert!(output.contains("# TYPE telemt_ip_tracker_entries gauge"));
    assert!(output.contains("# TYPE telemt_ip_tracker_cleanup_queue_len gauge"));
    assert!(output.contains("# TYPE telemt_ip_tracker_cleanup_total counter"));
    assert!(output.contains("# TYPE telemt_ip_tracker_cap_rejects_total counter"));
    assert!(output.contains("# TYPE telemt_tls_fetch_profile_cache_entries gauge"));
    assert!(output.contains("# TYPE telemt_tls_fetch_profile_cache_cap_drops_total counter"));
    assert!(output.contains("# TYPE telemt_tls_front_full_cert_budget_ips gauge"));
    assert!(output.contains("# TYPE telemt_tls_front_full_cert_budget_cap_drops_total counter"));
    assert!(output.contains("# TYPE telemt_tls_front_profile_domains gauge"));
    assert!(output.contains("# TYPE telemt_tls_front_profile_info gauge"));
    assert!(output.contains("# TYPE telemt_tls_front_profile_quality_info gauge"));
    assert!(output.contains("# TYPE telemt_tls_front_profile_age_seconds gauge"));
    assert!(output.contains("# TYPE telemt_tls_front_profile_server_hello_bytes gauge"));
    assert!(output.contains("# TYPE telemt_tls_front_profile_server_hello_extensions gauge"));
    assert!(output.contains("# TYPE telemt_tls_front_profile_app_data_records gauge"));
    assert!(output.contains("# TYPE telemt_tls_front_profile_ticket_records gauge"));
    assert!(output.contains("# TYPE telemt_tls_front_profile_change_cipher_spec_records gauge"));
    assert!(output.contains("# TYPE telemt_tls_front_profile_app_data_bytes gauge"));
}

#[tokio::test]
async fn test_endpoint_integration() {
    let stats = Arc::new(Stats::new());
    let beobachten = Arc::new(BeobachtenStore::new());
    let shared_state = ProxySharedState::new();
    let tracker = UserIpTracker::new();
    let mut config = ProxyConfig::default();
    stats.increment_connects_all();
    stats.increment_connects_all();
    stats.increment_connects_all();

    let req = Request::builder().uri("/metrics").body(()).unwrap();
    let resp = handle(
        req,
        &stats,
        &beobachten,
        shared_state.as_ref(),
        &tracker,
        None,
        &config,
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(
        std::str::from_utf8(body.as_ref())
            .unwrap()
            .contains("telemt_connections_total 3")
    );
    assert!(
        std::str::from_utf8(body.as_ref())
            .unwrap()
            .contains(&format!(
                "telemt_build_info{{version=\"{}\"}} 1",
                env!("CARGO_PKG_VERSION")
            ))
    );

    config.general.beobachten = true;
    config.general.beobachten_minutes = 10;
    beobachten.record(
        "TLS-scanner",
        "203.0.113.10".parse::<IpAddr>().unwrap(),
        Duration::from_secs(600),
    );
    let req_beob = Request::builder().uri("/beobachten").body(()).unwrap();
    let resp_beob = handle(
        req_beob,
        &stats,
        &beobachten,
        shared_state.as_ref(),
        &tracker,
        None,
        &config,
    )
    .await
    .unwrap();
    assert_eq!(resp_beob.status(), StatusCode::OK);
    let body_beob = resp_beob.into_body().collect().await.unwrap().to_bytes();
    let beob_text = std::str::from_utf8(body_beob.as_ref()).unwrap();
    assert!(beob_text.contains("[TLS-scanner]"));
    assert!(beob_text.contains("203.0.113.10-1"));

    let req404 = Request::builder().uri("/other").body(()).unwrap();
    let resp404 = handle(
        req404,
        &stats,
        &beobachten,
        shared_state.as_ref(),
        &tracker,
        None,
        &config,
    )
    .await
    .unwrap();
    assert_eq!(resp404.status(), StatusCode::NOT_FOUND);
}
