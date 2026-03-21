use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::{GeneralConfig, MeRouteNoWriterMode, MeSocksKdfPolicy, MeWriterPickMode};
use crate::crypto::SecureRandom;
use crate::network::probe::NetworkDecision;
use crate::stats::Stats;

use super::pool::MePool;

async fn make_pool() -> Arc<MePool> {
    let general = GeneralConfig::default();

    MePool::new(
        None,
        vec![1u8; 32],
        None,
        false,
        None,
        Vec::new(),
        1,
        None,
        12,
        1200,
        HashMap::new(),
        HashMap::new(),
        None,
        NetworkDecision::default(),
        None,
        Arc::new(SecureRandom::new()),
        Arc::new(Stats::default()),
        general.me_keepalive_enabled,
        general.me_keepalive_interval_secs,
        general.me_keepalive_jitter_secs,
        general.me_keepalive_payload_random,
        general.rpc_proxy_req_every,
        general.me_warmup_stagger_enabled,
        general.me_warmup_step_delay_ms,
        general.me_warmup_step_jitter_ms,
        general.me_reconnect_max_concurrent_per_dc,
        general.me_reconnect_backoff_base_ms,
        general.me_reconnect_backoff_cap_ms,
        general.me_reconnect_fast_retry_count,
        general.me_single_endpoint_shadow_writers,
        general.me_single_endpoint_outage_mode_enabled,
        general.me_single_endpoint_outage_disable_quarantine,
        general.me_single_endpoint_outage_backoff_min_ms,
        general.me_single_endpoint_outage_backoff_max_ms,
        general.me_single_endpoint_shadow_rotate_every_secs,
        general.me_floor_mode,
        general.me_adaptive_floor_idle_secs,
        general.me_adaptive_floor_min_writers_single_endpoint,
        general.me_adaptive_floor_min_writers_multi_endpoint,
        general.me_adaptive_floor_recover_grace_secs,
        general.me_adaptive_floor_writers_per_core_total,
        general.me_adaptive_floor_cpu_cores_override,
        general.me_adaptive_floor_max_extra_writers_single_per_core,
        general.me_adaptive_floor_max_extra_writers_multi_per_core,
        general.me_adaptive_floor_max_active_writers_per_core,
        general.me_adaptive_floor_max_warm_writers_per_core,
        general.me_adaptive_floor_max_active_writers_global,
        general.me_adaptive_floor_max_warm_writers_global,
        general.hardswap,
        general.me_pool_drain_ttl_secs,
        general.me_instadrain,
        general.me_pool_drain_threshold,
        general.me_pool_drain_soft_evict_enabled,
        general.me_pool_drain_soft_evict_grace_secs,
        general.me_pool_drain_soft_evict_per_writer,
        general.me_pool_drain_soft_evict_budget_per_core,
        general.me_pool_drain_soft_evict_cooldown_ms,
        general.effective_me_pool_force_close_secs(),
        general.me_pool_min_fresh_ratio,
        general.me_hardswap_warmup_delay_min_ms,
        general.me_hardswap_warmup_delay_max_ms,
        general.me_hardswap_warmup_extra_passes,
        general.me_hardswap_warmup_pass_backoff_base_ms,
        general.me_bind_stale_mode,
        general.me_bind_stale_ttl_secs,
        general.me_secret_atomic_snapshot,
        general.me_deterministic_writer_sort,
        MeWriterPickMode::default(),
        general.me_writer_pick_sample_size,
        MeSocksKdfPolicy::default(),
        general.me_writer_cmd_channel_capacity,
        general.me_route_channel_capacity,
        general.me_route_backpressure_base_timeout_ms,
        general.me_route_backpressure_high_timeout_ms,
        general.me_route_backpressure_high_watermark_pct,
        general.me_reader_route_data_wait_ms,
        general.me_health_interval_ms_unhealthy,
        general.me_health_interval_ms_healthy,
        general.me_warn_rate_limit_ms,
        MeRouteNoWriterMode::default(),
        general.me_route_no_writer_wait_ms,
        general.me_route_inline_recovery_attempts,
        general.me_route_inline_recovery_wait_ms,
    )
}

#[tokio::test]
async fn connectable_endpoints_waits_until_quarantine_expires() {
    let pool = make_pool().await;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 31, 0, 11)), 443);

    {
        let mut guard = pool.endpoint_quarantine.lock().await;
        guard.insert(addr, Instant::now() + Duration::from_millis(80));
    }

    let started = Instant::now();
    let endpoints = pool.connectable_endpoints_for_test(&[addr]).await;
    let elapsed = started.elapsed();

    assert_eq!(endpoints, vec![addr]);
    assert!(
        elapsed >= Duration::from_millis(50),
        "single-endpoint DC should honor quarantine before retry"
    );
}

#[tokio::test]
async fn connectable_endpoints_releases_quarantine_lock_before_sleep() {
    let pool = make_pool().await;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 31, 0, 12)), 443);

    {
        let mut guard = pool.endpoint_quarantine.lock().await;
        guard.insert(addr, Instant::now() + Duration::from_millis(120));
    }

    let pool_for_task = Arc::clone(&pool);
    let task = tokio::spawn(async move { pool_for_task.connectable_endpoints_for_test(&[addr]).await });

    tokio::time::sleep(Duration::from_millis(10)).await;

    let quarantine_check = tokio::time::timeout(
        Duration::from_millis(40),
        pool.is_endpoint_quarantined(addr),
    )
    .await;
    assert!(
        quarantine_check.is_ok(),
        "quarantine lock must not be held while waiting for expiry"
    );
    assert!(quarantine_check.expect("timeout"));

    let endpoints = tokio::time::timeout(Duration::from_millis(300), task)
        .await
        .expect("connectable_endpoints task timed out")
        .expect("task join failed");
    assert_eq!(endpoints, vec![addr]);
}
