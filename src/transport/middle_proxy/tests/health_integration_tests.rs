use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::codec::WriterCommand;
use super::health::health_drain_close_budget;
use super::me_health_monitor;
use super::pool::{MePool, MeWriter, WriterContour};
use super::registry::ConnMeta;
use crate::config::{GeneralConfig, MeRouteNoWriterMode, MeSocksKdfPolicy, MeWriterPickMode};
use crate::crypto::SecureRandom;
use crate::network::probe::NetworkDecision;
use crate::stats::Stats;

async fn make_pool(
    me_pool_drain_threshold: u64,
    me_health_interval_ms_unhealthy: u64,
    me_health_interval_ms_healthy: u64,
) -> (Arc<MePool>, Arc<SecureRandom>) {
    let general = GeneralConfig {
        me_pool_drain_threshold,
        me_health_interval_ms_unhealthy,
        me_health_interval_ms_healthy,
        ..GeneralConfig::default()
    };
    let rng = Arc::new(SecureRandom::new());
    let pool = MePool::new(
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
        rng.clone(),
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
    );
    (pool, rng)
}

async fn insert_draining_writer(
    pool: &Arc<MePool>,
    writer_id: u64,
    drain_started_at_epoch_secs: u64,
    bound_clients: usize,
    drain_deadline_epoch_secs: u64,
) {
    let (tx, _writer_rx) = mpsc::channel::<WriterCommand>(8);
    let writer = MeWriter {
        id: writer_id,
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5500 + writer_id as u16),
        source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        writer_dc: 2,
        generation: 1,
        contour: Arc::new(AtomicU8::new(WriterContour::Draining.as_u8())),
        created_at: Instant::now() - Duration::from_secs(writer_id),
        tx: tx.clone(),
        cancel: CancellationToken::new(),
        degraded: Arc::new(AtomicBool::new(false)),
        rtt_ema_ms_x10: Arc::new(AtomicU32::new(0)),
        draining: Arc::new(AtomicBool::new(true)),
        draining_started_at_epoch_secs: Arc::new(AtomicU64::new(drain_started_at_epoch_secs)),
        drain_deadline_epoch_secs: Arc::new(AtomicU64::new(drain_deadline_epoch_secs)),
        allow_drain_fallback: Arc::new(AtomicBool::new(false)),
    };
    pool.writers.write().await.push(writer);
    pool.registry.register_writer(writer_id, tx).await;
    pool.conn_count.fetch_add(1, Ordering::Relaxed);
    for idx in 0..bound_clients {
        let (conn_id, _rx) = pool.registry.register().await;
        assert!(
            pool.registry
                .bind_writer(
                    conn_id,
                    writer_id,
                    ConnMeta {
                        target_dc: 2,
                        client_addr: SocketAddr::new(
                            IpAddr::V4(Ipv4Addr::LOCALHOST),
                            7200 + idx as u16,
                        ),
                        our_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
                        proto_flags: 0,
                    },
                )
                .await
        );
    }
}

async fn wait_for_pool_empty(pool: &Arc<MePool>, timeout: Duration) {
    let start = Instant::now();
    loop {
        if pool.writers.read().await.is_empty() {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "timed out waiting for pool.writers to become empty"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn me_health_monitor_drains_expired_backlog_over_multiple_cycles() {
    let (pool, rng) = make_pool(128, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let writer_total = health_drain_close_budget()
        .saturating_mul(2)
        .saturating_add(9);
    for writer_id in 1..=writer_total as u64 {
        insert_draining_writer(
            &pool,
            writer_id,
            now_epoch_secs.saturating_sub(120),
            1,
            now_epoch_secs.saturating_sub(1),
        )
        .await;
    }

    let monitor = tokio::spawn(me_health_monitor(pool.clone(), rng, 0));
    wait_for_pool_empty(&pool, Duration::from_secs(1)).await;
    monitor.abort();
    let _ = monitor.await;

    assert!(pool.writers.read().await.is_empty());
}

#[tokio::test]
async fn me_health_monitor_cleans_empty_draining_writers_without_force_close() {
    let (pool, rng) = make_pool(128, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    for writer_id in 1..=24u64 {
        insert_draining_writer(&pool, writer_id, now_epoch_secs.saturating_sub(60), 0, 0).await;
    }

    let monitor = tokio::spawn(me_health_monitor(pool.clone(), rng, 0));
    wait_for_pool_empty(&pool, Duration::from_secs(1)).await;
    monitor.abort();
    let _ = monitor.await;

    assert!(pool.writers.read().await.is_empty());
}

#[tokio::test]
async fn me_health_monitor_converges_retry_like_threshold_backlog_to_empty() {
    let threshold = 4u64;
    let (pool, rng) = make_pool(threshold, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let writer_total = threshold as usize + health_drain_close_budget().saturating_add(11);
    for writer_id in 1..=writer_total as u64 {
        insert_draining_writer(
            &pool,
            writer_id,
            now_epoch_secs.saturating_sub(300).saturating_add(writer_id),
            1,
            0,
        )
        .await;
    }

    let monitor = tokio::spawn(me_health_monitor(pool.clone(), rng, 0));
    wait_for_pool_empty(&pool, Duration::from_secs(1)).await;
    monitor.abort();
    let _ = monitor.await;

    assert!(pool.writers.read().await.is_empty());
}
