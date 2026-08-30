use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::{ScheduledReconnects, reap_draining_writers};
use crate::config::{GeneralConfig, MeRouteNoWriterMode, MeSocksKdfPolicy, MeWriterPickMode};
use crate::crypto::SecureRandom;
use crate::network::IpFamily;
use crate::network::probe::NetworkDecision;
use crate::stats::Stats;
use crate::transport::middle_proxy::codec::WriterCommand;
use crate::transport::middle_proxy::pool::{MePool, MeWriter, WriterContour};
use crate::transport::middle_proxy::registry::ConnMeta;

#[test]
fn reconnect_batch_releases_every_reserved_key_after_join_failures() {
    let retained = (1, IpFamily::V4);
    let removed = (2, IpFamily::V6);
    let mut inflight = HashMap::from([(retained, 1)]);

    {
        let mut scheduled = ScheduledReconnects {
            inflight: &mut inflight,
            keys: Vec::new(),
        };
        scheduled.reserve(retained);
        scheduled.reserve(removed);
    }

    assert_eq!(inflight.get(&retained), Some(&1));
    assert!(!inflight.contains_key(&removed));
}

async fn make_pool(me_pool_drain_threshold: u64) -> Arc<MePool> {
    let general = GeneralConfig {
        me_pool_drain_threshold,
        ..GeneralConfig::default()
    };
    let mut proxy_map_v4 = HashMap::new();
    proxy_map_v4.insert(2, vec![(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 443)]);
    let decision = NetworkDecision {
        ipv4_me: true,
        ..NetworkDecision::default()
    };
    MePool::new(
        None,
        vec![1u8; 32],
        None,
        false,
        None,
        Vec::new(),
        false,
        Vec::new(),
        1,
        None,
        12,
        1200,
        proxy_map_v4,
        HashMap::new(),
        None,
        decision,
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
        general.me_writer_byte_budget_bytes,
        general.me_route_channel_capacity,
        general.me_route_backpressure_enabled,
        general.me_route_fairshare_enabled,
        general.me_route_backpressure_base_timeout_ms,
        general.me_route_backpressure_high_timeout_ms,
        general.me_route_backpressure_high_watermark_pct,
        general.me_reader_route_data_wait_ms,
        general.me_health_interval_ms_unhealthy,
        general.me_health_interval_ms_healthy,
        general.me_warn_rate_limit_ms,
        MeRouteNoWriterMode::default(),
        general.me_route_no_writer_wait_ms,
        general.me_route_hybrid_max_wait_ms,
        general.me_route_blocking_send_timeout_ms,
        general.me_route_inline_recovery_attempts,
        general.me_route_inline_recovery_wait_ms,
        16_384,
    )
}

async fn insert_draining_writer(
    pool: &Arc<MePool>,
    writer_id: u64,
    drain_started_at_epoch_secs: u64,
) -> u64 {
    let (conn_id, _rx) = pool.registry.register().await;
    let (tx, _writer_rx) = mpsc::channel::<WriterCommand>(8);
    let byte_budget = pool.new_writer_byte_budget();
    let writer = MeWriter {
        id: writer_id,
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000 + writer_id as u16),
        source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        writer_dc: 2,
        generation: 1,
        contour: Arc::new(AtomicU8::new(WriterContour::Draining.as_u8())),
        created_at: Instant::now() - Duration::from_secs(writer_id),
        tx: tx.clone(),
        byte_budget: byte_budget.clone(),
        cancel: CancellationToken::new(),
        degraded: Arc::new(AtomicBool::new(false)),
        rtt_ema_ms_x10: Arc::new(AtomicU32::new(0)),
        draining: Arc::new(AtomicBool::new(true)),
        draining_started_at_epoch_secs: Arc::new(AtomicU64::new(drain_started_at_epoch_secs)),
        drain_deadline_epoch_secs: Arc::new(AtomicU64::new(0)),
        allow_drain_fallback: Arc::new(AtomicBool::new(false)),
    };
    pool.writers.write().await.push(writer);
    pool.registry
        .register_writer(writer_id, tx, byte_budget)
        .await;
    pool.conn_count.fetch_add(1, Ordering::Relaxed);
    assert!(
        pool.registry
            .bind_writer(
                conn_id,
                writer_id,
                ConnMeta {
                    target_dc: 2,
                    client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6000),
                    our_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
                    proto_flags: 0,
                },
            )
            .await
    );
    conn_id
}

async fn insert_live_writer(pool: &Arc<MePool>, writer_id: u64, writer_dc: i32) {
    let (tx, _writer_rx) = mpsc::channel::<WriterCommand>(8);
    let byte_budget = pool.new_writer_byte_budget();
    let writer = MeWriter {
        id: writer_id,
        addr: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                203,
                0,
                113,
                (writer_id as u8).saturating_add(1),
            )),
            4000 + writer_id as u16,
        ),
        source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        writer_dc,
        generation: 2,
        contour: Arc::new(AtomicU8::new(WriterContour::Active.as_u8())),
        created_at: Instant::now(),
        tx: tx.clone(),
        byte_budget: byte_budget.clone(),
        cancel: CancellationToken::new(),
        degraded: Arc::new(AtomicBool::new(false)),
        rtt_ema_ms_x10: Arc::new(AtomicU32::new(0)),
        draining: Arc::new(AtomicBool::new(false)),
        draining_started_at_epoch_secs: Arc::new(AtomicU64::new(0)),
        drain_deadline_epoch_secs: Arc::new(AtomicU64::new(0)),
        allow_drain_fallback: Arc::new(AtomicBool::new(false)),
    };
    pool.writers.write().await.push(writer);
    pool.registry
        .register_writer(writer_id, tx, byte_budget)
        .await;
    pool.conn_count.fetch_add(1, Ordering::Relaxed);
}

#[tokio::test]
async fn reap_draining_writers_force_closes_oldest_over_threshold() {
    let pool = make_pool(2).await;
    insert_live_writer(&pool, 1, 2).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let conn_a = insert_draining_writer(&pool, 10, now_epoch_secs.saturating_sub(30)).await;
    let conn_b = insert_draining_writer(&pool, 20, now_epoch_secs.saturating_sub(20)).await;
    let conn_c = insert_draining_writer(&pool, 30, now_epoch_secs.saturating_sub(10)).await;
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    let mut writer_ids: Vec<u64> = pool
        .writers
        .read()
        .await
        .iter()
        .map(|writer| writer.id)
        .collect();
    writer_ids.sort_unstable();
    assert_eq!(writer_ids, vec![1, 20, 30]);
    assert!(pool.registry.get_writer(conn_a).await.is_none());
    assert_eq!(
        pool.registry.get_writer(conn_b).await.unwrap().writer_id,
        20
    );
    assert_eq!(
        pool.registry.get_writer(conn_c).await.unwrap().writer_id,
        30
    );
}

#[tokio::test]
async fn reap_draining_writers_force_closes_overflow_without_replacement() {
    let pool = make_pool(2).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let conn_a = insert_draining_writer(&pool, 10, now_epoch_secs.saturating_sub(30)).await;
    let conn_b = insert_draining_writer(&pool, 20, now_epoch_secs.saturating_sub(20)).await;
    let conn_c = insert_draining_writer(&pool, 30, now_epoch_secs.saturating_sub(10)).await;
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    let mut writer_ids: Vec<u64> = pool
        .writers
        .read()
        .await
        .iter()
        .map(|writer| writer.id)
        .collect();
    writer_ids.sort_unstable();
    assert_eq!(writer_ids, vec![20, 30]);
    assert!(pool.registry.get_writer(conn_a).await.is_none());
    assert_eq!(
        pool.registry.get_writer(conn_b).await.unwrap().writer_id,
        20
    );
    assert_eq!(
        pool.registry.get_writer(conn_c).await.unwrap().writer_id,
        30
    );
}

#[tokio::test]
async fn reap_draining_writers_keeps_timeout_only_behavior_when_threshold_disabled() {
    let pool = make_pool(0).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let conn_a = insert_draining_writer(&pool, 10, now_epoch_secs.saturating_sub(30)).await;
    let conn_b = insert_draining_writer(&pool, 20, now_epoch_secs.saturating_sub(20)).await;
    let conn_c = insert_draining_writer(&pool, 30, now_epoch_secs.saturating_sub(10)).await;
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    let writer_ids: Vec<u64> = pool
        .writers
        .read()
        .await
        .iter()
        .map(|writer| writer.id)
        .collect();
    assert_eq!(writer_ids, vec![10, 20, 30]);
    assert_eq!(
        pool.registry.get_writer(conn_a).await.unwrap().writer_id,
        10
    );
    assert_eq!(
        pool.registry.get_writer(conn_b).await.unwrap().writer_id,
        20
    );
    assert_eq!(
        pool.registry.get_writer(conn_c).await.unwrap().writer_id,
        30
    );
}
