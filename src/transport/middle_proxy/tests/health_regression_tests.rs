use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::codec::WriterCommand;
use super::health::{health_drain_close_budget, reap_draining_writers};
use super::pool::{MePool, MeWriter, WriterContour};
use super::registry::ConnMeta;
use crate::config::{
    GeneralConfig, MeBindStaleMode, MeRouteNoWriterMode, MeSocksKdfPolicy, MeWriterPickMode,
};
use crate::crypto::SecureRandom;
use crate::network::probe::NetworkDecision;
use crate::stats::Stats;

async fn make_pool(me_pool_drain_threshold: u64) -> Arc<MePool> {
    let general = GeneralConfig {
        me_pool_drain_threshold,
        ..GeneralConfig::default()
    };

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

async fn insert_draining_writer(
    pool: &Arc<MePool>,
    writer_id: u64,
    drain_started_at_epoch_secs: u64,
    bound_clients: usize,
    drain_deadline_epoch_secs: u64,
) -> Vec<u64> {
    let mut conn_ids = Vec::with_capacity(bound_clients);
    let (tx, _writer_rx) = mpsc::channel::<WriterCommand>(8);
    let writer = MeWriter {
        id: writer_id,
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4500 + writer_id as u16),
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
                            6200 + idx as u16,
                        ),
                        our_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
                        proto_flags: 0,
                    },
                )
                .await
        );
        conn_ids.push(conn_id);
    }
    conn_ids
}

async fn current_writer_ids(pool: &Arc<MePool>) -> Vec<u64> {
    let mut writer_ids = pool
        .writers
        .read()
        .await
        .iter()
        .map(|writer| writer.id)
        .collect::<Vec<_>>();
    writer_ids.sort_unstable();
    writer_ids
}

async fn writer_exists(pool: &Arc<MePool>, writer_id: u64) -> bool {
    pool.writers
        .read()
        .await
        .iter()
        .any(|writer| writer.id == writer_id)
}

async fn set_writer_draining(pool: &Arc<MePool>, writer_id: u64, draining: bool) {
    let writers = pool.writers.read().await;
    if let Some(writer) = writers.iter().find(|writer| writer.id == writer_id) {
        writer.draining.store(draining, Ordering::Relaxed);
    }
}

#[tokio::test]
async fn reap_draining_writers_drops_warn_state_for_removed_writer() {
    let pool = make_pool(128).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let conn_ids = insert_draining_writer(
        &pool,
        7,
        now_epoch_secs.saturating_sub(180),
        1,
        now_epoch_secs.saturating_add(3_600),
    )
    .await;
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;
    assert!(warn_next_allowed.contains_key(&7));

    let _ = pool.remove_writer_and_close_clients(7).await;
    assert!(pool.registry.get_writer(conn_ids[0]).await.is_none());

    reap_draining_writers(&pool, &mut warn_next_allowed).await;
    assert!(!warn_next_allowed.contains_key(&7));
}

#[tokio::test]
async fn reap_draining_writers_removes_empty_draining_writers() {
    let pool = make_pool(128).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    insert_draining_writer(&pool, 1, now_epoch_secs.saturating_sub(40), 0, 0).await;
    insert_draining_writer(&pool, 2, now_epoch_secs.saturating_sub(30), 0, 0).await;
    insert_draining_writer(&pool, 3, now_epoch_secs.saturating_sub(20), 1, 0).await;
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert_eq!(current_writer_ids(&pool).await, vec![3]);
}

#[tokio::test]
async fn reap_draining_writers_overflow_closes_oldest_non_empty_writers() {
    let pool = make_pool(2).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    insert_draining_writer(&pool, 11, now_epoch_secs.saturating_sub(40), 1, 0).await;
    insert_draining_writer(&pool, 22, now_epoch_secs.saturating_sub(30), 1, 0).await;
    insert_draining_writer(&pool, 33, now_epoch_secs.saturating_sub(20), 1, 0).await;
    insert_draining_writer(&pool, 44, now_epoch_secs.saturating_sub(10), 1, 0).await;
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert_eq!(current_writer_ids(&pool).await, vec![33, 44]);
}

#[tokio::test]
async fn reap_draining_writers_deadline_force_close_applies_under_threshold() {
    let pool = make_pool(128).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    insert_draining_writer(
        &pool,
        50,
        now_epoch_secs.saturating_sub(15),
        1,
        now_epoch_secs.saturating_sub(1),
    )
    .await;
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert!(current_writer_ids(&pool).await.is_empty());
}

#[tokio::test]
async fn reap_draining_writers_limits_closes_per_health_tick() {
    let pool = make_pool(1).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let close_budget = health_drain_close_budget();
    let writer_total = close_budget.saturating_add(20);
    for writer_id in 1..=writer_total as u64 {
        insert_draining_writer(&pool, writer_id, now_epoch_secs.saturating_sub(20), 1, 0).await;
    }
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert_eq!(pool.writers.read().await.len(), writer_total - close_budget);
}

#[tokio::test]
async fn reap_draining_writers_keeps_warn_state_for_deadline_backlog_writers() {
    let pool = make_pool(0).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let close_budget = health_drain_close_budget();
    let writer_total = close_budget.saturating_add(5);
    for writer_id in 1..=writer_total as u64 {
        insert_draining_writer(
            &pool,
            writer_id,
            now_epoch_secs.saturating_sub(60),
            1,
            now_epoch_secs.saturating_sub(1),
        )
        .await;
    }
    let target_writer_id = writer_total as u64;
    let mut warn_next_allowed = HashMap::new();
    warn_next_allowed.insert(target_writer_id, Instant::now() + Duration::from_secs(300));

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert!(writer_exists(&pool, target_writer_id).await);
    assert!(warn_next_allowed.contains_key(&target_writer_id));
}

#[tokio::test]
async fn reap_draining_writers_keeps_warn_state_for_overflow_backlog_writers() {
    let pool = make_pool(1).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let close_budget = health_drain_close_budget();
    let writer_total = close_budget.saturating_add(6);
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
    let target_writer_id = writer_total.saturating_sub(1) as u64;
    let mut warn_next_allowed = HashMap::new();
    warn_next_allowed.insert(target_writer_id, Instant::now() + Duration::from_secs(300));

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert!(writer_exists(&pool, target_writer_id).await);
    assert!(warn_next_allowed.contains_key(&target_writer_id));
}

#[tokio::test]
async fn reap_draining_writers_drops_warn_state_when_writer_exits_draining_state() {
    let pool = make_pool(128).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    insert_draining_writer(&pool, 71, now_epoch_secs.saturating_sub(60), 1, 0).await;

    let mut warn_next_allowed = HashMap::new();
    warn_next_allowed.insert(71, Instant::now() + Duration::from_secs(300));

    set_writer_draining(&pool, 71, false).await;
    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert!(writer_exists(&pool, 71).await);
    assert!(
        !warn_next_allowed.contains_key(&71),
        "warn cooldown state must be dropped after writer leaves draining state"
    );
}

#[tokio::test]
async fn reap_draining_writers_preserves_warn_state_across_multiple_budget_deferrals() {
    let pool = make_pool(0).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let close_budget = health_drain_close_budget();
    let writer_total = close_budget.saturating_mul(2).saturating_add(1);
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

    let tail_writer_id = writer_total as u64;
    let mut warn_next_allowed = HashMap::new();
    warn_next_allowed.insert(tail_writer_id, Instant::now() + Duration::from_secs(300));

    reap_draining_writers(&pool, &mut warn_next_allowed).await;
    assert!(writer_exists(&pool, tail_writer_id).await);
    assert!(warn_next_allowed.contains_key(&tail_writer_id));

    reap_draining_writers(&pool, &mut warn_next_allowed).await;
    assert!(writer_exists(&pool, tail_writer_id).await);
    assert!(warn_next_allowed.contains_key(&tail_writer_id));

    reap_draining_writers(&pool, &mut warn_next_allowed).await;
    assert!(!writer_exists(&pool, tail_writer_id).await);
    assert!(
        !warn_next_allowed.contains_key(&tail_writer_id),
        "warn cooldown state must clear once writer is actually removed"
    );
}

#[tokio::test]
async fn reap_draining_writers_backlog_drains_across_ticks() {
    let pool = make_pool(128).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let close_budget = health_drain_close_budget();
    let writer_total = close_budget.saturating_mul(2).saturating_add(7);
    for writer_id in 1..=writer_total as u64 {
        insert_draining_writer(&pool, writer_id, now_epoch_secs.saturating_sub(20), 0, 0).await;
    }
    let mut warn_next_allowed = HashMap::new();

    for _ in 0..8 {
        if pool.writers.read().await.is_empty() {
            break;
        }
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
    }

    assert!(pool.writers.read().await.is_empty());
}

#[tokio::test]
async fn reap_draining_writers_threshold_backlog_converges_to_threshold() {
    let threshold = 5u64;
    let pool = make_pool(threshold).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let close_budget = health_drain_close_budget();
    let writer_total = threshold as usize + close_budget.saturating_add(12);
    for writer_id in 1..=writer_total as u64 {
        insert_draining_writer(&pool, writer_id, now_epoch_secs.saturating_sub(20), 1, 0).await;
    }
    let mut warn_next_allowed = HashMap::new();

    for _ in 0..16 {
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
        if pool.writers.read().await.len() <= threshold as usize {
            break;
        }
    }

    assert_eq!(pool.writers.read().await.len(), threshold as usize);
}

#[tokio::test]
async fn reap_draining_writers_threshold_zero_preserves_non_expired_non_empty_writers() {
    let pool = make_pool(0).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    insert_draining_writer(&pool, 10, now_epoch_secs.saturating_sub(40), 1, 0).await;
    insert_draining_writer(&pool, 20, now_epoch_secs.saturating_sub(30), 1, 0).await;
    insert_draining_writer(&pool, 30, now_epoch_secs.saturating_sub(20), 1, 0).await;
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert_eq!(current_writer_ids(&pool).await, vec![10, 20, 30]);
}

#[tokio::test]
async fn reap_draining_writers_prioritizes_force_close_before_empty_cleanup() {
    let pool = make_pool(1).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let close_budget = health_drain_close_budget();
    for writer_id in 1..=close_budget.saturating_add(1) as u64 {
        insert_draining_writer(&pool, writer_id, now_epoch_secs.saturating_sub(20), 1, 0).await;
    }
    let empty_writer_id = close_budget.saturating_add(2) as u64;
    insert_draining_writer(
        &pool,
        empty_writer_id,
        now_epoch_secs.saturating_sub(20),
        0,
        0,
    )
    .await;
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert_eq!(current_writer_ids(&pool).await, vec![1, empty_writer_id]);
}

#[tokio::test]
async fn reap_draining_writers_empty_cleanup_does_not_increment_force_close_metric() {
    let pool = make_pool(128).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    insert_draining_writer(&pool, 1, now_epoch_secs.saturating_sub(60), 0, 0).await;
    insert_draining_writer(&pool, 2, now_epoch_secs.saturating_sub(50), 0, 0).await;
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert!(current_writer_ids(&pool).await.is_empty());
    assert_eq!(pool.stats.get_pool_force_close_total(), 0);
}

#[tokio::test]
async fn reap_draining_writers_handles_duplicate_force_close_requests_for_same_writer() {
    let pool = make_pool(1).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    insert_draining_writer(
        &pool,
        10,
        now_epoch_secs.saturating_sub(30),
        1,
        now_epoch_secs.saturating_sub(1),
    )
    .await;
    insert_draining_writer(
        &pool,
        20,
        now_epoch_secs.saturating_sub(20),
        1,
        now_epoch_secs.saturating_sub(1),
    )
    .await;
    let mut warn_next_allowed = HashMap::new();

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert!(current_writer_ids(&pool).await.is_empty());
}

#[tokio::test]
async fn reap_draining_writers_warn_state_never_exceeds_live_draining_population_under_churn() {
    let pool = make_pool(128).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let mut warn_next_allowed = HashMap::new();

    for wave in 0..12u64 {
        for offset in 0..9u64 {
            insert_draining_writer(
                &pool,
                wave * 100 + offset,
                now_epoch_secs.saturating_sub(120 + offset),
                1,
                0,
            )
            .await;
        }
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
        assert!(warn_next_allowed.len() <= pool.writers.read().await.len());

        let existing_writer_ids = current_writer_ids(&pool).await;
        for writer_id in existing_writer_ids.into_iter().take(4) {
            let _ = pool.remove_writer_and_close_clients(writer_id).await;
        }
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
        assert!(warn_next_allowed.len() <= pool.writers.read().await.len());
    }
}

#[tokio::test]
async fn reap_draining_writers_mixed_backlog_converges_without_leaking_warn_state() {
    let pool = make_pool(6).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let mut warn_next_allowed = HashMap::new();

    for writer_id in 1..=18u64 {
        let bound_clients = if writer_id % 3 == 0 { 0 } else { 1 };
        let deadline = if writer_id % 2 == 0 {
            now_epoch_secs.saturating_sub(1)
        } else {
            0
        };
        insert_draining_writer(
            &pool,
            writer_id,
            now_epoch_secs.saturating_sub(300).saturating_add(writer_id),
            bound_clients,
            deadline,
        )
        .await;
    }

    for _ in 0..16 {
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
        if pool.writers.read().await.len() <= 6 {
            break;
        }
    }

    assert!(pool.writers.read().await.len() <= 6);
    assert!(warn_next_allowed.len() <= pool.writers.read().await.len());
}

#[test]
fn general_config_default_drain_threshold_remains_enabled() {
    assert_eq!(GeneralConfig::default().me_pool_drain_threshold, 32);
    assert!(GeneralConfig::default().me_pool_drain_soft_evict_enabled);
    assert_eq!(
        GeneralConfig::default().me_pool_drain_soft_evict_grace_secs,
        10
    );
    assert_eq!(
        GeneralConfig::default().me_pool_drain_soft_evict_per_writer,
        2
    );
    assert_eq!(
        GeneralConfig::default().me_pool_drain_soft_evict_budget_per_core,
        16
    );
    assert_eq!(
        GeneralConfig::default().me_pool_drain_soft_evict_cooldown_ms,
        1000
    );
    assert_eq!(
        GeneralConfig::default().me_bind_stale_mode,
        MeBindStaleMode::Never
    );
}

#[tokio::test]
async fn prune_closed_writers_closes_bound_clients_when_writer_is_non_empty() {
    let pool = make_pool(128).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let conn_ids =
        insert_draining_writer(&pool, 910, now_epoch_secs.saturating_sub(60), 1, 0).await;

    pool.prune_closed_writers().await;

    assert!(!writer_exists(&pool, 910).await);
    assert!(pool.registry.get_writer(conn_ids[0]).await.is_none());
}
