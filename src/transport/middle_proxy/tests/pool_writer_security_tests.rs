use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::codec::WriterCommand;
use super::pool::{MePool, MeWriter, WriterContour};
use super::registry::ConnMeta;
use crate::config::{GeneralConfig, MeRouteNoWriterMode, MeSocksKdfPolicy, MeWriterPickMode};
use crate::crypto::SecureRandom;
use crate::network::probe::NetworkDecision;
use crate::stats::Stats;

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

async fn insert_writer(
    pool: &Arc<MePool>,
    writer_id: u64,
    writer_dc: i32,
    addr: SocketAddr,
    draining: bool,
    created_at: Instant,
) {
    let (tx, _rx) = mpsc::channel::<WriterCommand>(8);
    let contour = if draining {
        WriterContour::Draining
    } else {
        WriterContour::Active
    };
    let writer = MeWriter {
        id: writer_id,
        addr,
        source_ip: addr.ip(),
        writer_dc,
        generation: pool.current_generation(),
        contour: Arc::new(AtomicU8::new(contour.as_u8())),
        created_at,
        tx: tx.clone(),
        cancel: CancellationToken::new(),
        degraded: Arc::new(AtomicBool::new(false)),
        rtt_ema_ms_x10: Arc::new(AtomicU32::new(0)),
        draining: Arc::new(AtomicBool::new(draining)),
        draining_started_at_epoch_secs: Arc::new(AtomicU64::new(0)),
        drain_deadline_epoch_secs: Arc::new(AtomicU64::new(0)),
        allow_drain_fallback: Arc::new(AtomicBool::new(false)),
    };

    pool.writers.write().await.push(writer);
    pool.registry.register_writer(writer_id, tx).await;
    pool.conn_count.fetch_add(1, Ordering::Relaxed);
}

async fn current_writer_ids(pool: &Arc<MePool>) -> HashSet<u64> {
    pool.writers
        .read()
        .await
        .iter()
        .map(|writer| writer.id)
        .collect()
}

async fn bind_conn_to_writer(pool: &Arc<MePool>, writer_id: u64, port: u16) -> u64 {
    let (conn_id, _rx) = pool.registry.register().await;
    let bound = pool
        .registry
        .bind_writer(
            conn_id,
            writer_id,
            ConnMeta {
                target_dc: 2,
                client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                our_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
                proto_flags: 0,
            },
        )
        .await;
    assert!(bound, "writer binding must succeed");
    conn_id
}

#[tokio::test]
async fn remove_draining_writer_still_quarantines_flapping_endpoint() {
    let pool = make_pool().await;
    let writer_id = 77;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 12, 0, 77)), 443);
    insert_writer(
        &pool,
        writer_id,
        2,
        addr,
        true,
        Instant::now() - Duration::from_secs(1),
    )
    .await;

    pool.remove_writer_and_close_clients(writer_id).await;

    let writer_still_present = pool
        .writers
        .read()
        .await
        .iter()
        .any(|writer| writer.id == writer_id);
    assert!(
        !writer_still_present,
        "writer must be removed from pool after cleanup"
    );
    assert!(
        pool.is_endpoint_quarantined(addr).await,
        "draining removals must still quarantine flapping endpoints"
    );
    assert_eq!(pool.conn_count.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn positive_remove_writer_cleans_bound_registry_routes() {
    let pool = make_pool().await;
    let writer_id = 88;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 12, 0, 88)), 443);
    insert_writer(&pool, writer_id, 2, addr, false, Instant::now()).await;

    let conn_id = bind_conn_to_writer(&pool, writer_id, 7301).await;
    assert!(pool.registry.get_writer(conn_id).await.is_some());

    pool.remove_writer_and_close_clients(writer_id).await;

    assert!(pool.registry.get_writer(conn_id).await.is_none());
    assert!(!current_writer_ids(&pool).await.contains(&writer_id));
    assert_eq!(pool.conn_count.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn negative_unknown_writer_removal_is_noop() {
    let pool = make_pool().await;
    let before_quarantine = pool.stats.get_me_endpoint_quarantine_total();

    pool.remove_writer_and_close_clients(9_999_001).await;

    assert!(pool.writers.read().await.is_empty());
    assert_eq!(pool.conn_count.load(Ordering::Relaxed), 0);
    assert_eq!(
        pool.stats.get_me_endpoint_quarantine_total(),
        before_quarantine
    );
}

#[tokio::test]
async fn edge_draining_only_detach_rejects_active_writer() {
    let pool = make_pool().await;
    let writer_id = 91;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 12, 0, 91)), 443);
    insert_writer(&pool, writer_id, 2, addr, false, Instant::now()).await;

    let removed = pool.remove_draining_writer_hard_detach(writer_id).await;
    assert!(
        !removed,
        "active writer must not be detached by draining-only path"
    );
    assert!(current_writer_ids(&pool).await.contains(&writer_id));
    assert_eq!(pool.conn_count.load(Ordering::Relaxed), 1);

    pool.remove_writer_and_close_clients(writer_id).await;
}

#[tokio::test]
async fn adversarial_blackhat_single_remove_establishes_single_quarantine_entry() {
    let pool = make_pool().await;
    let writer_id = 93;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 12, 0, 93)), 443);
    insert_writer(
        &pool,
        writer_id,
        2,
        addr,
        true,
        Instant::now() - Duration::from_secs(1),
    )
    .await;

    pool.remove_writer_and_close_clients(writer_id).await;
    assert!(pool.is_endpoint_quarantined(addr).await);
    assert_eq!(pool.endpoint_quarantine.lock().await.len(), 1);
}

#[tokio::test]
async fn integration_old_uptime_writer_does_not_trigger_flap_quarantine() {
    let pool = make_pool().await;
    let writer_id = 94;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 12, 0, 94)), 443);
    insert_writer(
        &pool,
        writer_id,
        2,
        addr,
        false,
        Instant::now() - Duration::from_secs(30),
    )
    .await;

    let before = pool.stats.get_me_endpoint_quarantine_total();
    pool.remove_writer_and_close_clients(writer_id).await;
    let after = pool.stats.get_me_endpoint_quarantine_total();

    assert_eq!(after, before);
    assert!(!pool.is_endpoint_quarantined(addr).await);
}

#[tokio::test]
async fn light_fuzz_insert_remove_schedule_preserves_pool_invariants() {
    let pool = make_pool().await;
    let mut seed = 0xA11C_E551_D00D_BAADu64;
    let mut model = HashSet::<u64>::new();

    for _ in 0..240 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let writer_id = 1 + (seed % 64);
        let op_insert = ((seed >> 17) & 1) == 0;

        if op_insert {
            if !model.contains(&writer_id) {
                let ip_octet = (writer_id % 250) as u8;
                let addr = SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 13, 0, ip_octet.max(1))),
                    4000 + writer_id as u16,
                );
                let draining = ((seed >> 33) & 1) == 1;
                let created_at = if draining {
                    Instant::now() - Duration::from_secs(1)
                } else {
                    Instant::now() - Duration::from_secs(30)
                };
                insert_writer(&pool, writer_id, 2, addr, draining, created_at).await;
                model.insert(writer_id);
            }
        } else {
            pool.remove_writer_and_close_clients(writer_id).await;
            model.remove(&writer_id);
        }

        let actual_ids = current_writer_ids(&pool).await;
        assert_eq!(
            actual_ids, model,
            "writer-id set must match model under fuzz schedule"
        );
        assert_eq!(
            pool.conn_count.load(Ordering::Relaxed) as usize,
            model.len()
        );
    }

    for writer_id in model {
        pool.remove_writer_and_close_clients(writer_id).await;
    }
    assert!(pool.writers.read().await.is_empty());
    assert_eq!(pool.conn_count.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_parallel_duplicate_removals_are_idempotent() {
    let pool = make_pool().await;

    for writer_id in 1..=48u64 {
        let addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                127,
                14,
                (writer_id / 250) as u8,
                (writer_id % 250) as u8,
            )),
            5000 + writer_id as u16,
        );
        insert_writer(
            &pool,
            writer_id,
            2,
            addr,
            true,
            Instant::now() - Duration::from_secs(1),
        )
        .await;
    }

    let mut tasks = Vec::new();
    for worker in 0..8u64 {
        let pool = Arc::clone(&pool);
        tasks.push(tokio::spawn(async move {
            for writer_id in 1..=48u64 {
                if ((writer_id + worker) & 1) == 0 {
                    pool.remove_writer_and_close_clients(writer_id).await;
                } else {
                    pool.remove_writer_and_close_clients(100_000 + writer_id)
                        .await;
                }
            }
        }));
    }

    for task in tasks {
        task.await.expect("stress remover task must not panic");
    }

    for writer_id in 1..=48u64 {
        pool.remove_writer_and_close_clients(writer_id).await;
    }

    assert!(pool.writers.read().await.is_empty());
    assert_eq!(pool.conn_count.load(Ordering::Relaxed), 0);
}
