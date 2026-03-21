use std::collections::HashMap;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::codec::WriterCommand;
use super::health::{health_drain_close_budget, reap_draining_writers};
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
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6000 + writer_id as u16),
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
                            8000 + idx as u16,
                        ),
                        our_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
                        proto_flags: 0,
                    },
                )
                .await
        );
    }
}

async fn writer_count(pool: &Arc<MePool>) -> usize {
    pool.writers.read().await.len()
}

async fn sorted_writer_ids(pool: &Arc<MePool>) -> Vec<u64> {
    let mut ids = pool
        .writers
        .read()
        .await
        .iter()
        .map(|writer| writer.id)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids
}

fn lcg_next(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
    *state
}

async fn draining_writer_ids(pool: &Arc<MePool>) -> HashSet<u64> {
    pool.writers
        .read()
        .await
        .iter()
        .filter(|writer| writer.draining.load(Ordering::Relaxed))
        .map(|writer| writer.id)
        .collect::<HashSet<u64>>()
}

async fn set_writer_runtime_state(
    pool: &Arc<MePool>,
    writer_id: u64,
    draining: bool,
    drain_started_at_epoch_secs: u64,
    drain_deadline_epoch_secs: u64,
) {
    let writers = pool.writers.read().await;
    if let Some(writer) = writers.iter().find(|writer| writer.id == writer_id) {
        writer.draining.store(draining, Ordering::Relaxed);
        writer
            .draining_started_at_epoch_secs
            .store(drain_started_at_epoch_secs, Ordering::Relaxed);
        writer
            .drain_deadline_epoch_secs
            .store(drain_deadline_epoch_secs, Ordering::Relaxed);
    }
}

#[tokio::test]
async fn reap_draining_writers_clears_warn_state_when_pool_empty() {
    let (pool, _rng) = make_pool(128, 1, 1).await;
    let mut warn_next_allowed = HashMap::new();
    warn_next_allowed.insert(11, Instant::now() + Duration::from_secs(5));
    warn_next_allowed.insert(22, Instant::now() + Duration::from_secs(5));

    reap_draining_writers(&pool, &mut warn_next_allowed).await;

    assert!(warn_next_allowed.is_empty());
}

#[tokio::test]
async fn reap_draining_writers_respects_threshold_across_multiple_overflow_cycles() {
    let threshold = 3u64;
    let (pool, _rng) = make_pool(threshold, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();

    for writer_id in 1..=60u64 {
        insert_draining_writer(&pool, writer_id, now_epoch_secs.saturating_sub(20), 1, 0).await;
    }

    let mut warn_next_allowed = HashMap::new();
    for _ in 0..64 {
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
        if writer_count(&pool).await <= threshold as usize {
            break;
        }
    }

    assert_eq!(writer_count(&pool).await, threshold as usize);
    assert_eq!(sorted_writer_ids(&pool).await, vec![1, 2, 3]);
}

#[tokio::test]
async fn reap_draining_writers_handles_large_empty_writer_population() {
    let (pool, _rng) = make_pool(128, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let total = health_drain_close_budget()
        .saturating_mul(3)
        .saturating_add(27);

    for writer_id in 1..=total as u64 {
        insert_draining_writer(&pool, writer_id, now_epoch_secs.saturating_sub(120), 0, 0).await;
    }

    let mut warn_next_allowed = HashMap::new();
    for _ in 0..24 {
        if writer_count(&pool).await == 0 {
            break;
        }
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
    }

    assert_eq!(writer_count(&pool).await, 0);
}

#[tokio::test]
async fn reap_draining_writers_processes_mass_deadline_expiry_without_unbounded_growth() {
    let (pool, _rng) = make_pool(128, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let total = health_drain_close_budget()
        .saturating_mul(4)
        .saturating_add(31);

    for writer_id in 1..=total as u64 {
        insert_draining_writer(
            &pool,
            writer_id,
            now_epoch_secs.saturating_sub(180),
            1,
            now_epoch_secs.saturating_sub(1),
        )
        .await;
    }

    let mut warn_next_allowed = HashMap::new();
    for _ in 0..40 {
        if writer_count(&pool).await == 0 {
            break;
        }
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
    }

    assert_eq!(writer_count(&pool).await, 0);
}

#[tokio::test]
async fn reap_draining_writers_maintains_warn_state_subset_property_under_bulk_churn() {
    let (pool, _rng) = make_pool(128, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();
    let mut warn_next_allowed = HashMap::new();

    for wave in 0..40u64 {
        for offset in 0..8u64 {
            insert_draining_writer(
                &pool,
                wave * 100 + offset,
                now_epoch_secs.saturating_sub(400 + offset),
                1,
                0,
            )
            .await;
        }

        reap_draining_writers(&pool, &mut warn_next_allowed).await;
        assert!(warn_next_allowed.len() <= writer_count(&pool).await);

        let ids = sorted_writer_ids(&pool).await;
        for writer_id in ids.into_iter().take(3) {
            let _ = pool.remove_writer_and_close_clients(writer_id).await;
        }

        reap_draining_writers(&pool, &mut warn_next_allowed).await;
        assert!(warn_next_allowed.len() <= writer_count(&pool).await);
    }
}

#[tokio::test]
async fn reap_draining_writers_budgeted_cleanup_never_increases_pool_size() {
    let (pool, _rng) = make_pool(5, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();

    for writer_id in 1..=200u64 {
        insert_draining_writer(
            &pool,
            writer_id,
            now_epoch_secs.saturating_sub(240).saturating_add(writer_id),
            1,
            0,
        )
        .await;
    }

    let mut warn_next_allowed = HashMap::new();
    let mut previous = writer_count(&pool).await;
    for _ in 0..32 {
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
        let current = writer_count(&pool).await;
        assert!(current <= previous);
        previous = current;
    }
}

#[tokio::test]
async fn me_health_monitor_converges_to_threshold_under_live_injection_churn() {
    let threshold = 7u64;
    let (pool, rng) = make_pool(threshold, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();

    for writer_id in 1..=40u64 {
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

    for wave in 0..8u64 {
        for offset in 0..10u64 {
            insert_draining_writer(
                &pool,
                1000 + wave * 100 + offset,
                now_epoch_secs.saturating_sub(120).saturating_add(offset),
                1,
                0,
            )
            .await;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    tokio::time::sleep(Duration::from_millis(120)).await;
    monitor.abort();
    let _ = monitor.await;

    assert!(writer_count(&pool).await <= threshold as usize);
}

#[tokio::test]
async fn me_health_monitor_drains_deadline_storm_with_budgeted_progress() {
    let (pool, rng) = make_pool(128, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();

    for writer_id in 1..=220u64 {
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
    tokio::time::sleep(Duration::from_millis(120)).await;
    monitor.abort();
    let _ = monitor.await;

    assert_eq!(writer_count(&pool).await, 0);
}

#[tokio::test]
async fn me_health_monitor_eliminates_mixed_empty_and_deadline_backlog() {
    let threshold = 12u64;
    let (pool, rng) = make_pool(threshold, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();

    for writer_id in 1..=180u64 {
        let bound_clients = if writer_id % 3 == 0 { 0 } else { 1 };
        let deadline = if writer_id % 2 == 0 {
            now_epoch_secs.saturating_sub(1)
        } else {
            0
        };
        insert_draining_writer(
            &pool,
            writer_id,
            now_epoch_secs.saturating_sub(250).saturating_add(writer_id),
            bound_clients,
            deadline,
        )
        .await;
    }

    let monitor = tokio::spawn(me_health_monitor(pool.clone(), rng, 0));
    tokio::time::sleep(Duration::from_millis(140)).await;
    monitor.abort();
    let _ = monitor.await;

    assert!(writer_count(&pool).await <= threshold as usize);
}

#[tokio::test]
async fn reap_draining_writers_deterministic_mixed_state_churn_preserves_invariants() {
    let threshold = 9u64;
    let (pool, _rng) = make_pool(threshold, 1, 1).await;
    let mut warn_next_allowed = HashMap::new();
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut next_writer_id = 20_000u64;
    let now_epoch_secs = MePool::now_epoch_secs();

    for writer_id in 1..=72u64 {
        let bound_clients = if writer_id % 4 == 0 { 0 } else { 1 };
        let deadline = if writer_id % 5 == 0 {
            now_epoch_secs.saturating_sub(1)
        } else {
            0
        };
        insert_draining_writer(
            &pool,
            writer_id,
            now_epoch_secs.saturating_sub(500).saturating_add(writer_id),
            bound_clients,
            deadline,
        )
        .await;
    }

    for _round in 0..90 {
        reap_draining_writers(&pool, &mut warn_next_allowed).await;

        let draining_ids = draining_writer_ids(&pool).await;
        assert!(
            warn_next_allowed.keys().all(|id| draining_ids.contains(id)),
            "warn-state keys must always be a subset of live draining writers"
        );

        let writer_ids = sorted_writer_ids(&pool).await;
        if writer_ids.is_empty() {
            continue;
        }

        let remove_n = (lcg_next(&mut seed) % 3) as usize;
        for writer_id in writer_ids.iter().copied().take(remove_n) {
            let _ = pool.remove_writer_and_close_clients(writer_id).await;
        }

        let survivors = sorted_writer_ids(&pool).await;
        if !survivors.is_empty() {
            let idx = (lcg_next(&mut seed) as usize) % survivors.len();
            let target = survivors[idx];
            set_writer_runtime_state(&pool, target, false, 0, 0).await;
        }

        let survivors = sorted_writer_ids(&pool).await;
        if survivors.len() > 1 {
            let idx = (lcg_next(&mut seed) as usize) % survivors.len();
            let target = survivors[idx];
            let expired_deadline = if lcg_next(&mut seed) & 1 == 0 {
                now_epoch_secs.saturating_sub(1)
            } else {
                0
            };
            set_writer_runtime_state(
                &pool,
                target,
                true,
                now_epoch_secs.saturating_sub(120),
                expired_deadline,
            )
            .await;
        }

        let inject_n = (lcg_next(&mut seed) % 4) as usize;
        for _ in 0..inject_n {
            let bound_clients = if lcg_next(&mut seed) & 1 == 0 { 0 } else { 1 };
            let deadline = if lcg_next(&mut seed) & 1 == 0 {
                now_epoch_secs.saturating_sub(1)
            } else {
                0
            };
            insert_draining_writer(
                &pool,
                next_writer_id,
                now_epoch_secs.saturating_sub(240),
                bound_clients,
                deadline,
            )
            .await;
            next_writer_id = next_writer_id.saturating_add(1);
        }
    }

    for _ in 0..64 {
        reap_draining_writers(&pool, &mut warn_next_allowed).await;
        if writer_count(&pool).await <= threshold as usize {
            break;
        }
    }

    assert!(writer_count(&pool).await <= threshold as usize);
    let draining_ids = draining_writer_ids(&pool).await;
    assert!(warn_next_allowed.keys().all(|id| draining_ids.contains(id)));
}

#[tokio::test]
async fn reap_draining_writers_repeated_draining_flips_never_leave_stale_warn_state() {
    let (pool, _rng) = make_pool(64, 1, 1).await;
    let now_epoch_secs = MePool::now_epoch_secs();

    for writer_id in 1..=24u64 {
        insert_draining_writer(&pool, writer_id, now_epoch_secs.saturating_sub(240), 1, 0).await;
    }

    let mut warn_next_allowed = HashMap::new();
    for _round in 0..48u64 {
        for writer_id in 1..=24u64 {
            let draining = (writer_id + _round) % 3 != 0;
            set_writer_runtime_state(
                &pool,
                writer_id,
                draining,
                now_epoch_secs.saturating_sub(120),
                0,
            )
            .await;
        }

        reap_draining_writers(&pool, &mut warn_next_allowed).await;

        let draining_ids = draining_writer_ids(&pool).await;
        assert!(
            warn_next_allowed.keys().all(|id| draining_ids.contains(id)),
            "warn-state map must not retain entries for writers outside draining set"
        );
    }
}

#[test]
fn health_drain_close_budget_is_within_expected_bounds() {
    let budget = health_drain_close_budget();
    assert!((16..=256).contains(&budget));
}
