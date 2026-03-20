use std::collections::HashMap;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::Rng;
use tracing::{debug, info, warn};

use crate::config::MeFloorMode;
use crate::crypto::SecureRandom;
use crate::network::IpFamily;
use crate::stats::MeWriterTeardownReason;

use super::MePool;
use super::pool::{MeFamilyRuntimeState, MeWriter};

const JITTER_FRAC_NUM: u64 = 2; // jitter up to 50% of backoff
#[allow(dead_code)]
const MAX_CONCURRENT_PER_DC_DEFAULT: usize = 1;
const SHADOW_ROTATE_RETRY_SECS: u64 = 30;
const IDLE_REFRESH_TRIGGER_BASE_SECS: u64 = 45;
const IDLE_REFRESH_TRIGGER_JITTER_SECS: u64 = 5;
const IDLE_REFRESH_RETRY_SECS: u64 = 8;
const IDLE_REFRESH_SUCCESS_GUARD_SECS: u64 = 5;
const HEALTH_RECONNECT_BUDGET_PER_CORE: usize = 2;
const HEALTH_RECONNECT_BUDGET_PER_DC: usize = 1;
const HEALTH_RECONNECT_BUDGET_MIN: usize = 4;
const HEALTH_RECONNECT_BUDGET_MAX: usize = 128;
const HEALTH_DRAIN_CLOSE_BUDGET_PER_CORE: usize = 16;
const HEALTH_DRAIN_CLOSE_BUDGET_MIN: usize = 16;
const HEALTH_DRAIN_CLOSE_BUDGET_MAX: usize = 256;
const HEALTH_DRAIN_SOFT_EVICT_BUDGET_MIN: usize = 8;
const HEALTH_DRAIN_SOFT_EVICT_BUDGET_MAX: usize = 256;
const HEALTH_DRAIN_REAP_OPPORTUNISTIC_INTERVAL_SECS: u64 = 1;
const HEALTH_DRAIN_TIMEOUT_ENFORCER_INTERVAL_SECS: u64 = 1;
const FAMILY_SUPPRESS_FAIL_STREAK_THRESHOLD: u32 = 6;
const FAMILY_SUPPRESS_WINDOW_SECS: u64 = 120;
const FAMILY_RECOVER_PROBE_INTERVAL_SECS: u64 = 5;
const FAMILY_RECOVER_SUCCESS_STREAK_REQUIRED: u32 = 3;

#[derive(Debug, Clone)]
struct FamilyCircuitState {
    state: MeFamilyRuntimeState,
    state_since_at: Instant,
    suppressed_until: Option<Instant>,
    next_probe_at: Instant,
    fail_streak: u32,
    recover_success_streak: u32,
}

impl FamilyCircuitState {
    fn new(now: Instant) -> Self {
        Self {
            state: MeFamilyRuntimeState::Healthy,
            state_since_at: now,
            suppressed_until: None,
            next_probe_at: now,
            fail_streak: 0,
            recover_success_streak: 0,
        }
    }
}

#[derive(Debug, Clone)]
struct DcFloorPlanEntry {
    dc: i32,
    endpoints: Vec<SocketAddr>,
    alive: usize,
    min_required: usize,
    target_required: usize,
    max_required: usize,
    has_bound_clients: bool,
    floor_capped: bool,
}

#[derive(Debug, Clone)]
struct FamilyFloorPlan {
    by_dc: HashMap<i32, DcFloorPlanEntry>,
    active_cap_configured_total: usize,
    active_cap_effective_total: usize,
    warm_cap_configured_total: usize,
    warm_cap_effective_total: usize,
    active_writers_current: usize,
    warm_writers_current: usize,
    target_writers_total: usize,
}

pub async fn me_health_monitor(pool: Arc<MePool>, rng: Arc<SecureRandom>, _min_connections: usize) {
    let mut backoff: HashMap<(i32, IpFamily), u64> = HashMap::new();
    let mut next_attempt: HashMap<(i32, IpFamily), Instant> = HashMap::new();
    let mut inflight: HashMap<(i32, IpFamily), usize> = HashMap::new();
    let mut outage_backoff: HashMap<(i32, IpFamily), u64> = HashMap::new();
    let mut outage_next_attempt: HashMap<(i32, IpFamily), Instant> = HashMap::new();
    let mut single_endpoint_outage: HashSet<(i32, IpFamily)> = HashSet::new();
    let mut shadow_rotate_deadline: HashMap<(i32, IpFamily), Instant> = HashMap::new();
    let mut idle_refresh_next_attempt: HashMap<(i32, IpFamily), Instant> = HashMap::new();
    let mut adaptive_idle_since: HashMap<(i32, IpFamily), Instant> = HashMap::new();
    let mut adaptive_recover_until: HashMap<(i32, IpFamily), Instant> = HashMap::new();
    let mut floor_warn_next_allowed: HashMap<(i32, IpFamily), Instant> = HashMap::new();
    let mut drain_warn_next_allowed: HashMap<u64, Instant> = HashMap::new();
    let mut drain_soft_evict_next_allowed: HashMap<u64, Instant> = HashMap::new();
    let mut family_v4_circuit = FamilyCircuitState::new(Instant::now());
    let mut family_v6_circuit = FamilyCircuitState::new(Instant::now());
    let init_epoch_secs = MePool::now_epoch_secs();
    pool.set_family_runtime_state(
        IpFamily::V4,
        family_v4_circuit.state,
        init_epoch_secs,
        0,
        family_v4_circuit.fail_streak,
        family_v4_circuit.recover_success_streak,
    );
    pool.set_family_runtime_state(
        IpFamily::V6,
        family_v6_circuit.state,
        init_epoch_secs,
        0,
        family_v6_circuit.fail_streak,
        family_v6_circuit.recover_success_streak,
    );
    let mut degraded_interval = true;
    loop {
        let interval = if degraded_interval {
            pool.health_interval_unhealthy()
        } else {
            pool.health_interval_healthy()
        };
        tokio::time::sleep(interval).await;
        pool.prune_closed_writers().await;
        reap_draining_writers(
            &pool,
            &mut drain_warn_next_allowed,
            &mut drain_soft_evict_next_allowed,
        )
        .await;
        let now = Instant::now();
        let now_epoch_secs = MePool::now_epoch_secs();
        let v4_degraded_raw = check_family(
            IpFamily::V4,
            &pool,
            &rng,
            &mut backoff,
            &mut next_attempt,
            &mut inflight,
            &mut outage_backoff,
            &mut outage_next_attempt,
            &mut single_endpoint_outage,
            &mut shadow_rotate_deadline,
            &mut idle_refresh_next_attempt,
            &mut adaptive_idle_since,
            &mut adaptive_recover_until,
            &mut floor_warn_next_allowed,
            &mut drain_warn_next_allowed,
            &mut drain_soft_evict_next_allowed,
        )
        .await;
        let v4_degraded = apply_family_circuit_result(
            &pool,
            IpFamily::V4,
            &mut family_v4_circuit,
            Some(v4_degraded_raw),
            false,
            now,
            now_epoch_secs,
        );

        let v6_check_ran = should_run_family_check(&mut family_v6_circuit, now);
        let v6_degraded_raw = if v6_check_ran {
            check_family(
                IpFamily::V6,
                &pool,
                &rng,
                &mut backoff,
                &mut next_attempt,
                &mut inflight,
                &mut outage_backoff,
                &mut outage_next_attempt,
                &mut single_endpoint_outage,
                &mut shadow_rotate_deadline,
                &mut idle_refresh_next_attempt,
                &mut adaptive_idle_since,
                &mut adaptive_recover_until,
                &mut floor_warn_next_allowed,
                &mut drain_warn_next_allowed,
                &mut drain_soft_evict_next_allowed,
            )
            .await
        } else {
            false
        };
        let v6_degraded = apply_family_circuit_result(
            &pool,
            IpFamily::V6,
            &mut family_v6_circuit,
            if v6_check_ran {
                Some(v6_degraded_raw)
            } else {
                None
            },
            true,
            now,
            now_epoch_secs,
        );
        degraded_interval = v4_degraded || v6_degraded;
    }
}

pub async fn me_drain_timeout_enforcer(pool: Arc<MePool>) {
    let mut drain_warn_next_allowed: HashMap<u64, Instant> = HashMap::new();
    let mut drain_soft_evict_next_allowed: HashMap<u64, Instant> = HashMap::new();
    loop {
        tokio::time::sleep(Duration::from_secs(
            HEALTH_DRAIN_TIMEOUT_ENFORCER_INTERVAL_SECS,
        ))
        .await;
        reap_draining_writers(
            &pool,
            &mut drain_warn_next_allowed,
            &mut drain_soft_evict_next_allowed,
        )
        .await;
    }
}

fn should_run_family_check(circuit: &mut FamilyCircuitState, now: Instant) -> bool {
    match circuit.state {
        MeFamilyRuntimeState::Suppressed => {
            if now < circuit.next_probe_at {
                return false;
            }
            circuit.next_probe_at =
                now + Duration::from_secs(FAMILY_RECOVER_PROBE_INTERVAL_SECS);
            true
        }
        _ => true,
    }
}

fn apply_family_circuit_result(
    pool: &Arc<MePool>,
    family: IpFamily,
    circuit: &mut FamilyCircuitState,
    degraded: Option<bool>,
    allow_suppress: bool,
    now: Instant,
    now_epoch_secs: u64,
) -> bool {
    let Some(degraded) = degraded else {
        // Preserve suppression state when probe tick is intentionally skipped.
        return false;
    };

    let previous_state = circuit.state;
    match circuit.state {
        MeFamilyRuntimeState::Suppressed => {
            if degraded {
                circuit.fail_streak = circuit.fail_streak.saturating_add(1);
                circuit.recover_success_streak = 0;
                let until = now + Duration::from_secs(FAMILY_SUPPRESS_WINDOW_SECS);
                circuit.suppressed_until = Some(until);
                circuit.state_since_at = now;
                warn!(
                    ?family,
                    fail_streak = circuit.fail_streak,
                    suppress_secs = FAMILY_SUPPRESS_WINDOW_SECS,
                    "ME family remains suppressed due to ongoing failures"
                );
            } else {
                circuit.fail_streak = 0;
                circuit.recover_success_streak = 1;
                circuit.state = MeFamilyRuntimeState::Recovering;
            }
        }
        MeFamilyRuntimeState::Recovering => {
            if degraded {
                circuit.fail_streak = circuit.fail_streak.saturating_add(1);
                if allow_suppress {
                    circuit.state = MeFamilyRuntimeState::Suppressed;
                    let until = now + Duration::from_secs(FAMILY_SUPPRESS_WINDOW_SECS);
                    circuit.suppressed_until = Some(until);
                    circuit.next_probe_at =
                        now + Duration::from_secs(FAMILY_RECOVER_PROBE_INTERVAL_SECS);
                    warn!(
                        ?family,
                        fail_streak = circuit.fail_streak,
                        suppress_secs = FAMILY_SUPPRESS_WINDOW_SECS,
                        "ME family temporarily suppressed after repeated degradation"
                    );
                } else {
                    circuit.state = MeFamilyRuntimeState::Degraded;
                }
            } else {
                circuit.recover_success_streak = circuit.recover_success_streak.saturating_add(1);
                if circuit.recover_success_streak >= FAMILY_RECOVER_SUCCESS_STREAK_REQUIRED {
                    circuit.fail_streak = 0;
                    circuit.recover_success_streak = 0;
                    circuit.suppressed_until = None;
                    circuit.state = MeFamilyRuntimeState::Healthy;
                    info!(
                        ?family,
                        "ME family suppression lifted after stable recovery probes"
                    );
                }
            }
        }
        _ => {
            if degraded {
                circuit.fail_streak = circuit.fail_streak.saturating_add(1);
                circuit.recover_success_streak = 0;
                circuit.state = MeFamilyRuntimeState::Degraded;
                if allow_suppress && circuit.fail_streak >= FAMILY_SUPPRESS_FAIL_STREAK_THRESHOLD {
                    circuit.state = MeFamilyRuntimeState::Suppressed;
                    let until = now + Duration::from_secs(FAMILY_SUPPRESS_WINDOW_SECS);
                    circuit.suppressed_until = Some(until);
                    circuit.next_probe_at =
                        now + Duration::from_secs(FAMILY_RECOVER_PROBE_INTERVAL_SECS);
                    warn!(
                        ?family,
                        fail_streak = circuit.fail_streak,
                        suppress_secs = FAMILY_SUPPRESS_WINDOW_SECS,
                        "ME family temporarily suppressed after repeated degradation"
                    );
                }
            } else {
                circuit.fail_streak = 0;
                circuit.recover_success_streak = 0;
                circuit.suppressed_until = None;
                circuit.state = MeFamilyRuntimeState::Healthy;
            }
        }
    }

    if previous_state != circuit.state {
        circuit.state_since_at = now;
    }

    let suppressed_until_epoch_secs = circuit
        .suppressed_until
        .and_then(|until| {
            if until > now {
                Some(
                    now_epoch_secs
                        .saturating_add(until.saturating_duration_since(now).as_secs()),
                )
            } else {
                None
            }
        })
        .unwrap_or(0);
    let state_since_epoch_secs = if previous_state == circuit.state {
        pool.family_runtime_state_since_epoch_secs(family)
    } else {
        now_epoch_secs
    };
    pool.set_family_runtime_state(
        family,
        circuit.state,
        state_since_epoch_secs,
        suppressed_until_epoch_secs,
        circuit.fail_streak,
        circuit.recover_success_streak,
    );

    !matches!(circuit.state, MeFamilyRuntimeState::Suppressed) && degraded
}

fn draining_writer_timeout_expired(
    pool: &MePool,
    writer: &MeWriter,
    now_epoch_secs: u64,
    drain_ttl_secs: u64,
) -> bool {
    if pool
        .me_instadrain
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return true;
    }

    let deadline_epoch_secs = writer
        .drain_deadline_epoch_secs
        .load(std::sync::atomic::Ordering::Relaxed);
    if deadline_epoch_secs != 0 {
        return now_epoch_secs >= deadline_epoch_secs;
    }

    if drain_ttl_secs == 0 {
        return false;
    }
    let drain_started_at_epoch_secs = writer
        .draining_started_at_epoch_secs
        .load(std::sync::atomic::Ordering::Relaxed);
    if drain_started_at_epoch_secs == 0 {
        return false;
    }
    now_epoch_secs.saturating_sub(drain_started_at_epoch_secs) > drain_ttl_secs
}

pub(super) async fn reap_draining_writers(
    pool: &Arc<MePool>,
    warn_next_allowed: &mut HashMap<u64, Instant>,
    soft_evict_next_allowed: &mut HashMap<u64, Instant>,
) {
    let now_epoch_secs = MePool::now_epoch_secs();
    let now = Instant::now();
    let drain_ttl_secs = pool.me_pool_drain_ttl_secs.load(std::sync::atomic::Ordering::Relaxed);
    let drain_threshold = pool
        .me_pool_drain_threshold
        .load(std::sync::atomic::Ordering::Relaxed);
    let writers = pool.writers.read().await.clone();
    let activity = pool.registry.writer_activity_snapshot().await;
    let mut draining_writers = Vec::new();
    let mut empty_writer_ids = Vec::<u64>::new();
    let mut timeout_expired_writer_ids = Vec::<u64>::new();
    let mut force_close_writer_ids = Vec::<u64>::new();
    for writer in writers {
        if !writer.draining.load(std::sync::atomic::Ordering::Relaxed) {
            continue;
        }
        if draining_writer_timeout_expired(pool, &writer, now_epoch_secs, drain_ttl_secs) {
            timeout_expired_writer_ids.push(writer.id);
            continue;
        }
        if activity
            .bound_clients_by_writer
            .get(&writer.id)
            .copied()
            .unwrap_or(0)
            == 0
        {
            empty_writer_ids.push(writer.id);
            continue;
        }
        draining_writers.push(writer);
    }

    if drain_threshold > 0 && draining_writers.len() > drain_threshold as usize {
        draining_writers.sort_by(|left, right| {
            let left_started = left
                .draining_started_at_epoch_secs
                .load(std::sync::atomic::Ordering::Relaxed);
            let right_started = right
                .draining_started_at_epoch_secs
                .load(std::sync::atomic::Ordering::Relaxed);
            left_started
                .cmp(&right_started)
                .then_with(|| left.created_at.cmp(&right.created_at))
                .then_with(|| left.id.cmp(&right.id))
        });
        let overflow = draining_writers.len().saturating_sub(drain_threshold as usize);
        warn!(
            draining_writers = draining_writers.len(),
            me_pool_drain_threshold = drain_threshold,
            removing_writers = overflow,
            "ME draining writer threshold exceeded, force-closing oldest draining writers"
        );
        for writer in draining_writers.drain(..overflow) {
            force_close_writer_ids.push(writer.id);
        }
    }

    let mut active_draining_writer_ids = HashSet::with_capacity(draining_writers.len());
    for writer in &draining_writers {
        active_draining_writer_ids.insert(writer.id);
        let drain_started_at_epoch_secs = writer
            .draining_started_at_epoch_secs
            .load(std::sync::atomic::Ordering::Relaxed);
        if drain_ttl_secs > 0
            && drain_started_at_epoch_secs != 0
            && now_epoch_secs.saturating_sub(drain_started_at_epoch_secs) > drain_ttl_secs
            && should_emit_writer_warn(
                warn_next_allowed,
                writer.id,
                now,
                pool.warn_rate_limit_duration(),
            )
        {
            warn!(
                writer_id = writer.id,
                writer_dc = writer.writer_dc,
                endpoint = %writer.addr,
                generation = writer.generation,
                drain_ttl_secs,
                force_close_secs = pool.me_pool_force_close_secs.load(std::sync::atomic::Ordering::Relaxed),
                allow_drain_fallback = writer.allow_drain_fallback.load(std::sync::atomic::Ordering::Relaxed),
                "ME draining writer remains non-empty past drain TTL"
            );
        }
    }

    warn_next_allowed.retain(|writer_id, _| active_draining_writer_ids.contains(writer_id));
    soft_evict_next_allowed.retain(|writer_id, _| active_draining_writer_ids.contains(writer_id));

    if pool.drain_soft_evict_enabled() && drain_ttl_secs > 0 && !draining_writers.is_empty() {
        let mut force_close_ids = HashSet::<u64>::with_capacity(force_close_writer_ids.len());
        for writer_id in &force_close_writer_ids {
            force_close_ids.insert(*writer_id);
        }
        let soft_grace_secs = pool.drain_soft_evict_grace_secs();
        let soft_trigger_age_secs = drain_ttl_secs.saturating_add(soft_grace_secs);
        let per_writer_limit = pool.drain_soft_evict_per_writer();
        let soft_budget = health_drain_soft_evict_budget(pool);
        let soft_cooldown = pool.drain_soft_evict_cooldown();
        let mut soft_evicted_total = 0usize;

        for writer in &draining_writers {
            if soft_evicted_total >= soft_budget {
                break;
            }
            if force_close_ids.contains(&writer.id) {
                continue;
            }
            if pool.writer_accepts_new_binding(writer) {
                continue;
            }
            let started_epoch_secs = writer
                .draining_started_at_epoch_secs
                .load(std::sync::atomic::Ordering::Relaxed);
            if started_epoch_secs == 0
                || now_epoch_secs.saturating_sub(started_epoch_secs) < soft_trigger_age_secs
            {
                continue;
            }
            if !should_emit_writer_warn(
                soft_evict_next_allowed,
                writer.id,
                now,
                soft_cooldown,
            ) {
                continue;
            }

            let remaining_budget = soft_budget.saturating_sub(soft_evicted_total);
            let limit = per_writer_limit.min(remaining_budget);
            if limit == 0 {
                break;
            }
            let conn_ids = pool
                .registry
                .bound_conn_ids_for_writer_limited(writer.id, limit)
                .await;
            if conn_ids.is_empty() {
                continue;
            }

            let mut evicted_for_writer = 0usize;
            for conn_id in conn_ids {
                if pool.registry.evict_bound_conn_if_writer(conn_id, writer.id).await {
                    evicted_for_writer = evicted_for_writer.saturating_add(1);
                    soft_evicted_total = soft_evicted_total.saturating_add(1);
                    pool.stats.increment_pool_drain_soft_evict_total();
                    if soft_evicted_total >= soft_budget {
                        break;
                    }
                }
            }

            if evicted_for_writer > 0 {
                pool.stats.increment_pool_drain_soft_evict_writer_total();
                info!(
                    writer_id = writer.id,
                    writer_dc = writer.writer_dc,
                    endpoint = %writer.addr,
                    drained_connections = evicted_for_writer,
                    soft_budget,
                    soft_trigger_age_secs,
                    "ME draining writer soft-evicted bound clients"
                );
            }
        }
    }

    let mut closed_writer_ids = HashSet::<u64>::new();
    for writer_id in timeout_expired_writer_ids {
        if !closed_writer_ids.insert(writer_id) {
            continue;
        }
        pool.stats.increment_pool_force_close_total();
        pool.remove_writer_and_close_clients(writer_id, MeWriterTeardownReason::ReapTimeoutExpired)
            .await;
        pool.stats
            .increment_me_draining_writers_reap_progress_total();
    }

    let requested_force_close = force_close_writer_ids.len();
    let requested_empty_close = empty_writer_ids.len();
    let requested_close_total = requested_force_close.saturating_add(requested_empty_close);
    let close_budget = health_drain_close_budget();
    let mut closed_total = 0usize;
    for writer_id in force_close_writer_ids {
        if closed_total >= close_budget {
            break;
        }
        if !closed_writer_ids.insert(writer_id) {
            continue;
        }
        pool.stats.increment_pool_force_close_total();
        pool.remove_writer_and_close_clients(writer_id, MeWriterTeardownReason::ReapThresholdForce)
            .await;
        pool.stats
            .increment_me_draining_writers_reap_progress_total();
        closed_total = closed_total.saturating_add(1);
    }
    for writer_id in empty_writer_ids {
        if closed_total >= close_budget {
            break;
        }
        if !closed_writer_ids.insert(writer_id) {
            continue;
        }
        pool.remove_writer_and_close_clients(writer_id, MeWriterTeardownReason::ReapEmpty)
            .await;
        pool.stats
            .increment_me_draining_writers_reap_progress_total();
        closed_total = closed_total.saturating_add(1);
    }

    let pending_close_total = requested_close_total.saturating_sub(closed_total);
    if pending_close_total > 0 {
        warn!(
            close_budget,
            closed_total,
            pending_close_total,
            "ME draining close backlog deferred to next health cycle"
        );
    }
}

pub(super) fn health_drain_close_budget() -> usize {
    let cpu_cores = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    cpu_cores
        .saturating_mul(HEALTH_DRAIN_CLOSE_BUDGET_PER_CORE)
        .clamp(HEALTH_DRAIN_CLOSE_BUDGET_MIN, HEALTH_DRAIN_CLOSE_BUDGET_MAX)
}

pub(super) fn health_drain_soft_evict_budget(pool: &MePool) -> usize {
    let cpu_cores = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    let per_core = pool.drain_soft_evict_budget_per_core();
    cpu_cores
        .saturating_mul(per_core)
        .clamp(
            HEALTH_DRAIN_SOFT_EVICT_BUDGET_MIN,
            HEALTH_DRAIN_SOFT_EVICT_BUDGET_MAX,
        )
}

fn should_emit_writer_warn(
    next_allowed: &mut HashMap<u64, Instant>,
    writer_id: u64,
    now: Instant,
    cooldown: Duration,
) -> bool {
    let Some(ready_at) = next_allowed.get(&writer_id).copied() else {
        next_allowed.insert(writer_id, now + cooldown);
        return true;
    };
    if now >= ready_at {
        next_allowed.insert(writer_id, now + cooldown);
        return true;
    }
    false
}

async fn check_family(
    family: IpFamily,
    pool: &Arc<MePool>,
    rng: &Arc<SecureRandom>,
    backoff: &mut HashMap<(i32, IpFamily), u64>,
    next_attempt: &mut HashMap<(i32, IpFamily), Instant>,
    inflight: &mut HashMap<(i32, IpFamily), usize>,
    outage_backoff: &mut HashMap<(i32, IpFamily), u64>,
    outage_next_attempt: &mut HashMap<(i32, IpFamily), Instant>,
    single_endpoint_outage: &mut HashSet<(i32, IpFamily)>,
    shadow_rotate_deadline: &mut HashMap<(i32, IpFamily), Instant>,
    idle_refresh_next_attempt: &mut HashMap<(i32, IpFamily), Instant>,
    adaptive_idle_since: &mut HashMap<(i32, IpFamily), Instant>,
    adaptive_recover_until: &mut HashMap<(i32, IpFamily), Instant>,
    floor_warn_next_allowed: &mut HashMap<(i32, IpFamily), Instant>,
    drain_warn_next_allowed: &mut HashMap<u64, Instant>,
    drain_soft_evict_next_allowed: &mut HashMap<u64, Instant>,
) -> bool {
    let enabled = match family {
        IpFamily::V4 => pool.decision.ipv4_me,
        IpFamily::V6 => pool.decision.ipv6_me,
    };
    if !enabled {
        return false;
    }

    let mut family_degraded = false;

    let mut dc_endpoints = HashMap::<i32, Vec<SocketAddr>>::new();
    let map_guard = match family {
        IpFamily::V4 => pool.proxy_map_v4.read().await,
        IpFamily::V6 => pool.proxy_map_v6.read().await,
    };
    for (dc, addrs) in map_guard.iter() {
        let entry = dc_endpoints.entry(*dc).or_default();
        for (ip, port) in addrs.iter().copied() {
            entry.push(SocketAddr::new(ip, port));
        }
    }
    drop(map_guard);
    for endpoints in dc_endpoints.values_mut() {
        endpoints.sort_unstable();
        endpoints.dedup();
    }
    let mut reconnect_budget = health_reconnect_budget(pool, dc_endpoints.len());

    if pool.floor_mode() == MeFloorMode::Static {
        adaptive_idle_since.clear();
        adaptive_recover_until.clear();
    }

    let mut live_addr_counts = HashMap::<(i32, SocketAddr), usize>::new();
    let mut live_writer_ids_by_addr = HashMap::<(i32, SocketAddr), Vec<u64>>::new();
    for writer in pool.writers.read().await.iter().filter(|w| {
        !w.draining.load(std::sync::atomic::Ordering::Relaxed)
    }) {
        if !matches!(
            super::pool::WriterContour::from_u8(
                writer.contour.load(std::sync::atomic::Ordering::Relaxed),
            ),
            super::pool::WriterContour::Active
        ) {
            continue;
        }
        let key = (writer.writer_dc, writer.addr);
        *live_addr_counts.entry(key).or_insert(0) += 1;
        live_writer_ids_by_addr
            .entry(key)
            .or_default()
            .push(writer.id);
    }
    let writer_idle_since = pool.registry.writer_idle_since_snapshot().await;
    let bound_clients_by_writer = pool
        .registry
        .writer_activity_snapshot()
        .await
        .bound_clients_by_writer;
    let floor_plan = build_family_floor_plan(
        pool,
        family,
        &dc_endpoints,
        &live_addr_counts,
        &live_writer_ids_by_addr,
        &bound_clients_by_writer,
        adaptive_idle_since,
        adaptive_recover_until,
    )
    .await;
    pool.set_adaptive_floor_runtime_caps(
        floor_plan.active_cap_configured_total,
        floor_plan.active_cap_effective_total,
        floor_plan.warm_cap_configured_total,
        floor_plan.warm_cap_effective_total,
        floor_plan.target_writers_total,
        floor_plan.active_writers_current,
        floor_plan.warm_writers_current,
    );
    let mut next_drain_reap_at = Instant::now();

    for (dc, endpoints) in dc_endpoints {
        if Instant::now() >= next_drain_reap_at {
            reap_draining_writers(pool, drain_warn_next_allowed, drain_soft_evict_next_allowed)
                .await;
            next_drain_reap_at = Instant::now()
                + Duration::from_secs(HEALTH_DRAIN_REAP_OPPORTUNISTIC_INTERVAL_SECS);
        }
        if endpoints.is_empty() {
            continue;
        }
        let key = (dc, family);
        let required = floor_plan
            .by_dc
            .get(&dc)
            .map(|entry| entry.target_required)
            .unwrap_or_else(|| {
                pool.required_writers_for_dc_with_floor_mode(endpoints.len(), false)
            });
        let alive = endpoints
            .iter()
            .map(|addr| *live_addr_counts.get(&(dc, *addr)).unwrap_or(&0))
            .sum::<usize>();

        if endpoints.len() == 1 && pool.single_endpoint_outage_mode_enabled() && alive == 0 {
            family_degraded = true;
            if single_endpoint_outage.insert(key) {
                pool.stats.increment_me_single_endpoint_outage_enter_total();
                warn!(
                    dc = %dc,
                    ?family,
                    required,
                    endpoint_count = endpoints.len(),
                    "Single-endpoint DC outage detected"
                );
            }

            recover_single_endpoint_outage(
                pool,
                rng,
                key,
                endpoints[0],
                required,
                outage_backoff,
                outage_next_attempt,
                &mut reconnect_budget,
            )
            .await;
            continue;
        }

        if single_endpoint_outage.remove(&key) {
            pool.stats.increment_me_single_endpoint_outage_exit_total();
            outage_backoff.remove(&key);
            outage_next_attempt.remove(&key);
            shadow_rotate_deadline.remove(&key);
            idle_refresh_next_attempt.remove(&key);
            adaptive_idle_since.remove(&key);
            adaptive_recover_until.remove(&key);
            info!(
                dc = %dc,
                ?family,
                alive,
                required,
                endpoint_count = endpoints.len(),
                "Single-endpoint DC outage recovered"
            );
        }

        if alive >= required {
            maybe_refresh_idle_writer_for_dc(
                pool,
                rng,
                key,
                dc,
                family,
                &endpoints,
                alive,
                required,
                &live_writer_ids_by_addr,
                &writer_idle_since,
                &bound_clients_by_writer,
                idle_refresh_next_attempt,
            )
            .await;
            maybe_rotate_single_endpoint_shadow(
                pool,
                rng,
                key,
                dc,
                family,
                &endpoints,
                alive,
                required,
                &live_writer_ids_by_addr,
                &bound_clients_by_writer,
                shadow_rotate_deadline,
            )
            .await;
            continue;
        }
        let missing = required - alive;
        family_degraded = true;

        let now = Instant::now();
        if reconnect_budget == 0 {
            let base_ms = pool.me_reconnect_backoff_base.as_millis() as u64;
            let next_ms = (*backoff.get(&key).unwrap_or(&base_ms)).max(base_ms);
            let jitter = next_ms / JITTER_FRAC_NUM;
            let wait = Duration::from_millis(next_ms)
                + Duration::from_millis(rand::rng().random_range(0..=jitter.max(1)));
            next_attempt.insert(key, now + wait);
            debug!(
                dc = %dc,
                ?family,
                alive,
                required,
                endpoint_count = endpoints.len(),
                reconnect_budget,
                "Skipping reconnect due to per-tick health reconnect budget"
            );
            continue;
        }
        if let Some(ts) = next_attempt.get(&key)
            && now < *ts
        {
            continue;
        }

        let max_concurrent = pool.me_reconnect_max_concurrent_per_dc.max(1) as usize;
        if *inflight.get(&key).unwrap_or(&0) >= max_concurrent {
            continue;
        }
        if pool
            .has_refill_inflight_for_dc_key(super::pool::RefillDcKey { dc, family })
            .await
        {
            debug!(
                dc = %dc,
                ?family,
                alive,
                required,
                endpoint_count = endpoints.len(),
                "Skipping health reconnect: immediate refill is already in flight for this DC group"
            );
            continue;
        }
        *inflight.entry(key).or_insert(0) += 1;

        let mut restored = 0usize;
        for _ in 0..missing {
            if Instant::now() >= next_drain_reap_at {
                reap_draining_writers(pool, drain_warn_next_allowed, drain_soft_evict_next_allowed)
                    .await;
                next_drain_reap_at = Instant::now()
                    + Duration::from_secs(HEALTH_DRAIN_REAP_OPPORTUNISTIC_INTERVAL_SECS);
            }
            if reconnect_budget == 0 {
                break;
            }
            reconnect_budget = reconnect_budget.saturating_sub(1);
            if pool.active_contour_writer_count_total().await
                >= floor_plan.active_cap_effective_total
            {
                let swapped = maybe_swap_idle_writer_for_cap(
                    pool,
                    rng,
                    dc,
                    family,
                    &endpoints,
                    &live_writer_ids_by_addr,
                    &writer_idle_since,
                    &bound_clients_by_writer,
                )
                .await;
                if swapped {
                    pool.stats.increment_me_floor_swap_idle_total();
                    restored += 1;
                    continue;
                }
                pool.stats.increment_me_floor_cap_block_total();
                pool.stats.increment_me_floor_swap_idle_failed_total();
                debug!(
                    dc = %dc,
                    ?family,
                    alive,
                    required,
                    active_cap_effective_total = floor_plan.active_cap_effective_total,
                    "Adaptive floor cap reached, reconnect attempt blocked"
                );
                break;
            }
            let res = tokio::time::timeout(
                pool.me_one_timeout,
                pool.connect_endpoints_round_robin(dc, &endpoints, rng.as_ref()),
            )
            .await;
            match res {
                Ok(true) => {
                    restored += 1;
                    pool.stats.increment_me_reconnect_success();
                }
                Ok(false) => {
                    pool.stats.increment_me_reconnect_attempt();
                    debug!(dc = %dc, ?family, "ME round-robin reconnect failed")
                }
                Err(_) => {
                    pool.stats.increment_me_reconnect_attempt();
                    debug!(dc = %dc, ?family, "ME reconnect timed out");
                }
            }
        }

        let now_alive = alive + restored;
        if now_alive >= required {
            info!(
                dc = %dc,
                ?family,
                alive = now_alive,
                required,
                endpoint_count = endpoints.len(),
                "ME writer floor restored for DC"
            );
            backoff.insert(key, pool.me_reconnect_backoff_base.as_millis() as u64);
            let jitter = pool.me_reconnect_backoff_base.as_millis() as u64 / JITTER_FRAC_NUM;
            let wait = pool.me_reconnect_backoff_base
                + Duration::from_millis(rand::rng().random_range(0..=jitter.max(1)));
            next_attempt.insert(key, now + wait);
        } else {
            let curr = *backoff.get(&key).unwrap_or(&(pool.me_reconnect_backoff_base.as_millis() as u64));
            let next_ms = (curr.saturating_mul(2)).min(pool.me_reconnect_backoff_cap.as_millis() as u64);
            backoff.insert(key, next_ms);
            let jitter = next_ms / JITTER_FRAC_NUM;
            let wait = Duration::from_millis(next_ms)
                + Duration::from_millis(rand::rng().random_range(0..=jitter.max(1)));
            next_attempt.insert(key, now + wait);
            if pool.is_runtime_ready() {
                let warn_cooldown = pool.warn_rate_limit_duration();
                if should_emit_rate_limited_warn(
                    floor_warn_next_allowed,
                    key,
                    now,
                    warn_cooldown,
                ) {
                    warn!(
                        dc = %dc,
                        ?family,
                        alive = now_alive,
                        required,
                        endpoint_count = endpoints.len(),
                        backoff_ms = next_ms,
                        "DC writer floor is below required level, scheduled reconnect"
                    );
                }
            } else {
                info!(
                    dc = %dc,
                    ?family,
                    alive = now_alive,
                    required,
                    endpoint_count = endpoints.len(),
                    backoff_ms = next_ms,
                    "DC writer floor is below required level during startup, scheduled reconnect"
                );
            }
        }
        if let Some(v) = inflight.get_mut(&key) {
            *v = v.saturating_sub(1);
        }
    }

    family_degraded
}

fn health_reconnect_budget(pool: &Arc<MePool>, dc_groups: usize) -> usize {
    let cpu_cores = pool.adaptive_floor_effective_cpu_cores().max(1);
    let by_cpu = cpu_cores.saturating_mul(HEALTH_RECONNECT_BUDGET_PER_CORE);
    let by_dc = dc_groups.saturating_mul(HEALTH_RECONNECT_BUDGET_PER_DC);
    by_cpu
        .saturating_add(by_dc)
        .clamp(HEALTH_RECONNECT_BUDGET_MIN, HEALTH_RECONNECT_BUDGET_MAX)
}

fn should_emit_rate_limited_warn(
    next_allowed: &mut HashMap<(i32, IpFamily), Instant>,
    key: (i32, IpFamily),
    now: Instant,
    cooldown: Duration,
) -> bool {
    let Some(ready_at) = next_allowed.get(&key).copied() else {
        next_allowed.insert(key, now + cooldown);
        return true;
    };
    if now >= ready_at {
        next_allowed.insert(key, now + cooldown);
        return true;
    }
    false
}

fn adaptive_floor_class_min(
    pool: &Arc<MePool>,
    endpoint_count: usize,
    base_required: usize,
) -> usize {
    if endpoint_count <= 1 {
        let min_single = (pool
            .me_adaptive_floor_min_writers_single_endpoint
            .load(std::sync::atomic::Ordering::Relaxed) as usize)
            .max(1);
        min_single.min(base_required.max(1))
    } else {
        pool.adaptive_floor_min_writers_multi_endpoint()
            .min(base_required.max(1))
    }
}

fn adaptive_floor_class_max(
    pool: &Arc<MePool>,
    endpoint_count: usize,
    base_required: usize,
    cpu_cores: usize,
) -> usize {
    let extra_per_core = if endpoint_count <= 1 {
        pool.adaptive_floor_max_extra_single_per_core()
    } else {
        pool.adaptive_floor_max_extra_multi_per_core()
    };
    base_required.saturating_add(cpu_cores.saturating_mul(extra_per_core))
}

fn list_writer_ids_for_endpoints(
    dc: i32,
    endpoints: &[SocketAddr],
    live_writer_ids_by_addr: &HashMap<(i32, SocketAddr), Vec<u64>>,
) -> Vec<u64> {
    let mut out = Vec::<u64>::new();
    for endpoint in endpoints {
        if let Some(ids) = live_writer_ids_by_addr.get(&(dc, *endpoint)) {
            out.extend(ids.iter().copied());
        }
    }
    out
}

async fn build_family_floor_plan(
    pool: &Arc<MePool>,
    family: IpFamily,
    dc_endpoints: &HashMap<i32, Vec<SocketAddr>>,
    live_addr_counts: &HashMap<(i32, SocketAddr), usize>,
    live_writer_ids_by_addr: &HashMap<(i32, SocketAddr), Vec<u64>>,
    bound_clients_by_writer: &HashMap<u64, usize>,
    adaptive_idle_since: &mut HashMap<(i32, IpFamily), Instant>,
    adaptive_recover_until: &mut HashMap<(i32, IpFamily), Instant>,
) -> FamilyFloorPlan {
    let mut entries = Vec::<DcFloorPlanEntry>::new();
    let mut by_dc = HashMap::<i32, DcFloorPlanEntry>::new();
    let mut family_active_total = 0usize;

    let floor_mode = pool.floor_mode();
    let is_adaptive = floor_mode == MeFloorMode::Adaptive;
    let cpu_cores = pool.adaptive_floor_effective_cpu_cores().max(1);
    let (active_writers_current, warm_writers_current, _) =
        pool.non_draining_writer_counts_by_contour().await;

    for (dc, endpoints) in dc_endpoints {
        if endpoints.is_empty() {
            continue;
        }
        let key = (*dc, family);
        let reduce_for_idle = should_reduce_floor_for_idle(
            pool,
            key,
            *dc,
            endpoints,
            live_writer_ids_by_addr,
            bound_clients_by_writer,
            adaptive_idle_since,
            adaptive_recover_until,
        )
        .await;
        let base_required = pool.required_writers_for_dc(endpoints.len()).max(1);
        let min_required = if is_adaptive {
            adaptive_floor_class_min(pool, endpoints.len(), base_required)
        } else {
            base_required
        };
        let mut max_required = if is_adaptive {
            adaptive_floor_class_max(pool, endpoints.len(), base_required, cpu_cores)
        } else {
            base_required
        };
        if max_required < min_required {
            max_required = min_required;
        }
        let desired_raw = if is_adaptive && reduce_for_idle {
            min_required
        } else {
            base_required
        };
        let target_required = desired_raw.clamp(min_required, max_required);
        let alive = endpoints
            .iter()
            .map(|endpoint| live_addr_counts.get(&(*dc, *endpoint)).copied().unwrap_or(0))
            .sum::<usize>();
        family_active_total = family_active_total.saturating_add(alive);
        let writer_ids = list_writer_ids_for_endpoints(*dc, endpoints, live_writer_ids_by_addr);
        let has_bound_clients = has_bound_clients_on_endpoint(&writer_ids, bound_clients_by_writer);

        entries.push(DcFloorPlanEntry {
            dc: *dc,
            endpoints: endpoints.clone(),
            alive,
            min_required,
            target_required,
            max_required,
            has_bound_clients,
            floor_capped: false,
        });
    }

    if entries.is_empty() {
        let active_cap_configured_total = pool.adaptive_floor_active_cap_configured_total();
        let warm_cap_configured_total = pool.adaptive_floor_warm_cap_configured_total();
        return FamilyFloorPlan {
            by_dc,
            active_cap_configured_total,
            active_cap_effective_total: active_cap_configured_total,
            warm_cap_configured_total,
            warm_cap_effective_total: warm_cap_configured_total,
            active_writers_current,
            warm_writers_current,
            target_writers_total: 0,
        };
    }

    if !is_adaptive {
        let target_total = entries
            .iter()
            .map(|entry| entry.target_required)
            .sum::<usize>();
        let active_cap_configured_total = pool.adaptive_floor_active_cap_configured_total();
        let warm_cap_configured_total = pool.adaptive_floor_warm_cap_configured_total();
        for entry in entries {
            by_dc.insert(entry.dc, entry);
        }
        return FamilyFloorPlan {
            by_dc,
            active_cap_configured_total,
            active_cap_effective_total: active_cap_configured_total.max(target_total),
            warm_cap_configured_total,
            warm_cap_effective_total: warm_cap_configured_total,
            active_writers_current,
            warm_writers_current,
            target_writers_total: target_total,
        };
    }

    let active_cap_configured_total = pool.adaptive_floor_active_cap_configured_total();
    let warm_cap_configured_total = pool.adaptive_floor_warm_cap_configured_total();
    let other_active = active_writers_current.saturating_sub(family_active_total);
    let min_sum = entries
        .iter()
        .map(|entry| entry.min_required)
        .sum::<usize>();
    let mut target_sum = entries
        .iter()
        .map(|entry| entry.target_required)
        .sum::<usize>();
    let family_cap = active_cap_configured_total
        .saturating_sub(other_active)
        .max(min_sum);
    if target_sum > family_cap {
        entries.sort_by_key(|entry| {
            (
                entry.has_bound_clients,
                std::cmp::Reverse(entry.target_required.saturating_sub(entry.min_required)),
                std::cmp::Reverse(entry.alive),
                entry.dc.abs(),
                entry.dc,
                entry.endpoints.len(),
                entry.max_required,
            )
        });
        let mut changed = true;
        while target_sum > family_cap && changed {
            changed = false;
            for entry in &mut entries {
                if target_sum <= family_cap {
                    break;
                }
                if entry.target_required > entry.min_required {
                    entry.target_required -= 1;
                    entry.floor_capped = true;
                    target_sum -= 1;
                    changed = true;
                }
            }
        }
    }

    for entry in entries {
        by_dc.insert(entry.dc, entry);
    }
    let active_cap_effective_total =
        active_cap_configured_total.max(other_active.saturating_add(min_sum));
    let target_writers_total = other_active.saturating_add(target_sum);
    FamilyFloorPlan {
        by_dc,
        active_cap_configured_total,
        active_cap_effective_total,
        warm_cap_configured_total,
        warm_cap_effective_total: warm_cap_configured_total,
        active_writers_current,
        warm_writers_current,
        target_writers_total,
    }
}

async fn maybe_swap_idle_writer_for_cap(
    pool: &Arc<MePool>,
    rng: &Arc<SecureRandom>,
    dc: i32,
    family: IpFamily,
    endpoints: &[SocketAddr],
    live_writer_ids_by_addr: &HashMap<(i32, SocketAddr), Vec<u64>>,
    writer_idle_since: &HashMap<u64, u64>,
    bound_clients_by_writer: &HashMap<u64, usize>,
) -> bool {
    let now_epoch_secs = MePool::now_epoch_secs();
    let mut candidate: Option<(u64, SocketAddr, u64)> = None;
    for endpoint in endpoints {
        let Some(writer_ids) = live_writer_ids_by_addr.get(&(dc, *endpoint)) else {
            continue;
        };
        for writer_id in writer_ids {
            if bound_clients_by_writer.get(writer_id).copied().unwrap_or(0) > 0 {
                continue;
            }
            let Some(idle_since_epoch_secs) = writer_idle_since.get(writer_id).copied() else {
                continue;
            };
            let idle_age_secs = now_epoch_secs.saturating_sub(idle_since_epoch_secs);
            if candidate
                .as_ref()
                .map(|(_, _, age)| idle_age_secs > *age)
                .unwrap_or(true)
            {
                candidate = Some((*writer_id, *endpoint, idle_age_secs));
            }
        }
    }

    let Some((old_writer_id, endpoint, idle_age_secs)) = candidate else {
        return false;
    };

    let connected = match tokio::time::timeout(
        pool.me_one_timeout,
        pool.connect_one_for_dc(endpoint, dc, rng.as_ref()),
    )
    .await
    {
        Ok(Ok(())) => true,
        Ok(Err(error)) => {
            debug!(
                dc = %dc,
                ?family,
                %endpoint,
                old_writer_id,
                idle_age_secs,
                %error,
                "Adaptive floor cap swap connect failed"
            );
            false
        }
        Err(_) => {
            debug!(
                dc = %dc,
                ?family,
                %endpoint,
                old_writer_id,
                idle_age_secs,
                "Adaptive floor cap swap connect timed out"
            );
            false
        }
    };
    if !connected {
        return false;
    }

    pool.mark_writer_draining_with_timeout(old_writer_id, pool.force_close_timeout(), false)
        .await;
    info!(
        dc = %dc,
        ?family,
        %endpoint,
        old_writer_id,
        idle_age_secs,
        "Adaptive floor cap swap: idle writer rotated"
    );
    true
}

async fn maybe_refresh_idle_writer_for_dc(
    pool: &Arc<MePool>,
    rng: &Arc<SecureRandom>,
    key: (i32, IpFamily),
    dc: i32,
    family: IpFamily,
    endpoints: &[SocketAddr],
    alive: usize,
    required: usize,
    live_writer_ids_by_addr: &HashMap<(i32, SocketAddr), Vec<u64>>,
    writer_idle_since: &HashMap<u64, u64>,
    bound_clients_by_writer: &HashMap<u64, usize>,
    idle_refresh_next_attempt: &mut HashMap<(i32, IpFamily), Instant>,
) {
    if alive < required {
        return;
    }

    let now = Instant::now();
    if let Some(next) = idle_refresh_next_attempt.get(&key)
        && now < *next
    {
        return;
    }

    let now_epoch_secs = MePool::now_epoch_secs();
    let mut candidate: Option<(u64, SocketAddr, u64, u64)> = None;
    for endpoint in endpoints {
        let Some(writer_ids) = live_writer_ids_by_addr.get(&(dc, *endpoint)) else {
            continue;
        };
        for writer_id in writer_ids {
            if bound_clients_by_writer.get(writer_id).copied().unwrap_or(0) > 0 {
                continue;
            }
            let Some(idle_since_epoch_secs) = writer_idle_since.get(writer_id).copied() else {
                continue;
            };
            let idle_age_secs = now_epoch_secs.saturating_sub(idle_since_epoch_secs);
            let threshold_secs = IDLE_REFRESH_TRIGGER_BASE_SECS
                + (*writer_id % (IDLE_REFRESH_TRIGGER_JITTER_SECS + 1));
            if idle_age_secs < threshold_secs {
                continue;
            }
            if candidate
                .as_ref()
                .map(|(_, _, age, _)| idle_age_secs > *age)
                .unwrap_or(true)
            {
                candidate = Some((*writer_id, *endpoint, idle_age_secs, threshold_secs));
            }
        }
    }

    let Some((old_writer_id, endpoint, idle_age_secs, threshold_secs)) = candidate else {
        return;
    };

    let rotate_ok = match tokio::time::timeout(
        pool.me_one_timeout,
        pool.connect_one_for_dc(endpoint, dc, rng.as_ref()),
    )
    .await
    {
        Ok(Ok(())) => true,
        Ok(Err(error)) => {
            debug!(
                dc = %dc,
                ?family,
                %endpoint,
                old_writer_id,
                idle_age_secs,
                threshold_secs,
                %error,
                "Idle writer pre-refresh connect failed"
            );
            false
        }
        Err(_) => {
            debug!(
                dc = %dc,
                ?family,
                %endpoint,
                old_writer_id,
                idle_age_secs,
                threshold_secs,
                "Idle writer pre-refresh connect timed out"
            );
            false
        }
    };

    if !rotate_ok {
        idle_refresh_next_attempt.insert(key, now + Duration::from_secs(IDLE_REFRESH_RETRY_SECS));
        return;
    }

    pool.mark_writer_draining_with_timeout(old_writer_id, pool.force_close_timeout(), false)
        .await;
    idle_refresh_next_attempt.insert(
        key,
        now + Duration::from_secs(IDLE_REFRESH_SUCCESS_GUARD_SECS),
    );
    info!(
        dc = %dc,
        ?family,
        %endpoint,
        old_writer_id,
        idle_age_secs,
        threshold_secs,
        alive,
        required,
        "Idle writer refreshed before upstream idle timeout"
    );
}

async fn should_reduce_floor_for_idle(
    pool: &Arc<MePool>,
    key: (i32, IpFamily),
    dc: i32,
    endpoints: &[SocketAddr],
    live_writer_ids_by_addr: &HashMap<(i32, SocketAddr), Vec<u64>>,
    bound_clients_by_writer: &HashMap<u64, usize>,
    adaptive_idle_since: &mut HashMap<(i32, IpFamily), Instant>,
    adaptive_recover_until: &mut HashMap<(i32, IpFamily), Instant>,
) -> bool {
    if pool.floor_mode() != MeFloorMode::Adaptive {
        adaptive_idle_since.remove(&key);
        adaptive_recover_until.remove(&key);
        return false;
    }

    let now = Instant::now();
    let writer_ids = list_writer_ids_for_endpoints(dc, endpoints, live_writer_ids_by_addr);
    let has_bound_clients = has_bound_clients_on_endpoint(&writer_ids, bound_clients_by_writer);
    if has_bound_clients {
        adaptive_idle_since.remove(&key);
        adaptive_recover_until.insert(key, now + pool.adaptive_floor_recover_grace_duration());
        return false;
    }

    if let Some(recover_until) = adaptive_recover_until.get(&key)
        && now < *recover_until
    {
        adaptive_idle_since.remove(&key);
        return false;
    }
    adaptive_recover_until.remove(&key);

    let idle_since = adaptive_idle_since.entry(key).or_insert(now);
    now.saturating_duration_since(*idle_since) >= pool.adaptive_floor_idle_duration()
}

fn has_bound_clients_on_endpoint(
    writer_ids: &[u64],
    bound_clients_by_writer: &HashMap<u64, usize>,
) -> bool {
    writer_ids
        .iter()
        .any(|writer_id| bound_clients_by_writer.get(writer_id).copied().unwrap_or(0) > 0)
}

async fn recover_single_endpoint_outage(
    pool: &Arc<MePool>,
    rng: &Arc<SecureRandom>,
    key: (i32, IpFamily),
    endpoint: SocketAddr,
    required: usize,
    outage_backoff: &mut HashMap<(i32, IpFamily), u64>,
    outage_next_attempt: &mut HashMap<(i32, IpFamily), Instant>,
    reconnect_budget: &mut usize,
) {
    let now = Instant::now();
    if let Some(ts) = outage_next_attempt.get(&key)
        && now < *ts
    {
        return;
    }

    let (min_backoff_ms, max_backoff_ms) = pool.single_endpoint_outage_backoff_bounds_ms();
    if *reconnect_budget == 0 {
        outage_next_attempt.insert(key, now + Duration::from_millis(min_backoff_ms.max(250)));
        debug!(
            dc = %key.0,
            family = ?key.1,
            %endpoint,
            required,
            "Single-endpoint outage reconnect deferred by health reconnect budget"
        );
        return;
    }
    *reconnect_budget = (*reconnect_budget).saturating_sub(1);
    pool.stats
        .increment_me_single_endpoint_outage_reconnect_attempt_total();

    let bypass_quarantine = pool.single_endpoint_outage_disable_quarantine();
    let attempt_ok = if bypass_quarantine {
        pool.stats
            .increment_me_single_endpoint_quarantine_bypass_total();
        match tokio::time::timeout(
            pool.me_one_timeout,
            pool.connect_one_for_dc(endpoint, key.0, rng.as_ref()),
        )
        .await
        {
            Ok(Ok(())) => true,
            Ok(Err(e)) => {
                debug!(
                    dc = %key.0,
                    family = ?key.1,
                    %endpoint,
                    error = %e,
                    "Single-endpoint outage reconnect failed (quarantine bypass path)"
                );
                false
            }
            Err(_) => {
                debug!(
                    dc = %key.0,
                    family = ?key.1,
                    %endpoint,
                    "Single-endpoint outage reconnect timed out (quarantine bypass path)"
                );
                false
            }
        }
    } else {
        let one_endpoint = [endpoint];
        match tokio::time::timeout(
            pool.me_one_timeout,
            pool.connect_endpoints_round_robin(key.0, &one_endpoint, rng.as_ref()),
        )
        .await
        {
            Ok(ok) => ok,
            Err(_) => {
                debug!(
                    dc = %key.0,
                    family = ?key.1,
                    %endpoint,
                    "Single-endpoint outage reconnect timed out"
                );
                false
            }
        }
    };

    if attempt_ok {
        pool.stats
            .increment_me_single_endpoint_outage_reconnect_success_total();
        pool.stats.increment_me_reconnect_success();
        outage_backoff.insert(key, min_backoff_ms);
        let jitter = min_backoff_ms / JITTER_FRAC_NUM;
        let wait = Duration::from_millis(min_backoff_ms)
            + Duration::from_millis(rand::rng().random_range(0..=jitter.max(1)));
        outage_next_attempt.insert(key, now + wait);
        info!(
            dc = %key.0,
            family = ?key.1,
            %endpoint,
            required,
            backoff_ms = min_backoff_ms,
            "Single-endpoint outage reconnect succeeded"
        );
        return;
    }

    pool.stats.increment_me_reconnect_attempt();
    let current_ms = *outage_backoff.get(&key).unwrap_or(&min_backoff_ms);
    let next_ms = current_ms.saturating_mul(2).min(max_backoff_ms);
    outage_backoff.insert(key, next_ms);
    let jitter = next_ms / JITTER_FRAC_NUM;
    let wait = Duration::from_millis(next_ms)
        + Duration::from_millis(rand::rng().random_range(0..=jitter.max(1)));
    outage_next_attempt.insert(key, now + wait);
    warn!(
        dc = %key.0,
        family = ?key.1,
        %endpoint,
        required,
        backoff_ms = next_ms,
        "Single-endpoint outage reconnect scheduled"
    );
}

async fn maybe_rotate_single_endpoint_shadow(
    pool: &Arc<MePool>,
    rng: &Arc<SecureRandom>,
    key: (i32, IpFamily),
    dc: i32,
    family: IpFamily,
    endpoints: &[SocketAddr],
    alive: usize,
    required: usize,
    live_writer_ids_by_addr: &HashMap<(i32, SocketAddr), Vec<u64>>,
    bound_clients_by_writer: &HashMap<u64, usize>,
    shadow_rotate_deadline: &mut HashMap<(i32, IpFamily), Instant>,
) {
    if endpoints.len() != 1 || alive < required {
        return;
    }

    let Some(interval) = pool.single_endpoint_shadow_rotate_interval() else {
        return;
    };

    let now = Instant::now();
    if let Some(deadline) = shadow_rotate_deadline.get(&key)
        && now < *deadline
    {
        return;
    }

    let endpoint = endpoints[0];
    if pool.is_endpoint_quarantined(endpoint).await {
        pool.stats
            .increment_me_single_endpoint_shadow_rotate_skipped_quarantine_total();
        shadow_rotate_deadline.insert(key, now + Duration::from_secs(SHADOW_ROTATE_RETRY_SECS));
        debug!(
            dc = %dc,
            ?family,
            %endpoint,
            "Single-endpoint shadow rotation skipped: endpoint is quarantined"
        );
        return;
    }

    let Some(writer_ids) = live_writer_ids_by_addr.get(&(dc, endpoint)) else {
        shadow_rotate_deadline.insert(key, now + Duration::from_secs(SHADOW_ROTATE_RETRY_SECS));
        return;
    };

    let mut candidate_writer_id = None;
    for writer_id in writer_ids {
        if bound_clients_by_writer.get(writer_id).copied().unwrap_or(0) == 0 {
            candidate_writer_id = Some(*writer_id);
            break;
        }
    }

    let Some(old_writer_id) = candidate_writer_id else {
        shadow_rotate_deadline.insert(key, now + Duration::from_secs(SHADOW_ROTATE_RETRY_SECS));
        debug!(
            dc = %dc,
            ?family,
            %endpoint,
            alive,
            required,
            "Single-endpoint shadow rotation skipped: no empty writer candidate"
        );
        return;
    };

    let rotate_ok = match tokio::time::timeout(
        pool.me_one_timeout,
        pool.connect_one_for_dc(endpoint, dc, rng.as_ref()),
    )
    .await
    {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            debug!(
                dc = %dc,
                ?family,
                %endpoint,
                error = %e,
                "Single-endpoint shadow rotation connect failed"
            );
            false
        }
        Err(_) => {
            debug!(
                dc = %dc,
                ?family,
                %endpoint,
                "Single-endpoint shadow rotation connect timed out"
            );
            false
        }
    };

    if !rotate_ok {
        shadow_rotate_deadline.insert(
            key,
            now + interval.min(Duration::from_secs(SHADOW_ROTATE_RETRY_SECS)),
        );
        return;
    }

    pool.mark_writer_draining_with_timeout(old_writer_id, pool.force_close_timeout(), false)
        .await;
    pool.stats.increment_me_single_endpoint_shadow_rotate_total();
    shadow_rotate_deadline.insert(key, now + interval);
    info!(
        dc = %dc,
        ?family,
        %endpoint,
        old_writer_id,
        rotate_every_secs = interval.as_secs(),
        "Single-endpoint shadow writer rotated"
    );
}

/// Last-resort safety net for draining writers stuck past their deadline.
///
/// Runs every `TICK_SECS` and force-closes any draining writer whose
/// `drain_deadline_epoch_secs` has been exceeded by more than a threshold.
///
/// Two thresholds:
///   - `SOFT_THRESHOLD_SECS` (60s): writers with no bound clients
///   - `HARD_THRESHOLD_SECS` (300s): writers WITH bound clients (unconditional)
///
/// Intentionally kept trivial and independent of pool config to minimise
/// the probability of panicking itself. Uses `SystemTime` directly
/// as a fallback clock source and timeouts on every lock acquisition
/// and writer removal so one stuck writer cannot block the rest.
pub async fn me_zombie_writer_watchdog(pool: Arc<MePool>) {
    use std::time::{SystemTime, UNIX_EPOCH};

    const TICK_SECS: u64 = 30;
    const SOFT_THRESHOLD_SECS: u64 = 60;
    const HARD_THRESHOLD_SECS: u64 = 300;
    const LOCK_TIMEOUT_SECS: u64 = 5;
    const REMOVE_TIMEOUT_SECS: u64 = 10;
    const HARD_DETACH_TIMEOUT_STREAK: u8 = 3;

    let mut removal_timeout_streak = HashMap::<u64, u8>::new();

    loop {
        tokio::time::sleep(Duration::from_secs(TICK_SECS)).await;

        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => continue,
        };

        // Phase 1: collect zombie IDs under a short read-lock with timeout.
        let zombie_ids_with_meta: Vec<(u64, bool)> = {
            let Ok(ws) = tokio::time::timeout(
                Duration::from_secs(LOCK_TIMEOUT_SECS),
                pool.writers.read(),
            )
            .await
            else {
                warn!("zombie_watchdog: writers read-lock timeout, skipping tick");
                continue;
            };
            ws.iter()
                .filter(|w| w.draining.load(std::sync::atomic::Ordering::Relaxed))
                .filter_map(|w| {
                    let deadline = w
                        .drain_deadline_epoch_secs
                        .load(std::sync::atomic::Ordering::Relaxed);
                    if deadline == 0 {
                        return None;
                    }
                    let overdue = now.saturating_sub(deadline);
                    if overdue == 0 {
                        return None;
                    }
                    let started = w
                        .draining_started_at_epoch_secs
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let drain_age = now.saturating_sub(started);
                    if drain_age > HARD_THRESHOLD_SECS {
                        return Some((w.id, true));
                    }
                    if overdue > SOFT_THRESHOLD_SECS {
                        return Some((w.id, false));
                    }
                    None
                })
                .collect()
        };
        // read lock released here

        if zombie_ids_with_meta.is_empty() {
            removal_timeout_streak.clear();
            continue;
        }

        let mut active_zombie_ids = HashSet::<u64>::with_capacity(zombie_ids_with_meta.len());
        for (writer_id, _) in &zombie_ids_with_meta {
            active_zombie_ids.insert(*writer_id);
        }
        removal_timeout_streak.retain(|writer_id, _| active_zombie_ids.contains(writer_id));

        warn!(
            zombie_count = zombie_ids_with_meta.len(),
            soft_threshold_secs = SOFT_THRESHOLD_SECS,
            hard_threshold_secs = HARD_THRESHOLD_SECS,
            "Zombie draining writers detected by watchdog, force-closing"
        );

        // Phase 2: remove each writer individually with a timeout.
        // One stuck removal cannot block the rest.
        for (writer_id, had_clients) in &zombie_ids_with_meta {
            let result = tokio::time::timeout(
                Duration::from_secs(REMOVE_TIMEOUT_SECS),
                pool.remove_writer_and_close_clients(
                    *writer_id,
                    MeWriterTeardownReason::WatchdogStuckDraining,
                ),
            )
            .await;
            match result {
                Ok(true) => {
                    removal_timeout_streak.remove(writer_id);
                    pool.stats.increment_pool_force_close_total();
                    pool.stats
                        .increment_me_draining_writers_reap_progress_total();
                    info!(
                        writer_id,
                        had_clients,
                        "Zombie writer removed by watchdog"
                    );
                }
                Ok(false) => {
                    removal_timeout_streak.remove(writer_id);
                    debug!(
                        writer_id,
                        had_clients,
                        "Zombie writer watchdog removal became no-op"
                    );
                }
                Err(_) => {
                    pool.stats.increment_me_writer_teardown_timeout_total();
                    let streak = removal_timeout_streak
                        .entry(*writer_id)
                        .and_modify(|value| *value = value.saturating_add(1))
                        .or_insert(1);
                    warn!(
                        writer_id,
                        had_clients,
                        timeout_streak = *streak,
                        "Zombie writer removal timed out"
                    );
                    if *streak < HARD_DETACH_TIMEOUT_STREAK {
                        continue;
                    }
                    pool.stats.increment_me_writer_teardown_escalation_total();

                    let hard_detach = tokio::time::timeout(
                        Duration::from_secs(REMOVE_TIMEOUT_SECS),
                        pool.remove_draining_writer_hard_detach(
                            *writer_id,
                            MeWriterTeardownReason::WatchdogStuckDraining,
                        ),
                    )
                    .await;
                    match hard_detach {
                        Ok(true) => {
                            removal_timeout_streak.remove(writer_id);
                            pool.stats.increment_pool_force_close_total();
                            pool.stats
                                .increment_me_draining_writers_reap_progress_total();
                            info!(
                                writer_id,
                                had_clients,
                                "Zombie writer hard-detached after repeated timeouts"
                            );
                        }
                        Ok(false) => {
                            removal_timeout_streak.remove(writer_id);
                            debug!(
                                writer_id,
                                had_clients,
                                "Zombie hard-detach skipped (writer already gone or no longer draining)"
                            );
                        }
                        Err(_) => {
                            pool.stats.increment_me_writer_teardown_timeout_total();
                            warn!(
                                writer_id,
                                had_clients,
                                "Zombie hard-detach timed out, will retry next tick"
                            );
                        }
                    }
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use super::{
        FamilyCircuitState, apply_family_circuit_result, reap_draining_writers,
        should_run_family_check,
    };
    use crate::config::{GeneralConfig, MeRouteNoWriterMode, MeSocksKdfPolicy, MeWriterPickMode};
    use crate::crypto::SecureRandom;
    use crate::network::IpFamily;
    use crate::network::probe::NetworkDecision;
    use crate::stats::Stats;
    use crate::transport::middle_proxy::codec::WriterCommand;
    use crate::transport::middle_proxy::pool::{
        MeFamilyRuntimeState, MePool, MeWriter, WriterContour,
    };
    use crate::transport::middle_proxy::registry::ConnMeta;

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
            general.me_route_hybrid_max_wait_ms,
            general.me_route_blocking_send_timeout_ms,
            general.me_route_inline_recovery_attempts,
            general.me_route_inline_recovery_wait_ms,
        )
    }

    async fn insert_draining_writer(
        pool: &Arc<MePool>,
        writer_id: u64,
        drain_started_at_epoch_secs: u64,
    ) -> u64 {
        let (conn_id, _rx) = pool.registry.register().await;
        let (tx, _writer_rx) = mpsc::channel::<WriterCommand>(8);
        let writer = MeWriter {
            id: writer_id,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000 + writer_id as u16),
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
            drain_deadline_epoch_secs: Arc::new(AtomicU64::new(0)),
            allow_drain_fallback: Arc::new(AtomicBool::new(false)),
        };
        pool.writers.write().await.push(writer);
        pool.registry.register_writer(writer_id, tx).await;
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

    #[tokio::test]
    async fn reap_draining_writers_force_closes_oldest_over_threshold() {
        let pool = make_pool(2).await;
        let now_epoch_secs = MePool::now_epoch_secs();
        let conn_a = insert_draining_writer(&pool, 10, now_epoch_secs.saturating_sub(30)).await;
        let conn_b = insert_draining_writer(&pool, 20, now_epoch_secs.saturating_sub(20)).await;
        let conn_c = insert_draining_writer(&pool, 30, now_epoch_secs.saturating_sub(10)).await;
        let mut warn_next_allowed = HashMap::new();
        let mut soft_evict_next_allowed = HashMap::new();

        reap_draining_writers(&pool, &mut warn_next_allowed, &mut soft_evict_next_allowed).await;

        let writer_ids: Vec<u64> = pool.writers.read().await.iter().map(|writer| writer.id).collect();
        assert_eq!(writer_ids, vec![20, 30]);
        assert!(pool.registry.get_writer(conn_a).await.is_none());
        assert_eq!(pool.registry.get_writer(conn_b).await.unwrap().writer_id, 20);
        assert_eq!(pool.registry.get_writer(conn_c).await.unwrap().writer_id, 30);
    }

    #[tokio::test]
    async fn reap_draining_writers_keeps_timeout_only_behavior_when_threshold_disabled() {
        let pool = make_pool(0).await;
        let now_epoch_secs = MePool::now_epoch_secs();
        let conn_a = insert_draining_writer(&pool, 10, now_epoch_secs.saturating_sub(30)).await;
        let conn_b = insert_draining_writer(&pool, 20, now_epoch_secs.saturating_sub(20)).await;
        let conn_c = insert_draining_writer(&pool, 30, now_epoch_secs.saturating_sub(10)).await;
        let mut warn_next_allowed = HashMap::new();
        let mut soft_evict_next_allowed = HashMap::new();

        reap_draining_writers(&pool, &mut warn_next_allowed, &mut soft_evict_next_allowed).await;

        let writer_ids: Vec<u64> = pool.writers.read().await.iter().map(|writer| writer.id).collect();
        assert_eq!(writer_ids, vec![10, 20, 30]);
        assert_eq!(pool.registry.get_writer(conn_a).await.unwrap().writer_id, 10);
        assert_eq!(pool.registry.get_writer(conn_b).await.unwrap().writer_id, 20);
        assert_eq!(pool.registry.get_writer(conn_c).await.unwrap().writer_id, 30);
    }

    #[tokio::test]
    async fn suppressed_family_probe_skip_preserves_suppressed_state() {
        let pool = make_pool(0).await;
        let now = Instant::now();
        let now_epoch_secs = MePool::now_epoch_secs();
        let suppressed_until_epoch_secs = now_epoch_secs.saturating_add(60);
        pool.set_family_runtime_state(
            IpFamily::V6,
            MeFamilyRuntimeState::Suppressed,
            now_epoch_secs,
            suppressed_until_epoch_secs,
            7,
            0,
        );

        let mut circuit = FamilyCircuitState {
            state: MeFamilyRuntimeState::Suppressed,
            state_since_at: now,
            suppressed_until: Some(now + Duration::from_secs(60)),
            next_probe_at: now + Duration::from_secs(5),
            fail_streak: 7,
            recover_success_streak: 0,
        };

        assert!(!should_run_family_check(&mut circuit, now));
        assert!(!apply_family_circuit_result(
            &pool,
            IpFamily::V6,
            &mut circuit,
            None,
            true,
            now,
            now_epoch_secs,
        ));
        assert_eq!(circuit.state, MeFamilyRuntimeState::Suppressed);
        assert_eq!(circuit.fail_streak, 7);
        assert_eq!(circuit.recover_success_streak, 0);
        assert_eq!(
            pool.family_runtime_state(IpFamily::V6),
            MeFamilyRuntimeState::Suppressed,
        );
    }
}
