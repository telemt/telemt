use super::*;

pub async fn me_drain_timeout_enforcer(pool: Arc<MePool>) {
    let mut drain_warn_next_allowed: HashMap<u64, Instant> = HashMap::new();
    loop {
        tokio::time::sleep(Duration::from_secs(
            HEALTH_DRAIN_TIMEOUT_ENFORCER_INTERVAL_SECS,
        ))
        .await;
        reap_draining_writers(&pool, &mut drain_warn_next_allowed).await;
    }
}

pub(in crate::transport::middle_proxy) async fn reap_draining_writers(
    pool: &Arc<MePool>,
    warn_next_allowed: &mut HashMap<u64, Instant>,
) {
    let now_epoch_secs = MePool::now_epoch_secs();
    let now = Instant::now();
    let drain_ttl_secs = pool
        .drain_runtime
        .me_pool_drain_ttl_secs
        .load(std::sync::atomic::Ordering::Relaxed);
    let drain_threshold = pool
        .drain_runtime
        .me_pool_drain_threshold
        .load(std::sync::atomic::Ordering::Relaxed);
    let activity = pool.registry.writer_activity_snapshot().await;
    let mut draining_writers = Vec::<DrainingWriterSnapshot>::new();
    let mut empty_writer_ids = Vec::<u64>::new();
    let mut force_close_writer_ids = Vec::<u64>::new();
    let writers = pool.writers.read().await;
    for writer in writers.iter() {
        if !writer.draining.load(std::sync::atomic::Ordering::Relaxed) {
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
        draining_writers.push(DrainingWriterSnapshot {
            id: writer.id,
            writer_dc: writer.writer_dc,
            addr: writer.addr,
            generation: writer.generation,
            created_at: writer.created_at,
            draining_started_at_epoch_secs: writer
                .draining_started_at_epoch_secs
                .load(std::sync::atomic::Ordering::Relaxed),
            drain_deadline_epoch_secs: writer
                .drain_deadline_epoch_secs
                .load(std::sync::atomic::Ordering::Relaxed),
            allow_drain_fallback: writer
                .allow_drain_fallback
                .load(std::sync::atomic::Ordering::Relaxed),
        });
    }
    drop(writers);

    let overflow = if drain_threshold > 0 && draining_writers.len() > drain_threshold as usize {
        draining_writers
            .len()
            .saturating_sub(drain_threshold as usize)
    } else {
        0
    };

    if overflow > 0 {
        draining_writers.sort_by(|left, right| {
            left.draining_started_at_epoch_secs
                .cmp(&right.draining_started_at_epoch_secs)
                .then_with(|| left.created_at.cmp(&right.created_at))
                .then_with(|| left.id.cmp(&right.id))
        });
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

    for writer in draining_writers {
        if drain_ttl_secs > 0
            && writer.draining_started_at_epoch_secs != 0
            && now_epoch_secs.saturating_sub(writer.draining_started_at_epoch_secs) > drain_ttl_secs
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
                force_close_secs = pool
                    .drain_runtime
                    .me_pool_force_close_secs
                    .load(std::sync::atomic::Ordering::Relaxed),
                allow_drain_fallback = writer.allow_drain_fallback,
                "ME draining writer remains non-empty past drain TTL"
            );
        }
        if writer.drain_deadline_epoch_secs != 0
            && now_epoch_secs >= writer.drain_deadline_epoch_secs
        {
            warn!(writer_id = writer.id, "Drain timeout, force-closing");
            force_close_writer_ids.push(writer.id);
        }
    }

    let close_budget = health_drain_close_budget();
    let requested_force_close = force_close_writer_ids.len();
    let requested_empty_close = empty_writer_ids.len();
    let requested_close_total = requested_force_close.saturating_add(requested_empty_close);
    let mut closed_writer_ids = HashSet::<u64>::new();
    let mut closed_total = 0usize;
    for writer_id in force_close_writer_ids {
        if closed_total >= close_budget {
            break;
        }
        if !closed_writer_ids.insert(writer_id) {
            continue;
        }
        pool.stats.increment_pool_force_close_total();
        pool.remove_writer_and_close_clients(writer_id).await;
        closed_total = closed_total.saturating_add(1);
    }
    for writer_id in empty_writer_ids {
        if closed_total >= close_budget {
            break;
        }
        if !closed_writer_ids.insert(writer_id) {
            continue;
        }
        pool.remove_writer_and_close_clients(writer_id).await;
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

    // Keep warn cooldown state for draining writers still present in the pool;
    // drop state only once a writer is actually removed.
    let active_draining_writer_ids = {
        let writers = pool.writers.read().await;
        writers
            .iter()
            .filter(|writer| writer.draining.load(std::sync::atomic::Ordering::Relaxed))
            .map(|writer| writer.id)
            .collect::<HashSet<u64>>()
    };
    warn_next_allowed.retain(|writer_id, _| active_draining_writer_ids.contains(writer_id));
}

pub(in crate::transport::middle_proxy) fn health_drain_close_budget() -> usize {
    let cpu_cores = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    cpu_cores
        .saturating_mul(HEALTH_DRAIN_CLOSE_BUDGET_PER_CORE)
        .clamp(HEALTH_DRAIN_CLOSE_BUDGET_MIN, HEALTH_DRAIN_CLOSE_BUDGET_MAX)
}

#[derive(Debug, Clone)]
struct DrainingWriterSnapshot {
    id: u64,
    writer_dc: i32,
    addr: SocketAddr,
    generation: u64,
    created_at: Instant,
    draining_started_at_epoch_secs: u64,
    drain_deadline_epoch_secs: u64,
    allow_drain_fallback: bool,
}

pub(super) fn should_emit_writer_warn(
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
