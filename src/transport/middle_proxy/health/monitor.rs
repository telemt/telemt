use super::scheduler::{
    HealthJob, HealthObservation, HealthScheduler, JobKind, JobOutcome, idle_refresh_ready, run_job,
};
use super::*;

/// Observes family health independently of bounded, lifecycle-owned network operations.
pub async fn me_health_monitor(pool: Arc<MePool>, rng: Arc<SecureRandom>, _min_connections: usize) {
    let mut scheduler = HealthScheduler::default();
    let mut tasks = JoinSet::new();
    let mut observations = HashMap::<IpFamily, Arc<HealthObservation>>::new();
    let mut drain_warn_next_allowed = HashMap::new();
    let mut observe = true;
    let mut health_tick = true;
    let mut next_tick = tokio::time::Instant::now();

    loop {
        if observe {
            if health_tick {
                pool.prune_closed_writers().await;
                pool.sweep_endpoint_quarantine().await;
                reap_draining_writers(&pool, &mut drain_warn_next_allowed).await;
            }
            let mut target_total = 0usize;
            let mut effective_cap = 0usize;
            let mut cap_observation = None;
            let mut degraded = false;
            for family in [IpFamily::V4, IpFamily::V6] {
                let observation = Arc::new(check_family(family, &pool).await);
                let family_degraded = observation
                    .floor
                    .by_dc
                    .values()
                    .any(|entry| entry.alive < entry.target_required);
                if health_tick {
                    // Suppression applies to a family outage, not one missing DC.
                    let family_unavailable = !observation.floor.by_dc.is_empty()
                        && observation
                            .floor
                            .by_dc
                            .values()
                            .all(|entry| entry.alive == 0);
                    update_family_runtime_state(&pool, family, family_unavailable);
                }
                degraded |= family_degraded;
                target_total += observation
                    .floor
                    .by_dc
                    .values()
                    .map(|entry| entry.target_required)
                    .sum::<usize>();
                effective_cap = effective_cap.max(observation.floor.active_cap_effective_total);
                if cap_observation.is_none() {
                    cap_observation = Some(observation.clone());
                }
                observations.insert(family, observation);
            }
            if let Some(observation) = cap_observation
                && observations
                    .values()
                    .all(|other| other.authority == observation.authority)
            {
                let floor = &observation.floor;
                pool.set_adaptive_floor_runtime_caps(
                    observation.authority,
                    floor.active_cap_configured_total,
                    effective_cap.max(target_total),
                    floor.warm_cap_configured_total,
                    floor.warm_cap_effective_total,
                    target_total,
                    floor.active_writers_current,
                    floor.warm_writers_current,
                );
            }
            scheduler.observe(&observations);
            for (key, state) in &mut scheduler.groups {
                if health_tick {
                    state.deferred = false;
                }
                let Some(entry) = observations
                    .get(&key.1)
                    .and_then(|o| o.floor.by_dc.get(&key.0))
                else {
                    continue;
                };
                let outage = entry.endpoints.len() == 1
                    && entry.alive == 0
                    && pool.single_endpoint_outage_mode_enabled();
                if outage != state.outage {
                    if outage {
                        pool.stats.increment_me_single_endpoint_outage_enter_total();
                        warn!(dc = key.0, family = ?key.1, required = entry.target_required,
                            endpoint_count = entry.endpoints.len(), "Single-endpoint DC outage detected");
                    } else {
                        pool.stats.increment_me_single_endpoint_outage_exit_total();
                        info!(dc = key.0, family = ?key.1, alive = entry.alive, required = entry.target_required,
                            endpoint_count = entry.endpoints.len(), "Single-endpoint DC outage recovered");
                    }
                    state.outage = outage;
                    // Outage retries and ordinary missing-floor rounds use different bounds.
                    // A successful first writer must not inherit an outage failure delay.
                    state.backoff_ms = 0;
                    state.due = None;
                    state.round_left = 0;
                    state.round_active = false;
                }
                if state.round_active
                    && (state.round_left == 0 || entry.alive >= entry.target_required)
                {
                    let (base, cap) = if state.outage {
                        pool.single_endpoint_outage_backoff_bounds_ms()
                    } else {
                        (
                            pool.reconnect_runtime.me_reconnect_backoff_base.as_millis() as u64,
                            pool.reconnect_runtime.me_reconnect_backoff_cap.as_millis() as u64,
                        )
                    };
                    let restored = entry.alive >= entry.target_required;
                    state.backoff_ms = if restored {
                        base
                    } else {
                        state.backoff_ms.max(base).saturating_mul(2).min(cap)
                    };
                    let wait = Duration::from_millis(state.backoff_ms)
                        + Duration::from_millis(
                            rand::rng()
                                .random_range(0..=(state.backoff_ms / JITTER_FRAC_NUM).max(1)),
                        );
                    state.due = Some(Instant::now() + wait);
                    state.round_active = false;
                    if restored {
                        info!(dc = key.0, family = ?key.1, alive = entry.alive, required = entry.target_required,
                            endpoint_count = entry.endpoints.len(), "ME writer floor restored for DC");
                    }
                    if !restored && state.warn_due.is_none_or(|due| due <= Instant::now()) {
                        state.warn_due = Some(Instant::now() + pool.warn_rate_limit_duration());
                        if state.outage {
                            warn!(dc = key.0, family = ?key.1, endpoint = %entry.endpoints[0], required = entry.target_required,
                                backoff_ms = state.backoff_ms, "Single-endpoint outage reconnect scheduled");
                        } else if pool.is_runtime_ready() {
                            warn!(dc = key.0, family = ?key.1, alive = entry.alive, required = entry.target_required,
                                endpoint_count = entry.endpoints.len(), backoff_ms = state.backoff_ms,
                                "DC writer floor is below required level, scheduled reconnect");
                        } else {
                            info!(dc = key.0, family = ?key.1, alive = entry.alive, required = entry.target_required,
                                endpoint_count = entry.endpoints.len(), backoff_ms = state.backoff_ms,
                                "DC writer floor is below required level during startup, scheduled reconnect");
                        }
                    }
                }
            }
            if health_tick {
                next_tick = tokio::time::Instant::now()
                    + if degraded {
                        pool.health_interval_unhealthy()
                    } else {
                        pool.health_interval_healthy()
                    };
            }
            observe = false;
            health_tick = false;
        }

        let budget = family::health_reconnect_budget(&pool, scheduler.groups.len());
        for _ in 0..scheduler.queue.len() {
            if tasks.len() >= budget {
                break;
            }
            let Some(key) = scheduler.queue.pop_front() else {
                break;
            };
            scheduler.queue.push_back(key);
            if scheduler.busy(key) {
                continue;
            }
            let Some(observation) = observations.get(&key.1).cloned() else {
                continue;
            };
            if pool.floor_authority() != observation.authority
                || pool.current_generation() != observation.generation
            {
                continue;
            }
            let Some(entry) = observation.floor.by_dc.get(&key.0).cloned() else {
                continue;
            };
            if entry.endpoints.is_empty() {
                continue;
            }
            let Some(state) = scheduler.groups.get_mut(&key) else {
                continue;
            };
            if state.deferred {
                continue;
            }
            let now = Instant::now();
            let recover =
                entry.alive < entry.target_required && state.due.is_none_or(|due| due <= now);
            let refresh = state.refresh_due.is_none_or(|due| due <= now)
                && idle_refresh_ready(&observation, &entry);
            let mut kind = if refresh && (!recover || state.prefer_refresh) {
                JobKind::Refresh
            } else if recover {
                JobKind::Recover
            } else if entry.alive >= entry.target_required
                && entry.endpoints.len() == 1
                && pool.single_endpoint_shadow_rotate_interval().is_some()
                && state.shadow_due.is_none_or(|due| due <= now)
            {
                JobKind::Shadow
            } else {
                continue;
            };
            if kind == JobKind::Recover {
                if pool
                    .has_refill_inflight_for_target(RefillTargetKey {
                        dc: key.0,
                        family: key.1,
                        generation: observation.generation,
                        endpoint_revision: observation.authority.0,
                        contour: WriterContour::Active,
                    })
                    .await
                {
                    continue;
                }
                // Preflight distinguishes capacity pressure from unreachable endpoints without
                // retaining an opening token while a group waits in the fair queue.
                let reservation = pool
                    .reserve_writer_open(
                        WriterContour::Active,
                        WriterOpenIntent::Coverage,
                        key.0,
                        entry.endpoints[0],
                    )
                    .await;
                if reservation.is_none() {
                    kind = JobKind::Transfer;
                }
                drop(reservation);
                if !state.round_active {
                    state.round = state.round.wrapping_add(1);
                    state.round_left = if state.outage {
                        1
                    } else {
                        entry.target_required.saturating_sub(entry.alive)
                    };
                    state.round_active = true;
                }
                state.prefer_refresh = true;
            } else if kind == JobKind::Refresh {
                state.prefer_refresh = false;
            }
            let job = HealthJob {
                key,
                kind,
                observation,
                entry,
                round: state.round,
            };
            let future = run_job(pool.clone(), rng.clone(), job.clone());
            let Ok(tracked) = pool.lifecycle.track_producer(future) else {
                return;
            };
            let id = tasks.spawn(tracked).id();
            scheduler.owners.insert(id, job);
        }

        let now = Instant::now();
        let deadline = scheduler
            .groups
            .values()
            .flat_map(|state| [state.due, state.refresh_due, state.shadow_due])
            .flatten()
            .filter(|due| *due > now)
            .min()
            .map(tokio::time::Instant::from_std)
            .map_or(next_tick, |due| due.min(next_tick));
        tokio::select! {
            joined = tasks.join_next_with_id(), if !tasks.is_empty() => {
                let Some(joined) = joined else { continue; };
                let (id, output) = match joined {
                    Ok((id, output)) => (id, output),
                    Err(error) => {
                        debug!(error = %error, "Health writer operation failed");
                        (error.id(), Some(JobOutcome::Completed(None)))
                    }
                };
                if let Some(job) = scheduler.owners.remove(&id)
                    && let Some(deadline) = output {
                    scheduler.completed(&pool, job, deadline);
                }
                observe = true;
            }
            _ = tokio::time::sleep_until(deadline) => {
                observe = true;
                health_tick = tokio::time::Instant::now() >= next_tick;
            }
        }
    }
}
