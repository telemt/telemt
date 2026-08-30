use super::*;

pub(super) async fn check_family(
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
    floor_warn_next_allowed: &mut HashMap<(i32, IpFamily), Instant>,
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
    let reconnect_budget = health_reconnect_budget(pool, dc_endpoints.len());
    let reconnect_sem = Arc::new(Semaphore::new(reconnect_budget));

    if pool.floor_mode() == MeFloorMode::Static {}

    let mut live_addr_counts = HashMap::<(i32, SocketAddr), usize>::new();
    let mut live_writer_ids_by_addr = HashMap::<(i32, SocketAddr), Vec<u64>>::new();
    for writer in pool
        .writers
        .read()
        .await
        .iter()
        .filter(|w| !w.draining.load(std::sync::atomic::Ordering::Relaxed))
    {
        if !matches!(
            crate::transport::middle_proxy::pool::WriterContour::from_u8(
                writer.contour.load(std::sync::atomic::Ordering::Relaxed),
            ),
            crate::transport::middle_proxy::pool::WriterContour::Active
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
    let live_writer_ids_by_addr = Arc::new(live_writer_ids_by_addr);
    let writer_idle_since = Arc::new(writer_idle_since);
    let bound_clients_by_writer = Arc::new(bound_clients_by_writer);
    let mut reconnect_set = JoinSet::<FamilyReconnectOutcome>::new();
    let mut scheduled_reconnects = ScheduledReconnects {
        inflight,
        keys: Vec::new(),
    };

    for (dc, endpoints) in dc_endpoints {
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
                &reconnect_sem,
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
                live_writer_ids_by_addr.as_ref(),
                writer_idle_since.as_ref(),
                bound_clients_by_writer.as_ref(),
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
                live_writer_ids_by_addr.as_ref(),
                bound_clients_by_writer.as_ref(),
                shadow_rotate_deadline,
            )
            .await;
            continue;
        }
        let missing = required - alive;
        family_degraded = true;

        let now = Instant::now();
        if reconnect_sem.available_permits() == 0 {
            let base_ms = pool.reconnect_runtime.me_reconnect_backoff_base.as_millis() as u64;
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

        let max_concurrent = pool
            .reconnect_runtime
            .me_reconnect_max_concurrent_per_dc
            .max(1) as usize;
        if scheduled_reconnects.current(&key) >= max_concurrent {
            continue;
        }
        if pool
            .has_refill_inflight_for_dc_key(crate::transport::middle_proxy::pool::RefillDcKey {
                dc,
                family,
            })
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
        scheduled_reconnects.reserve(key);
        let pool_for_reconnect = pool.clone();
        let rng_for_reconnect = rng.clone();
        let reconnect_sem_for_dc = reconnect_sem.clone();
        let endpoints_for_dc = endpoints.clone();
        let live_writer_ids_by_addr_for_dc = live_writer_ids_by_addr.clone();
        let writer_idle_since_for_dc = writer_idle_since.clone();
        let bound_clients_by_writer_for_dc = bound_clients_by_writer.clone();
        let active_cap_effective_total = floor_plan.active_cap_effective_total;
        reconnect_set.spawn(async move {
            let mut restored = 0usize;
            for _ in 0..missing {
                let Ok(reconnect_permit) = reconnect_sem_for_dc.clone().try_acquire_owned() else {
                    break;
                };
                if pool_for_reconnect.active_contour_writer_count_total().await
                    >= active_cap_effective_total
                {
                    let swapped = maybe_swap_idle_writer_for_cap(
                        &pool_for_reconnect,
                        &rng_for_reconnect,
                        dc,
                        family,
                        &endpoints_for_dc,
                        live_writer_ids_by_addr_for_dc.as_ref(),
                        writer_idle_since_for_dc.as_ref(),
                        bound_clients_by_writer_for_dc.as_ref(),
                    )
                    .await;
                    if swapped {
                        pool_for_reconnect
                            .stats
                            .increment_me_floor_swap_idle_total();
                        restored += 1;
                        continue;
                    }

                    let base_req = pool_for_reconnect
                        .required_writers_for_dc_with_floor_mode(endpoints_for_dc.len(), false);
                    if alive + restored >= base_req {
                        pool_for_reconnect
                            .stats
                            .increment_me_floor_cap_block_total();
                        pool_for_reconnect
                            .stats
                            .increment_me_floor_swap_idle_failed_total();
                        debug!(
                            dc = %dc,
                            ?family,
                            alive,
                            required,
                            active_cap_effective_total,
                            "Adaptive floor cap reached, reconnect attempt blocked"
                        );
                        break;
                    }
                }
                pool_for_reconnect.stats.increment_me_reconnect_attempt();
                let res = tokio::time::timeout(
                    pool_for_reconnect.reconnect_runtime.me_one_timeout,
                    pool_for_reconnect.connect_endpoints_round_robin(
                        dc,
                        &endpoints_for_dc,
                        rng_for_reconnect.as_ref(),
                    ),
                )
                .await;
                match res {
                    Ok(true) => {
                        restored += 1;
                        pool_for_reconnect.stats.increment_me_reconnect_success();
                    }
                    Ok(false) => {
                        debug!(dc = %dc, ?family, "ME round-robin reconnect failed")
                    }
                    Err(_) => {
                        debug!(dc = %dc, ?family, "ME reconnect timed out");
                    }
                }
                drop(reconnect_permit);
            }

            FamilyReconnectOutcome {
                key,
                dc,
                family,
                required,
                endpoint_count: endpoints_for_dc.len(),
            }
        });
    }

    while let Some(joined) = reconnect_set.join_next().await {
        let outcome = match joined {
            Ok(outcome) => outcome,
            Err(join_error) => {
                debug!(error = %join_error, "Health reconnect task failed");
                continue;
            }
        };
        let now = Instant::now();
        let now_alive = live_active_writers_for_dc_family(pool, outcome.dc, outcome.family).await;
        if now_alive >= outcome.required {
            info!(
                dc = %outcome.dc,
                family = ?outcome.family,
                alive = now_alive,
                required = outcome.required,
                endpoint_count = outcome.endpoint_count,
                "ME writer floor restored for DC"
            );
            backoff.insert(
                outcome.key,
                pool.reconnect_runtime.me_reconnect_backoff_base.as_millis() as u64,
            );
            let jitter = pool.reconnect_runtime.me_reconnect_backoff_base.as_millis() as u64
                / JITTER_FRAC_NUM;
            let wait = pool.reconnect_runtime.me_reconnect_backoff_base
                + Duration::from_millis(rand::rng().random_range(0..=jitter.max(1)));
            next_attempt.insert(outcome.key, now + wait);
        } else {
            let curr = *backoff
                .get(&outcome.key)
                .unwrap_or(&(pool.reconnect_runtime.me_reconnect_backoff_base.as_millis() as u64));
            let next_ms = (curr.saturating_mul(2))
                .min(pool.reconnect_runtime.me_reconnect_backoff_cap.as_millis() as u64);
            backoff.insert(outcome.key, next_ms);
            let jitter = next_ms / JITTER_FRAC_NUM;
            let wait = Duration::from_millis(next_ms)
                + Duration::from_millis(rand::rng().random_range(0..=jitter.max(1)));
            next_attempt.insert(outcome.key, now + wait);
            if pool.is_runtime_ready() {
                let warn_cooldown = pool.warn_rate_limit_duration();
                if should_emit_rate_limited_warn(
                    floor_warn_next_allowed,
                    outcome.key,
                    now,
                    warn_cooldown,
                ) {
                    warn!(
                        dc = %outcome.dc,
                        family = ?outcome.family,
                        alive = now_alive,
                        required = outcome.required,
                        endpoint_count = outcome.endpoint_count,
                        backoff_ms = next_ms,
                        "DC writer floor is below required level, scheduled reconnect"
                    );
                }
            } else {
                info!(
                    dc = %outcome.dc,
                    family = ?outcome.family,
                    alive = now_alive,
                    required = outcome.required,
                    endpoint_count = outcome.endpoint_count,
                    backoff_ms = next_ms,
                    "DC writer floor is below required level during startup, scheduled reconnect"
                );
            }
        }
    }

    family_degraded
}

pub(super) fn health_reconnect_budget(pool: &Arc<MePool>, dc_groups: usize) -> usize {
    let cpu_cores = pool.adaptive_floor_effective_cpu_cores().max(1);
    let by_cpu = cpu_cores.saturating_mul(HEALTH_RECONNECT_BUDGET_PER_CORE);
    let by_dc = dc_groups.saturating_mul(HEALTH_RECONNECT_BUDGET_PER_DC);
    by_cpu
        .saturating_add(by_dc)
        .clamp(HEALTH_RECONNECT_BUDGET_MIN, HEALTH_RECONNECT_BUDGET_MAX)
}

pub(super) fn update_family_runtime_state(pool: &Arc<MePool>, family: IpFamily, degraded: bool) {
    let now_epoch_secs = MePool::now_epoch_secs();
    let previous_state = pool.family_runtime_state(family);
    let mut state_since_epoch_secs = pool.family_runtime_state_since_epoch_secs(family);
    let previous_suppressed_until_epoch_secs = pool.family_suppressed_until_epoch_secs(family);
    let previous_fail_streak = pool.family_fail_streak(family);
    let previous_recover_success_streak = pool.family_recover_success_streak(family);

    let (next_state, suppressed_until_epoch_secs, fail_streak, recover_success_streak) =
        if previous_suppressed_until_epoch_secs > now_epoch_secs {
            let fail_streak = if degraded {
                previous_fail_streak.saturating_add(1)
            } else {
                previous_fail_streak
            };
            (
                MeFamilyRuntimeState::Suppressed,
                previous_suppressed_until_epoch_secs,
                fail_streak,
                0,
            )
        } else if degraded {
            let fail_streak = previous_fail_streak.saturating_add(1);
            if fail_streak >= FAMILY_SUPPRESS_FAIL_STREAK_THRESHOLD {
                (
                    MeFamilyRuntimeState::Suppressed,
                    now_epoch_secs.saturating_add(FAMILY_SUPPRESS_DURATION_SECS),
                    fail_streak,
                    0,
                )
            } else {
                (MeFamilyRuntimeState::Degraded, 0, fail_streak, 0)
            }
        } else if matches!(previous_state, MeFamilyRuntimeState::Healthy) {
            (MeFamilyRuntimeState::Healthy, 0, 0, 0)
        } else {
            let recover_success_streak = previous_recover_success_streak.saturating_add(1);
            if recover_success_streak >= FAMILY_RECOVER_SUCCESS_STREAK_TARGET {
                (MeFamilyRuntimeState::Healthy, 0, 0, 0)
            } else {
                (
                    MeFamilyRuntimeState::Recovering,
                    0,
                    0,
                    recover_success_streak,
                )
            }
        };

    if next_state != previous_state || state_since_epoch_secs == 0 {
        state_since_epoch_secs = now_epoch_secs;
    }
    pool.set_family_runtime_state(
        family,
        next_state,
        state_since_epoch_secs,
        suppressed_until_epoch_secs,
        fail_streak,
        recover_success_streak,
    );
}
