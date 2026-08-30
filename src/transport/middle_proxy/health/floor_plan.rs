use super::*;

pub(super) fn should_emit_rate_limited_warn(
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

pub(super) async fn live_active_writers_for_dc_family(
    pool: &Arc<MePool>,
    dc: i32,
    family: IpFamily,
) -> usize {
    let writers = pool.writers.read().await;
    writers
        .iter()
        .filter(|writer| {
            if writer.draining.load(std::sync::atomic::Ordering::Relaxed) {
                return false;
            }
            if writer.writer_dc != dc {
                return false;
            }
            if !matches!(
                crate::transport::middle_proxy::pool::WriterContour::from_u8(
                    writer.contour.load(std::sync::atomic::Ordering::Relaxed),
                ),
                crate::transport::middle_proxy::pool::WriterContour::Active
            ) {
                return false;
            }
            match family {
                IpFamily::V4 => writer.addr.is_ipv4(),
                IpFamily::V6 => writer.addr.is_ipv6(),
            }
        })
        .count()
}

pub(super) fn adaptive_floor_class_min(
    pool: &Arc<MePool>,
    endpoint_count: usize,
    base_required: usize,
) -> usize {
    if endpoint_count <= 1 {
        let min_single = (pool
            .floor_runtime
            .me_adaptive_floor_min_writers_single_endpoint
            .load(std::sync::atomic::Ordering::Relaxed) as usize)
            .max(1);
        min_single.min(base_required.max(1))
    } else {
        pool.adaptive_floor_min_writers_multi_endpoint()
            .min(base_required.max(1))
    }
}

pub(super) fn adaptive_floor_class_max(
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

pub(super) fn list_writer_ids_for_endpoints(
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

pub(super) async fn build_family_floor_plan(
    pool: &Arc<MePool>,
    family: IpFamily,
    dc_endpoints: &HashMap<i32, Vec<SocketAddr>>,
    live_addr_counts: &HashMap<(i32, SocketAddr), usize>,
    live_writer_ids_by_addr: &HashMap<(i32, SocketAddr), Vec<u64>>,
    bound_clients_by_writer: &HashMap<u64, usize>,
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
        let _key = (*dc, family);
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
        // We initialize target_required at base_required to prevent 0-writer blackouts
        // caused by proactively dropping an idle DC to a single fragile connection.
        // The Adaptive Floor constraint loop below will gracefully compress idle DCs
        // (prioritized via has_bound_clients = false) to min_required only when global capacity is reached.
        let desired_raw = base_required;
        let target_required = desired_raw.clamp(min_required, max_required);
        let alive = endpoints
            .iter()
            .map(|endpoint| {
                live_addr_counts
                    .get(&(*dc, *endpoint))
                    .copied()
                    .unwrap_or(0)
            })
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
