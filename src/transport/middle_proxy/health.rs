use std::collections::HashMap;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::Rng;
use tracing::{debug, info, warn};

use crate::crypto::SecureRandom;
use crate::network::IpFamily;

use super::MePool;

const HEALTH_INTERVAL_SECS: u64 = 1;
const JITTER_FRAC_NUM: u64 = 2; // jitter up to 50% of backoff
#[allow(dead_code)]
const MAX_CONCURRENT_PER_DC_DEFAULT: usize = 1;
const SHADOW_ROTATE_RETRY_SECS: u64 = 30;

pub async fn me_health_monitor(pool: Arc<MePool>, rng: Arc<SecureRandom>, _min_connections: usize) {
    let mut backoff: HashMap<(i32, IpFamily), u64> = HashMap::new();
    let mut next_attempt: HashMap<(i32, IpFamily), Instant> = HashMap::new();
    let mut inflight: HashMap<(i32, IpFamily), usize> = HashMap::new();
    let mut outage_backoff: HashMap<(i32, IpFamily), u64> = HashMap::new();
    let mut outage_next_attempt: HashMap<(i32, IpFamily), Instant> = HashMap::new();
    let mut single_endpoint_outage: HashSet<(i32, IpFamily)> = HashSet::new();
    let mut shadow_rotate_deadline: HashMap<(i32, IpFamily), Instant> = HashMap::new();
    loop {
        tokio::time::sleep(Duration::from_secs(HEALTH_INTERVAL_SECS)).await;
        pool.prune_closed_writers().await;
        check_family(
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
        )
        .await;
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
        )
        .await;
    }
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
) {
    let enabled = match family {
        IpFamily::V4 => pool.decision.ipv4_me,
        IpFamily::V6 => pool.decision.ipv6_me,
    };
    if !enabled {
        return;
    }

    let map = match family {
        IpFamily::V4 => pool.proxy_map_v4.read().await.clone(),
        IpFamily::V6 => pool.proxy_map_v6.read().await.clone(),
    };

    let mut dc_endpoints = HashMap::<i32, Vec<SocketAddr>>::new();
    for (dc, addrs) in map {
        let entry = dc_endpoints.entry(dc.abs()).or_default();
        for (ip, port) in addrs {
            entry.push(SocketAddr::new(ip, port));
        }
    }
    for endpoints in dc_endpoints.values_mut() {
        endpoints.sort_unstable();
        endpoints.dedup();
    }

    let mut live_addr_counts = HashMap::<SocketAddr, usize>::new();
    let mut live_writer_ids_by_addr = HashMap::<SocketAddr, Vec<u64>>::new();
    for writer in pool.writers.read().await.iter().filter(|w| {
        !w.draining.load(std::sync::atomic::Ordering::Relaxed)
    }) {
        *live_addr_counts.entry(writer.addr).or_insert(0) += 1;
        live_writer_ids_by_addr
            .entry(writer.addr)
            .or_default()
            .push(writer.id);
    }

    for (dc, endpoints) in dc_endpoints {
        if endpoints.is_empty() {
            continue;
        }
        let required = pool.required_writers_for_dc(endpoints.len());
        let alive = endpoints
            .iter()
            .map(|addr| *live_addr_counts.get(addr).unwrap_or(&0))
            .sum::<usize>();
        let key = (dc, family);

        if endpoints.len() == 1 && pool.single_endpoint_outage_mode_enabled() && alive == 0 {
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
            )
            .await;
            continue;
        }

        if single_endpoint_outage.remove(&key) {
            pool.stats.increment_me_single_endpoint_outage_exit_total();
            outage_backoff.remove(&key);
            outage_next_attempt.remove(&key);
            shadow_rotate_deadline.remove(&key);
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
                shadow_rotate_deadline,
            )
            .await;
            continue;
        }
        let missing = required - alive;

        let now = Instant::now();
        if let Some(ts) = next_attempt.get(&key)
            && now < *ts
        {
            continue;
        }

        let max_concurrent = pool.me_reconnect_max_concurrent_per_dc.max(1) as usize;
        if *inflight.get(&key).unwrap_or(&0) >= max_concurrent {
            continue;
        }
        if pool.has_refill_inflight_for_endpoints(&endpoints).await {
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
            let res = tokio::time::timeout(
                pool.me_one_timeout,
                pool.connect_endpoints_round_robin(&endpoints, rng.as_ref()),
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
        if let Some(v) = inflight.get_mut(&key) {
            *v = v.saturating_sub(1);
        }
    }
}

async fn recover_single_endpoint_outage(
    pool: &Arc<MePool>,
    rng: &Arc<SecureRandom>,
    key: (i32, IpFamily),
    endpoint: SocketAddr,
    required: usize,
    outage_backoff: &mut HashMap<(i32, IpFamily), u64>,
    outage_next_attempt: &mut HashMap<(i32, IpFamily), Instant>,
) {
    let now = Instant::now();
    if let Some(ts) = outage_next_attempt.get(&key)
        && now < *ts
    {
        return;
    }

    let (min_backoff_ms, max_backoff_ms) = pool.single_endpoint_outage_backoff_bounds_ms();
    pool.stats
        .increment_me_single_endpoint_outage_reconnect_attempt_total();

    let bypass_quarantine = pool.single_endpoint_outage_disable_quarantine();
    let attempt_ok = if bypass_quarantine {
        pool.stats
            .increment_me_single_endpoint_quarantine_bypass_total();
        match tokio::time::timeout(pool.me_one_timeout, pool.connect_one(endpoint, rng.as_ref())).await {
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
            pool.connect_endpoints_round_robin(&one_endpoint, rng.as_ref()),
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
    live_writer_ids_by_addr: &HashMap<SocketAddr, Vec<u64>>,
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

    let Some(writer_ids) = live_writer_ids_by_addr.get(&endpoint) else {
        shadow_rotate_deadline.insert(key, now + Duration::from_secs(SHADOW_ROTATE_RETRY_SECS));
        return;
    };

    let mut candidate_writer_id = None;
    for writer_id in writer_ids {
        if pool.registry.is_writer_empty(*writer_id).await {
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

    let rotate_ok = match tokio::time::timeout(pool.me_one_timeout, pool.connect_one(endpoint, rng.as_ref())).await {
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
