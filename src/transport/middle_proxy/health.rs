use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};
use rand::Rng;

use crate::crypto::SecureRandom;
use crate::network::IpFamily;

use super::MePool;

const HEALTH_INTERVAL_SECS: u64 = 1;
const JITTER_FRAC_NUM: u64 = 2; // jitter up to 50% of backoff
#[allow(dead_code)]
const MAX_CONCURRENT_PER_DC_DEFAULT: usize = 1;

pub async fn me_health_monitor(pool: Arc<MePool>, rng: Arc<SecureRandom>, _min_connections: usize) {
    let mut backoff: HashMap<(i32, IpFamily), u64> = HashMap::new();
    let mut next_attempt: HashMap<(i32, IpFamily), Instant> = HashMap::new();
    let mut inflight: HashMap<(i32, IpFamily), usize> = HashMap::new();
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
        )
        .await;
        check_family(
            IpFamily::V6,
            &pool,
            &rng,
            &mut backoff,
            &mut next_attempt,
            &mut inflight,
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
    for writer in pool
        .writers
        .read()
        .await
        .iter()
        .filter(|w| !w.draining.load(std::sync::atomic::Ordering::Relaxed))
    {
        *live_addr_counts.entry(writer.addr).or_insert(0) += 1;
    }

    for (dc, endpoints) in dc_endpoints {
        if endpoints.is_empty() {
            continue;
        }
        let required = MePool::required_writers_for_dc(endpoints.len());
        let alive = endpoints
            .iter()
            .map(|addr| *live_addr_counts.get(addr).unwrap_or(&0))
            .sum::<usize>();
        if alive >= required {
            continue;
        }
        let missing = required - alive;

        let key = (dc, family);
        let now = Instant::now();
        if let Some(ts) = next_attempt.get(&key)
            && now < *ts
        {
            continue;
        }

        let max_concurrent = pool.me_reconnect_max_concurrent_per_dc.max(1) as usize;
        if *inflight.get(&key).unwrap_or(&0) >= max_concurrent {
            return;
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
