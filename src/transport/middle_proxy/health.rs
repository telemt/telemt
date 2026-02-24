use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};
use rand::seq::SliceRandom;
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
    let writer_addrs: HashSet<SocketAddr> = pool
        .writers
        .read()
        .await
        .iter()
        .filter(|w| !w.draining.load(std::sync::atomic::Ordering::Relaxed))
        .map(|w| w.addr)
        .collect();

    let entries: Vec<(i32, Vec<SocketAddr>)> = map
        .iter()
        .map(|(dc, addrs)| {
            let list = addrs
                .iter()
                .map(|(ip, port)| SocketAddr::new(*ip, *port))
                .collect::<Vec<_>>();
            (*dc, list)
        })
        .collect();

    for (dc, dc_addrs) in entries {
        let has_coverage = dc_addrs.iter().any(|a| writer_addrs.contains(a));
        if has_coverage {
            continue;
        }

        let key = (dc, family);
        let now = Instant::now();
        if let Some(ts) = next_attempt.get(&key) {
            if now < *ts {
                continue;
            }
        }

        let max_concurrent = pool.me_reconnect_max_concurrent_per_dc.max(1) as usize;
        if *inflight.get(&key).unwrap_or(&0) >= max_concurrent {
            return;
        }
        *inflight.entry(key).or_insert(0) += 1;

        let mut shuffled = dc_addrs.clone();
        shuffled.shuffle(&mut rand::rng());
        let mut success = false;
        for addr in shuffled {
            let res = tokio::time::timeout(pool.me_one_timeout, pool.connect_one(addr, rng.as_ref())).await;
            match res {
                Ok(Ok(())) => {
                    info!(%addr, dc = %dc, ?family, "ME reconnected for DC coverage");
                    pool.stats.increment_me_reconnect_success();
                    backoff.insert(key, pool.me_reconnect_backoff_base.as_millis() as u64);
                    let jitter = pool.me_reconnect_backoff_base.as_millis() as u64 / JITTER_FRAC_NUM;
                    let wait = pool.me_reconnect_backoff_base
                        + Duration::from_millis(rand::rng().random_range(0..=jitter.max(1)));
                    next_attempt.insert(key, now + wait);
                    success = true;
                    break;
                }
                Ok(Err(e)) => {
                    pool.stats.increment_me_reconnect_attempt();
                    debug!(%addr, dc = %dc, error = %e, ?family, "ME reconnect failed")
                }
                Err(_) => debug!(%addr, dc = %dc, ?family, "ME reconnect timed out"),
            }
        }
        if !success {
            pool.stats.increment_me_reconnect_attempt();
            let curr = *backoff.get(&key).unwrap_or(&(pool.me_reconnect_backoff_base.as_millis() as u64));
            let next_ms = (curr.saturating_mul(2)).min(pool.me_reconnect_backoff_cap.as_millis() as u64);
            backoff.insert(key, next_ms);
            let jitter = next_ms / JITTER_FRAC_NUM;
            let wait = Duration::from_millis(next_ms)
                + Duration::from_millis(rand::rng().random_range(0..=jitter.max(1)));
            next_attempt.insert(key, now + wait);
            warn!(dc = %dc, backoff_ms = next_ms, ?family, "DC has no ME coverage, scheduled reconnect");
        }
        if let Some(v) = inflight.get_mut(&key) {
            *v = v.saturating_sub(1);
        }
    }
}
