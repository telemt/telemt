use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};
use rand::seq::SliceRandom;

use crate::crypto::SecureRandom;
use crate::network::IpFamily;

use super::MePool;

pub async fn me_health_monitor(pool: Arc<MePool>, rng: Arc<SecureRandom>, _min_connections: usize) {
    let mut backoff: HashMap<(i32, IpFamily), u64> = HashMap::new();
    let mut last_attempt: HashMap<(i32, IpFamily), Instant> = HashMap::new();
    let mut inflight_single: HashSet<(i32, IpFamily)> = HashSet::new();
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        check_family(
            IpFamily::V4,
            &pool,
            &rng,
            &mut backoff,
            &mut last_attempt,
            &mut inflight_single,
        )
        .await;
        check_family(
            IpFamily::V6,
            &pool,
            &rng,
            &mut backoff,
            &mut last_attempt,
            &mut inflight_single,
        )
        .await;
    }
}

async fn check_family(
    family: IpFamily,
    pool: &Arc<MePool>,
    rng: &Arc<SecureRandom>,
    backoff: &mut HashMap<(i32, IpFamily), u64>,
    last_attempt: &mut HashMap<(i32, IpFamily), Instant>,
    inflight_single: &mut HashSet<(i32, IpFamily)>,
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
            inflight_single.remove(&(dc, family));
            continue;
        }
        let key = (dc, family);
        let delay = *backoff.get(&key).unwrap_or(&30);
        let now = Instant::now();
        if let Some(last) = last_attempt.get(&key) {
            if now.duration_since(*last).as_secs() < delay {
                continue;
            }
        }
        if dc_addrs.len() == 1 {
            // Single ME address: fast retries then slower background retries.
            if inflight_single.contains(&key) {
                continue;
            }
            inflight_single.insert(key);
            let addr = dc_addrs[0];
            let dc_id = dc;
            let pool_clone = pool.clone();
            let rng_clone = rng.clone();
            let timeout = pool.me_one_timeout;
            let quick_attempts = pool.me_one_retry.max(1);
            tokio::spawn(async move {
                let mut success = false;
                for _ in 0..quick_attempts {
                    let res = tokio::time::timeout(timeout, pool_clone.connect_one(addr, rng_clone.as_ref())).await;
                    match res {
                        Ok(Ok(())) => {
                            info!(%addr, dc = %dc_id, ?family, "ME reconnected for DC coverage");
                            success = true;
                            break;
                        }
                        Ok(Err(e)) => debug!(%addr, dc = %dc_id, error = %e, ?family, "ME reconnect failed"),
                        Err(_) => debug!(%addr, dc = %dc_id, ?family, "ME reconnect timed out"),
                    }
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                }
                if success {
                    return;
                }
                let timeout_ms = timeout.as_millis();
                warn!(
                    dc = %dc_id,
                    ?family,
                    attempts = quick_attempts,
                    timeout_ms,
                    "DC={} has no ME coverage: {} tries * {} ms... retry in 5 seconds...",
                    dc_id,
                    quick_attempts,
                    timeout_ms
                );
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    let res = tokio::time::timeout(timeout, pool_clone.connect_one(addr, rng_clone.as_ref())).await;
                    match res {
                        Ok(Ok(())) => {
                            info!(%addr, dc = %dc_id, ?family, "ME reconnected for DC coverage");
                            break;
                        }
                        Ok(Err(e)) => debug!(%addr, dc = %dc_id, error = %e, ?family, "ME reconnect failed"),
                        Err(_) => debug!(%addr, dc = %dc_id, ?family, "ME reconnect timed out"),
                    }
                }
                // will drop inflight flag in outer loop when coverage detected
            });
            continue;
        }

        warn!(dc = %dc, delay, ?family, "DC has no ME coverage, reconnecting...");
        let mut shuffled = dc_addrs.clone();
        shuffled.shuffle(&mut rand::rng());
        let mut reconnected = false;
        for addr in shuffled {
            match pool.connect_one(addr, rng.as_ref()).await {
                Ok(()) => {
                    info!(%addr, dc = %dc, ?family, "ME reconnected for DC coverage");
                    backoff.insert(key, 30);
                    last_attempt.insert(key, now);
                    reconnected = true;
                    break;
                }
                Err(e) => debug!(%addr, dc = %dc, error = %e, ?family, "ME reconnect failed"),
            }
        }
        if !reconnected {
            let next = (*backoff.get(&key).unwrap_or(&30)).saturating_mul(2).min(300);
            backoff.insert(key, next);
            last_attempt.insert(key, now);
        }
    }
}
