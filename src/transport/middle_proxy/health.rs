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
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        check_family(IpFamily::V4, &pool, &rng, &mut backoff, &mut last_attempt).await;
        check_family(IpFamily::V6, &pool, &rng, &mut backoff, &mut last_attempt).await;
    }
}

async fn check_family(
    family: IpFamily,
    pool: &Arc<MePool>,
    rng: &Arc<SecureRandom>,
    backoff: &mut HashMap<(i32, IpFamily), u64>,
    last_attempt: &mut HashMap<(i32, IpFamily), Instant>,
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

    for (dc, addrs) in map.iter() {
        let dc_addrs: Vec<SocketAddr> = addrs
            .iter()
            .map(|(ip, port)| SocketAddr::new(*ip, *port))
            .collect();
        let has_coverage = dc_addrs.iter().any(|a| writer_addrs.contains(a));
        if has_coverage {
            continue;
        }
        let key = (*dc, family);
        let delay = *backoff.get(&key).unwrap_or(&30);
        let now = Instant::now();
        if let Some(last) = last_attempt.get(&key) {
            if now.duration_since(*last).as_secs() < delay {
                continue;
            }
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
