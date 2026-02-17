use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};
use rand::seq::SliceRandom;

use crate::crypto::SecureRandom;

use super::MePool;

pub async fn me_health_monitor(pool: Arc<MePool>, rng: Arc<SecureRandom>, _min_connections: usize, ipv6_available: bool) {
    let mut backoff: HashMap<i32, u64> = HashMap::new();
    let mut last_attempt: HashMap<i32, Instant> = HashMap::new();
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        // Per-DC coverage check
        let map = pool.proxy_map_v4.read().await.clone();
        let writer_addrs: std::collections::HashSet<SocketAddr> = pool
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
            if !has_coverage {
                let delay = *backoff.get(dc).unwrap_or(&30);
                let now = Instant::now();
                if let Some(last) = last_attempt.get(dc) {
                    if now.duration_since(*last).as_secs() < delay {
                        continue;
                    }
                }
                warn!(dc = %dc, delay, "DC has no ME coverage, reconnecting...");
                let mut shuffled = dc_addrs.clone();
                shuffled.shuffle(&mut rand::rng());
                let mut reconnected = false;
                for addr in shuffled {
                    match pool.connect_one(addr, &rng).await {
                        Ok(()) => {
                            info!(%addr, dc = %dc, "ME reconnected for DC coverage");
                            backoff.insert(*dc, 30);
                            last_attempt.insert(*dc, now);
                            reconnected = true;
                            break;
                        }
                        Err(e) => debug!(%addr, dc = %dc, error = %e, "ME reconnect failed"),
                    }
                }
                if !reconnected {
                    let next = (*backoff.get(dc).unwrap_or(&30)).saturating_mul(2).min(300);
                    backoff.insert(*dc, next);
                    last_attempt.insert(*dc, now);
                }
            }
        }

        // IPv6 coverage check (skip if IPv6 not available on host)
        if !ipv6_available {
            continue;
        }
        let map_v6 = pool.proxy_map_v6.read().await.clone();
        let writer_addrs_v6: std::collections::HashSet<SocketAddr> = pool
            .writers
            .read()
            .await
            .iter()
            .map(|w| w.addr)
            .collect();
        for (dc, addrs) in map_v6.iter() {
            let dc_addrs: Vec<SocketAddr> = addrs
                .iter()
                .map(|(ip, port)| SocketAddr::new(*ip, *port))
                .collect();
            let has_coverage = dc_addrs.iter().any(|a| writer_addrs_v6.contains(a));
            if !has_coverage {
                let delay = *backoff.get(dc).unwrap_or(&30);
                let now = Instant::now();
                if let Some(last) = last_attempt.get(dc) {
                    if now.duration_since(*last).as_secs() < delay {
                        continue;
                    }
                }
                warn!(dc = %dc, delay, "IPv6 DC has no ME coverage, reconnecting...");
                let mut shuffled = dc_addrs.clone();
                shuffled.shuffle(&mut rand::rng());
                let mut reconnected = false;
                for addr in shuffled {
                    match pool.connect_one(addr, &rng).await {
                        Ok(()) => {
                            info!(%addr, dc = %dc, "ME reconnected for IPv6 DC coverage");
                            backoff.insert(*dc, 30);
                            last_attempt.insert(*dc, now);
                            reconnected = true;
                            break;
                        }
                        Err(e) => debug!(%addr, dc = %dc, error = %e, "ME reconnect failed (IPv6)"),
                    }
                }
                if !reconnected {
                    let next = (*backoff.get(dc).unwrap_or(&30)).saturating_mul(2).min(300);
                    backoff.insert(*dc, next);
                    last_attempt.insert(*dc, now);
                }
            }
        }
    }
}
