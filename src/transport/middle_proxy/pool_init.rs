use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rand::Rng;
use rand::seq::SliceRandom;
use tracing::{debug, info, warn};

use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};

use super::pool::MePool;

impl MePool {
    pub async fn init(self: &Arc<Self>, pool_size: usize, rng: &Arc<SecureRandom>) -> Result<()> {
        let family_order = self.family_order();
        let ks = self.key_selector().await;
        info!(
            me_servers = self.proxy_map_v4.read().await.len(),
            pool_size,
            key_selector = format_args!("0x{ks:08x}"),
            secret_len = self.proxy_secret.read().await.len(),
            "Initializing ME pool"
        );

        for family in family_order {
            let map = self.proxy_map_for_family(family).await;
            let mut grouped_dc_addrs: HashMap<i32, Vec<(IpAddr, u16)>> = HashMap::new();
            for (dc, addrs) in map {
                if addrs.is_empty() {
                    continue;
                }
                grouped_dc_addrs.entry(dc.abs()).or_default().extend(addrs);
            }
            let mut dc_addrs: Vec<(i32, Vec<(IpAddr, u16)>)> = grouped_dc_addrs
                .into_iter()
                .map(|(dc, mut addrs)| {
                    addrs.sort_unstable();
                    addrs.dedup();
                    (dc, addrs)
                })
                .collect();
            dc_addrs.sort_unstable_by_key(|(dc, _)| *dc);

            // Ensure at least one live writer per DC group; run missing DCs in parallel.
            let mut join = tokio::task::JoinSet::new();
            for (dc, addrs) in dc_addrs.iter().cloned() {
                if addrs.is_empty() {
                    continue;
                }
                let endpoints: HashSet<SocketAddr> = addrs
                    .iter()
                    .map(|(ip, port)| SocketAddr::new(*ip, *port))
                    .collect();
                if self.active_writer_count_for_endpoints(&endpoints).await > 0 {
                    continue;
                }
                let pool = Arc::clone(self);
                let rng_clone = Arc::clone(rng);
                join.spawn(async move { pool.connect_primary_for_dc(dc, addrs, rng_clone).await });
            }
            while join.join_next().await.is_some() {}

            let mut missing_dcs = Vec::new();
            for (dc, addrs) in &dc_addrs {
                let endpoints: HashSet<SocketAddr> = addrs
                    .iter()
                    .map(|(ip, port)| SocketAddr::new(*ip, *port))
                    .collect();
                if self.active_writer_count_for_endpoints(&endpoints).await == 0 {
                    missing_dcs.push(*dc);
                }
            }
            if !missing_dcs.is_empty() {
                return Err(ProxyError::Proxy(format!(
                    "ME init incomplete: no live writers for DC groups {missing_dcs:?}"
                )));
            }

            // Warm reserve writers asynchronously so startup does not block after first working pool is ready.
            let pool = Arc::clone(self);
            let rng_clone = Arc::clone(rng);
            let dc_addrs_bg = dc_addrs.clone();
            tokio::spawn(async move {
                if pool.me_warmup_stagger_enabled {
                    for (dc, addrs) in &dc_addrs_bg {
                        for (ip, port) in addrs {
                            if pool.connection_count() >= pool_size {
                                break;
                            }
                            let addr = SocketAddr::new(*ip, *port);
                            let jitter = rand::rng()
                                .random_range(0..=pool.me_warmup_step_jitter.as_millis() as u64);
                            let delay_ms = pool.me_warmup_step_delay.as_millis() as u64 + jitter;
                            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                            if let Err(e) = pool.connect_one(addr, rng_clone.as_ref()).await {
                                debug!(%addr, dc = %dc, error = %e, "Extra ME connect failed (staggered)");
                            }
                        }
                    }
                } else {
                    for (dc, addrs) in &dc_addrs_bg {
                        for (ip, port) in addrs {
                            if pool.connection_count() >= pool_size {
                                break;
                            }
                            let addr = SocketAddr::new(*ip, *port);
                            if let Err(e) = pool.connect_one(addr, rng_clone.as_ref()).await {
                                debug!(%addr, dc = %dc, error = %e, "Extra ME connect failed");
                            }
                        }
                        if pool.connection_count() >= pool_size {
                            break;
                        }
                    }
                }
                debug!(
                    target_pool_size = pool_size,
                    current_pool_size = pool.connection_count(),
                    "Background ME reserve warmup finished"
                );
            });

            if !self.decision.effective_multipath && self.connection_count() > 0 {
                break;
            }
        }

        if self.writers.read().await.is_empty() {
            return Err(ProxyError::Proxy("No ME connections".into()));
        }
        info!(
            active_writers = self.connection_count(),
            "ME primary pool ready; reserve warmup continues in background"
        );
        Ok(())
    }

    async fn connect_primary_for_dc(
        self: Arc<Self>,
        dc: i32,
        mut addrs: Vec<(IpAddr, u16)>,
        rng: Arc<SecureRandom>,
    ) -> bool {
        if addrs.is_empty() {
            return false;
        }
        addrs.shuffle(&mut rand::rng());
        if addrs.len() > 1 {
            let concurrency = 2usize;
            let mut join = tokio::task::JoinSet::new();
            let mut next_idx = 0usize;

            while next_idx < addrs.len() || !join.is_empty() {
                while next_idx < addrs.len() && join.len() < concurrency {
                    let (ip, port) = addrs[next_idx];
                    next_idx += 1;
                    let addr = SocketAddr::new(ip, port);
                    let pool = Arc::clone(&self);
                    let rng_clone = Arc::clone(&rng);
                    join.spawn(async move {
                        (addr, pool.connect_one(addr, rng_clone.as_ref()).await)
                    });
                }

                let Some(res) = join.join_next().await else {
                    break;
                };
                match res {
                    Ok((addr, Ok(()))) => {
                        info!(%addr, dc = %dc, "ME connected");
                        join.abort_all();
                        while join.join_next().await.is_some() {}
                        return true;
                    }
                    Ok((addr, Err(e))) => {
                        warn!(%addr, dc = %dc, error = %e, "ME connect failed, trying next");
                    }
                    Err(e) => {
                        warn!(dc = %dc, error = %e, "ME connect task failed");
                    }
                }
            }
            warn!(dc = %dc, "All ME servers for DC failed at init");
            return false;
        }

        for (ip, port) in addrs {
            let addr = SocketAddr::new(ip, port);
            match self.connect_one(addr, rng.as_ref()).await {
                Ok(()) => {
                    info!(%addr, dc = %dc, "ME connected");
                    return true;
                }
                Err(e) => warn!(%addr, dc = %dc, error = %e, "ME connect failed, trying next"),
            }
        }
        warn!(dc = %dc, "All ME servers for DC failed at init");
        false
    }
}
