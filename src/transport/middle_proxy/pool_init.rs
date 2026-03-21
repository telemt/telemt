use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rand::RngExt;
use rand::seq::SliceRandom;
use tracing::{debug, info, warn};

use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};

use super::pool::MePool;

impl MePool {
    pub async fn init(self: &Arc<Self>, pool_size: usize, rng: &Arc<SecureRandom>) -> Result<()> {
        let family_order = self.family_order();
        let connect_concurrency = self.me_reconnect_max_concurrent_per_dc.max(1) as usize;
        let ks = self.key_selector().await;
        info!(
            me_servers = self.proxy_map_v4.read().await.len(),
            pool_size,
            connect_concurrency,
            key_selector = format_args!("0x{ks:08x}"),
            secret_len = self.proxy_secret.read().await.secret.len(),
            "Initializing ME pool"
        );

        for family in family_order {
            let map = self.proxy_map_for_family(family).await;
            let mut dc_addrs: Vec<(i32, Vec<(IpAddr, u16)>)> = map
                .into_iter()
                .map(|(dc, mut addrs)| {
                    addrs.sort_unstable();
                    addrs.dedup();
                    (dc, addrs)
                })
                .filter(|(_, addrs)| !addrs.is_empty())
                .collect();
            dc_addrs.sort_unstable_by_key(|(dc, _)| *dc);
            dc_addrs.sort_by_key(|(_, addrs)| (addrs.len() != 1, addrs.len()));

            // Stage 1: build base coverage for conditional-cast.
            // Single-endpoint DCs are prefilled first; multi-endpoint DCs require one live writer.
            let mut join = tokio::task::JoinSet::new();
            for (dc, addrs) in dc_addrs.iter().cloned() {
                if addrs.is_empty() {
                    continue;
                }
                let target_writers = if addrs.len() == 1 {
                    self.required_writers_for_dc_with_floor_mode(addrs.len(), false)
                } else {
                    1usize
                };
                let endpoints: HashSet<SocketAddr> = addrs
                    .iter()
                    .map(|(ip, port)| SocketAddr::new(*ip, *port))
                    .collect();
                if self
                    .active_writer_count_for_dc_endpoints(dc, &endpoints)
                    .await
                    >= target_writers
                {
                    continue;
                }
                let pool = Arc::clone(self);
                let rng_clone = Arc::clone(rng);
                join.spawn(async move {
                    pool.connect_primary_for_dc(
                        dc,
                        addrs,
                        target_writers,
                        rng_clone,
                        connect_concurrency,
                        true,
                    )
                    .await
                });
            }
            while join.join_next().await.is_some() {}

            let mut missing_dcs = Vec::new();
            for (dc, addrs) in &dc_addrs {
                let endpoints: HashSet<SocketAddr> = addrs
                    .iter()
                    .map(|(ip, port)| SocketAddr::new(*ip, *port))
                    .collect();
                if self
                    .active_writer_count_for_dc_endpoints(*dc, &endpoints)
                    .await
                    == 0
                {
                    missing_dcs.push(*dc);
                }
            }
            if !missing_dcs.is_empty() {
                return Err(ProxyError::Proxy(format!(
                    "ME init incomplete: no live writers for DC groups {missing_dcs:?}"
                )));
            }

            // Stage 2: continue saturating multi-endpoint DC groups in background.
            let pool = Arc::clone(self);
            let rng_clone = Arc::clone(rng);
            let dc_addrs_bg = dc_addrs.clone();
            tokio::spawn(async move {
                let mut join_bg = tokio::task::JoinSet::new();
                for (dc, addrs) in dc_addrs_bg {
                    if addrs.len() <= 1 {
                        continue;
                    }
                    let target_writers =
                        pool.required_writers_for_dc_with_floor_mode(addrs.len(), false);
                    let pool_clone = Arc::clone(&pool);
                    let rng_clone_local = Arc::clone(&rng_clone);
                    join_bg.spawn(async move {
                        pool_clone
                            .connect_primary_for_dc(
                                dc,
                                addrs,
                                target_writers,
                                rng_clone_local,
                                connect_concurrency,
                                false,
                            )
                            .await
                    });
                }
                while join_bg.join_next().await.is_some() {}
                debug!(
                    current_pool_size = pool.connection_count(),
                    "Background ME saturation warmup finished"
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
        target_writers: usize,
        rng: Arc<SecureRandom>,
        connect_concurrency: usize,
        allow_coverage_override: bool,
    ) -> bool {
        if addrs.is_empty() {
            return false;
        }
        let target_writers = target_writers.max(1);
        addrs.shuffle(&mut rand::rng());
        let endpoints: Vec<SocketAddr> = addrs
            .iter()
            .map(|(ip, port)| SocketAddr::new(*ip, *port))
            .collect();
        let endpoint_set: HashSet<SocketAddr> = endpoints.iter().copied().collect();

        loop {
            let alive = self
                .active_writer_count_for_dc_endpoints(dc, &endpoint_set)
                .await;
            if alive >= target_writers {
                info!(
                    dc = %dc,
                    alive,
                    target_writers,
                    "ME connected"
                );
                return true;
            }

            let missing = target_writers.saturating_sub(alive).max(1);
            let concurrency = connect_concurrency.max(1).min(missing);
            let mut join = tokio::task::JoinSet::new();
            for _ in 0..concurrency {
                let pool = Arc::clone(&self);
                let rng_clone = Arc::clone(&rng);
                let endpoints_clone = endpoints.clone();
                let generation = self.current_generation();
                join.spawn(async move {
                    pool.connect_endpoints_round_robin_with_generation_contour(
                        dc,
                        &endpoints_clone,
                        rng_clone.as_ref(),
                        generation,
                        super::pool::WriterContour::Active,
                        allow_coverage_override,
                    )
                    .await
                });
            }

            let mut progress = false;
            while let Some(res) = join.join_next().await {
                match res {
                    Ok(true) => {
                        progress = true;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        warn!(dc = %dc, error = %e, "ME connect task failed");
                    }
                }
            }

            let alive_after = self
                .active_writer_count_for_dc_endpoints(dc, &endpoint_set)
                .await;
            if alive_after >= target_writers {
                info!(
                    dc = %dc,
                    alive = alive_after,
                    target_writers,
                    "ME connected"
                );
                return true;
            }
            if !progress {
                let active_writers_current = self.active_contour_writer_count_total().await;
                let active_cap_configured = self.adaptive_floor_active_cap_configured_total();
                if !allow_coverage_override && active_writers_current >= active_cap_configured {
                    info!(
                        dc = %dc,
                        alive = alive_after,
                        target_writers,
                        active_writers_current,
                        active_cap_configured,
                        "ME init saturation stopped by active writer cap"
                    );
                } else {
                    warn!(
                        dc = %dc,
                        alive = alive_after,
                        target_writers,
                        "All ME servers for DC failed at init"
                    );
                }
                return false;
            }

            if self.me_warmup_stagger_enabled {
                let jitter =
                    rand::rng().random_range(0..=self.me_warmup_step_jitter.as_millis() as u64);
                let delay_ms = self.me_warmup_step_delay.as_millis() as u64 + jitter;
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
        }
    }
}
