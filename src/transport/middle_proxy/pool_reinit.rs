use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use rand::Rng;
use rand::seq::SliceRandom;
use tracing::{debug, info, warn};

use crate::crypto::SecureRandom;

use super::pool::MePool;

impl MePool {
    fn coverage_ratio(
        desired_by_dc: &HashMap<i32, HashSet<SocketAddr>>,
        active_writer_addrs: &HashSet<SocketAddr>,
    ) -> (f32, Vec<i32>) {
        if desired_by_dc.is_empty() {
            return (1.0, Vec::new());
        }

        let mut missing_dc = Vec::<i32>::new();
        let mut covered = 0usize;
        for (dc, endpoints) in desired_by_dc {
            if endpoints.is_empty() {
                continue;
            }
            if endpoints
                .iter()
                .any(|addr| active_writer_addrs.contains(addr))
            {
                covered += 1;
            } else {
                missing_dc.push(*dc);
            }
        }

        missing_dc.sort_unstable();
        let total = desired_by_dc.len().max(1);
        let ratio = (covered as f32) / (total as f32);
        (ratio, missing_dc)
    }

    pub async fn reconcile_connections(self: &Arc<Self>, rng: &SecureRandom) {
        let writers = self.writers.read().await;
        let current: HashSet<SocketAddr> = writers
            .iter()
            .filter(|w| !w.draining.load(Ordering::Relaxed))
            .map(|w| w.addr)
            .collect();
        drop(writers);

        for family in self.family_order() {
            let map = self.proxy_map_for_family(family).await;
            for (_dc, addrs) in &map {
                let dc_addrs: Vec<SocketAddr> = addrs
                    .iter()
                    .map(|(ip, port)| SocketAddr::new(*ip, *port))
                    .collect();
                if !dc_addrs.iter().any(|a| current.contains(a)) {
                    let mut shuffled = dc_addrs.clone();
                    shuffled.shuffle(&mut rand::rng());
                    for addr in shuffled {
                        if self.connect_one(addr, rng).await.is_ok() {
                            break;
                        }
                    }
                }
            }
            if !self.decision.effective_multipath && !current.is_empty() {
                break;
            }
        }
    }

    async fn desired_dc_endpoints(&self) -> HashMap<i32, HashSet<SocketAddr>> {
        let mut out: HashMap<i32, HashSet<SocketAddr>> = HashMap::new();

        if self.decision.ipv4_me {
            let map_v4 = self.proxy_map_v4.read().await.clone();
            for (dc, addrs) in map_v4 {
                let entry = out.entry(dc.abs()).or_default();
                for (ip, port) in addrs {
                    entry.insert(SocketAddr::new(ip, port));
                }
            }
        }

        if self.decision.ipv6_me {
            let map_v6 = self.proxy_map_v6.read().await.clone();
            for (dc, addrs) in map_v6 {
                let entry = out.entry(dc.abs()).or_default();
                for (ip, port) in addrs {
                    entry.insert(SocketAddr::new(ip, port));
                }
            }
        }

        out
    }

    pub(super) fn required_writers_for_dc(endpoint_count: usize) -> usize {
        endpoint_count.max(3)
    }

    fn hardswap_warmup_connect_delay_ms(&self) -> u64 {
        let min_ms = self.me_hardswap_warmup_delay_min_ms.load(Ordering::Relaxed);
        let max_ms = self.me_hardswap_warmup_delay_max_ms.load(Ordering::Relaxed);
        let (min_ms, max_ms) = if min_ms <= max_ms {
            (min_ms, max_ms)
        } else {
            (max_ms, min_ms)
        };
        if min_ms == max_ms {
            return min_ms;
        }
        rand::rng().random_range(min_ms..=max_ms)
    }

    fn hardswap_warmup_backoff_ms(&self, pass_idx: usize) -> u64 {
        let base_ms = self
            .me_hardswap_warmup_pass_backoff_base_ms
            .load(Ordering::Relaxed);
        let cap_ms = (self.me_reconnect_backoff_cap.as_millis() as u64).max(base_ms);
        let shift = (pass_idx as u32).min(20);
        let scaled = base_ms.saturating_mul(1u64 << shift);
        let core = scaled.min(cap_ms);
        let jitter = (core / 2).max(1);
        core.saturating_add(rand::rng().random_range(0..=jitter))
    }

    async fn fresh_writer_count_for_endpoints(
        &self,
        generation: u64,
        endpoints: &HashSet<SocketAddr>,
    ) -> usize {
        let ws = self.writers.read().await;
        ws.iter()
            .filter(|w| !w.draining.load(Ordering::Relaxed))
            .filter(|w| w.generation == generation)
            .filter(|w| endpoints.contains(&w.addr))
            .count()
    }

    pub(super) async fn active_writer_count_for_endpoints(
        &self,
        endpoints: &HashSet<SocketAddr>,
    ) -> usize {
        let ws = self.writers.read().await;
        ws.iter()
            .filter(|w| !w.draining.load(Ordering::Relaxed))
            .filter(|w| endpoints.contains(&w.addr))
            .count()
    }

    async fn warmup_generation_for_all_dcs(
        self: &Arc<Self>,
        rng: &SecureRandom,
        generation: u64,
        desired_by_dc: &HashMap<i32, HashSet<SocketAddr>>,
    ) {
        let extra_passes = self
            .me_hardswap_warmup_extra_passes
            .load(Ordering::Relaxed)
            .min(10) as usize;
        let total_passes = 1 + extra_passes;

        for (dc, endpoints) in desired_by_dc {
            if endpoints.is_empty() {
                continue;
            }

            let mut endpoint_list: Vec<SocketAddr> = endpoints.iter().copied().collect();
            endpoint_list.sort_unstable();
            let required = Self::required_writers_for_dc(endpoint_list.len());
            let mut completed = false;
            let mut last_fresh_count = self
                .fresh_writer_count_for_endpoints(generation, endpoints)
                .await;

            for pass_idx in 0..total_passes {
                if last_fresh_count >= required {
                    completed = true;
                    break;
                }

                let missing = required.saturating_sub(last_fresh_count);
                debug!(
                    dc = *dc,
                    pass = pass_idx + 1,
                    total_passes,
                    fresh_count = last_fresh_count,
                    required,
                    missing,
                    endpoint_count = endpoint_list.len(),
                    "ME hardswap warmup pass started"
                );

                for attempt_idx in 0..missing {
                    let delay_ms = self.hardswap_warmup_connect_delay_ms();
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;

                    let connected = self.connect_endpoints_round_robin(&endpoint_list, rng).await;
                    debug!(
                        dc = *dc,
                        pass = pass_idx + 1,
                        total_passes,
                        attempt = attempt_idx + 1,
                        delay_ms,
                        connected,
                        "ME hardswap warmup connect attempt finished"
                    );
                }

                last_fresh_count = self
                    .fresh_writer_count_for_endpoints(generation, endpoints)
                    .await;
                if last_fresh_count >= required {
                    completed = true;
                    info!(
                        dc = *dc,
                        pass = pass_idx + 1,
                        total_passes,
                        fresh_count = last_fresh_count,
                        required,
                        "ME hardswap warmup floor reached for DC"
                    );
                    break;
                }

                if pass_idx + 1 < total_passes {
                    let backoff_ms = self.hardswap_warmup_backoff_ms(pass_idx);
                    debug!(
                        dc = *dc,
                        pass = pass_idx + 1,
                        total_passes,
                        fresh_count = last_fresh_count,
                        required,
                        backoff_ms,
                        "ME hardswap warmup pass incomplete, delaying next pass"
                    );
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                }
            }

            if !completed {
                warn!(
                    dc = *dc,
                    fresh_count = last_fresh_count,
                    required,
                    endpoint_count = endpoint_list.len(),
                    total_passes,
                    "ME warmup stopped: unable to reach required writer floor for DC"
                );
            }
        }
    }

    pub async fn zero_downtime_reinit_after_map_change(self: &Arc<Self>, rng: &SecureRandom) {
        let desired_by_dc = self.desired_dc_endpoints().await;
        if desired_by_dc.is_empty() {
            warn!("ME endpoint map is empty; skipping stale writer drain");
            return;
        }

        let previous_generation = self.current_generation();
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        let hardswap = self.hardswap.load(Ordering::Relaxed);

        if hardswap {
            self.warmup_generation_for_all_dcs(rng, generation, &desired_by_dc)
                .await;
        } else {
            self.reconcile_connections(rng).await;
        }

        let writers = self.writers.read().await;
        let active_writer_addrs: HashSet<SocketAddr> = writers
            .iter()
            .filter(|w| !w.draining.load(Ordering::Relaxed))
            .map(|w| w.addr)
            .collect();
        let min_ratio = Self::permille_to_ratio(
            self.me_pool_min_fresh_ratio_permille
                .load(Ordering::Relaxed),
        );
        let (coverage_ratio, missing_dc) = Self::coverage_ratio(&desired_by_dc, &active_writer_addrs);
        if !hardswap && coverage_ratio < min_ratio {
            warn!(
                previous_generation,
                generation,
                coverage_ratio = format_args!("{coverage_ratio:.3}"),
                min_ratio = format_args!("{min_ratio:.3}"),
                missing_dc = ?missing_dc,
                "ME reinit coverage below threshold; keeping stale writers"
            );
            return;
        }

        if hardswap {
            let mut fresh_missing_dc = Vec::<(i32, usize, usize)>::new();
            for (dc, endpoints) in &desired_by_dc {
                if endpoints.is_empty() {
                    continue;
                }
                let required = Self::required_writers_for_dc(endpoints.len());
                let fresh_count = writers
                    .iter()
                    .filter(|w| !w.draining.load(Ordering::Relaxed))
                    .filter(|w| w.generation == generation)
                    .filter(|w| endpoints.contains(&w.addr))
                    .count();
                if fresh_count < required {
                    fresh_missing_dc.push((*dc, fresh_count, required));
                }
            }
            if !fresh_missing_dc.is_empty() {
                warn!(
                    previous_generation,
                    generation,
                    missing_dc = ?fresh_missing_dc,
                    "ME hardswap pending: fresh generation coverage incomplete"
                );
                return;
            }
        } else if !missing_dc.is_empty() {
            warn!(
                missing_dc = ?missing_dc,
                // Keep stale writers alive when fresh coverage is incomplete.
                "ME reinit coverage incomplete; keeping stale writers"
            );
            return;
        }

        let desired_addrs: HashSet<SocketAddr> = desired_by_dc
            .values()
            .flat_map(|set| set.iter().copied())
            .collect();

        let stale_writer_ids: Vec<u64> = writers
            .iter()
            .filter(|w| !w.draining.load(Ordering::Relaxed))
            .filter(|w| {
                if hardswap {
                    w.generation < generation
                } else {
                    !desired_addrs.contains(&w.addr)
                }
            })
            .map(|w| w.id)
            .collect();
        drop(writers);

        if stale_writer_ids.is_empty() {
            debug!("ME reinit cycle completed with no stale writers");
            return;
        }

        let drain_timeout = self.force_close_timeout();
        let drain_timeout_secs = drain_timeout.map(|d| d.as_secs()).unwrap_or(0);
        info!(
            stale_writers = stale_writer_ids.len(),
            previous_generation,
            generation,
            hardswap,
            coverage_ratio = format_args!("{coverage_ratio:.3}"),
            min_ratio = format_args!("{min_ratio:.3}"),
            drain_timeout_secs,
            "ME reinit cycle covered; draining stale writers"
        );
        self.stats.increment_pool_swap_total();
        for writer_id in stale_writer_ids {
            self.mark_writer_draining_with_timeout(writer_id, drain_timeout, !hardswap)
                .await;
        }
    }

    pub async fn zero_downtime_reinit_periodic(self: &Arc<Self>, rng: &SecureRandom) {
        self.zero_downtime_reinit_after_map_change(rng).await;
    }
}
