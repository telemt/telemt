use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::crypto::SecureRandom;
use crate::network::IpFamily;

use super::pool::{MePool, RefillDcKey, RefillEndpointKey, WriterContour};

const ME_FLAP_UPTIME_THRESHOLD_SECS: u64 = 20;
const ME_FLAP_QUARANTINE_SECS: u64 = 25;

impl MePool {
    pub(super) async fn maybe_quarantine_flapping_endpoint(
        &self,
        addr: SocketAddr,
        uptime: Duration,
    ) {
        if uptime > Duration::from_secs(ME_FLAP_UPTIME_THRESHOLD_SECS) {
            return;
        }

        let until = Instant::now() + Duration::from_secs(ME_FLAP_QUARANTINE_SECS);
        let mut guard = self.endpoint_quarantine.lock().await;
        guard.retain(|_, expiry| *expiry > Instant::now());
        guard.insert(addr, until);
        self.stats.increment_me_endpoint_quarantine_total();
        warn!(
            %addr,
            uptime_ms = uptime.as_millis(),
            quarantine_secs = ME_FLAP_QUARANTINE_SECS,
            "ME endpoint temporarily quarantined due to rapid writer flap"
        );
    }

    pub(super) async fn is_endpoint_quarantined(&self, addr: SocketAddr) -> bool {
        let mut guard = self.endpoint_quarantine.lock().await;
        let now = Instant::now();
        guard.retain(|_, expiry| *expiry > now);
        guard.contains_key(&addr)
    }

    async fn connectable_endpoints(&self, endpoints: &[SocketAddr]) -> Vec<SocketAddr> {
        if endpoints.is_empty() {
            return Vec::new();
        }

        let mut guard = self.endpoint_quarantine.lock().await;
        let now = Instant::now();
        guard.retain(|_, expiry| *expiry > now);

        let mut ready = Vec::<SocketAddr>::with_capacity(endpoints.len());
        let mut earliest_quarantine: Option<(SocketAddr, Instant)> = None;
        for addr in endpoints {
            if let Some(expiry) = guard.get(addr).copied() {
                match earliest_quarantine {
                    Some((_, current_expiry)) if current_expiry <= expiry => {}
                    _ => earliest_quarantine = Some((*addr, expiry)),
                }
            } else {
                ready.push(*addr);
            }
        }

        if !ready.is_empty() {
            return ready;
        }

        if let Some((addr, expiry)) = earliest_quarantine {
            let remaining = expiry.saturating_duration_since(now);
            if remaining.is_zero() {
                return vec![addr];
            }
            drop(guard);
            debug!(
                %addr,
                wait_ms = expiry.saturating_duration_since(now).as_millis(),
                "All ME endpoints are quarantined for the DC group; waiting for quarantine expiry"
            );
            tokio::time::sleep(remaining).await;
            return vec![addr];
        }

        Vec::new()
    }

    #[cfg(test)]
    pub(super) async fn connectable_endpoints_for_test(
        &self,
        endpoints: &[SocketAddr],
    ) -> Vec<SocketAddr> {
        self.connectable_endpoints(endpoints).await
    }

    pub(super) async fn has_refill_inflight_for_dc_key(&self, key: RefillDcKey) -> bool {
        let guard = self.refill_inflight_dc.lock().await;
        guard.contains(&key)
    }

    pub(super) async fn connect_endpoints_round_robin(
        self: &Arc<Self>,
        dc: i32,
        endpoints: &[SocketAddr],
        rng: &SecureRandom,
    ) -> bool {
        self.connect_endpoints_round_robin_with_generation_contour(
            dc,
            endpoints,
            rng,
            self.current_generation(),
            WriterContour::Active,
            false,
        )
        .await
    }

    pub(super) async fn connect_endpoints_round_robin_with_generation_contour(
        self: &Arc<Self>,
        dc: i32,
        endpoints: &[SocketAddr],
        rng: &SecureRandom,
        generation: u64,
        contour: WriterContour,
        allow_coverage_override: bool,
    ) -> bool {
        let mut candidates = self.connectable_endpoints(endpoints).await;
        if candidates.is_empty() {
            return false;
        }
        if candidates.len() > 1 {
            let mut active_by_endpoint = HashMap::<SocketAddr, usize>::new();
            let ws = self.writers.read().await;
            for writer in ws.iter() {
                if writer.draining.load(Ordering::Relaxed) {
                    continue;
                }
                if writer.writer_dc != dc {
                    continue;
                }
                if !matches!(
                    super::pool::WriterContour::from_u8(writer.contour.load(Ordering::Relaxed),),
                    super::pool::WriterContour::Active
                ) {
                    continue;
                }
                if candidates.contains(&writer.addr) {
                    *active_by_endpoint.entry(writer.addr).or_insert(0) += 1;
                }
            }
            drop(ws);
            candidates
                .sort_by_key(|addr| (active_by_endpoint.get(addr).copied().unwrap_or(0), *addr));
        }
        let start = (self.rr.fetch_add(1, Ordering::Relaxed) as usize) % candidates.len();
        for offset in 0..candidates.len() {
            let idx = (start + offset) % candidates.len();
            let addr = candidates[idx];
            match self
                .connect_one_with_generation_contour_for_dc_with_cap_policy(
                    addr,
                    rng,
                    generation,
                    contour,
                    dc,
                    allow_coverage_override,
                )
                .await
            {
                Ok(()) => return true,
                Err(e) => debug!(%addr, error = %e, "ME connect failed during round-robin warmup"),
            }
        }
        false
    }

    async fn endpoints_for_dc(&self, target_dc: i32) -> Vec<SocketAddr> {
        let now_epoch_secs = Self::now_epoch_secs();
        let mut endpoints = HashSet::<SocketAddr>::new();

        if self.family_enabled_for_drain_coverage(IpFamily::V4, now_epoch_secs) {
            let map = self.proxy_map_v4.read().await;
            if let Some(addrs) = map.get(&target_dc) {
                for (ip, port) in addrs {
                    endpoints.insert(SocketAddr::new(*ip, *port));
                }
            }
        }

        if self.family_enabled_for_drain_coverage(IpFamily::V6, now_epoch_secs) {
            let map = self.proxy_map_v6.read().await;
            if let Some(addrs) = map.get(&target_dc) {
                for (ip, port) in addrs {
                    endpoints.insert(SocketAddr::new(*ip, *port));
                }
            }
        }

        let mut sorted: Vec<SocketAddr> = endpoints.into_iter().collect();
        sorted.sort_unstable();
        sorted
    }

    async fn refill_writer_after_loss(self: &Arc<Self>, addr: SocketAddr, writer_dc: i32) -> bool {
        let fast_retries = self.me_reconnect_fast_retry_count.max(1);
        let same_endpoint_quarantined = self.is_endpoint_quarantined(addr).await;

        if !same_endpoint_quarantined {
            for attempt in 0..fast_retries {
                self.stats.increment_me_reconnect_attempt();
                match self
                    .connect_one_for_dc(addr, writer_dc, self.rng.as_ref())
                    .await
                {
                    Ok(()) => {
                        self.stats.increment_me_reconnect_success();
                        self.stats
                            .increment_me_writer_restored_same_endpoint_total();
                        info!(
                            %addr,
                            attempt = attempt + 1,
                            "ME writer restored on the same endpoint"
                        );
                        return true;
                    }
                    Err(e) => {
                        debug!(
                            %addr,
                            attempt = attempt + 1,
                            error = %e,
                            "ME immediate same-endpoint reconnect failed"
                        );
                    }
                }
            }
        } else {
            debug!(
                %addr,
                "Skipping immediate same-endpoint reconnect because endpoint is quarantined"
            );
        }

        let dc_endpoints = self.endpoints_for_dc(writer_dc).await;
        if dc_endpoints.is_empty() {
            self.stats.increment_me_refill_failed_total();
            return false;
        }

        for attempt in 0..fast_retries {
            self.stats.increment_me_reconnect_attempt();
            if self
                .connect_endpoints_round_robin(writer_dc, &dc_endpoints, self.rng.as_ref())
                .await
            {
                self.stats.increment_me_reconnect_success();
                self.stats.increment_me_writer_restored_fallback_total();
                info!(
                    %addr,
                    attempt = attempt + 1,
                    "ME writer restored via DC fallback endpoint"
                );
                return true;
            }
        }

        self.stats.increment_me_refill_failed_total();
        false
    }

    pub(crate) fn trigger_immediate_refill_for_dc(
        self: &Arc<Self>,
        addr: SocketAddr,
        writer_dc: i32,
    ) {
        let endpoint_key = RefillEndpointKey {
            dc: writer_dc,
            addr,
        };
        let pre_inserted = if let Ok(mut guard) = self.refill_inflight.try_lock() {
            if !guard.insert(endpoint_key) {
                self.stats.increment_me_refill_skipped_inflight_total();
                return;
            }
            true
        } else {
            false
        };

        let pool = Arc::clone(self);
        tokio::spawn(async move {
            let dc_key = RefillDcKey {
                dc: writer_dc,
                family: if addr.is_ipv4() {
                    IpFamily::V4
                } else {
                    IpFamily::V6
                },
            };

            if !pre_inserted {
                let mut guard = pool.refill_inflight.lock().await;
                if !guard.insert(endpoint_key) {
                    pool.stats.increment_me_refill_skipped_inflight_total();
                    return;
                }
            }

            {
                let mut dc_guard = pool.refill_inflight_dc.lock().await;
                if dc_guard.contains(&dc_key) {
                    pool.stats.increment_me_refill_skipped_inflight_total();
                    drop(dc_guard);
                    let mut guard = pool.refill_inflight.lock().await;
                    guard.remove(&endpoint_key);
                    return;
                }
                dc_guard.insert(dc_key);
            }

            pool.stats.increment_me_refill_triggered_total();
            let restored = pool.refill_writer_after_loss(addr, writer_dc).await;
            if !restored {
                warn!(%addr, dc = writer_dc, "ME immediate refill failed");
            }

            let mut guard = pool.refill_inflight.lock().await;
            guard.remove(&endpoint_key);
            drop(guard);
            let mut dc_guard = pool.refill_inflight_dc.lock().await;
            dc_guard.remove(&dc_key);
        });
    }
}
