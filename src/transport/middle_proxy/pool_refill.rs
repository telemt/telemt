use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::crypto::SecureRandom;
use crate::network::IpFamily;

use super::pool::{MePool, RefillDcKey, WriterContour};

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
            debug!(
                %addr,
                wait_ms = expiry.saturating_duration_since(now).as_millis(),
                "All ME endpoints are quarantined for the DC group; retrying earliest one"
            );
            return vec![addr];
        }

        Vec::new()
    }

    pub(super) async fn has_refill_inflight_for_endpoints(&self, endpoints: &[SocketAddr]) -> bool {
        if endpoints.is_empty() {
            return false;
        }

        {
            let guard = self.refill_inflight.lock().await;
            if endpoints.iter().any(|addr| guard.contains(addr)) {
                return true;
            }
        }

        let dc_keys = self.resolve_refill_dc_keys_for_endpoints(endpoints).await;
        if dc_keys.is_empty() {
            return false;
        }
        let guard = self.refill_inflight_dc.lock().await;
        dc_keys.iter().any(|key| guard.contains(key))
    }

    async fn resolve_refill_dc_key_for_addr(&self, addr: SocketAddr) -> Option<RefillDcKey> {
        let family = if addr.is_ipv4() {
            IpFamily::V4
        } else {
            IpFamily::V6
        };
        let map = self.proxy_map_for_family(family).await;
        for (dc, endpoints) in map {
            if endpoints
                .into_iter()
                .any(|(ip, port)| SocketAddr::new(ip, port) == addr)
            {
                return Some(RefillDcKey {
                    dc: dc.abs(),
                    family,
                });
            }
        }
        None
    }

    async fn resolve_refill_dc_keys_for_endpoints(
        &self,
        endpoints: &[SocketAddr],
    ) -> HashSet<RefillDcKey> {
        let mut out = HashSet::<RefillDcKey>::new();
        for addr in endpoints {
            if let Some(key) = self.resolve_refill_dc_key_for_addr(*addr).await {
                out.insert(key);
            }
        }
        out
    }

    pub(super) async fn connect_endpoints_round_robin(
        self: &Arc<Self>,
        endpoints: &[SocketAddr],
        rng: &SecureRandom,
    ) -> bool {
        self.connect_endpoints_round_robin_with_generation_contour(
            endpoints,
            rng,
            self.current_generation(),
            WriterContour::Active,
        )
        .await
    }

    pub(super) async fn connect_endpoints_round_robin_with_generation_contour(
        self: &Arc<Self>,
        endpoints: &[SocketAddr],
        rng: &SecureRandom,
        generation: u64,
        contour: WriterContour,
    ) -> bool {
        let candidates = self.connectable_endpoints(endpoints).await;
        if candidates.is_empty() {
            return false;
        }
        let start = (self.rr.fetch_add(1, Ordering::Relaxed) as usize) % candidates.len();
        for offset in 0..candidates.len() {
            let idx = (start + offset) % candidates.len();
            let addr = candidates[idx];
            match self
                .connect_one_with_generation_contour(addr, rng, generation, contour)
                .await
            {
                Ok(()) => return true,
                Err(e) => debug!(%addr, error = %e, "ME connect failed during round-robin warmup"),
            }
        }
        false
    }

    async fn endpoints_for_same_dc(&self, addr: SocketAddr) -> Vec<SocketAddr> {
        let mut target_dc = HashSet::<i32>::new();
        let mut endpoints = HashSet::<SocketAddr>::new();

        if self.decision.ipv4_me {
            let map = self.proxy_map_v4.read().await.clone();
            for (dc, addrs) in &map {
                if addrs
                    .iter()
                    .any(|(ip, port)| SocketAddr::new(*ip, *port) == addr)
                {
                    target_dc.insert(dc.abs());
                }
            }
            for dc in &target_dc {
                for key in [*dc, -*dc] {
                    if let Some(addrs) = map.get(&key) {
                        for (ip, port) in addrs {
                            endpoints.insert(SocketAddr::new(*ip, *port));
                        }
                    }
                }
            }
        }

        if self.decision.ipv6_me {
            let map = self.proxy_map_v6.read().await.clone();
            for (dc, addrs) in &map {
                if addrs
                    .iter()
                    .any(|(ip, port)| SocketAddr::new(*ip, *port) == addr)
                {
                    target_dc.insert(dc.abs());
                }
            }
            for dc in &target_dc {
                for key in [*dc, -*dc] {
                    if let Some(addrs) = map.get(&key) {
                        for (ip, port) in addrs {
                            endpoints.insert(SocketAddr::new(*ip, *port));
                        }
                    }
                }
            }
        }

        let mut sorted: Vec<SocketAddr> = endpoints.into_iter().collect();
        sorted.sort_unstable();
        sorted
    }

    async fn refill_writer_after_loss(self: &Arc<Self>, addr: SocketAddr) -> bool {
        let fast_retries = self.me_reconnect_fast_retry_count.max(1);
        let same_endpoint_quarantined = self.is_endpoint_quarantined(addr).await;

        if !same_endpoint_quarantined {
            for attempt in 0..fast_retries {
                self.stats.increment_me_reconnect_attempt();
                match self.connect_one(addr, self.rng.as_ref()).await {
                    Ok(()) => {
                        self.stats.increment_me_reconnect_success();
                        self.stats.increment_me_writer_restored_same_endpoint_total();
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

        let dc_endpoints = self.endpoints_for_same_dc(addr).await;
        if dc_endpoints.is_empty() {
            self.stats.increment_me_refill_failed_total();
            return false;
        }

        for attempt in 0..fast_retries {
            self.stats.increment_me_reconnect_attempt();
            if self
                .connect_endpoints_round_robin(&dc_endpoints, self.rng.as_ref())
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

    pub(crate) fn trigger_immediate_refill(self: &Arc<Self>, addr: SocketAddr) {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            let dc_endpoints = pool.endpoints_for_same_dc(addr).await;
            let dc_keys = pool.resolve_refill_dc_keys_for_endpoints(&dc_endpoints).await;

            {
                let mut guard = pool.refill_inflight.lock().await;
                if !guard.insert(addr) {
                    pool.stats.increment_me_refill_skipped_inflight_total();
                    return;
                }
            }

            if !dc_keys.is_empty() {
                let mut dc_guard = pool.refill_inflight_dc.lock().await;
                if dc_keys.iter().any(|key| dc_guard.contains(key)) {
                    pool.stats.increment_me_refill_skipped_inflight_total();
                    drop(dc_guard);
                    let mut guard = pool.refill_inflight.lock().await;
                    guard.remove(&addr);
                    return;
                }
                dc_guard.extend(dc_keys.iter().copied());
            }

            pool.stats.increment_me_refill_triggered_total();

            let restored = pool.refill_writer_after_loss(addr).await;
            if !restored {
                warn!(%addr, "ME immediate refill failed");
            }

            let mut guard = pool.refill_inflight.lock().await;
            guard.remove(&addr);
            drop(guard);
            if !dc_keys.is_empty() {
                let mut dc_guard = pool.refill_inflight_dc.lock().await;
                for key in &dc_keys {
                    dc_guard.remove(key);
                }
            }
        });
    }
}
