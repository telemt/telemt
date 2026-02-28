use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tracing::{debug, info, warn};

use crate::crypto::SecureRandom;

use super::pool::MePool;

impl MePool {
    pub(super) async fn connect_endpoints_round_robin(
        self: &Arc<Self>,
        endpoints: &[SocketAddr],
        rng: &SecureRandom,
    ) -> bool {
        if endpoints.is_empty() {
            return false;
        }
        let start = (self.rr.fetch_add(1, Ordering::Relaxed) as usize) % endpoints.len();
        for offset in 0..endpoints.len() {
            let idx = (start + offset) % endpoints.len();
            let addr = endpoints[idx];
            match self.connect_one(addr, rng).await {
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
            {
                let mut guard = pool.refill_inflight.lock().await;
                if !guard.insert(addr) {
                    pool.stats.increment_me_refill_skipped_inflight_total();
                    return;
                }
            }
            pool.stats.increment_me_refill_triggered_total();

            let restored = pool.refill_writer_after_loss(addr).await;
            if !restored {
                warn!(%addr, "ME immediate refill failed");
            }

            let mut guard = pool.refill_inflight.lock().await;
            guard.remove(&addr);
        });
    }
}
