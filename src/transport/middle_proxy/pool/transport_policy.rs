use super::*;

impl MePool {
    pub fn reset_stun_state(&self) {
        self.nat_runtime
            .nat_probe_attempts
            .store(0, Ordering::Relaxed);
        self.nat_runtime
            .nat_probe_disabled
            .store(false, Ordering::Relaxed);
        if let Ok(mut live) = self.nat_runtime.nat_stun_live_servers.try_write() {
            live.clear();
        }
    }

    /// Translate the local ME address into the address material sent to the proxy.
    pub fn translate_our_addr(&self, addr: SocketAddr) -> SocketAddr {
        self.translate_our_addr_with_reflection(addr, None)
    }

    #[allow(dead_code)]
    pub fn registry(&self) -> &Arc<ConnRegistry> {
        &self.registry
    }

    pub fn update_runtime_transport_policy(
        &self,
        socks_kdf_policy: MeSocksKdfPolicy,
        route_backpressure_enabled: bool,
        route_fairshare_enabled: bool,
        route_backpressure_base_timeout_ms: u64,
        route_backpressure_high_timeout_ms: u64,
        route_backpressure_high_watermark_pct: u8,
        reader_route_data_wait_ms: u64,
    ) {
        self.transport_policy
            .me_socks_kdf_policy
            .store(socks_kdf_policy.as_u8(), Ordering::Relaxed);
        self.transport_policy
            .me_route_backpressure_enabled
            .store(route_backpressure_enabled, Ordering::Relaxed);
        self.transport_policy
            .me_route_fairshare_enabled
            .store(route_fairshare_enabled, Ordering::Relaxed);
        self.transport_policy
            .me_reader_route_data_wait_ms
            .store(reader_route_data_wait_ms, Ordering::Relaxed);
        self.registry.update_route_backpressure_policy(
            route_backpressure_base_timeout_ms,
            route_backpressure_high_timeout_ms,
            route_backpressure_high_watermark_pct,
        );
    }

    pub(in crate::transport::middle_proxy) fn socks_kdf_policy(&self) -> MeSocksKdfPolicy {
        MeSocksKdfPolicy::from_u8(
            self.transport_policy
                .me_socks_kdf_policy
                .load(Ordering::Relaxed),
        )
    }

    pub(in crate::transport::middle_proxy) fn writers_arc(&self) -> Arc<WritersState> {
        self.writers.clone()
    }

    pub(in crate::transport::middle_proxy) fn force_close_timeout(&self) -> Option<Duration> {
        let secs = Self::normalize_force_close_secs(
            self.drain_runtime
                .me_pool_force_close_secs
                .load(Ordering::Relaxed),
        );
        Some(Duration::from_secs(secs))
    }

    #[allow(dead_code)]
    pub(in crate::transport::middle_proxy) fn drain_soft_evict_enabled(&self) -> bool {
        self.drain_runtime
            .me_pool_drain_soft_evict_enabled
            .load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub(in crate::transport::middle_proxy) fn drain_soft_evict_grace_secs(&self) -> u64 {
        self.drain_runtime
            .me_pool_drain_soft_evict_grace_secs
            .load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub(in crate::transport::middle_proxy) fn drain_soft_evict_per_writer(&self) -> usize {
        self.drain_runtime
            .me_pool_drain_soft_evict_per_writer
            .load(Ordering::Relaxed)
            .max(1) as usize
    }

    #[allow(dead_code)]
    pub(in crate::transport::middle_proxy) fn drain_soft_evict_budget_per_core(&self) -> usize {
        self.drain_runtime
            .me_pool_drain_soft_evict_budget_per_core
            .load(Ordering::Relaxed)
            .max(1) as usize
    }

    #[allow(dead_code)]
    pub(in crate::transport::middle_proxy) fn drain_soft_evict_cooldown(&self) -> Duration {
        Duration::from_millis(
            self.drain_runtime
                .me_pool_drain_soft_evict_cooldown_ms
                .load(Ordering::Relaxed)
                .max(1),
        )
    }

    #[allow(dead_code)]
    pub(in crate::transport::middle_proxy) fn draining_active_runtime(&self) -> u64 {
        self.draining_active_runtime.load(Ordering::Relaxed)
    }

    pub(in crate::transport::middle_proxy) fn increment_draining_active_runtime(&self) {
        self.draining_active_runtime.fetch_add(1, Ordering::Relaxed);
    }

    pub(in crate::transport::middle_proxy) fn decrement_draining_active_runtime(&self) {
        let mut current = self.draining_active_runtime.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                break;
            }
            match self.draining_active_runtime.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }
}
