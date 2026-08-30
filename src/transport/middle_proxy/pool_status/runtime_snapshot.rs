use super::*;

impl MePool {
    #[allow(dead_code)]
    pub(crate) async fn api_runtime_snapshot(&self) -> MeApiRuntimeSnapshot {
        let reinit = self.reinit.status.load_full();
        self.api_runtime_snapshot_for_reinit(reinit.as_ref()).await
    }

    async fn api_runtime_snapshot_for_reinit(
        &self,
        reinit: &ReinitStatusSnapshot,
    ) -> MeApiRuntimeSnapshot {
        let now = Instant::now();
        let now_epoch_secs = Self::now_epoch_secs();
        let pending_started_at = reinit.pending_hardswap_started_at_epoch_secs;
        let pending_hardswap_age_secs =
            (pending_started_at > 0).then_some(now_epoch_secs.saturating_sub(pending_started_at));

        let mut quarantined_endpoints = Vec::<MeApiQuarantinedEndpointSnapshot>::new();
        {
            let guard = self.endpoint_quarantine.lock().await;
            for (endpoint, expires_at) in guard.iter() {
                if *expires_at <= now {
                    continue;
                }
                let remaining_ms = expires_at.duration_since(now).as_millis() as u64;
                quarantined_endpoints.push(MeApiQuarantinedEndpointSnapshot {
                    endpoint: *endpoint,
                    remaining_ms,
                });
            }
        }
        quarantined_endpoints.sort_by_key(|entry| entry.endpoint);

        let mut network_path = Vec::<MeApiDcPathSnapshot>::new();
        if let Some(upstream) = &self.upstream {
            for dc in 1..=5 {
                let dc_idx = dc as i16;
                let ip_preference = upstream
                    .get_dc_ip_preference(dc_idx)
                    .await
                    .map(ip_preference_label);
                let selected_addr_v4 = upstream.get_dc_addr(dc_idx, false).await;
                let selected_addr_v6 = upstream.get_dc_addr(dc_idx, true).await;
                network_path.push(MeApiDcPathSnapshot {
                    dc: dc_idx,
                    ip_preference,
                    selected_addr_v4,
                    selected_addr_v6,
                });
            }
        }

        MeApiRuntimeSnapshot {
            active_generation: reinit.active_generation,
            warm_generation: reinit.warm_generations.last().copied().unwrap_or(0),
            warm_generations: reinit.warm_generations.clone(),
            pending_hardswap_generation: reinit.pending_hardswap_generation,
            pending_hardswap_age_secs,
            reinit_inflight: reinit.inflight,
            reinit_max_concurrency_effective: self
                .reinit
                .max_concurrency_effective
                .load(Ordering::Acquire),
            hardswap_enabled: self.reinit.hardswap.load(Ordering::Relaxed),
            floor_mode: floor_mode_label(self.floor_mode()),
            adaptive_floor_idle_secs: self
                .floor_runtime
                .me_adaptive_floor_idle_secs
                .load(Ordering::Relaxed),
            adaptive_floor_min_writers_single_endpoint: self
                .floor_runtime
                .me_adaptive_floor_min_writers_single_endpoint
                .load(Ordering::Relaxed),
            adaptive_floor_min_writers_multi_endpoint: self
                .floor_runtime
                .me_adaptive_floor_min_writers_multi_endpoint
                .load(Ordering::Relaxed),
            adaptive_floor_recover_grace_secs: self
                .floor_runtime
                .me_adaptive_floor_recover_grace_secs
                .load(Ordering::Relaxed),
            adaptive_floor_writers_per_core_total: self
                .floor_runtime
                .me_adaptive_floor_writers_per_core_total
                .load(Ordering::Relaxed) as u16,
            adaptive_floor_cpu_cores_override: self
                .floor_runtime
                .me_adaptive_floor_cpu_cores_override
                .load(Ordering::Relaxed) as u16,
            adaptive_floor_max_extra_writers_single_per_core: self
                .floor_runtime
                .me_adaptive_floor_max_extra_writers_single_per_core
                .load(Ordering::Relaxed)
                as u16,
            adaptive_floor_max_extra_writers_multi_per_core: self
                .floor_runtime
                .me_adaptive_floor_max_extra_writers_multi_per_core
                .load(Ordering::Relaxed)
                as u16,
            adaptive_floor_max_active_writers_per_core: self
                .floor_runtime
                .me_adaptive_floor_max_active_writers_per_core
                .load(Ordering::Relaxed)
                as u16,
            adaptive_floor_max_warm_writers_per_core: self
                .floor_runtime
                .me_adaptive_floor_max_warm_writers_per_core
                .load(Ordering::Relaxed)
                as u16,
            adaptive_floor_max_active_writers_global: self
                .floor_runtime
                .me_adaptive_floor_max_active_writers_global
                .load(Ordering::Relaxed),
            adaptive_floor_max_warm_writers_global: self
                .floor_runtime
                .me_adaptive_floor_max_warm_writers_global
                .load(Ordering::Relaxed),
            adaptive_floor_cpu_cores_detected: self
                .floor_runtime
                .me_adaptive_floor_cpu_cores_detected
                .load(Ordering::Relaxed),
            adaptive_floor_cpu_cores_effective: self
                .floor_runtime
                .me_adaptive_floor_cpu_cores_effective
                .load(Ordering::Relaxed),
            adaptive_floor_global_cap_raw: self
                .floor_runtime
                .me_adaptive_floor_global_cap_raw
                .load(Ordering::Relaxed),
            adaptive_floor_global_cap_effective: self
                .floor_runtime
                .me_adaptive_floor_global_cap_effective
                .load(Ordering::Relaxed),
            adaptive_floor_target_writers_total: self
                .floor_runtime
                .me_adaptive_floor_target_writers_total
                .load(Ordering::Relaxed),
            adaptive_floor_active_cap_configured: self
                .floor_runtime
                .me_adaptive_floor_active_cap_configured
                .load(Ordering::Relaxed),
            adaptive_floor_active_cap_effective: self
                .floor_runtime
                .me_adaptive_floor_active_cap_effective
                .load(Ordering::Relaxed),
            adaptive_floor_warm_cap_configured: self
                .floor_runtime
                .me_adaptive_floor_warm_cap_configured
                .load(Ordering::Relaxed),
            adaptive_floor_warm_cap_effective: self
                .floor_runtime
                .me_adaptive_floor_warm_cap_effective
                .load(Ordering::Relaxed),
            adaptive_floor_active_writers_current: self
                .floor_runtime
                .me_adaptive_floor_active_writers_current
                .load(Ordering::Relaxed),
            adaptive_floor_warm_writers_current: self
                .floor_runtime
                .me_adaptive_floor_warm_writers_current
                .load(Ordering::Relaxed),
            me_keepalive_enabled: self.writer_lifecycle.me_keepalive_enabled,
            me_keepalive_interval_secs: self.writer_lifecycle.me_keepalive_interval.as_secs(),
            me_keepalive_jitter_secs: self.writer_lifecycle.me_keepalive_jitter.as_secs(),
            me_keepalive_payload_random: self.writer_lifecycle.me_keepalive_payload_random,
            rpc_proxy_req_every_secs: self
                .writer_lifecycle
                .rpc_proxy_req_every_secs
                .load(Ordering::Relaxed),
            me_reconnect_max_concurrent_per_dc: self
                .reconnect_runtime
                .me_reconnect_max_concurrent_per_dc,
            me_reconnect_backoff_base_ms: self
                .reconnect_runtime
                .me_reconnect_backoff_base
                .as_millis() as u64,
            me_reconnect_backoff_cap_ms: self.reconnect_runtime.me_reconnect_backoff_cap.as_millis()
                as u64,
            me_reconnect_fast_retry_count: self.reconnect_runtime.me_reconnect_fast_retry_count,
            me_pool_drain_ttl_secs: self
                .drain_runtime
                .me_pool_drain_ttl_secs
                .load(Ordering::Relaxed),
            me_pool_force_close_secs: self
                .drain_runtime
                .me_pool_force_close_secs
                .load(Ordering::Relaxed),
            me_pool_min_fresh_ratio: Self::permille_to_ratio(
                self.drain_runtime
                    .me_pool_min_fresh_ratio_permille
                    .load(Ordering::Relaxed),
            ),
            me_bind_stale_mode: bind_stale_mode_label(self.bind_stale_mode()),
            me_bind_stale_ttl_secs: self
                .binding_policy
                .me_bind_stale_ttl_secs
                .load(Ordering::Relaxed),
            me_single_endpoint_shadow_writers: self
                .single_endpoint_runtime
                .me_single_endpoint_shadow_writers
                .load(Ordering::Relaxed),
            me_single_endpoint_outage_mode_enabled: self
                .single_endpoint_runtime
                .me_single_endpoint_outage_mode_enabled
                .load(Ordering::Relaxed),
            me_single_endpoint_outage_disable_quarantine: self
                .single_endpoint_runtime
                .me_single_endpoint_outage_disable_quarantine
                .load(Ordering::Relaxed),
            me_single_endpoint_outage_backoff_min_ms: self
                .single_endpoint_runtime
                .me_single_endpoint_outage_backoff_min_ms
                .load(Ordering::Relaxed),
            me_single_endpoint_outage_backoff_max_ms: self
                .single_endpoint_runtime
                .me_single_endpoint_outage_backoff_max_ms
                .load(Ordering::Relaxed),
            me_single_endpoint_shadow_rotate_every_secs: self
                .single_endpoint_runtime
                .me_single_endpoint_shadow_rotate_every_secs
                .load(Ordering::Relaxed),
            me_deterministic_writer_sort: self
                .writer_selection_policy
                .me_deterministic_writer_sort
                .load(Ordering::Relaxed),
            me_writer_pick_mode: writer_pick_mode_label(self.writer_pick_mode()),
            me_writer_pick_sample_size: self.writer_pick_sample_size() as u8,
            me_socks_kdf_policy: socks_kdf_policy_label(self.socks_kdf_policy()),
            quarantined_endpoints,
            network_path,
        }
    }

    pub(crate) async fn api_coherent_snapshots(
        &self,
    ) -> (MeApiStatusSnapshot, MeApiRuntimeSnapshot) {
        let mut attempts = 0usize;
        loop {
            let reinit = self.reinit.status.load_full();
            let status = self.api_status_snapshot_for_reinit(reinit.as_ref()).await;
            let runtime = self.api_runtime_snapshot_for_reinit(reinit.as_ref()).await;
            attempts += 1;
            if Arc::ptr_eq(&reinit, &self.reinit.status.load_full()) || attempts >= 3 {
                return (status, runtime);
            }
        }
    }
}
