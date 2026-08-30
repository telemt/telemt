use super::*;

impl MePool {
    /// Creates the immutable byte semaphore assigned to one ME writer generation.
    pub(crate) fn new_writer_byte_budget(&self) -> Arc<Semaphore> {
        Arc::new(Semaphore::new(
            self.writer_lifecycle.writer_byte_budget_permits,
        ))
    }

    pub fn current_generation(&self) -> u64 {
        self.reinit.active_generation.load(Ordering::Relaxed)
    }

    pub fn set_runtime_ready(&self, ready: bool) {
        self.runtime_ready.store(ready, Ordering::Relaxed);
    }

    pub fn is_runtime_ready(&self) -> bool {
        self.runtime_ready.load(Ordering::Relaxed)
    }

    pub(in crate::transport::middle_proxy) fn now_epoch_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    pub(in crate::transport::middle_proxy) fn notify_writer_epoch(&self) {
        self.writer_epoch.send_modify(|epoch| {
            *epoch = epoch.wrapping_add(1);
        });
    }

    pub(in crate::transport::middle_proxy) fn set_family_runtime_state(
        &self,
        family: IpFamily,
        state: MeFamilyRuntimeState,
        state_since_epoch_secs: u64,
        suppressed_until_epoch_secs: u64,
        fail_streak: u32,
        recover_success_streak: u32,
    ) {
        let snapshot = Arc::new(FamilyHealthSnapshot::new(
            state,
            state_since_epoch_secs,
            suppressed_until_epoch_secs,
            fail_streak,
            recover_success_streak,
        ));
        match family {
            IpFamily::V4 => self.health_runtime.family_health_v4.store(snapshot),
            IpFamily::V6 => self.health_runtime.family_health_v6.store(snapshot),
        }
    }

    pub(crate) fn family_runtime_state(&self, family: IpFamily) -> MeFamilyRuntimeState {
        match family {
            IpFamily::V4 => self.health_runtime.family_health_v4.load().state,
            IpFamily::V6 => self.health_runtime.family_health_v6.load().state,
        }
    }

    pub(crate) fn family_runtime_state_since_epoch_secs(&self, family: IpFamily) -> u64 {
        match family {
            IpFamily::V4 => {
                self.health_runtime
                    .family_health_v4
                    .load()
                    .state_since_epoch_secs
            }
            IpFamily::V6 => {
                self.health_runtime
                    .family_health_v6
                    .load()
                    .state_since_epoch_secs
            }
        }
    }

    pub(crate) fn family_suppressed_until_epoch_secs(&self, family: IpFamily) -> u64 {
        match family {
            IpFamily::V4 => {
                self.health_runtime
                    .family_health_v4
                    .load()
                    .suppressed_until_epoch_secs
            }
            IpFamily::V6 => {
                self.health_runtime
                    .family_health_v6
                    .load()
                    .suppressed_until_epoch_secs
            }
        }
    }

    pub(crate) fn family_fail_streak(&self, family: IpFamily) -> u32 {
        match family {
            IpFamily::V4 => self.health_runtime.family_health_v4.load().fail_streak,
            IpFamily::V6 => self.health_runtime.family_health_v6.load().fail_streak,
        }
    }

    pub(crate) fn family_recover_success_streak(&self, family: IpFamily) -> u32 {
        match family {
            IpFamily::V4 => {
                self.health_runtime
                    .family_health_v4
                    .load()
                    .recover_success_streak
            }
            IpFamily::V6 => {
                self.health_runtime
                    .family_health_v6
                    .load()
                    .recover_success_streak
            }
        }
    }

    pub(crate) fn is_family_temporarily_suppressed(
        &self,
        family: IpFamily,
        now_epoch_secs: u64,
    ) -> bool {
        self.family_suppressed_until_epoch_secs(family) > now_epoch_secs
    }

    pub(in crate::transport::middle_proxy) fn family_enabled_for_drain_coverage(
        &self,
        family: IpFamily,
        now_epoch_secs: u64,
    ) -> bool {
        let configured = match family {
            IpFamily::V4 => self.decision.ipv4_me,
            IpFamily::V6 => self.decision.ipv6_me,
        };
        configured && !self.is_family_temporarily_suppressed(family, now_epoch_secs)
    }

    pub(in crate::transport::middle_proxy) fn set_last_drain_gate(
        &self,
        route_quorum_ok: bool,
        redundancy_ok: bool,
        block_reason: MeDrainGateReason,
        updated_at_epoch_secs: u64,
    ) {
        self.drain_runtime
            .me_last_drain_gate_route_quorum_ok
            .store(route_quorum_ok, Ordering::Relaxed);
        self.drain_runtime
            .me_last_drain_gate_redundancy_ok
            .store(redundancy_ok, Ordering::Relaxed);
        self.drain_runtime
            .me_last_drain_gate_block_reason
            .store(block_reason as u8, Ordering::Relaxed);
        self.drain_runtime
            .me_last_drain_gate_updated_at_epoch_secs
            .store(updated_at_epoch_secs, Ordering::Relaxed);
    }

    pub(crate) fn last_drain_gate_route_quorum_ok(&self) -> bool {
        self.drain_runtime
            .me_last_drain_gate_route_quorum_ok
            .load(Ordering::Relaxed)
    }

    pub(crate) fn last_drain_gate_redundancy_ok(&self) -> bool {
        self.drain_runtime
            .me_last_drain_gate_redundancy_ok
            .load(Ordering::Relaxed)
    }

    pub(crate) fn last_drain_gate_block_reason(&self) -> MeDrainGateReason {
        MeDrainGateReason::from_u8(
            self.drain_runtime
                .me_last_drain_gate_block_reason
                .load(Ordering::Relaxed),
        )
    }

    pub(crate) fn last_drain_gate_updated_at_epoch_secs(&self) -> u64 {
        self.drain_runtime
            .me_last_drain_gate_updated_at_epoch_secs
            .load(Ordering::Relaxed)
    }

    pub fn update_runtime_reinit_policy(
        &self,
        hardswap: bool,
        drain_ttl_secs: u64,
        instadrain: bool,
        pool_drain_threshold: u64,
        pool_drain_soft_evict_enabled: bool,
        pool_drain_soft_evict_grace_secs: u64,
        pool_drain_soft_evict_per_writer: u8,
        pool_drain_soft_evict_budget_per_core: u16,
        pool_drain_soft_evict_cooldown_ms: u64,
        force_close_secs: u64,
        min_fresh_ratio: f32,
        hardswap_warmup_delay_min_ms: u64,
        hardswap_warmup_delay_max_ms: u64,
        hardswap_warmup_extra_passes: u8,
        hardswap_warmup_pass_backoff_base_ms: u64,
        bind_stale_mode: MeBindStaleMode,
        bind_stale_ttl_secs: u64,
        secret_atomic_snapshot: bool,
        deterministic_writer_sort: bool,
        writer_pick_mode: MeWriterPickMode,
        writer_pick_sample_size: u8,
        single_endpoint_shadow_writers: u8,
        single_endpoint_outage_mode_enabled: bool,
        single_endpoint_outage_disable_quarantine: bool,
        single_endpoint_outage_backoff_min_ms: u64,
        single_endpoint_outage_backoff_max_ms: u64,
        single_endpoint_shadow_rotate_every_secs: u64,
        floor_mode: MeFloorMode,
        adaptive_floor_idle_secs: u64,
        adaptive_floor_min_writers_single_endpoint: u8,
        adaptive_floor_min_writers_multi_endpoint: u8,
        adaptive_floor_recover_grace_secs: u64,
        adaptive_floor_writers_per_core_total: u16,
        adaptive_floor_cpu_cores_override: u16,
        adaptive_floor_max_extra_writers_single_per_core: u16,
        adaptive_floor_max_extra_writers_multi_per_core: u16,
        adaptive_floor_max_active_writers_per_core: u16,
        adaptive_floor_max_warm_writers_per_core: u16,
        adaptive_floor_max_active_writers_global: u32,
        adaptive_floor_max_warm_writers_global: u32,
        me_health_interval_ms_unhealthy: u64,
        me_health_interval_ms_healthy: u64,
        me_warn_rate_limit_ms: u64,
    ) {
        self.reinit.hardswap.store(hardswap, Ordering::Relaxed);
        self.drain_runtime
            .me_pool_drain_ttl_secs
            .store(drain_ttl_secs, Ordering::Relaxed);
        self.drain_runtime
            .me_instadrain
            .store(instadrain, Ordering::Relaxed);
        self.drain_runtime
            .me_pool_drain_threshold
            .store(pool_drain_threshold, Ordering::Relaxed);
        // Runtime soft-evict knobs are updated lock-free to keep control-plane
        // writes non-blocking; readers observe a short eventual-consistency
        // window by design.
        self.drain_runtime
            .me_pool_drain_soft_evict_enabled
            .store(pool_drain_soft_evict_enabled, Ordering::Relaxed);
        self.drain_runtime
            .me_pool_drain_soft_evict_grace_secs
            .store(pool_drain_soft_evict_grace_secs, Ordering::Relaxed);
        self.drain_runtime
            .me_pool_drain_soft_evict_per_writer
            .store(pool_drain_soft_evict_per_writer.max(1), Ordering::Relaxed);
        self.drain_runtime
            .me_pool_drain_soft_evict_budget_per_core
            .store(
                pool_drain_soft_evict_budget_per_core.max(1) as u32,
                Ordering::Relaxed,
            );
        self.drain_runtime
            .me_pool_drain_soft_evict_cooldown_ms
            .store(pool_drain_soft_evict_cooldown_ms.max(1), Ordering::Relaxed);
        self.drain_runtime.me_pool_force_close_secs.store(
            Self::normalize_force_close_secs(force_close_secs),
            Ordering::Relaxed,
        );
        self.drain_runtime
            .me_pool_min_fresh_ratio_permille
            .store(Self::ratio_to_permille(min_fresh_ratio), Ordering::Relaxed);
        self.reinit
            .me_hardswap_warmup_delay_min_ms
            .store(hardswap_warmup_delay_min_ms, Ordering::Relaxed);
        self.reinit
            .me_hardswap_warmup_delay_max_ms
            .store(hardswap_warmup_delay_max_ms, Ordering::Relaxed);
        self.reinit
            .me_hardswap_warmup_extra_passes
            .store(hardswap_warmup_extra_passes as u32, Ordering::Relaxed);
        self.reinit
            .me_hardswap_warmup_pass_backoff_base_ms
            .store(hardswap_warmup_pass_backoff_base_ms, Ordering::Relaxed);
        self.binding_policy
            .me_bind_stale_mode
            .store(bind_stale_mode.as_u8(), Ordering::Relaxed);
        self.binding_policy
            .me_bind_stale_ttl_secs
            .store(bind_stale_ttl_secs, Ordering::Relaxed);
        self.writer_selection_policy
            .secret_atomic_snapshot
            .store(secret_atomic_snapshot, Ordering::Relaxed);
        self.writer_selection_policy
            .me_deterministic_writer_sort
            .store(deterministic_writer_sort, Ordering::Relaxed);
        let previous_writer_pick_mode = self.writer_pick_mode();
        self.writer_selection_policy
            .me_writer_pick_mode
            .store(writer_pick_mode.as_u8(), Ordering::Relaxed);
        self.writer_selection_policy
            .me_writer_pick_sample_size
            .store(writer_pick_sample_size.clamp(2, 4), Ordering::Relaxed);
        if previous_writer_pick_mode != writer_pick_mode {
            self.stats.increment_me_writer_pick_mode_switch_total();
        }
        self.single_endpoint_runtime
            .me_single_endpoint_shadow_writers
            .store(single_endpoint_shadow_writers, Ordering::Relaxed);
        self.single_endpoint_runtime
            .me_single_endpoint_outage_mode_enabled
            .store(single_endpoint_outage_mode_enabled, Ordering::Relaxed);
        self.single_endpoint_runtime
            .me_single_endpoint_outage_disable_quarantine
            .store(single_endpoint_outage_disable_quarantine, Ordering::Relaxed);
        self.single_endpoint_runtime
            .me_single_endpoint_outage_backoff_min_ms
            .store(single_endpoint_outage_backoff_min_ms, Ordering::Relaxed);
        self.single_endpoint_runtime
            .me_single_endpoint_outage_backoff_max_ms
            .store(single_endpoint_outage_backoff_max_ms, Ordering::Relaxed);
        self.single_endpoint_runtime
            .me_single_endpoint_shadow_rotate_every_secs
            .store(single_endpoint_shadow_rotate_every_secs, Ordering::Relaxed);
        let previous_floor_mode = self.floor_mode();
        self.floor_runtime
            .me_floor_mode
            .store(floor_mode.as_u8(), Ordering::Relaxed);
        self.floor_runtime
            .me_adaptive_floor_idle_secs
            .store(adaptive_floor_idle_secs, Ordering::Relaxed);
        self.floor_runtime
            .me_adaptive_floor_min_writers_single_endpoint
            .store(
                adaptive_floor_min_writers_single_endpoint,
                Ordering::Relaxed,
            );
        self.floor_runtime
            .me_adaptive_floor_min_writers_multi_endpoint
            .store(adaptive_floor_min_writers_multi_endpoint, Ordering::Relaxed);
        self.floor_runtime
            .me_adaptive_floor_recover_grace_secs
            .store(adaptive_floor_recover_grace_secs, Ordering::Relaxed);
        self.floor_runtime
            .me_adaptive_floor_writers_per_core_total
            .store(
                adaptive_floor_writers_per_core_total as u32,
                Ordering::Relaxed,
            );
        self.floor_runtime
            .me_adaptive_floor_cpu_cores_override
            .store(adaptive_floor_cpu_cores_override as u32, Ordering::Relaxed);
        self.floor_runtime
            .me_adaptive_floor_max_extra_writers_single_per_core
            .store(
                adaptive_floor_max_extra_writers_single_per_core as u32,
                Ordering::Relaxed,
            );
        self.floor_runtime
            .me_adaptive_floor_max_extra_writers_multi_per_core
            .store(
                adaptive_floor_max_extra_writers_multi_per_core as u32,
                Ordering::Relaxed,
            );
        self.floor_runtime
            .me_adaptive_floor_max_active_writers_per_core
            .store(
                adaptive_floor_max_active_writers_per_core as u32,
                Ordering::Relaxed,
            );
        self.floor_runtime
            .me_adaptive_floor_max_warm_writers_per_core
            .store(
                adaptive_floor_max_warm_writers_per_core as u32,
                Ordering::Relaxed,
            );
        self.floor_runtime
            .me_adaptive_floor_max_active_writers_global
            .store(adaptive_floor_max_active_writers_global, Ordering::Relaxed);
        self.floor_runtime
            .me_adaptive_floor_max_warm_writers_global
            .store(adaptive_floor_max_warm_writers_global, Ordering::Relaxed);
        self.health_runtime
            .me_health_interval_ms_unhealthy
            .store(me_health_interval_ms_unhealthy.max(1), Ordering::Relaxed);
        self.health_runtime
            .me_health_interval_ms_healthy
            .store(me_health_interval_ms_healthy.max(1), Ordering::Relaxed);
        self.health_runtime
            .me_warn_rate_limit_ms
            .store(me_warn_rate_limit_ms.max(1), Ordering::Relaxed);
        if previous_floor_mode != floor_mode {
            self.stats.increment_me_floor_mode_switch_total();
            match (previous_floor_mode, floor_mode) {
                (MeFloorMode::Static, MeFloorMode::Adaptive) => {
                    self.stats
                        .increment_me_floor_mode_switch_static_to_adaptive_total();
                }
                (MeFloorMode::Adaptive, MeFloorMode::Static) => {
                    self.stats
                        .increment_me_floor_mode_switch_adaptive_to_static_total();
                }
                _ => {}
            }
        }
    }
}
