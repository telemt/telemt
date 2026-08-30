use super::*;

impl MePool {
    pub(in crate::transport::middle_proxy) async fn key_selector(&self) -> u32 {
        self.proxy_secret.read().await.key_selector
    }

    pub(in crate::transport::middle_proxy) async fn non_draining_writer_counts_by_contour(
        &self,
    ) -> (usize, usize, usize) {
        let ws = self.writers.read().await;
        let mut active = 0usize;
        let mut warm = 0usize;
        for writer in ws.iter() {
            if writer.draining.load(Ordering::Relaxed) {
                continue;
            }
            match WriterContour::from_u8(writer.contour.load(Ordering::Relaxed)) {
                WriterContour::Active => active = active.saturating_add(1),
                WriterContour::Warm => warm = warm.saturating_add(1),
                WriterContour::Draining => {}
            }
        }
        (active, warm, active.saturating_add(warm))
    }

    pub(in crate::transport::middle_proxy) async fn active_contour_writer_count_total(
        &self,
    ) -> usize {
        let (active, _, _) = self.non_draining_writer_counts_by_contour().await;
        active
    }

    pub(in crate::transport::middle_proxy) async fn secret_snapshot(&self) -> SecretSnapshot {
        self.proxy_secret.read().await.clone()
    }

    pub(in crate::transport::middle_proxy) fn bind_stale_mode(&self) -> MeBindStaleMode {
        MeBindStaleMode::from_u8(
            self.binding_policy
                .me_bind_stale_mode
                .load(Ordering::Relaxed),
        )
    }

    pub(in crate::transport::middle_proxy) fn writer_pick_mode(&self) -> MeWriterPickMode {
        MeWriterPickMode::from_u8(
            self.writer_selection_policy
                .me_writer_pick_mode
                .load(Ordering::Relaxed),
        )
    }

    pub(in crate::transport::middle_proxy) fn writer_pick_sample_size(&self) -> usize {
        self.writer_selection_policy
            .me_writer_pick_sample_size
            .load(Ordering::Relaxed)
            .clamp(2, 4) as usize
    }

    pub(in crate::transport::middle_proxy) fn required_writers_for_dc(
        &self,
        endpoint_count: usize,
    ) -> usize {
        if endpoint_count == 0 {
            return 0;
        }
        if endpoint_count == 1 {
            let shadow = self
                .single_endpoint_runtime
                .me_single_endpoint_shadow_writers
                .load(Ordering::Relaxed) as usize;
            return (1 + shadow).max(3);
        }
        endpoint_count.max(3)
    }

    pub(in crate::transport::middle_proxy) fn floor_mode(&self) -> MeFloorMode {
        MeFloorMode::from_u8(self.floor_runtime.me_floor_mode.load(Ordering::Relaxed))
    }

    pub(in crate::transport::middle_proxy) fn adaptive_floor_min_writers_multi_endpoint(
        &self,
    ) -> usize {
        (self
            .floor_runtime
            .me_adaptive_floor_min_writers_multi_endpoint
            .load(Ordering::Relaxed) as usize)
            .max(1)
    }

    pub(in crate::transport::middle_proxy) fn adaptive_floor_max_extra_single_per_core(
        &self,
    ) -> usize {
        self.floor_runtime
            .me_adaptive_floor_max_extra_writers_single_per_core
            .load(Ordering::Relaxed) as usize
    }

    pub(in crate::transport::middle_proxy) fn adaptive_floor_max_extra_multi_per_core(
        &self,
    ) -> usize {
        self.floor_runtime
            .me_adaptive_floor_max_extra_writers_multi_per_core
            .load(Ordering::Relaxed) as usize
    }

    pub(in crate::transport::middle_proxy) fn adaptive_floor_max_active_writers_per_core(
        &self,
    ) -> usize {
        (self
            .floor_runtime
            .me_adaptive_floor_max_active_writers_per_core
            .load(Ordering::Relaxed) as usize)
            .max(1)
    }

    pub(in crate::transport::middle_proxy) fn adaptive_floor_max_warm_writers_per_core(
        &self,
    ) -> usize {
        (self
            .floor_runtime
            .me_adaptive_floor_max_warm_writers_per_core
            .load(Ordering::Relaxed) as usize)
            .max(1)
    }

    pub(in crate::transport::middle_proxy) fn adaptive_floor_max_active_writers_global(
        &self,
    ) -> usize {
        (self
            .floor_runtime
            .me_adaptive_floor_max_active_writers_global
            .load(Ordering::Relaxed) as usize)
            .max(1)
    }

    pub(in crate::transport::middle_proxy) fn adaptive_floor_max_warm_writers_global(
        &self,
    ) -> usize {
        (self
            .floor_runtime
            .me_adaptive_floor_max_warm_writers_global
            .load(Ordering::Relaxed) as usize)
            .max(1)
    }

    pub(in crate::transport::middle_proxy) fn adaptive_floor_detected_cpu_cores(&self) -> usize {
        std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(1)
            .max(1)
    }

    pub(in crate::transport::middle_proxy) fn adaptive_floor_effective_cpu_cores(&self) -> usize {
        let detected = self.adaptive_floor_detected_cpu_cores();
        let override_cores = self
            .floor_runtime
            .me_adaptive_floor_cpu_cores_override
            .load(Ordering::Relaxed) as usize;
        let effective = if override_cores == 0 {
            detected
        } else {
            override_cores.max(1)
        };
        self.floor_runtime
            .me_adaptive_floor_cpu_cores_detected
            .store(detected as u32, Ordering::Relaxed);
        self.floor_runtime
            .me_adaptive_floor_cpu_cores_effective
            .store(effective as u32, Ordering::Relaxed);
        self.stats
            .set_me_floor_cpu_cores_detected_gauge(detected as u64);
        self.stats
            .set_me_floor_cpu_cores_effective_gauge(effective as u64);
        effective
    }

    // Keeps per-contour (active/warm) writer budget bounded by CPU count.
    // Baseline is 86 writers on the first core and +48 for each extra core.
    pub(in crate::transport::middle_proxy) fn adaptive_floor_cpu_budget_per_contour_cap(
        &self,
        cores: usize,
    ) -> usize {
        const FIRST_CORE_WRITER_BUDGET: usize = 86;
        const EXTRA_CORE_WRITER_BUDGET: usize = 48;
        if cores == 0 {
            return FIRST_CORE_WRITER_BUDGET;
        }
        FIRST_CORE_WRITER_BUDGET.saturating_add(
            cores
                .saturating_sub(1)
                .saturating_mul(EXTRA_CORE_WRITER_BUDGET),
        )
    }

    pub(in crate::transport::middle_proxy) fn adaptive_floor_active_cap_configured_total(
        &self,
    ) -> usize {
        let cores = self.adaptive_floor_effective_cpu_cores();
        let per_contour_budget = self.adaptive_floor_cpu_budget_per_contour_cap(cores);
        let configured = cores
            .saturating_mul(self.adaptive_floor_max_active_writers_per_core())
            .min(self.adaptive_floor_max_active_writers_global())
            .min(per_contour_budget)
            .max(1);
        self.floor_runtime
            .me_adaptive_floor_active_cap_configured
            .store(configured as u64, Ordering::Relaxed);
        self.stats
            .set_me_floor_active_cap_configured_gauge(configured as u64);
        configured
    }

    pub(in crate::transport::middle_proxy) fn adaptive_floor_warm_cap_configured_total(
        &self,
    ) -> usize {
        let cores = self.adaptive_floor_effective_cpu_cores();
        let per_contour_budget = self.adaptive_floor_cpu_budget_per_contour_cap(cores);
        let configured = cores
            .saturating_mul(self.adaptive_floor_max_warm_writers_per_core())
            .min(self.adaptive_floor_max_warm_writers_global())
            .min(per_contour_budget)
            .max(1);
        self.floor_runtime
            .me_adaptive_floor_warm_cap_configured
            .store(configured as u64, Ordering::Relaxed);
        self.stats
            .set_me_floor_warm_cap_configured_gauge(configured as u64);
        configured
    }

    pub(in crate::transport::middle_proxy) fn set_adaptive_floor_runtime_caps(
        &self,
        active_cap_configured: usize,
        active_cap_effective: usize,
        warm_cap_configured: usize,
        warm_cap_effective: usize,
        target_writers_total: usize,
        active_writers_current: usize,
        warm_writers_current: usize,
    ) {
        self.floor_runtime
            .me_adaptive_floor_global_cap_raw
            .store(active_cap_configured as u64, Ordering::Relaxed);
        self.floor_runtime
            .me_adaptive_floor_global_cap_effective
            .store(active_cap_effective as u64, Ordering::Relaxed);
        self.floor_runtime
            .me_adaptive_floor_target_writers_total
            .store(target_writers_total as u64, Ordering::Relaxed);
        self.floor_runtime
            .me_adaptive_floor_active_cap_configured
            .store(active_cap_configured as u64, Ordering::Relaxed);
        self.floor_runtime
            .me_adaptive_floor_active_cap_effective
            .store(active_cap_effective as u64, Ordering::Relaxed);
        self.floor_runtime
            .me_adaptive_floor_warm_cap_configured
            .store(warm_cap_configured as u64, Ordering::Relaxed);
        self.floor_runtime
            .me_adaptive_floor_warm_cap_effective
            .store(warm_cap_effective as u64, Ordering::Relaxed);
        self.floor_runtime
            .me_adaptive_floor_active_writers_current
            .store(active_writers_current as u64, Ordering::Relaxed);
        self.floor_runtime
            .me_adaptive_floor_warm_writers_current
            .store(warm_writers_current as u64, Ordering::Relaxed);
        self.stats
            .set_me_floor_global_cap_raw_gauge(active_cap_configured as u64);
        self.stats
            .set_me_floor_global_cap_effective_gauge(active_cap_effective as u64);
        self.stats
            .set_me_floor_target_writers_total_gauge(target_writers_total as u64);
        self.stats
            .set_me_floor_active_cap_configured_gauge(active_cap_configured as u64);
        self.stats
            .set_me_floor_active_cap_effective_gauge(active_cap_effective as u64);
        self.stats
            .set_me_floor_warm_cap_configured_gauge(warm_cap_configured as u64);
        self.stats
            .set_me_floor_warm_cap_effective_gauge(warm_cap_effective as u64);
        self.stats
            .set_me_writers_active_current_gauge(active_writers_current as u64);
        self.stats
            .set_me_writers_warm_current_gauge(warm_writers_current as u64);
    }
}
