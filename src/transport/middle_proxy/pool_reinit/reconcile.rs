use super::*;

impl MePool {
    async fn warmup_generation_for_all_dcs(
        self: &Arc<Self>,
        rng: &SecureRandom,
        generation: u64,
        desired_by_dc: &HashMap<i32, HashSet<SocketAddr>>,
    ) {
        let extra_passes = self
            .reinit
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
            let required = self.required_writers_for_dc(endpoint_list.len());
            let mut completed = false;
            let mut last_fresh_count = self
                .fresh_writer_count_for_dc_endpoints(generation, *dc, endpoints)
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

                    let connected = self
                        .connect_endpoints_round_robin_with_generation_contour(
                            *dc,
                            &endpoint_list,
                            rng,
                            generation,
                            WriterContour::Warm,
                            false,
                        )
                        .await;
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
                    .fresh_writer_count_for_dc_endpoints(generation, *dc, endpoints)
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

    pub async fn zero_downtime_reinit_after_map_change(
        self: &Arc<Self>,
        rng: &SecureRandom,
    ) -> bool {
        let desired_by_dc = self.desired_dc_endpoints().await;
        let now_epoch_secs = Self::now_epoch_secs();
        let v4_suppressed = self.is_family_temporarily_suppressed(IpFamily::V4, now_epoch_secs);
        let v6_suppressed = self.is_family_temporarily_suppressed(IpFamily::V6, now_epoch_secs);
        if desired_by_dc.is_empty() {
            warn!("ME endpoint map is empty; skipping stale writer drain");
            let reason = if (self.decision.ipv4_me && v4_suppressed)
                || (self.decision.ipv6_me && v6_suppressed)
            {
                MeDrainGateReason::SuppressionActive
            } else {
                MeDrainGateReason::CoverageQuorum
            };
            self.set_last_drain_gate(false, false, reason, now_epoch_secs);
            return false;
        }

        let desired_map_hash = Self::desired_map_hash(&desired_by_dc);
        let hardswap = self.reinit.hardswap.load(Ordering::Relaxed);
        let reservation = self.reserve_reinit_attempt(hardswap, desired_map_hash, now_epoch_secs);
        let attempt = reservation.attempt;
        let previous_generation = attempt.previous_generation;
        let generation = attempt.generation;
        if reservation.pending_reused {
            self.stats.increment_me_hardswap_pending_reuse_total();
            debug!(
                previous_generation,
                generation,
                pending_age_secs = reservation.pending_age_secs,
                "ME hardswap continues with pending generation"
            );
        } else if reservation.pending_expired {
            self.stats.increment_me_hardswap_pending_ttl_expired_total();
            warn!(
                previous_generation,
                generation,
                pending_age_secs = reservation.pending_age_secs,
                pending_ttl_secs = ME_HARDSWAP_PENDING_TTL_SECS,
                "ME hardswap pending generation expired by TTL; starting fresh generation"
            );
        }

        if hardswap {
            self.warmup_generation_for_all_dcs(rng, generation, &desired_by_dc)
                .await;
        } else {
            self.reconcile_connections(rng).await;
        }

        let writers = self.writers.read().await;
        let active_writer_addrs: HashSet<(i32, SocketAddr)> = writers
            .iter()
            .filter(|w| !w.draining.load(Ordering::Relaxed))
            .map(|w| (w.writer_dc, w.addr))
            .collect();
        let min_ratio = Self::permille_to_ratio(
            self.drain_runtime
                .me_pool_min_fresh_ratio_permille
                .load(Ordering::Relaxed),
        );
        let (coverage_ratio, missing_dc) =
            Self::coverage_ratio(&desired_by_dc, &active_writer_addrs);
        let mut route_quorum_ok = coverage_ratio >= min_ratio;
        let mut redundancy_ok = missing_dc.is_empty();
        let mut redundancy_missing_dc = missing_dc.clone();
        let mut gate_coverage_ratio = coverage_ratio;
        if !hardswap && coverage_ratio < min_ratio {
            self.set_last_drain_gate(
                false,
                redundancy_ok,
                MeDrainGateReason::CoverageQuorum,
                now_epoch_secs,
            );
            warn!(
                previous_generation,
                generation,
                coverage_ratio = format_args!("{coverage_ratio:.3}"),
                min_ratio = format_args!("{min_ratio:.3}"),
                missing_dc = ?missing_dc,
                "ME reinit coverage below threshold; keeping stale writers"
            );
            return false;
        }

        if hardswap {
            let fresh_writer_addrs: HashSet<(i32, SocketAddr)> = writers
                .iter()
                .filter(|w| !w.draining.load(Ordering::Relaxed))
                .filter(|w| w.generation == generation)
                .map(|w| (w.writer_dc, w.addr))
                .collect();
            let (fresh_coverage_ratio, fresh_missing_dc) =
                Self::coverage_ratio(&desired_by_dc, &fresh_writer_addrs);
            route_quorum_ok = fresh_coverage_ratio >= min_ratio;
            redundancy_ok = fresh_missing_dc.is_empty();
            redundancy_missing_dc = fresh_missing_dc.clone();
            gate_coverage_ratio = fresh_coverage_ratio;
            if fresh_coverage_ratio < min_ratio {
                self.set_last_drain_gate(
                    false,
                    redundancy_ok,
                    MeDrainGateReason::CoverageQuorum,
                    now_epoch_secs,
                );
                warn!(
                    previous_generation,
                    generation,
                    fresh_coverage_ratio = format_args!("{fresh_coverage_ratio:.3}"),
                    missing_dc = ?fresh_missing_dc,
                    "ME hardswap pending: fresh generation DC coverage incomplete"
                );
                return false;
            }
        }

        self.set_last_drain_gate(
            route_quorum_ok,
            redundancy_ok,
            MeDrainGateReason::Open,
            now_epoch_secs,
        );
        if !redundancy_ok {
            warn!(
                missing_dc = ?redundancy_missing_dc,
                coverage_ratio = format_args!("{gate_coverage_ratio:.3}"),
                min_ratio = format_args!("{min_ratio:.3}"),
                "ME reinit proceeds with weighted quorum while some DC groups remain uncovered"
            );
        }

        if !self.commit_reinit_attempt(&attempt) {
            debug!(
                previous_generation,
                generation, "ME reinit result discarded after a newer desired-map attempt"
            );
            return false;
        }

        let desired_addrs: HashSet<(i32, SocketAddr)> = desired_by_dc
            .iter()
            .flat_map(|(dc, set)| set.iter().copied().map(|addr| (*dc, addr)))
            .collect();

        let stale_writer_ids: Vec<u64> = writers
            .iter()
            .filter(|w| !w.draining.load(Ordering::Relaxed))
            .filter(|w| {
                if hardswap {
                    w.generation < generation
                } else {
                    !desired_addrs.contains(&(w.writer_dc, w.addr))
                }
            })
            .map(|w| w.id)
            .collect();
        drop(writers);

        if stale_writer_ids.is_empty() {
            debug!("ME reinit cycle completed with no stale writers");
            return true;
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
            "ME reinit cycle covered; processing stale writers"
        );
        self.stats.increment_pool_swap_total();
        let can_drop_with_replacement = self.has_non_draining_writer_per_desired_dc_group().await;
        if can_drop_with_replacement {
            info!(
                stale_writers = stale_writer_ids.len(),
                "ME reinit stale writers: replacement coverage ready, force-closing clients for fast rebind"
            );
        } else {
            warn!(
                stale_writers = stale_writer_ids.len(),
                "ME reinit stale writers: replacement coverage incomplete, keeping draining fallback"
            );
        }
        for writer_id in stale_writer_ids {
            self.mark_writer_draining_with_timeout(writer_id, drain_timeout, !hardswap)
                .await;
            if can_drop_with_replacement {
                self.stats.increment_pool_force_close_total();
                self.remove_writer_and_close_clients(writer_id).await;
            }
        }
        true
    }

    pub async fn zero_downtime_reinit_periodic(self: &Arc<Self>, rng: &SecureRandom) -> bool {
        self.zero_downtime_reinit_after_map_change(rng).await
    }
}
