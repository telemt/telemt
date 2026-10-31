use super::*;

impl MePool {
    /// Checks the exact pending-generation tuple before starting more warmup work.
    pub(super) fn hardswap_warmup_is_authoritative(
        &self,
        generation: u64,
        map_hash: u64,
        endpoint_revision: u64,
    ) -> bool {
        let state = self.reinit.coordinator.lock();
        state.desired_map_hash == map_hash
            && state.endpoint_revision == endpoint_revision
            && state.pending.is_some_and(|pending| {
                pending.generation == generation
                    && pending.map_hash == map_hash
                    && pending.endpoint_revision == endpoint_revision
            })
    }

    async fn warmup_generation_for_all_dcs(
        self: &Arc<Self>,
        rng: &SecureRandom,
        generation: u64,
        map_hash: u64,
        endpoint_revision: u64,
        desired_by_dc: &HashMap<i32, HashSet<SocketAddr>>,
    ) {
        let extra_passes = self
            .reinit
            .me_hardswap_warmup_extra_passes
            .load(Ordering::Relaxed)
            .min(10) as usize;
        let total_passes = 1 + extra_passes;

        for (dc, endpoints) in desired_by_dc {
            if !self.hardswap_warmup_is_authoritative(generation, map_hash, endpoint_revision) {
                return;
            }
            for family in [IpFamily::V4, IpFamily::V6] {
                let family_endpoints = endpoints
                    .iter()
                    .copied()
                    .filter(|endpoint| endpoint.is_ipv4() == (family == IpFamily::V4))
                    .collect::<HashSet<_>>();
                if family_endpoints.is_empty() {
                    continue;
                }

                let mut endpoint_list = family_endpoints.iter().copied().collect::<Vec<_>>();
                endpoint_list.sort_unstable();
                let required = self.required_writers_for_dc(endpoint_list.len());
                let mut completed = false;
                let mut last_fresh_count = self
                    .fresh_writer_count_for_dc_endpoints(generation, *dc, &family_endpoints)
                    .await;

                for pass_idx in 0..total_passes {
                    if last_fresh_count >= required {
                        completed = true;
                        break;
                    }

                    let missing = required.saturating_sub(last_fresh_count);
                    debug!(
                        dc = *dc,
                        family = ?family,
                        pass = pass_idx + 1,
                        total_passes,
                        fresh_count = last_fresh_count,
                        required,
                        missing,
                        endpoint_count = endpoint_list.len(),
                        "ME hardswap family warmup pass started"
                    );

                    for attempt_idx in 0..missing {
                        if !self.hardswap_warmup_is_authoritative(
                            generation,
                            map_hash,
                            endpoint_revision,
                        ) {
                            return;
                        }
                        let delay_ms = self.hardswap_warmup_connect_delay_ms();
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        if !self.hardswap_warmup_is_authoritative(
                            generation,
                            map_hash,
                            endpoint_revision,
                        ) {
                            return;
                        }

                        let connected = self
                            .connect_endpoints_round_robin_with_generation_contour(
                                *dc,
                                &endpoint_list,
                                rng,
                                generation,
                                WriterContour::Warm,
                                WriterOpenIntent::Coverage,
                            )
                            .await;
                        debug!(
                            dc = *dc,
                            family = ?family,
                            pass = pass_idx + 1,
                            total_passes,
                            attempt = attempt_idx + 1,
                            delay_ms,
                            connected,
                            "ME hardswap family warmup connect attempt finished"
                        );
                    }

                    last_fresh_count = self
                        .fresh_writer_count_for_dc_endpoints(generation, *dc, &family_endpoints)
                        .await;
                    if last_fresh_count >= required {
                        completed = true;
                        info!(
                            dc = *dc,
                            family = ?family,
                            pass = pass_idx + 1,
                            total_passes,
                            fresh_count = last_fresh_count,
                            required,
                            "ME hardswap writer floor reached for DC family"
                        );
                        break;
                    }

                    if pass_idx + 1 < total_passes {
                        if !self.hardswap_warmup_is_authoritative(
                            generation,
                            map_hash,
                            endpoint_revision,
                        ) {
                            return;
                        }
                        let backoff_ms = self.hardswap_warmup_backoff_ms(pass_idx);
                        debug!(
                            dc = *dc,
                            family = ?family,
                            pass = pass_idx + 1,
                            total_passes,
                            fresh_count = last_fresh_count,
                            required,
                            backoff_ms,
                            "ME hardswap family warmup incomplete, delaying next pass"
                        );
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    }
                }

                if !completed {
                    warn!(
                        dc = *dc,
                        family = ?family,
                        fresh_count = last_fresh_count,
                        required,
                        endpoint_count = endpoint_list.len(),
                        total_passes,
                        "ME warmup stopped below the required DC-family writer floor"
                    );
                }
            }
        }
    }


    /// Reconciles exactly the revision owned by the scheduler's retry objective.
    pub(in crate::transport::middle_proxy) async fn reinit_endpoint_snapshot(
        self: &Arc<Self>,
        rng: &SecureRandom,
        endpoint_snapshot: Arc<EndpointSnapshot>,
    ) -> bool {
        let desired_by_dc = self.desired_dc_endpoints_from_snapshot(&endpoint_snapshot);
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
        let Some(reservation) = self.reserve_reinit_attempt(
            hardswap,
            desired_map_hash,
            endpoint_snapshot.revision,
            now_epoch_secs,
        ) else {
            debug!(
                endpoint_revision = endpoint_snapshot.revision,
                "ME reinit snapshot superseded before reservation"
            );
            return false;
        };
        let attempt = reservation.attempt;
        let previous_generation = attempt.previous_generation;
        let generation = attempt.generation;
        let reconciled_roles = self.reconcile_writer_generation_roles().await;
        if reconciled_roles > 0 {
            info!(
                reconciled_roles,
                active_generation = previous_generation,
                pending_generation = generation,
                "ME writer generation roles reconciled"
            );
        }
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
            self.warmup_generation_for_all_dcs(
                rng,
                generation,
                desired_map_hash,
                endpoint_snapshot.revision,
                &desired_by_dc,
            )
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
        if !hardswap && coverage_ratio < min_ratio {
            self.set_last_drain_gate(
                false,
                missing_dc.is_empty(),
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
            let fresh_writer_addrs: Vec<(i32, SocketAddr)> = writers
                .iter()
                .filter(|w| !w.draining.load(Ordering::Relaxed))
                .filter(|w| w.generation == generation)
                .map(|w| (w.writer_dc, w.addr))
                .collect();
            let fresh_coverage = self.hardswap_coverage(&desired_by_dc, &fresh_writer_addrs);
            if fresh_coverage.ratio < min_ratio {
                self.set_last_drain_gate(
                    false,
                    fresh_coverage.missing_groups.is_empty(),
                    MeDrainGateReason::CoverageQuorum,
                    now_epoch_secs,
                );
                warn!(
                    previous_generation,
                    generation,
                    fresh_coverage_ratio = format_args!("{:.3}", fresh_coverage.ratio),
                    writer_deficit = fresh_coverage.writer_deficit,
                    missing_groups = ?fresh_coverage.missing_groups,
                    "ME hardswap pending: fresh generation DC-family floors incomplete"
                );
                return false;
            }
        }

        drop(writers);
        let commit = self
            .commit_reinit_attempt(&attempt, &desired_by_dc, min_ratio)
            .await;
        let outcome = match commit {
            Ok(outcome) => outcome,
            Err(ReinitCommitFailure::Superseded) => {
                debug!(
                    previous_generation,
                    generation, "ME reinit result discarded after a newer desired-map attempt"
                );
                return false;
            }
            Err(ReinitCommitFailure::Coverage {
                coverage_ratio,
                missing_dc,
                missing_groups,
            }) => {
                self.set_last_drain_gate(
                    false,
                    missing_dc.is_empty(),
                    MeDrainGateReason::CoverageQuorum,
                    now_epoch_secs,
                );
                warn!(
                    previous_generation,
                    generation,
                    coverage_ratio = format_args!("{coverage_ratio:.3}"),
                    min_ratio = format_args!("{min_ratio:.3}"),
                    missing_dc = ?missing_dc,
                    missing_groups = ?missing_groups,
                    "ME reinit coverage changed before commit; keeping current generation"
                );
                return false;
            }
            Err(ReinitCommitFailure::Redundancy {
                coverage_ratio,
                missing_dc,
                missing_groups,
            }) => {
                self.set_last_drain_gate(
                    true,
                    false,
                    MeDrainGateReason::Redundancy,
                    now_epoch_secs,
                );
                warn!(
                    previous_generation,
                    generation,
                    coverage_ratio = format_args!("{coverage_ratio:.3}"),
                    min_ratio = format_args!("{min_ratio:.3}"),
                    missing_dc = ?missing_dc,
                    missing_groups = ?missing_groups,
                    "ME hardswap weighted quorum requires stale-binding fallback"
                );
                return false;
            }
        };
        self.set_last_drain_gate(
            true,
            outcome.missing_dc.is_empty(),
            MeDrainGateReason::Open,
            now_epoch_secs,
        );
        if !outcome.missing_dc.is_empty() {
            warn!(
                missing_dc = ?outcome.missing_dc,
                missing_groups = ?outcome.missing_groups,
                coverage_ratio = format_args!("{:.3}", outcome.coverage_ratio),
                min_ratio = format_args!("{min_ratio:.3}"),
                "ME reinit committed with bounded stale fallback for uncovered DC-family groups"
            );
        }

        if outcome.stale_writer_ids.is_empty() {
            debug!("ME reinit cycle completed with no stale writers");
            return true;
        }

        let drain_timeout = self.force_close_timeout();
        let drain_timeout_secs = drain_timeout.map(|d| d.as_secs()).unwrap_or(0);
        info!(
            stale_writers = outcome.stale_writer_ids.len(),
            force_close_writers = outcome.force_close_writer_ids.len(),
            previous_generation,
            generation,
            hardswap,
            coverage_ratio = format_args!("{:.3}", outcome.coverage_ratio),
            min_ratio = format_args!("{min_ratio:.3}"),
            drain_timeout_secs,
            "ME reinit cycle covered; processing stale writers"
        );
        self.stats.increment_pool_swap_total();
        for writer_id in outcome.force_close_writer_ids {
            self.stats.increment_pool_force_close_total();
            self.remove_writer_and_close_clients(writer_id).await;
        }
        true
    }

}
