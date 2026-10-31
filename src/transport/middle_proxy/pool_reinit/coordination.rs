use super::*;

impl MePool {
    /// Hashes the sorted desired endpoint map for generation authority checks.
    pub(in crate::transport::middle_proxy) fn desired_map_hash(
        desired_by_dc: &HashMap<i32, HashSet<SocketAddr>>,
    ) -> u64 {
        let mut hasher = DefaultHasher::new();
        let mut dcs: Vec<i32> = desired_by_dc.keys().copied().collect();
        dcs.sort_unstable();
        for dc in dcs {
            dc.hash(&mut hasher);
            let mut endpoints: Vec<SocketAddr> = desired_by_dc
                .get(&dc)
                .map(|set| set.iter().copied().collect())
                .unwrap_or_default();
            endpoints.sort_unstable();
            for endpoint in endpoints {
                endpoint.hash(&mut hasher);
            }
        }
        hasher.finish()
    }

    /// Reserves one generation attempt and publishes its pending ownership snapshot.
    pub(super) fn reserve_reinit_attempt(
        self: &Arc<Self>,
        hardswap: bool,
        map_hash: u64,
        endpoint_revision: u64,
        now_epoch_secs: u64,
    ) -> Option<ReinitReservation> {
        let mut state = self.reinit.coordinator.lock();
        if state.endpoint_revision != endpoint_revision {
            return None;
        }
        state.desired_map_hash = map_hash;
        let previous_generation = state.active_generation;
        let mut pending_reused = false;
        let mut pending_expired = false;
        let mut pending_age_secs = 0;

        let generation = if hardswap {
            let reusable = state.pending.filter(|pending| {
                pending_age_secs = now_epoch_secs.saturating_sub(pending.started_at_epoch_secs);
                pending_expired = pending.started_at_epoch_secs > 0
                    && pending_age_secs > ME_HARDSWAP_PENDING_TTL_SECS;
                pending.generation >= previous_generation
                    && pending.map_hash == map_hash
                    && pending.endpoint_revision == endpoint_revision
                    && !pending_expired
            });
            if let Some(pending) = reusable {
                pending_reused = true;
                pending.generation
            } else {
                let generation = self.reinit.generation.fetch_add(1, Ordering::AcqRel) + 1;
                state.pending = Some(ReinitPendingState {
                    generation,
                    started_at_epoch_secs: now_epoch_secs,
                    map_hash,
                    endpoint_revision,
                });
                generation
            }
        } else {
            state.pending = None;
            self.reinit.generation.fetch_add(1, Ordering::AcqRel) + 1
        };

        let attempt_id = state.next_attempt_id;
        state.next_attempt_id = state.next_attempt_id.saturating_add(1);
        state.attempts.insert(
            attempt_id,
            ReinitAttemptState {
                generation,
                map_hash,
                endpoint_revision,
                hardswap,
                committed: false,
            },
        );
        publish_reinit_state(self.reinit.as_ref(), &state);
        Some(ReinitReservation {
            attempt: ReinitAttemptGuard {
                reinit: Arc::clone(&self.reinit),
                attempt_id,
                generation,
                previous_generation,
                map_hash,
                endpoint_revision,
                hardswap,
            },
            pending_reused,
            pending_expired,
            pending_age_secs,
        })
    }

    /// Revalidates coverage and commits generation ownership under the publication barrier.
    pub(super) async fn commit_reinit_attempt(
        &self,
        attempt: &ReinitAttemptGuard,
        desired_by_dc: &HashMap<i32, HashSet<SocketAddr>>,
        min_ratio: f32,
    ) -> std::result::Result<ReinitCommitOutcome, ReinitCommitFailure> {
        let writers = self.writers.write().await;
        let mut registry_registration = self.registry.prepare_writer_registration().await;
        let mut state = self.reinit.coordinator.lock();
        let Some(record) = state.attempts.get(&attempt.attempt_id).copied() else {
            return Err(ReinitCommitFailure::Superseded);
        };
        if record.generation != attempt.generation
            || record.map_hash != state.desired_map_hash
            || record.map_hash != attempt.map_hash
            || record.endpoint_revision != attempt.endpoint_revision
            || record.endpoint_revision != state.endpoint_revision
            || (attempt.hardswap
                && !state.pending.is_some_and(|pending| {
                    pending.generation == attempt.generation
                        && pending.map_hash == attempt.map_hash
                        && pending.endpoint_revision == attempt.endpoint_revision
                }))
        {
            return Err(ReinitCommitFailure::Superseded);
        }

        let authoritative_writer_addrs = writers
            .iter()
            .filter(|writer| !writer.draining.load(Ordering::Acquire))
            .filter(|writer| {
                if attempt.hardswap {
                    writer.generation == attempt.generation
                } else {
                    writer.generation == state.active_generation
                        && WriterContour::from_u8(writer.contour.load(Ordering::Acquire))
                            == WriterContour::Active
                }
            })
            .map(|writer| (writer.writer_dc, writer.addr))
            .collect::<Vec<_>>();
        let (coverage_ratio, missing_dc, missing_groups) = if attempt.hardswap {
            let coverage = self.hardswap_coverage(desired_by_dc, &authoritative_writer_addrs);
            let missing_dc = Self::missing_group_dcs(&coverage.missing_groups);
            (coverage.ratio, missing_dc, coverage.missing_groups)
        } else {
            let authoritative_writer_addrs = authoritative_writer_addrs
                .iter()
                .copied()
                .collect::<HashSet<_>>();
            let (coverage_ratio, missing_dc) =
                Self::coverage_ratio(desired_by_dc, &authoritative_writer_addrs);
            (coverage_ratio, missing_dc, Vec::new())
        };
        if coverage_ratio < min_ratio {
            return Err(ReinitCommitFailure::Coverage {
                coverage_ratio,
                missing_dc,
                missing_groups,
            });
        }
        if attempt.hardswap
            && !missing_groups.is_empty()
            && self.bind_stale_mode() == MeBindStaleMode::Never
        {
            return Err(ReinitCommitFailure::Redundancy {
                coverage_ratio,
                missing_dc,
                missing_groups,
            });
        }
        if !commit_reinit_state(
            &mut state,
            attempt.attempt_id,
            attempt.generation,
            attempt.map_hash,
            attempt.endpoint_revision,
            attempt.hardswap,
        ) {
            return Err(ReinitCommitFailure::Superseded);
        }

        if attempt.hardswap {
            for writer in writers.iter() {
                if !writer.draining.load(Ordering::Acquire)
                    && writer.generation == attempt.generation
                {
                    writer
                        .contour
                        .store(WriterContour::Active.as_u8(), Ordering::Release);
                }
            }
        }

        let desired_addrs = desired_by_dc
            .iter()
            .flat_map(|(dc, endpoints)| endpoints.iter().copied().map(|addr| (*dc, addr)))
            .collect::<HashSet<_>>();
        let missing_group_set = missing_groups.iter().copied().collect::<HashSet<_>>();
        let mut stale_writer_ids = Vec::<u64>::new();
        let mut force_close_writer_ids = Vec::<u64>::new();
        for writer in writers.iter() {
            if writer.draining.load(Ordering::Acquire) {
                continue;
            }
            let stale = if attempt.hardswap {
                writer.generation < attempt.generation
            } else {
                !desired_addrs.contains(&(writer.writer_dc, writer.addr))
            };
            if !stale {
                continue;
            }

            let writer_group = DcFamilyGroup {
                dc: writer.writer_dc,
                family: if writer.addr.is_ipv4() {
                    IpFamily::V4
                } else {
                    IpFamily::V6
                },
            };
            let preserve_fallback = attempt.hardswap && missing_group_set.contains(&writer_group);
            if !preserve_fallback && attempt.hardswap {
                registry_registration.retire(writer.id);
            }
            self.apply_writer_draining_state(
                writer,
                self.force_close_timeout(),
                preserve_fallback || !attempt.hardswap,
            );
            stale_writer_ids.push(writer.id);
            if (attempt.hardswap && !preserve_fallback)
                || (!attempt.hardswap && missing_dc.is_empty())
            {
                force_close_writer_ids.push(writer.id);
            }
        }
        publish_reinit_state(self.reinit.as_ref(), &state);
        drop(state);
        drop(registry_registration);
        drop(writers);
        self.notify_writer_epoch();

        Ok(ReinitCommitOutcome {
            coverage_ratio,
            missing_dc,
            missing_groups,
            stale_writer_ids,
            force_close_writer_ids,
        })
    }

    /// Computes desired DC-group coverage and returns missing groups in stable order.
    pub(super) fn coverage_ratio(
        desired_by_dc: &HashMap<i32, HashSet<SocketAddr>>,
        active_writer_addrs: &HashSet<(i32, SocketAddr)>,
    ) -> (f32, Vec<i32>) {
        if desired_by_dc.is_empty() {
            return (1.0, Vec::new());
        }

        let mut missing_dc = Vec::<i32>::new();
        let mut covered = 0usize;
        let mut total = 0usize;
        for (dc, endpoints) in desired_by_dc {
            if endpoints.is_empty() {
                continue;
            }
            total += 1;
            if endpoints
                .iter()
                .any(|addr| active_writer_addrs.contains(&(*dc, *addr)))
            {
                covered += 1;
            } else {
                missing_dc.push(*dc);
            }
        }

        missing_dc.sort_unstable();
        if total == 0 {
            return (1.0, missing_dc);
        }
        let ratio = (covered as f32) / (total as f32);
        (ratio, missing_dc)
    }

    /// Evaluates full writer-floor coverage independently for every DC and address family.
    pub(in crate::transport::middle_proxy) fn hardswap_coverage(
        &self,
        desired_by_dc: &HashMap<i32, HashSet<SocketAddr>>,
        writer_addrs: &[(i32, SocketAddr)],
    ) -> HardswapCoverage {
        let mut covered = 0usize;
        let mut total = 0usize;
        let mut writer_deficit = 0usize;
        let mut missing_groups = Vec::new();
        for (dc, endpoints) in desired_by_dc {
            for family in [IpFamily::V4, IpFamily::V6] {
                let endpoint_count = endpoints
                    .iter()
                    .filter(|endpoint| endpoint.is_ipv4() == (family == IpFamily::V4))
                    .count();
                if endpoint_count == 0 {
                    continue;
                }
                total = total.saturating_add(1);
                let required = self.required_writers_for_dc(endpoint_count);
                let alive = writer_addrs
                    .iter()
                    .filter(|(writer_dc, endpoint)| {
                        *writer_dc == *dc
                            && endpoint.is_ipv4() == (family == IpFamily::V4)
                            && endpoints.contains(endpoint)
                    })
                    .count();
                if alive >= required {
                    covered = covered.saturating_add(1);
                } else {
                    writer_deficit = writer_deficit.saturating_add(required.saturating_sub(alive));
                    missing_groups.push(DcFamilyGroup { dc: *dc, family });
                }
            }
        }
        missing_groups
            .sort_unstable_by_key(|group| (group.dc, matches!(group.family, IpFamily::V6)));
        HardswapCoverage {
            ratio: if total == 0 {
                1.0
            } else {
                (covered as f32) / (total as f32)
            },
            missing_groups,
            writer_deficit,
        }
    }

    fn missing_group_dcs(groups: &[DcFamilyGroup]) -> Vec<i32> {
        let mut dcs = groups.iter().map(|group| group.dc).collect::<Vec<_>>();
        dcs.sort_unstable();
        dcs.dedup();
        dcs
    }

    /// Restores at least one active writer for every enabled desired DC group.
    pub async fn reconcile_connections(self: &Arc<Self>, rng: &SecureRandom) {
        let endpoint_snapshot = self.endpoint_snapshot.load_full();
        for family in self.family_order() {
            let map = match family {
                IpFamily::V4 => &endpoint_snapshot.map_v4,
                IpFamily::V6 => &endpoint_snapshot.map_v6,
            };
            for (dc, addrs) in map {
                let dc_addrs: Vec<SocketAddr> = addrs
                    .iter()
                    .map(|(ip, port)| SocketAddr::new(*ip, *port))
                    .collect();
                let dc_endpoints: HashSet<SocketAddr> = dc_addrs.iter().copied().collect();
                if self
                    .active_writer_count_for_dc_endpoints(*dc, &dc_endpoints)
                    .await
                    == 0
                {
                    let mut shuffled = dc_addrs.clone();
                    shuffled.shuffle(&mut rand::rng());
                    for addr in shuffled {
                        if self.connect_one_for_dc(addr, *dc, rng).await.is_ok() {
                            break;
                        }
                    }
                }
            }
            if !self.decision.effective_multipath && self.connection_count() > 0 {
                break;
            }
        }
    }

    /// Returns the currently authoritative endpoint set for drain and coverage decisions.
    #[cfg(test)]
    pub(in crate::transport::middle_proxy) async fn desired_dc_endpoints(
        &self,
    ) -> HashMap<i32, HashSet<SocketAddr>> {
        let endpoint_snapshot = self.endpoint_snapshot.load_full();
        self.desired_dc_endpoints_from_snapshot(&endpoint_snapshot)
    }

    /// Projects desired per-DC endpoint sets from one immutable endpoint revision.
    pub(in crate::transport::middle_proxy) fn desired_dc_endpoints_from_snapshot(
        &self,
        endpoint_snapshot: &EndpointSnapshot,
    ) -> HashMap<i32, HashSet<SocketAddr>> {
        let now_epoch_secs = Self::now_epoch_secs();
        let mut out: HashMap<i32, HashSet<SocketAddr>> = HashMap::new();

        if self.family_enabled_for_drain_coverage(IpFamily::V4, now_epoch_secs) {
            for (dc, addrs) in &endpoint_snapshot.map_v4 {
                let entry = out.entry(*dc).or_default();
                for (ip, port) in addrs {
                    entry.insert(SocketAddr::new(*ip, *port));
                }
            }
        }

        if self.family_enabled_for_drain_coverage(IpFamily::V6, now_epoch_secs) {
            for (dc, addrs) in &endpoint_snapshot.map_v6 {
                let entry = out.entry(*dc).or_default();
                for (ip, port) in addrs {
                    entry.insert(SocketAddr::new(*ip, *port));
                }
            }
        }

        out
    }

    /// Promotes authoritative warm writers and drains warm or active generation orphans.
    pub(super) async fn reconcile_writer_generation_roles(&self) -> usize {
        let writers = self.writers.write().await;
        let mut registry_registration = self.registry.prepare_writer_registration().await;
        let state = self.reinit.coordinator.lock();
        let active_generation = state.active_generation;
        let pending_generation = state.pending.map(|pending| pending.generation);
        let endpoint_snapshot = self.endpoint_snapshot.load();
        let now_epoch_secs = Self::now_epoch_secs();
        let mut changed = 0usize;

        for writer in writers.iter() {
            if writer.draining.load(Ordering::Acquire) {
                continue;
            }
            let contour = WriterContour::from_u8(writer.contour.load(Ordering::Acquire));
            let family = if writer.addr.is_ipv4() {
                IpFamily::V4
            } else {
                IpFamily::V6
            };
            let endpoint_is_current = self
                .family_enabled_for_drain_coverage(family, now_epoch_secs)
                && endpoint_snapshot.contains_dc_endpoint(writer.writer_dc, writer.addr);
            if contour == WriterContour::Warm
                && writer.generation == active_generation
                && endpoint_is_current
            {
                writer
                    .contour
                    .store(WriterContour::Active.as_u8(), Ordering::Release);
                changed = changed.saturating_add(1);
                continue;
            }
            let authoritative_warm = contour == WriterContour::Warm
                && pending_generation == Some(writer.generation)
                && endpoint_is_current;
            let stale_active =
                contour == WriterContour::Active && writer.generation != active_generation;
            if authoritative_warm || (contour == WriterContour::Active && !stale_active) {
                continue;
            }

            registry_registration.retire(writer.id);
            self.apply_writer_draining_state(writer, self.force_close_timeout(), false);
            changed = changed.saturating_add(1);
        }
        drop(endpoint_snapshot);
        drop(state);
        drop(registry_registration);
        drop(writers);
        if changed > 0 {
            self.notify_writer_epoch();
        }
        changed
    }

    pub(super) fn hardswap_warmup_connect_delay_ms(&self) -> u64 {
        let min_ms = self
            .reinit
            .me_hardswap_warmup_delay_min_ms
            .load(Ordering::Relaxed);
        let max_ms = self
            .reinit
            .me_hardswap_warmup_delay_max_ms
            .load(Ordering::Relaxed);
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

    /// Returns capped exponential retry delay with bounded positive jitter.
    pub(in crate::transport::middle_proxy) fn hardswap_warmup_backoff_ms(
        &self,
        pass_idx: usize,
    ) -> u64 {
        let base_ms = self
            .reinit
            .me_hardswap_warmup_pass_backoff_base_ms
            .load(Ordering::Relaxed);
        let cap_ms =
            (self.reconnect_runtime.me_reconnect_backoff_cap.as_millis() as u64).max(base_ms);
        let shift = (pass_idx as u32).min(20);
        let scaled = base_ms.saturating_mul(1u64 << shift);
        let core = scaled.min(cap_ms);
        let jitter = (core / 2).max(1);
        core.saturating_add(rand::rng().random_range(0..=jitter))
    }

    /// Counts non-draining writers owned by one generation and desired DC endpoint set.
    pub(super) async fn fresh_writer_count_for_dc_endpoints(
        &self,
        generation: u64,
        dc: i32,
        endpoints: &HashSet<SocketAddr>,
    ) -> usize {
        let ws = self.writers.read().await;
        ws.iter()
            .filter(|w| !w.draining.load(Ordering::Relaxed))
            .filter(|w| w.generation == generation)
            .filter(|w| w.writer_dc == dc)
            .filter(|w| endpoints.contains(&w.addr))
            .count()
    }

    /// Counts authoritative active writers for one desired DC endpoint set.
    pub(in crate::transport::middle_proxy) async fn active_writer_count_for_dc_endpoints(
        &self,
        dc: i32,
        endpoints: &HashSet<SocketAddr>,
    ) -> usize {
        let generation = self.current_generation();
        let ws = self.writers.read().await;
        ws.iter()
            .filter(|w| !w.draining.load(Ordering::Relaxed))
            .filter(|w| w.generation == generation)
            .filter(|w| {
                WriterContour::from_u8(w.contour.load(Ordering::Acquire)) == WriterContour::Active
            })
            .filter(|w| w.writer_dc == dc)
            .filter(|w| endpoints.contains(&w.addr))
            .count()
    }
}
