use super::*;

impl MePool {
    pub(super) fn desired_map_hash(desired_by_dc: &HashMap<i32, HashSet<SocketAddr>>) -> u64 {
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

    pub(super) fn reserve_reinit_attempt(
        self: &Arc<Self>,
        hardswap: bool,
        map_hash: u64,
        now_epoch_secs: u64,
    ) -> ReinitReservation {
        let mut state = self.reinit.coordinator.lock();
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
                hardswap,
                committed: false,
            },
        );
        publish_reinit_state(self.reinit.as_ref(), &state);
        ReinitReservation {
            attempt: ReinitAttemptGuard {
                reinit: Arc::clone(&self.reinit),
                attempt_id,
                generation,
                previous_generation,
                map_hash,
                hardswap,
            },
            pending_reused,
            pending_expired,
            pending_age_secs,
        }
    }

    pub(super) fn commit_reinit_attempt(&self, attempt: &ReinitAttemptGuard) -> bool {
        let mut state = self.reinit.coordinator.lock();
        if !commit_reinit_state(
            &mut state,
            attempt.attempt_id,
            attempt.generation,
            attempt.map_hash,
            attempt.hardswap,
        ) {
            return false;
        }
        if attempt.hardswap {
            let writers = self.writers.snapshot();
            for writer in writers.iter() {
                if !writer.draining.load(Ordering::Relaxed)
                    && writer.generation == attempt.generation
                {
                    writer
                        .contour
                        .store(WriterContour::Active.as_u8(), Ordering::Release);
                }
            }
        }
        publish_reinit_state(self.reinit.as_ref(), &state);
        true
    }

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

    pub async fn reconcile_connections(self: &Arc<Self>, rng: &SecureRandom) {
        for family in self.family_order() {
            let map = self.proxy_map_for_family(family).await;
            for (dc, addrs) in &map {
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

    pub(super) async fn desired_dc_endpoints(&self) -> HashMap<i32, HashSet<SocketAddr>> {
        let now_epoch_secs = Self::now_epoch_secs();
        let mut out: HashMap<i32, HashSet<SocketAddr>> = HashMap::new();

        if self.family_enabled_for_drain_coverage(IpFamily::V4, now_epoch_secs) {
            let map_v4 = self.proxy_map_v4.read().await.clone();
            for (dc, addrs) in map_v4 {
                let entry = out.entry(dc).or_default();
                for (ip, port) in addrs {
                    entry.insert(SocketAddr::new(ip, port));
                }
            }
        }

        if self.family_enabled_for_drain_coverage(IpFamily::V6, now_epoch_secs) {
            let map_v6 = self.proxy_map_v6.read().await.clone();
            for (dc, addrs) in map_v6 {
                let entry = out.entry(dc).or_default();
                for (ip, port) in addrs {
                    entry.insert(SocketAddr::new(ip, port));
                }
            }
        }

        out
    }

    pub(in crate::transport::middle_proxy) async fn has_non_draining_writer_per_desired_dc_group(
        &self,
    ) -> bool {
        let desired_by_dc = self.desired_dc_endpoints().await;
        let required_dcs: HashSet<i32> = desired_by_dc
            .iter()
            .filter_map(|(dc, endpoints)| {
                if endpoints.is_empty() {
                    None
                } else {
                    Some(*dc)
                }
            })
            .collect();
        if required_dcs.is_empty() {
            return true;
        }

        let ws = self.writers.read().await;
        let mut covered_dcs = HashSet::<i32>::with_capacity(required_dcs.len());
        for writer in ws.iter() {
            if writer.draining.load(Ordering::Relaxed) {
                continue;
            }
            if required_dcs.contains(&writer.writer_dc) {
                covered_dcs.insert(writer.writer_dc);
                if covered_dcs.len() == required_dcs.len() {
                    return true;
                }
            }
        }
        false
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

    pub(super) fn hardswap_warmup_backoff_ms(&self, pass_idx: usize) -> u64 {
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

    pub(in crate::transport::middle_proxy) async fn active_writer_count_for_dc_endpoints(
        &self,
        dc: i32,
        endpoints: &HashSet<SocketAddr>,
    ) -> usize {
        let ws = self.writers.read().await;
        ws.iter()
            .filter(|w| !w.draining.load(Ordering::Relaxed))
            .filter(|w| w.writer_dc == dc)
            .filter(|w| endpoints.contains(&w.addr))
            .count()
    }
}
