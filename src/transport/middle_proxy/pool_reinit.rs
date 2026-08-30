use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use rand::RngExt;
use rand::seq::SliceRandom;
use std::collections::hash_map::DefaultHasher;
use tracing::{debug, info, warn};

use crate::crypto::SecureRandom;
use crate::network::IpFamily;

use super::pool::{
    MeDrainGateReason, MePool, ReinitAttemptState, ReinitCoordinatorState, ReinitCore,
    ReinitPendingState, ReinitStatusSnapshot, WriterContour,
};

const ME_HARDSWAP_PENDING_TTL_SECS: u64 = 1800;

struct ReinitAttemptGuard {
    reinit: Arc<ReinitCore>,
    attempt_id: u64,
    generation: u64,
    previous_generation: u64,
    map_hash: u64,
    hardswap: bool,
}

impl Drop for ReinitAttemptGuard {
    fn drop(&mut self) {
        let mut state = self.reinit.coordinator.lock();
        state.attempts.remove(&self.attempt_id);
        publish_reinit_state(self.reinit.as_ref(), &state);
    }
}

struct ReinitReservation {
    attempt: ReinitAttemptGuard,
    pending_reused: bool,
    pending_expired: bool,
    pending_age_secs: u64,
}

fn publish_reinit_state(reinit: &ReinitCore, state: &ReinitCoordinatorState) {
    let mut warm_generations = state
        .attempts
        .values()
        .filter(|attempt| attempt.hardswap && !attempt.committed)
        .map(|attempt| attempt.generation)
        .collect::<Vec<_>>();
    warm_generations.sort_unstable();
    warm_generations.dedup();
    let pending = state.pending;
    let snapshot = ReinitStatusSnapshot {
        active_generation: state.active_generation,
        warm_generations,
        pending_hardswap_generation: pending.map_or(0, |value| value.generation),
        pending_hardswap_started_at_epoch_secs: pending
            .map_or(0, |value| value.started_at_epoch_secs),
        pending_hardswap_map_hash: pending.map_or(0, |value| value.map_hash),
        inflight: state.attempts.len(),
    };
    reinit
        .active_generation
        .store(snapshot.active_generation, Ordering::Release);
    reinit.warm_generation.store(
        snapshot.warm_generations.last().copied().unwrap_or(0),
        Ordering::Release,
    );
    reinit.pending_hardswap_generation.store(
        snapshot.pending_hardswap_generation,
        Ordering::Release,
    );
    reinit.pending_hardswap_started_at_epoch_secs.store(
        snapshot.pending_hardswap_started_at_epoch_secs,
        Ordering::Release,
    );
    reinit
        .pending_hardswap_map_hash
        .store(snapshot.pending_hardswap_map_hash, Ordering::Release);
    reinit.status.store(Arc::new(snapshot));
}

fn commit_reinit_state(
    state: &mut ReinitCoordinatorState,
    attempt_id: u64,
    generation: u64,
    map_hash: u64,
    hardswap: bool,
) -> bool {
    let Some(record) = state.attempts.get(&attempt_id).copied() else {
        return false;
    };
    if record.map_hash != state.desired_map_hash || record.map_hash != map_hash {
        return false;
    }
    if hardswap {
        let pending_matches = state.pending.is_some_and(|pending| {
            pending.generation == generation && pending.map_hash == map_hash
        });
        if !pending_matches || generation < state.active_generation {
            return false;
        }
        state.active_generation = generation;
        state.pending = None;
    }
    if let Some(record) = state.attempts.get_mut(&attempt_id) {
        record.committed = true;
    }
    true
}

impl MePool {
    fn desired_map_hash(desired_by_dc: &HashMap<i32, HashSet<SocketAddr>>) -> u64 {
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

    fn reserve_reinit_attempt(
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

    fn commit_reinit_attempt(&self, attempt: &ReinitAttemptGuard) -> bool {
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

    fn coverage_ratio(
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

    async fn desired_dc_endpoints(&self) -> HashMap<i32, HashSet<SocketAddr>> {
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

    pub(super) async fn has_non_draining_writer_per_desired_dc_group(&self) -> bool {
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

    fn hardswap_warmup_connect_delay_ms(&self) -> u64 {
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

    fn hardswap_warmup_backoff_ms(&self, pass_idx: usize) -> u64 {
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

    async fn fresh_writer_count_for_dc_endpoints(
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

    pub(super) async fn active_writer_count_for_dc_endpoints(
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
        let reservation =
            self.reserve_reinit_attempt(hardswap, desired_map_hash, now_epoch_secs);
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
                generation,
                "ME reinit result discarded after a newer desired-map attempt"
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

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{MePool, commit_reinit_state};
    use crate::transport::middle_proxy::pool::{
        ReinitAttemptState, ReinitCoordinatorState, ReinitPendingState,
    };

    fn addr(octet: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, octet)), port)
    }

    #[test]
    fn coverage_ratio_counts_dc_coverage_not_floor() {
        let dc1 = addr(1, 2001);
        let dc2 = addr(2, 2002);

        let mut desired_by_dc = HashMap::<i32, HashSet<SocketAddr>>::new();
        desired_by_dc.insert(1, HashSet::from([dc1]));
        desired_by_dc.insert(2, HashSet::from([dc2]));

        let active_writer_addrs = HashSet::from([(1, dc1)]);
        let (ratio, missing_dc) = MePool::coverage_ratio(&desired_by_dc, &active_writer_addrs);

        assert_eq!(ratio, 0.5);
        assert_eq!(missing_dc, vec![2]);
    }

    #[test]
    fn coverage_ratio_ignores_empty_dc_groups() {
        let dc1 = addr(1, 2001);

        let mut desired_by_dc = HashMap::<i32, HashSet<SocketAddr>>::new();
        desired_by_dc.insert(1, HashSet::from([dc1]));
        desired_by_dc.insert(2, HashSet::new());

        let active_writer_addrs = HashSet::from([(1, dc1)]);
        let (ratio, missing_dc) = MePool::coverage_ratio(&desired_by_dc, &active_writer_addrs);

        assert_eq!(ratio, 1.0);
        assert!(missing_dc.is_empty());
    }

    #[test]
    fn coverage_ratio_reports_missing_dcs_sorted() {
        let dc1 = addr(1, 2001);
        let dc2 = addr(2, 2002);

        let mut desired_by_dc = HashMap::<i32, HashSet<SocketAddr>>::new();
        desired_by_dc.insert(2, HashSet::from([dc2]));
        desired_by_dc.insert(1, HashSet::from([dc1]));

        let (ratio, missing_dc) = MePool::coverage_ratio(&desired_by_dc, &HashSet::new());

        assert_eq!(ratio, 0.0);
        assert_eq!(missing_dc, vec![1, 2]);
    }

    #[test]
    fn stale_concurrent_attempt_cannot_regress_active_generation() {
        let mut state = ReinitCoordinatorState {
            next_attempt_id: 3,
            active_generation: 1,
            desired_map_hash: 22,
            pending: Some(ReinitPendingState {
                generation: 3,
                started_at_epoch_secs: 1,
                map_hash: 22,
            }),
            attempts: HashMap::from([
                (
                    1,
                    ReinitAttemptState {
                        generation: 2,
                        map_hash: 11,
                        hardswap: true,
                        committed: false,
                    },
                ),
                (
                    2,
                    ReinitAttemptState {
                        generation: 3,
                        map_hash: 22,
                        hardswap: true,
                        committed: false,
                    },
                ),
            ]),
        };

        assert!(commit_reinit_state(&mut state, 2, 3, 22, true));
        assert_eq!(state.active_generation, 3);
        assert!(!commit_reinit_state(&mut state, 1, 2, 11, true));
        assert_eq!(state.active_generation, 3);
        assert!(state.pending.is_none());
    }
}
