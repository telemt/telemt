use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::crypto::SecureRandom;
use crate::network::IpFamily;

use super::pool::{
    MePool, RefillTargetKey, RefillTargetState, WriterContour, WriterOpenIntent, WriterRole,
};

const ME_FLAP_UPTIME_THRESHOLD_SECS: u64 = 20;
const ME_FLAP_QUARANTINE_SECS: u64 = 25;
const ME_FLAP_MIN_UPTIME_MILLIS: u64 = 500;
const ME_REFILL_TOTAL_ATTEMPT_CAP: u32 = 20;
const ME_REFILL_PENDING_PER_TARGET_MAX: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefillOutcome {
    Restored,
    Failed,
    Obsolete,
}

fn refill_open_intent(contour: WriterContour) -> WriterOpenIntent {
    match contour {
        WriterContour::Active | WriterContour::Warm => WriterOpenIntent::Coverage,
        WriterContour::Draining => WriterOpenIntent::Normal,
    }
}

struct RefillRunGuard {
    pool: Arc<MePool>,
    key: RefillTargetKey,
    active: bool,
}

impl RefillRunGuard {
    fn next_or_finish(&mut self) -> Option<SocketAddr> {
        let mut states = self.pool.refill_states.lock();
        let next = states.get_mut(&self.key).and_then(|state| {
            if state.pending_count == 0 {
                return None;
            }
            state.pending_count -= 1;
            state.next_addr
        });
        if let Some(next) = next {
            self.pool.refill_pending.fetch_sub(1, Ordering::AcqRel);
            return Some(next);
        }
        states.remove(&self.key);
        self.pool.refill_running.fetch_sub(1, Ordering::AcqRel);
        self.active = false;
        None
    }
}

impl Drop for RefillRunGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(state) = self.pool.refill_states.lock().remove(&self.key) {
            self.pool
                .refill_pending
                .fetch_sub(state.pending_count, Ordering::AcqRel);
        }
        self.pool.refill_running.fetch_sub(1, Ordering::AcqRel);
    }
}

impl MePool {
    pub(super) async fn sweep_endpoint_quarantine(&self) {
        let configured = self
            .endpoint_snapshot
            .load()
            .endpoint_dc_map
            .keys()
            .copied()
            .collect::<HashSet<SocketAddr>>();
        let now = Instant::now();
        let mut guard = self.endpoint_quarantine.lock().await;
        guard.retain(|addr, expiry| *expiry > now && configured.contains(addr));
    }

    pub(super) async fn maybe_quarantine_flapping_endpoint(
        &self,
        addr: SocketAddr,
        uptime: Duration,
        reason: &'static str,
    ) {
        if uptime < Duration::from_millis(ME_FLAP_MIN_UPTIME_MILLIS) {
            debug!(
                %addr,
                reason,
                uptime_ms = uptime.as_millis(),
                min_uptime_ms = ME_FLAP_MIN_UPTIME_MILLIS,
                "Skipping flap quarantine for ultra-short writer lifetime"
            );
            return;
        }

        if uptime > Duration::from_secs(ME_FLAP_UPTIME_THRESHOLD_SECS) {
            return;
        }

        let until = Instant::now() + Duration::from_secs(ME_FLAP_QUARANTINE_SECS);
        let mut guard = self.endpoint_quarantine.lock().await;
        guard.retain(|_, expiry| *expiry > Instant::now());
        guard.insert(addr, until);
        self.stats.increment_me_endpoint_quarantine_total();
        warn!(
            %addr,
            reason,
            uptime_ms = uptime.as_millis(),
            quarantine_secs = ME_FLAP_QUARANTINE_SECS,
            "ME endpoint temporarily quarantined due to rapid writer flap"
        );
    }

    pub(super) async fn is_endpoint_quarantined(&self, addr: SocketAddr) -> bool {
        let mut guard = self.endpoint_quarantine.lock().await;
        let now = Instant::now();
        guard.retain(|_, expiry| *expiry > now);
        guard.contains_key(&addr)
    }

    async fn connectable_endpoints(&self, endpoints: &[SocketAddr]) -> Vec<SocketAddr> {
        if endpoints.is_empty() {
            return Vec::new();
        }

        if endpoints.len() == 1 && self.single_endpoint_outage_disable_quarantine() {
            let mut guard = self.endpoint_quarantine.lock().await;
            guard.retain(|_, expiry| *expiry > Instant::now());
            return endpoints.to_vec();
        }

        let mut guard = self.endpoint_quarantine.lock().await;
        let now = Instant::now();
        guard.retain(|_, expiry| *expiry > now);

        let mut ready = Vec::<SocketAddr>::with_capacity(endpoints.len());
        let mut earliest_quarantine: Option<(SocketAddr, Instant)> = None;
        for addr in endpoints {
            if let Some(expiry) = guard.get(addr).copied() {
                match earliest_quarantine {
                    Some((_, current_expiry)) if current_expiry <= expiry => {}
                    _ => earliest_quarantine = Some((*addr, expiry)),
                }
            } else {
                ready.push(*addr);
            }
        }

        if !ready.is_empty() {
            return ready;
        }

        if let Some((addr, expiry)) = earliest_quarantine {
            let remaining = expiry.saturating_duration_since(now);
            if remaining.is_zero() {
                return vec![addr];
            }
            drop(guard);
            debug!(
                %addr,
                wait_ms = expiry.saturating_duration_since(now).as_millis(),
                "All ME endpoints are quarantined for the DC group; waiting for quarantine expiry"
            );
            tokio::time::sleep(remaining).await;
            return vec![addr];
        }

        Vec::new()
    }

    #[cfg(test)]
    pub(super) async fn connectable_endpoints_for_test(
        &self,
        endpoints: &[SocketAddr],
    ) -> Vec<SocketAddr> {
        self.connectable_endpoints(endpoints).await
    }

    /// Reports whether the exact generation and contour already has a refill producer.
    pub(super) async fn has_refill_inflight_for_target(&self, key: RefillTargetKey) -> bool {
        self.refill_states.lock().contains_key(&key)
    }

    pub(super) async fn connect_endpoints_round_robin_with_generation_contour(
        self: &Arc<Self>,
        dc: i32,
        endpoints: &[SocketAddr],
        rng: &SecureRandom,
        generation: u64,
        contour: WriterContour,
        intent: WriterOpenIntent,
    ) -> bool {
        let mut candidates = self.connectable_endpoints(endpoints).await;
        if candidates.is_empty() {
            return false;
        }
        if candidates.len() > 1 {
            let mut matching_by_endpoint = HashMap::<SocketAddr, usize>::new();
            let ws = self.writers.read().await;
            for writer in ws.iter() {
                if writer.draining.load(Ordering::Relaxed) {
                    continue;
                }
                if writer.writer_dc != dc {
                    continue;
                }
                if writer.generation != generation
                    || WriterContour::from_u8(writer.contour.load(Ordering::Acquire)) != contour
                {
                    continue;
                }
                if candidates.contains(&writer.addr) {
                    *matching_by_endpoint.entry(writer.addr).or_insert(0) += 1;
                }
            }
            drop(ws);
            candidates
                .sort_by_key(|addr| (matching_by_endpoint.get(addr).copied().unwrap_or(0), *addr));
        }
        let start = (self.rr.fetch_add(1, Ordering::Relaxed) as usize) % candidates.len();
        for offset in 0..candidates.len() {
            let idx = (start + offset) % candidates.len();
            let addr = candidates[idx];
            match self
                .connect_one_with_generation_contour_for_dc_with_intent(
                    addr, rng, generation, contour, dc, intent,
                )
                .await
            {
                Ok(()) => return true,
                Err(e) => debug!(%addr, error = %e, "ME connect failed during round-robin warmup"),
            }
        }
        false
    }

    async fn endpoints_for_refill_target(&self, target: RefillTargetKey) -> Vec<SocketAddr> {
        let now_epoch_secs = Self::now_epoch_secs();
        if !self.family_enabled_for_drain_coverage(target.family, now_epoch_secs) {
            return Vec::new();
        }
        let snapshot = self.endpoint_snapshot.load();
        let map = match target.family {
            IpFamily::V4 => &snapshot.map_v4,
            IpFamily::V6 => &snapshot.map_v6,
        };
        let mut endpoints = map
            .get(&target.dc)
            .into_iter()
            .flatten()
            .map(|(ip, port)| SocketAddr::new(*ip, *port))
            .collect::<Vec<_>>();
        endpoints.sort_unstable();
        endpoints.dedup();
        endpoints
    }

    fn refill_target_is_authoritative(&self, target: RefillTargetKey) -> bool {
        if !self.family_enabled_for_drain_coverage(target.family, Self::now_epoch_secs()) {
            return false;
        }
        let status = self.reinit.status.load();
        let role_is_authoritative = match target.contour {
            WriterContour::Active => target.generation == status.active_generation,
            WriterContour::Warm => {
                status.pending_hardswap_generation != 0
                    && target.generation == status.pending_hardswap_generation
            }
            WriterContour::Draining => false,
        };
        let pending_revision_matches = target.contour != WriterContour::Warm
            || target.endpoint_revision == status.pending_hardswap_endpoint_revision;
        let endpoint_snapshot = self.endpoint_snapshot.load();
        role_is_authoritative
            && pending_revision_matches
            && target.endpoint_revision == endpoint_snapshot.revision
            && !endpoint_snapshot
                .endpoints_for_dc_family(target.dc, target.family)
                .is_empty()
    }

    async fn refill_writer_after_loss(
        self: &Arc<Self>,
        addr: SocketAddr,
        target: RefillTargetKey,
    ) -> RefillOutcome {
        if !self.refill_target_is_authoritative(target) {
            return RefillOutcome::Obsolete;
        }
        let open_intent = refill_open_intent(target.contour);
        let fast_retries = self.reconnect_runtime.me_reconnect_fast_retry_count.max(1);
        let mut total_attempts = 0u32;
        let same_endpoint_quarantined = self.is_endpoint_quarantined(addr).await;
        let dc_endpoints = self.endpoints_for_refill_target(target).await;
        let single_endpoint_dc = dc_endpoints.len() == 1 && dc_endpoints[0] == addr;
        let bypass_quarantine_for_single_endpoint =
            single_endpoint_dc && self.single_endpoint_outage_disable_quarantine();

        if dc_endpoints.contains(&addr)
            && (!same_endpoint_quarantined || bypass_quarantine_for_single_endpoint)
        {
            if same_endpoint_quarantined && bypass_quarantine_for_single_endpoint {
                debug!(
                    %addr,
                    "Bypassing quarantine for immediate reconnect on single-endpoint DC"
                );
            }
            for attempt in 0..fast_retries {
                if !self.refill_target_is_authoritative(target) {
                    return RefillOutcome::Obsolete;
                }
                if total_attempts >= ME_REFILL_TOTAL_ATTEMPT_CAP {
                    break;
                }
                total_attempts = total_attempts.saturating_add(1);
                self.stats.increment_me_reconnect_attempt();
                match self
                    .connect_one_with_generation_contour_for_dc_with_intent(
                        addr,
                        self.rng.as_ref(),
                        target.generation,
                        target.contour,
                        target.dc,
                        open_intent,
                    )
                    .await
                {
                    Ok(()) => {
                        self.stats.increment_me_reconnect_success();
                        self.stats
                            .increment_me_writer_restored_same_endpoint_total();
                        info!(
                            %addr,
                            attempt = attempt + 1,
                            "ME writer restored on the same endpoint"
                        );
                        return RefillOutcome::Restored;
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
        } else {
            debug!(
                %addr,
                "Skipping immediate same-endpoint reconnect because endpoint is quarantined"
            );
        }

        if dc_endpoints.is_empty() {
            self.stats.increment_me_refill_failed_total();
            return RefillOutcome::Failed;
        }

        for attempt in 0..fast_retries {
            if !self.refill_target_is_authoritative(target) {
                return RefillOutcome::Obsolete;
            }
            if total_attempts >= ME_REFILL_TOTAL_ATTEMPT_CAP {
                break;
            }
            total_attempts = total_attempts.saturating_add(1);
            self.stats.increment_me_reconnect_attempt();
            if self
                .connect_endpoints_round_robin_with_generation_contour(
                    target.dc,
                    &dc_endpoints,
                    self.rng.as_ref(),
                    target.generation,
                    target.contour,
                    open_intent,
                )
                .await
            {
                self.stats.increment_me_reconnect_success();
                self.stats.increment_me_writer_restored_fallback_total();
                info!(
                    %addr,
                    attempt = attempt + 1,
                    "ME writer restored via DC fallback endpoint"
                );
                return RefillOutcome::Restored;
            }
        }

        self.stats.increment_me_refill_failed_total();
        RefillOutcome::Failed
    }

    pub(crate) fn trigger_immediate_refill_for_dc(
        self: &Arc<Self>,
        addr: SocketAddr,
        writer_dc: i32,
    ) {
        self.trigger_immediate_refill_for_role(
            addr,
            WriterRole {
                dc: writer_dc,
                family: if addr.is_ipv4() {
                    IpFamily::V4
                } else {
                    IpFamily::V6
                },
                generation: self.current_generation(),
                contour: WriterContour::Active,
            },
        );
    }

    /// Coalesces unexpected writer loss without changing its generation or contour role.
    pub(super) fn trigger_immediate_refill_for_role(
        self: &Arc<Self>,
        addr: SocketAddr,
        role: WriterRole,
    ) {
        let target = RefillTargetKey {
            dc: role.dc,
            family: role.family,
            generation: role.generation,
            endpoint_revision: self.endpoint_snapshot.load().revision,
            contour: role.contour,
        };
        if !self.refill_target_is_authoritative(target) {
            return;
        }
        let Some(registration) = self.lifecycle.try_register() else {
            return;
        };
        {
            let mut states = self.refill_states.lock();
            if let Some(state) = states.get_mut(&target) {
                if state.pending_count < ME_REFILL_PENDING_PER_TARGET_MAX {
                    state.pending_count += 1;
                    state.next_addr = Some(addr);
                    self.refill_pending.fetch_add(1, Ordering::AcqRel);
                }
                self.stats.increment_me_refill_skipped_inflight_total();
                return;
            }
            states.insert(target, RefillTargetState::default());
            self.refill_running.fetch_add(1, Ordering::AcqRel);
        }

        let pool = Arc::clone(self);
        let mut run_guard = RefillRunGuard {
            pool: Arc::clone(&pool),
            key: target,
            active: true,
        };
        self.lifecycle
            .spawn_registered_producer(registration, async move {
                let mut current_addr = addr;
                loop {
                    pool.stats.increment_me_refill_triggered_total();
                    let outcome = pool.refill_writer_after_loss(current_addr, target).await;
                    if outcome == RefillOutcome::Failed {
                        warn!(
                            %current_addr,
                            dc = target.dc,
                            generation = target.generation,
                            contour = ?target.contour,
                            "ME immediate refill failed"
                        );
                    } else if outcome == RefillOutcome::Obsolete {
                        debug!(
                            %current_addr,
                            dc = target.dc,
                            generation = target.generation,
                            contour = ?target.contour,
                            "ME immediate refill target is no longer authoritative"
                        );
                        return;
                    }

                    let Some(next_addr) = run_guard.next_or_finish() else {
                        return;
                    };
                    current_addr = next_addr;
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warm_refill_preserves_required_floor_coverage() {
        assert_eq!(
            refill_open_intent(WriterContour::Warm),
            WriterOpenIntent::Coverage
        );
    }
}
