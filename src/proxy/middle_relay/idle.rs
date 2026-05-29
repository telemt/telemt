use super::*;
use dashmap::DashMap;

mod read;

pub(crate) use self::read::read_client_payload_with_idle_policy_in;
#[cfg(test)]
pub(crate) use self::read::{
    read_client_payload, read_client_payload_legacy, read_client_payload_with_idle_policy,
};

#[derive(Default)]
pub(crate) struct RelayIdleCandidateRegistry {
    pub(in crate::proxy::middle_relay) by_conn_id: DashMap<u64, RelayIdleCandidateMeta>,
    pub(in crate::proxy::middle_relay) ordered: parking_lot::Mutex<BTreeSet<(u64, u64)>>,
    pressure_event_seq: AtomicU64,
    pressure_consumed_seq: AtomicU64,
}

/// Queue metadata used to preserve FIFO ordering for idle relay eviction.
#[derive(Clone, Copy)]
pub(in crate::proxy::middle_relay) struct RelayIdleCandidateMeta {
    pub(in crate::proxy::middle_relay) mark_order_seq: u64,
    pub(in crate::proxy::middle_relay) mark_pressure_seq: u64,
}

pub(super) fn mark_relay_idle_candidate_in(shared: &ProxySharedState, conn_id: u64) -> bool {
    let registry = &shared.middle_relay.relay_idle_registry;

    if registry.by_conn_id.contains_key(&conn_id) {
        return false;
    }

    let mark_order_seq = shared
        .middle_relay
        .relay_idle_mark_seq
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    let meta = RelayIdleCandidateMeta {
        mark_order_seq,
        mark_pressure_seq: registry.pressure_event_seq.load(Ordering::Relaxed),
    };
    match registry.by_conn_id.entry(conn_id) {
        dashmap::mapref::entry::Entry::Occupied(_) => false,
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(meta);
            registry
                .ordered
                .lock()
                .insert((meta.mark_order_seq, conn_id));
            true
        }
    }
}

pub(super) fn clear_relay_idle_candidate_in(shared: &ProxySharedState, conn_id: u64) {
    let registry = &shared.middle_relay.relay_idle_registry;

    if let Some((_, meta)) = registry.by_conn_id.remove(&conn_id) {
        registry
            .ordered
            .lock()
            .remove(&(meta.mark_order_seq, conn_id));
    }
}

pub(super) fn note_relay_pressure_event_in(shared: &ProxySharedState) {
    shared
        .middle_relay
        .relay_idle_registry
        .pressure_event_seq
        .fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn note_global_relay_pressure(shared: &ProxySharedState) {
    note_relay_pressure_event_in(shared);
}

pub(super) fn relay_pressure_event_seq_in(shared: &ProxySharedState) -> u64 {
    shared
        .middle_relay
        .relay_idle_registry
        .pressure_event_seq
        .load(Ordering::Relaxed)
}

pub(super) fn maybe_evict_idle_candidate_on_pressure_in(
    shared: &ProxySharedState,
    conn_id: u64,
    seen_pressure_seq: &mut u64,
    stats: &Stats,
) -> bool {
    let registry = &shared.middle_relay.relay_idle_registry;

    let latest_pressure_seq = registry.pressure_event_seq.load(Ordering::Relaxed);
    if latest_pressure_seq == *seen_pressure_seq {
        return false;
    }
    *seen_pressure_seq = latest_pressure_seq;

    let consumed_pressure_seq = registry.pressure_consumed_seq.load(Ordering::Relaxed);
    if latest_pressure_seq == consumed_pressure_seq {
        return false;
    }

    let oldest = {
        let mut ordered = registry.ordered.lock();
        loop {
            let Some((mark_order_seq, candidate_conn_id)) = ordered.iter().next().copied() else {
                // Empty queues consume the event so later candidates cannot replay stale pressure.
                let _ = registry.pressure_consumed_seq.compare_exchange(
                    consumed_pressure_seq,
                    latest_pressure_seq,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
                return false;
            };
            let Some(candidate_meta) = registry.by_conn_id.get(&candidate_conn_id) else {
                ordered.remove(&(mark_order_seq, candidate_conn_id));
                continue;
            };
            if candidate_meta.mark_order_seq != mark_order_seq {
                ordered.remove(&(mark_order_seq, candidate_conn_id));
                continue;
            }
            break Some(candidate_conn_id);
        }
    };
    if oldest != Some(conn_id) {
        return false;
    }

    let Some(candidate_meta) = registry
        .by_conn_id
        .get(&conn_id)
        .map(|entry| *entry.value())
    else {
        return false;
    };

    if latest_pressure_seq == candidate_meta.mark_pressure_seq {
        return false;
    }

    // Claim the global pressure budget before removal; otherwise racing sessions
    // can observe the next FIFO item and spend the same event more than once.
    if registry
        .pressure_consumed_seq
        .compare_exchange(
            consumed_pressure_seq,
            latest_pressure_seq,
            Ordering::Relaxed,
            Ordering::Relaxed,
        )
        .is_err()
    {
        return false;
    }

    if let Some((_, meta)) = registry.by_conn_id.remove(&conn_id) {
        registry
            .ordered
            .lock()
            .remove(&(meta.mark_order_seq, conn_id));
    }
    stats.increment_relay_pressure_evict_total();
    true
}

#[derive(Clone, Copy)]
pub(in crate::proxy::middle_relay) struct RelayClientIdlePolicy {
    pub(in crate::proxy::middle_relay) enabled: bool,
    pub(in crate::proxy::middle_relay) soft_idle: Duration,
    pub(in crate::proxy::middle_relay) hard_idle: Duration,
    pub(in crate::proxy::middle_relay) grace_after_downstream_activity: Duration,
    pub(in crate::proxy::middle_relay) legacy_frame_read_timeout: Duration,
}

impl RelayClientIdlePolicy {
    pub(super) fn from_config(config: &ProxyConfig) -> Self {
        let frame_read_timeout =
            Duration::from_secs(config.timeouts.relay_client_idle_hard_secs.max(1));
        if !config.timeouts.relay_idle_policy_v2_enabled {
            return Self::disabled(frame_read_timeout);
        }

        let soft_idle = Duration::from_secs(config.timeouts.relay_client_idle_soft_secs.max(1));
        let hard_idle = Duration::from_secs(config.timeouts.relay_client_idle_hard_secs.max(1));
        let grace_after_downstream_activity = Duration::from_secs(
            config
                .timeouts
                .relay_idle_grace_after_downstream_activity_secs,
        );

        Self {
            enabled: true,
            soft_idle,
            hard_idle,
            grace_after_downstream_activity,
            legacy_frame_read_timeout: frame_read_timeout,
        }
    }

    pub(in crate::proxy::middle_relay) fn disabled(frame_read_timeout: Duration) -> Self {
        Self {
            enabled: false,
            soft_idle: frame_read_timeout,
            hard_idle: frame_read_timeout,
            grace_after_downstream_activity: Duration::ZERO,
            legacy_frame_read_timeout: frame_read_timeout,
        }
    }

    pub(super) fn apply_pressure_caps(&mut self, profile: ConntrackPressureProfile) {
        let pressure_soft_idle_cap = Duration::from_secs(profile.middle_soft_idle_cap_secs());
        let pressure_hard_idle_cap = Duration::from_secs(profile.middle_hard_idle_cap_secs());

        self.soft_idle = self.soft_idle.min(pressure_soft_idle_cap);
        self.hard_idle = self.hard_idle.min(pressure_hard_idle_cap);
        if self.soft_idle > self.hard_idle {
            self.soft_idle = self.hard_idle;
        }
        self.legacy_frame_read_timeout = self.legacy_frame_read_timeout.min(pressure_hard_idle_cap);
        if self.grace_after_downstream_activity > self.hard_idle {
            self.grace_after_downstream_activity = self.hard_idle;
        }
    }
}

#[derive(Clone, Copy)]
pub(in crate::proxy::middle_relay) struct RelayClientIdleState {
    pub(in crate::proxy::middle_relay) last_client_frame_at: Instant,
    pub(in crate::proxy::middle_relay) soft_idle_marked: bool,
    pub(in crate::proxy::middle_relay) tiny_frame_debt: u32,
}

impl RelayClientIdleState {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            last_client_frame_at: now,
            soft_idle_marked: false,
            tiny_frame_debt: 0,
        }
    }

    pub(super) fn on_client_frame(&mut self, now: Instant) {
        self.last_client_frame_at = now;
        self.soft_idle_marked = false;
    }

    pub(super) fn on_client_tiny_frame(&mut self, now: Instant) {
        self.last_client_frame_at = now;
    }
}

#[cfg(test)]
pub(crate) fn mark_relay_idle_candidate_for_testing(
    shared: &ProxySharedState,
    conn_id: u64,
) -> bool {
    mark_relay_idle_candidate_in(shared, conn_id)
}

#[cfg(test)]
pub(crate) fn oldest_relay_idle_candidate_for_testing(shared: &ProxySharedState) -> Option<u64> {
    let registry = &shared.middle_relay.relay_idle_registry;
    registry
        .ordered
        .lock()
        .iter()
        .next()
        .map(|(_, conn_id)| *conn_id)
}

#[cfg(test)]
pub(crate) fn clear_relay_idle_candidate_for_testing(shared: &ProxySharedState, conn_id: u64) {
    clear_relay_idle_candidate_in(shared, conn_id);
}

#[cfg(test)]
pub(crate) fn clear_relay_idle_pressure_state_for_testing_in_shared(shared: &ProxySharedState) {
    let registry = &shared.middle_relay.relay_idle_registry;
    registry.by_conn_id.clear();
    registry.ordered.lock().clear();
    registry.pressure_event_seq.store(0, Ordering::Relaxed);
    registry.pressure_consumed_seq.store(0, Ordering::Relaxed);
    shared
        .middle_relay
        .relay_idle_mark_seq
        .store(0, Ordering::Relaxed);
}

#[cfg(test)]
pub(crate) fn note_relay_pressure_event_for_testing(shared: &ProxySharedState) {
    note_relay_pressure_event_in(shared);
}

#[cfg(test)]
pub(crate) fn relay_pressure_event_seq_for_testing(shared: &ProxySharedState) -> u64 {
    relay_pressure_event_seq_in(shared)
}

#[cfg(test)]
pub(crate) fn relay_idle_mark_seq_for_testing(shared: &ProxySharedState) -> u64 {
    shared
        .middle_relay
        .relay_idle_mark_seq
        .load(Ordering::Relaxed)
}

#[cfg(test)]
pub(crate) fn maybe_evict_idle_candidate_on_pressure_for_testing(
    shared: &ProxySharedState,
    conn_id: u64,
    seen_pressure_seq: &mut u64,
    stats: &Stats,
) -> bool {
    maybe_evict_idle_candidate_on_pressure_in(shared, conn_id, seen_pressure_seq, stats)
}

#[cfg(test)]
pub(crate) fn set_relay_pressure_state_for_testing(
    shared: &ProxySharedState,
    pressure_event_seq: u64,
    pressure_consumed_seq: u64,
) {
    let registry = &shared.middle_relay.relay_idle_registry;
    registry
        .pressure_event_seq
        .store(pressure_event_seq, Ordering::Relaxed);
    registry
        .pressure_consumed_seq
        .store(pressure_consumed_seq, Ordering::Relaxed);
}
