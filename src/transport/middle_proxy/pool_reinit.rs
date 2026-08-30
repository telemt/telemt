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

// Reinitialization admission, generation state, and coverage checks.
mod coordination;
// Generation warmup and stale-writer reconciliation.
mod reconcile;

#[cfg(test)]
mod tests;
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
    reinit
        .pending_hardswap_generation
        .store(snapshot.pending_hardswap_generation, Ordering::Release);
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
