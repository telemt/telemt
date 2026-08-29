use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;

use super::{ManagerError, ProfileKey, WebProcessRuntime, WebSocketBudgetLease};
use crate::web::telemetry::WebRejectionReason;

// Deterministic victim ordering remains isolated from registry mutation.
mod policy;

/// One process-owned WebSocket carrier class used for eviction priority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum WebSocketKind {
    /// One connection multiplexes every logical stream in a session.
    Multiplex,
    /// One connection owns exactly one logical stream lane.
    Lane(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct WebSocketClaimKey {
    session_hash: super::TokenHash,
    kind: WebSocketKind,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WebSocketPhase {
    Claimed,
    Upgraded,
    Active,
    Closing,
}

pub(super) struct WebSocketEntry {
    id: u64,
    owner: ProfileKey,
    session_id: u64,
    claim: WebSocketClaimKey,
    client_ip: IpAddr,
    kind: WebSocketKind,
    liveness_interval_ms: u64,
    created_tick: u64,
    last_peer_tick: AtomicU64,
    last_progress_tick: AtomicU64,
    phase: AtomicU8,
    closing: AtomicBool,
    cancel: CancellationToken,
    released: CancellationToken,
}

#[derive(Default)]
pub(super) struct WebSocketRegistry {
    entries: HashMap<u64, Arc<WebSocketEntry>>,
    claims: HashMap<WebSocketClaimKey, u64>,
    evictions_in_flight: usize,
    closed: bool,
}

/// Point-in-time WebSocket registry counters.
#[derive(Clone, Copy)]
pub(super) struct WebSocketRegistryStatus {
    pub(super) entries: usize,
    pub(super) claims: usize,
    pub(super) evictions_in_flight: usize,
    pub(super) closed: bool,
}

impl WebSocketRegistry {
    pub(super) fn status(&self) -> WebSocketRegistryStatus {
        WebSocketRegistryStatus {
            entries: self.entries.len(),
            claims: self.claims.len(),
            evictions_in_flight: self.evictions_in_flight,
            closed: self.closed,
        }
    }
}

/// Exact process-owned admission retained through the upgraded socket lifetime.
pub(crate) struct WebSocketConnection {
    runtime: std::sync::Weak<WebProcessRuntime>,
    entry: Arc<WebSocketEntry>,
    slot: Option<OwnedSemaphorePermit>,
    base_budget: Option<WebSocketBudgetLease>,
}

impl WebSocketConnection {
    /// Returns the cancellation signal used by shutdown and pressure eviction.
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.entry.cancel.clone()
    }

    /// Returns the process-unique connection identifier used only for debugging.
    pub(crate) fn id(&self) -> u64 {
        self.entry.id
    }

    /// Returns the creation-time transport liveness interval.
    pub(crate) fn liveness_interval(&self) -> Duration {
        Duration::from_millis(self.entry.liveness_interval_ms)
    }

    /// Marks successful ownership transfer from HTTP to the WebSocket codec.
    pub(crate) fn mark_opened(&self) -> bool {
        if self.entry.closing.load(Ordering::Acquire)
            || self
                .entry
                .phase
                .compare_exchange(
                    WebSocketPhase::Claimed as u8,
                    WebSocketPhase::Upgraded as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            || self.entry.closing.load(Ordering::Acquire)
        {
            return false;
        }
        self.mark_progress();
        true
    }

    /// Marks the first validated carrier binary message as active progress.
    pub(crate) fn mark_active(&self) -> bool {
        if self.entry.closing.load(Ordering::Acquire)
            || self
                .entry
                .phase
                .compare_exchange(
                    WebSocketPhase::Upgraded as u8,
                    WebSocketPhase::Active as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            || self.entry.closing.load(Ordering::Acquire)
        {
            return false;
        }
        self.mark_peer_activity();
        true
    }

    /// Refreshes the peer-liveness deadline after any received WebSocket message.
    pub(crate) fn mark_peer_activity(&self) {
        if let Some(runtime) = self.runtime.upgrade() {
            let now = runtime.websocket_tick();
            self.entry.last_peer_tick.store(now, Ordering::Release);
            self.entry.last_progress_tick.store(now, Ordering::Release);
        }
    }

    /// Refreshes least-recently-progressed ordering after a committed write.
    pub(crate) fn mark_progress(&self) {
        if let Some(runtime) = self.runtime.upgrade() {
            self.entry
                .last_progress_tick
                .store(runtime.websocket_tick(), Ordering::Release);
        }
    }
}

impl Drop for WebSocketConnection {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.upgrade() {
            let mut registry = runtime.websockets.lock();
            registry.entries.remove(&self.entry.id);
            if registry.claims.get(&self.entry.claim) == Some(&self.entry.id) {
                registry.claims.remove(&self.entry.claim);
            }
            if self.entry.closing.load(Ordering::Acquire) {
                if registry.evictions_in_flight == 0 {
                    registry.closed = true;
                } else {
                    registry.evictions_in_flight -= 1;
                }
            }
            drop(registry);
            drop(self.base_budget.take());
            drop(self.slot.take());
            self.entry.released.cancel();
            runtime.websocket_notify.notify_waiters();
            runtime.notify_operator_work_changed();
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn admit(
    runtime: &Arc<WebProcessRuntime>,
    owner: ProfileKey,
    session_id: u64,
    session_hash: super::TokenHash,
    client_ip: IpAddr,
    kind: WebSocketKind,
    base_bytes: usize,
    liveness_interval: Duration,
    eviction_timeout: Duration,
    parent_cancellation: CancellationToken,
) -> Result<WebSocketConnection, ManagerError> {
    if parent_cancellation.is_cancelled() {
        return Err(ManagerError::Closed);
    }
    let liveness_interval_ms = liveness_interval.as_millis().min(u128::from(u64::MAX)) as u64;
    let capacity_reason = match try_admit(
        runtime,
        owner,
        session_id,
        session_hash,
        client_ip,
        kind,
        base_bytes,
        liveness_interval_ms,
        &parent_cancellation,
    ) {
        Ok(connection) => return Ok(connection),
        Err(TryAdmitError::Conflict) => {
            runtime
                .telemetry()
                .record_rejection(WebRejectionReason::Concurrent);
            return Err(ManagerError::Concurrent);
        }
        Err(TryAdmitError::Closed) => {
            runtime
                .telemetry()
                .record_rejection(WebRejectionReason::RuntimeClosed);
            return Err(ManagerError::Closed);
        }
        Err(TryAdmitError::Capacity(reason)) => reason,
    };
    let Some(victim) = select_victim(runtime, owner, session_id, client_ip, None, true) else {
        runtime.record_limit_hit();
        runtime.telemetry().record_rejection(capacity_reason);
        return Err(ManagerError::Limit);
    };
    let released = victim.released.cancelled();
    victim.cancel.cancel();
    tokio::select! {
        _ = parent_cancellation.cancelled() => return Err(ManagerError::Closed),
        _ = tokio::time::timeout(eviction_timeout, released) => {}
    }
    if parent_cancellation.is_cancelled() {
        return Err(ManagerError::Closed);
    }
    match try_admit(
        runtime,
        owner,
        session_id,
        session_hash,
        client_ip,
        kind,
        base_bytes,
        liveness_interval_ms,
        &parent_cancellation,
    ) {
        Ok(connection) => Ok(connection),
        Err(TryAdmitError::Conflict) => {
            runtime
                .telemetry()
                .record_rejection(WebRejectionReason::Concurrent);
            Err(ManagerError::Concurrent)
        }
        Err(TryAdmitError::Closed) => {
            runtime
                .telemetry()
                .record_rejection(WebRejectionReason::RuntimeClosed);
            Err(ManagerError::Closed)
        }
        Err(TryAdmitError::Capacity(reason)) => {
            runtime.record_limit_hit();
            runtime.telemetry().record_rejection(reason);
            Err(ManagerError::Limit)
        }
    }
}

enum TryAdmitError {
    Capacity(WebRejectionReason),
    Conflict,
    Closed,
}

// Admission inputs stay explicit so quota and cancellation ownership cannot drift.
#[allow(clippy::too_many_arguments)]
fn try_admit(
    runtime: &Arc<WebProcessRuntime>,
    owner: ProfileKey,
    session_id: u64,
    session_hash: super::TokenHash,
    client_ip: IpAddr,
    kind: WebSocketKind,
    base_bytes: usize,
    liveness_interval_ms: u64,
    parent_cancellation: &CancellationToken,
) -> Result<WebSocketConnection, TryAdmitError> {
    if parent_cancellation.is_cancelled() {
        return Err(TryAdmitError::Closed);
    }
    let claim = WebSocketClaimKey { session_hash, kind };
    {
        let registry = runtime.websockets.lock();
        if registry.closed {
            return Err(TryAdmitError::Closed);
        }
        if registry.claims.contains_key(&claim) {
            return Err(TryAdmitError::Conflict);
        }
    }
    let slot = Arc::clone(&runtime.websocket_connections)
        .try_acquire_owned()
        .map_err(|_| TryAdmitError::Capacity(WebRejectionReason::WebSocketConnectionCapacity))?;
    let base_budget =
        runtime
            .try_websocket_base_budget(owner, base_bytes)
            .ok_or(TryAdmitError::Capacity(
                WebRejectionReason::WebSocketBytesCapacity,
            ))?;
    if parent_cancellation.is_cancelled() {
        return Err(TryAdmitError::Closed);
    }
    let id = runtime
        .websocket_next_id
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .map_err(|_| TryAdmitError::Capacity(WebRejectionReason::WebSocketConnectionCapacity))?;
    let now = runtime.websocket_tick();
    let entry = Arc::new(WebSocketEntry {
        id,
        owner,
        session_id,
        claim,
        client_ip,
        kind,
        liveness_interval_ms,
        created_tick: now,
        last_peer_tick: AtomicU64::new(now),
        last_progress_tick: AtomicU64::new(now),
        phase: AtomicU8::new(WebSocketPhase::Claimed as u8),
        closing: AtomicBool::new(false),
        cancel: parent_cancellation.child_token(),
        released: CancellationToken::new(),
    });
    let mut registry = runtime.websockets.lock();
    if registry.closed || parent_cancellation.is_cancelled() {
        return Err(TryAdmitError::Closed);
    }
    if registry.claims.contains_key(&claim) {
        return Err(TryAdmitError::Conflict);
    }
    registry.claims.insert(claim, id);
    registry.entries.insert(id, Arc::clone(&entry));
    drop(registry);
    Ok(WebSocketConnection {
        runtime: Arc::downgrade(runtime),
        entry,
        slot: Some(slot),
        base_budget: Some(base_budget),
    })
}

impl WebProcessRuntime {
    pub(super) fn websocket_tick(&self) -> u64 {
        self.websocket_clock.elapsed().as_millis() as u64
    }

    pub(super) fn cleanup_websockets(&self) {
        let now = self.websocket_tick();
        let mut victims = claim_stale_victims(self, now);
        if victims.is_empty() && self.data_budget.take_pressure() {
            if let Some(victim) = select_pressure_victim(self, now, true) {
                victims.push(victim);
            } else {
                self.data_budget.restore_pressure();
            }
        }
        for victim in victims {
            victim.cancel.cancel();
        }
    }

    pub(super) fn close_websockets(&self) {
        let victims = {
            let mut registry = self.websockets.lock();
            registry.closed = true;
            registry.entries.values().cloned().collect::<Vec<_>>()
        };
        for victim in victims {
            victim.cancel.cancel();
        }
    }
}

fn select_victim(
    runtime: &WebProcessRuntime,
    owner: ProfileKey,
    session_id: u64,
    client_ip: IpAddr,
    excluded_id: Option<u64>,
    claim: bool,
) -> Option<Arc<WebSocketEntry>> {
    let fairness = runtime.data_budget.fairness_snapshot(Some(owner));
    let now = runtime.websocket_tick();
    let mut registry = runtime.websockets.lock();
    if claim && registry.evictions_in_flight >= runtime.limits.max_websocket_evictions_in_flight {
        return None;
    }
    let selected = registry
        .entries
        .values()
        .filter(|entry| Some(entry.id) != excluded_id)
        .filter(|entry| !entry.closing.load(Ordering::Acquire))
        .filter_map(|entry| {
            policy::admission_key(entry, now, owner, session_id, client_ip, &fairness)
                .map(|key| (key, Arc::clone(entry)))
        })
        .min_by_key(|(key, _)| *key)
        .map(|(_, entry)| entry)?;
    if claim && !claim_entry(&mut registry, &selected, runtime) {
        return None;
    }
    Some(selected)
}

fn select_pressure_victim(
    runtime: &WebProcessRuntime,
    now: u64,
    claim: bool,
) -> Option<Arc<WebSocketEntry>> {
    let fairness = runtime.data_budget.fairness_snapshot(None);
    let mut registry = runtime.websockets.lock();
    if claim && registry.evictions_in_flight >= runtime.limits.max_websocket_evictions_in_flight {
        return None;
    }
    let selected = registry
        .entries
        .values()
        .filter(|entry| !entry.closing.load(Ordering::Acquire))
        .map(|entry| {
            (
                policy::pressure_key(entry, now, &fairness),
                Arc::clone(entry),
            )
        })
        .min_by_key(|(key, _)| *key)
        .map(|(_, entry)| entry)?;
    if claim && !claim_entry(&mut registry, &selected, runtime) {
        return None;
    }
    Some(selected)
}

fn claim_stale_victims(runtime: &WebProcessRuntime, now: u64) -> Vec<Arc<WebSocketEntry>> {
    let mut registry = runtime.websockets.lock();
    let available = runtime
        .limits
        .max_websocket_evictions_in_flight
        .saturating_sub(registry.evictions_in_flight);
    let mut candidates = registry
        .entries
        .values()
        .filter(|entry| !entry.closing.load(Ordering::Acquire))
        .filter(|entry| policy::victim_class(entry, now) == policy::VictimClass::Dead)
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_unstable_by_key(|entry| {
        (
            entry.last_peer_tick.load(Ordering::Acquire),
            entry.created_tick,
            entry.id,
        )
    });
    candidates
        .into_iter()
        .take(available)
        .filter(|entry| claim_entry(&mut registry, entry, runtime))
        .collect()
}

fn claim_entry(
    registry: &mut WebSocketRegistry,
    entry: &Arc<WebSocketEntry>,
    runtime: &WebProcessRuntime,
) -> bool {
    if registry.evictions_in_flight >= runtime.limits.max_websocket_evictions_in_flight
        || entry
            .closing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return false;
    }
    entry
        .phase
        .store(WebSocketPhase::Closing as u8, Ordering::Release);
    registry.evictions_in_flight += 1;
    true
}

fn dead_after(entry: &WebSocketEntry) -> u64 {
    entry.liveness_interval_ms.saturating_mul(2)
}

#[cfg(test)]
mod tests;
