use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{Notify, OwnedSemaphorePermit};

use super::{SessionCloseReason, SessionNegotiationPhase, WebSession};
use crate::config::WebLimitsConfig;
use crate::web::manager::{ManagerError, TokenHash};
use crate::web::telemetry::WebSessionLifecycleObservation;

const MAX_WINDOW: usize = 4;

/// Preserves one head body and handler capacity beyond the bounded down-poll plane.
pub(crate) fn conveyor_waiter_limit(limits: &WebLimitsConfig) -> usize {
    (limits.max_http_handlers / 4)
        .min(limits.max_body_readers.saturating_sub(1))
        .min((limits.max_body_bytes_global / limits.max_body_bytes.max(1)).saturating_sub(1))
}

/// HTTP-only failures distinguish expired exchanges from terminal protocol faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConveyorError {
    /// The bridge already confirmed this sequence, so its digest was retired.
    Stale,
    /// A negotiated mode cannot change within the same bearer session.
    Mode,
    /// Existing carrier failure semantics remain authoritative.
    Manager(ManagerError),
}

impl From<ManagerError> for ConveyorError {
    fn from(error: ManagerError) -> Self {
        Self::Manager(error)
    }
}

#[derive(Clone, Copy)]
struct Slot {
    sequence: u64,
    owner: u64,
    digest: Option<TokenHash>,
    committed: bool,
}

struct Channel {
    confirmed: u64,
    committed: u64,
    slots: [Option<Slot>; MAX_WINDOW],
    notify: Arc<Notify>,
}

impl Channel {
    fn new() -> Self {
        Self {
            confirmed: 0,
            committed: 0,
            slots: [None; MAX_WINDOW],
            notify: Arc::new(Notify::new()),
        }
    }
}

/// Session-owned replay metadata; bodies stay in their bounded HTTP handlers.
pub(super) struct ConveyorState {
    offered: u8,
    mode: Option<bool>,
    next_owner: u64,
    channels: HashMap<Option<u32>, Channel>,
}

impl Default for ConveyorState {
    fn default() -> Self {
        Self {
            offered: 1,
            mode: None,
            next_owner: 1,
            channels: HashMap::new(),
        }
    }
}

impl ConveyorState {
    /// Publishes commit history under the same lock as frame application.
    pub(super) fn commit(&mut self, lane: Option<u32>, sequence: u64, digest: TokenHash) {
        if self.mode != Some(true) {
            return;
        }
        if let Some(channel) = self.channels.get_mut(&lane) {
            let index = sequence as usize % MAX_WINDOW;
            channel.slots[index] = Some(Slot {
                sequence,
                digest: Some(digest),
                committed: true,
                owner: 0,
            });
            channel.committed = sequence;
        }
    }

    /// Detaches retired-lane ordering state for notification after unlocking.
    pub(super) fn remove(&mut self, lane: Option<u32>) -> Option<Arc<Notify>> {
        self.channels.remove(&lane).map(|channel| channel.notify)
    }

    /// Detaches all waiter notifications for the session's deferred close effects.
    pub(super) fn clear(&mut self) -> Vec<Arc<Notify>> {
        self.channels
            .drain()
            .map(|(_, channel)| channel.notify)
            .collect()
    }
}

/// An exact request owner; its body and ordinary body permit stay in the HTTP handler.
pub(crate) struct ConveyorClaim {
    session: Arc<WebSession>,
    lane: Option<u32>,
    sequence: u64,
    owner: u64,
    notify: Arc<Notify>,
    _waiter: Option<OwnedSemaphorePermit>,
}

impl WebSession {
    /// Freezes the offer before the newly created session is published by its manager.
    pub(crate) fn configure_conveyor(&self, requested: u8) {
        let mut state = self.state.lock();
        if state.conveyor.mode.is_none() {
            state.conveyor.offered = if conveyor_waiter_limit(&self.limits) == 0 {
                1
            } else {
                requested.clamp(1, MAX_WINDOW as u8)
            };
        }
    }

    /// Returns the immutable chain ceiling even across a WebSocket candidate.
    pub(crate) fn conveyor_offer(&self) -> u8 {
        self.state.lock().conveyor.offered
    }

    /// Returns the HTTP window without changing carrier capability negotiation.
    pub(crate) fn up_window(&self) -> u8 {
        if self.carrier().uses_websocket() {
            1
        } else {
            self.conveyor_offer()
        }
    }

    /// Claims an HTTP sequence before allocating a body, or locks in legacy serialization.
    pub(crate) fn claim_conveyor(
        self: &Arc<Self>,
        lane: Option<u32>,
        sequence: u64,
        confirmed: Option<u64>,
    ) -> Result<Option<ConveyorClaim>, ConveyorError> {
        let mut state = self.state.lock();
        self.ensure_carrier_active_locked(&state)?;
        if state.closed {
            return Err(ManagerError::Closed.into());
        }
        let enabled = confirmed.is_some();
        if (enabled && state.conveyor.offered <= 1)
            || state.conveyor.mode.is_some_and(|mode| mode != enabled)
        {
            return Err(ConveyorError::Mode);
        }
        if !enabled {
            state.conveyor.mode = Some(false);
            return Ok(None);
        }
        let confirmed = confirmed.unwrap_or(0);
        let window = u64::from(state.conveyor.offered);
        let existing = state.conveyor.channels.get(&lane);
        // Lane eviction retires its bounded digest history, not the parent session.
        if existing.is_none() && lane.is_some() && confirmed > 0 {
            return Err(ConveyorError::Stale);
        }
        let committed = existing.map_or(0, |channel| channel.committed);
        let floor = existing
            .map_or(0, |channel| channel.confirmed)
            .max(confirmed);
        if confirmed > committed || sequence == 0 || sequence > floor.saturating_add(window) {
            drop(state);
            self.close(SessionCloseReason::Protocol);
            return Err(ManagerError::Protocol.into());
        }
        if sequence <= floor {
            return Err(ConveyorError::Stale);
        }
        let index = sequence as usize % MAX_WINDOW;
        if existing
            .and_then(|channel| channel.slots[index])
            .is_some_and(|slot| slot.sequence == sequence && !slot.committed)
        {
            return Err(ManagerError::Concurrent.into());
        }
        if existing.is_none() {
            let limit = self
                .profile
                .shared
                .max_streams_per_session
                .saturating_add(self.limits.max_tombstones_per_session)
                .saturating_add(1);
            let provisional = state
                .conveyor
                .channels
                .keys()
                .filter(|id| id.is_some_and(|id| !state.carrier_lanes.contains_key(&id)))
                .count();
            if state.conveyor.channels.len() >= limit
                || (lane.is_some_and(|id| !state.carrier_lanes.contains_key(&id))
                    && state.carrier_lanes.len().saturating_add(provisional) >= limit)
            {
                return Err(ManagerError::Limit.into());
            }
            if lane.is_some_and(|id| {
                state.closed_streams.contains(&id) && !state.carrier_lanes.contains_key(&id)
            }) {
                return Err(ConveyorError::Stale);
            }
        }
        let owner = state.conveyor.next_owner;
        let next_owner = owner.checked_add(1).ok_or(ManagerError::Limit)?;
        // All fallible validation precedes the permit so no early return drops it under state.
        let waiter = if sequence > committed.saturating_add(1) {
            Some(
                self.manager
                    .upgrade()
                    .ok_or(ManagerError::Closed)?
                    .try_conveyor_waiter()
                    .ok_or(ManagerError::Backpressure)?,
            )
        } else {
            None
        };
        state.conveyor.mode = Some(true);
        state.conveyor.next_owner = next_owner;
        let channel = state
            .conveyor
            .channels
            .entry(lane)
            .or_insert_with(Channel::new);
        channel.confirmed = floor;
        for slot in &mut channel.slots {
            if slot.is_some_and(|slot| slot.sequence <= floor) {
                *slot = None;
            }
        }
        let replay = sequence <= channel.committed;
        if !replay {
            channel.slots[index] = Some(Slot {
                sequence,
                owner,
                digest: None,
                committed: false,
            });
        }
        Ok(Some(ConveyorClaim {
            session: Arc::clone(self),
            lane,
            sequence,
            owner: if replay { 0 } else { owner },
            notify: Arc::clone(&channel.notify),
            _waiter: waiter,
        }))
    }
}

impl ConveyorClaim {
    /// Revalidates exact ownership under the frame-application transaction's lock.
    pub(super) fn validate_locked(
        &self,
        state: &super::SessionState,
        digest: &TokenHash,
    ) -> Result<(), ManagerError> {
        let channel = state
            .conveyor
            .channels
            .get(&self.lane)
            .filter(|channel| Arc::ptr_eq(&channel.notify, &self.notify))
            .ok_or(ManagerError::Closed)?;
        let slot = channel.slots[self.sequence as usize % MAX_WINDOW]
            .filter(|slot| {
                slot.sequence == self.sequence
                    && slot.owner == self.owner
                    && !slot.committed
                    && slot
                        .digest
                        .is_some_and(|value| bool::from(value.ct_eq(digest)))
            })
            .ok_or(ManagerError::Closed)?;
        if channel.committed.checked_add(1) != Some(slot.sequence) {
            return Err(ManagerError::Concurrent);
        }
        Ok(())
    }

    /// Applies only the next sequence; duplicates verify the retained digest without replaying frames.
    pub(crate) async fn process(&self, body: &[u8]) -> Result<u64, ConveyorError> {
        let digest: TokenHash = Sha256::digest(body).into();
        let operation = async {
            loop {
                let notified = self.notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let ready = {
                    let mut state = self.session.state.lock();
                    self.session.ensure_carrier_active_locked(&state)?;
                    if state.closed {
                        return Err(ManagerError::Closed.into());
                    }
                    let Some(channel) = state
                        .conveyor
                        .channels
                        .get_mut(&self.lane)
                        .filter(|channel| Arc::ptr_eq(&channel.notify, &self.notify))
                    else {
                        return Err(ConveyorError::Stale);
                    };
                    if self.sequence <= channel.confirmed {
                        return Err(ConveyorError::Stale);
                    }
                    let Some(slot) = &mut channel.slots[self.sequence as usize % MAX_WINDOW] else {
                        return Err(ConveyorError::Stale);
                    };
                    if slot.sequence != self.sequence
                        || (!slot.committed && slot.owner != self.owner)
                    {
                        return Err(ConveyorError::Stale);
                    }
                    if slot
                        .digest
                        .is_some_and(|previous| !bool::from(previous.ct_eq(&digest)))
                    {
                        drop(state);
                        self.session.close(SessionCloseReason::Protocol);
                        return Err(ManagerError::Protocol.into());
                    }
                    slot.digest = Some(digest);
                    if slot.committed {
                        self.session.touch_peer_locked(
                            &mut state,
                            Instant::now(),
                            WebSessionLifecycleObservation::HttpActivityAfterGap,
                        );
                        if self.session.automatic_carrier
                            && state.negotiation_phase != SessionNegotiationPhase::Committed
                        {
                            return Err(ManagerError::Backpressure.into());
                        }
                        return Ok(self.sequence);
                    }
                    channel.committed.checked_add(1) == Some(self.sequence)
                        && (self.lane.is_some()
                            || !self
                                .session
                                .up_active
                                .load(std::sync::atomic::Ordering::Acquire))
                };
                if ready {
                    let result = match self.lane {
                        Some(lane) => self.session.process_up_lane_inner(
                            lane,
                            self.sequence,
                            body,
                            Some((self, digest)),
                        ),
                        None => self
                            .session
                            .process_claimed_up(self.sequence, body, self, digest),
                    };
                    self.notify.notify_waiters();
                    return result.map_err(ConveyorError::from);
                }
                tokio::select! {
                    _ = self.session.cancel.cancelled() => return Err(ManagerError::Closed.into()),
                    _ = notified => {}
                }
            }
        };
        tokio::time::timeout(
            Duration::from_secs(self.session.timeouts.body_secs),
            operation,
        )
        .await
        .map_err(|_| ConveyorError::Manager(ManagerError::Backpressure))?
    }
}

impl Drop for ConveyorClaim {
    fn drop(&mut self) {
        if self.owner == 0 {
            return;
        }
        let mut state = self.session.state.lock();
        if let Some(channel) = state
            .conveyor
            .channels
            .get_mut(&self.lane)
            .filter(|channel| Arc::ptr_eq(&channel.notify, &self.notify))
        {
            let slot = &mut channel.slots[self.sequence as usize % MAX_WINDOW];
            if slot.is_some_and(|slot| !slot.committed && slot.owner == self.owner) {
                *slot = None;
            }
            if channel.committed == 0 && channel.slots.iter().all(Option::is_none) {
                state.conveyor.channels.remove(&self.lane);
            }
        }
        drop(state);
        self.notify.notify_waiters();
    }
}

#[cfg(test)]
#[path = "conveyor/tests.rs"]
mod tests;
