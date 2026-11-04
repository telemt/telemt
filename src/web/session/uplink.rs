use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use bytes::Bytes;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::backend::StreamCompletion;
use super::{
    DeferredSessionEffects, InboundChunk, PendingClass, QUEUE_ITEM_COST, SessionCloseReason,
    SessionState, StreamIdentity, StreamState, WebSession, inbound_queue_cost,
};
use crate::web::frame::{self, Frame, FrameType};
use crate::web::manager::{ManagerError, TokenHash};
use crate::web::telemetry::WebSessionLifecycleObservation;

#[derive(Clone, Copy, Default)]
pub(super) struct AppliedProgress {
    pub(super) accepted_open: bool,
    pub(super) accepted_data: bool,
}

impl AppliedProgress {
    pub(super) fn any(self) -> bool {
        self.accepted_open || self.accepted_data
    }
}

impl WebSession {
    /// Applies one exactly-once uplink batch.
    pub(crate) fn process_up(
        self: &Arc<Self>,
        sequence: u64,
        body: &[u8],
    ) -> Result<u64, ManagerError> {
        let (acknowledged, progressed) = self.process_up_inner(
            sequence,
            body,
            WebSessionLifecycleObservation::HttpActivityAfterGap,
            None,
        )?;
        if self.automatic_carrier && !progressed && !self.is_carrier_committed() {
            return Err(ManagerError::Backpressure);
        }
        Ok(acknowledged)
    }

    /// Applies one WebSocket uplink batch and reports actual carrier progress.
    pub(crate) fn process_websocket_multiplex(
        self: &Arc<Self>,
        sequence: u64,
        body: &[u8],
    ) -> Result<bool, ManagerError> {
        self.process_up_inner(
            sequence,
            body,
            WebSessionLifecycleObservation::WebSocketActivityAfterGap,
            None,
        )
        .map(|(_, progress)| progress)
    }

    /// Applies an admitted conveyor head without weakening the carrier commit gate.
    pub(super) fn process_claimed_up(
        self: &Arc<Self>,
        sequence: u64,
        body: &[u8],
        claim: &super::conveyor::ConveyorClaim,
        digest: TokenHash,
    ) -> Result<u64, ManagerError> {
        let (acknowledged, progressed) = self.process_up_inner(
            sequence,
            body,
            WebSessionLifecycleObservation::HttpActivityAfterGap,
            Some((claim, digest)),
        )?;
        if self.automatic_carrier && !progressed && !self.is_carrier_committed() {
            return Err(ManagerError::Backpressure);
        }
        Ok(acknowledged)
    }

    fn process_up_inner(
        self: &Arc<Self>,
        sequence: u64,
        body: &[u8],
        observation: WebSessionLifecycleObservation,
        claim: Option<(&super::conveyor::ConveyorClaim, TokenHash)>,
    ) -> Result<(u64, bool), ManagerError> {
        if !self.carrier().is_multiplexed() {
            return Err(ManagerError::Protocol);
        }
        if self.close_if_cancelled() {
            return Err(ManagerError::Closed);
        }
        if self
            .up_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ManagerError::Concurrent);
        }
        let _uplink = UplinkGuard(&self.up_active);
        let frames = match frame::parse_all(body, &self.limits) {
            Ok(frames) => frames,
            Err(_) => {
                self.close(SessionCloseReason::Protocol);
                return Err(ManagerError::Protocol);
            }
        };
        if frames
            .iter()
            .copied()
            .any(|value| frame::validate_client_shape(value).is_err())
        {
            self.close(SessionCloseReason::Protocol);
            return Err(ManagerError::Protocol);
        }
        let digest: TokenHash =
            claim.map_or_else(|| Sha256::digest(body).into(), |(_, digest)| digest);
        let mut opened = Vec::new();
        let mut committed = false;
        let mut healthy = None;
        let mut effects = DeferredSessionEffects::new();
        let result = {
            let mut state = self.state.lock();
            if state.closed {
                return Err(ManagerError::Closed);
            }
            self.ensure_carrier_active_locked(&state)?;
            if let Some((claim, _)) = claim {
                claim.validate_locked(&state, &digest)?;
            }
            if sequence == state.last_up_sequence && sequence != 0 {
                return if bool::from(state.last_up_digest.ct_eq(&digest)) {
                    self.touch_peer_locked(&mut state, Instant::now(), observation);
                    Ok((sequence, false))
                } else {
                    drop(state);
                    self.close(SessionCloseReason::Protocol);
                    Err(ManagerError::Protocol)
                };
            }
            if sequence == 0 || sequence != state.last_up_sequence.saturating_add(1) {
                drop(state);
                self.close(SessionCloseReason::Protocol);
                return Err(ManagerError::Protocol);
            }
            if !validate_batch(&state, &frames) {
                drop(state);
                self.close(SessionCloseReason::Protocol);
                return Err(ManagerError::Protocol);
            }
            self.touch_peer_locked(&mut state, Instant::now(), observation);
            let (reserve_bytes, reserve_items) = inbound_reservation(&state, &frames);
            if !self.reserve_locked(
                &mut state,
                reserve_bytes,
                reserve_items,
                PendingClass::Uplink,
            ) {
                return Err(ManagerError::Backpressure);
            }
            let mut unused_bytes = reserve_bytes;
            let mut unused_items = reserve_items;
            let mut progress = AppliedProgress::default();
            let applied = self.apply_batch_locked(
                &mut state,
                &frames,
                &mut effects,
                &mut opened,
                &mut None,
                &mut unused_bytes,
                &mut unused_items,
                &mut progress,
            );
            self.release_locked(&mut state, &mut effects, unused_bytes, unused_items, false);
            if !applied {
                Err(ManagerError::Closed)
            } else {
                state.last_up_sequence = sequence;
                state.last_up_digest = digest;
                state.conveyor.commit(None, sequence, digest);
                (committed, healthy) = self.record_uplink_progress_locked(&mut state, progress);
                Ok((sequence, progress.any()))
            }
        };
        effects.finish();
        if matches!(result, Err(ManagerError::Backpressure)) {
            return result;
        }
        if matches!(result, Err(ManagerError::Closed)) && self.close_if_cancelled() {
            drop(opened);
            return result;
        }
        if result.is_err() {
            self.close(SessionCloseReason::Protocol);
            drop(opened);
            return result;
        }
        if committed {
            self.finish_carrier_commit();
        }
        if let Some(claim) = healthy {
            self.finish_carrier_health(claim);
        }
        for completion in opened {
            self.spawn_stream(completion, false);
        }
        if let Some(manager) = self.manager.upgrade() {
            manager.record_up(body.len());
        }
        result
    }

    // Batch application keeps every transactional accumulator explicit.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn apply_batch_locked(
        self: &Arc<Self>,
        state: &mut SessionState,
        frames: &[Frame<'_>],
        effects: &mut DeferredSessionEffects,
        opened: &mut Vec<StreamCompletion>,
        reserved_open: &mut Option<(u32, u16)>,
        unused_bytes: &mut usize,
        unused_items: &mut usize,
        progress: &mut AppliedProgress,
    ) -> bool {
        for value in frames {
            if value.stream_id == 0 {
                continue;
            }
            let was_closed = state.closed_streams.contains(&value.stream_id)
                || state.closing_streams.contains_key(&value.stream_id);
            match value.frame_type {
                FrameType::Open => {
                    let Some(stream) = next_stream_identity(state, value.stream_id) else {
                        return false;
                    };
                    let peer_port = match reserved_open.take() {
                        Some((reserved_stream_id, peer_port))
                            if reserved_stream_id == value.stream_id =>
                        {
                            peer_port
                        }
                        Some(reserved) => {
                            *reserved_open = Some(reserved);
                            return false;
                        }
                        None => {
                            let Some(peer_port) = self.reserve_stream_locked(state, effects) else {
                                self.remember_closed_locked(state, effects, value.stream_id);
                                if !self.queue_control_locked(
                                    state,
                                    effects,
                                    FrameType::Close,
                                    value.stream_id,
                                    &[],
                                ) {
                                    return false;
                                }
                                continue;
                            };
                            peer_port
                        }
                    };
                    if let Some(previous) = state.streams.insert(
                        value.stream_id,
                        StreamState {
                            instance: stream.instance,
                            inbound: VecDeque::new(),
                            receive_window: frame::INITIAL_STREAM_WINDOW,
                            send_credit: u64::from(frame::INITIAL_STREAM_WINDOW),
                            read_waker: None,
                            write_waker: None,
                        },
                    ) {
                        effects.retain_stream(previous);
                    }
                    progress.accepted_open = true;
                    opened.push(self.own_stream_task(stream, peer_port));
                }
                FrameType::Data if !was_closed => {
                    let Some(stream) = state.streams.get_mut(&value.stream_id) else {
                        return false;
                    };
                    stream.receive_window -= value.payload.len() as u32;
                    stream.inbound.push_back(InboundChunk {
                        bytes: Bytes::copy_from_slice(value.payload),
                        offset: 0,
                    });
                    progress.accepted_data = true;
                    *unused_bytes =
                        unused_bytes.saturating_sub(value.payload.len() + QUEUE_ITEM_COST);
                    *unused_items = unused_items.saturating_sub(1);
                    if let Some(waker) = stream.read_waker.take() {
                        effects.wake(waker);
                    }
                }
                FrameType::Window if !was_closed => {
                    let Some(stream) = state.streams.get_mut(&value.stream_id) else {
                        return false;
                    };
                    let amount = frame::window_amount(value.payload).unwrap_or(0);
                    stream.send_credit = stream
                        .send_credit
                        .saturating_add(u64::from(amount))
                        .min(u64::from(u32::MAX));
                    if let Some(waker) = stream.write_waker.take() {
                        effects.wake(waker);
                    }
                }
                FrameType::Close if !was_closed => {
                    let Some(stream) = state.streams.remove(&value.stream_id) else {
                        return false;
                    };
                    state
                        .closing_streams
                        .insert(value.stream_id, stream.instance);
                    let (bytes, items) = inbound_queue_cost(&stream.inbound);
                    self.release_locked(state, effects, bytes, items, false);
                    self.remember_closed_locked(state, effects, value.stream_id);
                    if let Some(waker) = stream.read_waker {
                        effects.wake(waker);
                    }
                    if let Some(waker) = stream.write_waker {
                        effects.wake(waker);
                    }
                }
                FrameType::Data | FrameType::Window | FrameType::Close => {}
                _ => return false,
            }
        }
        true
    }

    fn reserve_stream_locked(
        &self,
        state: &mut SessionState,
        effects: &mut DeferredSessionEffects,
    ) -> Option<u16> {
        let manager = self.manager.upgrade()?;
        if state.active_peer_ports.len() >= self.profile.shared.max_streams_per_session {
            manager.record_stream_rejected_reason(
                crate::web::telemetry::WebRejectionReason::StreamSessionCapacity,
            );
            return None;
        }
        let (peer_port, notify) = manager.try_acquire_stream_quiet(
            self.profile_key,
            self.profile.shared.max_streams,
            self.client_ip,
            self.profile.shared.public_addr,
        );
        if let Some(notify) = notify {
            effects.notify(notify);
        }
        let peer_port = peer_port.ok()?;
        if state.active_peer_ports.insert(peer_port) {
            return Some(peer_port);
        }
        if let Some(notify) = manager.release_stream_quiet(
            self.profile_key,
            self.client_ip,
            self.profile.shared.public_addr,
            peer_port,
        ) {
            effects.notify(notify);
        }
        None
    }
}

fn next_stream_identity(state: &mut SessionState, stream_id: u32) -> Option<StreamIdentity> {
    let instance = state.next_stream_instance;
    state.next_stream_instance = instance.checked_add(1)?;
    Some(StreamIdentity {
        id: stream_id,
        instance,
    })
}

struct UplinkGuard<'a>(&'a AtomicBool);

impl Drop for UplinkGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub(super) fn validate_batch(state: &SessionState, frames: &[Frame<'_>]) -> bool {
    let mut live = state
        .streams
        .iter()
        .map(|(id, stream)| (*id, (stream.receive_window, stream.send_credit)))
        .collect::<HashMap<_, _>>();
    let mut closed = HashSet::new();
    for value in frames {
        if value.stream_id == 0 {
            if value.frame_type != FrameType::Pong {
                return false;
            }
            continue;
        }
        let was_closed = state.closed_streams.contains(&value.stream_id)
            || state.closing_streams.contains_key(&value.stream_id)
            || closed.contains(&value.stream_id);
        match value.frame_type {
            FrameType::Open => {
                if live.contains_key(&value.stream_id) || was_closed {
                    return false;
                }
                live.insert(
                    value.stream_id,
                    (
                        frame::INITIAL_STREAM_WINDOW,
                        u64::from(frame::INITIAL_STREAM_WINDOW),
                    ),
                );
            }
            FrameType::Data if !was_closed => {
                let Some((receive_window, send_credit)) = live.get_mut(&value.stream_id) else {
                    return false;
                };
                let Ok(payload_len) = u32::try_from(value.payload.len()) else {
                    return false;
                };
                if payload_len > *receive_window {
                    return false;
                }
                *receive_window -= payload_len;
                let _ = send_credit;
            }
            FrameType::Window if !was_closed => {
                let Some((_, send_credit)) = live.get_mut(&value.stream_id) else {
                    return false;
                };
                let Ok(amount) = frame::window_amount(value.payload) else {
                    return false;
                };
                *send_credit = send_credit
                    .saturating_add(u64::from(amount))
                    .min(u64::from(u32::MAX));
            }
            FrameType::Close if !was_closed => {
                if live.remove(&value.stream_id).is_none() {
                    return false;
                }
                closed.insert(value.stream_id);
            }
            FrameType::Data | FrameType::Window | FrameType::Close => {}
            _ => return false,
        }
    }
    true
}

pub(super) fn inbound_reservation(state: &SessionState, frames: &[Frame<'_>]) -> (usize, usize) {
    let mut live = state.streams.keys().copied().collect::<HashSet<_>>();
    let mut bytes = 0usize;
    let mut items = 0usize;
    for value in frames {
        match value.frame_type {
            FrameType::Open => {
                live.insert(value.stream_id);
            }
            FrameType::Data if live.contains(&value.stream_id) => {
                bytes = bytes.saturating_add(value.payload.len() + QUEUE_ITEM_COST);
                items = items.saturating_add(1);
            }
            FrameType::Close => {
                live.remove(&value.stream_id);
            }
            _ => {}
        }
    }
    (bytes, items)
}

#[cfg(test)]
#[path = "uplink_tests.rs"]
mod tests;
