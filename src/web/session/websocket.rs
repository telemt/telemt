use std::sync::Arc;
use std::time::Instant;

use sha2::{Digest, Sha256};

use super::uplink::{AppliedProgress, inbound_reservation, validate_batch};
use super::{
    DeferredSessionEffects, PendingClass, StreamIdentity, WebSession, WebSocketLaneClaim,
    inbound_queue_cost, insert_carrier_lane,
};
use crate::config::WebCarrier;
use crate::web::frame;
use crate::web::manager::ManagerError;

// Reservation ownership keeps pre-OPEN quota and exact lane identity transactional.
mod reservation;
use reservation::WebSocketLaneReservationPhase;
pub(crate) use reservation::{WebSocketLaneReservation, WebSocketProbeReservation};

impl WebSession {
    /// Reserves the only automatic WebSocket probe before any HTTP 101 response.
    pub(crate) fn reserve_websocket_probe(
        self: &Arc<Self>,
        acknowledge_commit: bool,
    ) -> Result<Option<WebSocketProbeReservation>, ManagerError> {
        if self.close_if_cancelled() {
            return Err(ManagerError::Closed);
        }
        let mut state = self.state.lock();
        if state.closed || self.cancel.is_cancelled() {
            return Err(ManagerError::Closed);
        }
        self.ensure_carrier_active_locked(&state)?;
        if !self.automatic_carrier {
            return if acknowledge_commit {
                Err(ManagerError::Protocol)
            } else {
                Ok(None)
            };
        }
        match state.negotiation_phase {
            super::SessionNegotiationPhase::Uncommitted if acknowledge_commit => {
                if state.websocket_probe_claimed || state.websocket_commit_ack_owner.is_some() {
                    return Err(ManagerError::Concurrent);
                }
                state.websocket_probe_claimed = true;
                Ok(Some(WebSocketProbeReservation {
                    session: Arc::clone(self),
                    owner: None,
                }))
            }
            super::SessionNegotiationPhase::Committed if !acknowledge_commit => Ok(None),
            super::SessionNegotiationPhase::Committed => Err(ManagerError::Committed),
            super::SessionNegotiationPhase::Uncommitted => Err(ManagerError::Protocol),
            super::SessionNegotiationPhase::Replacing
            | super::SessionNegotiationPhase::Superseded => Err(ManagerError::Closed),
        }
    }

    /// Acquires stream quota and tuple ownership before a lane returns HTTP 101.
    pub(crate) fn reserve_websocket_lane(
        self: &Arc<Self>,
        lane_id: u32,
    ) -> Result<WebSocketLaneReservation, ManagerError> {
        if self.carrier() != WebCarrier::WebsocketLanes
            || lane_id == 0
            || lane_id > frame::MAX_STREAM_ID
        {
            return Err(ManagerError::Protocol);
        }
        if self.close_if_cancelled() {
            return Err(ManagerError::Closed);
        }
        let mut effects = DeferredSessionEffects::new();
        let mut state = self.state.lock();
        if state.closed || self.cancel.is_cancelled() {
            return Err(ManagerError::Closed);
        }
        if state.active_peer_ports.len() >= self.profile.shared.max_streams_per_session
            || state.streams.contains_key(&lane_id)
            || state.closing_streams.contains_key(&lane_id)
            || state.closed_streams.contains(&lane_id)
            || state.websocket_lane_reservations.contains_key(&lane_id)
        {
            return Err(ManagerError::Limit);
        }
        let Some(manager) = self.manager.upgrade() else {
            return Err(ManagerError::Closed);
        };
        let (peer_port, notify) = manager.try_acquire_stream_quiet(
            self.profile_key,
            self.profile.shared.max_streams,
            self.client_ip,
            self.profile.shared.public_addr,
        );
        if let Some(notify) = notify {
            effects.notify(notify);
        }
        let peer_port = match peer_port {
            Ok(peer_port) => peer_port,
            Err(error) => {
                drop(state);
                effects.finish();
                return Err(error);
            }
        };
        if !state.active_peer_ports.insert(peer_port) {
            if let Some(notify) = manager.release_stream_quiet(
                self.profile_key,
                self.client_ip,
                self.profile.shared.public_addr,
                peer_port,
            ) {
                effects.notify(notify);
            }
            drop(state);
            effects.finish();
            return Err(ManagerError::Limit);
        }
        let Some(lane) = insert_carrier_lane(&mut state, lane_id) else {
            state.active_peer_ports.remove(&peer_port);
            if let Some(notify) = manager.release_stream_quiet(
                self.profile_key,
                self.client_ip,
                self.profile.shared.public_addr,
                peer_port,
            ) {
                effects.notify(notify);
            }
            drop(state);
            effects.finish();
            return Err(ManagerError::Protocol);
        };
        let claim = WebSocketLaneClaim {
            lane,
            peer_port,
            connection_id: None,
        };
        let inserted = match state.websocket_lane_reservations.entry(lane_id) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(claim);
                true
            }
            std::collections::hash_map::Entry::Occupied(_) => false,
        };
        if !inserted {
            self.release_lane_locked(&mut state, &mut effects, lane_id);
            state.active_peer_ports.remove(&peer_port);
            if let Some(notify) = manager.release_stream_quiet(
                self.profile_key,
                self.client_ip,
                self.profile.shared.public_addr,
                peer_port,
            ) {
                effects.notify(notify);
            }
            drop(state);
            effects.finish();
            return Err(ManagerError::Concurrent);
        }
        effects.notify(Arc::clone(&self.lane_open_notify));
        drop(state);
        effects.finish();
        Ok(WebSocketLaneReservation {
            session: Arc::clone(self),
            claim,
            stream: None,
            phase: WebSocketLaneReservationPhase::Reserved,
        })
    }

    /// Applies one ordered WebSocket lane message without closing sibling lanes.
    pub(crate) fn process_websocket_lane(
        self: &Arc<Self>,
        reservation: &mut WebSocketLaneReservation,
        sequence: u64,
        body: &[u8],
    ) -> Result<bool, ManagerError> {
        if !Arc::ptr_eq(self, &reservation.session)
            || reservation.lane_id() == 0
            || reservation.lane_id() > frame::MAX_STREAM_ID
            || !matches!(
                reservation.phase,
                WebSocketLaneReservationPhase::Bound | WebSocketLaneReservationPhase::StreamOwned
            )
        {
            return Err(ManagerError::Protocol);
        }
        if self.close_if_cancelled() {
            return Err(ManagerError::Closed);
        }
        let lane_id = reservation.lane_id();
        let frames = frame::parse_all(body, &self.limits).map_err(|_| ManagerError::Protocol)?;
        if frames
            .iter()
            .copied()
            .any(|value| value.stream_id != lane_id || frame::validate_client_shape(value).is_err())
        {
            return Err(ManagerError::Protocol);
        }
        let digest = Sha256::digest(body).into();
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
            if state
                .carrier_lanes
                .get(&lane_id)
                .is_none_or(|lane| lane.instance != reservation.claim.lane.instance)
                || (reservation.phase == WebSocketLaneReservationPhase::Bound
                    && state.websocket_lane_reservations.get(&lane_id) != Some(&reservation.claim))
                || (reservation.phase == WebSocketLaneReservationPhase::StreamOwned
                    && reservation.stream.is_none_or(|stream| {
                        state
                            .streams
                            .get(&stream.id)
                            .is_none_or(|current| current.instance != stream.instance)
                    }))
            {
                return Err(ManagerError::Closed);
            }
            let Some(lane) = state.carrier_lanes.get_mut(&lane_id) else {
                return Err(ManagerError::Closed);
            };
            if sequence == 0 || sequence != lane.last_up_sequence.saturating_add(1) {
                return Err(ManagerError::Protocol);
            }
            if lane.up_active {
                return Err(ManagerError::Concurrent);
            }
            lane.up_active = true;
            if !validate_batch(&state, &frames) {
                if let Some(lane) = state.carrier_lanes.get_mut(&lane_id) {
                    lane.up_active = false;
                }
                return Err(ManagerError::Protocol);
            }
            let (reserve_bytes, reserve_items) = inbound_reservation(&state, &frames);
            if !self.reserve_locked(
                &mut state,
                reserve_bytes,
                reserve_items,
                PendingClass::Uplink,
            ) {
                if let Some(lane) = state.carrier_lanes.get_mut(&lane_id) {
                    lane.up_active = false;
                }
                return Err(ManagerError::Backpressure);
            }
            let mut unused_bytes = reserve_bytes;
            let mut unused_items = reserve_items;
            let mut progress = AppliedProgress::default();
            let mut reserved_open = (reservation.phase == WebSocketLaneReservationPhase::Bound)
                .then_some((lane_id, reservation.claim.peer_port));
            let applied = self.apply_batch_locked(
                &mut state,
                &frames,
                &mut effects,
                &mut opened,
                &mut reserved_open,
                &mut unused_bytes,
                &mut unused_items,
                &mut progress,
            );
            self.release_locked(&mut state, &mut effects, unused_bytes, unused_items, false);
            if let Some(lane) = state.carrier_lanes.get_mut(&lane_id) {
                lane.up_active = false;
                if applied {
                    lane.last_up_sequence = sequence;
                    lane.last_up_digest = digest;
                }
            }
            self.touch_peer_locked(
                &mut state,
                Instant::now(),
                crate::web::telemetry::WebSessionLifecycleObservation::WebSocketActivityAfterGap,
            );
            if applied {
                (committed, healthy) = self.record_uplink_progress_locked(&mut state, progress);
            }
            applied
                .then_some(progress.any())
                .ok_or(ManagerError::Protocol)
        };
        effects.finish();
        let progressed = result?;
        if committed {
            self.finish_carrier_commit();
        }
        if let Some(claim) = healthy {
            self.finish_carrier_health(claim);
        }
        for completion in opened {
            let stream = completion.stream;
            if stream.id != lane_id || completion.peer_port != reservation.claim.peer_port {
                return Err(ManagerError::Protocol);
            }
            reservation.transfer_to_stream(stream)?;
            reservation.mark_stream_owned(stream)?;
            if !self.spawn_stream(completion, true) {
                reservation.retain_after_rejected_spawn();
                return Err(ManagerError::Limit);
            }
        }
        if reservation.phase != WebSocketLaneReservationPhase::StreamOwned {
            return Err(ManagerError::Protocol);
        }
        if let Some(manager) = self.manager.upgrade() {
            manager.record_up(body.len());
        }
        Ok(progressed)
    }

    /// Ends one exact failed or disconnected lane without closing its parent session.
    pub(crate) fn close_websocket_lane(&self, mut reservation: WebSocketLaneReservation) {
        if std::ptr::eq(self, Arc::as_ptr(&reservation.session)) {
            reservation.release();
        }
    }

    fn release_websocket_lane_claim(
        &self,
        claim: WebSocketLaneClaim,
        stream: Option<StreamIdentity>,
        stream_owned: bool,
    ) {
        let mut effects = DeferredSessionEffects::new();
        let release_port = {
            let mut state = self.state.lock();
            let lane_matches = state
                .carrier_lanes
                .get(&claim.lane.lane_id)
                .is_some_and(|lane| lane.instance == claim.lane.instance);
            if !lane_matches && !state.closed {
                return;
            }
            let release_port = if let Some(stream) = stream {
                if stream.id != claim.lane.lane_id {
                    return;
                }
                let current_stream = state
                    .streams
                    .get(&stream.id)
                    .is_some_and(|current| current.instance == stream.instance);
                if current_stream {
                    let Some(stream_state) = state.streams.remove(&stream.id) else {
                        return;
                    };
                    state
                        .closing_streams
                        .insert(claim.lane.lane_id, stream.instance);
                    let (bytes, items) = inbound_queue_cost(&stream_state.inbound);
                    self.release_locked(&mut state, &mut effects, bytes, items, false);
                    if let Some(waker) = stream_state.read_waker {
                        effects.wake(waker);
                    }
                    if let Some(waker) = stream_state.write_waker {
                        effects.wake(waker);
                    }
                    false
                } else if stream_owned {
                    false
                } else {
                    state.active_peer_ports.remove(&claim.peer_port)
                }
            } else {
                if state.websocket_lane_reservations.get(&claim.lane.lane_id) != Some(&claim) {
                    return;
                }
                state
                    .websocket_lane_reservations
                    .remove(&claim.lane.lane_id);
                state.active_peer_ports.remove(&claim.peer_port)
            };
            if lane_matches {
                self.remember_closed_locked(&mut state, &mut effects, claim.lane.lane_id);
                if state
                    .carrier_lanes
                    .get(&claim.lane.lane_id)
                    .is_some_and(|lane| lane.instance == claim.lane.instance)
                {
                    self.release_lane_locked(&mut state, &mut effects, claim.lane.lane_id);
                }
            }
            release_port
        };
        effects.finish();
        if release_port && let Some(manager) = self.manager.upgrade() {
            manager.release_stream(
                self.profile_key,
                self.client_ip,
                self.profile.shared.public_addr,
                claim.peer_port,
            );
        }
        self.lane_open_notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests;
