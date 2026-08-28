use std::sync::Arc;
use std::time::Instant;

use sha2::{Digest, Sha256};

use super::uplink::{AppliedProgress, inbound_reservation, validate_batch};
use super::{
    CarrierLaneIdentity, PendingClass, StreamIdentity, WebSession, WebSocketLaneClaim,
    inbound_queue_cost, insert_carrier_lane,
};
use crate::config::WebCarrier;
use crate::web::frame;
use crate::web::manager::ManagerError;

/// Pre-OPEN stream quota and synthetic tuple ownership for one WebSocket lane.
pub(crate) struct WebSocketLaneReservation {
    session: Arc<WebSession>,
    claim: WebSocketLaneClaim,
    stream: Option<StreamIdentity>,
    phase: WebSocketLaneReservationPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WebSocketLaneReservationPhase {
    Reserved,
    Bound,
    Transferred,
    StreamOwned,
    Closing,
    Released,
}

/// Session-wide ownership of the only automatic WebSocket carrier probe.
pub(crate) struct WebSocketProbeReservation {
    session: Arc<WebSession>,
    owner: Option<u64>,
}

impl WebSocketProbeReservation {
    /// Binds the admitted process connection to the future commit acknowledgement.
    pub(crate) fn bind(&mut self, owner: u64) -> Result<(), ManagerError> {
        let mut state = self.session.state.lock();
        if state.closed
            || !state.websocket_probe_claimed
            || state.websocket_commit_ack_owner.is_some()
        {
            return Err(ManagerError::Closed);
        }
        state.websocket_commit_ack_owner = Some(owner);
        self.owner = Some(owner);
        Ok(())
    }
}

impl Drop for WebSocketProbeReservation {
    fn drop(&mut self) {
        let mut state = self.session.state.lock();
        state.websocket_probe_claimed = false;
        if state.websocket_commit_ack_owner == self.owner {
            state.websocket_commit_ack_owner = None;
            if !state.carrier_health_reported {
                state.websocket_commit_ack_written = false;
                state.carrier_health_uplink = false;
                state.carrier_health_activity_at = None;
            }
        }
    }
}

impl WebSocketLaneReservation {
    /// Returns the logical stream owned by this connection.
    pub(crate) fn lane_id(&self) -> u32 {
        self.claim.lane.lane_id
    }

    /// Returns the exact lane incarnation owned by this connection.
    pub(crate) fn lane_identity(&self) -> CarrierLaneIdentity {
        self.claim.lane
    }

    /// Binds this pre-upgrade reservation to one admitted process connection.
    pub(crate) fn bind(&mut self, connection_id: u64) -> Result<(), ManagerError> {
        if self.phase != WebSocketLaneReservationPhase::Reserved {
            return Err(ManagerError::Concurrent);
        }
        let mut state = self.session.state.lock();
        if state.closed
            || state
                .carrier_lanes
                .get(&self.claim.lane.lane_id)
                .is_none_or(|lane| lane.instance != self.claim.lane.instance)
        {
            return Err(ManagerError::Closed);
        }
        let Some(current) = state
            .websocket_lane_reservations
            .get_mut(&self.claim.lane.lane_id)
            .filter(|current| **current == self.claim && current.connection_id.is_none())
        else {
            return Err(ManagerError::Closed);
        };
        current.connection_id = Some(connection_id);
        self.claim.connection_id = Some(connection_id);
        self.phase = WebSocketLaneReservationPhase::Bound;
        Ok(())
    }

    fn transfer_to_stream(&mut self, stream: StreamIdentity) -> Result<(), ManagerError> {
        if self.phase != WebSocketLaneReservationPhase::Bound
            || stream.id != self.claim.lane.lane_id
        {
            return Err(ManagerError::Protocol);
        }
        let mut state = self.session.state.lock();
        if state
            .carrier_lanes
            .get(&self.claim.lane.lane_id)
            .is_none_or(|lane| lane.instance != self.claim.lane.instance)
            || state
                .streams
                .get(&stream.id)
                .is_none_or(|current| current.instance != stream.instance)
            || state
                .websocket_lane_reservations
                .get(&self.claim.lane.lane_id)
                != Some(&self.claim)
        {
            return Err(ManagerError::Closed);
        }
        state
            .websocket_lane_reservations
            .remove(&self.claim.lane.lane_id);
        self.stream = Some(stream);
        self.phase = WebSocketLaneReservationPhase::Transferred;
        Ok(())
    }

    fn mark_stream_owned(&mut self, stream: StreamIdentity) -> Result<(), ManagerError> {
        if self.phase != WebSocketLaneReservationPhase::Transferred || self.stream != Some(stream) {
            return Err(ManagerError::Protocol);
        }
        self.phase = WebSocketLaneReservationPhase::StreamOwned;
        Ok(())
    }

    fn retain_after_rejected_spawn(&mut self) {
        debug_assert_eq!(self.phase, WebSocketLaneReservationPhase::StreamOwned);
        self.phase = WebSocketLaneReservationPhase::Transferred;
    }

    fn release(&mut self) {
        if self.phase == WebSocketLaneReservationPhase::Released {
            return;
        }
        let stream_owned = self.phase == WebSocketLaneReservationPhase::StreamOwned;
        self.phase = WebSocketLaneReservationPhase::Closing;
        self.session
            .release_websocket_lane_claim(self.claim, self.stream, stream_owned);
        self.phase = WebSocketLaneReservationPhase::Released;
    }
}

impl Drop for WebSocketLaneReservation {
    fn drop(&mut self) {
        self.release();
    }
}

impl WebSession {
    /// Reserves the only automatic WebSocket probe before any HTTP 101 response.
    pub(crate) fn reserve_websocket_probe(
        self: &Arc<Self>,
        acknowledge_commit: bool,
    ) -> Result<Option<WebSocketProbeReservation>, ManagerError> {
        let mut state = self.state.lock();
        if state.closed {
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
        let mut state = self.state.lock();
        if state.closed {
            return Err(ManagerError::Closed);
        }
        if state.active_peer_ports.len() >= self.profile.max_streams_per_session
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
        let peer_port = manager.try_acquire_stream(
            self.profile_key,
            self.profile.max_streams,
            self.client_ip,
            self.profile.public_addr,
        )?;
        if !state.active_peer_ports.insert(peer_port) {
            manager.release_stream(
                self.profile_key,
                self.client_ip,
                self.profile.public_addr,
                peer_port,
            );
            return Err(ManagerError::Limit);
        }
        let Some(lane) = insert_carrier_lane(&mut state, lane_id) else {
            state.active_peer_ports.remove(&peer_port);
            manager.release_stream(
                self.profile_key,
                self.client_ip,
                self.profile.public_addr,
                peer_port,
            );
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
            self.release_lane_locked(&mut state, lane_id);
            state.active_peer_ports.remove(&peer_port);
            manager.release_stream(
                self.profile_key,
                self.client_ip,
                self.profile.public_addr,
                peer_port,
            );
            return Err(ManagerError::Concurrent);
        }
        drop(state);
        self.lane_open_notify.notify_waiters();
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
        let mut healthy = false;
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
                &mut opened,
                &mut reserved_open,
                &mut unused_bytes,
                &mut unused_items,
                &mut progress,
            );
            self.release_locked(&mut state, unused_bytes, unused_items, false);
            if let Some(lane) = state.carrier_lanes.get_mut(&lane_id) {
                lane.up_active = false;
                if applied {
                    lane.last_up_sequence = sequence;
                    lane.last_up_digest = digest;
                }
            }
            state.last_activity = Instant::now();
            if applied {
                (committed, healthy) = self.record_uplink_progress_locked(&mut state, progress);
            }
            applied
                .then_some(progress.any())
                .ok_or(ManagerError::Protocol)
        };
        let progressed = result?;
        if committed {
            self.finish_carrier_commit();
        }
        if healthy {
            self.finish_carrier_health();
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
                    self.release_locked(&mut state, bytes, items, false);
                    if let Some(waker) = stream_state.read_waker {
                        waker.wake();
                    }
                    if let Some(waker) = stream_state.write_waker {
                        waker.wake();
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
                self.remember_closed_locked(&mut state, claim.lane.lane_id);
                if state
                    .carrier_lanes
                    .get(&claim.lane.lane_id)
                    .is_some_and(|lane| lane.instance == claim.lane.instance)
                {
                    self.release_lane_locked(&mut state, claim.lane.lane_id);
                }
            }
            release_port
        };
        if release_port && let Some(manager) = self.manager.upgrade() {
            manager.release_stream(
                self.profile_key,
                self.client_ip,
                self.profile.public_addr,
                claim.peer_port,
            );
        }
        self.lane_open_notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests;
