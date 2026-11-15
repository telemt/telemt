use std::sync::Arc;

use super::super::{CarrierLaneIdentity, StreamIdentity, WebSession, WebSocketLaneClaim};
use crate::web::manager::ManagerError;

/// Pre-OPEN stream quota and synthetic tuple ownership for one WebSocket lane.
pub(crate) struct WebSocketLaneReservation {
    /// Session whose exact lane incarnation owns the reservation.
    pub(super) session: Arc<WebSession>,
    /// Stable lane, tuple, and connection claim validated during teardown.
    pub(super) claim: WebSocketLaneClaim,
    /// Logical stream identity after a successful OPEN transfer.
    pub(super) stream: Option<StreamIdentity>,
    /// Current single-owner lifecycle phase.
    pub(super) phase: WebSocketLaneReservationPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Internal ownership phase for one exact WebSocket lane reservation.
pub(super) enum WebSocketLaneReservationPhase {
    /// Stream quota and a synthetic tuple are reserved before upgrade.
    Reserved,
    /// The reservation is bound to an admitted WebSocket connection.
    Bound,
    /// OPEN transferred the tuple into session stream state.
    Transferred,
    /// A backend task owns stream completion and quota release.
    StreamOwned,
    /// Teardown is synchronously releasing exact incarnation ownership.
    Closing,
    /// All reservation-owned cleanup has completed.
    Released,
}

/// Session-wide ownership of the only automatic WebSocket carrier probe.
pub(crate) struct WebSocketProbeReservation {
    /// Session owning the single automatic-carrier probe slot.
    pub(super) session: Arc<WebSession>,
    /// Bound process connection allowed to acknowledge commit.
    pub(super) owner: Option<u64>,
}

impl WebSocketProbeReservation {
    /// Binds the admitted process connection to the future commit acknowledgement.
    pub(crate) fn bind(&mut self, owner: u64) -> Result<(), ManagerError> {
        if self.session.close_if_cancelled() {
            return Err(ManagerError::Closed);
        }
        let mut state = self.session.state.lock();
        if state.closed
            || self.session.cancel.is_cancelled()
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
            if self.session.carrier_health_publication_state()
                != super::super::CarrierHealthPublicationState::Published
            {
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

    /// Confirms a lane resume proof belongs to this exact connection and stream incarnation.
    pub(crate) fn is_current_resume_lane(&self, connection_id: u64) -> bool {
        if self.phase != WebSocketLaneReservationPhase::StreamOwned
            || self.claim.connection_id != Some(connection_id)
            || self
                .stream
                .is_none_or(|stream| stream.id != self.claim.lane.lane_id)
            || self.session.close_if_cancelled()
        {
            return false;
        }
        let Some(stream) = self.stream else {
            return false;
        };
        let state = self.session.state.lock();
        !state.closed
            && self.session.ensure_carrier_active_locked(&state).is_ok()
            && state
                .carrier_lanes
                .get(&self.claim.lane.lane_id)
                .is_some_and(|lane| lane.instance == self.claim.lane.instance)
            && state
                .streams
                .get(&stream.id)
                .is_some_and(|current| current.instance == stream.instance)
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
        if self.session.close_if_cancelled() {
            return Err(ManagerError::Closed);
        }
        let mut state = self.session.state.lock();
        if state.closed
            || self.session.cancel.is_cancelled()
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

    pub(super) fn transfer_to_stream(
        &mut self,
        stream: StreamIdentity,
    ) -> Result<(), ManagerError> {
        if self.phase != WebSocketLaneReservationPhase::Bound
            || stream.id != self.claim.lane.lane_id
        {
            return Err(ManagerError::Protocol);
        }
        if self.session.close_if_cancelled() {
            return Err(ManagerError::Closed);
        }
        let mut state = self.session.state.lock();
        if self.session.cancel.is_cancelled()
            || state
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

    pub(super) fn mark_stream_owned(&mut self, stream: StreamIdentity) -> Result<(), ManagerError> {
        if self.phase != WebSocketLaneReservationPhase::Transferred || self.stream != Some(stream) {
            return Err(ManagerError::Protocol);
        }
        self.phase = WebSocketLaneReservationPhase::StreamOwned;
        Ok(())
    }

    pub(super) fn retain_after_rejected_spawn(&mut self) {
        debug_assert_eq!(self.phase, WebSocketLaneReservationPhase::StreamOwned);
        self.phase = WebSocketLaneReservationPhase::Transferred;
    }

    pub(super) fn release(&mut self) {
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
