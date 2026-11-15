use std::time::{Duration, Instant};

use super::uplink::AppliedProgress;
use super::{SessionNegotiationPhase, SessionState, WebSession};

/// Fixed ownership state for one carrier-health publication attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum CarrierHealthPublicationState {
    /// No eligible callback has claimed publication.
    Awaiting,
    /// One callback is validating manager and transport ownership.
    Publishing,
    /// Manager state accepted the health transition.
    Published,
    /// Close or ownership validation permanently rejected publication.
    Rejected,
}

/// Transport owner captured by the single publication claimant.
#[derive(Clone, Copy)]
pub(super) struct CarrierHealthClaim {
    websocket_owner: Option<u64>,
}

impl WebSession {
    /// Returns whether accepted carrier progress made this attempt immutable.
    pub(crate) fn is_carrier_committed(&self) -> bool {
        self.state.lock().negotiation_phase == SessionNegotiationPhase::Committed
    }

    /// Requires a live committed WebSocket session before accepting a resume proof.
    pub(crate) fn is_resume_probe_eligible(&self) -> bool {
        if self.cancel.is_cancelled() || !self.selected_carrier.uses_websocket() {
            return false;
        }
        let state = self.state.lock();
        !state.closed && state.negotiation_phase == SessionNegotiationPhase::Committed
    }

    /// Rejects mutation after replacement, supersede, or the final chain deadline.
    pub(super) fn ensure_carrier_active_locked(
        &self,
        state: &SessionState,
    ) -> Result<(), crate::web::manager::ManagerError> {
        if self.cancel.is_cancelled() {
            return Err(crate::web::manager::ManagerError::Closed);
        }
        if state.negotiation_phase == SessionNegotiationPhase::Uncommitted
            && self
                .carrier_deadline_at
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(crate::web::manager::ManagerError::Closed);
        }
        match state.negotiation_phase {
            SessionNegotiationPhase::Uncommitted | SessionNegotiationPhase::Committed => Ok(()),
            SessionNegotiationPhase::Replacing | SessionNegotiationPhase::Superseded => {
                Err(crate::web::manager::ManagerError::Closed)
            }
        }
    }

    /// Publishes the already-linearized session commit to process state.
    pub(super) fn finish_carrier_commit(&self) {
        let published = self.manager.upgrade().is_some_and(|manager| {
            manager.carrier_committed(
                self.bootstrap_hash,
                self.token_hash,
                self.carrier_attempt,
                self.selected_carrier,
                self.carrier_class,
                self.client_ip,
                self.trace_identity(),
            )
        });
        if !published {
            return;
        }
        let healthy = {
            let mut state = self.state.lock();
            if state.closed || state.negotiation_phase != SessionNegotiationPhase::Committed {
                None
            } else {
                state.carrier_commit_published = true;
                self.carrier_health_ready_locked(&mut state, Instant::now())
            }
        };
        if let Some(claim) = healthy {
            self.finish_carrier_health(claim);
        }
    }

    /// Publishes complete transport-specific health evidence to process state.
    pub(super) fn finish_carrier_health(&self, claim: CarrierHealthClaim) {
        if let Some(manager) = self.manager.upgrade() {
            let outcome = manager.carrier_became_healthy(
                self.bootstrap_hash,
                self.token_hash,
                self.carrier_attempt,
                self.selected_carrier,
                self.carrier_class,
                self.learning_context,
                self.client_ip,
                self.trace_identity(),
                claim.websocket_owner,
            );
            if !outcome.published() {
                self.reject_carrier_health_publication();
            }
        } else {
            self.reject_carrier_health_publication();
        }
    }

    /// Records accepted OPEN or DATA progress and returns commit and health transitions.
    pub(super) fn record_uplink_progress_locked(
        &self,
        state: &mut SessionState,
        progress: AppliedProgress,
    ) -> (bool, Option<CarrierHealthClaim>) {
        if self.recovery && progress.any() && !state.recovery_committed {
            state.recovery_committed = true;
            if let Some(manager) = self.manager.upgrade() {
                manager.telemetry().record_bridge_recovery(
                    crate::web::telemetry::WebBridgeRecoveryEvent::Committed,
                );
            }
        }
        if !self.automatic_carrier || !progress.any() {
            return (false, None);
        }
        if self.selected_carrier.uses_websocket() {
            state.websocket_carrier_active = true;
            state.websocket_commit_ack_pending = true;
        } else if progress.accepted_data {
            state.carrier_health_uplink = true;
        }
        let now = Instant::now();
        let committed = if state.negotiation_phase == SessionNegotiationPhase::Uncommitted {
            state.negotiation_phase = SessionNegotiationPhase::Committed;
            state.carrier_health_due_at =
                Some(now + Duration::from_secs(self.timeouts.carrier_health_secs));
            true
        } else {
            false
        };
        state.carrier_health_activity_at = Some(now);
        let healthy = self.carrier_health_ready_locked(state, now);
        (committed, healthy)
    }

    /// Consumes complete post-commit health evidence at most once.
    pub(super) fn carrier_health_ready_locked(
        &self,
        state: &mut SessionState,
        now: Instant,
    ) -> Option<CarrierHealthClaim> {
        if !self.automatic_carrier
            || state.closed
            || state.negotiation_phase != SessionNegotiationPhase::Committed
            || !state.carrier_commit_published
            || state.carrier_health_due_at.is_none_or(|due| now < due)
        {
            return None;
        }
        let evidence = if state.websocket_carrier_active {
            state.websocket_probe_claimed
                && state.websocket_commit_ack_owner.is_some()
                && state.websocket_commit_ack_written
                && state.carrier_health_uplink
        } else {
            state.carrier_health_uplink
                && state.carrier_health_downlink
                && state
                    .carrier_health_activity_at
                    .zip(state.carrier_health_due_at)
                    .is_some_and(|(activity, due)| activity >= due)
        };
        if !evidence {
            return None;
        }
        self.carrier_health_publication
            .compare_exchange(
                CarrierHealthPublicationState::Awaiting as u8,
                CarrierHealthPublicationState::Publishing as u8,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .ok()
            .map(|_| CarrierHealthClaim {
                websocket_owner: state
                    .websocket_carrier_active
                    .then_some(state.websocket_commit_ack_owner)
                    .flatten(),
            })
    }

    /// Returns whether the exact automatic WebSocket owner must receive a commit acknowledgement.
    pub(crate) fn needs_websocket_commit_ack(&self, owner: u64) -> bool {
        let state = self.state.lock();
        !state.closed
            && state.websocket_commit_ack_owner == Some(owner)
            && state.websocket_commit_ack_pending
            && !state.websocket_commit_ack_written
    }

    /// Records that the commit acknowledgement reached its exact WebSocket owner.
    pub(crate) fn websocket_commit_ack_written(&self, owner: u64) -> bool {
        let mut state = self.state.lock();
        if state.closed
            || state.websocket_commit_ack_owner != Some(owner)
            || !state.websocket_commit_ack_pending
        {
            return false;
        }
        state.websocket_commit_ack_written = true;
        true
    }

    /// Records validated binary peer progress after the exact WebSocket acknowledgement.
    pub(crate) fn websocket_peer_after_commit_ack(&self, owner: u64) -> bool {
        let healthy = {
            let mut state = self.state.lock();
            if state.closed
                || state.websocket_commit_ack_owner != Some(owner)
                || !state.websocket_commit_ack_written
            {
                return false;
            }
            state.carrier_health_uplink = true;
            let now = Instant::now();
            state.carrier_health_activity_at = Some(now);
            self.carrier_health_ready_locked(&mut state, now)
        };
        if let Some(claim) = healthy {
            self.finish_carrier_health(claim);
        }
        true
    }

    /// Confirms manager ownership as the health publication linearization point.
    pub(crate) fn publish_carrier_health(&self) -> bool {
        self.carrier_health_publication
            .compare_exchange(
                CarrierHealthPublicationState::Publishing as u8,
                CarrierHealthPublicationState::Published as u8,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
    }

    /// Rejects an in-flight publication after manager validation fails.
    pub(super) fn reject_carrier_health_publication(&self) {
        let _ = self.carrier_health_publication.compare_exchange(
            CarrierHealthPublicationState::Publishing as u8,
            CarrierHealthPublicationState::Rejected as u8,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        );
    }

    /// Rejects pending health on close and reports whether no callback was in flight.
    pub(super) fn reject_carrier_health_on_close(&self) -> bool {
        loop {
            let current = self
                .carrier_health_publication
                .load(std::sync::atomic::Ordering::Acquire);
            let count_locally = current == CarrierHealthPublicationState::Awaiting as u8;
            if current != CarrierHealthPublicationState::Awaiting as u8
                && current != CarrierHealthPublicationState::Publishing as u8
            {
                return false;
            }
            if self
                .carrier_health_publication
                .compare_exchange(
                    current,
                    CarrierHealthPublicationState::Rejected as u8,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                )
                .is_ok()
            {
                return count_locally;
            }
        }
    }

    /// Returns the current fixed health-publication state.
    pub(super) fn carrier_health_publication_state(&self) -> CarrierHealthPublicationState {
        match self
            .carrier_health_publication
            .load(std::sync::atomic::Ordering::Acquire)
        {
            value if value == CarrierHealthPublicationState::Awaiting as u8 => {
                CarrierHealthPublicationState::Awaiting
            }
            value if value == CarrierHealthPublicationState::Publishing as u8 => {
                CarrierHealthPublicationState::Publishing
            }
            value if value == CarrierHealthPublicationState::Published as u8 => {
                CarrierHealthPublicationState::Published
            }
            _ => CarrierHealthPublicationState::Rejected,
        }
    }
}

// Carrier health publication and negotiation race tests.
#[cfg(test)]
mod tests;
