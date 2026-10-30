use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use super::state::CarrierChainPhase;
use super::{
    CarrierClientClass, CarrierEcho, CarrierLearningContext, CarrierRequest, TokenHash,
    WebProcessRuntime,
};
use crate::config::WebCarrier;
use crate::web::session::WebSession;
use crate::web::telemetry::WebCarrierLearningOutcome;
use crate::web::trace::{TraceIdentity, TraceLifecycleEvent};

/// Typed result of publishing one exact session health transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CarrierHealthPublicationOutcome {
    /// Manager ownership was confirmed and the attempt became healthy.
    Published(WebCarrierLearningOutcome),
    /// Manager or transport ownership rejected the publication.
    Rejected(WebCarrierLearningOutcome),
}

impl CarrierHealthPublicationOutcome {
    /// Returns whether manager state accepted the health transition.
    pub(crate) const fn published(self) -> bool {
        matches!(self, Self::Published(_))
    }
}

impl WebProcessRuntime {
    /// Returns authenticated current chain metadata after a committed retry conflict.
    pub(crate) fn carrier_echo(
        &self,
        bootstrap_hash: TokenHash,
        host: &str,
        client_ip: IpAddr,
        request: CarrierRequest,
    ) -> Option<CarrierEcho> {
        let state = self.state.lock();
        let entry = state.bootstraps.get(&bootstrap_hash)?;
        let session = entry.session.as_ref()?;
        if !entry.used
            || entry.profile.host != host
            || entry.session_client_ip != Some(client_ip)
            || entry
                .carrier_request
                .is_none_or(|current| !current.matches_client(request))
            || !(matches!(
                entry.carrier_phase,
                CarrierChainPhase::CommittedPendingHealth | CarrierChainPhase::Healthy
            ) || session.is_carrier_committed())
        {
            return None;
        }
        Some(CarrierEcho {
            carrier: session.carrier(),
            attempt: entry.carrier_attempt,
            candidate_count: u8::try_from(entry.carrier_candidates.len()).unwrap_or(4),
            deadline_secs: entry.profile.shared.carrier_negotiation_deadlines_secs[3],
            state: if entry.carrier_phase == CarrierChainPhase::Provisional
                && session.is_carrier_committed()
            {
                CarrierChainPhase::CommittedPendingHealth.as_str()
            } else {
                entry.carrier_phase.as_str()
            },
        })
    }

    /// Restores the exact old attempt after successor admission fails.
    pub(super) fn cancel_replacement(
        &self,
        bootstrap_hash: TokenHash,
        old_session: &Arc<WebSession>,
    ) {
        old_session.cancel_carrier_supersede();
        let mut state = self.state.lock();
        if let Some(entry) = state.bootstraps.get_mut(&bootstrap_hash)
            && entry
                .session
                .as_ref()
                .is_some_and(|session| Arc::ptr_eq(session, old_session))
        {
            entry.carrier_transitioning = false;
        }
    }

    /// Freezes replacement immediately after accepted carrier state mutation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn carrier_committed(
        self: &Arc<Self>,
        bootstrap_hash: TokenHash,
        session_hash: TokenHash,
        attempt: u8,
        carrier: WebCarrier,
        class: CarrierClientClass,
        client_ip: IpAddr,
        identity: TraceIdentity,
    ) -> bool {
        let mut state = self.state.lock();
        let outcome = state.bootstraps.get_mut(&bootstrap_hash).and_then(|entry| {
            if entry.carrier_attempt == attempt
                && entry
                    .session
                    .as_ref()
                    .is_some_and(|session| session.token_hash() == session_hash)
                && entry.carrier_phase == CarrierChainPhase::Provisional
            {
                entry.carrier_phase = CarrierChainPhase::CommittedPendingHealth;
                Some(entry.carrier_scores)
            } else {
                None
            }
        });
        drop(state);
        let Some(scores) = outcome else {
            return false;
        };
        self.trace.record_carrier_lifecycle(
            client_ip,
            identity.clone(),
            TraceLifecycleEvent::CarrierCommitted,
            class.as_str(),
            carrier,
            attempt,
            scores,
            None,
        );
        true
    }

    /// Promotes one exact committed attempt after transport-specific health evidence.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn carrier_became_healthy(
        &self,
        bootstrap_hash: TokenHash,
        session_hash: TokenHash,
        attempt: u8,
        carrier: WebCarrier,
        class: CarrierClientClass,
        learning_context: Option<CarrierLearningContext>,
        client_ip: IpAddr,
        identity: TraceIdentity,
        websocket_owner: Option<u64>,
    ) -> CarrierHealthPublicationOutcome {
        if carrier.uses_websocket()
            && websocket_owner.is_none_or(|owner| !self.claim_websocket_health(owner, session_hash))
        {
            let outcome = WebCarrierLearningOutcome::OwnerNotLive;
            self.telemetry.record_carrier_learning(carrier, outcome);
            return CarrierHealthPublicationOutcome::Rejected(outcome);
        }
        let scores = {
            let mut state = self.state.lock();
            let Some(entry) = state.bootstraps.get_mut(&bootstrap_hash) else {
                let outcome = WebCarrierLearningOutcome::MissingChain;
                self.telemetry.record_carrier_learning(carrier, outcome);
                return CarrierHealthPublicationOutcome::Rejected(outcome);
            };
            if entry.carrier_phase != CarrierChainPhase::CommittedPendingHealth {
                let outcome = WebCarrierLearningOutcome::PhaseMismatch;
                self.telemetry.record_carrier_learning(carrier, outcome);
                return CarrierHealthPublicationOutcome::Rejected(outcome);
            }
            let Some(session) = entry.session.as_ref().filter(|session| {
                entry.carrier_attempt == attempt && session.token_hash() == session_hash
            }) else {
                let outcome = WebCarrierLearningOutcome::SessionMismatch;
                self.telemetry.record_carrier_learning(carrier, outcome);
                return CarrierHealthPublicationOutcome::Rejected(outcome);
            };
            if !session.publish_carrier_health() {
                let outcome = WebCarrierLearningOutcome::ClosedBeforeHealth;
                self.telemetry.record_carrier_learning(carrier, outcome);
                return CarrierHealthPublicationOutcome::Rejected(outcome);
            }
            entry.carrier_phase = CarrierChainPhase::Healthy;
            entry.carrier_scores
        };
        let learning_outcome = if let Some(context) = learning_context {
            let now = Instant::now();
            let outcome =
                self.learning
                    .lock()
                    .record_chain(now, context.epoch, context, &[], carrier);
            match outcome {
                super::learning::CarrierLearningRecordOutcome::Recorded => {
                    WebCarrierLearningOutcome::Recorded
                }
                super::learning::CarrierLearningRecordOutcome::PolicyDisabled => {
                    WebCarrierLearningOutcome::PolicyDisabled
                }
                super::learning::CarrierLearningRecordOutcome::StaleEpoch => {
                    WebCarrierLearningOutcome::StaleEpoch
                }
                super::learning::CarrierLearningRecordOutcome::CapacityRejected => {
                    WebCarrierLearningOutcome::CapacityRejected
                }
                super::learning::CarrierLearningRecordOutcome::SequenceExhausted => {
                    WebCarrierLearningOutcome::SequenceExhausted
                }
            }
        } else {
            WebCarrierLearningOutcome::NotEligible
        };
        self.telemetry
            .record_carrier_learning(carrier, learning_outcome);
        self.trace.record_carrier_lifecycle(
            client_ip,
            identity,
            TraceLifecycleEvent::CarrierHealthy,
            class.as_str(),
            carrier,
            attempt,
            scores,
            None,
        );
        CarrierHealthPublicationOutcome::Published(learning_outcome)
    }
}
