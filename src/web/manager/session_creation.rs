use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::negotiation::carrier_attempt_deadline_index;
use super::session_admission::admit_initial;
use super::state::{
    CarrierChainPhase, LiveSessionIndex, decrement_map, matching_profile, new_unique_token,
    profile_key, remember_closed_token_locked, remove_expired_locked,
};
use super::{
    CarrierLearningContext, CarrierRequest, CreateResult, ManagerError, TokenHash,
    WebProcessRuntime,
};
use crate::config::{WebCarrier, WebRuntimeProfile};
use crate::web::frame;
use crate::web::session::WebSession;
use crate::web::trace::TraceLifecycleEvent;

struct Replacement {
    old_session: Arc<WebSession>,
    profile: Arc<WebRuntimeProfile>,
    profile_key: super::ProfileKey,
    trace_session_id: u64,
    attempt: u8,
    carrier: WebCarrier,
    request: CarrierRequest,
    scores: [i16; 4],
    learning_epoch: u64,
    ip_learning_eligible: bool,
    carrier_deadline_at: Instant,
}

impl WebProcessRuntime {
    /// Creates, replays, or atomically supersedes one pre-commit carrier session.
    pub(crate) fn create_session(
        self: &Arc<Self>,
        bootstrap_hash: TokenHash,
        host: &str,
        client_ip: IpAddr,
        body: &[u8],
        carrier_request: CarrierRequest,
        ip_learning_eligible: bool,
    ) -> std::result::Result<CreateResult, ManagerError> {
        if !frame::validate_hello(body, &self.limits) {
            return Err(ManagerError::Protocol);
        }
        let body_digest: TokenHash = Sha256::digest(body).into();
        let generation = self.active_generation();
        let config = generation.config();
        let now = Instant::now();
        let mut state = self.state.lock();
        remove_expired_locked(&mut state, now);
        state.apply_issuance_policy(generation.id, config.web.enabled);
        if state.closed || !state.issuance_enabled {
            return Err(ManagerError::Closed);
        }
        let Some(entry) = state.bootstraps.get(&bootstrap_hash) else {
            return Err(ManagerError::Authentication);
        };
        if entry.profile.host != host || now > entry.expires_at {
            return Err(ManagerError::Authentication);
        }
        if entry.used {
            if entry
                .carrier_deadline_at
                .is_some_and(|deadline| now >= deadline)
                && entry
                    .session
                    .as_ref()
                    .is_some_and(|session| !session.is_carrier_committed())
            {
                let session = entry.session.clone();
                drop(state);
                if let Some(session) = session {
                    session.close();
                }
                return Err(ManagerError::Closed);
            }
            if entry.close_requested {
                return Err(ManagerError::Closed);
            }
            let digest_matches = bool::from(entry.body_digest.ct_eq(&body_digest));
            let client_matches = entry.session_client_ip == Some(client_ip)
                && entry.session_ip_learning_eligible == ip_learning_eligible;
            let request_matches = entry
                .carrier_request
                .is_some_and(|current| current.matches_client(carrier_request));
            if !digest_matches || !client_matches || !request_matches {
                return Err(ManagerError::Authentication);
            }
            if entry.carrier_transitioning {
                return Err(ManagerError::Concurrent);
            }
            if carrier_request.attempt() == Some(entry.carrier_attempt)
                || (!carrier_request.is_automatic() && entry.carrier_attempt == 1)
            {
                if entry
                    .carrier_request
                    .is_none_or(|current| !current.matches_attempt(carrier_request))
                {
                    return Err(ManagerError::Authentication);
                }
                let session = entry.session.as_ref().ok_or(ManagerError::Authentication)?;
                let automatic = carrier_request.is_automatic();
                let carrier_state = if entry.carrier_phase == CarrierChainPhase::Provisional
                    && session.is_carrier_committed()
                {
                    CarrierChainPhase::CommittedPendingHealth.as_str()
                } else {
                    entry.carrier_phase.as_str()
                };
                let result = CreateResult {
                    token: entry.session_token.as_str().to_owned(),
                    carrier: session.carrier(),
                    attempt: carrier_request.attempt(),
                    candidate_count: automatic
                        .then(|| u8::try_from(entry.carrier_candidates.len()).unwrap_or(4)),
                    deadline_secs: automatic
                        .then_some(entry.profile.carrier_negotiation_deadlines_secs[3]),
                    carrier_state: automatic.then_some(carrier_state),
                };
                let identity = session.trace_identity();
                drop(state);
                self.trace.record_lifecycle(
                    None,
                    Some(client_ip),
                    identity,
                    TraceLifecycleEvent::SessionReplayed,
                    None,
                    None,
                );
                return Ok(result);
            }
            let next_attempt = entry.carrier_attempt.saturating_add(1);
            if !carrier_request.is_automatic()
                || carrier_request.attempt() != Some(next_attempt)
                || matches!(
                    entry.carrier_phase,
                    CarrierChainPhase::CommittedPendingHealth | CarrierChainPhase::Healthy
                )
            {
                return Err(
                    if matches!(
                        entry.carrier_phase,
                        CarrierChainPhase::CommittedPendingHealth | CarrierChainPhase::Healthy
                    ) {
                        ManagerError::Committed
                    } else {
                        ManagerError::Protocol
                    },
                );
            }
            let Some(carrier) = entry
                .carrier_candidates
                .get(usize::from(next_attempt - 1))
                .copied()
            else {
                return Err(ManagerError::Protocol);
            };
            let candidate_count =
                u8::try_from(entry.carrier_candidates.len()).map_err(|_| ManagerError::Protocol)?;
            let deadline_index = carrier_attempt_deadline_index(candidate_count, next_attempt)
                .ok_or(ManagerError::Protocol)?;
            if entry.carrier_started_at.is_some_and(|started| {
                now.saturating_duration_since(started)
                    >= Duration::from_secs(
                        entry.profile.carrier_negotiation_deadlines_secs[deadline_index],
                    )
            }) {
                return Err(ManagerError::Protocol);
            }
            let old_session = entry.session.clone().ok_or(ManagerError::Authentication)?;
            let replacement = Replacement {
                profile: Arc::clone(&entry.profile),
                profile_key: old_session.profile_key(),
                trace_session_id: entry.trace_session_id,
                old_session,
                attempt: next_attempt,
                carrier,
                request: carrier_request,
                scores: entry.carrier_scores,
                learning_epoch: entry.carrier_learning_epoch,
                ip_learning_eligible,
                carrier_deadline_at: entry.carrier_deadline_at.ok_or(ManagerError::Protocol)?,
            };
            let _operator_admission = self.try_operator_admission()?;
            state
                .bootstraps
                .get_mut(&bootstrap_hash)
                .ok_or(ManagerError::Authentication)?
                .carrier_transitioning = true;
            drop(state);
            return self.replace_session(bootstrap_hash, client_ip, replacement);
        }

        if (carrier_request.is_automatic() && carrier_request.attempt() != Some(1))
            || (!carrier_request.is_automatic() && carrier_request.attempt().is_some())
        {
            return Err(ManagerError::Protocol);
        }
        let trace_session_id = entry.trace_session_id;
        let issued_profile = Arc::clone(&entry.profile);
        let issued_timeouts = entry.timeouts.clone();
        let profile = config
            .web
            .runtime
            .as_ref()
            .and_then(|runtime| matching_profile(runtime, &issued_profile))
            .filter(|profile| generation.proxy_shared.is_user_enabled(&profile.user))
            .ok_or(ManagerError::Authentication)?;
        let profile_key = profile_key(&profile);
        if carrier_request.is_automatic() && !profile.carrier_negotiation_enabled {
            return Err(ManagerError::Protocol);
        }
        let capability_selection =
            carrier_request.uses_capabilities() && profile.carrier_negotiation_enabled;
        let learning_policy = (
            config.web.carrier_negotiation_enabled() && config.web.carrier_learning,
            config.web.carrier_negotiation_aggressiveness,
            Duration::from_secs(config.web.timeouts.carrier_learning_secs),
        );
        let (candidates, scores, learning_epoch) = if capability_selection
            && profile.carrier_learning
        {
            let learning = self.learning.lock();
            if let Some(epoch) =
                learning.epoch_for_policy(learning_policy.0, learning_policy.1, learning_policy.2)
            {
                let (candidates, scores) = learning.rank(
                    now,
                    &profile.carriers,
                    carrier_request,
                    profile_key,
                    client_ip,
                    ip_learning_eligible,
                );
                (candidates, scores, Some(epoch))
            } else {
                (
                    profile
                        .carriers
                        .iter()
                        .copied()
                        .filter(|carrier| carrier_request.supports(*carrier))
                        .collect(),
                    [0; 4],
                    None,
                )
            }
        } else if capability_selection {
            (
                profile
                    .carriers
                    .iter()
                    .copied()
                    .filter(|carrier| carrier_request.supports(*carrier))
                    .collect(),
                [0; 4],
                None,
            )
        } else if carrier_request.uses_capabilities() && !carrier_request.supports(profile.carrier)
        {
            return Err(ManagerError::Protocol);
        } else {
            (vec![profile.carrier], [0; 4], None)
        };
        let Some(carrier) = candidates.first().copied() else {
            return Err(ManagerError::Protocol);
        };
        let _operator_admission = self.try_operator_admission()?;
        if !admit_initial(self, &mut state, now, client_ip, profile_key, &profile) {
            return Err(ManagerError::Limit);
        }
        let Some((session_token, session_hash)) = new_unique_token(&generation, &state) else {
            self.record_limit_hit();
            self.telemetry
                .record_rejection(crate::web::telemetry::WebRejectionReason::SessionCapacity);
            return Err(ManagerError::Limit);
        };
        let carrier_deadline_at = carrier_request
            .is_automatic()
            .then_some(now + Duration::from_secs(profile.carrier_negotiation_deadlines_secs[3]));
        let learning_context = learning_epoch.map(|epoch| CarrierLearningContext {
            profile_key,
            client_ip,
            class: carrier_request.class(),
            user_agent_hash: carrier_request.user_agent_hash(),
            epoch,
            ip_learning_eligible,
        });
        let session = WebSession::new(
            Arc::downgrade(self),
            session_hash,
            client_ip,
            trace_session_id,
            Arc::clone(&profile),
            profile_key,
            carrier,
            1,
            bootstrap_hash,
            carrier_deadline_at,
            carrier_request.class(),
            learning_context,
            carrier_request.is_automatic(),
            self.limits.clone(),
            issued_timeouts.clone(),
        );
        state.sessions.insert(session_hash, Arc::clone(&session));
        *state.sessions_per_ip.entry(client_ip).or_insert(0) += 1;
        *state.sessions_per_profile.entry(profile_key).or_insert(0) += 1;
        let (issuance_ip, candidate_count, user_agent, user_agent_id) = {
            let entry = state
                .bootstraps
                .get_mut(&bootstrap_hash)
                .ok_or(ManagerError::Authentication)?;
            entry.used = true;
            entry.body_digest = body_digest;
            entry.session_token = Zeroizing::new(session_token.clone());
            entry.session = Some(Arc::clone(&session));
            entry.carrier_request = Some(carrier_request);
            entry.carrier_candidates = candidates.into();
            entry.carrier_scores = scores;
            entry.carrier_attempt = 1;
            entry.carrier_phase = CarrierChainPhase::Provisional;
            entry.carrier_started_at = carrier_request.is_automatic().then_some(now);
            entry.carrier_deadline_at = carrier_deadline_at;
            entry.carrier_failures = [None; 3];
            entry.carrier_learning_epoch = learning_epoch.unwrap_or(0);
            entry.expires_at = now + Duration::from_secs(issued_timeouts.bootstrap_lifetime_secs);
            entry.session_client_ip = Some(client_ip);
            entry.session_ip_learning_eligible = ip_learning_eligible;
            (
                entry.issuance_ip,
                u8::try_from(entry.carrier_candidates.len()).unwrap_or(4),
                entry.user_agent.clone(),
                entry.user_agent_id,
            )
        };
        decrement_map(&mut state.bootstraps_per_ip, &issuance_ip);
        self.telemetry.record_session_created();
        let identity = session.trace_identity();
        let result = CreateResult {
            token: session_token,
            carrier,
            attempt: carrier_request.attempt(),
            candidate_count: carrier_request.is_automatic().then_some(candidate_count),
            deadline_secs: carrier_request
                .is_automatic()
                .then_some(profile.carrier_negotiation_deadlines_secs[3]),
            carrier_state: carrier_request
                .is_automatic()
                .then_some(CarrierChainPhase::Provisional.as_str()),
        };
        state.session_index.insert(
            trace_session_id,
            LiveSessionIndex {
                session_hash,
                bootstrap_hash,
                attempt: 1,
                user_agent,
                user_agent_id,
            },
        );
        drop(state);
        self.trace.record_carrier_lifecycle(
            client_ip,
            identity.clone(),
            TraceLifecycleEvent::CarrierClassified,
            carrier_request.class().as_str(),
            carrier,
            1,
            scores,
            None,
        );
        self.trace.record_carrier_lifecycle(
            client_ip,
            identity.clone(),
            TraceLifecycleEvent::CarrierSelected,
            carrier_request.class().as_str(),
            carrier,
            1,
            scores,
            None,
        );
        self.trace.record_lifecycle(
            None,
            Some(client_ip),
            identity,
            TraceLifecycleEvent::SessionCreated,
            None,
            None,
        );
        Ok(result)
    }
}

// Atomic pre-commit carrier replacement and frozen-policy transfer.
mod replacement;
