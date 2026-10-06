use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::state::{
    Bootstrap, CarrierChainPhase, allow_rate, evict_oldest_unused_bootstrap, matching_profile,
    new_unique_token, profile_key, remove_expired_locked,
};
use super::{BootstrapResult, ManagerError, TOKEN_BYTES, TokenHash, TokenKind, WebProcessRuntime};
use crate::config::WebRuntimeProfile;
use crate::maestro::generation::RuntimeGeneration;
use crate::web::session::{SessionCloseReason, WebSession};
use crate::web::telemetry::{WebBridgeRecoveryEvent, WebRejectionReason};

impl WebProcessRuntime {
    /// Issues a one-use bootstrap credential for an active compatible profile.
    #[cfg(test)]
    pub(crate) fn issue_bootstrap(
        &self,
        profile: Arc<WebRuntimeProfile>,
        client_ip: IpAddr,
    ) -> std::result::Result<BootstrapResult, ManagerError> {
        let generation = self.active_generation();
        self.issue_bootstrap_inner(&generation, profile, client_ip, None, false, None)
    }

    /// Issues one bootstrap against the generation that selected the bridge profile.
    #[cfg(test)]
    pub(crate) fn issue_bootstrap_for_generation(
        &self,
        generation: &Arc<RuntimeGeneration>,
        profile: Arc<WebRuntimeProfile>,
        client_ip: IpAddr,
    ) -> std::result::Result<BootstrapResult, ManagerError> {
        self.issue_bootstrap_inner(generation, profile, client_ip, None, false, None)
    }

    /// Issues one bridge bootstrap with bounded non-secret request metadata.
    pub(crate) fn issue_bootstrap_for_request(
        &self,
        generation: &Arc<RuntimeGeneration>,
        profile: Arc<WebRuntimeProfile>,
        client_ip: IpAddr,
        user_agent: Option<&str>,
    ) -> std::result::Result<BootstrapResult, ManagerError> {
        self.issue_bootstrap_inner(generation, profile, client_ip, user_agent, false, None)
    }

    /// Issues one recovery bootstrap with the same positive-only admission boundary.
    pub(crate) fn issue_recovery_bootstrap_for_request(
        &self,
        generation: &Arc<RuntimeGeneration>,
        profile: Arc<WebRuntimeProfile>,
        client_ip: IpAddr,
        user_agent: Option<&str>,
        predecessor_session_id: Option<u64>,
    ) -> std::result::Result<BootstrapResult, ManagerError> {
        self.issue_bootstrap_inner(
            generation,
            profile,
            client_ip,
            user_agent,
            true,
            predecessor_session_id,
        )
    }

    fn issue_bootstrap_inner(
        &self,
        generation: &Arc<RuntimeGeneration>,
        profile: Arc<WebRuntimeProfile>,
        client_ip: IpAddr,
        user_agent: Option<&str>,
        recovery: bool,
        predecessor_session_id: Option<u64>,
    ) -> std::result::Result<BootstrapResult, ManagerError> {
        let config = generation.config();
        let profile = config
            .web
            .runtime
            .as_ref()
            .and_then(|runtime| matching_profile(runtime, &profile))
            .ok_or(ManagerError::Authentication)?;
        if !config.web.enabled {
            self.telemetry
                .record_rejection(WebRejectionReason::ConfigDisabled);
            return Err(ManagerError::Closed);
        }
        let _operator_admission = self.try_operator_admission()?;
        let now = Instant::now();
        let mut state = self.state.lock();
        let expired_recoveries = remove_expired_locked(&mut state, now);
        self.telemetry.record_bridge_recovery_count(
            WebBridgeRecoveryEvent::ExpiredUnused,
            expired_recoveries,
        );
        state.apply_issuance_policy(generation.id, config.web.enabled);
        if state.closed || !state.issuance_enabled {
            self.record_limit_hit();
            self.telemetry
                .record_rejection(WebRejectionReason::RuntimeClosed);
            return Err(ManagerError::Closed);
        }
        if state
            .bootstraps_per_ip
            .get(&client_ip)
            .copied()
            .unwrap_or(0)
            >= self.limits.max_bootstraps_per_ip
        {
            self.record_limit_hit();
            self.telemetry
                .record_rejection(WebRejectionReason::BootstrapCapacity);
            return Err(ManagerError::Limit);
        }
        let global_capacity_full = state.bootstraps.len() >= self.limits.max_bootstraps_global;
        if global_capacity_full && !state.bootstraps.values().any(|bootstrap| !bootstrap.used) {
            self.record_limit_hit();
            self.telemetry
                .record_rejection(WebRejectionReason::BootstrapCapacity);
            return Err(ManagerError::Limit);
        }
        let Some((token, hash)) = new_unique_token(
            generation,
            &state,
            &self.token_authenticator,
            TokenKind::Bootstrap,
        ) else {
            self.record_limit_hit();
            self.telemetry
                .record_rejection(WebRejectionReason::BootstrapCapacity);
            return Err(ManagerError::Limit);
        };
        let Some(mut user_publication) = generation
            .proxy_shared
            .claim_authenticated_user(&profile.user, profile.credential_id)
        else {
            self.telemetry
                .record_rejection(WebRejectionReason::UserDisabled);
            return Err(ManagerError::Closed);
        };
        let Some(user_registration) = user_publication.take_registration() else {
            return Err(ManagerError::Closed);
        };
        if !allow_rate(
            &mut state.bootstrap_rate,
            now,
            self.limits.new_bootstraps_per_minute,
            self.limits.new_bootstraps_burst,
        ) {
            self.record_limit_hit();
            self.telemetry
                .record_rejection(WebRejectionReason::BootstrapRate);
            return Err(ManagerError::Limit);
        }
        let evicted_bootstrap = global_capacity_full
            .then(|| evict_oldest_unused_bootstrap(&mut state))
            .flatten();
        if global_capacity_full && evicted_bootstrap.is_none() {
            return Err(ManagerError::Limit);
        }
        let trace_session_id = self.trace.next_session_id();
        let bridge_diagnostics_enabled = config.web.debug.bridge_diagnostics_enabled();
        let (user_agent, user_agent_id) = bounded_user_agent(user_agent);
        let issued_profile = Arc::clone(&profile);
        let expires_at = now + Duration::from_secs(config.web.timeouts.bootstrap_lifetime_secs);
        state.bootstrap_expiry = Some(state.bootstrap_expiry.unwrap_or(expires_at).min(expires_at));
        state.bootstraps.insert(
            hash,
            Bootstrap {
                user_registration,
                expires_at,
                issued_at: now,
                issuance_ip: client_ip,
                profile,
                timeouts: config.web.timeouts.clone(),
                trace_session_id,
                bridge_diagnostics_enabled,
                bridge_diagnostic_events: 0,
                user_agent,
                user_agent_id,
                body_digest: [0; TOKEN_BYTES],
                session_token: Zeroizing::new(String::new()),
                session: None,
                carrier_request: None,
                carrier_candidates: Arc::from([]),
                carrier_scores: [0; 4],
                carrier_attempt: 0,
                carrier_transitioning: false,
                carrier_phase: CarrierChainPhase::Provisional,
                carrier_started_at: None,
                carrier_deadline_at: None,
                carrier_failures: [None; 3],
                carrier_learning_epoch: 0,
                carrier_learning_disposition:
                    crate::web::telemetry::WebCarrierSelectionDisposition::ProfileDisabled,
                close_requested: false,
                session_client_ip: None,
                session_ip_learning_eligible: false,
                used: false,
                recovery,
                predecessor_session_id,
            },
        );
        *state.bootstraps_per_ip.entry(client_ip).or_insert(0) += 1;
        user_publication.commit();
        drop(state);
        drop(evicted_bootstrap);
        if recovery {
            self.telemetry
                .record_bridge_recovery(WebBridgeRecoveryEvent::BootstrapIssued);
        }
        if recovery {
            self.trace.record_lifecycle_with_context(
                None,
                Some(client_ip),
                crate::web::trace::TraceIdentity::from_optional_profile(
                    Some(trace_session_id),
                    &issued_profile,
                ),
                crate::web::trace::TraceLifecycleEvent::BridgeIssued,
                None,
                None,
                crate::web::trace::TraceLifecycleContext {
                    peer_gap_ms: None,
                    predecessor_session_id,
                },
            );
        } else {
            self.trace.record_profile_lifecycle(
                client_ip,
                Some(trace_session_id),
                &issued_profile,
                crate::web::trace::TraceLifecycleEvent::BridgeIssued,
                None,
                None,
            );
        }
        Ok(BootstrapResult {
            token,
            trace_session_id,
        })
    }

    /// Resolves bootstrap trace identity and its issuance-frozen body timeout.
    pub(crate) fn bootstrap_trace_identity(
        &self,
        hash: TokenHash,
        host: &str,
    ) -> Option<(u64, Arc<WebRuntimeProfile>, Duration)> {
        let now = Instant::now();
        self.state
            .lock()
            .bootstraps
            .get(&hash)
            .filter(|entry| {
                entry.profile.host == host
                    && now <= entry.expires_at
                    && !entry.user_registration.is_cancelled()
            })
            .map(|entry| {
                (
                    entry.trace_session_id,
                    Arc::clone(&entry.profile),
                    entry.session.as_ref().map_or_else(
                        || Duration::from_secs(entry.timeouts.body_secs),
                        |session| Duration::from_secs(session.timeouts().body_secs),
                    ),
                )
            })
    }

    /// Resolves an authenticated session token.
    pub(crate) fn get_session(
        &self,
        hash: TokenHash,
        host: &str,
    ) -> std::result::Result<Arc<WebSession>, ManagerError> {
        let state = self.state.lock();
        let session = state
            .sessions
            .get(&hash)
            .cloned()
            .filter(|session| session.matches_host(host));
        let retired_carrier = state
            .closed_tokens
            .get(&hash)
            .filter(|closed| closed.host == host)
            .map(|closed| closed.carrier);
        drop(state);
        if let Some(session) = session {
            if session.close_if_cancelled() {
                return Err(ManagerError::Closed);
            }
            return Ok(session);
        }
        if let Some(carrier) = retired_carrier {
            self.telemetry.record_session_observation(
                carrier,
                crate::web::telemetry::WebSessionLifecycleObservation::RequestAfterClose,
            );
        }
        Err(ManagerError::Authentication)
    }

    /// Resolves a current bearer only when it belongs to the recovering profile.
    pub(crate) fn bridge_recovery_session(
        &self,
        hash: TokenHash,
        host: &str,
        profile: &WebRuntimeProfile,
    ) -> Option<Arc<WebSession>> {
        let expected_profile = profile_key(profile);
        let session = self
            .state
            .lock()
            .sessions
            .get(&hash)
            .filter(|session| {
                session.matches_host(host) && session.profile_key() == expected_profile
            })
            .cloned();
        session.filter(|session| !session.close_if_cancelled())
    }

    /// Closes a live token and accepts bounded tombstone retries.
    pub(crate) fn close_token(
        &self,
        hash: TokenHash,
        host: &str,
        failure: Option<super::CarrierFailure>,
    ) -> std::result::Result<(), ManagerError> {
        let mut state = self.state.lock();
        let session = state
            .sessions
            .get(&hash)
            .filter(|session| session.matches_host(host))
            .cloned();
        let mut failure_phase = None;
        if let Some(session) = &session {
            for bootstrap in state.bootstraps.values_mut() {
                if bootstrap
                    .session
                    .as_ref()
                    .is_some_and(|current| current.token_hash() == hash)
                {
                    bootstrap.close_requested = true;
                    failure_phase = Some(
                        if matches!(
                            bootstrap.carrier_phase,
                            CarrierChainPhase::CommittedPendingHealth | CarrierChainPhase::Healthy
                        ) || session.is_carrier_committed()
                        {
                            crate::web::telemetry::WebCarrierFailurePhase::Committed
                        } else {
                            crate::web::telemetry::WebCarrierFailurePhase::Provisional
                        },
                    );
                    break;
                }
            }
        }
        let closed = state
            .closed_tokens
            .get(&hash)
            .is_some_and(|closed| closed.host == host);
        drop(state);
        if let Some(session) = session {
            if session.close(SessionCloseReason::ClientDelete).accepted()
                && let (Some(failure), Some(phase)) = (failure, failure_phase)
            {
                self.telemetry
                    .record_carrier_failure(session.carrier(), phase, failure);
            }
            return Ok(());
        }
        closed.then_some(()).ok_or(ManagerError::Authentication)
    }
}

fn bounded_user_agent(value: Option<&str>) -> (Option<Arc<str>>, Option<[u8; 16]>) {
    const DISPLAY_BYTES: usize = 256;
    const HASH_CONTEXT: &[u8] = b"telemt-web-user-agent-v1\0";
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return (None, None);
    };
    let mut digest = Sha256::new();
    digest.update(HASH_CONTEXT);
    digest.update(value.as_bytes());
    let digest = digest.finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    let mut display = String::with_capacity(value.len().min(DISPLAY_BYTES));
    for character in value.chars() {
        let character = if character.is_control() {
            '\u{fffd}'
        } else {
            character
        };
        if display.len().saturating_add(character.len_utf8()) > DISPLAY_BYTES {
            break;
        }
        display.push(character);
    }
    (Some(Arc::from(display)), Some(id))
}
