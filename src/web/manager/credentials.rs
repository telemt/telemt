use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::state::{
    Bootstrap, CarrierChainPhase, allow_rate, evict_oldest_unused_bootstrap, matching_profile,
    new_unique_token, remove_expired_locked,
};
use super::{BootstrapResult, ManagerError, TOKEN_BYTES, TokenHash, WebProcessRuntime};
use crate::config::WebRuntimeProfile;
use crate::maestro::generation::RuntimeGeneration;
use crate::web::session::WebSession;

impl WebProcessRuntime {
    /// Issues a one-use bootstrap credential for an active compatible profile.
    #[cfg(test)]
    pub(crate) fn issue_bootstrap(
        &self,
        profile: Arc<WebRuntimeProfile>,
        client_ip: IpAddr,
    ) -> std::result::Result<BootstrapResult, ManagerError> {
        let generation = self.active_generation();
        self.issue_bootstrap_inner(&generation, profile, client_ip, None)
    }

    /// Issues one bootstrap against the generation that selected the bridge profile.
    #[cfg(test)]
    pub(crate) fn issue_bootstrap_for_generation(
        &self,
        generation: &Arc<RuntimeGeneration>,
        profile: Arc<WebRuntimeProfile>,
        client_ip: IpAddr,
    ) -> std::result::Result<BootstrapResult, ManagerError> {
        self.issue_bootstrap_inner(generation, profile, client_ip, None)
    }

    /// Issues one bridge bootstrap with bounded non-secret request metadata.
    pub(crate) fn issue_bootstrap_for_request(
        &self,
        generation: &Arc<RuntimeGeneration>,
        profile: Arc<WebRuntimeProfile>,
        client_ip: IpAddr,
        user_agent: Option<&str>,
    ) -> std::result::Result<BootstrapResult, ManagerError> {
        self.issue_bootstrap_inner(generation, profile, client_ip, user_agent)
    }

    fn issue_bootstrap_inner(
        &self,
        generation: &Arc<RuntimeGeneration>,
        profile: Arc<WebRuntimeProfile>,
        client_ip: IpAddr,
        user_agent: Option<&str>,
    ) -> std::result::Result<BootstrapResult, ManagerError> {
        let config = generation.config();
        let profile = config
            .web
            .runtime
            .as_ref()
            .and_then(|runtime| matching_profile(runtime, &profile))
            .ok_or(ManagerError::Authentication)?;
        if !config.web.enabled || !generation.proxy_shared.is_user_enabled(&profile.user) {
            return Err(ManagerError::Closed);
        }
        let _operator_admission = self.try_operator_admission()?;
        let now = Instant::now();
        let mut state = self.state.lock();
        remove_expired_locked(&mut state, now);
        state.apply_issuance_policy(generation.id, config.web.enabled);
        if state.closed
            || !state.issuance_enabled
            || state
                .bootstraps_per_ip
                .get(&client_ip)
                .copied()
                .unwrap_or(0)
                >= self.limits.max_bootstraps_per_ip
            || !allow_rate(
                &mut state.bootstrap_rate,
                now,
                self.limits.new_bootstraps_per_minute,
                self.limits.new_bootstraps_burst,
            )
        {
            self.limit_hits.fetch_add(1, Ordering::Relaxed);
            return Err(ManagerError::Limit);
        }
        if state.bootstraps.len() >= self.limits.max_bootstraps_global
            && !evict_oldest_unused_bootstrap(&mut state)
        {
            self.limit_hits.fetch_add(1, Ordering::Relaxed);
            return Err(ManagerError::Limit);
        }
        let Some((token, hash)) = new_unique_token(generation, &state) else {
            self.limit_hits.fetch_add(1, Ordering::Relaxed);
            return Err(ManagerError::Limit);
        };
        let trace_session_id = self.trace.next_session_id();
        let (user_agent, user_agent_id) = bounded_user_agent(user_agent);
        state.bootstraps.insert(
            hash,
            Bootstrap {
                expires_at: now + Duration::from_secs(config.web.timeouts.bootstrap_lifetime_secs),
                issued_at: now,
                issuance_ip: client_ip,
                profile,
                timeouts: config.web.timeouts.clone(),
                trace_session_id,
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
                close_requested: false,
                session_client_ip: None,
                session_ip_learning_eligible: false,
                used: false,
            },
        );
        *state.bootstraps_per_ip.entry(client_ip).or_insert(0) += 1;
        let profile = state
            .bootstraps
            .get(&hash)
            .map(|entry| Arc::clone(&entry.profile))
            .ok_or(ManagerError::Closed)?;
        drop(state);
        self.trace.record_profile_lifecycle(
            client_ip,
            Some(trace_session_id),
            &profile,
            crate::web::trace::TraceLifecycleEvent::BridgeIssued,
            None,
            None,
        );
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
            .filter(|entry| entry.profile.host == host && now <= entry.expires_at)
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
        self.state
            .lock()
            .sessions
            .get(&hash)
            .cloned()
            .filter(|session| session.matches_host(host))
            .ok_or(ManagerError::Authentication)
    }

    /// Closes a live token and accepts bounded tombstone retries.
    pub(crate) fn close_token(
        &self,
        hash: TokenHash,
        host: &str,
    ) -> std::result::Result<(), ManagerError> {
        let mut state = self.state.lock();
        let session = state
            .sessions
            .get(&hash)
            .filter(|session| session.matches_host(host))
            .cloned();
        if session.is_some() {
            for bootstrap in state.bootstraps.values_mut() {
                if bootstrap
                    .session
                    .as_ref()
                    .is_some_and(|current| current.token_hash() == hash)
                {
                    bootstrap.close_requested = true;
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
            session.close();
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
