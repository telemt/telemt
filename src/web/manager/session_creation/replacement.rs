use super::*;

impl WebProcessRuntime {
    pub(super) fn replace_session(
        self: &Arc<Self>,
        bootstrap_hash: TokenHash,
        client_ip: IpAddr,
        replacement: Replacement,
    ) -> std::result::Result<CreateResult, ManagerError> {
        if !replacement.old_session.begin_carrier_supersede() {
            let committed = replacement.old_session.is_carrier_committed();
            self.cancel_replacement(bootstrap_hash, &replacement.old_session);
            return Err(if committed {
                ManagerError::Committed
            } else {
                ManagerError::Closed
            });
        }
        let generation = self.active_generation();
        let config = generation.config();
        let now = Instant::now();
        let mut state = self.state.lock();
        remove_expired_locked(&mut state, now);
        state.apply_issuance_policy(generation.id, config.web.enabled);
        let valid = state.bootstraps.get(&bootstrap_hash).is_some_and(|entry| {
            entry.carrier_transitioning
                && entry.carrier_phase == CarrierChainPhase::Provisional
                && !entry.close_requested
                && entry.carrier_attempt.saturating_add(1) == replacement.attempt
                && now < replacement.carrier_deadline_at
                && entry
                    .session
                    .as_ref()
                    .is_some_and(|session| Arc::ptr_eq(session, &replacement.old_session))
        }) && state
            .sessions
            .get(&replacement.old_session.token_hash())
            .is_some_and(|session| Arc::ptr_eq(session, &replacement.old_session));
        if !valid
            || state.closed
            || !state.issuance_enabled
            || !generation
                .proxy_shared
                .is_user_enabled(&replacement.profile.user)
        {
            drop(state);
            self.cancel_replacement(bootstrap_hash, &replacement.old_session);
            return Err(ManagerError::Closed);
        }
        let Some((session_token, session_hash)) = new_unique_token(&generation, &state) else {
            self.record_limit_hit();
            self.telemetry
                .record_rejection(crate::web::telemetry::WebRejectionReason::SessionCapacity);
            drop(state);
            self.cancel_replacement(bootstrap_hash, &replacement.old_session);
            return Err(ManagerError::Limit);
        };
        let learning_context = (replacement.profile.carrier_learning
            && replacement.learning_epoch != 0)
            .then_some(CarrierLearningContext {
                profile_key: replacement.profile_key,
                client_ip,
                class: replacement.request.class(),
                user_agent_hash: replacement.request.user_agent_hash(),
                epoch: replacement.learning_epoch,
                ip_learning_eligible: replacement.ip_learning_eligible,
            });
        let session = WebSession::new(
            Arc::downgrade(self),
            session_hash,
            client_ip,
            replacement.trace_session_id,
            Arc::clone(&replacement.profile),
            replacement.profile_key,
            replacement.carrier,
            replacement.attempt,
            bootstrap_hash,
            Some(replacement.carrier_deadline_at),
            replacement.request.class(),
            learning_context,
            true,
            self.limits.clone(),
            replacement.old_session.timeouts().clone(),
        );
        let Some(supersede) = replacement.old_session.prepare_carrier_supersede() else {
            drop(state);
            self.cancel_replacement(bootstrap_hash, &replacement.old_session);
            session.close();
            return Err(ManagerError::Closed);
        };
        let old_hash = replacement.old_session.token_hash();
        state.sessions.remove(&old_hash);
        remember_closed_token_locked(
            &mut state,
            old_hash,
            &replacement.profile.host,
            Duration::from_secs(replacement.old_session.timeouts().bootstrap_lifetime_secs),
            self.limits.max_sessions_global.saturating_mul(16),
        );
        state.sessions.insert(session_hash, Arc::clone(&session));
        let entry = state
            .bootstraps
            .get_mut(&bootstrap_hash)
            .ok_or(ManagerError::Authentication)?;
        entry.session_token = Zeroizing::new(session_token.clone());
        entry.session = Some(Arc::clone(&session));
        entry.carrier_request = Some(replacement.request);
        entry.carrier_attempt = replacement.attempt;
        entry.carrier_transitioning = false;
        entry.carrier_phase = CarrierChainPhase::Provisional;
        if let Some(slot) = entry
            .carrier_failures
            .get_mut(usize::from(replacement.attempt.saturating_sub(2)))
        {
            *slot = Some(replacement.old_session.carrier());
        }
        self.telemetry.record_session_created();
        self.telemetry.record_session_closed();
        let result = CreateResult {
            token: session_token,
            carrier: replacement.carrier,
            attempt: Some(replacement.attempt),
            candidate_count: Some(u8::try_from(entry.carrier_candidates.len()).unwrap_or(4)),
            deadline_secs: Some(entry.profile.carrier_negotiation_deadlines_secs[3]),
            carrier_state: Some(CarrierChainPhase::Provisional.as_str()),
        };
        if let Some(index) = state.session_index.get_mut(&replacement.trace_session_id)
            && index.session_hash == old_hash
        {
            index.session_hash = session_hash;
            index.bootstrap_hash = bootstrap_hash;
            index.attempt = replacement.attempt;
        }
        let identity = session.trace_identity();
        let old_identity = replacement.old_session.trace_identity();
        drop(state);
        supersede.finish();
        self.trace.record_carrier_lifecycle(
            client_ip,
            old_identity.clone(),
            TraceLifecycleEvent::CarrierFailed,
            replacement.request.class().as_str(),
            replacement.old_session.carrier(),
            replacement.attempt - 1,
            replacement.scores,
            replacement
                .request
                .failure()
                .map(|failure| failure.as_str()),
        );
        self.trace.record_carrier_lifecycle(
            client_ip,
            old_identity,
            TraceLifecycleEvent::CarrierSuperseded,
            replacement.request.class().as_str(),
            replacement.old_session.carrier(),
            replacement.attempt - 1,
            replacement.scores,
            replacement
                .request
                .failure()
                .map(|failure| failure.as_str()),
        );
        self.trace.record_carrier_lifecycle(
            client_ip,
            identity.clone(),
            TraceLifecycleEvent::CarrierSelected,
            replacement.request.class().as_str(),
            replacement.carrier,
            replacement.attempt,
            replacement.scores,
            None,
        );
        self.trace.record_lifecycle(
            None,
            Some(client_ip),
            identity,
            TraceLifecycleEvent::SessionCreated,
            None,
            replacement
                .request
                .failure()
                .map(|failure| failure.as_str()),
        );
        Ok(result)
    }
}
