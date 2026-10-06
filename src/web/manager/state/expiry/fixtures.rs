use crate::config::WebSecretMode;
use crate::proxy::user_admission::{UserAdmissionAuthority, credential_id_from_hex};
use crate::web::telemetry::WebCarrierSelectionDisposition;

struct Fixture {
    authority: Arc<UserAdmissionAuthority>,
    profile: Arc<WebRuntimeProfile>,
}

impl Fixture {
    fn new() -> Self {
        let secret = "0123456789abcdef0123456789abcdef";
        let authority = UserAdmissionAuthority::new();
        authority.apply_config(
            &HashMap::from([("alice".to_string(), secret.to_string())]),
            &HashMap::new(),
        );
        Self {
            authority,
            profile: Arc::new(WebRuntimeProfile {
                host: "proxy.example.com".to_string(),
                public_addr: "203.0.113.10:443".parse().unwrap(),
                user: "alice".to_string(),
                secret_mode: WebSecretMode::Plain,
                carrier: WebCarrier::Https,
                carrier_negotiation_enabled: false,
                carrier_learning: true,
                carriers: Arc::from([WebCarrier::Https]),
                carrier_negotiation_deadlines_secs: [3, 5, 8, 12],
                capability: [7; 32],
                credential_id: credential_id_from_hex(secret).unwrap(),
                key_fingerprint: "0000000000000000".to_string(),
                max_sessions: 1024,
                max_streams: 1024,
                max_streams_per_session: 1,
            }),
        }
    }

    fn bootstrap(&self, issued_at: Instant, expires_at: Instant, flags: u8) -> Bootstrap {
        Bootstrap {
            user_registration: self.authority.register_legacy("alice").unwrap(),
            expires_at,
            issued_at,
            issuance_ip: "192.0.2.10".parse().unwrap(),
            profile: Arc::clone(&self.profile),
            timeouts: WebTimeoutsConfig::default(),
            trace_session_id: 1,
            bridge_diagnostics_enabled: false,
            bridge_diagnostic_events: 0,
            user_agent: None,
            user_agent_id: None,
            body_digest: [0; 32],
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
            carrier_learning_disposition: WebCarrierSelectionDisposition::ProfileDisabled,
            close_requested: false,
            session_client_ip: None,
            session_ip_learning_eligible: false,
            used: flags & 1 != 0,
            recovery: flags & 2 != 0,
            predecessor_session_id: None,
        }
    }
}

fn insert_bootstrap(state: &mut ManagerState, hash: TokenHash, bootstrap: Bootstrap) {
    remove_bootstrap_locked(state, hash);
    let expires_at = bootstrap.expires_at;
    state.bootstrap_expiry = Some(state.bootstrap_expiry.unwrap_or(expires_at).min(expires_at));
    if !bootstrap.used {
        *state.bootstraps_per_ip.entry(bootstrap.issuance_ip).or_insert(0) += 1;
    }
    state.bootstraps.insert(hash, bootstrap);
}

fn insert_closed_token(state: &mut ManagerState, hash: TokenHash, expires_at: Instant) {
    state.closed_token_expiry = Some(state.closed_token_expiry.unwrap_or(expires_at).min(expires_at));
    state.closed_tokens.insert(hash, ClosedToken {
        expires_at,
        host: "proxy.example.com".to_string(),
        carrier: WebCarrier::Https,
    });
}
