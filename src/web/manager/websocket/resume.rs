use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::{
    WebProcessRuntime, WebSocketClaimKey, WebSocketConnection, WebSocketEntry, WebSocketKind,
    WebSocketPhase,
};
use crate::web::session::WebSession;

fn same_profile_owner(
    owner: super::super::ProfileKey,
    session_owner: super::super::ProfileKey,
) -> bool {
    owner == session_owner
}

impl WebSocketConnection {
    /// Confirms this active socket remains the exact registry owner of a committed session.
    pub(crate) fn is_current_resume_owner(
        &self,
        session: &WebSession,
        kind: WebSocketKind,
    ) -> bool {
        if session.token_hash() != self.entry.claim.session_hash
            || session.trace_session_id() != self.entry.session_id
            || !same_profile_owner(self.entry.owner, session.profile_key())
            || !session.is_resume_probe_eligible()
            || !session.current_generation_matches()
            || self.entry.kind != kind
        {
            return false;
        }
        self.runtime.upgrade().is_some_and(|runtime| {
            runtime.is_current_resume_owner(self.entry.id, &self.entry, session, kind)
        })
    }
}

impl WebProcessRuntime {
    fn is_current_resume_owner(
        &self,
        id: u64,
        expected: &Arc<WebSocketEntry>,
        session: &WebSession,
        kind: WebSocketKind,
    ) -> bool {
        let claim = WebSocketClaimKey {
            session_hash: session.token_hash(),
            kind,
        };
        let registry = self.websockets.lock();
        let Some(entry) = registry.entries.get(&id) else {
            return false;
        };
        !registry.closed
            && registry.claims.get(&claim) == Some(&id)
            && Arc::ptr_eq(entry, expected)
            && entry.session_id == session.trace_session_id()
            && same_profile_owner(entry.owner, session.profile_key())
            && entry.claim.session_hash == session.token_hash()
            && entry.kind == kind
            && entry.phase.load(Ordering::Acquire) == WebSocketPhase::Active as u8
            && !entry.closing.load(Ordering::Acquire)
            && !entry.cancel.is_cancelled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{WebRuntimeProfile, WebRuntimeProfileShared, WebSecretMode};

    #[test]
    fn host_aliases_sharing_profile_policy_keep_distinct_resume_owners() {
        let shared = Arc::new(WebRuntimeProfileShared {
            derivation_context: [0; 32],
            public_addr: "203.0.113.10:443".parse().unwrap(),
            user: "default".into(),
            secret_mode: WebSecretMode::Plain,
            carrier: crate::config::WebCarrier::Websocket,
            carrier_negotiation_enabled: true,
            carrier_learning: true,
            carriers: Arc::from([
                crate::config::WebCarrier::Websocket,
                crate::config::WebCarrier::Https,
            ]),
            carrier_negotiation_deadlines_secs: [3, 5, 8, 12],
            credential_id: [0; 16],
            key_fingerprint: "0000000000000000".into(),
            max_sessions: 2,
            max_streams: 2,
            max_streams_per_session: 1,
        });
        let profile = WebRuntimeProfile {
            host: "proxy.example.com".into(),
            capability: [7; 32],
            shared: Arc::clone(&shared),
        };
        let alias = WebRuntimeProfile {
            host: "alias.example.com".into(),
            capability: [8; 32],
            shared,
        };
        assert!(Arc::ptr_eq(&profile.shared, &alias.shared));
        let owner = crate::web::manager::state::profile_key(&profile);
        let alias_owner = crate::web::manager::state::profile_key(&alias);
        assert_ne!(owner, alias_owner);
        assert!(!same_profile_owner(owner, alias_owner));
    }
}
