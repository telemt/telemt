use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use dashmap::DashMap;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::proxy::direct_buffer_budget::{DirectBufferBudget, fallback_direct_buffer_hard_limit};
use crate::proxy::handshake::{AuthProbeSaturationState, AuthProbeState};
use crate::proxy::middle_relay::{DesyncDedupRotationState, RelayIdleCandidateRegistry};
use crate::proxy::pending_handshake::PendingHandshakeLimiter;
use crate::proxy::traffic_limiter::TrafficLimiter;
use crate::proxy::user_admission::{
    UserAdmissionAuthority, UserAdmissionPublication, UserCredentialId, UserIncarnation,
    UserMutationResult, UserSessionRegistration,
};
use crate::slot_budget::SlotBudget;

const HANDSHAKE_RECENT_USER_RING_LEN: usize = 64;
const MASKING_FALLBACK_MAX_CONCURRENT: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConntrackCloseReason {
    NormalEof,
    Timeout,
    Pressure,
    Reset,
    Other,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ConntrackCloseEvent {
    pub(crate) src: SocketAddr,
    pub(crate) dst: SocketAddr,
    pub(crate) reason: ConntrackCloseReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConntrackClosePublishResult {
    Sent,
    Disabled,
    QueueFull,
    QueueClosed,
}

/// Controls whether a relay tuple maps to a real kernel conntrack entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConntrackClosePolicy {
    /// Publish closure for a tuple backed by an accepted kernel TCP flow.
    Publish,
    /// Suppress closure for a virtual transport tuple with no kernel flow.
    Suppress,
}

pub(crate) struct HandshakeSharedState {
    pub(crate) auth_probe: DashMap<IpAddr, AuthProbeState>,
    /// Exact capacity authority for the authentication probe registry.
    pub(crate) auth_probe_slots: SlotBudget,
    pub(crate) auth_probe_saturation: Mutex<Option<AuthProbeSaturationState>>,
    pub(crate) auth_probe_eviction_hasher: RandomState,
    pub(crate) invalid_secret_warned: Mutex<HashSet<(String, String)>>,
    pub(crate) unknown_sni_warn_next_allowed: Mutex<Option<Instant>>,
    /// Stable credential hints keyed by exact peer IP.
    pub(crate) sticky_user_by_ip: DashMap<IpAddr, u64>,
    /// Exact capacity authority for peer-IP credential hints.
    pub(crate) sticky_user_by_ip_slots: SlotBudget,
    /// Stable credential hints keyed by bounded peer network prefix.
    pub(crate) sticky_user_by_ip_prefix: DashMap<u64, u64>,
    /// Exact capacity authority for peer-prefix credential hints.
    pub(crate) sticky_user_by_ip_prefix_slots: SlotBudget,
    /// Stable credential hints keyed by normalized SNI hash.
    pub(crate) sticky_user_by_sni_hash: DashMap<u64, u64>,
    /// Exact capacity authority for SNI credential hints.
    pub(crate) sticky_user_by_sni_hash_slots: SlotBudget,
    /// Bounded recent credential-hint ring used as an authentication fallback.
    pub(crate) recent_user_ring: Box<[AtomicU64]>,
    pub(crate) recent_user_ring_seq: AtomicU64,
    pub(crate) auth_expensive_checks_total: AtomicU64,
    pub(crate) auth_budget_exhausted_total: AtomicU64,
}

pub(crate) struct MiddleRelaySharedState {
    pub(crate) desync_dedup: DashMap<u64, Instant>,
    pub(crate) desync_dedup_previous: DashMap<u64, Instant>,
    pub(crate) desync_hasher: RandomState,
    pub(crate) desync_full_cache_last_emit_at: Mutex<Option<Instant>>,
    pub(crate) desync_dedup_rotation_state: Mutex<DesyncDedupRotationState>,
    pub(crate) relay_idle_registry: RelayIdleCandidateRegistry,
    pub(crate) relay_idle_mark_seq: AtomicU64,
}

pub(crate) struct ProxySharedState {
    pub(crate) handshake: HandshakeSharedState,
    pub(crate) middle_relay: MiddleRelaySharedState,
    pub(crate) traffic_limiter: Arc<TrafficLimiter>,
    pub(crate) direct_buffer_budget: Arc<DirectBufferBudget>,
    user_admission: Arc<UserAdmissionAuthority>,
    pub(crate) conntrack_pressure_active: AtomicBool,
    pub(crate) conntrack_close_tx: Mutex<Option<mpsc::Sender<ConntrackCloseEvent>>>,
    masking_fallback_permits: Arc<Semaphore>,
    pub(crate) pending_handshakes: Arc<PendingHandshakeLimiter>,
}

impl ProxySharedState {
    pub(crate) fn new() -> Arc<Self> {
        Self::new_with_direct_buffer_budget(DirectBufferBudget::new(
            fallback_direct_buffer_hard_limit(),
        ))
    }

    /// Creates process state with the startup-resolved Direct buffer envelope.
    pub(crate) fn new_with_direct_buffer_budget(
        direct_buffer_budget: Arc<DirectBufferBudget>,
    ) -> Arc<Self> {
        Self::new_with_direct_buffer_budget_and_user_admission(
            direct_buffer_budget,
            UserAdmissionAuthority::new(),
        )
    }

    /// Creates generation state around one process-owned user authority.
    pub(crate) fn new_with_direct_buffer_budget_and_user_admission(
        direct_buffer_budget: Arc<DirectBufferBudget>,
        user_admission: Arc<UserAdmissionAuthority>,
    ) -> Arc<Self> {
        Self::new_with_process_authorities(
            direct_buffer_budget,
            TrafficLimiter::new(),
            user_admission,
            Arc::new(PendingHandshakeLimiter::default()),
        )
    }

    /// Creates generation-local caches around process-owned data-plane authorities.
    ///
    /// `pending_handshakes` is process-owned as well: a drain-reload passes the
    /// old generation's limiter on, so handshakes still in progress in the old
    /// generation keep counting against `server.max_pending_handshakes_per_ip`.
    pub(crate) fn new_with_process_authorities(
        direct_buffer_budget: Arc<DirectBufferBudget>,
        traffic_limiter: Arc<TrafficLimiter>,
        user_admission: Arc<UserAdmissionAuthority>,
        pending_handshakes: Arc<PendingHandshakeLimiter>,
    ) -> Arc<Self> {
        Arc::new(Self {
            handshake: HandshakeSharedState {
                auth_probe: DashMap::new(),
                auth_probe_slots: SlotBudget::new(
                    crate::proxy::handshake::AUTH_PROBE_TRACK_MAX_ENTRIES,
                ),
                auth_probe_saturation: Mutex::new(None),
                auth_probe_eviction_hasher: RandomState::new(),
                invalid_secret_warned: Mutex::new(HashSet::new()),
                unknown_sni_warn_next_allowed: Mutex::new(None),
                sticky_user_by_ip: DashMap::new(),
                sticky_user_by_ip_slots: SlotBudget::new(
                    crate::proxy::handshake::STICKY_HINT_MAX_ENTRIES,
                ),
                sticky_user_by_ip_prefix: DashMap::new(),
                sticky_user_by_ip_prefix_slots: SlotBudget::new(
                    crate::proxy::handshake::STICKY_HINT_MAX_ENTRIES,
                ),
                sticky_user_by_sni_hash: DashMap::new(),
                sticky_user_by_sni_hash_slots: SlotBudget::new(
                    crate::proxy::handshake::STICKY_HINT_MAX_ENTRIES,
                ),
                recent_user_ring: std::iter::repeat_with(|| AtomicU64::new(0))
                    .take(HANDSHAKE_RECENT_USER_RING_LEN)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                recent_user_ring_seq: AtomicU64::new(0),
                auth_expensive_checks_total: AtomicU64::new(0),
                auth_budget_exhausted_total: AtomicU64::new(0),
            },
            middle_relay: MiddleRelaySharedState {
                desync_dedup: DashMap::new(),
                desync_dedup_previous: DashMap::new(),
                desync_hasher: RandomState::new(),
                desync_full_cache_last_emit_at: Mutex::new(None),
                desync_dedup_rotation_state: Mutex::new(DesyncDedupRotationState::default()),
                relay_idle_registry: RelayIdleCandidateRegistry::default(),
                relay_idle_mark_seq: AtomicU64::new(0),
            },
            traffic_limiter,
            direct_buffer_budget,
            user_admission,
            conntrack_pressure_active: AtomicBool::new(false),
            conntrack_close_tx: Mutex::new(None),
            masking_fallback_permits: Arc::new(Semaphore::new(MASKING_FALLBACK_MAX_CONCURRENT)),
            pending_handshakes,
        })
    }

    /// Attempts to reserve one masking fallback slot for a pre-auth connection.
    pub(crate) fn try_acquire_masking_fallback_permit(&self) -> Option<OwnedSemaphorePermit> {
        self.masking_fallback_permits
            .clone()
            .try_acquire_owned()
            .ok()
    }

    pub(crate) fn is_user_enabled(&self, user: &str) -> bool {
        self.user_admission.is_user_enabled(user)
    }

    /// Returns the process authority shared by every runtime generation.
    pub(crate) fn user_admission(&self) -> Arc<UserAdmissionAuthority> {
        Arc::clone(&self.user_admission)
    }

    /// Reconciles the complete user authentication policy from configuration.
    pub(crate) fn apply_user_config(
        &self,
        users: &HashMap<String, String>,
        user_enabled: &HashMap<String, bool>,
    ) -> Vec<(String, usize)> {
        self.user_admission.apply_config(users, user_enabled)
    }

    /// Transfers user-policy ownership to one runtime generation.
    pub(crate) fn activate_user_config_source(
        &self,
        source_generation: u64,
        expected_epoch: Option<u64>,
        users: &HashMap<String, String>,
        user_enabled: &HashMap<String, bool>,
    ) -> Option<Vec<(String, usize)>> {
        self.user_admission.activate_config_source(
            source_generation,
            expected_epoch,
            users,
            user_enabled,
        )
    }

    /// Applies an update only from the active runtime generation.
    pub(crate) fn apply_user_config_from_source(
        &self,
        source_generation: u64,
        users: &HashMap<String, String>,
        user_enabled: &HashMap<String, bool>,
    ) -> Option<Vec<(String, usize)>> {
        self.user_admission
            .apply_config_from_source(source_generation, users, user_enabled)
    }

    /// Applies one persisted user mutation before asynchronous config reload.
    pub(crate) fn stage_user(
        &self,
        user: &str,
        secret: &str,
        enabled: bool,
    ) -> Option<UserMutationResult> {
        self.user_admission.stage_user(user, secret, enabled)
    }

    /// Applies one prevalidated persisted credential before asynchronous reload.
    pub(crate) fn stage_user_credential(
        &self,
        user: &str,
        credential_id: UserCredentialId,
        enabled: bool,
    ) -> UserMutationResult {
        self.user_admission
            .stage_user_credential(user, credential_id, enabled)
    }

    /// Installs a deletion tombstone and cancels every current owner.
    pub(crate) fn delete_user(&self, user: &str) -> UserMutationResult {
        self.user_admission.delete_user(user)
    }

    /// Returns the current incarnation for an exact authenticated credential.
    pub(crate) fn authenticated_user_incarnation(
        &self,
        user: &str,
        credential_id: UserCredentialId,
    ) -> Option<UserIncarnation> {
        self.user_admission
            .authenticated_incarnation(user, credential_id)
    }

    /// Starts an atomic publication boundary for an authenticated owner.
    pub(crate) fn claim_authenticated_user(
        self: &Arc<Self>,
        user: &str,
        credential_id: UserCredentialId,
    ) -> Option<UserAdmissionPublication<'_>> {
        self.user_admission.claim_authenticated(user, credential_id)
    }

    pub(crate) fn register_user_session(
        self: &Arc<Self>,
        user: &str,
        _session_id: u64,
    ) -> Option<UserSessionRegistration> {
        self.user_admission.register_legacy(user)
    }

    /// Registers a relay session against the exact credential that authenticated it.
    pub(crate) fn register_authenticated_user_session(
        self: &Arc<Self>,
        user: &str,
        credential_id: UserCredentialId,
    ) -> Option<UserSessionRegistration> {
        let mut publication = self.claim_authenticated_user(user, credential_id)?;
        let registration = publication.take_registration()?;
        publication.commit();
        Some(registration)
    }

    pub(crate) fn cancel_user_sessions(&self, user: &str) -> usize {
        self.user_admission.cancel_user_owners(user)
    }

    pub(crate) fn set_conntrack_close_sender(&self, tx: mpsc::Sender<ConntrackCloseEvent>) {
        match self.conntrack_close_tx.lock() {
            Ok(mut guard) => {
                *guard = Some(tx);
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                *guard = Some(tx);
                self.conntrack_close_tx.clear_poison();
            }
        }
    }

    pub(crate) fn disable_conntrack_close_sender(&self) {
        match self.conntrack_close_tx.lock() {
            Ok(mut guard) => {
                *guard = None;
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                *guard = None;
                self.conntrack_close_tx.clear_poison();
            }
        }
    }

    pub(crate) fn publish_conntrack_close_event(
        &self,
        event: ConntrackCloseEvent,
    ) -> ConntrackClosePublishResult {
        let tx = match self.conntrack_close_tx.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => {
                let guard = poisoned.into_inner();
                let cloned = guard.clone();
                self.conntrack_close_tx.clear_poison();
                cloned
            }
        };

        let Some(tx) = tx else {
            return ConntrackClosePublishResult::Disabled;
        };

        match tx.try_send(event) {
            Ok(()) => ConntrackClosePublishResult::Sent,
            Err(mpsc::error::TrySendError::Full(_)) => ConntrackClosePublishResult::QueueFull,
            Err(mpsc::error::TrySendError::Closed(_)) => ConntrackClosePublishResult::QueueClosed,
        }
    }

    pub(crate) fn set_conntrack_pressure_active(&self, active: bool) {
        self.conntrack_pressure_active
            .store(active, Ordering::Relaxed);
    }

    pub(crate) fn conntrack_pressure_active(&self) -> bool {
        self.conntrack_pressure_active.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE_SECRET: &str = "00112233445566778899aabbccddeeff";

    fn configured_shared() -> Arc<ProxySharedState> {
        let shared = ProxySharedState::new();
        let users = HashMap::from([
            ("alice".to_string(), ALICE_SECRET.to_string()),
            (
                "bob".to_string(),
                "ffeeddccbbaa99887766554433221100".to_string(),
            ),
        ]);
        shared.apply_user_config(&users, &HashMap::new());
        shared
    }

    #[test]
    fn user_enabled_config_sync_tracks_disabled_overrides() {
        let shared = configured_shared();
        assert!(shared.is_user_enabled("alice"));

        let users = HashMap::from([
            ("alice".to_string(), ALICE_SECRET.to_string()),
            (
                "bob".to_string(),
                "ffeeddccbbaa99887766554433221100".to_string(),
            ),
        ]);
        let mut user_enabled = HashMap::new();
        user_enabled.insert("alice".to_string(), false);
        user_enabled.insert("bob".to_string(), true);

        let mut newly_disabled = shared.apply_user_config(&users, &user_enabled);
        newly_disabled.sort();
        assert_eq!(newly_disabled, vec![("alice".to_string(), 0)]);
        assert!(!shared.is_user_enabled("alice"));
        assert!(shared.is_user_enabled("bob"));

        assert!(shared.apply_user_config(&users, &user_enabled).is_empty());

        user_enabled.clear();
        assert!(shared.apply_user_config(&users, &user_enabled).is_empty());
        assert!(shared.is_user_enabled("alice"));
    }

    #[test]
    fn cancel_user_sessions_cancels_only_registered_matching_user() {
        let shared = configured_shared();
        let alice_1 = shared.register_user_session("alice", 1).unwrap();
        let alice_2 = shared.register_user_session("alice", 2).unwrap();
        let bob = shared.register_user_session("bob", 1).unwrap();
        let alice_1_token = alice_1.token();
        let alice_2_token = alice_2.token();
        let bob_token = bob.token();

        drop(alice_1);

        assert_eq!(shared.cancel_user_sessions("alice"), 1);
        assert!(!alice_1_token.is_cancelled());
        assert!(alice_2_token.is_cancelled());
        assert!(!bob_token.is_cancelled());
    }

    #[test]
    fn disabled_user_cannot_register_after_the_cancellation_snapshot() {
        let shared = configured_shared();

        let result = shared.stage_user("alice", ALICE_SECRET, false).unwrap();
        assert!(result.newly_disabled);
        assert_eq!(result.cancelled, 0);
        assert_eq!(shared.cancel_user_sessions("alice"), 0);

        let late = shared.register_user_session("alice", 1);
        assert!(
            late.is_none(),
            "a session registered after disable returned must be rejected"
        );
    }

    #[test]
    fn disabling_user_cancels_existing_sessions_before_return() {
        let shared = configured_shared();
        let registration = shared.register_user_session("alice", 1).unwrap();
        let token = registration.token();

        let result = shared.stage_user("alice", ALICE_SECRET, false).unwrap();
        assert!(result.newly_disabled);
        assert_eq!(result.cancelled, 1);
        assert!(token.is_cancelled());
        assert!(shared.register_user_session("alice", 2).is_none());

        let result = shared.stage_user("alice", ALICE_SECRET, true).unwrap();
        assert!(!result.newly_disabled);
        assert_eq!(result.cancelled, 0);
        assert!(shared.register_user_session("alice", 3).is_some());
    }

    #[test]
    fn concurrent_disable_and_registration_never_leave_a_live_session() {
        const ITERATIONS: usize = 10_000;

        let shared = ProxySharedState::new();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let register_shared = Arc::clone(&shared);
        let register_barrier = Arc::clone(&barrier);
        let register = std::thread::spawn(move || {
            let mut registrations = Vec::with_capacity(ITERATIONS);
            for session_id in 0..ITERATIONS as u64 {
                let user = format!("user-{session_id}");
                register_barrier.wait();
                registrations.push(register_shared.register_user_session(&user, session_id));
            }
            registrations
        });

        for session_id in 0..ITERATIONS as u64 {
            let user = format!("user-{session_id}");
            barrier.wait();
            let secret = "00112233445566778899aabbccddeeff";
            shared.stage_user(&user, secret, false).unwrap();
        }

        for registration in register.join().unwrap().into_iter().flatten() {
            assert!(registration.token().is_cancelled());
        }
    }
}
