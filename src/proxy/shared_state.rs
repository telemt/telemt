use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use dashmap::DashMap;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

use crate::proxy::direct_buffer_budget::{DirectBufferBudget, fallback_direct_buffer_hard_limit};
use crate::proxy::handshake::{AuthProbeSaturationState, AuthProbeState};
use crate::proxy::middle_relay::{DesyncDedupRotationState, RelayIdleCandidateRegistry};
use crate::proxy::traffic_limiter::TrafficLimiter;

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

pub(crate) struct HandshakeSharedState {
    pub(crate) auth_probe: DashMap<IpAddr, AuthProbeState>,
    pub(crate) auth_probe_saturation: Mutex<Option<AuthProbeSaturationState>>,
    pub(crate) auth_probe_eviction_hasher: RandomState,
    pub(crate) invalid_secret_warned: Mutex<HashSet<(String, String)>>,
    pub(crate) unknown_sni_warn_next_allowed: Mutex<Option<Instant>>,
    pub(crate) sticky_user_by_ip: DashMap<IpAddr, u32>,
    pub(crate) sticky_user_by_ip_prefix: DashMap<u64, u32>,
    pub(crate) sticky_user_by_sni_hash: DashMap<u64, u32>,
    pub(crate) recent_user_ring: Box<[AtomicU32]>,
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
    disabled_users: DashMap<String, ()>,
    active_user_sessions: DashMap<(String, u64), CancellationToken>,
    pub(crate) conntrack_pressure_active: AtomicBool,
    pub(crate) conntrack_close_tx: Mutex<Option<mpsc::Sender<ConntrackCloseEvent>>>,
    masking_fallback_permits: Arc<Semaphore>,
}

#[must_use = "registered user sessions must be kept alive until relay completion"]
pub(crate) struct UserSessionRegistration {
    token: CancellationToken,
    _guard: UserSessionGuard,
}

impl UserSessionRegistration {
    pub(crate) fn token(&self) -> CancellationToken {
        self.token.clone()
    }
}

struct UserSessionGuard {
    shared: Arc<ProxySharedState>,
    key: (String, u64),
}

impl Drop for UserSessionGuard {
    fn drop(&mut self) {
        self.shared.active_user_sessions.remove(&self.key);
    }
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
        Arc::new(Self {
            handshake: HandshakeSharedState {
                auth_probe: DashMap::new(),
                auth_probe_saturation: Mutex::new(None),
                auth_probe_eviction_hasher: RandomState::new(),
                invalid_secret_warned: Mutex::new(HashSet::new()),
                unknown_sni_warn_next_allowed: Mutex::new(None),
                sticky_user_by_ip: DashMap::new(),
                sticky_user_by_ip_prefix: DashMap::new(),
                sticky_user_by_sni_hash: DashMap::new(),
                recent_user_ring: std::iter::repeat_with(|| AtomicU32::new(0))
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
            traffic_limiter: TrafficLimiter::new(),
            direct_buffer_budget,
            disabled_users: DashMap::new(),
            active_user_sessions: DashMap::new(),
            conntrack_pressure_active: AtomicBool::new(false),
            conntrack_close_tx: Mutex::new(None),
            masking_fallback_permits: Arc::new(Semaphore::new(MASKING_FALLBACK_MAX_CONCURRENT)),
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
        !self.disabled_users.contains_key(user)
    }

    pub(crate) fn set_user_enabled(&self, user: &str, enabled: bool) -> bool {
        if enabled {
            self.disabled_users.remove(user);
            false
        } else {
            self.disabled_users.insert(user.to_string(), ()).is_none()
        }
    }

    pub(crate) fn apply_user_enabled_config(
        &self,
        user_enabled: &HashMap<String, bool>,
    ) -> Vec<String> {
        let desired_disabled = user_enabled
            .iter()
            .filter_map(|(user, enabled)| (!*enabled).then_some(user.clone()))
            .collect::<HashSet<_>>();
        let current_disabled = self
            .disabled_users
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<HashSet<_>>();

        for user in current_disabled.difference(&desired_disabled) {
            self.disabled_users.remove(user);
        }
        let newly_disabled = desired_disabled
            .difference(&current_disabled)
            .cloned()
            .collect::<Vec<_>>();
        for user in desired_disabled {
            self.disabled_users.insert(user, ());
        }
        newly_disabled
    }

    pub(crate) fn register_user_session(
        self: &Arc<Self>,
        user: &str,
        session_id: u64,
    ) -> UserSessionRegistration {
        let token = CancellationToken::new();
        let key = (user.to_string(), session_id);
        self.active_user_sessions.insert(key.clone(), token.clone());
        UserSessionRegistration {
            token,
            _guard: UserSessionGuard {
                shared: Arc::clone(self),
                key,
            },
        }
    }

    pub(crate) fn cancel_user_sessions(&self, user: &str) -> usize {
        let tokens = self
            .active_user_sessions
            .iter()
            .filter_map(|entry| (entry.key().0 == user).then(|| entry.value().clone()))
            .collect::<Vec<_>>();
        for token in &tokens {
            token.cancel();
        }
        tokens.len()
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

    #[test]
    fn user_enabled_config_sync_tracks_disabled_overrides() {
        let shared = ProxySharedState::new();
        assert!(shared.is_user_enabled("alice"));

        let mut user_enabled = HashMap::new();
        user_enabled.insert("alice".to_string(), false);
        user_enabled.insert("bob".to_string(), true);

        let mut newly_disabled = shared.apply_user_enabled_config(&user_enabled);
        newly_disabled.sort();
        assert_eq!(newly_disabled, vec!["alice".to_string()]);
        assert!(!shared.is_user_enabled("alice"));
        assert!(shared.is_user_enabled("bob"));

        assert!(shared.apply_user_enabled_config(&user_enabled).is_empty());

        user_enabled.clear();
        assert!(shared.apply_user_enabled_config(&user_enabled).is_empty());
        assert!(shared.is_user_enabled("alice"));
    }

    #[test]
    fn cancel_user_sessions_cancels_only_registered_matching_user() {
        let shared = ProxySharedState::new();
        let alice_1 = shared.register_user_session("alice", 1);
        let alice_2 = shared.register_user_session("alice", 2);
        let bob = shared.register_user_session("bob", 1);
        let alice_1_token = alice_1.token();
        let alice_2_token = alice_2.token();
        let bob_token = bob.token();

        drop(alice_1);

        assert_eq!(shared.cancel_user_sessions("alice"), 1);
        assert!(!alice_1_token.is_cancelled());
        assert!(alice_2_token.is_cancelled());
        assert!(!bob_token.is_cancelled());
    }
}
