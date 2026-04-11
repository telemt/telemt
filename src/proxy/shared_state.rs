use std::collections::HashSet;
use std::collections::hash_map::RandomState;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use dashmap::DashMap;
use tokio::sync::mpsc;

use crate::proxy::handshake::{AuthProbeSaturationState, AuthProbeState};
use crate::proxy::middle_relay::{DesyncDedupRotationState, RelayIdleCandidateRegistry};

const HANDSHAKE_RECENT_USER_RING_LEN: usize = 64;

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
    pub(crate) auth_candidate_scan_seq: AtomicU64,
    pub(crate) auth_expensive_checks_total: AtomicU64,
    pub(crate) auth_budget_exhausted_total: AtomicU64,
}

pub(crate) struct MiddleRelaySharedState {
    pub(crate) desync_dedup: DashMap<u64, Instant>,
    pub(crate) desync_dedup_previous: DashMap<u64, Instant>,
    pub(crate) desync_hasher: RandomState,
    pub(crate) desync_full_cache_last_emit_at: Mutex<Option<Instant>>,
    pub(crate) desync_dedup_rotation_state: Mutex<DesyncDedupRotationState>,
    pub(crate) relay_idle_registry: Mutex<RelayIdleCandidateRegistry>,
    pub(crate) relay_idle_mark_seq: AtomicU64,
}

pub(crate) struct ProxySharedState {
    pub(crate) handshake: HandshakeSharedState,
    pub(crate) middle_relay: MiddleRelaySharedState,
    pub(crate) conntrack_pressure_active: AtomicBool,
    pub(crate) conntrack_close_tx: Mutex<Option<mpsc::Sender<ConntrackCloseEvent>>>,
}

impl ProxySharedState {
    pub(crate) fn new() -> Arc<Self> {
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
                auth_candidate_scan_seq: AtomicU64::new(0),
                auth_expensive_checks_total: AtomicU64::new(0),
                auth_budget_exhausted_total: AtomicU64::new(0),
            },
            middle_relay: MiddleRelaySharedState {
                desync_dedup: DashMap::new(),
                desync_dedup_previous: DashMap::new(),
                desync_hasher: RandomState::new(),
                desync_full_cache_last_emit_at: Mutex::new(None),
                desync_dedup_rotation_state: Mutex::new(DesyncDedupRotationState::default()),
                relay_idle_registry: Mutex::new(RelayIdleCandidateRegistry::default()),
                relay_idle_mark_seq: AtomicU64::new(0),
            },
            conntrack_pressure_active: AtomicBool::new(false),
            conntrack_close_tx: Mutex::new(None),
        })
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
