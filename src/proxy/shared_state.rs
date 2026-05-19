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
use crate::proxy::traffic_limiter::TrafficLimiter;

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
    pub(crate) traffic_limiter: Arc<TrafficLimiter>,
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
            traffic_limiter: TrafficLimiter::new(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering::Relaxed;

    fn dummy_event(reason: ConntrackCloseReason) -> ConntrackCloseEvent {
        ConntrackCloseEvent {
            src: "127.0.0.1:12345".parse().unwrap(),
            dst: "127.0.0.1:54321".parse().unwrap(),
            reason,
        }
    }

    #[test]
    fn new_returns_arc_and_initial_state() {
        let state = ProxySharedState::new();

        assert!(state.handshake.recent_user_ring.len() == HANDSHAKE_RECENT_USER_RING_LEN);
        assert_eq!(state.handshake.recent_user_ring_seq.load(Relaxed), 0);
        assert_eq!(
            state
                .handshake
                .auth_expensive_checks_total
                .load(Relaxed),
            0
        );
        assert_eq!(
            state
                .handshake
                .auth_budget_exhausted_total
                .load(Relaxed),
            0
        );
        assert!(!state.conntrack_pressure_active());
        assert_eq!(state.middle_relay.relay_idle_mark_seq.load(Relaxed), 0);
        assert!(state.handshake.auth_probe.is_empty());
        assert!(state.handshake.sticky_user_by_ip.is_empty());
        assert!(state.handshake.sticky_user_by_ip_prefix.is_empty());
        assert!(state.handshake.sticky_user_by_sni_hash.is_empty());
        assert!(state.middle_relay.desync_dedup.is_empty());
        assert!(state.middle_relay.desync_dedup_previous.is_empty());
    }

    #[test]
    fn conntrack_pressure_round_trip() {
        let state = ProxySharedState::new();

        assert!(!state.conntrack_pressure_active());

        state.set_conntrack_pressure_active(true);
        assert!(state.conntrack_pressure_active());

        state.set_conntrack_pressure_active(false);
        assert!(!state.conntrack_pressure_active());
    }

    #[tokio::test]
    async fn conntrack_close_publish_disabled_when_no_sender() {
        let state = ProxySharedState::new();
        let result = state.publish_conntrack_close_event(dummy_event(ConntrackCloseReason::NormalEof));
        assert_eq!(result, ConntrackClosePublishResult::Disabled);
    }

    #[tokio::test]
    async fn conntrack_close_publish_sent() {
        let state = ProxySharedState::new();
        let (tx, mut rx) = mpsc::channel(4);
        state.set_conntrack_close_sender(tx);

        let event = dummy_event(ConntrackCloseReason::Timeout);
        let result = state.publish_conntrack_close_event(event);
        assert_eq!(result, ConntrackClosePublishResult::Sent);

        let received = rx.recv().await.unwrap();
        assert_eq!(received.src, event.src);
        assert_eq!(received.dst, event.dst);
        assert_eq!(received.reason, event.reason);
    }

    #[tokio::test]
    async fn conntrack_close_publish_queue_full() {
        let state = ProxySharedState::new();
        let (tx, _rx) = mpsc::channel(1);
        state.set_conntrack_close_sender(tx);

        let r = state.publish_conntrack_close_event(dummy_event(ConntrackCloseReason::Pressure));
        assert_eq!(r, ConntrackClosePublishResult::Sent);

        let r = state.publish_conntrack_close_event(dummy_event(ConntrackCloseReason::Reset));
        assert_eq!(r, ConntrackClosePublishResult::QueueFull);
    }

    #[tokio::test]
    async fn conntrack_close_publish_queue_closed() {
        let state = ProxySharedState::new();
        let (tx, rx) = mpsc::channel(4);
        state.set_conntrack_close_sender(tx);
        drop(rx);

        let r = state.publish_conntrack_close_event(dummy_event(ConntrackCloseReason::Other));
        assert_eq!(r, ConntrackClosePublishResult::QueueClosed);
    }

    #[tokio::test]
    async fn conntrack_close_publish_disabled_after_disable() {
        let state = ProxySharedState::new();
        let (tx, _rx) = mpsc::channel(4);
        state.set_conntrack_close_sender(tx);
        state.disable_conntrack_close_sender();

        let r = state.publish_conntrack_close_event(dummy_event(ConntrackCloseReason::NormalEof));
        assert_eq!(r, ConntrackClosePublishResult::Disabled);
    }

}
