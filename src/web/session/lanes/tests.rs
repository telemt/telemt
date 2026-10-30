use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Wake, Waker};

use arc_swap::ArcSwap;
use bytes::BytesMut;

use super::*;
use crate::config::{
    ProxyConfig, WebCarrier, WebLimitsConfig, WebRuntimeProfile, WebSecretMode, WebTimeoutsConfig,
};
use crate::maestro::generation::test_runtime_generation;
use crate::web::manager::WebProcessRuntime;
use crate::web::session::{CarrierLane, StreamState, insert_carrier_lane};

struct SessionLockProbe {
    session: std::sync::Weak<WebSession>,
    lock_was_free: Arc<AtomicBool>,
}

impl Wake for SessionLockProbe {
    fn wake(self: Arc<Self>) {
        if let Some(session) = self.session.upgrade() {
            self.lock_was_free
                .store(session.state.try_lock().is_some(), Ordering::Release);
        }
    }
}

fn session_with_limits(limits: WebLimitsConfig) -> Arc<WebSession> {
    new_session(limits, std::sync::Weak::new())
}

fn new_session(
    limits: WebLimitsConfig,
    manager: std::sync::Weak<WebProcessRuntime>,
) -> Arc<WebSession> {
    new_session_with_automatic(limits, manager, false)
}

fn new_session_with_automatic(
    limits: WebLimitsConfig,
    manager: std::sync::Weak<WebProcessRuntime>,
    automatic: bool,
) -> Arc<WebSession> {
    let profile = Arc::new(WebRuntimeProfile {
        host: "proxy.example.com".to_string(),
        capability: [0; 32],
        shared: Arc::new(crate::config::WebRuntimeProfileShared {
            derivation_context: [0; 32],
            public_addr: SocketAddr::from(([203, 0, 113, 10], 443)),
            user: "alice".to_string(),
            secret_mode: WebSecretMode::Plain,
            carrier: WebCarrier::HttpsLanes,
            carrier_negotiation_enabled: false,
            carrier_learning: true,
            carriers: Arc::from([WebCarrier::HttpsLanes]),
            carrier_negotiation_deadlines_secs: [3, 5, 8, 12],
            credential_id: [0; 16],
            key_fingerprint: "0000000000000000".to_string(),
            max_sessions: 1,
            max_streams: 2,
            max_streams_per_session: 2,
        }),
    });
    WebSession::new(
        manager,
        [1; 32],
        "192.0.2.10".parse().unwrap(),
        1,
        profile,
        [2; 32],
        WebCarrier::HttpsLanes,
        1,
        [3; 32],
        None,
        if automatic {
            crate::web::manager::CarrierClientClass::Bridge
        } else {
            crate::web::manager::CarrierClientClass::Legacy
        },
        None,
        automatic,
        false,
        limits,
        WebTimeoutsConfig::default(),
        None,
    )
}

fn session_with_manager() -> (Arc<WebSession>, Arc<WebProcessRuntime>) {
    session_with_manager_limits(WebLimitsConfig::default())
}

fn session_with_manager_limits(
    limits: WebLimitsConfig,
) -> (Arc<WebSession>, Arc<WebProcessRuntime>) {
    let generation = test_runtime_generation(1, ProxyConfig::default());
    let manager = WebProcessRuntime::start(Arc::new(ArcSwap::from(generation)));
    let session = new_session(limits, Arc::downgrade(&manager));
    (session, manager)
}

fn session() -> Arc<WebSession> {
    session_with_limits(WebLimitsConfig::default())
}

#[tokio::test]
async fn early_down_waits_without_creating_a_provisional_lane() {
    let (session, manager) = session_with_manager();
    let polling = Arc::clone(&session);
    let poll = tokio::spawn(async move { polling.poll_down_lane(7, 0).await });
    while session.state.lock().lane_open_waits == 0 {
        tokio::task::yield_now().await;
    }
    assert!(!session.state.lock().carrier_lanes.contains_key(&7));
    session.with_state_effects(|state, effects| {
        assert!(insert_carrier_lane(state, 7).is_some());
        state.closed_streams.insert(7);
        assert!(session.queue_control_locked(state, effects, FrameType::Close, 7, &[]));
    });
    session.lane_open_notify.notify_waiters();
    let result = tokio::time::timeout(Duration::from_secs(1), poll)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!result.body.is_empty());
    assert_eq!(session.state.lock().lane_open_waits, 0);
    drop(result);
    session.close(super::super::SessionCloseReason::ApiClose);
    manager.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn early_down_timeout_is_empty_and_releases_its_session_slot() {
    let (session, manager) = session_with_manager();
    let polling = Arc::clone(&session);
    let poll = tokio::spawn(async move { polling.poll_down_lane(7, 0).await });
    while session.state.lock().lane_open_waits == 0 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(3)).await;
    let result = poll.await.unwrap().unwrap();
    assert!(result.body.is_empty());
    assert_eq!(result.next_cursor, 0);
    assert!(!result.lane_closed);
    assert_eq!(session.state.lock().lane_open_waits, 0);
    session.close(super::super::SessionCloseReason::ApiClose);
    manager.shutdown().await;
}

#[tokio::test]
async fn early_down_admission_is_bounded_and_cancellation_safe() {
    let limits = WebLimitsConfig {
        max_lane_open_waits_per_session: 2,
        ..WebLimitsConfig::default()
    };
    let (session, manager) = session_with_manager_limits(limits);
    let mut waits = Vec::new();
    for lane_id in [7, 8] {
        let polling = Arc::clone(&session);
        waits.push(tokio::spawn(async move {
            polling.poll_down_lane(lane_id, 0).await
        }));
    }
    while session.state.lock().lane_open_waits < 2 {
        tokio::task::yield_now().await;
    }
    assert!(matches!(
        session.poll_down_lane(9, 0).await,
        Err(ManagerError::Limit)
    ));
    for wait in waits {
        wait.abort();
        let _ = wait.await;
    }
    assert_eq!(session.state.lock().lane_open_waits, 0);
    session.close(super::super::SessionCloseReason::ApiClose);
    manager.shutdown().await;
}

#[tokio::test]
async fn session_close_wakes_early_down_with_closed_state() {
    let (session, manager) = session_with_manager();
    let polling = Arc::clone(&session);
    let poll = tokio::spawn(async move { polling.poll_down_lane(7, 0).await });
    while session.state.lock().lane_open_waits == 0 {
        tokio::task::yield_now().await;
    }
    session.close(super::super::SessionCloseReason::ApiClose);
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), poll)
            .await
            .unwrap()
            .unwrap(),
        Err(ManagerError::Closed)
    ));
    assert_eq!(session.state.lock().lane_open_waits, 0);
    manager.shutdown().await;
}

#[test]
fn lane_uplink_sequences_are_independent_and_exactly_once() {
    let session = session();
    {
        let mut state = session.state.lock();
        for lane_id in [51, 52] {
            state
                .carrier_lanes
                .insert(lane_id, CarrierLane::new(u64::from(lane_id)));
            state.closed_streams.insert(lane_id);
        }
    }
    let first = frame::encode(FrameType::Data, 51, b"first");
    let second = frame::encode(FrameType::Data, 52, b"second");
    assert_eq!(session.process_up_lane(51, 1, &first), Ok(1));
    assert_eq!(session.process_up_lane(52, 1, &second), Ok(1));
    assert_eq!(session.process_up_lane(51, 1, &first), Ok(1));
    assert_eq!(session.state.lock().carrier_lanes[&52].last_up_sequence, 1);
}

#[test]
fn cross_lane_frame_is_fatal_to_https_lane_session() {
    let session = session();
    let body = frame::encode(FrameType::Data, 52, b"wrong lane");
    assert_eq!(
        session.process_up_lane(51, 1, &body),
        Err(ManagerError::Protocol)
    );
    assert!(session.state.lock().closed);
}

#[tokio::test]
async fn drained_closed_lane_replays_then_signals_completion() {
    let (session, manager) = session_with_manager();
    session.with_state_effects(|state, effects| {
        state.carrier_lanes.insert(7, CarrierLane::new(7));
        state.closed_streams.insert(7);
        assert!(session.queue_control_locked(state, effects, FrameType::Close, 7, &[]));
    });
    let first = session.poll_down_lane(7, 0).await.unwrap();
    let replay = session.poll_down_lane(7, 0).await.unwrap();
    assert_eq!(first.body, replay.body);
    assert!(!replay.lane_closed);
    let finished = session.poll_down_lane(7, 1).await.unwrap();
    assert!(finished.body.is_empty());
    assert!(finished.lane_closed);
    drop(first);
    drop(replay);
    session.close(super::super::SessionCloseReason::ApiClose);
    manager.shutdown().await;
}

#[tokio::test]
async fn lane_ack_wakes_writer_only_after_releasing_session_lock() {
    let (session, manager) = session_with_manager();
    session.with_state_effects(|state, effects| {
        state.carrier_lanes.insert(7, CarrierLane::new(7));
        state.streams.insert(
            7,
            StreamState {
                instance: 1,
                inbound: VecDeque::new(),
                receive_window: frame::INITIAL_STREAM_WINDOW,
                send_credit: 0,
                read_waker: None,
                write_waker: None,
            },
        );
        assert!(session.queue_control_locked(
            state,
            effects,
            FrameType::Window,
            7,
            &frame::window_payload(1),
        ));
    });
    let first = session.poll_down_lane(7, 0).await.unwrap();
    let lock_was_free = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(SessionLockProbe {
        session: Arc::downgrade(&session),
        lock_was_free: Arc::clone(&lock_was_free),
    }));
    session.with_state_effects(|state, effects| {
        state.streams.get_mut(&7).unwrap().write_waker = Some(waker);
        assert!(session.queue_control_locked(
            state,
            effects,
            FrameType::Window,
            7,
            &frame::window_payload(1),
        ));
    });

    let second = session.poll_down_lane(7, first.next_cursor).await.unwrap();

    assert!(lock_was_free.load(Ordering::Acquire));
    drop(first);
    drop(second);
    session.close(super::super::SessionCloseReason::ApiClose);
    manager.shutdown().await;
}

#[test]
fn tombstone_eviction_releases_lane_budget_and_accepts_late_frames() {
    let limits = WebLimitsConfig {
        max_tombstones_per_session: 1,
        ..WebLimitsConfig::default()
    };
    let session = session_with_limits(limits);
    session.with_state_effects(|state, effects| {
        state.carrier_lanes.insert(7, CarrierLane::new(7));
        let encoded = frame::encode(FrameType::Close, 7, &[]);
        let cost = encoded.len() + QUEUE_ITEM_COST;
        state
            .carrier_lanes
            .get_mut(&7)
            .unwrap()
            .pending_frames
            .push_back(QueuedFrame {
                encoded: BytesMut::from(encoded.as_ref()),
                frame_type: FrameType::Close,
                stream_id: 7,
                control: true,
                cost,
            });
        state.pending_bytes = cost;
        state.pending_items = 1;
        state.pending_control_bytes = cost;
        state.pending_control_items = 1;
        session.remember_closed_locked(state, effects, 7);
        state.carrier_lanes.insert(8, CarrierLane::new(8));
        session.remember_closed_locked(state, effects, 8);
        assert!(!state.carrier_lanes.contains_key(&7));
        assert_eq!(state.pending_bytes, 0);
        assert_eq!(state.pending_items, 0);
    });
    let late = frame::encode(FrameType::Data, 7, b"late");
    assert_eq!(session.process_up_lane(7, 7, &late), Ok(7));
    assert!(!session.state.lock().closed);
}

#[test]
fn automatic_lane_does_not_ack_a_missing_lane_without_real_progress() {
    let session =
        new_session_with_automatic(WebLimitsConfig::default(), std::sync::Weak::new(), true);
    let late = frame::encode(FrameType::Data, 7, b"late");

    assert_eq!(
        session.process_up_lane(7, 1, &late),
        Err(ManagerError::Backpressure)
    );
    assert!(!session.is_carrier_committed());
    assert!(!session.state.lock().closed);
}
