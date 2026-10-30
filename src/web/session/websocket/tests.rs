use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Wake, Waker};

use arc_swap::ArcSwap;
use tokio::sync::watch;

use super::*;
use crate::config::{ProxyConfig, WebRuntimeConfig, WebRuntimeProfile, WebSecretMode};
use crate::maestro::generation::{RuntimeGeneration, test_runtime_generation_with_admission};
use crate::web::frame::FrameType;
use crate::web::manager::WebProcessRuntime;
use crate::web::session::StreamState;

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

struct TestRuntime {
    session: Arc<WebSession>,
    manager: Arc<WebProcessRuntime>,
    generation: Arc<RuntimeGeneration>,
}

impl TestRuntime {
    async fn shutdown(self) {
        self.session
            .close(super::super::SessionCloseReason::ApiClose);
        self.session.wait().await;
        self.manager.shutdown().await;
        self.generation.stop_sessions().await;
        self.generation.stop_background_tasks().await;
    }
}

fn runtime(admission: bool) -> TestRuntime {
    let profile = Arc::new(WebRuntimeProfile {
        host: "proxy.example.com".to_string(),
        capability: [7; 32],
        shared: Arc::new(crate::config::WebRuntimeProfileShared {
            derivation_context: [0; 32],
            public_addr: "203.0.113.10:443".parse().unwrap(),
            user: "default".to_string(),
            secret_mode: WebSecretMode::Plain,
            carrier: WebCarrier::WebsocketLanes,
            carrier_negotiation_enabled: false,
            carrier_learning: true,
            carriers: Arc::from([WebCarrier::WebsocketLanes]),
            carrier_negotiation_deadlines_secs: [3, 5, 8, 12],
            credential_id: [0; 16],
            key_fingerprint: "0000000000000000".to_string(),
            max_sessions: 2,
            max_streams: 1,
            max_streams_per_session: 1,
        }),
    });
    let mut config = ProxyConfig::default();
    config.web.enabled = true;
    config.web.carrier = WebCarrier::WebsocketLanes;
    config.web.timeouts.shutdown_secs = 1;
    config.web.runtime = Some(Arc::new(WebRuntimeConfig {
        snapshot_id: 0,
        wildcards: Default::default(),
        catch_all: None,
        vhosts: BTreeMap::new(),
        profiles: vec![Arc::clone(&profile)],
        capabilities: vec![[7; 32]].into_boxed_slice(),
    }));
    config.rebuild_runtime_user_auth().unwrap();
    let limits = config.web.limits.clone();
    let timeouts = config.web.timeouts.clone();
    let (_admission_tx, admission_rx) = watch::channel(admission);
    let generation = test_runtime_generation_with_admission(1, config, admission_rx);
    let manager = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let session = WebSession::new(
        Arc::downgrade(&manager),
        [8; 32],
        "192.0.2.10".parse().unwrap(),
        1,
        profile,
        [7; 32],
        WebCarrier::WebsocketLanes,
        1,
        [9; 32],
        None,
        crate::web::manager::CarrierClientClass::Legacy,
        None,
        false,
        false,
        limits,
        timeouts,
        None,
    );
    TestRuntime {
        session,
        manager,
        generation,
    }
}

fn detach_stale_lane(runtime: &TestRuntime, reservation: &WebSocketLaneReservation) {
    let claim = reservation.claim;
    runtime.session.with_state_effects(|state, effects| {
        assert_eq!(
            state
                .websocket_lane_reservations
                .remove(&claim.lane.lane_id),
            Some(claim)
        );
        runtime
            .session
            .release_lane_locked(state, effects, claim.lane.lane_id);
        assert!(state.active_peer_ports.remove(&claim.peer_port));
    });
    runtime.manager.release_stream(
        runtime.session.profile_key,
        runtime.session.client_ip,
        runtime.session.profile.shared.public_addr,
        claim.peer_port,
    );
}

fn replacement_lane(
    runtime: &TestRuntime,
    stale: &WebSocketLaneReservation,
) -> WebSocketLaneReservation {
    detach_stale_lane(runtime, stale);
    let mut replacement = runtime
        .session
        .reserve_websocket_lane(stale.lane_id())
        .unwrap();
    replacement.bind(2).unwrap();
    assert_ne!(replacement.lane_identity(), stale.lane_identity());
    replacement
}

#[tokio::test]
async fn rejected_open_retains_stream_quota_until_lane_socket_teardown() {
    let runtime = runtime(false);
    let mut reservation = runtime.session.reserve_websocket_lane(7).unwrap();
    reservation.bind(1).unwrap();
    let open = frame::encode(FrameType::Open, 7, &[]);

    assert_eq!(
        runtime
            .session
            .process_websocket_lane(&mut reservation, 1, &open),
        Err(ManagerError::Limit),
    );
    assert_eq!(
        reservation.phase,
        WebSocketLaneReservationPhase::Transferred
    );
    assert!(reservation.stream.is_some());
    assert!(
        !runtime
            .session
            .state
            .lock()
            .websocket_lane_reservations
            .contains_key(&7)
    );
    assert!(
        runtime
            .manager
            .try_acquire_stream(
                runtime.session.profile_key,
                runtime.session.profile.shared.max_streams,
                runtime.session.client_ip,
                runtime.session.profile.shared.public_addr,
            )
            .is_err()
    );

    runtime.session.close_websocket_lane(reservation);
    let peer_port = runtime
        .manager
        .try_acquire_stream(
            runtime.session.profile_key,
            runtime.session.profile.shared.max_streams,
            runtime.session.client_ip,
            runtime.session.profile.shared.public_addr,
        )
        .unwrap();
    runtime.manager.release_stream(
        runtime.session.profile_key,
        runtime.session.client_ip,
        runtime.session.profile.shared.public_addr,
        peer_port,
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn closed_session_releases_bound_lane_quota_on_reservation_drop() {
    let runtime = runtime(true);
    let mut reservation = runtime.session.reserve_websocket_lane(7).unwrap();
    reservation.bind(1).unwrap();

    runtime
        .session
        .close(super::super::SessionCloseReason::ApiClose);
    drop(reservation);

    assert!(runtime.session.state.lock().active_peer_ports.is_empty());
    let peer_port = runtime
        .manager
        .try_acquire_stream(
            runtime.session.profile_key,
            runtime.session.profile.shared.max_streams,
            runtime.session.client_ip,
            runtime.session.profile.shared.public_addr,
        )
        .unwrap();
    runtime.manager.release_stream(
        runtime.session.profile_key,
        runtime.session.client_ip,
        runtime.session.profile.shared.public_addr,
        peer_port,
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn closed_session_releases_transferred_rejected_lane_quota() {
    let runtime = runtime(false);
    let mut reservation = runtime.session.reserve_websocket_lane(7).unwrap();
    reservation.bind(1).unwrap();
    let open = frame::encode(FrameType::Open, 7, &[]);
    assert_eq!(
        runtime
            .session
            .process_websocket_lane(&mut reservation, 1, &open),
        Err(ManagerError::Limit),
    );
    assert_eq!(
        reservation.phase,
        WebSocketLaneReservationPhase::Transferred
    );

    runtime
        .session
        .close(super::super::SessionCloseReason::ApiClose);
    drop(reservation);

    assert!(runtime.session.state.lock().active_peer_ports.is_empty());
    let peer_port = runtime
        .manager
        .try_acquire_stream(
            runtime.session.profile_key,
            runtime.session.profile.shared.max_streams,
            runtime.session.client_ip,
            runtime.session.profile.shared.public_addr,
        )
        .unwrap();
    runtime.manager.release_stream(
        runtime.session.profile_key,
        runtime.session.client_ip,
        runtime.session.profile.shared.public_addr,
        peer_port,
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn closed_session_keeps_stream_owned_quota_until_task_completion() {
    let runtime = runtime(true);
    let mut reservation = runtime.session.reserve_websocket_lane(7).unwrap();
    reservation.bind(1).unwrap();
    let open = frame::encode(FrameType::Open, 7, &[]);
    assert_eq!(
        runtime
            .session
            .process_websocket_lane(&mut reservation, 1, &open),
        Ok(true),
    );
    assert_eq!(
        reservation.phase,
        WebSocketLaneReservationPhase::StreamOwned
    );

    runtime
        .session
        .close(super::super::SessionCloseReason::ApiClose);
    drop(reservation);

    assert!(
        runtime
            .manager
            .try_acquire_stream(
                runtime.session.profile_key,
                runtime.session.profile.shared.max_streams,
                runtime.session.client_ip,
                runtime.session.profile.shared.public_addr,
            )
            .is_err()
    );
    runtime.session.wait().await;
    let peer_port = runtime
        .manager
        .try_acquire_stream(
            runtime.session.profile_key,
            runtime.session.profile.shared.max_streams,
            runtime.session.client_ip,
            runtime.session.profile.shared.public_addr,
        )
        .unwrap();
    runtime.manager.release_stream(
        runtime.session.profile_key,
        runtime.session.client_ip,
        runtime.session.profile.shared.public_addr,
        peer_port,
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn malformed_lane_message_does_not_close_sibling_session_state() {
    let runtime = runtime(true);
    let mut reservation = runtime.session.reserve_websocket_lane(7).unwrap();
    reservation.bind(1).unwrap();
    let data = frame::encode(FrameType::Data, 7, &[1]);

    assert_eq!(
        runtime
            .session
            .process_websocket_lane(&mut reservation, 1, &data),
        Err(ManagerError::Protocol),
    );
    assert!(!runtime.session.state.lock().closed);

    runtime.session.close_websocket_lane(reservation);
    assert!(runtime.session.reserve_websocket_lane(8).is_ok());
    runtime.shutdown().await;
}

#[tokio::test]
async fn stale_websocket_poll_does_not_close_reused_lane_instance() {
    let runtime = runtime(true);
    let mut stale = runtime.session.reserve_websocket_lane(7).unwrap();
    stale.bind(1).unwrap();
    let stale_identity = stale.lane_identity();
    let replacement = replacement_lane(&runtime, &stale);

    let result = runtime
        .session
        .poll_down_websocket_lane(stale_identity, u64::MAX)
        .await
        .unwrap();

    assert!(result.lane_closed);
    assert!(!runtime.session.state.lock().closed);
    assert_eq!(
        runtime
            .session
            .state
            .lock()
            .carrier_lanes
            .get(&7)
            .map(|lane| lane.instance),
        Some(replacement.lane_identity().instance)
    );
    drop(stale);
    runtime.session.close_websocket_lane(replacement);
    runtime.shutdown().await;
}

#[tokio::test]
async fn stale_close_preserves_replacement_lane_and_tuple() {
    let runtime = runtime(true);
    let mut stale = runtime.session.reserve_websocket_lane(7).unwrap();
    stale.bind(1).unwrap();
    let replacement = replacement_lane(&runtime, &stale);
    let replacement_claim = replacement.claim;
    stale.phase = WebSocketLaneReservationPhase::Transferred;
    stale.stream = Some(StreamIdentity { id: 7, instance: 1 });

    runtime.session.close_websocket_lane(stale);

    {
        let state = runtime.session.state.lock();
        assert_eq!(
            state.websocket_lane_reservations.get(&7),
            Some(&replacement_claim)
        );
        assert!(
            state
                .active_peer_ports
                .contains(&replacement_claim.peer_port)
        );
        assert_eq!(
            state.carrier_lanes.get(&7).map(|lane| lane.instance),
            Some(replacement_claim.lane.instance)
        );
    }
    runtime.session.close_websocket_lane(replacement);
    runtime.shutdown().await;
}

#[tokio::test]
async fn stale_reservation_drop_preserves_replacement_claim() {
    let runtime = runtime(true);
    let mut stale = runtime.session.reserve_websocket_lane(7).unwrap();
    stale.bind(1).unwrap();
    let replacement = replacement_lane(&runtime, &stale);
    let replacement_claim = replacement.claim;

    drop(stale);

    {
        let state = runtime.session.state.lock();
        assert_eq!(
            state.websocket_lane_reservations.get(&7),
            Some(&replacement_claim)
        );
        assert!(
            state
                .active_peer_ports
                .contains(&replacement_claim.peer_port)
        );
    }
    runtime.session.close_websocket_lane(replacement);
    runtime.shutdown().await;
}

#[tokio::test]
async fn exact_lane_teardown_wakes_stream_after_releasing_session_lock() {
    let runtime = runtime(true);
    let mut reservation = runtime.session.reserve_websocket_lane(7).unwrap();
    reservation.bind(1).unwrap();
    let claim = reservation.claim;
    let stream = StreamIdentity { id: 7, instance: 1 };
    let read_lock_was_free = Arc::new(AtomicBool::new(false));
    let write_lock_was_free = Arc::new(AtomicBool::new(false));
    let read_waker = Waker::from(Arc::new(SessionLockProbe {
        session: Arc::downgrade(&runtime.session),
        lock_was_free: Arc::clone(&read_lock_was_free),
    }));
    let write_waker = Waker::from(Arc::new(SessionLockProbe {
        session: Arc::downgrade(&runtime.session),
        lock_was_free: Arc::clone(&write_lock_was_free),
    }));
    runtime.session.state.lock().streams.insert(
        stream.id,
        StreamState {
            instance: stream.instance,
            inbound: VecDeque::new(),
            receive_window: frame::INITIAL_STREAM_WINDOW,
            send_credit: u64::from(frame::INITIAL_STREAM_WINDOW),
            read_waker: Some(read_waker),
            write_waker: Some(write_waker),
        },
    );

    runtime
        .session
        .release_websocket_lane_claim(claim, Some(stream), false);

    assert!(read_lock_was_free.load(Ordering::Acquire));
    assert!(write_lock_was_free.load(Ordering::Acquire));
    assert!(
        runtime
            .session
            .state
            .lock()
            .active_peer_ports
            .remove(&claim.peer_port)
    );
    runtime.manager.release_stream(
        runtime.session.profile_key,
        runtime.session.client_ip,
        runtime.session.profile.shared.public_addr,
        claim.peer_port,
    );
    drop(reservation);
    runtime.shutdown().await;
}

#[tokio::test]
async fn stale_transfer_cannot_remove_current_reservation() {
    let runtime = runtime(true);
    let mut stale = runtime.session.reserve_websocket_lane(7).unwrap();
    stale.bind(1).unwrap();
    let replacement = replacement_lane(&runtime, &stale);
    let replacement_claim = replacement.claim;

    assert_eq!(
        stale.transfer_to_stream(StreamIdentity { id: 7, instance: 1 }),
        Err(ManagerError::Closed)
    );
    assert_eq!(
        runtime
            .session
            .state
            .lock()
            .websocket_lane_reservations
            .get(&7),
        Some(&replacement_claim)
    );
    drop(stale);
    runtime.session.close_websocket_lane(replacement);
    runtime.shutdown().await;
}
