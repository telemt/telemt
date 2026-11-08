use super::*;
use std::collections::VecDeque;
use std::future::Future;
use std::task::{Context, Poll, Wake, Waker};

use crate::config::{ProxyConfig, WebCarrier, WebRuntimeProfile, WebSecretMode, WebTimeoutsConfig};
use crate::maestro::generation::test_runtime_generation;
use crate::web::frame::{self, FrameType};
use crate::web::manager::{CarrierClientClass, WebProcessRuntime};
use crate::web::session::{CarrierLane, StreamState};
use arc_swap::ArcSwap;

fn fixture(
    carrier: WebCarrier,
    limits: WebLimitsConfig,
    automatic: bool,
) -> (Arc<WebSession>, Arc<WebProcessRuntime>) {
    let mut config = ProxyConfig::default();
    config.web.limits = limits.clone();
    let manager =
        WebProcessRuntime::start(Arc::new(ArcSwap::from(test_runtime_generation(1, config))));
    let profile = Arc::new(WebRuntimeProfile {
        host: "proxy.example.com".into(),
        capability: [0; 32],
        shared: Arc::new(crate::config::WebRuntimeProfileShared {
            derivation_context: [0; 32],
            public_addr: "203.0.113.10:443".parse().unwrap(),
            user: "default".into(),
            secret_mode: WebSecretMode::Plain,
            carrier,
            carrier_negotiation_enabled: automatic,
            carrier_learning: false,
            carriers: Arc::from([carrier]),
            carrier_negotiation_deadlines_secs: [3, 5, 8, 12],
            credential_id: [0; 16],
            key_fingerprint: "0000000000000000".into(),
            max_sessions: 2,
            max_streams: 2,
            max_streams_per_session: 2,
        }),
    });
    let session = WebSession::new(
        Arc::downgrade(&manager),
        [1; 32],
        "192.0.2.1".parse().unwrap(),
        1,
        profile,
        [2; 32],
        carrier,
        1,
        [3; 32],
        None,
        if automatic {
            CarrierClientClass::Bridge
        } else {
            CarrierClientClass::Legacy
        },
        None,
        automatic,
        false,
        limits,
        WebTimeoutsConfig::default(),
        None,
    );
    session.configure_conveyor(4);
    (session, manager)
}

fn claim(session: &Arc<WebSession>, lane: Option<u32>, seq: u64, ack: u64) -> ConveyorClaim {
    session
        .claim_conveyor(lane, seq, Some(ack))
        .unwrap()
        .unwrap()
}

fn stream(session: &WebSession, carrier: WebCarrier) -> Option<u32> {
    let mut state = session.state.lock();
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
    if carrier.uses_lanes() {
        state.carrier_lanes.insert(7, CarrierLane::new(7));
        Some(7)
    } else {
        None
    }
}

async fn cleanup(session: Arc<WebSession>, manager: Arc<WebProcessRuntime>) {
    session.close(SessionCloseReason::ApiClose);
    session.wait().await;
    manager.shutdown().await;
}

#[tokio::test]
async fn reordered_data_and_window_apply_once_in_sequence_for_both_carriers() {
    for carrier in [WebCarrier::Https, WebCarrier::HttpsLanes] {
        let (session, manager) = fixture(carrier, WebLimitsConfig::default(), false);
        let lane = stream(&session, carrier);
        let first = frame::encode(FrameType::Data, 7, b"first");
        let second = frame::encode(FrameType::Data, 7, b"second");
        let credit = frame::encode(FrameType::Window, 7, &5u32.to_be_bytes());
        let second_claim = claim(&session, lane, 2, 0);
        let credit_claim = claim(&session, lane, 3, 0);
        let mut second_wait = Box::pin(second_claim.process(&second));
        let mut credit_wait = Box::pin(credit_claim.process(&credit));
        assert!(futures::poll!(&mut second_wait).is_pending());
        assert!(futures::poll!(&mut credit_wait).is_pending());
        assert!(session.state.lock().streams[&7].inbound.is_empty());
        assert_eq!(claim(&session, lane, 1, 0).process(&first).await, Ok(1));
        assert!(futures::poll!(&mut credit_wait).is_pending());
        assert_eq!(second_wait.await, Ok(2));
        assert_eq!(credit_wait.await, Ok(3));
        for (seq, body) in [(1, &first), (2, &second), (3, &credit)] {
            assert_eq!(claim(&session, lane, seq, 0).process(body).await, Ok(seq));
        }
        {
            let state = session.state.lock();
            let stream = &state.streams[&7];
            assert_eq!(stream.inbound.len(), 2);
            assert_eq!(stream.inbound[0].bytes.as_ref(), b"first");
            assert_eq!(stream.inbound[1].bytes.as_ref(), b"second");
            assert_eq!(stream.send_credit, 5);
            assert_eq!(state.conveyor.channels[&lane].committed, 3);
        }
        cleanup(session, manager).await;
    }
}

#[tokio::test]
async fn confirmed_floor_retires_only_acknowledged_history_and_never_replays_it() {
    let (session, manager) = fixture(WebCarrier::Https, WebLimitsConfig::default(), false);
    let body = frame::encode(FrameType::Pong, 0, b"same");
    for seq in 1..=4 {
        assert_eq!(claim(&session, None, seq, 0).process(&body).await, Ok(seq));
    }
    // ACK2 through ACK4 do not constitute confirmation of a lost ACK1.
    assert_eq!(claim(&session, None, 1, 0).process(&body).await, Ok(1));
    assert_eq!(claim(&session, None, 5, 4).process(&body).await, Ok(5));
    assert!(matches!(
        session.claim_conveyor(None, 1, Some(0)),
        Err(ConveyorError::Stale)
    ));
    assert!(!session.state.lock().closed);
    assert_eq!(session.state.lock().last_up_sequence, 5);
    assert_eq!(
        session.state.lock().conveyor.channels[&None]
            .slots
            .iter()
            .flatten()
            .count(),
        1
    );
    cleanup(session, manager).await;
}

#[tokio::test]
async fn digest_mismatch_and_window_violations_are_terminal() {
    for invalid in [0, 1, 2] {
        let (session, manager) = fixture(WebCarrier::Https, WebLimitsConfig::default(), false);
        let body = frame::encode(FrameType::Pong, 0, b"first");
        assert_eq!(claim(&session, None, 1, 0).process(&body).await, Ok(1));
        if invalid == 0 {
            let changed = frame::encode(FrameType::Pong, 0, b"changed");
            assert_eq!(
                claim(&session, None, 1, 0).process(&changed).await,
                Err(ConveyorError::Manager(ManagerError::Protocol))
            );
        } else {
            let (sequence, confirmed) = if invalid == 1 { (5, 0) } else { (3, 2) };
            assert!(matches!(
                session.claim_conveyor(None, sequence, Some(confirmed)),
                Err(ConveyorError::Manager(ManagerError::Protocol))
            ));
        }
        assert!(session.state.lock().closed);
        cleanup(session, manager).await;
    }
}

#[tokio::test]
async fn duplicate_pending_claims_and_cancelled_owners_do_not_consume_or_erase_new_slots() {
    let (session, manager) = fixture(WebCarrier::Https, WebLimitsConfig::default(), false);
    let first = claim(&session, None, 2, 0);
    assert!(matches!(
        session.claim_conveyor(None, 2, Some(0)),
        Err(ConveyorError::Manager(ManagerError::Concurrent))
    ));
    drop(first);
    assert!(session.state.lock().conveyor.channels.is_empty());
    let cancelled = claim(&session, None, 2, 0);
    session.with_state_effects(|state, effects| {
        effects.notify(state.conveyor.remove(None).unwrap());
    });
    let replacement = claim(&session, None, 2, 0);
    drop(cancelled);
    assert_eq!(
        session.state.lock().conveyor.channels[&None].slots[2]
            .unwrap()
            .owner,
        replacement.owner
    );
    drop(replacement);
    assert!(session.state.lock().conveyor.channels.is_empty());
    cleanup(session, manager).await;
}

#[tokio::test(start_paused = true)]
async fn missing_head_times_out_without_committing_and_returns_waiter_capacity() {
    let (session, manager) = fixture(WebCarrier::Https, WebLimitsConfig::default(), false);
    let body = frame::encode(FrameType::Pong, 0, &[]);
    let tail = claim(&session, None, 2, 0);
    let mut waiting = Box::pin(tail.process(&body));
    assert!(futures::poll!(&mut waiting).is_pending());
    tokio::time::advance(Duration::from_secs(session.timeouts.body_secs)).await;
    assert_eq!(
        waiting.await,
        Err(ConveyorError::Manager(ManagerError::Backpressure))
    );
    assert_eq!(session.state.lock().last_up_sequence, 0);
    drop(tail);
    let mut permits = Vec::new();
    while let Some(permit) = manager.try_conveyor_waiter() {
        permits.push(permit);
    }
    assert_eq!(
        permits.len(),
        conveyor_waiter_limit(&WebLimitsConfig::default())
    );
    drop(permits);
    cleanup(session, manager).await;
}

#[test]
fn waiter_ceiling_always_preserves_head_handler_reader_and_bytes() {
    let defaults = WebLimitsConfig::default();
    assert_eq!(conveyor_waiter_limit(&defaults), 31);
    for (handlers, readers, bodies, expected) in [
        (8, 4, 8, 2),
        (100, 2, 8, 1),
        (100, 8, 2, 1),
        (3, 8, 8, 0),
        (8, 1, 8, 0),
        (8, 8, 1, 0),
    ] {
        let limits = WebLimitsConfig {
            max_http_handlers: handlers,
            max_body_readers: readers,
            max_body_bytes: 32,
            max_body_bytes_global: bodies * 32,
            ..defaults.clone()
        };
        assert_eq!(conveyor_waiter_limit(&limits), expected);
    }
}

#[tokio::test]
async fn future_request_saturation_keeps_head_admissible_before_any_body_is_read() {
    let limits = WebLimitsConfig {
        max_http_handlers: 8,
        max_body_readers: 3,
        max_body_bytes: 32,
        max_body_bytes_global: 96,
        ..WebLimitsConfig::default()
    };
    let (session, manager) = fixture(WebCarrier::HttpsLanes, limits, false);
    let a = claim(&session, Some(7), 2, 0);
    let b = claim(&session, Some(8), 2, 0);
    let a_body = manager.try_body_budget(32).unwrap();
    let b_body = manager.try_body_budget(32).unwrap();
    assert!(matches!(
        session.claim_conveyor(Some(9), 2, Some(0)),
        Err(ConveyorError::Manager(ManagerError::Backpressure))
    ));
    assert!(
        !session
            .state
            .lock()
            .conveyor
            .channels
            .contains_key(&Some(9))
    );
    let head = claim(&session, Some(7), 1, 0);
    let head_body = manager
        .try_body_budget(32)
        .expect("head reader and byte reserve");
    assert!(!session.state.lock().carrier_lanes.contains_key(&7));
    drop((a, b, head, a_body, b_body, head_body));
    cleanup(session, manager).await;
}

#[tokio::test]
async fn mode_is_frozen_and_control_only_ack_cannot_commit_an_automatic_carrier() {
    for carrier in [WebCarrier::Https, WebCarrier::HttpsLanes] {
        let (session, manager) = fixture(carrier, WebLimitsConfig::default(), true);
        let lane = carrier.uses_lanes().then_some(0);
        let body = frame::encode(FrameType::Pong, 0, &[]);
        for _ in 0..2 {
            assert_eq!(
                claim(&session, lane, 1, 0).process(&body).await,
                Err(ConveyorError::Manager(ManagerError::Backpressure))
            );
        }
        assert!(!session.is_carrier_committed());
        assert!(matches!(
            session.claim_conveyor(lane, 2, None),
            Err(ConveyorError::Mode)
        ));
        assert!(!session.state.lock().closed);
        cleanup(session, manager).await;
    }
    let (session, manager) = fixture(WebCarrier::Https, WebLimitsConfig::default(), false);
    assert!(session.claim_conveyor(None, 1, None).unwrap().is_none());
    assert!(matches!(
        session.claim_conveyor(None, 1, Some(0)),
        Err(ConveyorError::Mode)
    ));
    cleanup(session, manager).await;
}

#[tokio::test]
async fn first_data_on_unknown_lane_is_not_silently_acknowledged() {
    let (session, manager) = fixture(WebCarrier::HttpsLanes, WebLimitsConfig::default(), false);
    let body = frame::encode(FrameType::Data, 7, b"not opened");
    assert_eq!(
        claim(&session, Some(7), 1, 0).process(&body).await,
        Err(ConveyorError::Manager(ManagerError::Protocol))
    );
    assert!(session.state.lock().closed);
    cleanup(session, manager).await;
}

struct LockProbe {
    session: Arc<WebSession>,
    notified: std::sync::atomic::AtomicBool,
}

impl Wake for LockProbe {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        assert!(
            self.session.state.try_lock().is_some(),
            "wake under session lock"
        );
        self.notified
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

#[tokio::test]
async fn close_and_lane_retirement_wake_parked_requests_only_after_unlock() {
    for close in [false, true] {
        let (session, manager) = fixture(WebCarrier::HttpsLanes, WebLimitsConfig::default(), false);
        let body = frame::encode(FrameType::Data, 7, b"future");
        let tail = claim(&session, Some(7), 2, 0);
        let mut waiting = Box::pin(tail.process(&body));
        let probe = Arc::new(LockProbe {
            session: Arc::clone(&session),
            notified: std::sync::atomic::AtomicBool::new(false),
        });
        let waker = Waker::from(Arc::clone(&probe));
        assert!(matches!(
            waiting.as_mut().poll(&mut Context::from_waker(&waker)),
            Poll::Pending
        ));
        if close {
            session.close(SessionCloseReason::ApiClose);
        } else {
            session.with_state_effects(|state, effects| {
                session.release_lane_locked(state, effects, 7);
            });
        }
        assert!(probe.notified.load(std::sync::atomic::Ordering::Acquire));
        assert!(waiting.await.is_err());
        assert!(session.state.lock().conveyor.channels.is_empty());
        drop(tail);
        cleanup(session, manager).await;
    }
}

#[tokio::test]
async fn delayed_retry_after_lane_history_retirement_is_request_local() {
    let (session, manager) = fixture(WebCarrier::HttpsLanes, WebLimitsConfig::default(), false);
    let lane = stream(&session, WebCarrier::HttpsLanes);
    let body = frame::encode(FrameType::Window, 7, &1u32.to_be_bytes());
    for seq in 1..=2 {
        assert_eq!(
            claim(&session, lane, seq, seq - 1).process(&body).await,
            Ok(seq)
        );
    }
    session.with_state_effects(|state, effects| {
        state.streams.remove(&7);
        session.release_lane_locked(state, effects, 7);
    });
    assert!(matches!(
        session.claim_conveyor(lane, 2, Some(1)),
        Err(ConveyorError::Stale)
    ));
    assert!(!session.state.lock().closed);
    cleanup(session, manager).await;
}

#[tokio::test]
async fn verified_replay_renews_peer_activity_without_reapplying_credit() {
    let (session, manager) = fixture(WebCarrier::Https, WebLimitsConfig::default(), false);
    stream(&session, WebCarrier::Https);
    let body = frame::encode(FrameType::Window, 7, &1u32.to_be_bytes());
    assert_eq!(claim(&session, None, 1, 0).process(&body).await, Ok(1));
    let now = std::time::Instant::now();
    session.state.lock().activity =
        crate::web::session::activity::SessionActivity::new(now - Duration::from_secs(60));
    assert_eq!(claim(&session, None, 1, 0).process(&body).await, Ok(1));
    assert!(session.state.lock().activity.peer_idle(now) < Duration::from_secs(1));
    assert_eq!(session.state.lock().streams[&7].send_credit, 1);
    cleanup(session, manager).await;
}

#[tokio::test]
async fn full_lane_registry_still_admits_first_control_channel_request() {
    let limits = WebLimitsConfig {
        max_tombstones_per_session: 0,
        ..WebLimitsConfig::default()
    };
    let (session, manager) = fixture(WebCarrier::HttpsLanes, limits, false);
    stream(&session, WebCarrier::HttpsLanes);
    session
        .state
        .lock()
        .carrier_lanes
        .insert(8, CarrierLane::new(8));
    let body = frame::encode(FrameType::Pong, 0, &[]);
    assert_eq!(claim(&session, Some(0), 1, 0).process(&body).await, Ok(1));
    cleanup(session, manager).await;
}

#[test]
fn per_channel_memory_estimate_covers_window_notify_and_hash_table_slack() {
    // The memory-envelope validator reserves 512 additional bytes per bounded lane slot.
    let key_and_value = std::mem::size_of::<(Option<u32>, Channel)>();
    let table_slack = key_and_value.div_ceil(7);
    let notify_allocation = std::mem::size_of::<Notify>() + 2 * std::mem::size_of::<usize>();
    assert!(key_and_value + table_slack + notify_allocation + 32 <= 512);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_windows_preserve_contiguous_application_under_scheduler_pressure() {
    let (session, manager) = fixture(WebCarrier::Https, WebLimitsConfig::default(), false);
    let body = frame::encode(FrameType::Pong, 0, &[]);
    for window in 0..256u64 {
        let confirmed = window * 4;
        let mut tasks = Vec::new();
        for offset in (1..=4).rev() {
            let claim = claim(&session, None, confirmed + offset, confirmed);
            let body = body.clone();
            tasks.push(tokio::spawn(async move {
                tokio::task::yield_now().await;
                claim.process(&body).await
            }));
        }
        for (task, offset) in tasks.into_iter().zip((1..=4).rev()) {
            assert_eq!(task.await.unwrap(), Ok(confirmed + offset));
        }
        let state = session.state.lock();
        assert_eq!(state.last_up_sequence, confirmed + 4);
        assert_eq!(state.conveyor.channels[&None].committed, confirmed + 4);
        assert_eq!(
            state.conveyor.channels[&None]
                .slots
                .iter()
                .flatten()
                .count(),
            4
        );
    }
    cleanup(session, manager).await;
}

#[tokio::test]
async fn next_head_waits_for_previous_synchronous_uplink_guard_to_drop() {
    let (session, manager) = fixture(WebCarrier::Https, WebLimitsConfig::default(), false);
    let body = frame::encode(FrameType::Pong, 0, &[]);
    let head = claim(&session, None, 1, 0);
    session
        .up_active
        .store(true, std::sync::atomic::Ordering::Release);
    let mut waiting = Box::pin(head.process(&body));
    assert!(futures::poll!(&mut waiting).is_pending());
    session
        .up_active
        .store(false, std::sync::atomic::Ordering::Release);
    head.notify.notify_waiters();
    assert_eq!(waiting.await, Ok(1));
    cleanup(session, manager).await;
}

#[tokio::test]
async fn new_lane_future_data_waits_for_open_without_creating_a_backend_early() {
    let (session, manager) = fixture(WebCarrier::HttpsLanes, WebLimitsConfig::default(), true);
    let body = frame::encode(FrameType::Data, 7, b"first inner bytes");
    let future = claim(&session, Some(7), 2, 0);
    let mut waiting = Box::pin(future.process(&body));
    assert!(futures::poll!(&mut waiting).is_pending());
    assert!(session.state.lock().streams.is_empty());
    assert!(!session.state.lock().carrier_lanes.contains_key(&7));
    assert_eq!(session.tasks_live(), 0);
    assert!(!session.is_carrier_committed());
    let open = frame::encode(FrameType::Open, 7, &[]);
    assert_eq!(claim(&session, Some(7), 1, 0).process(&open).await, Ok(1));
    assert!(session.is_carrier_committed());
    assert_eq!(waiting.await, Ok(2));
    assert_eq!(
        session.state.lock().streams[&7].inbound[0].bytes,
        b"first inner bytes"[..]
    );
    cleanup(session, manager).await;
}
