use super::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::task::{Wake, Waker};

use crate::config::{
    WebCarrier, WebLimitsConfig, WebRuntimeProfile, WebSecretMode, WebTimeoutsConfig,
};
use crate::web::manager::WebProcessRuntime;
use crate::web::session::SessionCloseOutcome;

fn session() -> Arc<WebSession> {
    session_with_automatic(false)
}

fn session_with_automatic(automatic: bool) -> Arc<WebSession> {
    let profile = Arc::new(WebRuntimeProfile {
        host: "proxy.example.com".to_string(),
        capability: [0; 32],
        shared: Arc::new(crate::config::WebRuntimeProfileShared {
            public_addr: SocketAddr::from(([203, 0, 113, 10], 443)),
            user: "alice".to_string(),
            secret_mode: WebSecretMode::Plain,
            carrier: WebCarrier::Https,
            carrier_negotiation_enabled: false,
            carrier_learning: true,
            carriers: Arc::from([WebCarrier::Https]),
            carrier_negotiation_deadlines_secs: [3, 5, 8, 12],
            credential_id: [0; 16],
            key_fingerprint: "0000000000000000".to_string(),
            max_sessions: 1,
            max_streams: 1,
            max_streams_per_session: 1,
        }),
    });
    WebSession::new(
        std::sync::Weak::<WebProcessRuntime>::new(),
        [1; 32],
        "192.0.2.10".parse().unwrap(),
        1,
        profile,
        [2; 32],
        WebCarrier::Https,
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
        WebLimitsConfig::default(),
        WebTimeoutsConfig::default(),
        None,
    )
}

struct SessionLockProbe {
    session: std::sync::Weak<WebSession>,
    lock_was_free: Arc<AtomicBool>,
}

impl Wake for SessionLockProbe {
    fn wake(self: Arc<Self>) {
        if let Some(session) = self.session.upgrade() {
            self.lock_was_free
                .store(session.state.try_lock().is_some(), AtomicOrdering::Release);
        }
    }
}

#[test]
fn close_wakes_stream_only_after_releasing_session_lock() {
    let session = session();
    let lock_was_free = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(SessionLockProbe {
        session: Arc::downgrade(&session),
        lock_was_free: Arc::clone(&lock_was_free),
    }));
    {
        let mut state = session.state.lock();
        state.streams.insert(
            1,
            StreamState {
                instance: 1,
                inbound: VecDeque::new(),
                receive_window: frame::INITIAL_STREAM_WINDOW,
                send_credit: u64::from(frame::INITIAL_STREAM_WINDOW),
                read_waker: Some(waker),
                write_waker: None,
            },
        );
    }

    assert_eq!(
        session.close(SessionCloseReason::ApiClose),
        SessionCloseOutcome::Closed
    );
    assert!(lock_was_free.load(AtomicOrdering::Acquire));
}

#[test]
fn supersede_completion_defers_stream_wake_until_finish() {
    let session = session();
    let lock_was_free = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(SessionLockProbe {
        session: Arc::downgrade(&session),
        lock_was_free: Arc::clone(&lock_was_free),
    }));
    {
        let mut state = session.state.lock();
        state.streams.insert(
            1,
            StreamState {
                instance: 1,
                inbound: VecDeque::new(),
                receive_window: frame::INITIAL_STREAM_WINDOW,
                send_credit: u64::from(frame::INITIAL_STREAM_WINDOW),
                read_waker: Some(waker),
                write_waker: None,
            },
        );
    }

    assert!(session.begin_carrier_supersede());
    let completion = session.prepare_carrier_supersede().unwrap();
    assert!(!lock_was_free.load(AtomicOrdering::Acquire));
    completion.finish();
    assert!(lock_was_free.load(AtomicOrdering::Acquire));
}

#[test]
fn data_wakes_reader_only_after_releasing_session_lock() {
    let session = session();
    let lock_was_free = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(SessionLockProbe {
        session: Arc::downgrade(&session),
        lock_was_free: Arc::clone(&lock_was_free),
    }));
    {
        let mut state = session.state.lock();
        state.streams.insert(
            1,
            StreamState {
                instance: 1,
                inbound: VecDeque::new(),
                receive_window: frame::INITIAL_STREAM_WINDOW,
                send_credit: u64::from(frame::INITIAL_STREAM_WINDOW),
                read_waker: Some(waker),
                write_waker: None,
            },
        );
    }

    let body = frame::encode(FrameType::Data, 1, &[1]);
    let frames = frame::parse_all(&body, &session.limits).unwrap();
    let mut opened = Vec::new();
    let mut unused_bytes = body.len().saturating_add(QUEUE_ITEM_COST);
    let mut unused_items = 1;
    let mut progress = AppliedProgress::default();
    session.with_state_effects(|state, effects| {
        assert!(session.apply_batch_locked(
            state,
            &frames,
            effects,
            &mut opened,
            &mut None,
            &mut unused_bytes,
            &mut unused_items,
            &mut progress,
        ));
    });
    assert!(lock_was_free.load(AtomicOrdering::Acquire));
}

#[test]
fn rejected_batch_dispatches_prior_effects_after_releasing_session_lock() {
    let session = session();
    let lock_was_free = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(SessionLockProbe {
        session: Arc::downgrade(&session),
        lock_was_free: Arc::clone(&lock_was_free),
    }));
    {
        let mut state = session.state.lock();
        state.streams.insert(
            1,
            StreamState {
                instance: 1,
                inbound: VecDeque::new(),
                receive_window: frame::INITIAL_STREAM_WINDOW,
                send_credit: u64::from(frame::INITIAL_STREAM_WINDOW),
                read_waker: Some(waker),
                write_waker: None,
            },
        );
    }

    let mut body = frame::encode(FrameType::Data, 1, &[1]).to_vec();
    body.extend_from_slice(&frame::encode(FrameType::Ping, 1, &[]));
    let frames = frame::parse_all(&body, &session.limits).unwrap();
    let mut opened = Vec::new();
    let mut unused_bytes = body.len().saturating_add(QUEUE_ITEM_COST);
    let mut unused_items = 1;
    let mut progress = AppliedProgress::default();
    let applied = session.with_state_effects(|state, effects| {
        session.apply_batch_locked(
            state,
            &frames,
            effects,
            &mut opened,
            &mut None,
            &mut unused_bytes,
            &mut unused_items,
            &mut progress,
        )
    });

    assert!(!applied);
    assert!(lock_was_free.load(AtomicOrdering::Acquire));
}

#[test]
fn window_wakes_writer_only_after_releasing_session_lock() {
    let session = session();
    let lock_was_free = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(SessionLockProbe {
        session: Arc::downgrade(&session),
        lock_was_free: Arc::clone(&lock_was_free),
    }));
    {
        let mut state = session.state.lock();
        state.streams.insert(
            1,
            StreamState {
                instance: 1,
                inbound: VecDeque::new(),
                receive_window: frame::INITIAL_STREAM_WINDOW,
                send_credit: 0,
                read_waker: None,
                write_waker: Some(waker),
            },
        );
    }

    let body = frame::encode(FrameType::Window, 1, &frame::window_payload(1));
    let frames = frame::parse_all(&body, &session.limits).unwrap();
    let mut opened = Vec::new();
    let mut unused_bytes = 0;
    let mut unused_items = 0;
    let mut progress = AppliedProgress::default();
    session.with_state_effects(|state, effects| {
        assert!(session.apply_batch_locked(
            state,
            &frames,
            effects,
            &mut opened,
            &mut None,
            &mut unused_bytes,
            &mut unused_items,
            &mut progress,
        ));
    });
    assert!(lock_was_free.load(AtomicOrdering::Acquire));
}

#[test]
fn close_frame_wakes_both_stream_halves_after_releasing_session_lock() {
    let session = session();
    let read_lock_was_free = Arc::new(AtomicBool::new(false));
    let write_lock_was_free = Arc::new(AtomicBool::new(false));
    let read_waker = Waker::from(Arc::new(SessionLockProbe {
        session: Arc::downgrade(&session),
        lock_was_free: Arc::clone(&read_lock_was_free),
    }));
    let write_waker = Waker::from(Arc::new(SessionLockProbe {
        session: Arc::downgrade(&session),
        lock_was_free: Arc::clone(&write_lock_was_free),
    }));
    {
        let mut state = session.state.lock();
        state.streams.insert(
            1,
            StreamState {
                instance: 1,
                inbound: VecDeque::new(),
                receive_window: frame::INITIAL_STREAM_WINDOW,
                send_credit: u64::from(frame::INITIAL_STREAM_WINDOW),
                read_waker: Some(read_waker),
                write_waker: Some(write_waker),
            },
        );
    }
    let body = frame::encode(FrameType::Close, 1, &[]);
    let frames = frame::parse_all(&body, &session.limits).unwrap();
    let mut opened = Vec::new();
    let mut unused_bytes = 0;
    let mut unused_items = 0;
    let mut progress = AppliedProgress::default();

    session.with_state_effects(|state, effects| {
        assert!(session.apply_batch_locked(
            state,
            &frames,
            effects,
            &mut opened,
            &mut None,
            &mut unused_bytes,
            &mut unused_items,
            &mut progress,
        ));
    });

    assert!(read_lock_was_free.load(AtomicOrdering::Acquire));
    assert!(write_lock_was_free.load(AtomicOrdering::Acquire));
}

#[test]
fn uplink_retry_commits_only_one_exact_body() {
    let session = session();
    let first = frame::encode(FrameType::Pong, 0, &[1, 2, 3]);
    assert_eq!(session.process_up(1, &first), Ok(1));
    assert_eq!(session.process_up(1, &first), Ok(1));

    let changed = frame::encode(FrameType::Pong, 0, &[1, 2, 4]);
    assert_eq!(session.process_up(1, &changed), Err(ManagerError::Protocol));
    assert!(session.state.lock().closed);
}

#[test]
fn concurrent_uplink_does_not_commit_sequence() {
    let session = session();
    let body = frame::encode(FrameType::Pong, 0, &[]);
    session.up_active.store(true, Ordering::Release);
    assert_eq!(session.process_up(1, &body), Err(ManagerError::Concurrent));
    assert_eq!(session.state.lock().last_up_sequence, 0);
    session.up_active.store(false, Ordering::Release);
    assert_eq!(session.process_up(1, &body), Ok(1));
}

#[test]
fn backpressured_uplink_does_not_commit_or_close() {
    let session = session();
    {
        let mut state = session.state.lock();
        state.streams.insert(
            1,
            StreamState {
                instance: 1,
                inbound: VecDeque::new(),
                receive_window: frame::INITIAL_STREAM_WINDOW,
                send_credit: u64::from(frame::INITIAL_STREAM_WINDOW),
                read_waker: None,
                write_waker: None,
            },
        );
        state.pending_bytes = session.limits.pending_bytes_per_session;
    }
    let body = frame::encode(FrameType::Data, 1, &[1]);

    assert_eq!(
        session.process_up(1, &body),
        Err(ManagerError::Backpressure)
    );
    let state = session.state.lock();
    assert!(!state.closed);
    assert_eq!(state.last_up_sequence, 0);
    assert!(state.streams.get(&1).unwrap().inbound.is_empty());
}

#[test]
fn uplink_gap_is_fatal() {
    let session = session();
    let body = frame::encode(FrameType::Pong, 0, &[]);
    assert_eq!(session.process_up(2, &body), Err(ManagerError::Protocol));
    assert!(session.state.lock().closed);
}

#[test]
fn automatic_uplink_does_not_ack_a_batch_without_real_progress() {
    let session = session_with_automatic(true);
    let body = frame::encode(FrameType::Pong, 0, &[]);

    assert_eq!(
        session.process_up(1, &body),
        Err(ManagerError::Backpressure)
    );
    assert!(!session.is_carrier_committed());
    assert!(!session.state.lock().closed);
}
