use super::*;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use arc_swap::ArcSwap;

use crate::config::{
    ProxyConfig, WebCarrier, WebLimitsConfig, WebRuntimeProfile, WebSecretMode, WebTimeoutsConfig,
};
use crate::maestro::generation::test_runtime_generation;
use crate::web::manager::WebProcessRuntime;

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

fn session() -> (Arc<WebSession>, Arc<WebProcessRuntime>) {
    let generation = test_runtime_generation(1, ProxyConfig::default());
    let manager = WebProcessRuntime::start(Arc::new(ArcSwap::from(generation)));
    let profile = Arc::new(WebRuntimeProfile {
        host: "proxy.example.com".to_string(),
        capability: [0; 32],
        shared: Arc::new(crate::config::WebRuntimeProfileShared {
            derivation_context: [0; 32],
            public_addr: SocketAddr::from(([203, 0, 113, 10], 443)),
            user: "alice".to_string(),
            secret_mode: WebSecretMode::Plain,
            carrier: WebCarrier::Https,
            carrier_negotiation_enabled: false,
            carrier_learning: false,
            carriers: Arc::from([WebCarrier::Https]),
            carrier_negotiation_deadlines_secs: [3, 5, 8, 12],
            credential_id: [0; 16],
            key_fingerprint: "0000000000000000".to_string(),
            max_sessions: 1,
            max_streams: 1,
            max_streams_per_session: 1,
        }),
    });
    let timeouts = WebTimeoutsConfig {
        long_poll_secs: 1,
        ..WebTimeoutsConfig::default()
    };
    let session = WebSession::new(
        Arc::downgrade(&manager),
        [1; 32],
        "192.0.2.10".parse().unwrap(),
        1,
        profile,
        [2; 32],
        WebCarrier::Https,
        1,
        [3; 32],
        None,
        crate::web::manager::CarrierClientClass::Legacy,
        None,
        false,
        false,
        WebLimitsConfig::default(),
        timeouts,
        None,
    );
    (session, manager)
}

fn queue_close(session: &WebSession) {
    session.with_state_effects(|state, effects| {
        assert!(session.queue_control_locked(state, effects, FrameType::Close, 1, &[]));
    });
}

#[tokio::test]
async fn queued_frame_notifies_only_after_releasing_session_lock() {
    let (session, manager) = session();
    let lock_was_free = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(SessionLockProbe {
        session: Arc::downgrade(&session),
        lock_was_free: Arc::clone(&lock_was_free),
    }));
    let mut context = Context::from_waker(&waker);
    let mut notified = Box::pin(session.down_notify.notified());
    assert!(matches!(
        notified.as_mut().poll(&mut context),
        Poll::Pending
    ));

    queue_close(&session);

    assert!(lock_was_free.load(Ordering::Acquire));
    session.close(super::SessionCloseReason::ApiClose);
    manager.shutdown().await;
}

#[tokio::test]
async fn budget_release_notifies_only_after_session_accounting_and_unlock() {
    let (session, manager) = session();
    queue_close(&session);
    let lock_was_free = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(SessionLockProbe {
        session: Arc::downgrade(&session),
        lock_was_free: Arc::clone(&lock_was_free),
    }));
    let mut context = Context::from_waker(&waker);
    let mut notified = Box::pin(manager.budget_notify().notified_owned());
    assert!(matches!(
        notified.as_mut().poll(&mut context),
        Poll::Pending
    ));

    session.with_state_effects(|state, effects| {
        let bytes = state.pending_control_bytes;
        let items = state.pending_control_items;
        state.pending_frames.clear();
        state.pending_windows.clear();
        session.release_locked(state, effects, bytes, items, true);
        assert_eq!(state.pending_bytes, 0);
        assert_eq!(state.pending_items, 0);
    });

    assert!(lock_was_free.load(Ordering::Acquire));
    session.close(super::SessionCloseReason::ApiClose);
    manager.shutdown().await;
}

#[tokio::test]
async fn staging_permit_wakes_waiter_after_batch_publication_and_unlock() {
    let (session, manager) = session();
    queue_close(&session);
    let body_len = session
        .state
        .lock()
        .pending_frames
        .front()
        .map(|frame| frame.encoded.len())
        .unwrap();
    let held = manager
        .try_downlink_staging_budget(session.limits.max_body_bytes_global - body_len)
        .unwrap();
    let semaphore = Arc::clone(held.semaphore());
    let lock_was_free = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(SessionLockProbe {
        session: Arc::downgrade(&session),
        lock_was_free: Arc::clone(&lock_was_free),
    }));
    let mut context = Context::from_waker(&waker);
    let mut effects = DeferredSessionEffects::new();
    let mut state = session.state.lock();
    let batch = session
        .take_down_batch_locked(&mut state, &mut effects, 0)
        .unwrap();
    let mut waiter = Box::pin(semaphore.acquire_owned());
    assert!(matches!(waiter.as_mut().poll(&mut context), Poll::Pending));
    assert!(state.unacked.replace(batch).is_none());
    drop(state);

    effects.finish();

    assert!(lock_was_free.load(Ordering::Acquire));
    drop(waiter);
    drop(held);
    session.close(super::SessionCloseReason::ApiClose);
    manager.shutdown().await;
}

#[tokio::test]
async fn downlink_replays_unacknowledged_batch_byte_for_byte() {
    let (session, manager) = session();
    queue_close(&session);
    let first = session.poll_down(0).await.unwrap();
    let replay = session.poll_down(0).await.unwrap();
    assert_eq!(first.next_cursor, 1);
    assert_eq!(replay.next_cursor, 1);
    assert_eq!(first.body, replay.body);
    drop(first);
    drop(replay);
    session.close(super::SessionCloseReason::ApiClose);
    manager.shutdown().await;
}

#[tokio::test]
async fn acknowledged_response_stays_resident_until_the_last_body_clone_drops() {
    let (session, manager) = session();
    queue_close(&session);
    let response = session.poll_down(0).await.unwrap();
    let retained = response.body.clone();
    session.with_state_effects(|state, effects| {
        session.release_unacked_locked(state, effects);
        assert_eq!(state.pending_bytes, 0);
    });
    assert!(session.resident.snapshot().bytes() > 0);
    drop(response);
    assert!(session.resident.snapshot().bytes() > 0);
    drop(retained);
    assert_eq!(session.resident.snapshot().bytes(), 0);
    session.close(super::SessionCloseReason::ApiClose);
    manager.shutdown().await;
}

#[tokio::test]
async fn invalid_or_overflowing_cursor_closes_session() {
    let (invalid, invalid_manager) = session();
    assert!(matches!(
        invalid.poll_down(1).await,
        Err(ManagerError::Protocol)
    ));
    assert!(invalid.state.lock().closed);
    invalid_manager.shutdown().await;

    let (overflow, overflow_manager) = session();
    {
        let mut state = overflow.state.lock();
        state.down_cursor = u64::MAX;
    }
    queue_close(&overflow);
    assert!(matches!(
        overflow.poll_down(u64::MAX).await,
        Err(ManagerError::Protocol)
    ));
    assert!(overflow.state.lock().closed);
    overflow_manager.shutdown().await;
}

#[tokio::test]
async fn newer_poll_supersedes_older_poll_without_closing_session() {
    let (session, manager) = session();
    let first_session = Arc::clone(&session);
    let first = tokio::spawn(async move { first_session.poll_down(0).await });
    while session.state.lock().down_epoch < 1 {
        tokio::task::yield_now().await;
    }
    let second_session = Arc::clone(&session);
    let second = tokio::spawn(async move { second_session.poll_down(0).await });
    while session.state.lock().down_epoch < 2 {
        tokio::task::yield_now().await;
    }
    let superseded = tokio::time::timeout(Duration::from_secs(1), first)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(superseded.body.is_empty());
    assert_eq!(superseded.next_cursor, 0);
    assert!(!session.state.lock().closed);
    second.abort();
    session.close(super::SessionCloseReason::ApiClose);
    manager.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poll_queue_scheduler_pressure_preserves_single_batch_ownership() {
    const POLLS: usize = 256;

    let (session, manager) = session();
    let mut polls = tokio::task::JoinSet::new();
    for _ in 0..POLLS {
        let polling = Arc::clone(&session);
        polls.spawn(async move { polling.poll_down(0).await });
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while session.state.lock().down_epoch < POLLS as u64 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    queue_close(&session);

    let mut nonempty = 0usize;
    tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(result) = polls.join_next().await {
            let result = result.unwrap().unwrap();
            nonempty += usize::from(!result.body.is_empty());
        }
    })
    .await
    .unwrap();

    assert_eq!(nonempty, 1);
    assert!(!session.state.lock().closed);
    session.close(super::SessionCloseReason::ApiClose);
    manager.shutdown().await;
}

#[tokio::test]
async fn websocket_downlink_poll_does_not_extend_the_peer_lease() {
    let (session, manager) = session();
    session
        .state
        .lock()
        .activity
        .touch_peer(Instant::now() - Duration::from_secs(121));
    queue_close(&session);

    session.poll_down_websocket(0).await.unwrap();

    assert!(session.close_if_due(Instant::now()));
    manager.shutdown().await;
}
