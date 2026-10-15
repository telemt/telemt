use std::net::SocketAddr;
use std::sync::{Arc, Barrier};

use super::*;
use crate::config::{
    WebCarrier, WebLimitsConfig, WebRuntimeProfile, WebSecretMode, WebTimeoutsConfig,
};
use crate::web::manager::{CarrierClientClass, WebProcessRuntime};
use crate::web::session::{SessionCloseOutcome, SessionCloseReason};

fn session(carrier: WebCarrier, deadline: Instant) -> Arc<WebSession> {
    let profile = Arc::new(WebRuntimeProfile {
        host: "proxy.example.com".to_string(),
        capability: [0; 32],
        shared: Arc::new(crate::config::WebRuntimeProfileShared {
            public_addr: SocketAddr::from(([203, 0, 113, 10], 443)),
            user: "alice".to_string(),
            secret_mode: WebSecretMode::Plain,
            carrier,
            carrier_negotiation_enabled: true,
            carrier_learning: false,
            carriers: Arc::from([carrier]),
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
        carrier,
        1,
        [3; 32],
        Some(deadline),
        CarrierClientClass::Bridge,
        None,
        true,
        false,
        WebLimitsConfig::default(),
        WebTimeoutsConfig::default(),
        None,
    )
}

fn arm_http_health(session: &WebSession, now: Instant) {
    let mut state = session.state.lock();
    state.negotiation_phase = SessionNegotiationPhase::Committed;
    state.carrier_commit_published = true;
    state.carrier_health_due_at = Some(now - Duration::from_secs(1));
    state.carrier_health_uplink = true;
    state.carrier_health_downlink = true;
    state.carrier_health_activity_at = Some(now);
}

#[test]
fn final_deadline_refuses_uncommitted_progress() {
    let session = session(WebCarrier::Https, Instant::now() - Duration::from_secs(1));
    let state = session.state.lock();
    assert_eq!(
        session.ensure_carrier_active_locked(&state),
        Err(crate::web::manager::ManagerError::Closed)
    );
    assert!(matches!(
        state.negotiation_phase,
        SessionNegotiationPhase::Uncommitted
    ));
}

#[test]
fn http_health_requires_authenticated_activity_after_the_window() {
    let session = session(WebCarrier::Https, Instant::now() + Duration::from_secs(60));
    let now = Instant::now();
    let mut state = session.state.lock();
    state.negotiation_phase = SessionNegotiationPhase::Committed;
    state.carrier_commit_published = true;
    state.carrier_health_due_at = Some(now - Duration::from_secs(1));
    state.carrier_health_uplink = true;
    state.carrier_health_downlink = true;
    state.carrier_health_activity_at = Some(now - Duration::from_secs(2));
    assert!(
        session
            .carrier_health_ready_locked(&mut state, now)
            .is_none()
    );
    state.carrier_health_activity_at = Some(now);
    assert!(
        session
            .carrier_health_ready_locked(&mut state, now)
            .is_some()
    );
}

#[test]
fn websocket_health_requires_the_exact_live_probe_owner() {
    let session = session(
        WebCarrier::Websocket,
        Instant::now() + Duration::from_secs(60),
    );
    let now = Instant::now();
    let mut state = session.state.lock();
    state.negotiation_phase = SessionNegotiationPhase::Committed;
    state.carrier_commit_published = true;
    state.carrier_health_due_at = Some(now - Duration::from_secs(1));
    state.websocket_carrier_active = true;
    state.websocket_commit_ack_owner = Some(7);
    state.websocket_commit_ack_written = true;
    state.carrier_health_uplink = true;
    assert!(
        session
            .carrier_health_ready_locked(&mut state, now)
            .is_none()
    );
    state.websocket_probe_claimed = true;
    assert!(
        session
            .carrier_health_ready_locked(&mut state, now)
            .is_some()
    );
}

#[test]
fn health_waits_for_manager_commit_publication() {
    let session = session(WebCarrier::Https, Instant::now() + Duration::from_secs(60));
    let now = Instant::now();
    let mut state = session.state.lock();
    state.negotiation_phase = SessionNegotiationPhase::Committed;
    state.carrier_health_due_at = Some(now - Duration::from_secs(1));
    state.carrier_health_uplink = true;
    state.carrier_health_downlink = true;
    state.carrier_health_activity_at = Some(now);

    assert!(
        session
            .carrier_health_ready_locked(&mut state, now)
            .is_none()
    );
    assert_eq!(
        session.carrier_health_publication_state(),
        CarrierHealthPublicationState::Awaiting
    );
}

#[test]
fn health_publication_claim_is_single_shot() {
    let session = session(WebCarrier::Https, Instant::now() + Duration::from_secs(60));
    let now = Instant::now();
    arm_http_health(&session, now);
    let mut state = session.state.lock();

    assert!(
        session
            .carrier_health_ready_locked(&mut state, now)
            .is_some()
    );
    assert!(
        session
            .carrier_health_ready_locked(&mut state, now)
            .is_none()
    );
    drop(state);
    assert_eq!(
        session.carrier_health_publication_state(),
        CarrierHealthPublicationState::Publishing
    );
    assert!(session.publish_carrier_health());
    assert!(!session.publish_carrier_health());
    assert_eq!(
        session.carrier_health_publication_state(),
        CarrierHealthPublicationState::Published
    );
}

#[test]
fn concurrent_health_and_close_always_reach_one_terminal_state() {
    for _ in 0..512 {
        let session = session(WebCarrier::Https, Instant::now() + Duration::from_secs(60));
        let now = Instant::now();
        arm_http_health(&session, now);
        let barrier = Arc::new(Barrier::new(3));
        let health_session = Arc::clone(&session);
        let health_barrier = Arc::clone(&barrier);
        let health = std::thread::spawn(move || {
            health_barrier.wait();
            std::thread::yield_now();
            let claim = {
                let mut state = health_session.state.lock();
                health_session.carrier_health_ready_locked(&mut state, now)
            };
            if claim.is_some() {
                health_session.publish_carrier_health();
            }
        });
        let close_session = Arc::clone(&session);
        let close_barrier = Arc::clone(&barrier);
        let close = std::thread::spawn(move || {
            close_barrier.wait();
            std::thread::yield_now();
            close_session.close(SessionCloseReason::ApiClose);
        });
        barrier.wait();
        health.join().unwrap();
        close.join().unwrap();

        assert!(matches!(
            session.carrier_health_publication_state(),
            CarrierHealthPublicationState::Published | CarrierHealthPublicationState::Rejected
        ));
        assert!(!session.publish_carrier_health());
        assert_eq!(
            session.close(SessionCloseReason::ApiClose),
            SessionCloseOutcome::AlreadyClosing
        );
    }
}

#[test]
fn commit_and_supersede_have_one_session_lock_winner() {
    let committed = session(WebCarrier::Https, Instant::now() + Duration::from_secs(60));
    {
        let mut state = committed.state.lock();
        assert!(
            committed
                .record_uplink_progress_locked(
                    &mut state,
                    AppliedProgress {
                        accepted_open: true,
                        accepted_data: true,
                    },
                )
                .0
        );
    }
    assert!(!committed.begin_carrier_supersede());

    let replacing = session(WebCarrier::Https, Instant::now() + Duration::from_secs(60));
    assert!(replacing.begin_carrier_supersede());
    assert_eq!(
        replacing.ensure_carrier_active_locked(&replacing.state.lock()),
        Err(crate::web::manager::ManagerError::Closed)
    );
    replacing.cancel_carrier_supersede();
    assert!(
        replacing
            .ensure_carrier_active_locked(&replacing.state.lock())
            .is_ok()
    );
}
