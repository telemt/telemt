use super::super::*;
use proptest::prelude::*;

// Keep synthetic ownership fixtures separate from the frozen exhaustive algorithm.
include!("fixtures.rs");
#[path = "benchmarks.rs"]
mod benchmarks;
#[path = "production_tests.rs"]
mod production_tests;
#[path = "reference.rs"]
mod reference;

fn assert_equivalent(actual: &ManagerState, expected: &ManagerState) {
    let bootstraps = |state: &ManagerState| {
        state
            .bootstraps
            .iter()
            .map(|(key, b)| {
                (
                    *key,
                    (b.expires_at, b.issued_at, b.issuance_ip, b.used, b.recovery),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    let closed = |state: &ManagerState| {
        state
            .closed_tokens
            .iter()
            .map(|(key, c)| (*key, (c.expires_at, c.host.clone(), c.carrier)))
            .collect::<BTreeMap<_, _>>()
    };
    let sessions = |state: &ManagerState| {
        state
            .closed_sessions
            .iter()
            .map(|(key, c)| {
                (
                    *key,
                    (c.expires_at, c.closed_at, c.attempt, c.carrier, c.reason),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    assert_eq!(bootstraps(actual), bootstraps(expected));
    assert_eq!(closed(actual), closed(expected));
    assert_eq!(sessions(actual), sessions(expected));
    assert_eq!(actual.closed_session_order, expected.closed_session_order);
    assert_eq!(actual.bootstraps_per_ip, expected.bootstraps_per_ip);
    for b in actual.bootstraps.values() {
        assert!(
            actual
                .bootstrap_expiry
                .is_some_and(|expiry| expiry <= b.expires_at)
        );
        assert!(!b.user_registration.is_cancelled());
    }
    for c in actual.closed_tokens.values() {
        assert!(
            actual
                .closed_token_expiry
                .is_some_and(|expiry| expiry <= c.expires_at)
        );
    }
}

#[test]
fn exact_expiry_boundary_and_recovery_accounting_match_exhaustive_sweep() {
    let fixture = Fixture::new();
    let now = Instant::now();
    let deadline = now + Duration::from_secs(1);
    let mut actual = ManagerState::default();
    let mut expected = ManagerState::default();
    for state in [&mut actual, &mut expected] {
        for flags in 0..4 {
            insert_bootstrap(state, [flags; 32], fixture.bootstrap(now, deadline, flags));
        }
        insert_closed_token(state, [8; 32], deadline);
        insert_bootstrap(
            state,
            [6; 32],
            fixture.bootstrap(now, deadline + Duration::from_secs(2), 0),
        );
        insert_closed_token(state, [9; 32], deadline + Duration::from_secs(2));
    }
    for (time, count) in [
        (deadline - Duration::from_nanos(1), 0),
        (deadline, 0),
        (deadline + Duration::from_nanos(1), 1),
        // A caller may have captured an older time before waiting for the manager lock.
        (deadline - Duration::from_nanos(1), 0),
        (deadline + Duration::from_secs(1), 0),
        (deadline + Duration::from_secs(3), 0),
    ] {
        assert_eq!(remove_expired_locked(&mut actual, time), count);
        assert_eq!(reference::exhaustive(&mut expected, time), count);
        assert_equivalent(&actual, &expected);
    }
    assert!(actual.bootstraps_per_ip.is_empty());
    assert_eq!(actual.bootstrap_expiry, None);
    assert_eq!(actual.closed_token_expiry, None);
}

#[test]
fn independent_hints_do_not_skip_logical_session_tombstones() {
    let fixture = Fixture::new();
    let now = Instant::now();
    for bootstrap_due in [false, true] {
        let mut state = ManagerState::default();
        let early = now - Duration::from_secs(1);
        let late = now + Duration::from_secs(1);
        insert_bootstrap(
            &mut state,
            [1; 32],
            fixture.bootstrap(early, if bootstrap_due { early } else { late }, 0),
        );
        insert_closed_token(
            &mut state,
            [2; 32],
            if bootstrap_due { late } else { early },
        );
        state.closed_sessions.insert(
            3,
            ClosedSession {
                expires_at: early,
                attempt: 1,
                carrier: WebCarrier::Https,
                reason: crate::web::session::SessionCloseReason::ApiClose,
                closed_at: early,
            },
        );
        state.closed_session_order.push_back(3);
        remove_expired_locked(&mut state, now);
        assert_eq!(state.bootstraps.is_empty(), bootstrap_due);
        assert_eq!(state.closed_tokens.is_empty(), !bootstrap_due);
        assert!(state.closed_sessions.is_empty());
        assert!(state.closed_session_order.is_empty());
    }
    let mut state = ManagerState::default();
    remember_closed_session_locked(
        &mut state,
        1,
        1,
        WebCarrier::Https,
        crate::web::session::SessionCloseReason::ApiClose,
        Duration::ZERO,
        1,
    );
    let time = state.closed_sessions[&1].expires_at + Duration::from_nanos(1);
    remove_expired_locked(&mut state, time);
    assert!(state.closed_sessions.is_empty());
}

#[test]
fn closed_token_overwrite_and_capacity_eviction_keep_a_conservative_hint() {
    let mut state = ManagerState::default();
    for (lifetime, capacity) in [(60, 2), (1, 2), (120, 2), (1, 0), (60, 1)] {
        remember_closed_token_locked(
            &mut state,
            [1; 32],
            "proxy.example.com",
            WebCarrier::Https,
            Duration::from_secs(lifetime),
            capacity,
        );
        assert!(state.closed_tokens.len() <= capacity);
        for c in state.closed_tokens.values() {
            assert!(state.closed_token_expiry.unwrap() <= c.expires_at);
        }
    }
    let deadline = state.closed_tokens[&[1; 32]].expires_at;
    remove_expired_locked(&mut state, deadline);
    assert_eq!(state.closed_tokens.len(), 1);
    remove_expired_locked(&mut state, deadline + Duration::from_nanos(1));
    assert!(state.closed_tokens.is_empty());

    for (key, lifetime) in [(1, 1), (2, 60), (3, 120)] {
        remember_closed_token_locked(
            &mut state,
            [key; 32],
            "proxy.example.com",
            WebCarrier::Https,
            Duration::from_secs(lifetime),
            2,
        );
    }
    let stale_hint = state.closed_token_expiry.unwrap();
    assert!(!state.closed_tokens.contains_key(&[1; 32]));
    assert!(state.closed_tokens.contains_key(&[2; 32]));
    assert!(state.closed_tokens.contains_key(&[3; 32]));
    let survivor_min = state
        .closed_tokens
        .values()
        .map(|c| c.expires_at)
        .min()
        .unwrap();
    assert!(stale_hint < survivor_min);
    remove_expired_locked(&mut state, stale_hint + Duration::from_nanos(1));
    assert_eq!(state.closed_tokens.len(), 2);
    assert_eq!(state.closed_token_expiry, Some(survivor_min));
}

#[test]
fn concurrent_due_sweeps_match_exhaustive_accounting() {
    let fixture = Fixture::new();
    let now = Instant::now();
    let states = parking_lot::Mutex::new((ManagerState::default(), ManagerState::default()));
    let barrier = std::sync::Barrier::new(16);
    std::thread::scope(|scope| {
        for worker in 0..16 {
            let fixture = &fixture;
            let states = &states;
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                for iteration in 0..64 {
                    let flags = (iteration % 4) as u8;
                    let expired = now - Duration::from_nanos(1);
                    let first = fixture.bootstrap(expired, expired, flags);
                    let second = fixture.bootstrap(expired, expired, flags);
                    let mut states = states.lock();
                    let (actual, expected) = &mut *states;
                    insert_bootstrap(actual, [worker; 32], first);
                    insert_bootstrap(expected, [worker; 32], second);
                    insert_closed_token(actual, [worker; 32], expired);
                    insert_closed_token(expected, [worker; 32], expired);
                    assert_eq!(
                        remove_expired_locked(actual, now),
                        reference::exhaustive(expected, now),
                    );
                    assert_equivalent(actual, expected);
                    assert!(actual.bootstraps_per_ip.is_empty());
                    assert!(actual.closed_tokens.is_empty());
                }
            });
        }
    });
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn mixed_registry_operations_match_exhaustive_sweep(
        actions in prop::collection::vec((0u8..9, any::<u8>(), 0u16..100), 1..300)
    ) {
        let fixture = Fixture::new();
        let mut actual = ManagerState::default();
        let mut expected = ManagerState::default();
        let start = Instant::now();
        let mut now = start;
        for (step, (operation, key, ttl)) in actions.into_iter().enumerate() {
            let hash = [key; 32];
            let expiry = now + Duration::from_millis(u64::from(ttl));
            for state in [&mut actual, &mut expected] {
                match operation {
                    0 => insert_bootstrap(state, hash, fixture.bootstrap(
                        start + Duration::from_nanos(step as u64), expiry, key % 4,
                    )),
                    1 => remove_bootstrap_locked(state, hash),
                    2 => {
                        if let Some(b) = state.bootstraps.get_mut(&hash) {
                            if !b.used {
                                decrement_map(&mut state.bootstraps_per_ip, &b.issuance_ip);
                                b.used = true;
                            }
                            b.expires_at += Duration::from_millis(u64::from(ttl));
                        }
                    }
                    3 => { drop(evict_oldest_unused_bootstrap(state)); }
                    4 => insert_closed_token(state, hash, expiry),
                    5 => { state.closed_tokens.remove(&hash); }
                    6 => {
                        state.bootstraps.clear();
                        state.bootstraps_per_ip.clear();
                        state.bootstrap_expiry = None;
                    }
                    7 => {
                        let id = u64::from(key);
                        if state.closed_sessions.insert(id, ClosedSession {
                            expires_at: expiry,
                            attempt: 1,
                            carrier: WebCarrier::Https,
                            reason: crate::web::session::SessionCloseReason::ApiClose,
                            closed_at: now,
                        }).is_none() {
                            state.closed_session_order.push_back(id);
                        }
                    }
                    _ => {}
                }
            }
            if operation == 8 {
                now += Duration::from_millis(u64::from(ttl));
            }
            assert_eq!(
                remove_expired_locked(&mut actual, now),
                reference::exhaustive(&mut expected, now),
            );
            assert_equivalent(&actual, &expected);
        }
    }
}
