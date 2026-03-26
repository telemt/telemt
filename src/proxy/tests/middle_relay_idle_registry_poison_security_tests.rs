use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

#[test]
fn blackhat_registry_poison_recovers_with_fail_closed_reset_and_pressure_accounting() {
    let _guard = relay_idle_pressure_test_scope();
    clear_relay_idle_pressure_state_for_testing();

    let _ = catch_unwind(AssertUnwindSafe(|| {
        let registry = relay_idle_candidate_registry();
        let mut guard = registry
            .lock()
            .expect("registry lock must be acquired before poison");
        guard.by_conn_id.insert(
            999,
            RelayIdleCandidateMeta {
                mark_order_seq: 1,
                mark_pressure_seq: 0,
            },
        );
        guard.ordered.insert((1, 999));
        panic!("intentional poison for idle-registry recovery");
    }));

    // Helper lock must recover from poison, reset stale state, and continue.
    assert!(mark_relay_idle_candidate(42));
    assert_eq!(oldest_relay_idle_candidate(), Some(42));

    let before = relay_pressure_event_seq();
    note_relay_pressure_event();
    let after = relay_pressure_event_seq();
    assert!(
        after > before,
        "pressure accounting must still advance after poison"
    );

    clear_relay_idle_pressure_state_for_testing();
}

#[test]
fn clear_state_helper_must_reset_poisoned_registry_for_deterministic_fifo_tests() {
    let _guard = relay_idle_pressure_test_scope();
    clear_relay_idle_pressure_state_for_testing();

    let _ = catch_unwind(AssertUnwindSafe(|| {
        let registry = relay_idle_candidate_registry();
        let _guard = registry
            .lock()
            .expect("registry lock must be acquired before poison");
        panic!("intentional poison while lock held");
    }));

    clear_relay_idle_pressure_state_for_testing();

    assert_eq!(oldest_relay_idle_candidate(), None);
    assert_eq!(relay_pressure_event_seq(), 0);

    assert!(mark_relay_idle_candidate(7));
    assert_eq!(oldest_relay_idle_candidate(), Some(7));

    clear_relay_idle_pressure_state_for_testing();
}
