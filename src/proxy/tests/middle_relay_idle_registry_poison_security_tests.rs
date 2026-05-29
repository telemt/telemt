use super::*;

#[test]
fn blackhat_registry_stale_order_entry_is_skipped_and_pressure_accounting_continues() {
    let shared = ProxySharedState::new();
    clear_relay_idle_pressure_state_for_testing_in_shared(shared.as_ref());

    shared
        .middle_relay
        .relay_idle_registry
        .ordered
        .lock()
        .insert((0, 999));

    assert!(mark_relay_idle_candidate_for_testing(shared.as_ref(), 42));
    assert_eq!(
        oldest_relay_idle_candidate_for_testing(shared.as_ref()),
        Some(999)
    );

    let before = relay_pressure_event_seq_for_testing(shared.as_ref());
    note_relay_pressure_event_for_testing(shared.as_ref());
    let after = relay_pressure_event_seq_for_testing(shared.as_ref());
    assert!(
        after > before,
        "pressure accounting must still advance with stale ordered entries"
    );

    let mut seen_pressure_seq = before;
    assert!(maybe_evict_idle_candidate_on_pressure_for_testing(
        shared.as_ref(),
        42,
        &mut seen_pressure_seq,
        &Stats::new()
    ));
    assert_eq!(
        oldest_relay_idle_candidate_for_testing(shared.as_ref()),
        None
    );

    clear_relay_idle_pressure_state_for_testing_in_shared(shared.as_ref());
}

#[test]
fn clear_state_helper_must_reset_split_registry_for_deterministic_fifo_tests() {
    let shared = ProxySharedState::new();
    clear_relay_idle_pressure_state_for_testing_in_shared(shared.as_ref());

    shared.middle_relay.relay_idle_registry.by_conn_id.insert(
        999,
        RelayIdleCandidateMeta {
            mark_order_seq: 1,
            mark_pressure_seq: 0,
        },
    );
    shared
        .middle_relay
        .relay_idle_registry
        .ordered
        .lock()
        .insert((1, 999));
    set_relay_pressure_state_for_testing(shared.as_ref(), 7, 6);

    clear_relay_idle_pressure_state_for_testing_in_shared(shared.as_ref());

    assert_eq!(
        oldest_relay_idle_candidate_for_testing(shared.as_ref()),
        None
    );
    assert_eq!(relay_pressure_event_seq_for_testing(shared.as_ref()), 0);

    assert!(mark_relay_idle_candidate_for_testing(shared.as_ref(), 7));
    assert_eq!(
        oldest_relay_idle_candidate_for_testing(shared.as_ref()),
        Some(7)
    );

    clear_relay_idle_pressure_state_for_testing_in_shared(shared.as_ref());
}
