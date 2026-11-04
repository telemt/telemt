use super::*;
use crate::stats::Stats;
use std::sync::Barrier;

#[test]
fn quota_counters_are_shared_across_stats_generations() {
    let store = Arc::new(QuotaStore::default());
    let first = Stats::with_quota_store(store.clone());
    store.user("alice").charge(512);
    assert_eq!(first.get_user_quota_used("alice"), 512);

    let second = Stats::with_quota_store(store);
    assert_eq!(second.get_user_quota_used("alice"), 512);
    second.reset_user_quota("alice");
    assert_eq!(first.get_user_quota_used("alice"), 0);
}

#[test]
fn quota_snapshot_never_combines_different_generations() {
    const ITERATIONS: u64 = 10_000;

    let store = Arc::new(QuotaStore::default());
    store.load("alice", 1, 1);
    let barrier = Arc::new(Barrier::new(2));
    let writer_store = Arc::clone(&store);
    let writer_barrier = Arc::clone(&barrier);
    let writer = std::thread::spawn(move || {
        writer_barrier.wait();
        for generation in 2..=ITERATIONS {
            writer_store.load("alice", generation, generation);
        }
    });

    barrier.wait();
    for _ in 0..ITERATIONS {
        let snapshot = store.snapshot().remove("alice").unwrap();
        assert_eq!(snapshot.used_bytes, snapshot.last_reset_epoch_secs);
    }
    writer.join().unwrap();
}

#[test]
fn repeated_old_generation_refunds_leave_new_usage_intact() {
    const ITERATIONS: u64 = 10_000;

    let store = QuotaStore::default();
    let state = store.user("alice");
    for generation in 1..=ITERATIONS {
        let reservation = state.try_reserve(80, 100).unwrap();
        store.load("alice", 40, generation);
        drop(reservation);
        assert_eq!(store.used("alice"), 40);
        store.reset("alice", generation);
    }
}

#[test]
fn retired_incarnation_cannot_charge_recreated_username() {
    let store = QuotaStore::default();
    store.activate_fresh("alice", 1);
    let retired = store.handle_exact("alice", 1).unwrap();
    retired.charge(40);
    store.retire_through("alice", 2);
    store.activate_fresh("alice", 3);

    retired.charge(20);

    assert_eq!(retired.used(), 60);
    assert_eq!(store.handle_exact("alice", 3).unwrap().used(), 0);
}

#[test]
fn credential_rotation_preserves_usage_without_sharing_future_charges() {
    let store = QuotaStore::default();
    store.activate_fresh("alice", 1);
    let old = store.handle_exact("alice", 1).unwrap();
    old.charge(40);
    store.advance_preserving_usage("alice", 2);
    let current = store.handle_exact("alice", 2).unwrap();

    old.charge(20);

    assert_eq!(old.used(), 60);
    assert_eq!(current.used(), 40);
}

#[test]
fn captured_reset_handle_cannot_reset_a_new_incarnation() {
    let store = QuotaStore::default();
    store.activate_fresh("alice", 1);
    let reset_target = store.handle_exact("alice", 1).unwrap();
    reset_target.charge(40);
    store.advance_preserving_usage("alice", 2);
    let current = store.handle_exact("alice", 2).unwrap();
    current.charge(20);

    reset_target.reset(7);

    assert_eq!(reset_target.used(), 0);
    assert_eq!(current.used(), 60);
}

#[test]
fn stale_retirement_cannot_remove_newer_quota_owner() {
    let store = QuotaStore::default();
    store.activate_fresh("alice", 1);
    store.retire_through("alice", 2);
    store.activate_fresh("alice", 3);

    store.retire_through("alice", 2);

    assert!(store.handle_exact("alice", 3).is_some());
}

#[test]
fn old_reservation_refund_does_not_debit_recreated_username() {
    let store = QuotaStore::default();
    store.activate_fresh("alice", 1);
    let old = store.handle_exact("alice", 1).unwrap();
    let reservation = old.try_reserve(80, 100).unwrap();
    store.retire_through("alice", 2);
    store.activate_fresh("alice", 3);
    let current = store.handle_exact("alice", 3).unwrap();
    current.charge(50);

    drop(reservation);

    assert_eq!(old.used(), 0);
    assert_eq!(current.used(), 50);
}
