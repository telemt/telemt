use super::*;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use std::sync::Arc;

#[test]
fn positive_direct_cutover_sets_timestamp_and_snapshot_coherently() {
    let runtime = RouteRuntimeController::new(RelayRouteMode::Middle);
    let rx = runtime.subscribe();

    assert!(
        runtime.direct_since_epoch_secs().is_none(),
        "middle startup must not expose direct-since timestamp"
    );

    let emitted = runtime
        .set_mode(RelayRouteMode::Direct)
        .expect("middle->direct must emit cutover");
    let observed = *rx.borrow();

    assert_eq!(
        observed, emitted,
        "watch snapshot must match emitted cutover"
    );
    assert_eq!(observed.mode, RelayRouteMode::Direct);
    assert!(
        runtime.direct_since_epoch_secs().is_some(),
        "direct cutover must publish a non-empty direct-since timestamp"
    );
}

#[test]
fn negative_idempotent_set_mode_does_not_mutate_timestamp_or_generation() {
    let runtime = RouteRuntimeController::new(RelayRouteMode::Direct);

    let before_state = runtime.snapshot();
    let before_ts = runtime.direct_since_epoch_secs();

    let changed = runtime.set_mode(RelayRouteMode::Direct);

    let after_state = runtime.snapshot();
    let after_ts = runtime.direct_since_epoch_secs();

    assert!(changed.is_none(), "idempotent set_mode must return None");
    assert_eq!(
        after_state.generation, before_state.generation,
        "idempotent set_mode must not advance generation"
    );
    assert_eq!(
        after_ts, before_ts,
        "idempotent set_mode must not alter direct-since timestamp"
    );
}

#[test]
fn edge_middle_cutover_clears_timestamp() {
    let runtime = RouteRuntimeController::new(RelayRouteMode::Direct);
    let rx = runtime.subscribe();

    assert!(
        runtime.direct_since_epoch_secs().is_some(),
        "direct startup must expose direct-since timestamp"
    );

    let emitted = runtime
        .set_mode(RelayRouteMode::Middle)
        .expect("direct->middle must emit cutover");
    let observed = *rx.borrow();

    assert_eq!(
        observed, emitted,
        "watch snapshot must match emitted cutover"
    );
    assert_eq!(observed.mode, RelayRouteMode::Middle);
    assert!(
        runtime.direct_since_epoch_secs().is_none(),
        "middle cutover must clear direct-since timestamp"
    );
}

#[test]
fn adversarial_blackhat_probe_sequence_observes_consistent_mode_timestamp_pairs() {
    let runtime = RouteRuntimeController::new(RelayRouteMode::Middle);
    let rx = runtime.subscribe();

    for _ in 0..2048usize {
        let emitted_direct = runtime
            .set_mode(RelayRouteMode::Direct)
            .expect("middle->direct must emit");
        let observed_direct = *rx.borrow();
        assert_eq!(observed_direct, emitted_direct);
        assert!(
            runtime.direct_since_epoch_secs().is_some(),
            "direct observation must never expose empty timestamp"
        );

        let emitted_middle = runtime
            .set_mode(RelayRouteMode::Middle)
            .expect("direct->middle must emit");
        let observed_middle = *rx.borrow();
        assert_eq!(observed_middle, emitted_middle);
        assert!(
            runtime.direct_since_epoch_secs().is_none(),
            "middle observation must never expose direct timestamp"
        );
    }
}

#[test]
fn integration_subscriber_and_runtime_gates_stay_coherent_across_cutovers() {
    let runtime = RouteRuntimeController::new(RelayRouteMode::Middle);
    let rx = runtime.subscribe();

    let plan = [
        RelayRouteMode::Direct,
        RelayRouteMode::Middle,
        RelayRouteMode::Direct,
        RelayRouteMode::Middle,
        RelayRouteMode::Direct,
    ];

    let mut expected_generation = 0u64;

    for mode in plan {
        let emitted = runtime
            .set_mode(mode)
            .expect("each planned transition toggles mode and must emit");
        expected_generation = expected_generation.saturating_add(1);

        let watched = *rx.borrow();
        let snapshot = runtime.snapshot();

        assert_eq!(emitted.mode, mode);
        assert_eq!(emitted.generation, expected_generation);
        assert_eq!(watched, emitted);
        assert_eq!(snapshot, emitted);

        if matches!(mode, RelayRouteMode::Direct) {
            assert!(runtime.direct_since_epoch_secs().is_some());
        } else {
            assert!(runtime.direct_since_epoch_secs().is_none());
        }
    }
}

#[test]
fn light_fuzz_random_mode_plan_preserves_timestamp_and_generation_invariants() {
    let runtime = RouteRuntimeController::new(RelayRouteMode::Middle);
    let mut rng = StdRng::seed_from_u64(0x5EED_CAFE_D15C_A11E);

    let mut expected_mode = RelayRouteMode::Middle;
    let mut expected_generation = 0u64;

    for _ in 0..25_000usize {
        let candidate = if rng.random::<bool>() {
            RelayRouteMode::Direct
        } else {
            RelayRouteMode::Middle
        };

        let changed = runtime.set_mode(candidate);
        if candidate == expected_mode {
            assert!(changed.is_none(), "idempotent fuzz step must not emit");
            continue;
        }

        expected_mode = candidate;
        expected_generation = expected_generation.saturating_add(1);

        let emitted = changed.expect("non-idempotent fuzz step must emit");
        assert_eq!(emitted.mode, expected_mode);
        assert_eq!(emitted.generation, expected_generation);

        let snapshot = runtime.snapshot();
        assert_eq!(snapshot, emitted, "snapshot must match emitted cutover");

        if matches!(snapshot.mode, RelayRouteMode::Direct) {
            assert!(
                runtime.direct_since_epoch_secs().is_some(),
                "direct fuzz state must expose timestamp"
            );
        } else {
            assert!(
                runtime.direct_since_epoch_secs().is_none(),
                "middle fuzz state must clear timestamp"
            );
        }
    }
}

#[test]
fn stress_parallel_subscribers_never_observe_generation_regression() {
    let runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Middle));

    let mut readers = Vec::new();
    for _ in 0..4usize {
        let runtime = Arc::clone(&runtime);
        readers.push(std::thread::spawn(move || {
            let rx = runtime.subscribe();
            let mut last = rx.borrow().generation;
            for _ in 0..10_000usize {
                let current = rx.borrow().generation;
                assert!(
                    current >= last,
                    "watch generation must be monotonic for every subscriber"
                );
                last = current;
                std::thread::yield_now();
            }
        }));
    }

    for step in 0..20_000usize {
        let mode = if (step & 1) == 0 {
            RelayRouteMode::Direct
        } else {
            RelayRouteMode::Middle
        };
        let _ = runtime.set_mode(mode);
    }

    for reader in readers {
        reader
            .join()
            .expect("parallel subscriber reader must not panic");
    }

    let final_state = runtime.snapshot();
    if matches!(final_state.mode, RelayRouteMode::Direct) {
        assert!(runtime.direct_since_epoch_secs().is_some());
    } else {
        assert!(runtime.direct_since_epoch_secs().is_none());
    }
}
