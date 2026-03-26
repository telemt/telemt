use super::*;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[test]
fn cutover_stagger_delay_is_deterministic_for_same_inputs() {
    let d1 = cutover_stagger_delay(0x0123_4567_89ab_cdef, 42);
    let d2 = cutover_stagger_delay(0x0123_4567_89ab_cdef, 42);
    assert_eq!(
        d1, d2,
        "stagger delay must be deterministic for identical session/generation inputs"
    );
}

#[test]
fn cutover_stagger_delay_stays_within_budget_bounds() {
    // Black-hat model: censors trigger many cutovers and correlate disconnect timing.
    // Keep delay inside a narrow coarse window to avoid long-tail spikes.
    for generation in [0u64, 1, 2, 3, 16, 128, u32::MAX as u64, u64::MAX] {
        for session_id in [0u64, 1, 2, 0xdead_beef, 0xfeed_face_cafe_babe, u64::MAX] {
            let delay = cutover_stagger_delay(session_id, generation);
            assert!(
                (1000..=1999).contains(&delay.as_millis()),
                "stagger delay must remain in fixed 1000..=1999ms budget"
            );
        }
    }
}

#[test]
fn cutover_stagger_delay_changes_with_generation_for_same_session() {
    let session_id = 0x0123_4567_89ab_cdef;
    let first = cutover_stagger_delay(session_id, 100);
    let second = cutover_stagger_delay(session_id, 101);
    assert_ne!(
        first, second,
        "adjacent cutover generations should decorrelate disconnect delays"
    );
}

#[test]
fn route_runtime_set_mode_is_idempotent_for_same_mode() {
    let runtime = RouteRuntimeController::new(RelayRouteMode::Direct);
    let first = runtime.snapshot();
    let changed = runtime.set_mode(RelayRouteMode::Direct);
    let second = runtime.snapshot();

    assert!(
        changed.is_none(),
        "setting already-active mode must not produce a cutover event"
    );
    assert_eq!(
        first.generation, second.generation,
        "idempotent mode set must not bump generation"
    );
}

#[test]
fn affected_cutover_state_triggers_only_for_newer_generation() {
    let runtime = RouteRuntimeController::new(RelayRouteMode::Direct);
    let rx = runtime.subscribe();
    let initial = runtime.snapshot();

    assert!(
        affected_cutover_state(&rx, RelayRouteMode::Direct, initial.generation).is_none(),
        "current generation must not be considered a cutover for existing session"
    );

    let next = runtime
        .set_mode(RelayRouteMode::Middle)
        .expect("mode change must produce cutover state");
    let seen = affected_cutover_state(&rx, RelayRouteMode::Direct, initial.generation)
        .expect("newer generation must be observed as cutover");

    assert_eq!(seen.generation, next.generation);
    assert_eq!(seen.mode, RelayRouteMode::Middle);
}

#[test]
fn integration_watch_and_snapshot_follow_same_transition_sequence() {
    let runtime = RouteRuntimeController::new(RelayRouteMode::Direct);
    let rx = runtime.subscribe();

    let sequence = [
        RelayRouteMode::Middle,
        RelayRouteMode::Middle,
        RelayRouteMode::Direct,
        RelayRouteMode::Direct,
        RelayRouteMode::Middle,
    ];

    let mut expected_generation = 0u64;
    let mut expected_mode = RelayRouteMode::Direct;

    for target in sequence {
        let changed = runtime.set_mode(target);
        if target == expected_mode {
            assert!(changed.is_none(), "idempotent transition must return none");
        } else {
            expected_mode = target;
            expected_generation = expected_generation.saturating_add(1);
            let emitted = changed.expect("real transition must emit cutover state");
            assert_eq!(emitted.mode, expected_mode);
            assert_eq!(emitted.generation, expected_generation);
        }

        let snap = runtime.snapshot();
        let watched = *rx.borrow();
        assert_eq!(snap, watched, "snapshot and watch state must stay aligned");
        assert_eq!(snap.mode, expected_mode);
        assert_eq!(snap.generation, expected_generation);
    }
}

#[test]
fn session_is_not_affected_when_mode_matches_even_if_generation_advanced() {
    let session_mode = RelayRouteMode::Direct;
    let current = RouteCutoverState {
        mode: RelayRouteMode::Direct,
        generation: 2,
    };
    let session_generation = 0;

    assert!(
        !is_session_affected_by_cutover(current, session_mode, session_generation),
        "session on matching final route mode should not be force-cut over on intermediate generation bumps"
    );
}

#[test]
fn cutover_predicate_rejects_equal_generation_even_if_mode_differs() {
    let current = RouteCutoverState {
        mode: RelayRouteMode::Middle,
        generation: 77,
    };
    assert!(
        !is_session_affected_by_cutover(current, RelayRouteMode::Direct, 77),
        "equal generation must never trigger cutover regardless of mode mismatch"
    );
}

#[test]
fn adversarial_route_oscillation_only_cuts_over_sessions_with_different_final_mode() {
    let runtime = RouteRuntimeController::new(RelayRouteMode::Direct);
    let rx = runtime.subscribe();
    let session_generation = runtime.snapshot().generation;

    runtime
        .set_mode(RelayRouteMode::Middle)
        .expect("direct->middle must transition");
    runtime
        .set_mode(RelayRouteMode::Direct)
        .expect("middle->direct must transition");

    assert!(
        affected_cutover_state(&rx, RelayRouteMode::Direct, session_generation).is_none(),
        "direct session should survive when final mode returns to direct"
    );
    assert!(
        affected_cutover_state(&rx, RelayRouteMode::Middle, session_generation).is_some(),
        "middle session should be cut over when final mode is direct"
    );
}

#[test]
fn light_fuzz_cutover_predicate_matches_reference_oracle() {
    let mut rng = StdRng::seed_from_u64(0xC0DEC0DE5EED);
    for _ in 0..20_000 {
        let current = RouteCutoverState {
            mode: if rng.random::<bool>() {
                RelayRouteMode::Direct
            } else {
                RelayRouteMode::Middle
            },
            generation: rng.random_range(0u64..1_000_000),
        };
        let session_mode = if rng.random::<bool>() {
            RelayRouteMode::Direct
        } else {
            RelayRouteMode::Middle
        };
        let session_generation = rng.random_range(0u64..1_000_000);

        let expected = current.generation > session_generation && current.mode != session_mode;
        let actual = is_session_affected_by_cutover(current, session_mode, session_generation);
        assert_eq!(
            actual, expected,
            "cutover predicate must match mode-aware generation oracle"
        );
    }
}

#[test]
fn light_fuzz_set_mode_generation_tracks_only_real_transitions() {
    let runtime = RouteRuntimeController::new(RelayRouteMode::Direct);
    let mut rng = StdRng::seed_from_u64(0x0DDC0FFE);

    let mut expected_mode = RelayRouteMode::Direct;
    let mut expected_generation = 0u64;

    for _ in 0..10_000 {
        let candidate = if rng.random::<bool>() {
            RelayRouteMode::Direct
        } else {
            RelayRouteMode::Middle
        };
        let changed = runtime.set_mode(candidate);

        if candidate == expected_mode {
            assert!(
                changed.is_none(),
                "idempotent set_mode must not emit cutover state"
            );
        } else {
            expected_mode = candidate;
            expected_generation = expected_generation.saturating_add(1);
            let next = changed.expect("mode transition must emit cutover state");
            assert_eq!(next.mode, expected_mode);
            assert_eq!(next.generation, expected_generation);
        }
    }

    let final_state = runtime.snapshot();
    assert_eq!(final_state.mode, expected_mode);
    assert_eq!(final_state.generation, expected_generation);
}

#[test]
fn stress_snapshot_and_watch_state_remain_consistent_under_concurrent_switch_storm() {
    let runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));

    std::thread::scope(|scope| {
        let mut writers = Vec::new();
        for worker in 0..4usize {
            let runtime = Arc::clone(&runtime);
            writers.push(scope.spawn(move || {
                for step in 0..20_000usize {
                    let mode = if (worker + step) % 2 == 0 {
                        RelayRouteMode::Direct
                    } else {
                        RelayRouteMode::Middle
                    };
                    let _ = runtime.set_mode(mode);
                }
            }));
        }

        for writer in writers {
            writer
                .join()
                .expect("route mode writer thread must not panic");
        }

        let rx = runtime.subscribe();
        for _ in 0..128 {
            assert_eq!(
                runtime.snapshot(),
                *rx.borrow(),
                "snapshot and watch state must converge after concurrent set_mode churn"
            );
            std::thread::yield_now();
        }
    });
}

#[test]
fn stress_concurrent_transition_count_matches_final_generation() {
    let runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let successful_transitions = Arc::new(AtomicU64::new(0));

    std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for worker in 0..6usize {
            let runtime = Arc::clone(&runtime);
            let successful_transitions = Arc::clone(&successful_transitions);
            workers.push(scope.spawn(move || {
                let mut state = (worker as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
                for _ in 0..25_000usize {
                    state ^= state << 7;
                    state ^= state >> 9;
                    state ^= state << 8;
                    let mode = if (state & 1) == 0 {
                        RelayRouteMode::Direct
                    } else {
                        RelayRouteMode::Middle
                    };
                    if runtime.set_mode(mode).is_some() {
                        successful_transitions.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }

        for worker in workers {
            worker
                .join()
                .expect("route mode transition worker must not panic");
        }
    });

    let final_state = runtime.snapshot();
    assert_eq!(
        final_state.generation,
        successful_transitions.load(Ordering::Relaxed),
        "final generation must equal number of accepted mode transitions"
    );
    assert_eq!(
        final_state,
        *runtime.subscribe().borrow(),
        "watch and snapshot state must match after concurrent transition accounting"
    );
}

#[test]
fn light_fuzz_cutover_stagger_delay_distribution_stays_in_fixed_window() {
    // Deterministic xorshift fuzzing keeps this test stable across runs.
    let mut s: u64 = 0x9E37_79B9_7F4A_7C15;

    for _ in 0..20_000 {
        s ^= s << 7;
        s ^= s >> 9;
        s ^= s << 8;
        let session_id = s;

        s ^= s << 7;
        s ^= s >> 9;
        s ^= s << 8;
        let generation = s;

        let delay = cutover_stagger_delay(session_id, generation);
        assert!(
            (1000..=1999).contains(&delay.as_millis()),
            "fuzzed inputs must always map into fixed stagger window"
        );
    }
}

#[test]
fn cutover_stagger_delay_distribution_has_no_empty_buckets_under_sequential_sessions() {
    let mut buckets = [0usize; 1000];
    let generation = 4242u64;

    for session_id in 0..250_000u64 {
        let delay_ms = cutover_stagger_delay(session_id, generation).as_millis() as usize;
        let idx = delay_ms - 1000;
        buckets[idx] += 1;
    }

    let empty = buckets.iter().filter(|&&count| count == 0).count();
    assert_eq!(
        empty, 0,
        "all 1000 delay buckets must be exercised to avoid cutover herd clustering"
    );
}

#[test]
fn light_fuzz_cutover_stagger_delay_distribution_stays_reasonably_uniform() {
    let mut buckets = [0usize; 1000];
    let mut s: u64 = 0x1BAD_B002_CAFE_F00D;

    for _ in 0..300_000usize {
        s ^= s << 7;
        s ^= s >> 9;
        s ^= s << 8;
        let session_id = s;

        s ^= s << 7;
        s ^= s >> 9;
        s ^= s << 8;
        let generation = s;

        let delay_ms = cutover_stagger_delay(session_id, generation).as_millis() as usize;
        buckets[delay_ms - 1000] += 1;
    }

    let min = *buckets.iter().min().unwrap_or(&0);
    let max = *buckets.iter().max().unwrap_or(&0);
    assert!(min > 0, "fuzzed distribution must not leave empty buckets");
    assert!(
        max <= min.saturating_mul(3),
        "bucket skew is too high for anti-herd staggering (max={max}, min={min})"
    );
}

#[test]
fn stress_cutover_stagger_delay_distribution_remains_stable_across_generations() {
    for generation in [0u64, 1, 7, 31, 255, 1024, u32::MAX as u64, u64::MAX - 1] {
        let mut buckets = [0usize; 1000];
        for session_id in 0..100_000u64 {
            let delay_ms =
                cutover_stagger_delay(session_id ^ 0x9E37_79B9, generation).as_millis() as usize;
            buckets[delay_ms - 1000] += 1;
        }

        let min = *buckets.iter().min().unwrap_or(&0);
        let max = *buckets.iter().max().unwrap_or(&0);
        assert!(
            max <= min.saturating_mul(4).max(1),
            "generation={generation}: distribution collapsed (max={max}, min={min})"
        );
    }
}
