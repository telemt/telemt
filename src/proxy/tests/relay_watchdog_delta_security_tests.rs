use super::watchdog_delta;

#[test]
fn positive_monotonic_growth_returns_exact_delta() {
    assert_eq!(watchdog_delta(42, 40), 2);
    assert_eq!(watchdog_delta(4096, 1024), 3072);
}

#[test]
fn edge_equal_values_return_zero_delta() {
    assert_eq!(watchdog_delta(0, 0), 0);
    assert_eq!(watchdog_delta(777, 777), 0);
}

#[test]
fn adversarial_wrap_like_regression_saturates_to_zero() {
    // Simulates a wrapped or reset counter observation where current < previous.
    assert_eq!(watchdog_delta(0, 1), 0);
    assert_eq!(watchdog_delta(12, 4096), 0);
}

#[test]
fn adversarial_blackhat_large_previous_value_never_underflows() {
    let current = 3u64;
    let previous = u64::MAX - 1;
    assert_eq!(watchdog_delta(current, previous), 0);
}

#[test]
fn light_fuzz_mixed_pairs_match_saturating_sub_contract() {
    // Deterministic xorshift64* generator for reproducible pseudo-fuzzing.
    let mut seed = 0xA51C_ED42_D00D_F00Du64;

    for _ in 0..10_000 {
        seed ^= seed >> 12;
        seed ^= seed << 25;
        seed ^= seed >> 27;
        let current = seed.wrapping_mul(0x2545_F491_4F6C_DD1D);

        seed ^= seed >> 12;
        seed ^= seed << 25;
        seed ^= seed >> 27;
        let previous = seed.wrapping_mul(0x2545_F491_4F6C_DD1D);

        let expected = current.saturating_sub(previous);
        let actual = watchdog_delta(current, previous);
        assert_eq!(actual, expected, "delta mismatch for ({current}, {previous})");
    }
}

#[test]
fn stress_long_running_monotonic_sequence_remains_exact() {
    let mut prev = 0u64;

    for step in 1u64..=200_000 {
        let curr = prev.saturating_add(step & 0x7);
        let delta = watchdog_delta(curr, prev);
        assert_eq!(delta, curr - prev);
        prev = curr;
    }
}
