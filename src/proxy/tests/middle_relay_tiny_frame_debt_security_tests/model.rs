use super::*;

#[test]
fn tiny_frame_debt_constants_match_security_budget_expectations() {
    assert_eq!(TINY_FRAME_DEBT_PER_TINY, 8);
    assert_eq!(TINY_FRAME_DEBT_LIMIT, 512);
}

#[test]
fn relay_client_idle_state_initial_debt_is_zero() {
    let state = RelayClientIdleState::new(Instant::now());
    assert_eq!(state.tiny_frame_debt, 0);
}

#[test]
fn on_client_frame_does_not_reset_tiny_frame_debt() {
    let now = Instant::now();
    let mut state = RelayClientIdleState::new(now);
    state.tiny_frame_debt = 77;
    state.on_client_frame(now);
    assert_eq!(state.tiny_frame_debt, 77);
}

#[test]
fn tiny_frame_debt_increment_is_saturating() {
    let mut debt = u32::MAX - 1;
    debt = debt.saturating_add(TINY_FRAME_DEBT_PER_TINY);
    assert_eq!(debt, u32::MAX);
}

#[test]
fn tiny_frame_debt_decrement_is_saturating() {
    let mut debt = 0u32;
    debt = debt.saturating_sub(1);
    assert_eq!(debt, 0);
}

#[test]
fn consecutive_tiny_frames_close_exactly_at_threshold() {
    let max_tiny_without_close = (TINY_FRAME_DEBT_LIMIT / TINY_FRAME_DEBT_PER_TINY) as usize;
    let pattern = vec![true; max_tiny_without_close];
    let (closed_at, _, _) = simulate_tiny_debt_pattern(&pattern, pattern.len());
    assert_eq!(closed_at, Some(max_tiny_without_close));
}

#[test]
fn one_less_than_threshold_tiny_frames_do_not_close() {
    let tiny_count = (TINY_FRAME_DEBT_LIMIT / TINY_FRAME_DEBT_PER_TINY) as usize - 1;
    let pattern = vec![true; tiny_count];
    let (closed_at, debt, _) = simulate_tiny_debt_pattern(&pattern, pattern.len());
    assert_eq!(closed_at, None);
    assert!(debt < TINY_FRAME_DEBT_LIMIT);
}

#[test]
fn alternating_one_to_one_closes_with_bounded_real_frame_count() {
    let mut pattern = Vec::with_capacity(512);
    for _ in 0..256 {
        pattern.push(true);
        pattern.push(false);
    }
    let (closed_at, _, reals) = simulate_tiny_debt_pattern(&pattern, pattern.len());
    assert!(closed_at.is_some());
    assert!(
        reals <= 80,
        "expected bounded real frames before close, got {reals}"
    );
}

#[test]
fn alternating_one_to_eight_is_stable_for_long_runs() {
    let mut pattern = Vec::with_capacity(9 * 5000);
    for _ in 0..5000 {
        pattern.push(true);
        for _ in 0..8 {
            pattern.push(false);
        }
    }
    let (closed_at, debt, _) = simulate_tiny_debt_pattern(&pattern, pattern.len());
    assert_eq!(closed_at, None);
    assert!(debt <= TINY_FRAME_DEBT_PER_TINY);
}

#[test]
fn alternating_one_to_seven_eventually_closes() {
    let mut pattern = Vec::with_capacity(8 * 2000);
    for _ in 0..2000 {
        pattern.push(true);
        for _ in 0..7 {
            pattern.push(false);
        }
    }
    let (closed_at, _, _) = simulate_tiny_debt_pattern(&pattern, pattern.len());
    assert!(
        closed_at.is_some(),
        "1:7 tiny-to-real must eventually close"
    );
}

#[test]
fn two_tiny_one_real_closes_faster_than_one_to_one() {
    let mut one_to_one = Vec::with_capacity(512);
    for _ in 0..256 {
        one_to_one.push(true);
        one_to_one.push(false);
    }

    let mut two_to_one = Vec::with_capacity(768);
    for _ in 0..256 {
        two_to_one.push(true);
        two_to_one.push(true);
        two_to_one.push(false);
    }

    let (a_close, _, _) = simulate_tiny_debt_pattern(&one_to_one, one_to_one.len());
    let (b_close, _, _) = simulate_tiny_debt_pattern(&two_to_one, two_to_one.len());
    assert!(a_close.is_some() && b_close.is_some());
    assert!(b_close.unwrap_or(usize::MAX) < a_close.unwrap_or(0));
}

#[test]
fn burst_then_drain_can_recover_without_close() {
    let burst_tiny = ((TINY_FRAME_DEBT_LIMIT / TINY_FRAME_DEBT_PER_TINY) / 2) as usize;
    let mut pattern = Vec::with_capacity(burst_tiny + 600);
    for _ in 0..burst_tiny {
        pattern.push(true);
    }
    pattern.extend(std::iter::repeat_n(false, 600));

    let (closed_at, debt, _) = simulate_tiny_debt_pattern(&pattern, pattern.len());
    assert_eq!(closed_at, None);
    assert_eq!(debt, 0);
}

#[test]
fn light_fuzz_tiny_frame_debt_model_stays_within_bounds() {
    let mut seed = 0xA5A5_91C3_2026_0322u64;
    for _case in 0..128 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let len = 512 + ((seed as usize) & 0x3ff);
        let mut pattern = Vec::with_capacity(len);
        let mut local_seed = seed;
        for _ in 0..len {
            local_seed ^= local_seed << 7;
            local_seed ^= local_seed >> 9;
            local_seed ^= local_seed << 8;
            pattern.push((local_seed & 1) == 0);
        }

        let (closed_at, debt, _) = simulate_tiny_debt_pattern(&pattern, pattern.len());
        if closed_at.is_none() {
            assert!(debt < TINY_FRAME_DEBT_LIMIT);
        }
        assert!(debt <= TINY_FRAME_DEBT_LIMIT.saturating_add(TINY_FRAME_DEBT_PER_TINY));
    }
}

#[test]
fn stress_many_independent_simulations_keep_isolated_debt_state() {
    for idx in 0..2048usize {
        let mut pattern = Vec::with_capacity(64);
        for j in 0..64usize {
            pattern.push(((idx ^ j) & 3) == 0);
        }
        let (_closed_at, debt, _reals) = simulate_tiny_debt_pattern(&pattern, pattern.len());
        assert!(debt <= TINY_FRAME_DEBT_LIMIT.saturating_add(TINY_FRAME_DEBT_PER_TINY));
    }
}
