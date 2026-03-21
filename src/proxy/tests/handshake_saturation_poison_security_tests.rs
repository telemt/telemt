use super::*;
use std::time::{Duration, Instant};

fn auth_probe_test_guard() -> std::sync::MutexGuard<'static, ()> {
    auth_probe_test_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn poison_saturation_mutex() {
    let saturation = auth_probe_saturation_state();
    let poison_thread = std::thread::spawn(move || {
        let _guard = saturation
            .lock()
            .expect("saturation mutex must be lockable for poison setup");
        panic!("intentional poison for saturation mutex resilience test");
    });
    let _ = poison_thread.join();
}

#[test]
fn auth_probe_saturation_note_recovers_after_mutex_poison() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();
    poison_saturation_mutex();

    let now = Instant::now();
    auth_probe_note_saturation(now);

    assert!(
        auth_probe_saturation_is_throttled_at_for_testing(now),
        "poisoned saturation mutex must not disable saturation throttling"
    );
}

#[test]
fn auth_probe_saturation_check_recovers_after_mutex_poison() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();
    poison_saturation_mutex();

    {
        let mut guard = auth_probe_saturation_state_lock();
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: Instant::now() + Duration::from_millis(10),
            last_seen: Instant::now(),
        });
    }

    assert!(
        auth_probe_saturation_is_throttled_for_testing(),
        "throttle check must recover poisoned saturation mutex and stay fail-closed"
    );
}

#[test]
fn clear_auth_probe_state_clears_saturation_even_if_poisoned() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();
    poison_saturation_mutex();

    auth_probe_note_saturation(Instant::now());
    assert!(auth_probe_saturation_is_throttled_for_testing());

    clear_auth_probe_state_for_testing();
    assert!(
        !auth_probe_saturation_is_throttled_for_testing(),
        "clear helper must clear saturation state even after poison"
    );
}
