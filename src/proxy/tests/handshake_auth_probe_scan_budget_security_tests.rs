use super::*;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

fn auth_probe_test_guard() -> std::sync::MutexGuard<'static, ()> {
    auth_probe_test_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn edge_zero_state_len_yields_zero_start_offset() {
    let _guard = auth_probe_test_guard();
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 44));
    let now = Instant::now();

    assert_eq!(
        auth_probe_scan_start_offset(ip, now, 0, 16),
        0,
        "empty map must not produce non-zero scan offset"
    );
}

#[test]
fn adversarial_large_state_must_allow_start_offset_outside_scan_budget_window() {
    let _guard = auth_probe_test_guard();
    let base = Instant::now();
    let scan_limit = 16usize;
    let state_len = 65_536usize;

    let mut saw_offset_outside_window = false;
    for i in 0..2048u32 {
        let ip = IpAddr::V4(Ipv4Addr::new(
            203,
            ((i >> 16) & 0xff) as u8,
            ((i >> 8) & 0xff) as u8,
            (i & 0xff) as u8,
        ));
        let now = base + Duration::from_micros(i as u64);
        let start = auth_probe_scan_start_offset(ip, now, state_len, scan_limit);
        assert!(
            start < state_len,
            "start offset must stay within state length; start={start}, len={state_len}"
        );
        if start >= scan_limit {
            saw_offset_outside_window = true;
            break;
        }
    }

    assert!(
        saw_offset_outside_window,
        "large-state eviction must sample beyond the first scan window"
    );
}

#[test]
fn positive_state_smaller_than_scan_limit_caps_to_state_len() {
    let _guard = auth_probe_test_guard();
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 17));
    let now = Instant::now();

    for state_len in 1..32usize {
        let start = auth_probe_scan_start_offset(ip, now, state_len, 64);
        assert!(
            start < state_len,
            "start offset must never exceed state length when scan limit is larger"
        );
    }
}

#[test]
fn light_fuzz_scan_offset_budget_never_exceeds_effective_window() {
    let _guard = auth_probe_test_guard();
    let mut seed = 0x5A41_5356_4C32_3236u64;
    let base = Instant::now();

    for _ in 0..4096 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let ip = IpAddr::V4(Ipv4Addr::new(
            (seed >> 24) as u8,
            (seed >> 16) as u8,
            (seed >> 8) as u8,
            seed as u8,
        ));
        let state_len = ((seed >> 8) as usize % 131_072).saturating_add(1);
        let scan_limit = ((seed >> 32) as usize % 512).saturating_add(1);
        let now = base + Duration::from_nanos(seed & 0xffff);
        let start = auth_probe_scan_start_offset(ip, now, state_len, scan_limit);

        assert!(
            start < state_len,
            "scan offset must stay inside state length"
        );
    }
}
