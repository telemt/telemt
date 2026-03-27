use super::*;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

fn auth_probe_test_guard() -> std::sync::MutexGuard<'static, ()> {
    auth_probe_test_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn adversarial_large_state_offsets_escape_first_scan_window() {
    let _guard = auth_probe_test_guard();
    let base = Instant::now();
    let state_len = 65_536usize;
    let scan_limit = 1_024usize;

    let mut saw_offset_outside_first_window = false;
    for i in 0..8_192u64 {
        let ip = IpAddr::V4(Ipv4Addr::new(
            ((i >> 16) & 0xff) as u8,
            ((i >> 8) & 0xff) as u8,
            (i & 0xff) as u8,
            ((i.wrapping_mul(131)) & 0xff) as u8,
        ));
        let now = base + Duration::from_nanos(i);
        let start = auth_probe_scan_start_offset(ip, now, state_len, scan_limit);
        if start >= scan_limit {
            saw_offset_outside_first_window = true;
            break;
        }
    }

    assert!(
        saw_offset_outside_first_window,
        "scan start offset must cover the full auth-probe state, not only the first scan window"
    );
}

#[test]
fn stress_large_state_offsets_cover_many_scan_windows() {
    let _guard = auth_probe_test_guard();
    let base = Instant::now();
    let state_len = 65_536usize;
    let scan_limit = 1_024usize;

    let mut covered_windows = HashSet::new();
    for i in 0..16_384u64 {
        let ip = IpAddr::V4(Ipv4Addr::new(
            ((i >> 16) & 0xff) as u8,
            ((i >> 8) & 0xff) as u8,
            (i & 0xff) as u8,
            ((i.wrapping_mul(17)) & 0xff) as u8,
        ));
        let now = base + Duration::from_micros(i);
        let start = auth_probe_scan_start_offset(ip, now, state_len, scan_limit);
        covered_windows.insert(start / scan_limit);
    }

    assert!(
        covered_windows.len() >= 16,
        "eviction scan must not collapse to a tiny hot zone; covered windows={} out of {}",
        covered_windows.len(),
        state_len / scan_limit
    );
}

#[test]
fn light_fuzz_offset_always_stays_inside_state_len() {
    let _guard = auth_probe_test_guard();
    let mut seed = 0xC0FF_EE12_3456_789Au64;
    let base = Instant::now();

    for _ in 0..8_192usize {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let ip = IpAddr::V4(Ipv4Addr::new(
            (seed >> 24) as u8,
            (seed >> 16) as u8,
            (seed >> 8) as u8,
            seed as u8,
        ));
        let state_len = ((seed >> 16) as usize % 200_000).saturating_add(1);
        let scan_limit = ((seed >> 40) as usize % 2_048).saturating_add(1);
        let now = base + Duration::from_nanos(seed & 0x0fff);
        let start = auth_probe_scan_start_offset(ip, now, state_len, scan_limit);

        assert!(
            start < state_len,
            "scan offset must stay inside state length"
        );
    }
}
