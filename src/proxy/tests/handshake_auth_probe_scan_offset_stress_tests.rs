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
fn positive_same_ip_moving_time_yields_diverse_scan_offsets() {
    let _guard = auth_probe_test_guard();
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));
    let base = Instant::now();
    let mut uniq = HashSet::new();

    for i in 0..512u64 {
        let now = base + Duration::from_nanos(i);
        let offset = auth_probe_scan_start_offset(ip, now, 65_536, 16);
        uniq.insert(offset);
    }

    assert!(
        uniq.len() >= 256,
        "offset randomization collapsed unexpectedly for same-ip moving-time samples (uniq={})",
        uniq.len()
    );
}

#[test]
fn adversarial_many_ips_same_time_spreads_offsets_without_bias_collapse() {
    let _guard = auth_probe_test_guard();
    let now = Instant::now();
    let mut uniq = HashSet::new();

    for i in 0..1024u32 {
        let ip = IpAddr::V4(Ipv4Addr::new(
            (i >> 16) as u8,
            (i >> 8) as u8,
            i as u8,
            (255 - (i as u8)),
        ));
        uniq.insert(auth_probe_scan_start_offset(ip, now, 65_536, 16));
    }

    assert!(
        uniq.len() >= 512,
        "scan offset distribution collapsed unexpectedly across adversarial peer set (uniq={})",
        uniq.len()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_parallel_failure_churn_under_saturation_remains_capped_and_live() {
    let _guard = auth_probe_test_guard();
    clear_auth_probe_state_for_testing();

    let start = Instant::now();
    let mut workers = Vec::new();
    for worker in 0..8u8 {
        workers.push(tokio::spawn(async move {
            for i in 0..8192u32 {
                let ip = IpAddr::V4(Ipv4Addr::new(
                    10,
                    worker,
                    ((i >> 8) & 0xff) as u8,
                    (i & 0xff) as u8,
                ));
                auth_probe_record_failure(ip, start + Duration::from_micros((i % 128) as u64));
            }
        }));
    }

    for worker in workers {
        worker.await.expect("saturation worker must not panic");
    }

    assert!(
        auth_probe_state_map().len() <= AUTH_PROBE_TRACK_MAX_ENTRIES,
        "state must remain hard-capped under parallel saturation churn"
    );

    let probe = IpAddr::V4(Ipv4Addr::new(10, 4, 1, 1));
    let _ = auth_probe_should_apply_preauth_throttle(probe, start + Duration::from_millis(1));
}

#[test]
fn light_fuzz_scan_offset_stays_within_window_for_randomized_inputs() {
    let _guard = auth_probe_test_guard();
    let mut seed = 0xA55A_1357_2468_9BDFu64;
    let base = Instant::now();

    for _ in 0..8192 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let ip = IpAddr::V4(Ipv4Addr::new(
            (seed >> 24) as u8,
            (seed >> 16) as u8,
            (seed >> 8) as u8,
            seed as u8,
        ));
        let state_len = ((seed >> 8) as usize % 200_000).saturating_add(1);
        let scan_limit = ((seed >> 40) as usize % 1024).saturating_add(1);
        let now = base + Duration::from_nanos(seed & 0x1fff);

        let offset = auth_probe_scan_start_offset(ip, now, state_len, scan_limit);
        assert!(
            offset < state_len,
            "scan offset must always remain inside state length"
        );
    }
}
