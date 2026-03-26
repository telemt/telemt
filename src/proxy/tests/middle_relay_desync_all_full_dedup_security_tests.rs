use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

#[test]
fn desync_all_full_bypass_does_not_initialize_or_grow_dedup_cache() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let initial_len = DESYNC_DEDUP.get().map(|dedup| dedup.len()).unwrap_or(0);
    let now = Instant::now();

    for i in 0..20_000u64 {
        assert!(
            should_emit_full_desync(0xD35E_D000_0000_0000u64 ^ i, true, now),
            "desync_all_full path must always emit"
        );
    }

    let after_len = DESYNC_DEDUP.get().map(|dedup| dedup.len()).unwrap_or(0);
    assert_eq!(
        after_len, initial_len,
        "desync_all_full bypass must not allocate or accumulate dedup entries"
    );
}

#[test]
fn desync_all_full_bypass_keeps_existing_dedup_entries_unchanged() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let dedup = DESYNC_DEDUP.get_or_init(DashMap::new);
    let seed_time = Instant::now() - Duration::from_secs(7);
    dedup.insert(0xAAAABBBBCCCCDDDD, seed_time);
    dedup.insert(0x1111222233334444, seed_time);

    let now = Instant::now();
    for i in 0..2048u64 {
        assert!(
            should_emit_full_desync(0xF011_F000_0000_0000u64 ^ i, true, now),
            "desync_all_full must bypass suppression and dedup refresh"
        );
    }

    assert_eq!(
        dedup.len(),
        2,
        "bypass path must not mutate dedup cardinality"
    );
    assert_eq!(
        *dedup
            .get(&0xAAAABBBBCCCCDDDD)
            .expect("seed key must remain"),
        seed_time,
        "bypass path must not refresh existing dedup timestamps"
    );
    assert_eq!(
        *dedup
            .get(&0x1111222233334444)
            .expect("seed key must remain"),
        seed_time,
        "bypass path must not touch unrelated dedup entries"
    );
}

#[test]
fn edge_all_full_burst_does_not_poison_later_false_path_tracking() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let now = Instant::now();
    for i in 0..8192u64 {
        assert!(should_emit_full_desync(
            0xABCD_0000_0000_0000 ^ i,
            true,
            now
        ));
    }

    let tracked_key = 0xDEAD_BEEF_0000_0001u64;
    assert!(
        should_emit_full_desync(tracked_key, false, now),
        "first false-path event after all_full burst must still be tracked and emitted"
    );

    let dedup = DESYNC_DEDUP
        .get()
        .expect("false path should initialize dedup");
    assert!(dedup.get(&tracked_key).is_some());
}

#[test]
fn adversarial_mixed_sequence_true_steps_never_change_cache_len() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let dedup = DESYNC_DEDUP.get_or_init(DashMap::new);
    for i in 0..256u64 {
        dedup.insert(0x1000_0000_0000_0000 ^ i, Instant::now());
    }

    let mut seed = 0xC0DE_CAFE_BAAD_F00Du64;
    for i in 0..4096u64 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let flag_all_full = (seed & 0x1) == 1;
        let key = 0x7000_0000_0000_0000u64 ^ i ^ seed;
        let before = dedup.len();
        let _ = should_emit_full_desync(key, flag_all_full, Instant::now());
        let after = dedup.len();

        if flag_all_full {
            assert_eq!(after, before, "all_full step must not mutate dedup length");
        }
    }
}

#[test]
fn light_fuzz_all_full_mode_always_emits_and_stays_bounded() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let mut seed = 0x1234_5678_9ABC_DEF0u64;
    let before = DESYNC_DEDUP.get().map(|d| d.len()).unwrap_or(0);

    for _ in 0..20_000 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;
        let key = seed ^ 0x55AA_55AA_55AA_55AAu64;
        assert!(should_emit_full_desync(key, true, Instant::now()));
    }

    let after = DESYNC_DEDUP.get().map(|d| d.len()).unwrap_or(0);
    assert_eq!(after, before);
    assert!(after <= DESYNC_DEDUP_MAX_ENTRIES);
}

#[test]
fn stress_parallel_all_full_storm_does_not_grow_or_mutate_cache() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let dedup = DESYNC_DEDUP.get_or_init(DashMap::new);
    let seed_time = Instant::now() - Duration::from_secs(2);
    for i in 0..1024u64 {
        dedup.insert(0x8888_0000_0000_0000 ^ i, seed_time);
    }
    let before_len = dedup.len();

    let emits = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    for worker in 0..16u64 {
        let emits = Arc::clone(&emits);
        workers.push(thread::spawn(move || {
            let now = Instant::now();
            for i in 0..4096u64 {
                let key = 0xFACE_0000_0000_0000u64 ^ (worker << 20) ^ i;
                if should_emit_full_desync(key, true, now) {
                    emits.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    for worker in workers {
        worker.join().expect("worker must not panic");
    }

    assert_eq!(emits.load(Ordering::Relaxed), 16 * 4096);
    assert_eq!(
        dedup.len(),
        before_len,
        "parallel all_full storm must not mutate cache len"
    );
}
