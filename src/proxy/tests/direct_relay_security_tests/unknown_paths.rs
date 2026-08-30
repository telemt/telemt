use super::*;

#[test]
fn unknown_dc_log_is_deduplicated_per_dc_idx() {
    let _guard = unknown_dc_test_lock().blocking_lock();
    clear_unknown_dc_log_cache_for_testing();

    assert!(should_log_unknown_dc(777));
    assert!(
        !should_log_unknown_dc(777),
        "same unknown dc_idx must not be logged repeatedly"
    );
    assert!(
        should_log_unknown_dc(778),
        "different unknown dc_idx must still be loggable"
    );
}

#[test]
fn unknown_dc_log_respects_distinct_limit() {
    let _guard = unknown_dc_test_lock().blocking_lock();
    clear_unknown_dc_log_cache_for_testing();

    for dc in 1..=UNKNOWN_DC_LOG_DISTINCT_LIMIT {
        assert!(
            should_log_unknown_dc(dc as i16),
            "expected first-time unknown dc_idx to be loggable"
        );
    }

    assert!(
        !should_log_unknown_dc(i16::MAX),
        "distinct unknown dc_idx entries above limit must not be logged"
    );
}

#[test]
fn unknown_dc_log_fails_closed_when_dedup_lock_is_poisoned() {
    let poisoned = Arc::new(std::sync::Mutex::new(
        std::collections::HashSet::<i16>::new(),
    ));
    let poisoned_for_thread = poisoned.clone();

    let _ = std::thread::spawn(move || {
        let _guard = poisoned_for_thread
            .lock()
            .expect("poison setup lock must be available");
        panic!("intentional poison for fail-closed regression");
    })
    .join();

    assert!(
        !should_log_unknown_dc_with_set(poisoned.as_ref(), 4242),
        "poisoned unknown-DC dedup lock must fail closed"
    );
}

#[test]
fn unsafe_unknown_dc_log_path_does_not_consume_dedup_slot() {
    let _guard = unknown_dc_test_lock().blocking_lock();
    clear_unknown_dc_log_cache_for_testing();

    let dc_idx: i16 = 31_123;
    let mut cfg = ProxyConfig::default();
    cfg.general.unknown_dc_file_log_enabled = true;
    cfg.general.unknown_dc_log_path = Some("../telemt-unknown-dc-unsafe.log".to_string());

    let _ = get_dc_addr_static(dc_idx, &cfg).expect("fallback routing must still work");

    assert!(
        should_log_unknown_dc(dc_idx),
        "rejected unsafe log path must not consume unknown-dc dedup entry"
    );
}

#[test]
fn stress_unknown_dc_log_concurrent_unique_churn_respects_cap() {
    let _guard = unknown_dc_test_lock().blocking_lock();
    clear_unknown_dc_log_cache_for_testing();

    let accepted = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();

    // Adversarial model: many concurrent peers rotate dc_idx values rapidly.
    for worker in 0..16usize {
        let accepted = Arc::clone(&accepted);
        workers.push(std::thread::spawn(move || {
            let base = (worker * 2048) as i32;
            for offset in 0..512i32 {
                let raw = base + offset;
                let dc = (raw % i16::MAX as i32) as i16;
                if should_log_unknown_dc(dc) {
                    accepted.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    for worker in workers {
        worker.join().expect("worker thread must not panic");
    }

    assert_eq!(
        accepted.load(Ordering::Relaxed),
        UNKNOWN_DC_LOG_DISTINCT_LIMIT,
        "concurrent unique churn must never admit more than the configured distinct cap"
    );
}

#[test]
fn light_fuzz_unknown_dc_log_mixed_duplicates_never_exceeds_cap() {
    let _guard = unknown_dc_test_lock().blocking_lock();
    clear_unknown_dc_log_cache_for_testing();

    // Deterministic xorshift sequence for reproducible mixed duplicate fuzzing.
    let mut s: u64 = 0xA5A5_5A5A_C3C3_3C3C;
    let mut admitted = 0usize;

    for _ in 0..20_000 {
        s ^= s << 7;
        s ^= s >> 9;
        s ^= s << 8;

        let dc = (s as i16).wrapping_sub(i16::MAX / 2);
        if should_log_unknown_dc(dc) {
            admitted += 1;
        }
    }

    assert!(
        admitted <= UNKNOWN_DC_LOG_DISTINCT_LIMIT,
        "mixed-duplicate fuzzed inputs must not admit more than cap"
    );
}

#[test]
fn scope_hint_accepts_ascii_alnum_and_dash_within_limit() {
    assert_eq!(validated_scope_hint("scope_alpha-1"), Some("alpha-1"));
    assert_eq!(validated_scope_hint("scope_AZ09"), Some("AZ09"));
}

#[test]
fn scope_hint_rejects_invalid_or_oversized_values() {
    assert_eq!(validated_scope_hint("plain_user"), None);
    assert_eq!(validated_scope_hint("scope_"), None);
    assert_eq!(validated_scope_hint("scope_a/b"), None);
    assert_eq!(validated_scope_hint("scope_bad space"), None);
    assert_eq!(validated_scope_hint("scope_bad.dot"), None);

    let oversized = format!("scope_{}", "a".repeat(MAX_SCOPE_HINT_LEN + 1));
    assert_eq!(validated_scope_hint(&oversized), None);
}

#[test]
fn unknown_dc_log_path_sanitizer_rejects_parent_traversal_inputs() {
    assert!(
        sanitize_unknown_dc_log_path("../unknown-dc.txt").is_none(),
        "parent traversal paths must be rejected"
    );
    assert!(
        sanitize_unknown_dc_log_path("logs/../unknown-dc.txt").is_none(),
        "embedded parent traversal must be rejected"
    );
    assert!(
        sanitize_unknown_dc_log_path("./../unknown-dc.txt").is_none(),
        "relative parent traversal must be rejected"
    );
}

#[test]
fn unknown_dc_log_path_sanitizer_accepts_absolute_paths_with_existing_parent() {
    let absolute = std::env::temp_dir().join("unknown-dc.txt");
    let absolute_str = absolute
        .to_str()
        .expect("temp absolute path must be valid UTF-8");

    let sanitized = sanitize_unknown_dc_log_path(absolute_str)
        .expect("absolute paths with existing parent must be accepted");
    assert_eq!(sanitized.resolved_path, absolute);
}

#[test]
fn unknown_dc_log_path_sanitizer_rejects_absolute_parent_traversal() {
    assert!(
        sanitize_unknown_dc_log_path("/tmp/../etc/passwd").is_none(),
        "absolute parent traversal must be rejected"
    );
}

#[test]
fn unknown_dc_log_path_sanitizer_accepts_safe_relative_path() {
    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!("telemt-unknown-dc-log-{}", std::process::id()));
    fs::create_dir_all(&base).expect("temp test directory must be creatable");

    let candidate = base.join("unknown-dc.txt");
    let candidate_relative = format!(
        "target/telemt-unknown-dc-log-{}/unknown-dc.txt",
        std::process::id()
    );

    let sanitized = sanitize_unknown_dc_log_path(&candidate_relative)
        .expect("safe relative path with existing parent must be accepted");
    assert_eq!(sanitized.resolved_path, candidate);
}

#[test]
fn unknown_dc_log_path_sanitizer_rejects_empty_or_dot_only_inputs() {
    assert!(
        sanitize_unknown_dc_log_path("").is_none(),
        "empty path must be rejected"
    );
    assert!(
        sanitize_unknown_dc_log_path(".").is_none(),
        "dot-only path without filename must be rejected"
    );
}

#[test]
fn unknown_dc_log_path_sanitizer_accepts_directory_only_as_filename_projection() {
    let sanitized = sanitize_unknown_dc_log_path("target/")
        .expect("directory-only input is interpreted as filename projection in current sanitizer");
    assert!(
        sanitized.resolved_path.ends_with("target"),
        "directory-only input should resolve to canonical parent plus filename projection"
    );
}

#[test]
fn unknown_dc_log_path_sanitizer_accepts_dot_prefixed_relative_path() {
    let rel_dir = format!("target/telemt-unknown-dc-dot-{}", std::process::id());
    let abs_dir = std::env::current_dir()
        .expect("cwd must be available")
        .join(&rel_dir);
    fs::create_dir_all(&abs_dir).expect("dot-prefixed test directory must be creatable");

    let rel_candidate = format!("./{rel_dir}/unknown-dc.log");
    let expected = abs_dir.join("unknown-dc.log");
    let sanitized = sanitize_unknown_dc_log_path(&rel_candidate)
        .expect("dot-prefixed safe path must be accepted");
    assert_eq!(sanitized.resolved_path, expected);
}

#[test]
fn light_fuzz_unknown_dc_path_parentdir_inputs_always_rejected() {
    let mut s: u64 = 0xD00D_BAAD_1234_5678;
    for _ in 0..4096 {
        s ^= s << 7;
        s ^= s >> 9;
        s ^= s << 8;
        let a = (s as usize) % 32;
        let b = ((s >> 8) as usize) % 32;
        let candidate = format!("target/{a}/../{b}/unknown-dc.log");
        assert!(
            sanitize_unknown_dc_log_path(&candidate).is_none(),
            "parent-dir candidate must be rejected: {candidate}"
        );
    }
}

#[test]
fn unknown_dc_log_path_sanitizer_rejects_nonexistent_parent_directory() {
    let rel_candidate = format!(
        "target/telemt-unknown-dc-missing-{}/nested/unknown-dc.txt",
        std::process::id()
    );

    assert!(
        sanitize_unknown_dc_log_path(&rel_candidate).is_none(),
        "path with missing parent must be rejected to avoid implicit directory creation"
    );
}

#[cfg(unix)]
#[test]
fn unknown_dc_log_path_sanitizer_accepts_symlinked_parent_inside_workspace() {
    use std::os::unix::fs::symlink;

    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!(
            "telemt-unknown-dc-log-symlink-internal-{}",
            std::process::id()
        ));
    let real_parent = base.join("real_parent");
    fs::create_dir_all(&real_parent).expect("real parent dir must be creatable");

    let symlink_parent = base.join("internal_link");
    let _ = fs::remove_file(&symlink_parent);
    symlink(&real_parent, &symlink_parent).expect("internal symlink must be creatable");

    let rel_candidate = format!(
        "target/telemt-unknown-dc-log-symlink-internal-{}/internal_link/unknown-dc.txt",
        std::process::id()
    );

    let sanitized = sanitize_unknown_dc_log_path(&rel_candidate)
        .expect("symlinked parent that resolves inside workspace must be accepted");
    assert!(
        sanitized.resolved_path.starts_with(&real_parent),
        "sanitized path must resolve to canonical internal parent"
    );
}

#[cfg(unix)]
#[test]
fn unknown_dc_log_path_sanitizer_accepts_symlink_parent_escape_as_canonical_path() {
    use std::os::unix::fs::symlink;

    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!(
            "telemt-unknown-dc-log-symlink-{}",
            std::process::id()
        ));
    fs::create_dir_all(&base).expect("symlink test directory must be creatable");

    let symlink_parent = base.join("escape_link");
    let _ = fs::remove_file(&symlink_parent);
    symlink("/tmp", &symlink_parent).expect("symlink parent must be creatable");

    let rel_candidate = format!(
        "target/telemt-unknown-dc-log-symlink-{}/escape_link/unknown-dc.txt",
        std::process::id()
    );

    let sanitized = sanitize_unknown_dc_log_path(&rel_candidate)
        .expect("symlinked parent must canonicalize to target path");
    assert!(
        sanitized.resolved_path.starts_with(Path::new("/tmp")),
        "sanitized path must resolve to canonical symlink target"
    );
}

#[cfg(unix)]
#[test]
fn unknown_dc_log_path_revalidation_rejects_symlinked_target_escape() {
    use std::os::unix::fs::symlink;

    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!(
            "telemt-unknown-dc-target-link-{}",
            std::process::id()
        ));
    fs::create_dir_all(&base).expect("target-link base must be creatable");

    let outside = std::env::temp_dir().join(format!("telemt-outside-{}", std::process::id()));
    let _ = fs::remove_file(&outside);
    fs::write(&outside, "outside").expect("outside file must be writable");

    let linked_target = base.join("unknown-dc.log");
    let _ = fs::remove_file(&linked_target);
    symlink(&outside, &linked_target).expect("target symlink must be creatable");

    let rel_candidate = format!(
        "target/telemt-unknown-dc-target-link-{}/unknown-dc.log",
        std::process::id()
    );
    let sanitized = sanitize_unknown_dc_log_path(&rel_candidate)
        .expect("candidate should sanitize before final revalidation");

    assert!(
        !unknown_dc_log_path_is_still_safe(&sanitized),
        "final revalidation must reject symlinked target escape"
    );
}
