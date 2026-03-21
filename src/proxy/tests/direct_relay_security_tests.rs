use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use crate::crypto::{AesCtr, SecureRandom};
use crate::protocol::constants::ProtoTag;
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader, CryptoWriter};
use crate::transport::UpstreamManager;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::io::duplex;
use tokio::net::TcpListener;
use tokio::time::{Duration as TokioDuration, timeout};

fn make_crypto_reader<R>(reader: R) -> CryptoReader<R>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoReader::new(reader, AesCtr::new(&key, iv))
}

fn make_crypto_writer<W>(writer: W) -> CryptoWriter<W>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoWriter::new(writer, AesCtr::new(&key, iv), 8 * 1024)
}

fn nonempty_line_count(text: &str) -> usize {
    text.lines().filter(|line| !line.trim().is_empty()).count()
}

#[test]
fn unknown_dc_log_is_deduplicated_per_dc_idx() {
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
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
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
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
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
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
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
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
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
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

#[cfg(unix)]
#[test]
fn unknown_dc_open_append_rejects_symlink_target_with_nofollow() {
    use std::os::unix::fs::symlink;

    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!("telemt-unknown-dc-nofollow-{}", std::process::id()));
    fs::create_dir_all(&base).expect("nofollow base must be creatable");

    let outside = std::env::temp_dir().join(format!(
        "telemt-unknown-dc-nofollow-outside-{}.log",
        std::process::id()
    ));
    let _ = fs::remove_file(&outside);
    fs::write(&outside, "outside\n").expect("outside file must be writable");

    let linked_target = base.join("unknown-dc.log");
    let _ = fs::remove_file(&linked_target);
    symlink(&outside, &linked_target).expect("symlink target must be creatable");

    let err = open_unknown_dc_log_append(&linked_target)
        .expect_err("O_NOFOLLOW open must fail for symlink target");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ELOOP),
        "symlink target must be rejected with ELOOP when O_NOFOLLOW is applied"
    );
}

#[cfg(unix)]
#[test]
fn unknown_dc_open_append_rejects_broken_symlink_target_with_nofollow() {
    use std::os::unix::fs::symlink;

    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!(
            "telemt-unknown-dc-broken-link-{}",
            std::process::id()
        ));
    fs::create_dir_all(&base).expect("broken-link base must be creatable");

    let linked_target = base.join("unknown-dc.log");
    let _ = fs::remove_file(&linked_target);
    symlink(base.join("missing-target.log"), &linked_target)
        .expect("broken symlink target must be creatable");

    let err = open_unknown_dc_log_append(&linked_target)
        .expect_err("O_NOFOLLOW open must fail for broken symlink target");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ELOOP),
        "broken symlink target must be rejected with ELOOP when O_NOFOLLOW is applied"
    );
}

#[cfg(unix)]
#[test]
fn adversarial_unknown_dc_open_append_symlink_flip_never_writes_outside_file() {
    use std::os::unix::fs::symlink;

    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!(
            "telemt-unknown-dc-symlink-flip-{}",
            std::process::id()
        ));
    fs::create_dir_all(&base).expect("symlink-flip base must be creatable");

    let outside = std::env::temp_dir().join(format!(
        "telemt-unknown-dc-symlink-flip-outside-{}.log",
        std::process::id()
    ));
    fs::write(&outside, "outside-baseline\n").expect("outside baseline file must be writable");
    let outside_before = fs::read_to_string(&outside).expect("outside baseline must be readable");

    let target = base.join("unknown-dc.log");
    let _ = fs::remove_file(&target);

    for step in 0..1024usize {
        let _ = fs::remove_file(&target);
        if step % 2 == 0 {
            symlink(&outside, &target).expect("symlink creation in flip loop must succeed");
        }
        if let Ok(mut file) = open_unknown_dc_log_append(&target) {
            writeln!(file, "dc_idx={step}").expect("append on regular file must succeed");
        }
    }

    let outside_after = fs::read_to_string(&outside).expect("outside file must remain readable");
    assert_eq!(
        outside_after, outside_before,
        "outside file must never be modified under symlink-flip adversarial churn"
    );
}

#[test]
fn unknown_dc_open_append_creates_regular_file() {
    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!("telemt-unknown-dc-open-{}", std::process::id()));
    fs::create_dir_all(&base).expect("open test base must be creatable");

    let target = base.join("unknown-dc.log");
    let _ = fs::remove_file(&target);

    {
        let mut file = open_unknown_dc_log_append(&target)
            .expect("regular target must be creatable with append open");
        writeln!(file, "dc_idx=1234").expect("append write must succeed");
    }

    let meta = fs::symlink_metadata(&target).expect("created target metadata must be readable");
    assert!(meta.file_type().is_file(), "target must be a regular file");
    assert!(
        !meta.file_type().is_symlink(),
        "regular target open path must not produce symlink artifacts"
    );
}

#[test]
fn stress_unknown_dc_open_append_regular_file_preserves_line_integrity() {
    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!(
            "telemt-unknown-dc-open-stress-{}",
            std::process::id()
        ));
    fs::create_dir_all(&base).expect("stress open base must be creatable");

    let target = base.join("unknown-dc.log");
    let _ = fs::remove_file(&target);

    let writes = 2048usize;
    for idx in 0..writes {
        let mut file = open_unknown_dc_log_append(&target)
            .expect("stress append open on regular file must succeed");
        writeln!(file, "dc_idx={idx}").expect("stress append write must succeed");
    }

    let content = fs::read_to_string(&target).expect("stress output file must be readable");
    assert_eq!(
        nonempty_line_count(&content),
        writes,
        "regular-file append stress must preserve one logical line per write"
    );
}

#[test]
fn unknown_dc_log_path_revalidation_accepts_regular_existing_target() {
    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!(
            "telemt-unknown-dc-safe-target-{}",
            std::process::id()
        ));
    fs::create_dir_all(&base).expect("safe target base must be creatable");

    let target = base.join("unknown-dc.log");
    fs::write(&target, "seed\n").expect("safe target seed write must succeed");

    let rel_candidate = format!(
        "target/telemt-unknown-dc-safe-target-{}/unknown-dc.log",
        std::process::id()
    );
    let sanitized =
        sanitize_unknown_dc_log_path(&rel_candidate).expect("safe candidate must sanitize");
    assert!(
        unknown_dc_log_path_is_still_safe(&sanitized),
        "revalidation must allow safe existing regular files"
    );
}

#[test]
fn unknown_dc_log_path_revalidation_rejects_deleted_parent_after_sanitize() {
    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!(
            "telemt-unknown-dc-vanish-parent-{}",
            std::process::id()
        ));
    fs::create_dir_all(&base).expect("vanish-parent base must be creatable");

    let rel_candidate = format!(
        "target/telemt-unknown-dc-vanish-parent-{}/unknown-dc.log",
        std::process::id()
    );
    let sanitized = sanitize_unknown_dc_log_path(&rel_candidate)
        .expect("candidate must sanitize before parent deletion");

    fs::remove_dir_all(&base).expect("test parent directory must be removable");
    assert!(
        !unknown_dc_log_path_is_still_safe(&sanitized),
        "revalidation must fail when sanitized parent disappears before write"
    );
}

#[cfg(unix)]
#[test]
fn unknown_dc_log_path_revalidation_rejects_parent_swapped_to_symlink() {
    use std::os::unix::fs::symlink;

    let parent = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!(
            "telemt-unknown-dc-parent-swap-{}",
            std::process::id()
        ));
    fs::create_dir_all(&parent).expect("parent-swap test parent must be creatable");

    let rel_candidate = format!(
        "target/telemt-unknown-dc-parent-swap-{}/unknown-dc.log",
        std::process::id()
    );
    let sanitized = sanitize_unknown_dc_log_path(&rel_candidate)
        .expect("candidate must sanitize before parent swap");

    let moved = parent.with_extension("bak");
    let _ = fs::remove_dir_all(&moved);
    fs::rename(&parent, &moved).expect("parent must be movable for swap simulation");
    symlink("/tmp", &parent).expect("symlink replacement for parent must be creatable");

    assert!(
        !unknown_dc_log_path_is_still_safe(&sanitized),
        "revalidation must fail when canonical parent is swapped to a symlinked target"
    );
}

#[cfg(unix)]
#[test]
fn adversarial_check_then_symlink_flip_is_blocked_by_nofollow_open() {
    use std::os::unix::fs::symlink;

    let parent = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!(
            "telemt-unknown-dc-check-open-race-{}",
            std::process::id()
        ));
    fs::create_dir_all(&parent).expect("check-open-race parent must be creatable");

    let target = parent.join("unknown-dc.log");
    fs::write(&target, "seed\n").expect("seed target file must be writable");
    let rel_candidate = format!(
        "target/telemt-unknown-dc-check-open-race-{}/unknown-dc.log",
        std::process::id()
    );
    let sanitized = sanitize_unknown_dc_log_path(&rel_candidate).expect("candidate must sanitize");

    assert!(
        unknown_dc_log_path_is_still_safe(&sanitized),
        "precondition: target should initially pass revalidation"
    );

    let outside = std::env::temp_dir().join(format!(
        "telemt-unknown-dc-check-open-race-outside-{}.log",
        std::process::id()
    ));
    fs::write(&outside, "outside\n").expect("outside file must be writable");
    fs::remove_file(&target).expect("target removal before flip must succeed");
    symlink(&outside, &target).expect("target symlink flip must be creatable");

    let err = open_unknown_dc_log_append(&sanitized.resolved_path)
        .expect_err("nofollow open must fail after symlink flip between check and open");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ELOOP),
        "symlink flip in check/open window must be neutralized by O_NOFOLLOW"
    );
}

#[cfg(unix)]
#[test]
fn adversarial_parent_swap_after_check_is_blocked_by_anchored_open() {
    use std::os::unix::fs::symlink;

    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!(
            "telemt-unknown-dc-parent-swap-openat-{}",
            std::process::id()
        ));
    fs::create_dir_all(&base).expect("parent-swap-openat base must be creatable");

    let rel_candidate = format!(
        "target/telemt-unknown-dc-parent-swap-openat-{}/unknown-dc.log",
        std::process::id()
    );
    let sanitized = sanitize_unknown_dc_log_path(&rel_candidate)
        .expect("candidate must sanitize before parent swap");
    fs::write(&sanitized.resolved_path, "seed\n").expect("seed target file must be writable");

    assert!(
        unknown_dc_log_path_is_still_safe(&sanitized),
        "precondition: target should initially pass revalidation"
    );

    let outside_parent = std::env::temp_dir().join(format!(
        "telemt-unknown-dc-parent-swap-openat-outside-{}",
        std::process::id()
    ));
    fs::create_dir_all(&outside_parent).expect("outside parent directory must be creatable");
    let outside_target = outside_parent.join("unknown-dc.log");
    let _ = fs::remove_file(&outside_target);

    let moved = base.with_extension("bak");
    let _ = fs::remove_dir_all(&moved);
    fs::rename(&base, &moved).expect("base parent must be movable for swap simulation");
    symlink(&outside_parent, &base).expect("base parent symlink replacement must be creatable");

    let err = open_unknown_dc_log_append_anchored(&sanitized)
        .expect_err("anchored open must fail when parent is swapped to symlink");
    let raw = err.raw_os_error();
    assert!(
        matches!(
            raw,
            Some(libc::ELOOP) | Some(libc::ENOTDIR) | Some(libc::ENOENT)
        ),
        "anchored open must fail closed on parent swap race, got raw_os_error={raw:?}"
    );
    assert!(
        !outside_target.exists(),
        "anchored open must never create a log file in swapped outside parent"
    );
}

#[cfg(unix)]
#[test]
fn anchored_open_nix_path_writes_expected_lines() {
    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!(
            "telemt-unknown-dc-anchored-open-ok-{}",
            std::process::id()
        ));
    fs::create_dir_all(&base).expect("anchored-open-ok base must be creatable");

    let rel_candidate = format!(
        "target/telemt-unknown-dc-anchored-open-ok-{}/unknown-dc.log",
        std::process::id()
    );
    let sanitized =
        sanitize_unknown_dc_log_path(&rel_candidate).expect("candidate must sanitize");
    let _ = fs::remove_file(&sanitized.resolved_path);

    let mut first = open_unknown_dc_log_append_anchored(&sanitized)
        .expect("anchored open must create log file in allowed parent");
    append_unknown_dc_line(&mut first, 31_200).expect("first append must succeed");

    let mut second = open_unknown_dc_log_append_anchored(&sanitized)
        .expect("anchored reopen must succeed for existing regular file");
    append_unknown_dc_line(&mut second, 31_201).expect("second append must succeed");

    let content =
        fs::read_to_string(&sanitized.resolved_path).expect("anchored log file must be readable");
    let lines: Vec<&str> = content.lines().filter(|line| !line.trim().is_empty()).collect();
    assert_eq!(lines.len(), 2, "expected one line per anchored append call");
    assert!(
        lines.contains(&"dc_idx=31200") && lines.contains(&"dc_idx=31201"),
        "anchored append output must contain both expected dc_idx lines"
    );
}

#[cfg(unix)]
#[test]
fn anchored_open_parallel_appends_preserve_line_integrity() {
    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!(
            "telemt-unknown-dc-anchored-open-parallel-{}",
            std::process::id()
        ));
    fs::create_dir_all(&base).expect("anchored-open-parallel base must be creatable");

    let rel_candidate = format!(
        "target/telemt-unknown-dc-anchored-open-parallel-{}/unknown-dc.log",
        std::process::id()
    );
    let sanitized =
        sanitize_unknown_dc_log_path(&rel_candidate).expect("candidate must sanitize");
    let _ = fs::remove_file(&sanitized.resolved_path);

    let mut workers = Vec::new();
    for idx in 0..64i16 {
        let sanitized = sanitized.clone();
        workers.push(std::thread::spawn(move || {
            let mut file = open_unknown_dc_log_append_anchored(&sanitized)
                .expect("anchored open must succeed in worker");
            append_unknown_dc_line(&mut file, 32_000 + idx).expect("worker append must succeed");
        }));
    }

    for worker in workers {
        worker.join().expect("worker must not panic");
    }

    let content =
        fs::read_to_string(&sanitized.resolved_path).expect("parallel log file must be readable");
    let lines: Vec<&str> = content.lines().filter(|line| !line.trim().is_empty()).collect();
    assert_eq!(lines.len(), 64, "expected one complete line per worker append");
    for line in lines {
        assert!(
            line.starts_with("dc_idx="),
            "line must keep dc_idx prefix and not be interleaved: {line}"
        );
        let value = line
            .strip_prefix("dc_idx=")
            .expect("prefix checked above")
            .parse::<i16>();
        assert!(
            value.is_ok(),
            "line payload must remain parseable i16 and not be corrupted: {line}"
        );
    }
}

#[cfg(unix)]
#[test]
fn anchored_open_creates_private_0600_file_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!(
            "telemt-unknown-dc-anchored-perms-{}",
            std::process::id()
        ));
    fs::create_dir_all(&base).expect("anchored-perms base must be creatable");

    let rel_candidate = format!(
        "target/telemt-unknown-dc-anchored-perms-{}/unknown-dc.log",
        std::process::id()
    );
    let sanitized =
        sanitize_unknown_dc_log_path(&rel_candidate).expect("candidate must sanitize");
    let _ = fs::remove_file(&sanitized.resolved_path);

    let mut file = open_unknown_dc_log_append_anchored(&sanitized)
        .expect("anchored open must create file with restricted mode");
    append_unknown_dc_line(&mut file, 31_210).expect("initial append must succeed");
    drop(file);

    let mode = fs::metadata(&sanitized.resolved_path)
        .expect("created log file metadata must be readable")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "anchored open must create unknown-dc log file with owner-only rw permissions"
    );
}

#[cfg(unix)]
#[test]
fn anchored_open_rejects_existing_symlink_target() {
    use std::os::unix::fs::symlink;

    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!(
            "telemt-unknown-dc-anchored-symlink-target-{}",
            std::process::id()
        ));
    fs::create_dir_all(&base).expect("anchored-symlink-target base must be creatable");

    let rel_candidate = format!(
        "target/telemt-unknown-dc-anchored-symlink-target-{}/unknown-dc.log",
        std::process::id()
    );
    let sanitized =
        sanitize_unknown_dc_log_path(&rel_candidate).expect("candidate must sanitize");

    let outside = std::env::temp_dir().join(format!(
        "telemt-unknown-dc-anchored-symlink-outside-{}.log",
        std::process::id()
    ));
    fs::write(&outside, "outside\n").expect("outside baseline file must be writable");

    let _ = fs::remove_file(&sanitized.resolved_path);
    symlink(&outside, &sanitized.resolved_path)
        .expect("target symlink for anchored-open rejection test must be creatable");

    let err = open_unknown_dc_log_append_anchored(&sanitized)
        .expect_err("anchored open must reject symlinked filename target");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ELOOP),
        "anchored open should fail closed with ELOOP on symlinked target"
    );
}

#[cfg(unix)]
#[test]
fn anchored_open_high_contention_multi_write_preserves_complete_lines() {
    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!(
            "telemt-unknown-dc-anchored-contention-{}",
            std::process::id()
        ));
    fs::create_dir_all(&base).expect("anchored-contention base must be creatable");

    let rel_candidate = format!(
        "target/telemt-unknown-dc-anchored-contention-{}/unknown-dc.log",
        std::process::id()
    );
    let sanitized =
        sanitize_unknown_dc_log_path(&rel_candidate).expect("candidate must sanitize");
    let _ = fs::remove_file(&sanitized.resolved_path);

    let workers = 24usize;
    let rounds = 40usize;
    let mut threads = Vec::new();

    for worker in 0..workers {
        let sanitized = sanitized.clone();
        threads.push(std::thread::spawn(move || {
            for round in 0..rounds {
                let mut file = open_unknown_dc_log_append_anchored(&sanitized)
                    .expect("anchored open must succeed under contention");
                let dc_idx = 20_000i16.wrapping_add((worker * rounds + round) as i16);
                append_unknown_dc_line(&mut file, dc_idx)
                    .expect("each contention append must complete");
            }
        }));
    }

    for thread in threads {
        thread.join().expect("contention worker must not panic");
    }

    let content = fs::read_to_string(&sanitized.resolved_path)
        .expect("contention output file must be readable");
    let lines: Vec<&str> = content.lines().filter(|line| !line.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        workers * rounds,
        "every contention append must produce exactly one line"
    );

    let mut unique = std::collections::HashSet::new();
    for line in lines {
        assert!(
            line.starts_with("dc_idx="),
            "line must preserve expected prefix under heavy contention: {line}"
        );
        let value = line
            .strip_prefix("dc_idx=")
            .expect("prefix validated")
            .parse::<i16>()
            .expect("line payload must remain parseable i16 under contention");
        unique.insert(value);
    }

    assert_eq!(
        unique.len(),
        workers * rounds,
        "contention output must not lose or duplicate logical writes"
    );
}

#[cfg(unix)]
#[test]
fn append_unknown_dc_line_returns_error_for_read_only_descriptor() {
    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!(
            "telemt-unknown-dc-append-ro-{}",
            std::process::id()
        ));
    fs::create_dir_all(&base).expect("append-ro base must be creatable");

    let rel_candidate = format!(
        "target/telemt-unknown-dc-append-ro-{}/unknown-dc.log",
        std::process::id()
    );
    let sanitized =
        sanitize_unknown_dc_log_path(&rel_candidate).expect("candidate must sanitize");
    fs::write(&sanitized.resolved_path, "seed\n").expect("seed file must be writable");

    let mut readonly = std::fs::OpenOptions::new()
        .read(true)
        .open(&sanitized.resolved_path)
        .expect("readonly file open must succeed");

    append_unknown_dc_line(&mut readonly, 31_222)
        .expect_err("append on readonly descriptor must fail closed");

    let content_after =
        fs::read_to_string(&sanitized.resolved_path).expect("seed file must remain readable");
    assert_eq!(
        nonempty_line_count(&content_after),
        1,
        "failed readonly append must not modify persisted unknown-dc log content"
    );
}

#[tokio::test]
async fn unknown_dc_absolute_log_path_writes_one_entry() {
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
    clear_unknown_dc_log_cache_for_testing();

    let dc_idx: i16 = 31_001;
    let file_path = std::env::temp_dir().join(format!(
        "telemt-unknown-dc-abs-{}-{}.log",
        std::process::id(),
        dc_idx
    ));
    let _ = fs::remove_file(&file_path);

    let mut cfg = ProxyConfig::default();
    cfg.general.unknown_dc_file_log_enabled = true;
    cfg.general.unknown_dc_log_path = Some(
        file_path
            .to_str()
            .expect("temp file path must be valid UTF-8")
            .to_string(),
    );

    let _ = get_dc_addr_static(dc_idx, &cfg).expect("fallback routing must still work");

    let mut content = None;
    for _ in 0..20 {
        if let Ok(text) = fs::read_to_string(&file_path) {
            content = Some(text);
            break;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }

    let text = content.expect("absolute unknown-DC log path must produce exactly one log write");
    assert!(
        text.contains(&format!("dc_idx={dc_idx}")),
        "absolute unknown-DC integration log must contain requested dc_idx"
    );
}

#[tokio::test]
async fn unknown_dc_safe_relative_log_path_writes_one_entry() {
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
    clear_unknown_dc_log_cache_for_testing();

    let dc_idx: i16 = 31_002;
    let rel_dir = format!("target/telemt-unknown-dc-int-{}", std::process::id());
    let rel_file = format!("{rel_dir}/unknown-dc.log");
    let abs_dir = std::env::current_dir()
        .expect("cwd must be available")
        .join(&rel_dir);
    fs::create_dir_all(&abs_dir).expect("integration test log directory must be creatable");
    let abs_file = abs_dir.join("unknown-dc.log");
    let _ = fs::remove_file(&abs_file);

    let mut cfg = ProxyConfig::default();
    cfg.general.unknown_dc_file_log_enabled = true;
    cfg.general.unknown_dc_log_path = Some(rel_file);

    let _ = get_dc_addr_static(dc_idx, &cfg).expect("fallback routing must still work");

    let mut content = None;
    for _ in 0..20 {
        if let Ok(text) = fs::read_to_string(&abs_file) {
            content = Some(text);
            break;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }

    let text = content.expect("safe relative path must produce exactly one log write");
    assert!(
        text.contains(&format!("dc_idx={dc_idx}")),
        "unknown-DC integration log must contain requested dc_idx"
    );
}

#[tokio::test]
async fn unknown_dc_same_index_burst_writes_only_once() {
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
    clear_unknown_dc_log_cache_for_testing();

    let dc_idx: i16 = 31_010;
    let rel_dir = format!("target/telemt-unknown-dc-same-{}", std::process::id());
    let rel_file = format!("{rel_dir}/unknown-dc.log");
    let abs_dir = std::env::current_dir().unwrap().join(&rel_dir);
    fs::create_dir_all(&abs_dir).expect("same-index log directory must be creatable");
    let abs_file = abs_dir.join("unknown-dc.log");
    let _ = fs::remove_file(&abs_file);

    let mut cfg = ProxyConfig::default();
    cfg.general.unknown_dc_file_log_enabled = true;
    cfg.general.unknown_dc_log_path = Some(rel_file);

    for _ in 0..64 {
        let _ = get_dc_addr_static(dc_idx, &cfg).expect("fallback routing must still work");
    }

    let mut content = None;
    for _ in 0..30 {
        if let Ok(text) = fs::read_to_string(&abs_file) {
            content = Some(text);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let text = content.expect("same-index burst must produce at least one log write");
    assert_eq!(
        nonempty_line_count(&text),
        1,
        "same unknown dc index must be deduplicated to one file line"
    );
}

#[tokio::test]
async fn unknown_dc_distinct_burst_is_hard_capped_on_file_writes() {
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
    clear_unknown_dc_log_cache_for_testing();

    let rel_dir = format!("target/telemt-unknown-dc-cap-{}", std::process::id());
    let rel_file = format!("{rel_dir}/unknown-dc.log");
    let abs_dir = std::env::current_dir().unwrap().join(&rel_dir);
    fs::create_dir_all(&abs_dir).expect("cap log directory must be creatable");
    let abs_file = abs_dir.join("unknown-dc.log");
    let _ = fs::remove_file(&abs_file);

    let mut cfg = ProxyConfig::default();
    cfg.general.unknown_dc_file_log_enabled = true;
    cfg.general.unknown_dc_log_path = Some(rel_file);

    for i in 0..(UNKNOWN_DC_LOG_DISTINCT_LIMIT + 128) {
        let dc_idx = 20_000i16.wrapping_add(i as i16);
        let _ = get_dc_addr_static(dc_idx, &cfg).expect("fallback routing must still work");
    }

    let mut final_text = String::new();
    for _ in 0..80 {
        if let Ok(text) = fs::read_to_string(&abs_file) {
            final_text = text;
            if nonempty_line_count(&final_text) >= UNKNOWN_DC_LOG_DISTINCT_LIMIT {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let line_count = nonempty_line_count(&final_text);
    assert!(
        line_count > 0,
        "distinct unknown-dc burst must write at least one line"
    );
    assert!(
        line_count <= UNKNOWN_DC_LOG_DISTINCT_LIMIT,
        "distinct unknown-dc writes must stay within dedup hard cap"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn unknown_dc_symlinked_target_escape_is_not_written_integration() {
    use std::os::unix::fs::symlink;

    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
    clear_unknown_dc_log_cache_for_testing();

    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!(
            "telemt-unknown-dc-no-write-link-{}",
            std::process::id()
        ));
    fs::create_dir_all(&base).expect("integration symlink base must be creatable");

    let outside = std::env::temp_dir().join(format!(
        "telemt-unknown-dc-outside-{}.log",
        std::process::id()
    ));
    fs::write(&outside, "baseline\n").expect("outside baseline file must be writable");

    let linked_target = base.join("unknown-dc.log");
    let _ = fs::remove_file(&linked_target);
    symlink(&outside, &linked_target).expect("symlink target must be creatable");

    let rel_file = format!(
        "target/telemt-unknown-dc-no-write-link-{}/unknown-dc.log",
        std::process::id()
    );
    let dc_idx: i16 = 31_050;

    let mut cfg = ProxyConfig::default();
    cfg.general.unknown_dc_file_log_enabled = true;
    cfg.general.unknown_dc_log_path = Some(rel_file);

    let before = fs::read_to_string(&outside).expect("must read baseline outside file");
    let _ = get_dc_addr_static(dc_idx, &cfg).expect("fallback routing must still work");
    tokio::time::sleep(Duration::from_millis(80)).await;
    let after = fs::read_to_string(&outside).expect("must read outside file after attempt");

    assert_eq!(
        after, before,
        "symlink target escape must not be written by unknown-DC logging"
    );
}

#[test]
fn fallback_dc_never_panics_with_single_dc_list() {
    let mut cfg = ProxyConfig::default();
    cfg.network.prefer = 6;
    cfg.network.ipv6 = Some(true);
    cfg.default_dc = Some(42);

    let addr = get_dc_addr_static(999, &cfg).expect("fallback dc must resolve safely");
    let expected = SocketAddr::new(TG_DATACENTERS_V6[0], TG_DATACENTER_PORT);
    assert_eq!(addr, expected);
}

#[tokio::test]
async fn direct_relay_abort_midflight_releases_route_gauge() {
    let tg_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tg_addr = tg_listener.local_addr().unwrap();

    let tg_accept_task = tokio::spawn(async move {
        let (stream, _) = tg_listener.accept().await.unwrap();
        let _hold_stream = stream;
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    let stats = Arc::new(Stats::new());
    let mut config = ProxyConfig::default();
    config
        .dc_overrides
        .insert("2".to_string(), vec![tg_addr.to_string()]);
    let config = Arc::new(config);

    let upstream_manager = Arc::new(UpstreamManager::new(
        vec![UpstreamConfig {
            upstream_type: UpstreamType::Direct {
                interface: None,
                bind_addresses: None,
            },
            weight: 1,
            enabled: true,
            scopes: String::new(),
            selected_scope: String::new(),
        }],
        1,
        1,
        1,
        1,
        false,
        stats.clone(),
    ));

    let rng = Arc::new(SecureRandom::new());
    let buffer_pool = Arc::new(BufferPool::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let route_snapshot = route_runtime.snapshot();

    let (server_side, client_side) = duplex(64 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_side);
    let client_reader = make_crypto_reader(server_reader);
    let client_writer = make_crypto_writer(server_writer);

    let success = HandshakeSuccess {
        user: "abort-direct-user".to_string(),
        dc_idx: 2,
        proto_tag: ProtoTag::Intermediate,
        dec_key: [0u8; 32],
        dec_iv: 0,
        enc_key: [0u8; 32],
        enc_iv: 0,
        peer: "127.0.0.1:50000".parse().unwrap(),
        is_tls: false,
    };

    let relay_task = tokio::spawn(handle_via_direct(
        client_reader,
        client_writer,
        success,
        upstream_manager,
        stats.clone(),
        config,
        buffer_pool,
        rng,
        route_runtime.subscribe(),
        route_snapshot,
        0xabad1dea,
    ));

    let started = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if stats.get_current_connections_direct() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        started.is_ok(),
        "direct relay must increment route gauge before abort"
    );

    relay_task.abort();
    let joined = relay_task.await;
    assert!(
        joined.is_err(),
        "aborted direct relay task must return join error"
    );

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        stats.get_current_connections_direct(),
        0,
        "route gauge must be released when direct relay task is aborted mid-flight"
    );

    drop(client_side);
    tg_accept_task.abort();
    let _ = tg_accept_task.await;
}

#[tokio::test]
async fn direct_relay_cutover_midflight_releases_route_gauge() {
    let tg_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tg_addr = tg_listener.local_addr().unwrap();

    let tg_accept_task = tokio::spawn(async move {
        let (stream, _) = tg_listener.accept().await.unwrap();
        let _hold_stream = stream;
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    let stats = Arc::new(Stats::new());
    let mut config = ProxyConfig::default();
    config
        .dc_overrides
        .insert("2".to_string(), vec![tg_addr.to_string()]);
    let config = Arc::new(config);

    let upstream_manager = Arc::new(UpstreamManager::new(
        vec![UpstreamConfig {
            upstream_type: UpstreamType::Direct {
                interface: None,
                bind_addresses: None,
            },
            weight: 1,
            enabled: true,
            scopes: String::new(),
            selected_scope: String::new(),
        }],
        1,
        1,
        1,
        1,
        false,
        stats.clone(),
    ));

    let rng = Arc::new(SecureRandom::new());
    let buffer_pool = Arc::new(BufferPool::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let route_snapshot = route_runtime.snapshot();

    let (server_side, client_side) = duplex(64 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_side);
    let client_reader = make_crypto_reader(server_reader);
    let client_writer = make_crypto_writer(server_writer);

    let success = HandshakeSuccess {
        user: "cutover-direct-user".to_string(),
        dc_idx: 2,
        proto_tag: ProtoTag::Intermediate,
        dec_key: [0u8; 32],
        dec_iv: 0,
        enc_key: [0u8; 32],
        enc_iv: 0,
        peer: "127.0.0.1:50002".parse().unwrap(),
        is_tls: false,
    };

    let relay_task = tokio::spawn(handle_via_direct(
        client_reader,
        client_writer,
        success,
        upstream_manager,
        stats.clone(),
        config,
        buffer_pool,
        rng,
        route_runtime.subscribe(),
        route_snapshot,
        0xface_cafe,
    ));

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if stats.get_current_connections_direct() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("direct relay must increment route gauge before cutover");

    assert!(
        route_runtime.set_mode(RelayRouteMode::Middle).is_some(),
        "cutover must advance route generation"
    );

    let relay_result = tokio::time::timeout(Duration::from_secs(6), relay_task)
        .await
        .expect("direct relay must terminate after cutover")
        .expect("direct relay task must not panic");
    assert!(
        relay_result.is_err(),
        "cutover should terminate direct relay session"
    );
    assert!(
        matches!(
            relay_result,
            Err(ProxyError::Proxy(ref msg)) if msg == ROUTE_SWITCH_ERROR_MSG
        ),
        "client-visible cutover error must stay generic and avoid route-internal metadata"
    );

    assert_eq!(
        stats.get_current_connections_direct(),
        0,
        "route gauge must be released when direct relay exits on cutover"
    );

    drop(client_side);
    tg_accept_task.abort();
    let _ = tg_accept_task.await;
}

#[tokio::test]
async fn direct_relay_cutover_storm_multi_session_keeps_generic_errors_and_releases_gauge() {
    let session_count = 6usize;
    let tg_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tg_addr = tg_listener.local_addr().unwrap();

    let tg_accept_task = tokio::spawn(async move {
        let mut held_streams = Vec::with_capacity(session_count);
        for _ in 0..session_count {
            let (stream, _) = tg_listener.accept().await.unwrap();
            held_streams.push(stream);
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
        drop(held_streams);
    });

    let stats = Arc::new(Stats::new());
    let mut config = ProxyConfig::default();
    config
        .dc_overrides
        .insert("2".to_string(), vec![tg_addr.to_string()]);
    let config = Arc::new(config);

    let upstream_manager = Arc::new(UpstreamManager::new(
        vec![UpstreamConfig {
            upstream_type: UpstreamType::Direct {
                interface: None,
                bind_addresses: None,
            },
            weight: 1,
            enabled: true,
            scopes: String::new(),
            selected_scope: String::new(),
        }],
        1,
        1,
        1,
        1,
        false,
        stats.clone(),
    ));

    let rng = Arc::new(SecureRandom::new());
    let buffer_pool = Arc::new(BufferPool::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let route_snapshot = route_runtime.snapshot();

    let mut relay_tasks = Vec::with_capacity(session_count);
    let mut client_sides = Vec::with_capacity(session_count);

    for idx in 0..session_count {
        let (server_side, client_side) = duplex(64 * 1024);
        client_sides.push(client_side);
        let (server_reader, server_writer) = tokio::io::split(server_side);
        let client_reader = make_crypto_reader(server_reader);
        let client_writer = make_crypto_writer(server_writer);

        let success = HandshakeSuccess {
            user: format!("cutover-storm-direct-user-{idx}"),
            dc_idx: 2,
            proto_tag: ProtoTag::Intermediate,
            dec_key: [0u8; 32],
            dec_iv: 0,
            enc_key: [0u8; 32],
            enc_iv: 0,
            peer: SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                51000 + idx as u16,
            ),
            is_tls: false,
        };

        relay_tasks.push(tokio::spawn(handle_via_direct(
            client_reader,
            client_writer,
            success,
            upstream_manager.clone(),
            stats.clone(),
            config.clone(),
            buffer_pool.clone(),
            rng.clone(),
            route_runtime.subscribe(),
            route_snapshot,
            0xA000_0000 + idx as u64,
        )));
    }

    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if stats.get_current_connections_direct() == session_count as u64 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("all direct sessions must become active before cutover storm");

    let route_runtime_flipper = route_runtime.clone();
    let flipper = tokio::spawn(async move {
        for step in 0..64u32 {
            let mode = if (step & 1) == 0 {
                RelayRouteMode::Middle
            } else {
                RelayRouteMode::Direct
            };
            let _ = route_runtime_flipper.set_mode(mode);
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    });

    for relay_task in relay_tasks {
        let relay_result = tokio::time::timeout(Duration::from_secs(10), relay_task)
            .await
            .expect("direct relay task must finish under cutover storm")
            .expect("direct relay task must not panic");

        assert!(
            matches!(
                relay_result,
                Err(ProxyError::Proxy(ref msg)) if msg == ROUTE_SWITCH_ERROR_MSG
            ),
            "storm-cutover termination must remain generic for all direct sessions"
        );
    }

    flipper.abort();
    let _ = flipper.await;

    assert_eq!(
        stats.get_current_connections_direct(),
        0,
        "direct route gauge must return to zero after cutover storm"
    );

    drop(client_sides);
    tg_accept_task.abort();
    let _ = tg_accept_task.await;
}

#[test]
fn prefer_v6_override_matrix_prefers_matching_family_then_degrades_safely() {
    let dc_idx: i16 = 2;

    let mut cfg_a = ProxyConfig::default();
    cfg_a.network.prefer = 6;
    cfg_a.network.ipv6 = Some(true);
    cfg_a.dc_overrides.insert(
        dc_idx.to_string(),
        vec![
            "203.0.113.90:443".to_string(),
            "[2001:db8::90]:443".to_string(),
        ],
    );
    let a = get_dc_addr_static(dc_idx, &cfg_a).expect("v6+v4 override set must resolve");
    assert!(
        a.is_ipv6(),
        "prefer_v6 should choose v6 override when present"
    );

    let mut cfg_b = ProxyConfig::default();
    cfg_b.network.prefer = 6;
    cfg_b.network.ipv6 = Some(true);
    cfg_b
        .dc_overrides
        .insert(dc_idx.to_string(), vec!["203.0.113.91:443".to_string()]);
    let b = get_dc_addr_static(dc_idx, &cfg_b).expect("v4-only override must still resolve");
    assert!(
        b.is_ipv4(),
        "when no v6 override exists, v4 override must be used"
    );

    let mut cfg_c = ProxyConfig::default();
    cfg_c.network.prefer = 6;
    cfg_c.network.ipv6 = Some(true);
    let c = get_dc_addr_static(dc_idx, &cfg_c).expect("table fallback must resolve");
    assert_eq!(
        c,
        SocketAddr::new(TG_DATACENTERS_V6[(dc_idx as usize) - 1], TG_DATACENTER_PORT),
        "without overrides, prefer_v6 path must resolve from static v6 datacenter table"
    );
}

#[test]
fn prefer_v6_override_matrix_ignores_invalid_entries_and_keeps_fail_closed_fallback() {
    let dc_idx: i16 = 3;

    let mut cfg = ProxyConfig::default();
    cfg.network.prefer = 6;
    cfg.network.ipv6 = Some(true);
    cfg.dc_overrides.insert(
        dc_idx.to_string(),
        vec![
            "not-an-addr".to_string(),
            "also:bad".to_string(),
            "203.0.113.55:443".to_string(),
        ],
    );

    let addr = get_dc_addr_static(dc_idx, &cfg)
        .expect("at least one valid override must keep resolution alive");
    assert_eq!(addr, "203.0.113.55:443".parse::<SocketAddr>().unwrap());
}

#[test]
fn stress_prefer_v6_override_matrix_is_deterministic_under_mixed_inputs() {
    for idx in 1..=5i16 {
        let mut cfg = ProxyConfig::default();
        cfg.network.prefer = 6;
        cfg.network.ipv6 = Some(true);
        cfg.dc_overrides.insert(
            idx.to_string(),
            vec![
                format!("203.0.113.{}:443", 100 + idx),
                format!("[2001:db8::{}]:443", 100 + idx),
            ],
        );

        let first = get_dc_addr_static(idx, &cfg).expect("first lookup must resolve");
        let second = get_dc_addr_static(idx, &cfg).expect("second lookup must resolve");
        assert_eq!(
            first, second,
            "override resolution must stay deterministic for dc {idx}"
        );
        assert!(first.is_ipv6(), "dc {idx}: v6 override should be preferred");
    }
}

#[tokio::test]
async fn negative_direct_relay_dc_connection_refused_fails_fast() {
    let (client_reader_side, _client_writer_side) = duplex(1024);
    let (_client_reader_relay, client_writer_side) = duplex(1024);

    let key = [0u8; 32];
    let iv = 0u128;
    let client_reader = CryptoReader::new(client_reader_side, AesCtr::new(&key, iv));
    let client_writer = CryptoWriter::new(client_writer_side, AesCtr::new(&key, iv), 1024);

    let stats = Arc::new(Stats::new());
    let buffer_pool = Arc::new(BufferPool::with_config(1024, 1));
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = RouteRuntimeController::new(RelayRouteMode::Direct);

    // Reserve an ephemeral port and immediately release it to deterministically
    // exercise the direct-connect failure path without long-lived hangs.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dc_addr = listener.local_addr().unwrap();
    drop(listener);

    let mut config_with_override = ProxyConfig::default();
    config_with_override
        .dc_overrides
        .insert("1".to_string(), vec![dc_addr.to_string()]);
    let config = Arc::new(config_with_override);

    let upstream_manager = Arc::new(UpstreamManager::new(
        vec![UpstreamConfig {
            enabled: true,
            weight: 1,
            scopes: String::new(),
            upstream_type: UpstreamType::Direct {
                interface: None,
                bind_addresses: None,
            },
            selected_scope: String::new(),
        }],
        1,
        100,
        5000,
        3,
        false,
        stats.clone(),
    ));

    let success = HandshakeSuccess {
        user: "test-user".to_string(),
        peer: "127.0.0.1:12345".parse().unwrap(),
        dc_idx: 1,
        proto_tag: ProtoTag::Intermediate,
        enc_key: key,
        enc_iv: iv,
        dec_key: key,
        dec_iv: iv,
        is_tls: false,
    };

    let result = timeout(
        TokioDuration::from_secs(2),
        handle_via_direct(
            client_reader,
            client_writer,
            success,
            upstream_manager,
            stats,
            config,
            buffer_pool,
            rng,
            route_runtime.subscribe(),
            route_runtime.snapshot(),
            0xABCD_1234,
        ),
    )
    .await
    .expect("direct relay must fail fast on connection-refused upstream");

    assert!(
        result.is_err(),
        "connection-refused upstream must fail closed"
    );
}

#[tokio::test]
async fn adversarial_direct_relay_cutover_integrity() {
    let (client_reader_side, _client_writer_side) = duplex(1024);
    let (_client_reader_relay, client_writer_side) = duplex(1024);

    let key = [0u8; 32];
    let iv = 0u128;
    let client_reader = CryptoReader::new(client_reader_side, AesCtr::new(&key, iv));
    let client_writer = CryptoWriter::new(client_writer_side, AesCtr::new(&key, iv), 1024);

    let stats = Arc::new(Stats::new());
    let buffer_pool = Arc::new(BufferPool::with_config(1024, 1));
    let rng = Arc::new(SecureRandom::new());
    let route_runtime = RouteRuntimeController::new(RelayRouteMode::Direct);

    // Mock upstream server.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dc_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        // Read handshake nonce.
        let mut nonce = [0u8; 64];
        let _ = stream.read_exact(&mut nonce).await;
        // Keep connection open.
        tokio::time::sleep(TokioDuration::from_secs(5)).await;
    });

    let mut config_with_override = ProxyConfig::default();
    config_with_override
        .dc_overrides
        .insert("1".to_string(), vec![dc_addr.to_string()]);
    let config = Arc::new(config_with_override);

    let upstream_manager = Arc::new(UpstreamManager::new(
        vec![UpstreamConfig {
            enabled: true,
            weight: 1,
            scopes: String::new(),
            upstream_type: UpstreamType::Direct {
                interface: None,
                bind_addresses: None,
            },
            selected_scope: String::new(),
        }],
        1,
        100,
        5000,
        3,
        false,
        stats.clone(),
    ));

    let success = HandshakeSuccess {
        user: "test-user".to_string(),
        peer: "127.0.0.1:12345".parse().unwrap(),
        dc_idx: 1,
        proto_tag: ProtoTag::Intermediate,
        enc_key: key,
        enc_iv: iv,
        dec_key: key,
        dec_iv: iv,
        is_tls: false,
    };

    let stats_for_task = stats.clone();
    let runtime_clone = route_runtime.clone();
    let session_task = tokio::spawn(async move {
        handle_via_direct(
            client_reader,
            client_writer,
            success,
            upstream_manager,
            stats_for_task,
            config,
            buffer_pool,
            rng,
            runtime_clone.subscribe(),
            runtime_clone.snapshot(),
            0xABCD_1234,
        )
        .await
    });

    timeout(TokioDuration::from_secs(2), async {
        loop {
            if stats.get_current_connections_direct() == 1 {
                break;
            }
            tokio::time::sleep(TokioDuration::from_millis(10)).await;
        }
    })
    .await
    .expect("direct relay session must start before cutover");

    // Trigger cutover.
    route_runtime.set_mode(RelayRouteMode::Middle).unwrap();

    // The session should terminate after the staggered delay (1000-2000ms).
    let result = timeout(TokioDuration::from_secs(5), session_task)
        .await
        .expect("Session must terminate after cutover")
        .expect("Session must not panic");

    assert!(
        matches!(
            result,
            Err(ProxyError::Proxy(ref msg)) if msg == ROUTE_SWITCH_ERROR_MSG
        ),
        "Session must terminate with route switch error on cutover"
    );
}
