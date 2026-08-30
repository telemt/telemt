use super::*;

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
    if let Ok(meta) = fs::symlink_metadata(&parent) {
        if meta.file_type().is_symlink() || meta.is_file() {
            fs::remove_file(&parent).expect("stale parent-swap path must be removable");
        } else {
            fs::remove_dir_all(&parent).expect("stale parent-swap directory must be removable");
        }
    }
    let moved = parent.with_extension("bak");
    if let Ok(meta) = fs::symlink_metadata(&moved) {
        if meta.file_type().is_symlink() || meta.is_file() {
            fs::remove_file(&moved).expect("stale parent-swap backup path must be removable");
        } else {
            fs::remove_dir_all(&moved)
                .expect("stale parent-swap backup directory must be removable");
        }
    }
    fs::create_dir_all(&parent).expect("parent-swap test parent must be creatable");

    let rel_candidate = format!(
        "target/telemt-unknown-dc-parent-swap-{}/unknown-dc.log",
        std::process::id()
    );
    let sanitized = sanitize_unknown_dc_log_path(&rel_candidate)
        .expect("candidate must sanitize before parent swap");

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
    if let Ok(meta) = fs::symlink_metadata(&parent) {
        if meta.file_type().is_symlink() || meta.is_file() {
            fs::remove_file(&parent).expect("stale check-open-race path must be removable");
        } else {
            fs::remove_dir_all(&parent).expect("stale check-open-race parent must be removable");
        }
    }
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
