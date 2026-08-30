use super::*;

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
    if let Ok(meta) = fs::symlink_metadata(&base) {
        if meta.file_type().is_symlink() || meta.is_file() {
            fs::remove_file(&base).expect("stale parent-swap-openat path must be removable");
        } else {
            fs::remove_dir_all(&base)
                .expect("stale parent-swap-openat directory must be removable");
        }
    }
    let moved = base.with_extension("bak");
    if let Ok(meta) = fs::symlink_metadata(&moved) {
        if meta.file_type().is_symlink() || meta.is_file() {
            fs::remove_file(&moved)
                .expect("stale parent-swap-openat backup path must be removable");
        } else {
            fs::remove_dir_all(&moved)
                .expect("stale parent-swap-openat backup directory must be removable");
        }
    }
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
    let sanitized = sanitize_unknown_dc_log_path(&rel_candidate).expect("candidate must sanitize");
    let _ = fs::remove_file(&sanitized.resolved_path);

    let mut first = open_unknown_dc_log_append_anchored(&sanitized)
        .expect("anchored open must create log file in allowed parent");
    append_unknown_dc_line(&mut first, 31_200).expect("first append must succeed");

    let mut second = open_unknown_dc_log_append_anchored(&sanitized)
        .expect("anchored reopen must succeed for existing regular file");
    append_unknown_dc_line(&mut second, 31_201).expect("second append must succeed");

    let content =
        fs::read_to_string(&sanitized.resolved_path).expect("anchored log file must be readable");
    let lines: Vec<&str> = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
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
    let sanitized = sanitize_unknown_dc_log_path(&rel_candidate).expect("candidate must sanitize");
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
    let lines: Vec<&str> = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        lines.len(),
        64,
        "expected one complete line per worker append"
    );
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
    let sanitized = sanitize_unknown_dc_log_path(&rel_candidate).expect("candidate must sanitize");
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
    let sanitized = sanitize_unknown_dc_log_path(&rel_candidate).expect("candidate must sanitize");

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
    let sanitized = sanitize_unknown_dc_log_path(&rel_candidate).expect("candidate must sanitize");
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
    let lines: Vec<&str> = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
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
    let sanitized = sanitize_unknown_dc_log_path(&rel_candidate).expect("candidate must sanitize");
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
