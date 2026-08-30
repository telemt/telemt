use super::*;

#[tokio::test]
async fn unknown_dc_absolute_log_path_writes_one_entry() {
    let _guard = unknown_dc_test_lock().lock().await;
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
    let _guard = unknown_dc_test_lock().lock().await;
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
    let _guard = unknown_dc_test_lock().lock().await;
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
    let _guard = unknown_dc_test_lock().lock().await;
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

    let _guard = unknown_dc_test_lock().lock().await;
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
