use super::*;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn write_temp_config(contents: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must be after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("telemt-load-mask-shape-security-{nonce}.toml"));
    fs::write(&path, contents).expect("temp config write must succeed");
    path
}

fn remove_temp_config(path: &PathBuf) {
    let _ = fs::remove_file(path);
}

#[test]
fn load_rejects_zero_mask_shape_bucket_floor_bytes() {
    let path = write_temp_config(
        r#"
[censorship]
mask_shape_bucket_floor_bytes = 0
mask_shape_bucket_cap_bytes = 4096
"#,
    );

    let err =
        ProxyConfig::load(&path).expect_err("zero mask_shape_bucket_floor_bytes must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("censorship.mask_shape_bucket_floor_bytes must be > 0"),
        "error must explain floor>0 invariant, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_rejects_mask_shape_bucket_cap_less_than_floor() {
    let path = write_temp_config(
        r#"
[censorship]
mask_shape_bucket_floor_bytes = 1024
mask_shape_bucket_cap_bytes = 512
"#,
    );

    let err =
        ProxyConfig::load(&path).expect_err("mask_shape_bucket_cap_bytes < floor must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains(
            "censorship.mask_shape_bucket_cap_bytes must be >= censorship.mask_shape_bucket_floor_bytes"
        ),
        "error must explain cap>=floor invariant, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_accepts_mask_shape_bucket_cap_equal_to_floor() {
    let path = write_temp_config(
        r#"
[censorship]
mask_shape_hardening = true
mask_shape_bucket_floor_bytes = 1024
mask_shape_bucket_cap_bytes = 1024
"#,
    );

    let cfg = ProxyConfig::load(&path).expect("equal cap and floor must be accepted");
    assert!(cfg.censorship.mask_shape_hardening);
    assert_eq!(cfg.censorship.mask_shape_bucket_floor_bytes, 1024);
    assert_eq!(cfg.censorship.mask_shape_bucket_cap_bytes, 1024);

    remove_temp_config(&path);
}

#[test]
fn load_rejects_above_cap_blur_when_shape_hardening_disabled() {
    let path = write_temp_config(
        r#"
[censorship]
mask_shape_hardening = false
mask_shape_above_cap_blur = true
mask_shape_above_cap_blur_max_bytes = 64
"#,
    );

    let err = ProxyConfig::load(&path)
        .expect_err("above-cap blur must require shape hardening enabled");
    let msg = err.to_string();
    assert!(
        msg.contains("censorship.mask_shape_above_cap_blur requires censorship.mask_shape_hardening = true"),
        "error must explain blur prerequisite, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_rejects_above_cap_blur_with_zero_max_bytes() {
    let path = write_temp_config(
        r#"
[censorship]
mask_shape_hardening = true
mask_shape_above_cap_blur = true
mask_shape_above_cap_blur_max_bytes = 0
"#,
    );

    let err = ProxyConfig::load(&path)
        .expect_err("above-cap blur max bytes must be > 0 when enabled");
    let msg = err.to_string();
    assert!(
        msg.contains("censorship.mask_shape_above_cap_blur_max_bytes must be > 0 when censorship.mask_shape_above_cap_blur is enabled"),
        "error must explain blur max bytes invariant, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_rejects_timing_normalization_floor_zero_when_enabled() {
    let path = write_temp_config(
        r#"
[censorship]
mask_timing_normalization_enabled = true
mask_timing_normalization_floor_ms = 0
mask_timing_normalization_ceiling_ms = 200
"#,
    );

    let err = ProxyConfig::load(&path)
        .expect_err("timing normalization floor must be > 0 when enabled");
    let msg = err.to_string();
    assert!(
        msg.contains("censorship.mask_timing_normalization_floor_ms must be > 0 when censorship.mask_timing_normalization_enabled is true"),
        "error must explain timing floor invariant, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_rejects_timing_normalization_ceiling_below_floor() {
    let path = write_temp_config(
        r#"
[censorship]
mask_timing_normalization_enabled = true
mask_timing_normalization_floor_ms = 220
mask_timing_normalization_ceiling_ms = 200
"#,
    );

    let err = ProxyConfig::load(&path)
        .expect_err("timing normalization ceiling must be >= floor");
    let msg = err.to_string();
    assert!(
        msg.contains("censorship.mask_timing_normalization_ceiling_ms must be >= censorship.mask_timing_normalization_floor_ms"),
        "error must explain timing ceiling/floor invariant, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_accepts_valid_timing_normalization_and_above_cap_blur_config() {
    let path = write_temp_config(
        r#"
[censorship]
mask_shape_hardening = true
mask_shape_above_cap_blur = true
mask_shape_above_cap_blur_max_bytes = 128
mask_timing_normalization_enabled = true
mask_timing_normalization_floor_ms = 150
mask_timing_normalization_ceiling_ms = 240
"#,
    );

    let cfg = ProxyConfig::load(&path)
        .expect("valid blur and timing normalization settings must be accepted");
    assert!(cfg.censorship.mask_shape_hardening);
    assert!(cfg.censorship.mask_shape_above_cap_blur);
    assert_eq!(cfg.censorship.mask_shape_above_cap_blur_max_bytes, 128);
    assert!(cfg.censorship.mask_timing_normalization_enabled);
    assert_eq!(cfg.censorship.mask_timing_normalization_floor_ms, 150);
    assert_eq!(cfg.censorship.mask_timing_normalization_ceiling_ms, 240);

    remove_temp_config(&path);
}
