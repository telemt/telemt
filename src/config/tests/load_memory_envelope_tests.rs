use super::*;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn write_temp_config(contents: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must be after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("telemt-load-memory-envelope-{nonce}.toml"));
    fs::write(&path, contents).expect("temp config write must succeed");
    path
}

fn remove_temp_config(path: &PathBuf) {
    let _ = fs::remove_file(path);
}

#[test]
fn defaults_enable_byte_bounded_route_fairness() {
    let cfg = ProxyConfig::default();

    assert!(
        cfg.general.me_route_fairshare_enabled,
        "D2C route fairness must be enabled by default to bound queued bytes"
    );
    assert!(
        cfg.general.me_route_backpressure_enabled,
        "D2C route backpressure must be enabled by default to shed under sustained pressure"
    );
}

#[test]
fn load_rejects_writer_cmd_capacity_above_upper_bound() {
    let path = write_temp_config(
        r#"
[general]
me_writer_cmd_channel_capacity = 16385
"#,
    );

    let err =
        ProxyConfig::load(&path).expect_err("writer command capacity above hard cap must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("general.me_writer_cmd_channel_capacity must be within [1, 16384]"),
        "error must explain writer command capacity hard cap, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_rejects_route_channel_capacity_above_upper_bound() {
    let path = write_temp_config(
        r#"
[general]
me_route_channel_capacity = 8193
"#,
    );

    let err =
        ProxyConfig::load(&path).expect_err("route channel capacity above hard cap must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("general.me_route_channel_capacity must be within [1, 8192]"),
        "error must explain route channel hard cap, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_rejects_c2me_channel_capacity_above_upper_bound() {
    let path = write_temp_config(
        r#"
[general]
me_c2me_channel_capacity = 8193
"#,
    );

    let err = ProxyConfig::load(&path).expect_err("c2me channel capacity above hard cap must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("general.me_c2me_channel_capacity must be within [1, 8192]"),
        "error must explain c2me channel hard cap, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_rejects_max_client_frame_above_upper_bound() {
    let path = write_temp_config(
        r#"
[general]
max_client_frame = 16777217
"#,
    );

    let err = ProxyConfig::load(&path).expect_err("max_client_frame above hard cap must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("general.max_client_frame must be within [4096, 16777216]"),
        "error must explain max_client_frame hard cap, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_accepts_memory_limits_at_hard_upper_bounds() {
    let path = write_temp_config(
        r#"
[general]
me_writer_cmd_channel_capacity = 16384
me_route_channel_capacity = 8192
me_c2me_channel_capacity = 8192
max_client_frame = 16777216
"#,
    );

    let cfg = ProxyConfig::load(&path).expect("hard upper bound values must be accepted");
    assert_eq!(cfg.general.me_writer_cmd_channel_capacity, 16384);
    assert_eq!(cfg.general.me_route_channel_capacity, 8192);
    assert_eq!(cfg.general.me_c2me_channel_capacity, 8192);
    assert_eq!(cfg.general.max_client_frame, 16 * 1024 * 1024);

    remove_temp_config(&path);
}
