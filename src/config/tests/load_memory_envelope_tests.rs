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
fn load_rejects_writer_byte_budget_below_frame_residency_minimum() {
    let path = write_temp_config(
        r#"
[general]
max_client_frame = 16777216
me_writer_byte_budget_bytes = 33554432
"#,
    );

    let err = ProxyConfig::load(&path)
        .expect_err("writer byte budget below frame residency minimum must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("general.me_writer_byte_budget_bytes must be within [33570816, 268435456]"),
        "error must explain writer byte budget minimum, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_rejects_unaligned_writer_byte_budget() {
    let path = write_temp_config(
        r#"
[general]
me_writer_byte_budget_bytes = 33570817
"#,
    );

    let err = ProxyConfig::load(&path)
        .expect_err("writer byte budget outside permit granularity must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("general.me_writer_byte_budget_bytes must be a multiple of 16384"),
        "error must explain writer byte budget alignment, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_rejects_writer_byte_budget_above_hard_cap() {
    let path = write_temp_config(
        r#"
[general]
me_writer_byte_budget_bytes = 268451840
"#,
    );

    let err = ProxyConfig::load(&path).expect_err("writer byte budget above hard cap must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("general.me_writer_byte_budget_bytes must be within [33570816, 268435456]"),
        "error must explain writer byte budget hard cap, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_rejects_unaligned_direct_relay_buffer_budget() {
    let path = write_temp_config(
        r#"
[general]
direct_relay_buffer_budget_max_bytes = 16777217
"#,
    );

    let err = ProxyConfig::load(&path).expect_err("unaligned direct relay buffer budget must fail");
    assert!(
        err.to_string().contains(
            "general.direct_relay_buffer_budget_max_bytes must be 0 or a multiple of 4096"
        )
    );
    remove_temp_config(&path);
}

#[test]
fn load_rejects_direct_relay_buffer_budget_above_hard_cap() {
    let path = write_temp_config(
        r#"
[general]
direct_relay_buffer_budget_max_bytes = 2147487744
"#,
    );

    let err =
        ProxyConfig::load(&path).expect_err("direct relay buffer budget above hard cap must fail");
    assert!(err.to_string().contains(
        "general.direct_relay_buffer_budget_max_bytes must be 0 or within [16777216, 2147483648]"
    ));
    remove_temp_config(&path);
}

#[test]
fn load_rejects_listen_backlog_above_i32_upper_bound() {
    let path = write_temp_config(
        r#"
[server]
listen_backlog = 2147483648
"#,
    );

    let err = ProxyConfig::load(&path).expect_err("listen_backlog above socket cap must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("server.listen_backlog must be within [1, 2147483647]"),
        "error must explain listen_backlog hard cap, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_rejects_zero_listen_backlog() {
    let path = write_temp_config(
        r#"
[server]
listen_backlog = 0
"#,
    );

    let err = ProxyConfig::load(&path).expect_err("zero listen_backlog must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("server.listen_backlog must be within [1, 2147483647]"),
        "error must explain listen_backlog lower bound, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_accepts_memory_limits_at_hard_upper_bounds() {
    let path = write_temp_config(
        r#"
[general]
me_writer_cmd_channel_capacity = 16384
me_writer_byte_budget_bytes = 268435456
me_route_channel_capacity = 8192
me_c2me_channel_capacity = 8192
direct_relay_buffer_budget_max_bytes = 2147483648
max_client_frame = 16777216
"#,
    );

    let cfg = ProxyConfig::load(&path).expect("hard upper bound values must be accepted");
    assert_eq!(cfg.general.me_writer_cmd_channel_capacity, 16384);
    assert_eq!(cfg.general.me_writer_byte_budget_bytes, 256 * 1024 * 1024);
    assert_eq!(cfg.general.me_route_channel_capacity, 8192);
    assert_eq!(cfg.general.me_c2me_channel_capacity, 8192);
    assert_eq!(
        cfg.general.direct_relay_buffer_budget_max_bytes,
        2 * 1024 * 1024 * 1024
    );
    assert_eq!(cfg.general.max_client_frame, 16 * 1024 * 1024);

    remove_temp_config(&path);
}
