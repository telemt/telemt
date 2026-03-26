use super::*;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn write_temp_config(contents: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must be after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("telemt-idle-policy-{nonce}.toml"));
    fs::write(&path, contents).expect("temp config write must succeed");
    path
}

fn remove_temp_config(path: &PathBuf) {
    let _ = fs::remove_file(path);
}

#[test]
fn load_rejects_relay_hard_idle_smaller_than_soft_idle_with_clear_error() {
    let path = write_temp_config(
        r#"
[timeouts]
relay_client_idle_soft_secs = 120
relay_client_idle_hard_secs = 60
"#,
    );

    let err = ProxyConfig::load(&path).expect_err("config with hard<soft must fail");
    let msg = err.to_string();
    assert!(
        msg.contains(
            "timeouts.relay_client_idle_hard_secs must be >= timeouts.relay_client_idle_soft_secs"
        ),
        "error must explain the violated hard>=soft invariant, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_rejects_relay_grace_larger_than_hard_idle_with_clear_error() {
    let path = write_temp_config(
        r#"
[timeouts]
relay_client_idle_soft_secs = 60
relay_client_idle_hard_secs = 120
relay_idle_grace_after_downstream_activity_secs = 121
"#,
    );

    let err = ProxyConfig::load(&path).expect_err("config with grace>hard must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("timeouts.relay_idle_grace_after_downstream_activity_secs must be <= timeouts.relay_client_idle_hard_secs"),
        "error must explain the violated grace<=hard invariant, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_rejects_zero_handshake_timeout_with_clear_error() {
    let path = write_temp_config(
        r#"
[timeouts]
client_handshake = 0
"#,
    );

    let err = ProxyConfig::load(&path).expect_err("config with zero handshake timeout must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("timeouts.client_handshake must be > 0"),
        "error must explain that handshake timeout must be positive, got: {msg}"
    );

    remove_temp_config(&path);
}
