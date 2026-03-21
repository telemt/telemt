use super::*;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn write_temp_config(contents: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must be after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("telemt-load-security-{nonce}.toml"));
    fs::write(&path, contents).expect("temp config write must succeed");
    path
}

fn remove_temp_config(path: &PathBuf) {
    let _ = fs::remove_file(path);
}

#[test]
fn load_rejects_server_hello_delay_equal_to_handshake_timeout_budget() {
    let path = write_temp_config(
        r#"
[timeouts]
client_handshake = 1

[censorship]
server_hello_delay_max_ms = 1000
"#,
    );

    let err = ProxyConfig::load(&path)
        .expect_err("delay equal to handshake timeout must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("censorship.server_hello_delay_max_ms must be < timeouts.client_handshake * 1000"),
        "error must explain delay<timeout invariant, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_rejects_server_hello_delay_larger_than_handshake_timeout_budget() {
    let path = write_temp_config(
        r#"
[timeouts]
client_handshake = 1

[censorship]
server_hello_delay_max_ms = 1500
"#,
    );

    let err = ProxyConfig::load(&path)
        .expect_err("delay larger than handshake timeout must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("censorship.server_hello_delay_max_ms must be < timeouts.client_handshake * 1000"),
        "error must explain delay<timeout invariant, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_accepts_server_hello_delay_strictly_below_handshake_timeout_budget() {
    let path = write_temp_config(
        r#"
[timeouts]
client_handshake = 1

[censorship]
server_hello_delay_max_ms = 999
"#,
    );

    let cfg = ProxyConfig::load(&path)
        .expect("delay below handshake timeout budget must be accepted");
    assert_eq!(cfg.timeouts.client_handshake, 1);
    assert_eq!(cfg.censorship.server_hello_delay_max_ms, 999);

    remove_temp_config(&path);
}
