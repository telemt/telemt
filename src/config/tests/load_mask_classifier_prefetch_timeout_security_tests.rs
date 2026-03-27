use super::*;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn write_temp_config(contents: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must be after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "telemt-load-mask-prefetch-timeout-security-{nonce}.toml"
    ));
    fs::write(&path, contents).expect("temp config write must succeed");
    path
}

fn remove_temp_config(path: &PathBuf) {
    let _ = fs::remove_file(path);
}

#[test]
fn load_rejects_mask_classifier_prefetch_timeout_below_min_bound() {
    let path = write_temp_config(
        r#"
[censorship]
mask_classifier_prefetch_timeout_ms = 4
"#,
    );

    let err = ProxyConfig::load(&path)
        .expect_err("prefetch timeout below minimum security bound must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("censorship.mask_classifier_prefetch_timeout_ms must be within [5, 50]"),
        "error must explain timeout bound invariant, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_rejects_mask_classifier_prefetch_timeout_above_max_bound() {
    let path = write_temp_config(
        r#"
[censorship]
mask_classifier_prefetch_timeout_ms = 51
"#,
    );

    let err = ProxyConfig::load(&path)
        .expect_err("prefetch timeout above max security bound must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("censorship.mask_classifier_prefetch_timeout_ms must be within [5, 50]"),
        "error must explain timeout bound invariant, got: {msg}"
    );

    remove_temp_config(&path);
}

#[test]
fn load_accepts_mask_classifier_prefetch_timeout_within_bounds() {
    let path = write_temp_config(
        r#"
[censorship]
mask_classifier_prefetch_timeout_ms = 20
"#,
    );

    let cfg =
        ProxyConfig::load(&path).expect("prefetch timeout within security bounds must be accepted");
    assert_eq!(cfg.censorship.mask_classifier_prefetch_timeout_ms, 20);

    remove_temp_config(&path);
}
