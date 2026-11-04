use super::*;
use crate::config::CidrRateLimitKey;

const TEST_SHADOWSOCKS_URL: &str =
    "ss://2022-blake3-aes-256-gcm:MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=@127.0.0.1:8388";

fn load_config_from_temp_toml(toml: &str) -> ProxyConfig {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("telemt_load_cfg_{nonce}"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.toml");
    std::fs::write(&path, toml).unwrap();
    let cfg = ProxyConfig::load(&path).unwrap();
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir(dir);
    cfg
}

fn load_config_error_from_temp_toml(toml: &str) -> String {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("telemt_load_cfg_error_{nonce}"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.toml");
    std::fs::write(&path, toml).unwrap();
    let error = ProxyConfig::load(&path).unwrap_err().to_string();
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir(dir);
    error
}

#[path = "load_basic_tests/api_tests.rs"]
mod api_tests;
#[path = "load_basic_tests/conntrack_tests.rs"]
mod conntrack_tests;
#[path = "load_basic_tests/defaults_access_tests.rs"]
mod defaults_access_tests;
#[path = "load_basic_tests/legacy_policy_tests.rs"]
mod legacy_policy_tests;
#[path = "load_basic_tests/me_route_tests.rs"]
mod me_route_tests;
#[path = "load_basic_tests/me_startup_tests.rs"]
mod me_startup_tests;
#[path = "load_basic_tests/quota_period_tests.rs"]
mod quota_period_tests;
#[path = "load_basic_tests/source_security_tests.rs"]
mod source_security_tests;
#[path = "load_basic_tests/synlimit_mss_tests.rs"]
mod synlimit_mss_tests;
#[path = "load_basic_tests/tls_fetch_tests.rs"]
mod tls_fetch_tests;
#[path = "load_basic_tests/upstream_tests.rs"]
mod upstream_tests;
#[path = "load_basic_tests/web_tests.rs"]
mod web_tests;
