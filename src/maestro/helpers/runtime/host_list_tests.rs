use super::*;

#[test]
fn grouped_startup_links_include_every_alias_and_selected_profile() {
    const CHILD: &str = "TELEMT_F1_LINK_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
[general.links]
show = ["alice"]
[access.users]
alice = "000102030405060708090a0b0c0d0e0f"
bob = "101112131415161718191a1b1c1d1e1f"
[[server.listeners]]
ip = "127.0.0.1"
port = 18080
transport = "web"
web_trusted_proxy_cidrs = ["127.0.0.1/32"]
[web]
enabled = true
[[web.vhosts]]
hosts = ["a.example.com", "b.example.com"]
base_path = "MixedCase/path"
public_addr = "203.0.113.10:443"
[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://127.0.0.1:18081"
[[web.vhosts.profiles]]
user = "alice"
secret_mode = "plain"
[[web.vhosts.profiles]]
user = "alice"
secret_mode = "dd"
[[web.vhosts.profiles]]
user = "bob"
secret_mode = "dd"
"#,
        )
        .unwrap();
        print_web_proxy_links(&ProxyConfig::load(&path).unwrap());
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "maestro::helpers::runtime::host_list_tests::grouped_startup_links_include_every_alias_and_selected_profile", "--nocapture"])
        .env(CHILD, "1")
        .output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(stderr.matches("WEB: tg://webproxy?").count(), 4, "{stderr}");
    for host in ["a.example.com", "b.example.com"] {
        for mode in [
            crate::config::WebSecretMode::Plain,
            crate::config::WebSecretMode::Dd,
        ] {
            let link = format_web_proxy_link(
                host,
                "MixedCase/path",
                "000102030405060708090a0b0c0d0e0f",
                mode,
            )
            .unwrap();
            assert_eq!(stderr.matches(&link).count(), 1, "{stderr}");
        }
    }
    assert!(!stderr.contains("User: bob"));
}
