use super::*;

#[test]
fn host_list_reload_publishes_complete_tables_and_preserves_invalid_candidates() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let source = r#"
[access.users]
alice = "000102030405060708090a0b0c0d0e0f"
[web]
enabled = true
[[server.listeners]]
ip = "127.0.0.1"
port = 18080
transport = "web"
web_trusted_proxy_cidrs = ["127.0.0.1/32"]
[[web.vhosts]]
host = "a.example.com"
public_addr = "203.0.113.10:443"
[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://127.0.0.1:18081"
[[web.vhosts.profiles]]
user = "alice"
secret_mode = "dd"
"#;
    std::fs::write(&path, source).unwrap();
    let loaded = ProxyConfig::load_with_metadata(&path).unwrap();
    let initial = Arc::new(loaded.config);
    let (config_tx, _config_rx) = watch::channel(Arc::clone(&initial));
    let (log_tx, _log_rx) = watch::channel(initial.general.log_level.clone());
    let mut state = ReloadState::new(Some(loaded.rendered_hash));
    let capability = initial.web.runtime.as_ref().unwrap().capabilities[0];
    for (selector, valid, hosts) in [
        (
            "hosts = [\"a.example.com\", \"A.Example.COM\"]",
            false,
            vec![],
        ),
        (
            "hosts = [\"b.example.com\", \"a.example.com\"]",
            true,
            vec!["b.example.com", "a.example.com"],
        ),
        ("hosts = [\"a.example.com\"]", true, vec!["a.example.com"]),
    ] {
        let before = config_tx.borrow().clone();
        std::fs::write(&path, source.replace("host = \"a.example.com\"", selector)).unwrap();
        reload_config(&path, &config_tx, &log_tx, None, None, &mut state);
        let applied = config_tx.borrow().clone();
        if !valid {
            assert!(Arc::ptr_eq(&before, &applied));
            continue;
        }
        let runtime = applied.web.runtime.as_ref().unwrap();
        assert_eq!(runtime.vhosts.len(), hosts.len());
        assert_eq!(runtime.profiles.len(), hosts.len());
        assert_eq!(runtime.capabilities.len(), hosts.len());
        assert_eq!(runtime.vhosts["a.example.com"].capabilities[0], capability);
        for (idx, host) in hosts.iter().enumerate() {
            assert_eq!(runtime.profiles[idx].host, *host);
            assert_eq!(
                runtime.capabilities[idx],
                runtime.vhosts[*host].capabilities[0]
            );
        }
    }
}
