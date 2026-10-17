use super::*;

#[test]
fn wildcard_watcher_freezes_enable_flag_and_publishes_patterns_only_after_restart() {
    for enabled in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        let source = format!(
            r#"
[access.users]
alice = "000102030405060708090a0b0c0d0e0f"
[web]
allow_wildcard_hosts = {enabled}
[web.limits]
memory_envelope_bytes = 1610612736
[[web.vhosts]]
host = "a.example.com"
public_addr = "203.0.113.10:443"
[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://127.0.0.1:18081"
[[web.vhosts.profiles]]
user = "alice"
secret_mode = "plain"
"#
        );
        std::fs::write(&path, &source).unwrap();
        let loaded = ProxyConfig::load_with_metadata(&path).unwrap();
        let initial = Arc::new(loaded.config);
        let (config_tx, _config_rx) = watch::channel(initial.clone());
        let (log_tx, _log_rx) = watch::channel(initial.general.log_level.clone());
        let mut state = ReloadState::new(Some(loaded.rendered_hash));
        let desired = source
            .replace(
                "allow_wildcard_hosts = false",
                "allow_wildcard_hosts = true",
            )
            .replace("host = \"a.example.com\"", "host = \"*.example.com\"");
        std::fs::write(&path, desired).unwrap();
        reload_config(&path, &config_tx, &log_tx, None, None, &mut state);
        let active = config_tx.borrow().clone();
        assert_eq!(active.web.allow_wildcard_hosts, enabled);
        if enabled {
            assert!(
                active
                    .web
                    .runtime
                    .as_ref()
                    .unwrap()
                    .wildcards
                    .contains_key("example.com")
            );
            assert_ne!(
                active.web.runtime.as_ref().unwrap().snapshot_id,
                initial.web.runtime.as_ref().unwrap().snapshot_id
            );
        } else {
            assert!(Arc::ptr_eq(&initial, &active));
        }
    }
}
