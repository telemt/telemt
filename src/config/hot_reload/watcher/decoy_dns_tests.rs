use super::*;

const SOURCE: &str = r#"
[access.users]
alice = "000102030405060708090a0b0c0d0e0f"
[[server.listeners]]
ip = "127.0.0.1"
port = 18080
transport = "web"
web_trusted_proxy_cidrs = ["127.0.0.1/32"]
[web]
enabled = true
[[web.vhosts]]
host = "proxy.example.com"
public_addr = "203.0.113.10:443"
[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://localhost:18081"
resolve = "startup"
[[web.vhosts.profiles]]
user = "alice"
secret_mode = "dd"
"#;

#[tokio::test]
async fn decoy_dns_watcher_publishes_dns_only_changes_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, SOURCE).unwrap();
    let mut loaded = ProxyConfig::load_prepared(path.clone()).await.unwrap();
    let (config_tx, mut config_rx) = watch::channel(Arc::new(loaded.config.clone()));
    let (log_tx, _) = watch::channel(loaded.config.general.log_level.clone());
    let old = config_rx.borrow().clone();
    let mut state = ReloadState::new(Some(loaded.rendered_hash));
    Arc::make_mut(&mut loaded.config.web.decoy_dns)
        .origins
        .insert(
            ("localhost".to_string(), 18081),
            vec!["127.0.0.2:18081".parse().unwrap()],
        );
    loaded.config.rebuild_runtime_web().unwrap();
    let applied = prepare_effective_config(&old, &loaded.config).unwrap();
    reload_config_with_resolver(
        (loaded.clone(), applied),
        &config_tx,
        &log_tx,
        None,
        None,
        &mut state,
        None,
        false,
    )
    .unwrap();
    assert!(config_rx.has_changed().unwrap());
    let published = config_rx.borrow_and_update().clone();
    assert!(!old.web_decoy_endpoints_equal(&published));
    let applied = prepare_effective_config(&published, &loaded.config).unwrap();
    reload_config_with_resolver(
        (loaded, applied),
        &config_tx,
        &log_tx,
        None,
        None,
        &mut state,
        None,
        false,
    )
    .unwrap();
    assert!(!config_rx.has_changed().unwrap());
    assert!(Arc::ptr_eq(&published, &config_rx.borrow()));

    preparation::reload(
        &path, &config_tx, &log_tx, None, None, &mut state, None, false, None, None,
    )
    .await
    .unwrap();
    assert!(!config_rx.has_changed().unwrap());
    assert!(Arc::ptr_eq(&published, &config_rx.borrow()));

    // Explicit reload bypasses the unchanged source hash and replaces the injected endpoint.
    preparation::reload(
        &path, &config_tx, &log_tx, None, None, &mut state, None, true, None, None,
    )
    .await
    .unwrap();
    assert!(config_rx.has_changed().unwrap());
    assert!(!published.web_decoy_endpoints_equal(&config_rx.borrow()));

    let current = config_rx.borrow_and_update().clone();
    std::fs::write(&path, SOURCE.replace("localhost:18081", "localhost:18080")).unwrap();
    preparation::reload(
        &path, &config_tx, &log_tx, None, None, &mut state, None, false, None, None,
    )
    .await
    .unwrap();
    assert!(!config_rx.has_changed().unwrap());
    assert!(Arc::ptr_eq(&current, &config_rx.borrow()));
}

#[tokio::test]
async fn decoy_dns_unchanged_watcher_source_skips_resolution() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        SOURCE.replace("localhost", "unresolvable.example.invalid"),
    )
    .unwrap();
    let source = preparation::read_source(&path).await.unwrap();
    let initial = Arc::new(source.config.clone());
    let (config_tx, config_rx) = watch::channel(initial.clone());
    let (log_tx, _) = watch::channel(initial.general.log_level.clone());
    let mut state = ReloadState::new(Some(source.rendered_hash));
    assert!(preparation::source_matches_active(&initial, &source));
    preparation::reload(
        &path, &config_tx, &log_tx, None, None, &mut state, None, false, None, None,
    )
    .await
    .unwrap();
    assert!(!config_rx.has_changed().unwrap());
    assert!(Arc::ptr_eq(&initial, &config_rx.borrow()));
}

#[tokio::test]
async fn decoy_dns_watcher_init_ignores_retained_restart_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, SOURCE).unwrap();
    let loaded = ProxyConfig::load_prepared(path.clone()).await.unwrap();
    let mut source = ProxyConfig::parse_source(&path).unwrap();
    source.config.web.limits.max_static_file_bytes += 1;
    assert!(preparation::source_matches_active(&loaded.config, &source));
    source.config.web.conveyor = !source.config.web.conveyor;
    assert!(!preparation::source_matches_active(&loaded.config, &source));
}
