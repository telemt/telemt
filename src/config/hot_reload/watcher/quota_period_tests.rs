use super::*;

#[tokio::test]
async fn quota_period_unchanged_source_refreshes_only_fenced_accounts_without_dns() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[access.users]\nalice = '0123456789abcdef0123456789abcdef'\n",
    )
    .unwrap();
    let source = ProxyConfig::parse_source(&path).unwrap();
    let initial = Arc::new(source.config);
    let (tx, mut rx) = watch::channel(initial.clone());
    let (log, _) = watch::channel(initial.general.log_level.clone());
    let mut state = ReloadState::new(Some(source.rendered_hash));
    let gate = Arc::new(tokio::sync::Mutex::new(()));
    preparation::reload(
        &path,
        &tx,
        &log,
        None,
        None,
        &mut state,
        None,
        false,
        Some(&gate),
        Some(&|| true),
    )
    .await
    .unwrap();
    assert!(rx.has_changed().unwrap());
    let refreshed = rx.borrow_and_update().clone();
    assert!(config_equal(&initial, &refreshed));
    assert!(refreshed.quota_source_read_at > initial.quota_source_read_at);
    preparation::reload(
        &path,
        &tx,
        &log,
        None,
        None,
        &mut state,
        None,
        false,
        Some(&gate),
        Some(&|| false),
    )
    .await
    .unwrap();
    assert!(!rx.has_changed().unwrap());
    assert!(Arc::ptr_eq(&refreshed, &rx.borrow()));
    preparation::reload(
        &path,
        &tx,
        &log,
        None,
        None,
        &mut state,
        None,
        true,
        Some(&gate),
        Some(&|| true),
    )
    .await
    .unwrap();
    assert!(rx.has_changed().unwrap());
    assert!(rx.borrow().quota_source_read_at > refreshed.quota_source_read_at);
    assert!(config_equal(&refreshed, &rx.borrow()));
}

#[tokio::test]
async fn quota_period_watcher_initialization_refreshes_pending_identical_source() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[access.users]\nalice = '0123456789abcdef0123456789abcdef'\n",
    )
    .unwrap();
    let initial = Arc::new(ProxyConfig::load(&path).unwrap());
    let cancel = tokio_util::sync::CancellationToken::new();
    let (mut rx, _, task) = spawn_config_watcher(
        path,
        initial.clone(),
        None,
        None,
        cancel.clone(),
        None,
        None,
        Some(Arc::new(tokio::sync::Mutex::new(()))),
        Some(Arc::new(|| true)),
    );
    let task = tokio::spawn(task);
    tokio::time::timeout(Duration::from_secs(5), rx.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(config_equal(&initial, &rx.borrow()));
    assert!(rx.borrow().quota_source_read_at > initial.quota_source_read_at);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}
