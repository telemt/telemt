use super::*;

// Source polling and explicit reloads have distinct DNS preparation lifecycles.
mod preparation;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct WatchManifest {
    files: BTreeSet<PathBuf>,
    dirs: BTreeSet<PathBuf>,
}

impl WatchManifest {
    fn from_source_files(source_files: &[PathBuf]) -> Self {
        let mut files = BTreeSet::new();
        let mut dirs = BTreeSet::new();

        for path in source_files {
            let normalized = normalize_watch_path(path);
            files.insert(normalized.clone());
            if let Some(parent) = normalized.parent() {
                dirs.insert(parent.to_path_buf());
            }
        }

        Self { files, dirs }
    }

    fn matches_event_paths(&self, event_paths: &[PathBuf]) -> bool {
        event_paths
            .iter()
            .map(|path| normalize_watch_path(path))
            .any(|path| self.files.contains(&path))
    }
}

#[derive(Debug, Default)]
pub(super) struct ReloadState {
    applied_snapshot_hash: Option<u64>,
}

impl ReloadState {
    pub(super) fn new(applied_snapshot_hash: Option<u64>) -> Self {
        Self {
            applied_snapshot_hash,
        }
    }

    fn is_applied(&self, hash: u64) -> bool {
        self.applied_snapshot_hash == Some(hash)
    }

    fn mark_applied(&mut self, hash: u64) {
        self.applied_snapshot_hash = Some(hash);
    }
}

fn normalize_watch_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn sync_watch_paths<W: Watcher>(
    watcher: &mut W,
    current: &BTreeSet<PathBuf>,
    next: &BTreeSet<PathBuf>,
    recursive_mode: RecursiveMode,
    kind: &str,
) {
    for path in current.difference(next) {
        if let Err(e) = watcher.unwatch(path) {
            warn!(path = %path.display(), error = %e, "config watcher: failed to unwatch {kind}");
        }
    }

    for path in next.difference(current) {
        if let Err(e) = watcher.watch(path, recursive_mode) {
            warn!(path = %path.display(), error = %e, "config watcher: failed to watch {kind}");
        }
    }
}

fn apply_watch_manifest<W1: Watcher, W2: Watcher>(
    notify_watcher: Option<&mut W1>,
    poll_watcher: Option<&mut W2>,
    manifest_state: &Arc<StdRwLock<WatchManifest>>,
    next_manifest: WatchManifest,
) {
    let current_manifest = manifest_state
        .read()
        .map(|manifest| manifest.clone())
        .unwrap_or_default();

    if current_manifest == next_manifest {
        return;
    }

    if let Some(watcher) = notify_watcher {
        sync_watch_paths(
            watcher,
            &current_manifest.dirs,
            &next_manifest.dirs,
            RecursiveMode::NonRecursive,
            "config directory",
        );
    }

    if let Some(watcher) = poll_watcher {
        sync_watch_paths(
            watcher,
            &current_manifest.files,
            &next_manifest.files,
            RecursiveMode::NonRecursive,
            "config file",
        );
    }

    if let Ok(mut manifest) = manifest_state.write() {
        *manifest = next_manifest;
    }
}

/// Builds the effective WEB snapshot without changing live state.
fn prepare_effective_config(
    old_cfg: &ProxyConfig,
    new_cfg: &ProxyConfig,
) -> crate::error::Result<ProxyConfig> {
    new_cfg.validate()?;
    let mut applied_cfg = overlay_hot_fields(old_cfg, new_cfg);
    applied_cfg.validate_effective_web()?;
    applied_cfg.rebuild_runtime_web()?;
    Ok(applied_cfg)
}

/// Diffs and publishes a fully prepared configuration on the watcher owner task.
fn reload_config_with_resolver(
    prepared: (LoadedConfig, ProxyConfig),
    config_tx: &watch::Sender<Arc<ProxyConfig>>,
    log_tx: &watch::Sender<LogLevel>,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
    reload_state: &mut ReloadState,
    dns_resolver: Option<&crate::network::dns_overrides::GenerationDnsResolver>,
    refresh_quota_source: bool,
) -> Option<WatchManifest> {
    let (loaded, applied_cfg) = prepared;
    let LoadedConfig {
        config: new_cfg,
        source_files,
        source_contents: _,
        rendered_hash,
    } = loaded;
    let next_manifest = WatchManifest::from_source_files(&source_files);

    let old_cfg = config_tx.borrow().clone();
    let old_hot = HotFields::from_config(&old_cfg);
    let applied_hot = HotFields::from_config(&applied_cfg);
    let non_hot_changed = !config_equal(&applied_cfg, &new_cfg);
    let hot_changed =
        !config_equal(&old_cfg, &applied_cfg) || !old_cfg.web_decoy_endpoints_equal(&applied_cfg);

    if non_hot_changed {
        warn_non_hot_changes(&old_cfg, &new_cfg, non_hot_changed);
    }

    if !hot_changed {
        if refresh_quota_source {
            config_tx.send(Arc::new(applied_cfg)).ok();
        }
        reload_state.mark_applied(rendered_hash);
        return Some(next_manifest);
    }

    if old_hot.dns_overrides != applied_hot.dns_overrides
        && let Some(dns_resolver) = dns_resolver
        && let Err(e) = dns_resolver.apply_entries(&applied_hot.dns_overrides)
    {
        error!(
            "config reload: invalid network.dns_overrides: {}; keeping old config",
            e
        );
        return Some(next_manifest);
    }

    log_changes(
        &old_hot,
        &applied_hot,
        &applied_cfg,
        log_tx,
        detected_ip_v4,
        detected_ip_v6,
    );
    config_tx.send(Arc::new(applied_cfg)).ok();
    reload_state.mark_applied(rendered_hash);
    Some(next_manifest)
}

#[cfg(test)]
pub(super) fn reload_config(
    config_path: &PathBuf,
    config_tx: &watch::Sender<Arc<ProxyConfig>>,
    log_tx: &watch::Sender<LogLevel>,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
    reload_state: &mut ReloadState,
) -> Option<WatchManifest> {
    let loaded = ProxyConfig::load_with_metadata(config_path).ok()?;
    if reload_state.is_applied(loaded.rendered_hash) {
        return Some(WatchManifest::from_source_files(&loaded.source_files));
    }
    let applied = prepare_effective_config(&config_tx.borrow(), &loaded.config).ok()?;
    reload_config_with_resolver(
        (loaded, applied),
        config_tx,
        log_tx,
        detected_ip_v4,
        detected_ip_v6,
        reload_state,
        None,
        false,
    )
}

/// Spawn the hot-reload watcher task.
///
/// Uses `notify` (inotify on Linux) to detect file changes instantly.
/// SIGHUP is also handled on Unix as an additional manual trigger.
///
/// `detected_ip_v4` / `detected_ip_v6` are the IPs discovered during the
/// startup probe — used when generating proxy links for newly added users,
/// matching the same logic as the startup output.
/// The watcher releases its notify and signal resources when `cancellation` fires.
pub fn spawn_config_watcher(
    config_path: PathBuf,
    initial: Arc<ProxyConfig>,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
    cancellation: tokio_util::sync::CancellationToken,
    dns_resolver: Option<Arc<crate::network::dns_overrides::GenerationDnsResolver>>,
    mut activation: Option<watch::Receiver<bool>>,
    quota_mutation: Option<Arc<tokio::sync::Mutex<()>>>,
    quota_source_refresh: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
) -> (
    watch::Receiver<Arc<ProxyConfig>>,
    watch::Receiver<LogLevel>,
    impl std::future::Future<Output = ()> + Send + 'static,
) {
    let initial_level = initial.general.log_level.clone();
    let (config_tx, config_rx) = watch::channel(initial);
    let (log_tx, log_rx) = watch::channel(initial_level);

    let config_path = normalize_watch_path(&config_path);
    let task = async move {
        if let Some(activation) = activation.as_mut() {
            loop {
                if *activation.borrow_and_update() {
                    break;
                }
                tokio::select! {
                    result = activation.changed() => {
                        if result.is_err() {
                            return;
                        }
                    }
                    _ = cancellation.cancelled() => return,
                }
            }
        }
        let initial_loaded = preparation::read_source(&config_path).await;
        let initial_manifest = initial_loaded
            .as_ref()
            .map(|loaded| WatchManifest::from_source_files(&loaded.source_files))
            .unwrap_or_else(|| {
                WatchManifest::from_source_files(std::slice::from_ref(&config_path))
            });
        let initial_matches_disk = initial_loaded
            .as_ref()
            .is_some_and(|source| preparation::source_matches_active(&config_tx.borrow(), source));
        let initial_snapshot_hash = initial_loaded
            .as_ref()
            .filter(|_| initial_matches_disk)
            .map(|loaded| loaded.rendered_hash);
        let (notify_tx, mut notify_rx) = mpsc::channel::<()>(4);
        let manifest_state = Arc::new(StdRwLock::new(WatchManifest::default()));
        let mut reload_state = ReloadState::new(initial_snapshot_hash);

        let tx_inotify = notify_tx.clone();
        let manifest_for_inotify = manifest_state.clone();
        let mut inotify_watcher =
            match recommended_watcher(move |res: notify::Result<notify::Event>| {
                let Ok(event) = res else { return };
                if !matches!(
                    event.kind,
                    EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                ) {
                    return;
                }
                let is_our_file = manifest_for_inotify
                    .read()
                    .map(|manifest| manifest.matches_event_paths(&event.paths))
                    .unwrap_or(false);
                if is_our_file {
                    let _ = tx_inotify.try_send(());
                }
            }) {
                Ok(watcher) => Some(watcher),
                Err(e) => {
                    warn!("config watcher: inotify unavailable: {}", e);
                    None
                }
            };
        apply_watch_manifest(
            inotify_watcher.as_mut(),
            Option::<&mut notify::poll::PollWatcher>::None,
            &manifest_state,
            initial_manifest.clone(),
        );
        if inotify_watcher.is_some() {
            info!("config watcher: inotify active on {:?}", config_path);
        }

        let tx_poll = notify_tx.clone();
        let manifest_for_poll = manifest_state.clone();
        let mut poll_watcher = match notify::poll::PollWatcher::new(
            move |res: notify::Result<notify::Event>| {
                let Ok(event) = res else { return };
                if !matches!(
                    event.kind,
                    EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                ) {
                    return;
                }
                let is_our_file = manifest_for_poll
                    .read()
                    .map(|manifest| manifest.matches_event_paths(&event.paths))
                    .unwrap_or(false);
                if is_our_file {
                    let _ = tx_poll.try_send(());
                }
            },
            notify::Config::default()
                .with_poll_interval(Duration::from_secs(3))
                .with_compare_contents(true),
        ) {
            Ok(watcher) => Some(watcher),
            Err(e) => {
                warn!("config watcher: poll watcher unavailable: {}", e);
                None
            }
        };
        apply_watch_manifest(
            Option::<&mut notify::RecommendedWatcher>::None,
            poll_watcher.as_mut(),
            &manifest_state,
            initial_manifest.clone(),
        );
        if poll_watcher.is_some() {
            info!("config watcher: poll watcher active (Docker/NFS safe)");
        }
        if initial_loaded.is_some()
            && (!initial_matches_disk
                || quota_source_refresh
                    .as_ref()
                    .is_some_and(|refresh| refresh()))
        {
            let _ = notify_tx.try_send(());
        }

        #[cfg(unix)]
        let mut sighup = {
            use tokio::signal::unix::{SignalKind, signal};
            signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler")
        };

        loop {
            let mut force = false;
            #[cfg(unix)]
            tokio::select! {
                msg = notify_rx.recv() => {
                    if msg.is_none() { break; }
                }
                _ = sighup.recv() => {
                    force = true;
                    info!("SIGHUP received — reloading {:?}", config_path);
                }
                _ = cancellation.cancelled() => break,
            }
            #[cfg(not(unix))]
            tokio::select! {
                msg = notify_rx.recv() => {
                    if msg.is_none() { break; }
                }
                _ = cancellation.cancelled() => break,
            }

            // Debounce: drain extra events that arrive within a short quiet window.
            tokio::time::sleep(HOT_RELOAD_DEBOUNCE).await;
            while notify_rx.try_recv().is_ok() {}

            let mut next_manifest = preparation::reload(
                &config_path,
                &config_tx,
                &log_tx,
                detected_ip_v4,
                detected_ip_v6,
                &mut reload_state,
                dns_resolver.clone(),
                force,
                quota_mutation.as_ref(),
                quota_source_refresh.as_deref(),
            )
            .await;
            if next_manifest.is_none() {
                tokio::time::sleep(HOT_RELOAD_DEBOUNCE).await;
                while notify_rx.try_recv().is_ok() {}
                next_manifest = preparation::reload(
                    &config_path,
                    &config_tx,
                    &log_tx,
                    detected_ip_v4,
                    detected_ip_v6,
                    &mut reload_state,
                    dns_resolver.clone(),
                    force,
                    quota_mutation.as_ref(),
                    quota_source_refresh.as_deref(),
                )
                .await;
            }

            if let Some(next_manifest) = next_manifest {
                apply_watch_manifest(
                    inotify_watcher.as_mut(),
                    poll_watcher.as_mut(),
                    &manifest_state,
                    next_manifest,
                );
            }
        }
    };

    (config_rx, log_rx, task)
}

#[cfg(all(test, unix))]
mod path_tests {
    use std::os::unix::fs::symlink;

    use super::normalize_watch_path;

    #[test]
    fn watch_path_normalization_preserves_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.toml");
        let linked = dir.path().join("linked.toml");
        std::fs::write(&real, "").unwrap();
        symlink(&real, &linked).unwrap();

        assert_eq!(normalize_watch_path(&linked), linked);
    }
}

#[cfg(test)]
mod decoy_dns_tests;

#[cfg(test)]
mod quota_period_tests;
