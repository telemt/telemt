use super::*;

/// Restart-only differences must not enqueue another DNS preparation after activation.
pub(super) fn source_matches_active(
    active: &ProxyConfig,
    source: &crate::config::ParsedConfigSource,
) -> bool {
    config_equal(active, &overlay_hot_fields(active, &source.config))
}

/// Reads only source state; watcher initialization and unchanged events never need DNS.
pub(super) async fn read_source(path: &PathBuf) -> Option<crate::config::ParsedConfigSource> {
    let path = path.clone();
    match tokio::task::spawn_blocking(move || ProxyConfig::parse_source(path)).await {
        Ok(Ok(source)) => Some(source),
        Ok(Err(error)) => {
            error!("config reload: failed to parse: {}", error);
            None
        }
        Err(error) => {
            error!("config reload: source reader failed: {}", error);
            None
        }
    }
}

/// Prepares fresh evidence only for changed sources or an explicit reload request.
pub(super) async fn reload(
    path: &PathBuf,
    config_tx: &watch::Sender<Arc<ProxyConfig>>,
    log_tx: &watch::Sender<LogLevel>,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
    reload_state: &mut ReloadState,
    dns_resolver: Option<Arc<crate::network::dns_overrides::GenerationDnsResolver>>,
    force: bool,
    quota_mutation: Option<&Arc<tokio::sync::Mutex<()>>>,
    quota_source_refresh: Option<&(dyn Fn() -> bool + Send + Sync)>,
) -> Option<WatchManifest> {
    // Serialize source acquisition with API lifecycle commits, then release before DNS.
    // The source timestamp fences any later mutation during asynchronous preparation.
    let guard = match quota_mutation {
        Some(gate) => Some(gate.lock().await),
        None => None,
    };
    let source = read_source(path).await?;
    let manifest = WatchManifest::from_source_files(&source.source_files);
    // A new file edit can restore the exact pre-creation bytes. Refresh only source
    // evidence for fenced accounts, retaining prepared DNS and immutable WEB state.
    if !force
        && quota_source_refresh.is_some_and(|refresh| refresh())
        && source_matches_active(&config_tx.borrow(), &source)
    {
        let mut refreshed = (**config_tx.borrow()).clone();
        refreshed.quota_source_read_at = source.config.quota_source_read_at;
        config_tx.send(Arc::new(refreshed)).ok();
        reload_state.mark_applied(source.rendered_hash);
        return Some(manifest);
    }
    drop(guard);
    if !force && reload_state.is_applied(source.rendered_hash) {
        return Some(manifest);
    }
    let loaded = match source.prepare().await {
        Ok(loaded) => loaded,
        Err(error) => {
            error!(
                "config reload: preparation failed: {}; keeping old config",
                error
            );
            return Some(manifest);
        }
    };
    let old = config_tx.borrow().clone();
    // Static-site reconstruction after the listener overlay must not block Tokio workers.
    // The worker only builds data: cancellation cannot leave a detached publisher behind.
    let result = tokio::task::spawn_blocking(move || {
        prepare_effective_config(&old, &loaded.config).map(|applied| (loaded, applied))
    })
    .await;
    match result {
        Ok(Ok(prepared)) => reload_config_with_resolver(
            prepared,
            config_tx,
            log_tx,
            detected_ip_v4,
            detected_ip_v6,
            reload_state,
            dns_resolver.as_deref(),
            quota_source_refresh.is_some_and(|refresh| refresh()),
        ),
        Ok(Err(error)) => {
            error!(
                "config reload: effective WEB validation failed: {}; keeping old config",
                error
            );
            Some(manifest)
        }
        Err(error) => {
            error!(
                "config reload: runtime builder failed: {}; keeping old config",
                error
            );
            Some(manifest)
        }
    }
}
