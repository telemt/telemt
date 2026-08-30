use super::*;

fn sample_config() -> ProxyConfig {
    ProxyConfig::default()
}

fn write_reload_config(path: &Path, ad_tag: Option<&str>, server_port: Option<u16>) {
    let mut config = String::from(
        r#"
                [censorship]
                tls_domain = "example.com"

                [access.users]
                user = "00000000000000000000000000000000"
            "#,
    );

    if ad_tag.is_some() {
        config.push_str("\n[general]\n");
        if let Some(tag) = ad_tag {
            config.push_str(&format!("ad_tag = \"{tag}\"\n"));
        }
    }

    if let Some(port) = server_port {
        config.push_str("\n[server]\n");
        config.push_str(&format!("port = {port}\n"));
    }

    std::fs::write(path, config).unwrap();
}

fn write_web_reload_config(path: &Path, carriers: &str, carrier_learning: bool) {
    let config = format!(
        r#"
                [censorship]
                tls_domain = "example.com"

                [access.users]
                user = "00000000000000000000000000000000"

                [web]
                carriers = {carriers}
                carrier_learning = {carrier_learning}
            "#,
    );
    std::fs::write(path, config).unwrap();
}

fn temp_config_path(prefix: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}_{nonce}.toml"))
}

#[test]
fn overlay_applies_hot_and_preserves_non_hot() {
    let old = sample_config();
    let mut new = old.clone();
    new.general.hardswap = !old.general.hardswap;
    new.server.port = old.server.port.saturating_add(1);

    let applied = overlay_hot_fields(&old, &new);
    assert_eq!(applied.general.hardswap, new.general.hardswap);
    assert_eq!(applied.server.port, old.server.port);
}

#[test]
fn non_hot_only_change_does_not_change_hot_snapshot() {
    let old = sample_config();
    let mut new = old.clone();
    new.server.port = old.server.port.saturating_add(1);

    let applied = overlay_hot_fields(&old, &new);
    assert_eq!(
        HotFields::from_config(&old),
        HotFields::from_config(&applied)
    );
    assert_eq!(applied.server.port, old.server.port);
}

#[test]
fn bind_stale_mode_is_hot() {
    let old = sample_config();
    let mut new = old.clone();
    new.general.me_bind_stale_mode = match old.general.me_bind_stale_mode {
        MeBindStaleMode::Never => MeBindStaleMode::Ttl,
        MeBindStaleMode::Ttl => MeBindStaleMode::Always,
        MeBindStaleMode::Always => MeBindStaleMode::Never,
    };

    let applied = overlay_hot_fields(&old, &new);
    assert_eq!(
        applied.general.me_bind_stale_mode,
        new.general.me_bind_stale_mode
    );
    assert_ne!(
        HotFields::from_config(&old),
        HotFields::from_config(&applied)
    );
}

#[test]
fn web_debug_policy_is_hot_while_debug_capacity_is_process_owned() {
    let old = sample_config();
    let mut new = old.clone();
    new.web.debug.enabled = true;
    new.web.debug.default_window_secs = 60;
    new.web.limits.debug_records_capacity += 1;

    let applied = overlay_hot_fields(&old, &new);
    assert!(applied.web.debug.enabled);
    assert_eq!(applied.web.debug.default_window_secs, 60);
    assert_eq!(
        applied.web.limits.debug_records_capacity,
        old.web.limits.debug_records_capacity
    );
    assert_ne!(
        HotFields::from_config(&old),
        HotFields::from_config(&applied)
    );
}

#[test]
fn web_debug_prefix_requiring_deferred_capacity_is_not_hot_applied() {
    let old = sample_config();
    let mut new = old.clone();
    new.web.limits.max_body_bytes = 4 * 1024 * 1024;
    new.web.debug.body_prefix_bytes = 3 * 1024 * 1024;

    let applied = overlay_hot_fields(&old, &new);
    assert_eq!(
        applied.web.limits.max_body_bytes,
        old.web.limits.max_body_bytes
    );
    assert_eq!(
        applied.web.debug.body_prefix_bytes,
        old.web.debug.body_prefix_bytes
    );
}

#[test]
fn keepalive_is_not_hot() {
    let old = sample_config();
    let mut new = old.clone();
    new.general.me_keepalive_interval_secs = old.general.me_keepalive_interval_secs + 5;

    let applied = overlay_hot_fields(&old, &new);
    assert_eq!(
        applied.general.me_keepalive_interval_secs,
        old.general.me_keepalive_interval_secs
    );
    assert_eq!(
        HotFields::from_config(&old),
        HotFields::from_config(&applied)
    );
}

#[test]
fn mixed_hot_and_non_hot_change_applies_only_hot_subset() {
    let old = sample_config();
    let mut new = old.clone();
    new.general.hardswap = !old.general.hardswap;
    new.general.use_middle_proxy = !old.general.use_middle_proxy;

    let applied = overlay_hot_fields(&old, &new);
    assert_eq!(applied.general.hardswap, new.general.hardswap);
    assert_eq!(
        applied.general.use_middle_proxy,
        old.general.use_middle_proxy
    );
    assert!(!config_equal(&applied, &new));
}

#[test]
fn listener_synlimit_fields_are_process_owned() {
    let mut old = sample_config();
    old.server.listeners.push(ListenerConfig {
        ip: "0.0.0.0".parse().unwrap(),
        transport: crate::config::ListenerTransport::Mtproxy,
        port: Some(443),
        client_mss: None,
        synlimit: SynLimitMode::Iptables,
        synlimit_seconds: 60,
        synlimit_hitcount: 48,
        synlimit_burst: 1,
        synlimit_ios_seconds: 1,
        synlimit_ios_hitcount: 12,
        synlimit_ios_burst: 24,
        synlimit_hashlimit_expire_ms: 60_000,
        synlimit_hashlimit_size: 32_768,
        announce: None,
        announce_ip: None,
        proxy_protocol: None,
        reuse_allow: false,
        web_client_ip_source: crate::config::WebClientIpSource::XForwardedFor,
        web_trusted_proxy_cidrs: Vec::new(),
    });
    let mut new = old.clone();
    new.server.port = 8443;
    new.server.listeners[0].synlimit_seconds = 120;
    new.server.listeners[0].synlimit_hitcount = 96;
    new.server.listeners[0].synlimit_burst = 2;
    new.server.listeners[0].synlimit_ios_seconds = 2;
    new.server.listeners[0].synlimit_ios_hitcount = 18;
    new.server.listeners[0].synlimit_ios_burst = 36;
    new.server.listeners[0].synlimit_hashlimit_expire_ms = 90_000;
    new.server.listeners[0].synlimit_hashlimit_size = 65_536;

    let applied = overlay_hot_fields(&old, &new);
    let listener = &applied.server.listeners[0];
    assert_eq!(applied.server.port, old.server.port);
    assert_eq!(
        listener.synlimit_seconds,
        old.server.listeners[0].synlimit_seconds
    );
    assert_eq!(
        listener.synlimit_hitcount,
        old.server.listeners[0].synlimit_hitcount
    );
    assert_eq!(
        listener.synlimit_burst,
        old.server.listeners[0].synlimit_burst
    );
    assert_eq!(
        listener.synlimit_hashlimit_size,
        old.server.listeners[0].synlimit_hashlimit_size
    );
    assert!(classify_config_changes(&old, &new).restart_required);
}

#[test]
fn reload_applies_hot_change_on_first_observed_snapshot() {
    let initial_tag = "11111111111111111111111111111111";
    let final_tag = "22222222222222222222222222222222";
    let path = temp_config_path("telemt_hot_reload_stable");

    write_reload_config(&path, Some(initial_tag), None);
    let initial_cfg = Arc::new(ProxyConfig::load(&path).unwrap());
    let initial_hash = ProxyConfig::load_with_metadata(&path)
        .unwrap()
        .rendered_hash;
    let (config_tx, _config_rx) = watch::channel(initial_cfg.clone());
    let (log_tx, _log_rx) = watch::channel(initial_cfg.general.log_level.clone());
    let mut reload_state = ReloadState::new(Some(initial_hash));

    write_reload_config(&path, Some(final_tag), None);
    reload_config(&path, &config_tx, &log_tx, None, None, &mut reload_state).unwrap();
    assert_eq!(
        config_tx.borrow().general.ad_tag.as_deref(),
        Some(final_tag)
    );

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn candidate_watcher_waits_for_activation_and_reconciles_disk() {
    let initial_tag = "10101010101010101010101010101010";
    let disk_tag = "20202020202020202020202020202020";
    let path = temp_config_path("telemt_hot_reload_activation_gate");
    write_reload_config(&path, Some(initial_tag), None);
    let initial = Arc::new(ProxyConfig::load(&path).unwrap());
    write_reload_config(&path, Some(disk_tag), None);
    let cancellation = tokio_util::sync::CancellationToken::new();
    let (activation_tx, activation_rx) = watch::channel(false);
    let (mut config_rx, _log_rx, watcher) = spawn_config_watcher(
        path.clone(),
        initial,
        None,
        None,
        cancellation.clone(),
        None,
        Some(activation_rx),
    );
    let watcher = tokio::spawn(watcher);

    tokio::task::yield_now().await;
    assert_eq!(
        config_rx.borrow().general.ad_tag.as_deref(),
        Some(initial_tag)
    );
    activation_tx.send_replace(true);
    tokio::time::timeout(Duration::from_secs(2), config_rx.changed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        config_rx.borrow_and_update().general.ad_tag.as_deref(),
        Some(disk_tag)
    );

    cancellation.cancel();
    watcher.await.unwrap();
    let _ = std::fs::remove_file(path);
}

#[test]
fn reload_keeps_hot_apply_when_non_hot_fields_change() {
    let initial_tag = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let final_tag = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let path = temp_config_path("telemt_hot_reload_mixed");

    write_reload_config(&path, Some(initial_tag), None);
    let initial_cfg = Arc::new(ProxyConfig::load(&path).unwrap());
    let initial_hash = ProxyConfig::load_with_metadata(&path)
        .unwrap()
        .rendered_hash;
    let (config_tx, _config_rx) = watch::channel(initial_cfg.clone());
    let (log_tx, _log_rx) = watch::channel(initial_cfg.general.log_level.clone());
    let mut reload_state = ReloadState::new(Some(initial_hash));

    write_reload_config(&path, Some(final_tag), Some(initial_cfg.server.port + 1));
    reload_config(&path, &config_tx, &log_tx, None, None, &mut reload_state).unwrap();

    let applied = config_tx.borrow().clone();
    assert_eq!(applied.general.ad_tag.as_deref(), Some(final_tag));
    assert_eq!(applied.server.port, initial_cfg.server.port);

    let _ = std::fs::remove_file(path);
}

#[test]
fn reload_publishes_web_negotiation_policy_outside_hot_field_reporting() {
    let path = temp_config_path("telemt_web_negotiation_reload");

    write_web_reload_config(&path, "false", true);
    let initial_cfg = Arc::new(ProxyConfig::load(&path).unwrap());
    let initial_hash = ProxyConfig::load_with_metadata(&path)
        .unwrap()
        .rendered_hash;
    let (config_tx, _config_rx) = watch::channel(initial_cfg.clone());
    let (log_tx, _log_rx) = watch::channel(initial_cfg.general.log_level.clone());
    let mut reload_state = ReloadState::new(Some(initial_hash));

    write_web_reload_config(&path, "[\"websocket\", \"https\"]", false);
    reload_config(&path, &config_tx, &log_tx, None, None, &mut reload_state).unwrap();

    let applied = config_tx.borrow().clone();
    assert!(applied.web.carrier_negotiation_enabled());
    assert!(!applied.web.carrier_learning);

    let _ = std::fs::remove_file(path);
}

#[test]
fn classify_sni_change_requires_restart() {
    // censorship.* is not in overlay_hot_fields -> restart.
    let old = ProxyConfig::default();
    let mut new = ProxyConfig::default();
    new.censorship.tls_domain = "front.example".to_string();

    let class = classify_config_changes(&old, &new);
    assert!(class.restart_required);
    assert!(class.changed.iter().any(|c| c == "censorship"));
}

#[test]
fn classify_dns_overrides_change_is_hot() {
    // network.dns_overrides IS in overlay_hot_fields -> no restart.
    let old = ProxyConfig::default();
    let mut new = ProxyConfig::default();
    new.network.dns_overrides.push("1.1.1.1".to_string());

    let class = classify_config_changes(&old, &new);
    assert!(!class.restart_required);
    assert!(class.changed.iter().any(|c| c == "network"));
}

#[test]
fn classify_timeouts_change_requires_restart() {
    // timeouts.* is NOT in overlay_hot_fields -> restart.
    let old = ProxyConfig::default();
    let mut new = ProxyConfig::default();
    new.timeouts.client_handshake = old.timeouts.client_handshake + 1;

    let class = classify_config_changes(&old, &new);
    assert!(class.restart_required);
}

#[test]
fn reload_recovers_after_parse_error_on_next_attempt() {
    let initial_tag = "cccccccccccccccccccccccccccccccc";
    let final_tag = "dddddddddddddddddddddddddddddddd";
    let path = temp_config_path("telemt_hot_reload_parse_recovery");

    write_reload_config(&path, Some(initial_tag), None);
    let initial_cfg = Arc::new(ProxyConfig::load(&path).unwrap());
    let initial_hash = ProxyConfig::load_with_metadata(&path)
        .unwrap()
        .rendered_hash;
    let (config_tx, _config_rx) = watch::channel(initial_cfg.clone());
    let (log_tx, _log_rx) = watch::channel(initial_cfg.general.log_level.clone());
    let mut reload_state = ReloadState::new(Some(initial_hash));

    std::fs::write(&path, "[access.users\nuser = \"broken\"\n").unwrap();
    assert!(reload_config(&path, &config_tx, &log_tx, None, None, &mut reload_state).is_none());
    assert_eq!(
        config_tx.borrow().general.ad_tag.as_deref(),
        Some(initial_tag)
    );

    write_reload_config(&path, Some(final_tag), None);
    reload_config(&path, &config_tx, &log_tx, None, None, &mut reload_state).unwrap();
    assert_eq!(
        config_tx.borrow().general.ad_tag.as_deref(),
        Some(final_tag)
    );

    let _ = std::fs::remove_file(path);
}
