//! Hot-reload: watches the config file via inotify (Linux) / FSEvents (macOS)
//! / ReadDirectoryChangesW (Windows) using the `notify` crate.
//! SIGHUP is also supported on Unix as an additional manual trigger.
//!
//! # What can be reloaded without restart
//!
//! | Section   | Field                         | Effect                            |
//! |-----------|-------------------------------|-----------------------------------|
//! | `general` | `log_level`                   | Filter updated via `log_level_tx` |
//! | `general` | `ad_tag`                      | Passed on next connection         |
//! | `general` | `middle_proxy_pool_size`      | Passed on next connection         |
//! | `general` | `me_keepalive_*`              | Passed on next connection         |
//! | `access`  | All user/quota fields         | Effective immediately             |
//!
//! Fields that require re-binding sockets (`server.port`, `censorship.*`,
//! `network.*`, `use_middle_proxy`) are **not** applied; a warning is emitted.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use notify::{EventKind, RecursiveMode, Watcher, recommended_watcher};
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

use crate::config::LogLevel;
use super::load::ProxyConfig;

// ── Hot fields ────────────────────────────────────────────────────────────────

/// Fields that are safe to swap without restarting listeners.
#[derive(Debug, Clone, PartialEq)]
pub struct HotFields {
    pub log_level:               LogLevel,
    pub ad_tag:                  Option<String>,
    pub middle_proxy_pool_size:  usize,
    pub me_keepalive_enabled:    bool,
    pub me_keepalive_interval_secs: u64,
    pub me_keepalive_jitter_secs:   u64,
    pub me_keepalive_payload_random: bool,
    pub access:                  crate::config::AccessConfig,
}

impl HotFields {
    pub fn from_config(cfg: &ProxyConfig) -> Self {
        Self {
            log_level:               cfg.general.log_level.clone(),
            ad_tag:                  cfg.general.ad_tag.clone(),
            middle_proxy_pool_size:  cfg.general.middle_proxy_pool_size,
            me_keepalive_enabled:    cfg.general.me_keepalive_enabled,
            me_keepalive_interval_secs: cfg.general.me_keepalive_interval_secs,
            me_keepalive_jitter_secs:   cfg.general.me_keepalive_jitter_secs,
            me_keepalive_payload_random: cfg.general.me_keepalive_payload_random,
            access:                  cfg.access.clone(),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Warn if any non-hot fields changed (require restart).
fn warn_non_hot_changes(old: &ProxyConfig, new: &ProxyConfig) {
    if old.server.port != new.server.port {
        warn!(
            "config reload: server.port changed ({} → {}); restart required",
            old.server.port, new.server.port
        );
    }
    if old.censorship.tls_domain != new.censorship.tls_domain {
        warn!(
            "config reload: censorship.tls_domain changed ('{}' → '{}'); restart required",
            old.censorship.tls_domain, new.censorship.tls_domain
        );
    }
    if old.network.ipv4 != new.network.ipv4 || old.network.ipv6 != new.network.ipv6 {
        warn!("config reload: network.ipv4/ipv6 changed; restart required");
    }
    if old.general.use_middle_proxy != new.general.use_middle_proxy {
        warn!("config reload: use_middle_proxy changed; restart required");
    }
}

/// Resolve the public host for link generation — mirrors the logic in main.rs.
///
/// Priority:
/// 1. `[general.links] public_host` — explicit override in config
/// 2. `detected_ip_v4` — from STUN/interface probe at startup
/// 3. `detected_ip_v6` — fallback
/// 4. `"UNKNOWN"` — warn the user to set `public_host`
fn resolve_link_host(
    cfg: &ProxyConfig,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
) -> String {
    if let Some(ref h) = cfg.general.links.public_host {
        return h.clone();
    }
    detected_ip_v4
        .or(detected_ip_v6)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| {
            warn!(
                "config reload: could not determine public IP for proxy links. \
                 Set [general.links] public_host in config."
            );
            "UNKNOWN".to_string()
        })
}

/// Print TG proxy links for a single user — mirrors print_proxy_links() in main.rs.
fn print_user_links(user: &str, secret: &str, host: &str, port: u16, cfg: &ProxyConfig) {
    info!(target: "telemt::links", "--- New user: {} ---", user);
    if cfg.general.modes.classic {
        info!(
            target: "telemt::links",
            "  Classic: tg://proxy?server={}&port={}&secret={}",
            host, port, secret
        );
    }
    if cfg.general.modes.secure {
        info!(
            target: "telemt::links",
            "  DD:      tg://proxy?server={}&port={}&secret=dd{}",
            host, port, secret
        );
    }
    if cfg.general.modes.tls {
        let mut domains = vec![cfg.censorship.tls_domain.clone()];
        for d in &cfg.censorship.tls_domains {
            if !domains.contains(d) {
                domains.push(d.clone());
            }
        }
        for domain in &domains {
            let domain_hex = hex::encode(domain.as_bytes());
            info!(
                target: "telemt::links",
                "  EE-TLS:  tg://proxy?server={}&port={}&secret=ee{}{}",
                host, port, secret, domain_hex
            );
        }
    }
    info!(target: "telemt::links", "--------------------");
}

/// Log all detected changes and emit TG links for new users.
fn log_changes(
    old_hot: &HotFields,
    new_hot: &HotFields,
    new_cfg: &ProxyConfig,
    log_tx: &watch::Sender<LogLevel>,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
) {
    if old_hot.log_level != new_hot.log_level {
        info!(
            "config reload: log_level: '{}' → '{}'",
            old_hot.log_level, new_hot.log_level
        );
        log_tx.send(new_hot.log_level.clone()).ok();
    }

    if old_hot.ad_tag != new_hot.ad_tag {
        info!(
            "config reload: ad_tag: {} → {}",
            old_hot.ad_tag.as_deref().unwrap_or("none"),
            new_hot.ad_tag.as_deref().unwrap_or("none"),
        );
    }

    if old_hot.middle_proxy_pool_size != new_hot.middle_proxy_pool_size {
        info!(
            "config reload: middle_proxy_pool_size: {} → {}",
            old_hot.middle_proxy_pool_size, new_hot.middle_proxy_pool_size,
        );
    }

    if old_hot.me_keepalive_enabled        != new_hot.me_keepalive_enabled
    || old_hot.me_keepalive_interval_secs  != new_hot.me_keepalive_interval_secs
    || old_hot.me_keepalive_jitter_secs    != new_hot.me_keepalive_jitter_secs
    || old_hot.me_keepalive_payload_random != new_hot.me_keepalive_payload_random
    {
        info!(
            "config reload: me_keepalive: enabled={} interval={}s jitter={}s random_payload={}",
            new_hot.me_keepalive_enabled,
            new_hot.me_keepalive_interval_secs,
            new_hot.me_keepalive_jitter_secs,
            new_hot.me_keepalive_payload_random,
        );
    }

    if old_hot.access.users != new_hot.access.users {
        let mut added: Vec<&String> = new_hot.access.users.keys()
            .filter(|u| !old_hot.access.users.contains_key(*u))
            .collect();
        added.sort();

        let mut removed: Vec<&String> = old_hot.access.users.keys()
            .filter(|u| !new_hot.access.users.contains_key(*u))
            .collect();
        removed.sort();

        let mut changed: Vec<&String> = new_hot.access.users.keys()
            .filter(|u| {
                old_hot.access.users.get(*u)
                    .map(|s| s != &new_hot.access.users[*u])
                    .unwrap_or(false)
            })
            .collect();
        changed.sort();

        if !added.is_empty() {
            info!(
                "config reload: users added: [{}]",
                added.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            );
            let host = resolve_link_host(new_cfg, detected_ip_v4, detected_ip_v6);
            let port = new_cfg.general.links.public_port.unwrap_or(new_cfg.server.port);
            for user in &added {
                if let Some(secret) = new_hot.access.users.get(*user) {
                    print_user_links(user, secret, &host, port, new_cfg);
                }
            }
        }
        if !removed.is_empty() {
            info!(
                "config reload: users removed: [{}]",
                removed.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            );
        }
        if !changed.is_empty() {
            info!(
                "config reload: users secret changed: [{}]",
                changed.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            );
        }
    }

    if old_hot.access.user_max_tcp_conns != new_hot.access.user_max_tcp_conns {
        info!(
            "config reload: user_max_tcp_conns updated ({} entries)",
            new_hot.access.user_max_tcp_conns.len()
        );
    }
    if old_hot.access.user_expirations != new_hot.access.user_expirations {
        info!(
            "config reload: user_expirations updated ({} entries)",
            new_hot.access.user_expirations.len()
        );
    }
    if old_hot.access.user_data_quota != new_hot.access.user_data_quota {
        info!(
            "config reload: user_data_quota updated ({} entries)",
            new_hot.access.user_data_quota.len()
        );
    }
    if old_hot.access.user_max_unique_ips != new_hot.access.user_max_unique_ips {
        info!(
            "config reload: user_max_unique_ips updated ({} entries)",
            new_hot.access.user_max_unique_ips.len()
        );
    }
}

/// Load config, validate, diff against current, and broadcast if changed.
fn reload_config(
    config_path: &PathBuf,
    config_tx: &watch::Sender<Arc<ProxyConfig>>,
    log_tx: &watch::Sender<LogLevel>,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
) {
    let new_cfg = match ProxyConfig::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("config reload: failed to parse {:?}: {}", config_path, e);
            return;
        }
    };

    if let Err(e) = new_cfg.validate() {
        error!("config reload: validation failed: {}; keeping old config", e);
        return;
    }

    let old_cfg = config_tx.borrow().clone();
    let old_hot = HotFields::from_config(&old_cfg);
    let new_hot = HotFields::from_config(&new_cfg);

    if old_hot == new_hot {
        return;
    }

    warn_non_hot_changes(&old_cfg, &new_cfg);
    log_changes(&old_hot, &new_hot, &new_cfg, log_tx, detected_ip_v4, detected_ip_v6);
    config_tx.send(Arc::new(new_cfg)).ok();
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Spawn the hot-reload watcher task.
///
/// Uses `notify` (inotify on Linux) to detect file changes instantly.
/// SIGHUP is also handled on Unix as an additional manual trigger.
///
/// `detected_ip_v4` / `detected_ip_v6` are the IPs discovered during the
/// startup probe — used when generating proxy links for newly added users,
/// matching the same logic as the startup output.
pub fn spawn_config_watcher(
    config_path: PathBuf,
    initial: Arc<ProxyConfig>,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
) -> (watch::Receiver<Arc<ProxyConfig>>, watch::Receiver<LogLevel>) {
    let initial_level = initial.general.log_level.clone();
    let (config_tx, config_rx) = watch::channel(initial);
    let (log_tx, log_rx)       = watch::channel(initial_level);

    // Bridge: sync notify callback → async task via mpsc.
    let (notify_tx, mut notify_rx) = mpsc::channel::<()>(4);

    // Canonicalize the config path so it matches what notify returns in events
    // (notify always gives absolute paths, but config_path may be relative).
    let config_path = match config_path.canonicalize() {
        Ok(p) => p,
        Err(_) => config_path.to_path_buf(), // file doesn't exist yet, use as-is
    };

    // Watch the parent directory rather than the file itself, because many
    // editors (vim, nano, systemd-sysusers) write via rename, which would
    // cause inotify to lose track of the original inode.
    let watch_dir = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();

    let config_file = config_path.clone();
    let tx_clone    = notify_tx.clone();

    let watcher_result = recommended_watcher(move |res: notify::Result<notify::Event>| {
        let Ok(event) = res else { return };

        let is_our_file = event.paths.iter().any(|p| p == &config_file);
        if !is_our_file {
            return;
        }
        let relevant = matches!(
            event.kind,
            EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
        );
        if relevant {
            let _ = tx_clone.try_send(());
        }
    });

    match watcher_result {
        Ok(mut watcher) => {
            match watcher.watch(&watch_dir, RecursiveMode::NonRecursive) {
                Ok(()) => info!("config watcher: watching {:?} via inotify", config_path),
                Err(e) => warn!(
                    "config watcher: failed to watch {:?}: {}; use SIGHUP to reload",
                    watch_dir, e
                ),
            }

            tokio::spawn(async move {
                let _watcher = watcher; // keep alive

                #[cfg(unix)]
                let mut sighup = {
                    use tokio::signal::unix::{SignalKind, signal};
                    signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler")
                };

                loop {
                    #[cfg(unix)]
                    tokio::select! {
                        msg = notify_rx.recv() => {
                            if msg.is_none() { break; }
                        }
                        _ = sighup.recv() => {
                            info!("SIGHUP received — reloading {:?}", config_path);
                        }
                    }
                    #[cfg(not(unix))]
                    if notify_rx.recv().await.is_none() { break; }

                    // Debounce: drain extra events fired within 50ms.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    while notify_rx.try_recv().is_ok() {}

                    reload_config(
                        &config_path,
                        &config_tx,
                        &log_tx,
                        detected_ip_v4,
                        detected_ip_v6,
                    );
                }
            });
        }
        Err(e) => {
            warn!(
                "config watcher: inotify unavailable ({}); only SIGHUP will trigger reload",
                e
            );
            // Fall back to SIGHUP-only.
            tokio::spawn(async move {
                #[cfg(unix)]
                {
                    use tokio::signal::unix::{SignalKind, signal};
                    let mut sighup = signal(SignalKind::hangup())
                        .expect("Failed to register SIGHUP handler");
                    loop {
                        sighup.recv().await;
                        info!("SIGHUP received — reloading {:?}", config_path);
                        reload_config(
                            &config_path,
                            &config_tx,
                            &log_tx,
                            detected_ip_v4,
                            detected_ip_v6,
                        );
                    }
                }
                #[cfg(not(unix))]
                let _ = (config_tx, log_tx, config_path);
            });
        }
    }

    (config_rx, log_rx)
}
