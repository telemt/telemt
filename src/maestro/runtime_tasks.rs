use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::reload;

use crate::config::hot_reload::spawn_config_watcher;
use crate::config::{LogLevel, ProxyConfig};
use crate::crypto::SecureRandom;
use crate::ip_tracker::UserIpTracker;
use crate::metrics;
use crate::network::probe::NetworkProbe;
use crate::startup::{
    COMPONENT_CONFIG_WATCHER_START, COMPONENT_METRICS_START, COMPONENT_RUNTIME_READY,
    StartupTracker,
};
use crate::stats::beobachten::BeobachtenStore;
use crate::stats::telemetry::TelemetryPolicy;
use crate::stats::{ReplayChecker, Stats};
use crate::transport::UpstreamManager;
use crate::transport::middle_proxy::{MePool, MeReinitTrigger};

use super::helpers::write_beobachten_snapshot;

pub(crate) struct RuntimeWatches {
    pub(crate) config_rx: watch::Receiver<Arc<ProxyConfig>>,
    pub(crate) log_level_rx: watch::Receiver<LogLevel>,
    pub(crate) detected_ip_v4: Option<IpAddr>,
    pub(crate) detected_ip_v6: Option<IpAddr>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_runtime_tasks(
    config: &Arc<ProxyConfig>,
    config_path: &Path,
    probe: &NetworkProbe,
    prefer_ipv6: bool,
    decision_ipv4_dc: bool,
    decision_ipv6_dc: bool,
    startup_tracker: &Arc<StartupTracker>,
    stats: Arc<Stats>,
    upstream_manager: Arc<UpstreamManager>,
    replay_checker: Arc<ReplayChecker>,
    me_pool: Option<Arc<MePool>>,
    rng: Arc<SecureRandom>,
    ip_tracker: Arc<UserIpTracker>,
    beobachten: Arc<BeobachtenStore>,
    api_config_tx: watch::Sender<Arc<ProxyConfig>>,
    me_pool_for_policy: Option<Arc<MePool>>,
) -> RuntimeWatches {
    let um_clone = upstream_manager.clone();
    let dc_overrides_for_health = config.dc_overrides.clone();
    tokio::spawn(async move {
        um_clone
            .run_health_checks(
                prefer_ipv6,
                decision_ipv4_dc,
                decision_ipv6_dc,
                dc_overrides_for_health,
            )
            .await;
    });

    let rc_clone = replay_checker.clone();
    tokio::spawn(async move {
        rc_clone.run_periodic_cleanup().await;
    });

    let detected_ip_v4: Option<IpAddr> = probe.detected_ipv4.map(IpAddr::V4);
    let detected_ip_v6: Option<IpAddr> = probe.detected_ipv6.map(IpAddr::V6);
    debug!(
        "Detected IPs: v4={:?} v6={:?}",
        detected_ip_v4, detected_ip_v6
    );

    startup_tracker
        .start_component(
            COMPONENT_CONFIG_WATCHER_START,
            Some("spawn config hot-reload watcher".to_string()),
        )
        .await;
    let (config_rx, log_level_rx): (watch::Receiver<Arc<ProxyConfig>>, watch::Receiver<LogLevel>) =
        spawn_config_watcher(
            config_path.to_path_buf(),
            config.clone(),
            detected_ip_v4,
            detected_ip_v6,
        );
    startup_tracker
        .complete_component(
            COMPONENT_CONFIG_WATCHER_START,
            Some("config hot-reload watcher started".to_string()),
        )
        .await;
    let mut config_rx_api_bridge = config_rx.clone();
    let api_config_tx_bridge = api_config_tx.clone();
    tokio::spawn(async move {
        loop {
            if config_rx_api_bridge.changed().await.is_err() {
                break;
            }
            let cfg = config_rx_api_bridge.borrow_and_update().clone();
            api_config_tx_bridge.send_replace(cfg);
        }
    });

    let stats_policy = stats.clone();
    let mut config_rx_policy = config_rx.clone();
    tokio::spawn(async move {
        loop {
            if config_rx_policy.changed().await.is_err() {
                break;
            }
            let cfg = config_rx_policy.borrow_and_update().clone();
            stats_policy
                .apply_telemetry_policy(TelemetryPolicy::from_config(&cfg.general.telemetry));
            if let Some(pool) = &me_pool_for_policy {
                pool.update_runtime_transport_policy(
                    cfg.general.me_socks_kdf_policy,
                    cfg.general.me_route_backpressure_base_timeout_ms,
                    cfg.general.me_route_backpressure_high_timeout_ms,
                    cfg.general.me_route_backpressure_high_watermark_pct,
                    cfg.general.me_reader_route_data_wait_ms,
                );
            }
        }
    });

    let ip_tracker_policy = ip_tracker.clone();
    let mut config_rx_ip_limits = config_rx.clone();
    tokio::spawn(async move {
        let mut prev_limits = config_rx_ip_limits
            .borrow()
            .access
            .user_max_unique_ips
            .clone();
        let mut prev_global_each = config_rx_ip_limits
            .borrow()
            .access
            .user_max_unique_ips_global_each;
        let mut prev_mode = config_rx_ip_limits.borrow().access.user_max_unique_ips_mode;
        let mut prev_window = config_rx_ip_limits
            .borrow()
            .access
            .user_max_unique_ips_window_secs;

        loop {
            if config_rx_ip_limits.changed().await.is_err() {
                break;
            }
            let cfg = config_rx_ip_limits.borrow_and_update().clone();

            if prev_limits != cfg.access.user_max_unique_ips
                || prev_global_each != cfg.access.user_max_unique_ips_global_each
            {
                ip_tracker_policy
                    .load_limits(
                        cfg.access.user_max_unique_ips_global_each,
                        &cfg.access.user_max_unique_ips,
                    )
                    .await;
                prev_limits = cfg.access.user_max_unique_ips.clone();
                prev_global_each = cfg.access.user_max_unique_ips_global_each;
            }

            if prev_mode != cfg.access.user_max_unique_ips_mode
                || prev_window != cfg.access.user_max_unique_ips_window_secs
            {
                ip_tracker_policy
                    .set_limit_policy(
                        cfg.access.user_max_unique_ips_mode,
                        cfg.access.user_max_unique_ips_window_secs,
                    )
                    .await;
                prev_mode = cfg.access.user_max_unique_ips_mode;
                prev_window = cfg.access.user_max_unique_ips_window_secs;
            }
        }
    });

    let beobachten_writer = beobachten.clone();
    let config_rx_beobachten = config_rx.clone();
    tokio::spawn(async move {
        loop {
            let cfg = config_rx_beobachten.borrow().clone();
            let sleep_secs = cfg.general.beobachten_flush_secs.max(1);

            if cfg.general.beobachten {
                let ttl = std::time::Duration::from_secs(
                    cfg.general.beobachten_minutes.saturating_mul(60),
                );
                let path = cfg.general.beobachten_file.clone();
                let snapshot = beobachten_writer.snapshot_text(ttl);
                if let Err(e) = write_beobachten_snapshot(&path, &snapshot).await {
                    warn!(error = %e, path = %path, "Failed to flush beobachten snapshot");
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(sleep_secs)).await;
        }
    });

    if let Some(pool) = me_pool {
        let reinit_trigger_capacity = config.general.me_reinit_trigger_channel.max(1);
        let (reinit_tx, reinit_rx) = mpsc::channel::<MeReinitTrigger>(reinit_trigger_capacity);

        let pool_clone_sched = pool.clone();
        let rng_clone_sched = rng.clone();
        let config_rx_clone_sched = config_rx.clone();
        tokio::spawn(async move {
            crate::transport::middle_proxy::me_reinit_scheduler(
                pool_clone_sched,
                rng_clone_sched,
                config_rx_clone_sched,
                reinit_rx,
            )
            .await;
        });

        let pool_clone = pool.clone();
        let config_rx_clone = config_rx.clone();
        let reinit_tx_updater = reinit_tx.clone();
        tokio::spawn(async move {
            crate::transport::middle_proxy::me_config_updater(
                pool_clone,
                config_rx_clone,
                reinit_tx_updater,
            )
            .await;
        });

        let config_rx_clone_rot = config_rx.clone();
        let reinit_tx_rotation = reinit_tx.clone();
        tokio::spawn(async move {
            crate::transport::middle_proxy::me_rotation_task(
                config_rx_clone_rot,
                reinit_tx_rotation,
            )
            .await;
        });
    }

    RuntimeWatches {
        config_rx,
        log_level_rx,
        detected_ip_v4,
        detected_ip_v6,
    }
}

pub(crate) async fn apply_runtime_log_filter(
    has_rust_log: bool,
    effective_log_level: &LogLevel,
    filter_handle: reload::Handle<EnvFilter, tracing_subscriber::Registry>,
    mut log_level_rx: watch::Receiver<LogLevel>,
) {
    let runtime_filter = if has_rust_log {
        EnvFilter::from_default_env()
    } else if matches!(effective_log_level, LogLevel::Silent) {
        EnvFilter::new("warn,telemt::links=info")
    } else {
        EnvFilter::new(effective_log_level.to_filter_str())
    };
    filter_handle
        .reload(runtime_filter)
        .expect("Failed to switch log filter");

    tokio::spawn(async move {
        loop {
            if log_level_rx.changed().await.is_err() {
                break;
            }
            let level = log_level_rx.borrow_and_update().clone();
            let new_filter = tracing_subscriber::EnvFilter::new(level.to_filter_str());
            if let Err(e) = filter_handle.reload(new_filter) {
                tracing::error!("config reload: failed to update log filter: {}", e);
            }
        }
    });
}

pub(crate) async fn spawn_metrics_if_configured(
    config: &Arc<ProxyConfig>,
    startup_tracker: &Arc<StartupTracker>,
    stats: Arc<Stats>,
    beobachten: Arc<BeobachtenStore>,
    ip_tracker: Arc<UserIpTracker>,
    config_rx: watch::Receiver<Arc<ProxyConfig>>,
) {
    // metrics_listen takes precedence; fall back to metrics_port for backward compat.
    let metrics_target: Option<(u16, Option<String>)> =
        if let Some(ref listen) = config.server.metrics_listen {
            match listen.parse::<std::net::SocketAddr>() {
                Ok(addr) => Some((addr.port(), Some(listen.clone()))),
                Err(e) => {
                    startup_tracker
                        .skip_component(
                            COMPONENT_METRICS_START,
                            Some(format!("invalid metrics_listen \"{}\": {}", listen, e)),
                        )
                        .await;
                    None
                }
            }
        } else {
            config.server.metrics_port.map(|p| (p, None))
        };

    if let Some((port, listen)) = metrics_target {
        let fallback_label = format!("port {}", port);
        let label = listen.as_deref().unwrap_or(&fallback_label);
        startup_tracker
            .start_component(
                COMPONENT_METRICS_START,
                Some(format!("spawn metrics endpoint on {}", label)),
            )
            .await;
        let stats = stats.clone();
        let beobachten = beobachten.clone();
        let config_rx_metrics = config_rx.clone();
        let ip_tracker_metrics = ip_tracker.clone();
        let whitelist = config.server.metrics_whitelist.clone();
        tokio::spawn(async move {
            metrics::serve(
                port,
                listen,
                stats,
                beobachten,
                ip_tracker_metrics,
                config_rx_metrics,
                whitelist,
            )
            .await;
        });
        startup_tracker
            .complete_component(
                COMPONENT_METRICS_START,
                Some("metrics task spawned".to_string()),
            )
            .await;
    } else if config.server.metrics_listen.is_none() {
        startup_tracker
            .skip_component(
                COMPONENT_METRICS_START,
                Some("server.metrics_port is not configured".to_string()),
            )
            .await;
    }
}

pub(crate) async fn mark_runtime_ready(startup_tracker: &Arc<StartupTracker>) {
    startup_tracker
        .complete_component(
            COMPONENT_RUNTIME_READY,
            Some("startup pipeline is fully initialized".to_string()),
        )
        .await;
    startup_tracker.mark_ready().await;
}
