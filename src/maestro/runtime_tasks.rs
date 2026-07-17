use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Registry;
use tracing_subscriber::reload;

use crate::config::hot_reload::spawn_config_watcher;
use crate::config::{LogLevel, ProxyConfig};
use crate::crypto::SecureRandom;
use crate::ip_tracker::UserIpTracker;
use crate::metrics;
use crate::network::probe::NetworkProbe;
use crate::proxy::shared_state::ProxySharedState;
use crate::startup::{
    COMPONENT_CONFIG_WATCHER_START, COMPONENT_METRICS_START, COMPONENT_RUNTIME_READY,
    StartupTracker,
};
use crate::stats::beobachten::BeobachtenStore;
use crate::stats::telemetry::TelemetryPolicy;
use crate::stats::{ReplayChecker, Stats};
use crate::transport::UpstreamManager;
use crate::transport::middle_proxy::{MePool, MeReinitTrigger};

use super::generation::RuntimeGeneration;
use super::generation::RuntimeTaskScope;
use super::helpers::write_beobachten_snapshot;

pub(crate) struct RuntimeWatches {
    pub(crate) config_rx: watch::Receiver<Arc<ProxyConfig>>,
    pub(crate) log_level_rx: watch::Receiver<LogLevel>,
    pub(crate) detected_ip_v4: Option<IpAddr>,
    pub(crate) detected_ip_v6: Option<IpAddr>,
}

#[derive(Clone)]
pub(crate) struct RuntimeLogFilter {
    handle: reload::Handle<EnvFilter, Registry>,
}

impl RuntimeLogFilter {
    pub(crate) fn new(handle: reload::Handle<EnvFilter, Registry>) -> Self {
        Self { handle }
    }

    pub(crate) fn start(
        &self,
        has_rust_log: bool,
        effective_log_level: &LogLevel,
        log_level_rx: watch::Receiver<LogLevel>,
        task_scope: RuntimeTaskScope,
    ) {
        self.apply(effective_log_level, has_rust_log);
        self.spawn_watcher(log_level_rx, task_scope);
    }

    pub(crate) fn apply_reload(&self, level: &LogLevel) {
        self.apply(level, false);
    }

    pub(crate) fn spawn_watcher(
        &self,
        mut log_level_rx: watch::Receiver<LogLevel>,
        task_scope: RuntimeTaskScope,
    ) {
        let filter = self.clone();
        task_scope.spawn(async move {
            loop {
                if log_level_rx.changed().await.is_err() {
                    break;
                }
                let level = log_level_rx.borrow_and_update().clone();
                filter.apply_reload(&level);
            }
        });
    }

    fn apply(&self, level: &LogLevel, has_rust_log: bool) {
        let runtime_filter = EnvFilter::new(log_filter_spec(has_rust_log, level));
        if let Err(error) = self.handle.reload(runtime_filter) {
            tracing::error!(error = %error, "Failed to update runtime log filter");
        }
    }
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
    shared_state: Arc<ProxySharedState>,
    me_ready_tx: watch::Sender<u64>,
    task_scope: RuntimeTaskScope,
) -> RuntimeWatches {
    let um_clone = upstream_manager.clone();
    let dc_overrides_for_health = config.dc_overrides.clone();
    task_scope.spawn(async move {
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
    task_scope.spawn(async move {
        rc_clone.run_periodic_cleanup().await;
    });

    let stats_maintenance = stats.clone();
    task_scope.spawn(async move {
        stats_maintenance
            .run_periodic_user_stats_maintenance()
            .await;
    });

    let ip_tracker_maintenance = ip_tracker.clone();
    task_scope.spawn(async move {
        ip_tracker_maintenance.run_periodic_maintenance().await;
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
            task_scope.cancellation_token(),
        );
    startup_tracker
        .complete_component(
            COMPONENT_CONFIG_WATCHER_START,
            Some("config hot-reload watcher started".to_string()),
        )
        .await;
    let mut config_rx_api_bridge = config_rx.clone();
    let api_config_tx_bridge = api_config_tx.clone();
    task_scope.spawn(async move {
        loop {
            if config_rx_api_bridge.changed().await.is_err() {
                break;
            }
            let cfg = config_rx_api_bridge.borrow_and_update().clone();
            api_config_tx_bridge.send_replace(cfg);
        }
    });

    let stats_policy = stats.clone();
    let upstream_policy = upstream_manager.clone();
    let mut config_rx_policy = config_rx.clone();
    task_scope.spawn(async move {
        loop {
            if config_rx_policy.changed().await.is_err() {
                break;
            }
            let cfg = config_rx_policy.borrow_and_update().clone();
            stats_policy
                .apply_telemetry_policy(TelemetryPolicy::from_config(&cfg.general.telemetry));
            if let Err(error) = upstream_policy.update_dns_overrides(&cfg.network.dns_overrides) {
                warn!(error = %error, "Failed to update generation DNS overrides");
            }
            if let Some(pool) = &me_pool_for_policy {
                pool.update_runtime_transport_policy(
                    cfg.general.me_socks_kdf_policy,
                    cfg.general.me_route_backpressure_enabled,
                    cfg.general.me_route_fairshare_enabled,
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
    task_scope.spawn(async move {
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

    let limiter = shared_state.traffic_limiter.clone();
    limiter.apply_policy(
        config.access.user_rate_limits.clone(),
        config.access.cidr_rate_limits.clone(),
    );
    let mut config_rx_rate_limits = config_rx.clone();
    task_scope.spawn(async move {
        let mut prev_user_limits = config_rx_rate_limits
            .borrow()
            .access
            .user_rate_limits
            .clone();
        let mut prev_cidr_limits = config_rx_rate_limits
            .borrow()
            .access
            .cidr_rate_limits
            .clone();
        loop {
            if config_rx_rate_limits.changed().await.is_err() {
                break;
            }
            let cfg = config_rx_rate_limits.borrow_and_update().clone();
            if prev_user_limits != cfg.access.user_rate_limits
                || prev_cidr_limits != cfg.access.cidr_rate_limits
            {
                limiter.apply_policy(
                    cfg.access.user_rate_limits.clone(),
                    cfg.access.cidr_rate_limits.clone(),
                );
                prev_user_limits = cfg.access.user_rate_limits.clone();
                prev_cidr_limits = cfg.access.cidr_rate_limits.clone();
            }
        }
    });

    let shared_user_enabled = shared_state.clone();
    let mut config_rx_user_enabled = config_rx.clone();
    task_scope.spawn(async move {
        loop {
            if config_rx_user_enabled.changed().await.is_err() {
                break;
            }
            let cfg = config_rx_user_enabled.borrow_and_update().clone();
            for user in shared_user_enabled.apply_user_enabled_config(&cfg.access.user_enabled) {
                let cancelled = shared_user_enabled.cancel_user_sessions(&user);
                if cancelled > 0 {
                    info!(
                        user = %user,
                        cancelled,
                        "Disabled user sessions cancelled after config reload"
                    );
                }
            }
        }
    });

    let beobachten_writer = beobachten.clone();
    let config_rx_beobachten = config_rx.clone();
    task_scope.spawn(async move {
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
        spawn_middle_proxy_runtime_tasks(
            config,
            config_rx.clone(),
            pool,
            rng,
            me_ready_tx,
            task_scope,
        );
    }

    RuntimeWatches {
        config_rx,
        log_level_rx,
        detected_ip_v4,
        detected_ip_v6,
    }
}

pub(crate) fn spawn_middle_proxy_runtime_tasks(
    config: &ProxyConfig,
    config_rx: watch::Receiver<Arc<ProxyConfig>>,
    pool: Arc<MePool>,
    rng: Arc<SecureRandom>,
    me_ready_tx: watch::Sender<u64>,
    task_scope: RuntimeTaskScope,
) {
    let reinit_trigger_capacity = config.general.me_reinit_trigger_channel.max(1);
    let (reinit_tx, reinit_rx) = mpsc::channel::<MeReinitTrigger>(reinit_trigger_capacity);

    let pool_clone_sched = pool.clone();
    let rng_clone_sched = rng.clone();
    let config_rx_clone_sched = config_rx.clone();
    let me_ready_tx_sched = me_ready_tx.clone();
    task_scope.spawn(async move {
        crate::transport::middle_proxy::me_reinit_scheduler(
            pool_clone_sched,
            rng_clone_sched,
            config_rx_clone_sched,
            reinit_rx,
            me_ready_tx_sched,
        )
        .await;
    });

    let pool_clone = pool.clone();
    let config_rx_clone = config_rx.clone();
    let reinit_tx_updater = reinit_tx.clone();
    task_scope.spawn(async move {
        crate::transport::middle_proxy::me_config_updater(
            pool_clone,
            config_rx_clone,
            reinit_tx_updater,
        )
        .await;
    });

    let config_rx_clone_rot = config_rx.clone();
    let reinit_tx_rotation = reinit_tx.clone();
    task_scope.spawn(async move {
        crate::transport::middle_proxy::me_rotation_task(config_rx_clone_rot, reinit_tx_rotation)
            .await;
    });
}

pub(crate) fn log_filter_spec(has_rust_log: bool, effective_log_level: &LogLevel) -> String {
    if has_rust_log {
        std::env::var("RUST_LOG")
            .unwrap_or_else(|_| effective_log_level.to_filter_str().to_string())
    } else if matches!(effective_log_level, LogLevel::Silent) {
        "warn,telemt::links=info".to_string()
    } else {
        effective_log_level.to_filter_str().to_string()
    }
}

pub(crate) async fn spawn_metrics_if_configured(
    config: &Arc<ProxyConfig>,
    startup_tracker: &Arc<StartupTracker>,
    active_runtime: Arc<ArcSwap<RuntimeGeneration>>,
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
        let active_runtime = active_runtime.clone();
        let listen_backlog = config.server.listen_backlog;
        tokio::spawn(async move {
            metrics::serve(port, listen, listen_backlog, active_runtime).await;
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
