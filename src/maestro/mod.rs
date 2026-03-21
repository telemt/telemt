//! telemt — Telegram MTProto Proxy

#![allow(unused_assignments)]

// Runtime orchestration modules.
// - helpers: CLI and shared startup/runtime helper routines.
// - tls_bootstrap: TLS front cache bootstrap and refresh tasks.
// - me_startup: Middle-End secret/config fetch and pool initialization.
// - connectivity: startup ME/DC connectivity diagnostics.
// - runtime_tasks: hot-reload and background task orchestration.
// - admission: conditional-cast gate and route mode switching.
// - listeners: TCP/Unix listener bind and accept-loop orchestration.
// - shutdown: graceful shutdown sequence and uptime logging.
mod admission;
mod connectivity;
mod helpers;
mod listeners;
mod me_startup;
mod runtime_tasks;
mod shutdown;
mod tls_bootstrap;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, Semaphore, watch};
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*, reload};

use crate::api;
use crate::config::{LogLevel, ProxyConfig};
use crate::crypto::SecureRandom;
use crate::ip_tracker::UserIpTracker;
use crate::network::probe::{decide_network_capabilities, log_probe_result, run_probe};
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::startup::{
    COMPONENT_API_BOOTSTRAP, COMPONENT_CONFIG_LOAD, COMPONENT_ME_POOL_CONSTRUCT,
    COMPONENT_ME_POOL_INIT_STAGE1, COMPONENT_ME_PROXY_CONFIG_V4, COMPONENT_ME_PROXY_CONFIG_V6,
    COMPONENT_ME_SECRET_FETCH, COMPONENT_NETWORK_PROBE, COMPONENT_TRACING_INIT, StartupMeStatus,
    StartupTracker,
};
use crate::stats::beobachten::BeobachtenStore;
use crate::stats::telemetry::TelemetryPolicy;
use crate::stats::{ReplayChecker, Stats};
use crate::stream::BufferPool;
use crate::transport::UpstreamManager;
use crate::transport::middle_proxy::MePool;
use helpers::{parse_cli, resolve_runtime_config_path};

/// Runs the full telemt runtime startup pipeline and blocks until shutdown.
pub async fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let process_started_at = Instant::now();
    let process_started_at_epoch_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let startup_tracker = Arc::new(StartupTracker::new(process_started_at_epoch_secs));
    startup_tracker
        .start_component(
            COMPONENT_CONFIG_LOAD,
            Some("load and validate config".to_string()),
        )
        .await;
    let (config_path_cli, data_path, cli_silent, cli_log_level) = parse_cli();
    let startup_cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(e) => {
            eprintln!("[telemt] Can't read current_dir: {}", e);
            std::process::exit(1);
        }
    };
    let config_path = resolve_runtime_config_path(&config_path_cli, &startup_cwd);

    let mut config = match ProxyConfig::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            if config_path.exists() {
                eprintln!("[telemt] Error: {}", e);
                std::process::exit(1);
            } else {
                let default = ProxyConfig::default();
                std::fs::write(&config_path, toml::to_string_pretty(&default).unwrap()).unwrap();
                eprintln!(
                    "[telemt] Created default config at {}",
                    config_path.display()
                );
                default
            }
        }
    };

    if let Err(e) = config.validate() {
        eprintln!("[telemt] Invalid config: {}", e);
        std::process::exit(1);
    }

    if let Some(p) = data_path {
        config.general.data_path = Some(p);
    }

    if let Some(ref data_path) = config.general.data_path {
        if !data_path.is_absolute() {
            eprintln!(
                "[telemt] data_path must be absolute: {}",
                data_path.display()
            );
            std::process::exit(1);
        }

        if data_path.exists() {
            if !data_path.is_dir() {
                eprintln!(
                    "[telemt] data_path exists but is not a directory: {}",
                    data_path.display()
                );
                std::process::exit(1);
            }
        } else {
            if let Err(e) = std::fs::create_dir_all(data_path) {
                eprintln!(
                    "[telemt] Can't create data_path {}: {}",
                    data_path.display(),
                    e
                );
                std::process::exit(1);
            }
        }

        if let Err(e) = std::env::set_current_dir(data_path) {
            eprintln!(
                "[telemt] Can't use data_path {}: {}",
                data_path.display(),
                e
            );
            std::process::exit(1);
        }
    }

    if let Err(e) = crate::network::dns_overrides::install_entries(&config.network.dns_overrides) {
        eprintln!("[telemt] Invalid network.dns_overrides: {}", e);
        std::process::exit(1);
    }
    startup_tracker
        .complete_component(COMPONENT_CONFIG_LOAD, Some("config is ready".to_string()))
        .await;

    let has_rust_log = std::env::var("RUST_LOG").is_ok();
    let effective_log_level = if cli_silent {
        LogLevel::Silent
    } else if let Some(ref s) = cli_log_level {
        LogLevel::from_str_loose(s)
    } else {
        config.general.log_level.clone()
    };

    let (filter_layer, filter_handle) = reload::Layer::new(EnvFilter::new("info"));
    startup_tracker
        .start_component(
            COMPONENT_TRACING_INIT,
            Some("initialize tracing subscriber".to_string()),
        )
        .await;

    // Configure color output based on config
    let fmt_layer = if config.general.disable_colors {
        fmt::Layer::default().with_ansi(false)
    } else {
        fmt::Layer::default().with_ansi(true)
    };

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();
    startup_tracker
        .complete_component(
            COMPONENT_TRACING_INIT,
            Some("tracing initialized".to_string()),
        )
        .await;

    info!("Telemt MTProxy v{}", env!("CARGO_PKG_VERSION"));
    info!("Log level: {}", effective_log_level);
    if config.general.disable_colors {
        info!("Colors: disabled");
    }
    info!(
        "Modes: classic={} secure={} tls={}",
        config.general.modes.classic, config.general.modes.secure, config.general.modes.tls
    );
    if config.general.modes.classic {
        warn!("Classic mode is vulnerable to DPI detection; enable only for legacy clients");
    }
    info!("TLS domain: {}", config.censorship.tls_domain);
    if let Some(ref sock) = config.censorship.mask_unix_sock {
        info!("Mask: {} -> unix:{}", config.censorship.mask, sock);
        if !std::path::Path::new(sock).exists() {
            warn!(
                "Unix socket '{}' does not exist yet. Masking will fail until it appears.",
                sock
            );
        }
    } else {
        info!(
            "Mask: {} -> {}:{}",
            config.censorship.mask,
            config
                .censorship
                .mask_host
                .as_deref()
                .unwrap_or(&config.censorship.tls_domain),
            config.censorship.mask_port
        );
    }

    if config.censorship.tls_domain == "www.google.com" {
        warn!("Using default tls_domain. Consider setting a custom domain.");
    }

    let stats = Arc::new(Stats::new());
    stats.apply_telemetry_policy(TelemetryPolicy::from_config(&config.general.telemetry));

    let upstream_manager = Arc::new(UpstreamManager::new(
        config.upstreams.clone(),
        config.general.upstream_connect_retry_attempts,
        config.general.upstream_connect_retry_backoff_ms,
        config.general.upstream_connect_budget_ms,
        config.general.upstream_unhealthy_fail_threshold,
        config.general.upstream_connect_failfast_hard_errors,
        stats.clone(),
    ));
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker
        .load_limits(
            config.access.user_max_unique_ips_global_each,
            &config.access.user_max_unique_ips,
        )
        .await;
    ip_tracker
        .set_limit_policy(
            config.access.user_max_unique_ips_mode,
            config.access.user_max_unique_ips_window_secs,
        )
        .await;
    if config.access.user_max_unique_ips_global_each > 0
        || !config.access.user_max_unique_ips.is_empty()
    {
        info!(
            global_each_limit = config.access.user_max_unique_ips_global_each,
            explicit_user_limits = config.access.user_max_unique_ips.len(),
            "User unique IP limits configured"
        );
    }
    if !config.network.dns_overrides.is_empty() {
        info!(
            "Runtime DNS overrides configured: {} entries",
            config.network.dns_overrides.len()
        );
    }

    let (api_config_tx, api_config_rx) = watch::channel(Arc::new(config.clone()));
    let (detected_ips_tx, detected_ips_rx) = watch::channel((None::<IpAddr>, None::<IpAddr>));
    let initial_admission_open = !config.general.use_middle_proxy;
    let (admission_tx, admission_rx) = watch::channel(initial_admission_open);
    let initial_route_mode = if config.general.use_middle_proxy {
        RelayRouteMode::Middle
    } else {
        RelayRouteMode::Direct
    };
    let route_runtime = Arc::new(RouteRuntimeController::new(initial_route_mode));
    let api_me_pool = Arc::new(RwLock::new(None::<Arc<MePool>>));
    startup_tracker
        .start_component(
            COMPONENT_API_BOOTSTRAP,
            Some("spawn API listener task".to_string()),
        )
        .await;

    if config.server.api.enabled {
        let listen = match config.server.api.listen.parse::<SocketAddr>() {
            Ok(listen) => listen,
            Err(error) => {
                warn!(
                    error = %error,
                    listen = %config.server.api.listen,
                    "Invalid server.api.listen; API is disabled"
                );
                SocketAddr::from(([127, 0, 0, 1], 0))
            }
        };
        if listen.port() != 0 {
            let stats_api = stats.clone();
            let ip_tracker_api = ip_tracker.clone();
            let me_pool_api = api_me_pool.clone();
            let upstream_manager_api = upstream_manager.clone();
            let route_runtime_api = route_runtime.clone();
            let config_rx_api = api_config_rx.clone();
            let admission_rx_api = admission_rx.clone();
            let config_path_api = config_path.clone();
            let startup_tracker_api = startup_tracker.clone();
            let detected_ips_rx_api = detected_ips_rx.clone();
            tokio::spawn(async move {
                api::serve(
                    listen,
                    stats_api,
                    ip_tracker_api,
                    me_pool_api,
                    route_runtime_api,
                    upstream_manager_api,
                    config_rx_api,
                    admission_rx_api,
                    config_path_api,
                    detected_ips_rx_api,
                    process_started_at_epoch_secs,
                    startup_tracker_api,
                )
                .await;
            });
            startup_tracker
                .complete_component(
                    COMPONENT_API_BOOTSTRAP,
                    Some(format!("api task spawned on {}", listen)),
                )
                .await;
        } else {
            startup_tracker
                .skip_component(
                    COMPONENT_API_BOOTSTRAP,
                    Some("server.api.listen has zero port".to_string()),
                )
                .await;
        }
    } else {
        startup_tracker
            .skip_component(
                COMPONENT_API_BOOTSTRAP,
                Some("server.api.enabled is false".to_string()),
            )
            .await;
    }

    let mut tls_domains = Vec::with_capacity(1 + config.censorship.tls_domains.len());
    tls_domains.push(config.censorship.tls_domain.clone());
    for d in &config.censorship.tls_domains {
        if !tls_domains.contains(d) {
            tls_domains.push(d.clone());
        }
    }

    let tls_cache = tls_bootstrap::bootstrap_tls_front(
        &config,
        &tls_domains,
        upstream_manager.clone(),
        &startup_tracker,
    )
    .await;

    startup_tracker
        .start_component(
            COMPONENT_NETWORK_PROBE,
            Some("probe network capabilities".to_string()),
        )
        .await;
    let probe = run_probe(
        &config.network,
        &config.upstreams,
        config.general.middle_proxy_nat_probe,
        config.general.stun_nat_probe_concurrency,
    )
    .await?;
    detected_ips_tx.send_replace((
        probe.detected_ipv4.map(IpAddr::V4),
        probe.detected_ipv6.map(IpAddr::V6),
    ));
    let decision =
        decide_network_capabilities(&config.network, &probe, config.general.middle_proxy_nat_ip);
    log_probe_result(&probe, &decision);
    startup_tracker
        .complete_component(
            COMPONENT_NETWORK_PROBE,
            Some("network capabilities determined".to_string()),
        )
        .await;

    let prefer_ipv6 = decision.prefer_ipv6();
    let mut use_middle_proxy = config.general.use_middle_proxy;
    let beobachten = Arc::new(BeobachtenStore::new());
    let rng = Arc::new(SecureRandom::new());

    // Connection concurrency limit (0 = unlimited)
    let max_connections_limit = if config.server.max_connections == 0 {
        Semaphore::MAX_PERMITS
    } else {
        config.server.max_connections as usize
    };
    let max_connections = Arc::new(Semaphore::new(max_connections_limit));

    let me2dc_fallback = config.general.me2dc_fallback;
    let me_init_retry_attempts = config.general.me_init_retry_attempts;
    if use_middle_proxy && !decision.ipv4_me && !decision.ipv6_me {
        if me2dc_fallback {
            warn!("No usable IP family for Middle Proxy detected; falling back to direct DC");
            use_middle_proxy = false;
        } else {
            warn!(
                "No usable IP family for Middle Proxy detected; me2dc_fallback=false, ME init retries stay active"
            );
        }
    }

    if use_middle_proxy {
        startup_tracker
            .set_me_status(StartupMeStatus::Initializing, COMPONENT_ME_SECRET_FETCH)
            .await;
        startup_tracker
            .start_component(
                COMPONENT_ME_SECRET_FETCH,
                Some("fetch proxy-secret from source/cache".to_string()),
            )
            .await;
        startup_tracker
            .set_me_retry_limit(if !me2dc_fallback || me_init_retry_attempts == 0 {
                "unlimited".to_string()
            } else {
                me_init_retry_attempts.to_string()
            })
            .await;
    } else {
        startup_tracker
            .set_me_status(StartupMeStatus::Skipped, "skipped")
            .await;
        startup_tracker
            .skip_component(
                COMPONENT_ME_SECRET_FETCH,
                Some("middle proxy mode disabled".to_string()),
            )
            .await;
        startup_tracker
            .skip_component(
                COMPONENT_ME_PROXY_CONFIG_V4,
                Some("middle proxy mode disabled".to_string()),
            )
            .await;
        startup_tracker
            .skip_component(
                COMPONENT_ME_PROXY_CONFIG_V6,
                Some("middle proxy mode disabled".to_string()),
            )
            .await;
        startup_tracker
            .skip_component(
                COMPONENT_ME_POOL_CONSTRUCT,
                Some("middle proxy mode disabled".to_string()),
            )
            .await;
        startup_tracker
            .skip_component(
                COMPONENT_ME_POOL_INIT_STAGE1,
                Some("middle proxy mode disabled".to_string()),
            )
            .await;
    }

    let me_pool: Option<Arc<MePool>> = me_startup::initialize_me_pool(
        use_middle_proxy,
        &config,
        &decision,
        &probe,
        &startup_tracker,
        upstream_manager.clone(),
        rng.clone(),
        stats.clone(),
        api_me_pool.clone(),
    )
    .await;

    // If ME failed to initialize, force direct-only mode.
    if me_pool.is_some() {
        startup_tracker.set_transport_mode("middle_proxy").await;
        startup_tracker.set_degraded(false).await;
        info!("Transport: Middle-End Proxy - all DC-over-RPC");
    } else {
        let _ = use_middle_proxy;
        use_middle_proxy = false;
        // Make runtime config reflect direct-only mode for handlers.
        config.general.use_middle_proxy = false;
        startup_tracker.set_transport_mode("direct").await;
        startup_tracker.set_degraded(true).await;
        if me2dc_fallback {
            startup_tracker
                .set_me_status(StartupMeStatus::Failed, "fallback_to_direct")
                .await;
        } else {
            startup_tracker
                .set_me_status(StartupMeStatus::Skipped, "skipped")
                .await;
        }
        info!("Transport: Direct DC - TCP - standard DC-over-TCP");
    }

    // Freeze config after possible fallback decision
    let config = Arc::new(config);

    let replay_checker = Arc::new(ReplayChecker::new(
        config.access.replay_check_len,
        Duration::from_secs(config.access.replay_window_secs),
    ));

    let buffer_pool = Arc::new(BufferPool::with_config(64 * 1024, 4096));

    connectivity::run_startup_connectivity(
        &config,
        &me_pool,
        rng.clone(),
        &startup_tracker,
        upstream_manager.clone(),
        prefer_ipv6,
        &decision,
        process_started_at,
        api_me_pool.clone(),
    )
    .await;

    let runtime_watches = runtime_tasks::spawn_runtime_tasks(
        &config,
        &config_path,
        &probe,
        prefer_ipv6,
        decision.ipv4_dc,
        decision.ipv6_dc,
        &startup_tracker,
        stats.clone(),
        upstream_manager.clone(),
        replay_checker.clone(),
        me_pool.clone(),
        rng.clone(),
        ip_tracker.clone(),
        beobachten.clone(),
        api_config_tx.clone(),
        me_pool.clone(),
    )
    .await;
    let config_rx = runtime_watches.config_rx;
    let log_level_rx = runtime_watches.log_level_rx;
    let detected_ip_v4 = runtime_watches.detected_ip_v4;
    let detected_ip_v6 = runtime_watches.detected_ip_v6;

    admission::configure_admission_gate(
        &config,
        me_pool.clone(),
        route_runtime.clone(),
        &admission_tx,
        config_rx.clone(),
    )
    .await;
    let _admission_tx_hold = admission_tx;

    let bound = listeners::bind_listeners(
        &config,
        decision.ipv4_dc,
        decision.ipv6_dc,
        detected_ip_v4,
        detected_ip_v6,
        &startup_tracker,
        config_rx.clone(),
        admission_rx.clone(),
        stats.clone(),
        upstream_manager.clone(),
        replay_checker.clone(),
        buffer_pool.clone(),
        rng.clone(),
        me_pool.clone(),
        route_runtime.clone(),
        tls_cache.clone(),
        ip_tracker.clone(),
        beobachten.clone(),
        max_connections.clone(),
    )
    .await?;
    let listeners = bound.listeners;
    let has_unix_listener = bound.has_unix_listener;

    if listeners.is_empty() && !has_unix_listener {
        error!("No listeners. Exiting.");
        std::process::exit(1);
    }

    runtime_tasks::apply_runtime_log_filter(
        has_rust_log,
        &effective_log_level,
        filter_handle,
        log_level_rx,
    )
    .await;

    runtime_tasks::spawn_metrics_if_configured(
        &config,
        &startup_tracker,
        stats.clone(),
        beobachten.clone(),
        ip_tracker.clone(),
        config_rx.clone(),
    )
    .await;

    runtime_tasks::mark_runtime_ready(&startup_tracker).await;

    listeners::spawn_tcp_accept_loops(
        listeners,
        config_rx.clone(),
        admission_rx.clone(),
        stats.clone(),
        upstream_manager.clone(),
        replay_checker.clone(),
        buffer_pool.clone(),
        rng.clone(),
        me_pool.clone(),
        route_runtime.clone(),
        tls_cache.clone(),
        ip_tracker.clone(),
        beobachten.clone(),
        max_connections.clone(),
    );

    shutdown::wait_for_shutdown(process_started_at, me_pool).await;

    Ok(())
}
