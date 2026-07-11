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
use crate::conntrack_control;
use crate::crypto::SecureRandom;
use crate::ip_tracker::UserIpTracker;
use crate::network::probe::{decide_network_capabilities, log_probe_result, run_probe};
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::proxy::direct_buffer_budget::{
    DirectBufferBudget, resolve_direct_buffer_hard_limit,
    spawn_direct_buffer_budget_controller,
};
use crate::proxy::shared_state::ProxySharedState;
use crate::startup::{
    COMPONENT_API_BOOTSTRAP, COMPONENT_CONFIG_LOAD, COMPONENT_DC_CONNECTIVITY_PING,
    COMPONENT_ME_CONNECTIVITY_PING, COMPONENT_ME_POOL_CONSTRUCT, COMPONENT_ME_POOL_INIT_STAGE1,
    COMPONENT_ME_PROXY_CONFIG_V4, COMPONENT_ME_PROXY_CONFIG_V6, COMPONENT_ME_SECRET_FETCH,
    COMPONENT_NETWORK_PROBE, COMPONENT_TRACING_INIT, StartupMeStatus, StartupTracker,
};
use crate::stats::beobachten::BeobachtenStore;
use crate::stats::telemetry::TelemetryPolicy;
use crate::stats::{ReplayChecker, Stats};
use crate::stream::BufferPool;
use crate::synlimit_control;
use crate::transport::UpstreamManager;
use crate::transport::middle_proxy::MePool;
use helpers::{
    parse_cli, print_maestro_line, resolve_runtime_base_dir, resolve_runtime_config_path,
    set_maestro_colors_enabled,
};

#[cfg(unix)]
use crate::daemon::{DaemonOptions, PidFile, drop_privileges};

/// Runs the full telemt runtime startup pipeline and blocks until shutdown.
///
/// On Unix, daemon options should be handled before calling this function
/// (daemonization must happen before tokio runtime starts).
#[cfg(unix)]
pub async fn run_with_daemon(
    daemon_opts: DaemonOptions,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    run_inner(daemon_opts).await
}

/// Runs the full telemt runtime startup pipeline and blocks until shutdown.
///
/// This is the main entry point for non-daemon mode or when called as a library.
#[allow(dead_code)]
pub async fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        // Parse CLI to get daemon options even in simple run() path
        let args: Vec<String> = std::env::args().skip(1).collect();
        let daemon_opts = crate::cli::parse_daemon_args(&args);
        run_inner(daemon_opts).await
    }
    #[cfg(not(unix))]
    {
        run_inner().await
    }
}

// Shared maestro startup and main loop. `drop_after_bind` runs on Unix after listeners are bound
// (for privilege drop); it is a no-op on other platforms.
async fn run_telemt_core(
    drop_after_bind: impl FnOnce(),
) -> std::result::Result<(), Box<dyn std::error::Error>> {
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
    let cli_args = parse_cli();
    let config_path_cli = cli_args.config_path;
    let config_path_explicit = cli_args.config_path_explicit;
    let data_path = cli_args.data_path;
    let cli_silent = cli_args.silent;
    let cli_log_level = cli_args.log_level;
    let log_cli_options = cli_args.log_cli_options;
    let startup_cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(e) => {
            eprintln!("[telemt] Can't read current_dir: {}", e);
            std::process::exit(1);
        }
    };
    if let Some(ref data_path) = data_path
        && !data_path.is_absolute()
    {
        eprintln!(
            "[telemt] data_path must be absolute: {}",
            data_path.display()
        );
        std::process::exit(1);
    }
    let mut config_path =
        resolve_runtime_config_path(&config_path_cli, &startup_cwd, config_path_explicit);
    let runtime_base_dir = resolve_runtime_base_dir(
        &config_path,
        &startup_cwd,
        config_path_explicit,
        data_path.as_deref(),
    );

    if !runtime_base_dir.exists()
        && let Err(e) = std::fs::create_dir_all(&runtime_base_dir)
    {
        eprintln!(
            "[telemt] Can't create runtime directory {}: {}",
            runtime_base_dir.display(),
            e
        );
        std::process::exit(1);
    }

    if !runtime_base_dir.is_dir() {
        eprintln!(
            "[telemt] Runtime path exists but is not a directory: {}",
            runtime_base_dir.display()
        );
        std::process::exit(1);
    }

    if let Err(e) = std::env::set_current_dir(&runtime_base_dir) {
        eprintln!(
            "[telemt] Can't use runtime directory {}: {}",
            runtime_base_dir.display(),
            e
        );
        std::process::exit(1);
    }

    let mut config = match ProxyConfig::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            if config_path.exists() {
                eprintln!("[telemt] Error: {}", e);
                std::process::exit(1);
            } else {
                let default = ProxyConfig::default();

                let serialized =
                    match toml::to_string_pretty(&default).or_else(|_| toml::to_string(&default)) {
                        Ok(value) => Some(value),
                        Err(serialize_error) => {
                            eprintln!(
                                "[telemt] Warning: failed to serialize default config: {}",
                                serialize_error
                            );
                            None
                        }
                    };

                if config_path_explicit {
                    if let Some(serialized) = serialized.as_ref() {
                        if let Err(write_error) = std::fs::write(&config_path, serialized) {
                            eprintln!(
                                "[telemt] Error: failed to create explicit config at {}: {}",
                                config_path.display(),
                                write_error
                            );
                            std::process::exit(1);
                        }
                        eprintln!(
                            "[telemt] Created default config at {}",
                            config_path.display()
                        );
                    } else {
                        eprintln!(
                            "[telemt] Warning: running with in-memory default config without writing to disk"
                        );
                    }
                } else {
                    let runtime_config_path = runtime_base_dir.join("telemt.toml");
                    let fallback_config_path = runtime_base_dir.join("config.toml");
                    let mut persisted = false;

                    if let Some(serialized) = serialized.as_ref() {
                        match std::fs::create_dir_all(&runtime_base_dir) {
                            Ok(()) => match std::fs::write(&runtime_config_path, serialized) {
                                Ok(()) => {
                                    config_path = runtime_config_path;
                                    eprintln!(
                                        "[telemt] Created default config at {}",
                                        config_path.display()
                                    );
                                    persisted = true;
                                }
                                Err(write_error) => {
                                    eprintln!(
                                        "[telemt] Warning: failed to write default config at {}: {}",
                                        runtime_config_path.display(),
                                        write_error
                                    );
                                }
                            },
                            Err(create_error) => {
                                eprintln!(
                                    "[telemt] Warning: failed to create {}: {}",
                                    runtime_base_dir.display(),
                                    create_error
                                );
                            }
                        }

                        if !persisted {
                            match std::fs::write(&fallback_config_path, serialized) {
                                Ok(()) => {
                                    config_path = fallback_config_path;
                                    eprintln!(
                                        "[telemt] Created default config at {}",
                                        config_path.display()
                                    );
                                    persisted = true;
                                }
                                Err(write_error) => {
                                    eprintln!(
                                        "[telemt] Warning: failed to write default config at {}: {}",
                                        fallback_config_path.display(),
                                        write_error
                                    );
                                }
                            }
                        }
                    }

                    if !persisted {
                        eprintln!(
                            "[telemt] Warning: running with in-memory default config without writing to disk"
                        );
                    }
                }
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
        } else if let Err(e) = std::fs::create_dir_all(data_path) {
            eprintln!(
                "[telemt] Can't create data_path {}: {}",
                data_path.display(),
                e
            );
            std::process::exit(1);
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
    set_maestro_colors_enabled(!config.general.disable_colors);
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

    let initial_filter_spec = runtime_tasks::log_filter_spec(has_rust_log, &effective_log_level);
    let log_destination =
        match crate::logging::resolve_log_destination(&config.logging, &log_cli_options) {
            Ok(destination) => destination,
            Err(error) => {
                eprintln!("[telemt] {error}");
                std::process::exit(1);
            }
        };
    let (filter_layer, filter_handle) =
        reload::Layer::new(EnvFilter::new(initial_filter_spec.clone()));
    startup_tracker
        .start_component(
            COMPONENT_TRACING_INIT,
            Some("initialize tracing subscriber".to_string()),
        )
        .await;

    // Initialize logging based on destination
    let _logging_guard: Option<crate::logging::LoggingGuard>;
    match log_destination {
        crate::logging::LogDestination::Stderr => {
            // Default: log to stderr (works with systemd journald)
            let fmt_layer = if config.general.disable_colors {
                fmt::Layer::default().with_ansi(false)
            } else {
                fmt::Layer::default().with_ansi(true)
            };
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt_layer)
                .init();
            _logging_guard = None;
        }
        #[cfg(unix)]
        crate::logging::LogDestination::Syslog => {
            // Syslog: for OpenRC/FreeBSD
            let logging_opts = crate::logging::LoggingOptions {
                destination: log_destination,
                disable_colors: true,
            };
            let (_, guard) = crate::logging::init_logging(&logging_opts, &initial_filter_spec);
            _logging_guard = Some(guard);
        }
        crate::logging::LogDestination::File { .. } => {
            // File logging with optional rotation
            let logging_opts = crate::logging::LoggingOptions {
                destination: log_destination,
                disable_colors: true,
            };
            let (_, guard) = crate::logging::init_logging(&logging_opts, &initial_filter_spec);
            _logging_guard = Some(guard);
        }
    }

    startup_tracker
        .complete_component(
            COMPONENT_TRACING_INIT,
            Some("tracing initialized".to_string()),
        )
        .await;

    print_maestro_line(format!("Telemt MTProxy v{}", env!("CARGO_PKG_VERSION")));
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
    let quota_state_path = config.general.quota_state_path.clone();
    crate::quota_state::load_quota_state(&quota_state_path, stats.as_ref()).await;

    let upstream_manager = Arc::new(UpstreamManager::new(
        config.upstreams.clone(),
        config.general.upstream_connect_retry_attempts,
        config.general.upstream_connect_retry_backoff_ms,
        config.general.upstream_connect_budget_ms,
        config.general.tg_connect,
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
    let direct_buffer_hard_limit = resolve_direct_buffer_hard_limit(
        config.general.direct_relay_buffer_budget_max_bytes,
    )
    .await;
    let direct_buffer_budget = DirectBufferBudget::new(direct_buffer_hard_limit);
    info!(
        hard_limit_bytes = direct_buffer_hard_limit,
        configured_override_bytes = config.general.direct_relay_buffer_budget_max_bytes,
        "Direct relay buffer budget initialized"
    );
    let shared_state =
        ProxySharedState::new_with_direct_buffer_budget(direct_buffer_budget.clone());
    shared_state.apply_user_enabled_config(&config.access.user_enabled);
    shared_state.traffic_limiter.apply_policy(
        config.access.user_rate_limits.clone(),
        config.access.cidr_rate_limits.clone(),
    );

    let (api_config_tx, api_config_rx) = watch::channel(Arc::new(config.clone()));
    let (detected_ips_tx, detected_ips_rx) = watch::channel((None::<IpAddr>, None::<IpAddr>));
    let initial_direct_first = config.general.use_middle_proxy && config.general.me2dc_fallback;
    let initial_admission_open = !config.general.use_middle_proxy || initial_direct_first;
    let (admission_tx, admission_rx) = watch::channel(initial_admission_open);
    let initial_route_mode = if !config.general.use_middle_proxy || initial_direct_first {
        RelayRouteMode::Direct
    } else {
        RelayRouteMode::Middle
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
            let proxy_shared_api = shared_state.clone();
            let config_rx_api = api_config_rx.clone();
            let admission_rx_api = admission_rx.clone();
            let config_path_api = config_path.clone();
            let quota_state_path_api = quota_state_path.clone();
            let startup_tracker_api = startup_tracker.clone();
            let detected_ips_rx_api = detected_ips_rx.clone();
            tokio::spawn(async move {
                api::serve(
                    listen,
                    stats_api,
                    ip_tracker_api,
                    me_pool_api,
                    route_runtime_api,
                    proxy_shared_api,
                    upstream_manager_api,
                    config_rx_api,
                    admission_rx_api,
                    config_path_api,
                    quota_state_path_api,
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
            warn!(
                "No usable IP family for Middle Proxy detected; Direct-DC startup fallback is active while ME init retries continue"
            );
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

    let (me_ready_tx, me_ready_rx) = watch::channel(0_u64);
    let direct_first_startup = use_middle_proxy && me2dc_fallback;

    let me_pool: Option<Arc<MePool>> = if direct_first_startup {
        None
    } else {
        me_startup::initialize_me_pool(
            use_middle_proxy,
            &config,
            &decision,
            &probe,
            &startup_tracker,
            upstream_manager.clone(),
            rng.clone(),
            stats.clone(),
            api_me_pool.clone(),
            me_ready_tx.clone(),
        )
        .await
    };

    // If ME failed to initialize, force direct-only mode.
    if direct_first_startup {
        startup_tracker.set_transport_mode("direct").await;
        startup_tracker.set_degraded(true).await;
        info!(
            "Transport: Direct DC startup fallback active; Middle-End bootstrap continues in background"
        );
    } else if me_pool.is_some() {
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

    if direct_first_startup {
        startup_tracker
            .skip_component(
                COMPONENT_ME_CONNECTIVITY_PING,
                Some("deferred by direct-first startup".to_string()),
            )
            .await;
        startup_tracker
            .skip_component(
                COMPONENT_DC_CONNECTIVITY_PING,
                Some("background health checks active".to_string()),
            )
            .await;
    } else {
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
    }

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
        shared_state.clone(),
        me_ready_tx.clone(),
    )
    .await;
    let config_rx = runtime_watches.config_rx;
    let log_level_rx = runtime_watches.log_level_rx;
    let detected_ip_v4 = runtime_watches.detected_ip_v4;
    let detected_ip_v6 = runtime_watches.detected_ip_v6;

    if direct_first_startup {
        let config_bg = config.clone();
        let decision_bg = decision.clone();
        let probe_bg = probe.clone();
        let startup_tracker_bg = startup_tracker.clone();
        let upstream_manager_bg = upstream_manager.clone();
        let rng_bg = rng.clone();
        let stats_bg = stats.clone();
        let api_me_pool_bg = api_me_pool.clone();
        let me_ready_tx_bg = me_ready_tx.clone();
        let config_rx_bg = config_rx.clone();
        tokio::spawn(async move {
            let mut bootstrap_attempt: u32 = 0;
            loop {
                bootstrap_attempt = bootstrap_attempt.saturating_add(1);
                let pool = me_startup::initialize_me_pool(
                    true,
                    config_bg.as_ref(),
                    &decision_bg,
                    &probe_bg,
                    &startup_tracker_bg,
                    upstream_manager_bg.clone(),
                    rng_bg.clone(),
                    stats_bg.clone(),
                    api_me_pool_bg.clone(),
                    me_ready_tx_bg.clone(),
                )
                .await;
                if let Some(pool) = pool {
                    runtime_tasks::spawn_middle_proxy_runtime_tasks(
                        config_bg.as_ref(),
                        config_rx_bg,
                        pool,
                        rng_bg,
                        me_ready_tx_bg,
                    );
                    break;
                }
                if me_init_retry_attempts > 0 && bootstrap_attempt >= me_init_retry_attempts {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });

        let startup_tracker_ready = startup_tracker.clone();
        let api_me_pool_ready = api_me_pool.clone();
        let mut me_ready_rx_transport = me_ready_tx.subscribe();
        tokio::spawn(async move {
            if me_ready_rx_transport.changed().await.is_ok() {
                if let Some(pool) = api_me_pool_ready.read().await.as_ref() {
                    pool.set_runtime_ready(true);
                }
                startup_tracker_ready
                    .set_transport_mode("middle_proxy")
                    .await;
                startup_tracker_ready.set_degraded(false).await;
                info!("Transport: Middle-End Proxy restored for new sessions");
            }
        });
    }

    admission::configure_admission_gate(
        &config,
        me_pool.clone(),
        api_me_pool.clone(),
        route_runtime.clone(),
        &admission_tx,
        config_rx.clone(),
        me_ready_rx,
    )
    .await;
    let _admission_tx_hold = admission_tx;
    conntrack_control::spawn_conntrack_controller(
        config_rx.clone(),
        stats.clone(),
        shared_state.clone(),
    );
    spawn_direct_buffer_budget_controller(
        direct_buffer_budget,
        stats.clone(),
        shared_state.clone(),
        config.server.max_connections,
    );

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
        api_me_pool.clone(),
        route_runtime.clone(),
        tls_cache.clone(),
        ip_tracker.clone(),
        beobachten.clone(),
        shared_state.clone(),
        max_connections.clone(),
    )
    .await?;
    let listeners = bound.listeners;
    let has_unix_listener = bound.has_unix_listener;

    if listeners.is_empty() && !has_unix_listener {
        error!("No listeners. Exiting.");
        std::process::exit(1);
    }

    // On Unix, caller supplies privilege drop after bind (may require root for port < 1024).
    drop_after_bind();

    synlimit_control::reconcile_synlimit_rules(&config).await;
    synlimit_control::spawn_synlimit_controller(config_rx.clone());

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
        shared_state.clone(),
        ip_tracker.clone(),
        tls_cache.clone(),
        config_rx.clone(),
    )
    .await;

    runtime_tasks::mark_runtime_ready(&startup_tracker).await;

    // Spawn signal handlers for SIGUSR1/SIGUSR2 (non-shutdown signals)
    shutdown::spawn_signal_handlers(stats.clone(), process_started_at);

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
        api_me_pool.clone(),
        route_runtime.clone(),
        tls_cache.clone(),
        ip_tracker.clone(),
        beobachten.clone(),
        shared_state,
        max_connections.clone(),
    );

    shutdown::wait_for_shutdown(process_started_at, me_pool, stats, quota_state_path).await;

    Ok(())
}

#[cfg(unix)]
async fn run_inner(
    daemon_opts: DaemonOptions,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Acquire PID file if daemonizing or if explicitly requested
    // Keep it alive until shutdown (underscore prefix = intentionally kept for RAII cleanup)
    let _pid_file = if daemon_opts.daemonize || daemon_opts.pid_file.is_some() {
        let mut pf = PidFile::new(daemon_opts.pid_file_path());
        if let Err(e) = pf.acquire() {
            eprintln!("[telemt] {}", e);
            std::process::exit(1);
        }
        Some(pf)
    } else {
        None
    };

    let user = daemon_opts.user.clone();
    let group = daemon_opts.group.clone();

    run_telemt_core(|| {
        if user.is_some() || group.is_some() {
            if let Err(e) = drop_privileges(user.as_deref(), group.as_deref(), _pid_file.as_ref()) {
                error!(error = %e, "Failed to drop privileges");
                std::process::exit(1);
            }
        }
    })
    .await
}

#[cfg(not(unix))]
async fn run_inner() -> std::result::Result<(), Box<dyn std::error::Error>> {
    run_telemt_core(|| {}).await
}
