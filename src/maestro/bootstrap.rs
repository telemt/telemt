use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*, reload as tracing_reload};

use crate::config::{LogLevel, ProxyConfig};
use crate::startup::{COMPONENT_CONFIG_LOAD, COMPONENT_TRACING_INIT, StartupTracker};

use super::helpers::{
    parse_cli, print_maestro_line, resolve_runtime_base_dir, resolve_runtime_config_path,
    set_maestro_colors_enabled,
};
use super::runtime_tasks;
use super::validate_synlimit_privilege_drop;

/// Process-level configuration and logging resources retained across runtime generations.
pub(super) struct BootstrapState {
    /// Monotonic process startup time.
    pub(super) process_started_at: Instant,
    /// Process startup time as Unix epoch seconds.
    pub(super) process_started_at_epoch_secs: u64,
    /// Startup component progress shared with the control plane.
    pub(super) startup_tracker: Arc<StartupTracker>,
    /// Validated initial runtime configuration.
    pub(super) config: ProxyConfig,
    /// Resolved source path used by reload operations.
    pub(super) config_path: PathBuf,
    /// Whether the environment owns the log filter policy.
    pub(super) has_rust_log: bool,
    /// Initial verbosity after CLI overrides.
    pub(super) effective_log_level: LogLevel,
    /// Process-owned dynamic tracing filter.
    pub(super) runtime_log_filter: runtime_tasks::RuntimeLogFilter,
    /// Keeps the file logging worker alive until process shutdown.
    pub(super) logging_guard: Option<crate::logging::LoggingGuard>,
}

/// Loads configuration and initializes process logging with the startup parent-path policy.
pub(super) async fn bootstrap(
    privilege_drop_requested: bool,
    strict_runtime_paths: bool,
) -> std::result::Result<BootstrapState, Box<dyn std::error::Error>> {
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

    if let Err(e) = enter_runtime_directory(&runtime_base_dir) {
        eprintln!(
            "[telemt] Can't use runtime directory {}: {}",
            runtime_base_dir.display(),
            e
        );
        std::process::exit(1);
    }

    let mut config = match ProxyConfig::load_prepared(config_path.clone()).await {
        Ok(loaded) => loaded.config,
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
                        if let Err(write_error) = write_private_file(&config_path, serialized) {
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
                            Ok(()) => match write_private_file(&runtime_config_path, serialized) {
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
                            match write_private_file(&fallback_config_path, serialized) {
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
    validate_synlimit_privilege_drop(&config, privilege_drop_requested)?;

    if let Some(p) = data_path {
        if config.general.data_path.as_ref() != Some(&p) {
            config.provenance = crate::config::observation::ConfigProvenance::Mixed;
        }
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

        if let Err(e) = enter_runtime_directory(data_path) {
            eprintln!(
                "[telemt] Can't use data_path {}: {}",
                data_path.display(),
                e
            );
            std::process::exit(1);
        }
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
        tracing_reload::Layer::new(EnvFilter::new(initial_filter_spec.clone()));
    startup_tracker
        .start_component(
            COMPONENT_TRACING_INIT,
            Some("initialize tracing subscriber".to_string()),
        )
        .await;

    let logging_guard: Option<crate::logging::LoggingGuard>;
    match log_destination {
        crate::logging::LogDestination::Stderr => {
            let fmt_layer = if config.general.disable_colors {
                fmt::Layer::default().with_ansi(false)
            } else {
                fmt::Layer::default().with_ansi(true)
            };
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt_layer)
                .init();
            logging_guard = None;
        }
        #[cfg(unix)]
        crate::logging::LogDestination::Syslog => {
            let logging_opts = crate::logging::LoggingOptions {
                destination: log_destination,
                disable_colors: true,
                strict_runtime_paths,
            };
            let (_, guard) = crate::logging::init_logging(&logging_opts, &initial_filter_spec);
            logging_guard = Some(guard);
        }
        crate::logging::LogDestination::File { .. } => {
            let logging_opts = crate::logging::LoggingOptions {
                destination: log_destination,
                disable_colors: true,
                strict_runtime_paths,
            };
            let (_, guard) = crate::logging::init_logging(&logging_opts, &initial_filter_spec);
            logging_guard = Some(guard);
        }
    }
    let runtime_log_filter = runtime_tasks::RuntimeLogFilter::new(filter_handle);

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

    Ok(BootstrapState {
        process_started_at,
        process_started_at_epoch_secs,
        startup_tracker,
        config,
        config_path,
        has_rust_log,
        effective_log_level,
        runtime_log_filter,
        logging_guard,
    })
}

fn enter_runtime_directory(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        crate::util::secure_fs::chdir_nofollow_or_create(path, 0o750)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)?;
        std::env::set_current_dir(path)
    }
}

fn write_private_file(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        crate::util::secure_fs::atomic_replace(path, contents.as_bytes(), 0o600)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}
