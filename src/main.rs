//! Telemt - MTProxy on Rust

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::Semaphore;
use tracing::{info, error, warn, debug};
use tracing_subscriber::{fmt, EnvFilter, reload, prelude::*};

mod cli;
mod config;
mod crypto;
mod error;
mod protocol;
mod proxy;
mod stats;
mod stream;
mod transport;
mod util;

use crate::config::{ProxyConfig, LogLevel};
use crate::proxy::ClientHandler;
use crate::stats::{Stats, ReplayChecker};
use crate::crypto::SecureRandom;
use crate::transport::{create_listener, ListenOptions, UpstreamManager};
use crate::util::ip::detect_ip;
use crate::stream::BufferPool;

fn parse_cli() -> (String, bool, Option<String>) {
    let mut config_path = "config.toml".to_string();
    let mut silent = false;
    let mut log_level: Option<String> = None;
    
    let args: Vec<String> = std::env::args().skip(1).collect();
    
    // Check for --init first (handled before tokio)
    if let Some(init_opts) = cli::parse_init_args(&args) {
        if let Err(e) = cli::run_init(init_opts) {
            eprintln!("[telemt] Init failed: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }
    
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--silent" | "-s" => { silent = true; }
            "--log-level" => {
                i += 1;
                if i < args.len() { log_level = Some(args[i].clone()); }
            }
            s if s.starts_with("--log-level=") => {
                log_level = Some(s.trim_start_matches("--log-level=").to_string());
            }
            "--help" | "-h" => {
                eprintln!("Usage: telemt [config.toml] [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --silent, -s            Suppress info logs");
                eprintln!("  --log-level <LEVEL>     debug|verbose|normal|silent");
                eprintln!("  --help, -h              Show this help");
                eprintln!();
                eprintln!("Setup (fire-and-forget):");
                eprintln!("  --init                  Generate config, install systemd service, start");
                eprintln!("    --port <PORT>          Listen port (default: 443)");
                eprintln!("    --domain <DOMAIN>      TLS domain for masking (default: www.google.com)");
                eprintln!("    --secret <HEX>         32-char hex secret (auto-generated if omitted)");
                eprintln!("    --user <NAME>          Username (default: user)");
                eprintln!("    --config-dir <DIR>     Config directory (default: /etc/telemt)");
                eprintln!("    --no-start             Don't start the service after install");
                std::process::exit(0);
            }
            s if !s.starts_with('-') => { config_path = s.to_string(); }
            other => { eprintln!("Unknown option: {}", other); }
        }
        i += 1;
    }
    
    (config_path, silent, log_level)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (config_path, cli_silent, cli_log_level) = parse_cli();

    let config = match ProxyConfig::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            if std::path::Path::new(&config_path).exists() {
                eprintln!("[telemt] Error: {}", e);
                std::process::exit(1);
            } else {
                let default = ProxyConfig::default();
                std::fs::write(&config_path, toml::to_string_pretty(&default).unwrap()).unwrap();
                eprintln!("[telemt] Created default config at {}", config_path);
                default
            }
        }
    };
    
    if let Err(e) = config.validate() {
        eprintln!("[telemt] Invalid config: {}", e);
        std::process::exit(1);
    }

    let has_rust_log = std::env::var("RUST_LOG").is_ok();
    let effective_log_level = if cli_silent {
        LogLevel::Silent
    } else if let Some(ref s) = cli_log_level {
        LogLevel::from_str_loose(s)
    } else {
        config.general.log_level.clone()
    };

    // Start with INFO so startup messages are always visible,
    // then switch to user-configured level after startup
    let (filter_layer, filter_handle) = reload::Layer::new(EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt::Layer::default())
        .init();

    info!("Telemt MTProxy v{}", env!("CARGO_PKG_VERSION"));
    info!("Log level: {}", effective_log_level);
    info!("Modes: classic={} secure={} tls={}",
        config.general.modes.classic,
        config.general.modes.secure,
        config.general.modes.tls);
    info!("TLS domain: {}", config.censorship.tls_domain);
    if let Some(ref sock) = config.censorship.mask_unix_sock {
        info!("Mask: {} -> unix:{}", config.censorship.mask, sock);
        if !std::path::Path::new(sock).exists() {
            warn!("Unix socket '{}' does not exist yet. Masking will fail until it appears.", sock);
        }
    } else {
        info!("Mask: {} -> {}:{}",
            config.censorship.mask,
            config.censorship.mask_host.as_deref().unwrap_or(&config.censorship.tls_domain),
            config.censorship.mask_port);
    }

    if config.censorship.tls_domain == "www.google.com" {
        warn!("Using default tls_domain. Consider setting a custom domain.");
    }
    
    let prefer_ipv6 = config.general.prefer_ipv6;
    let config = Arc::new(config);
    let stats = Arc::new(Stats::new());
    let rng = Arc::new(SecureRandom::new());
    
    let replay_checker = Arc::new(ReplayChecker::new(
        config.access.replay_check_len,
        Duration::from_secs(config.access.replay_window_secs),
    ));
    
    let upstream_manager = Arc::new(UpstreamManager::new(config.upstreams.clone()));
    let buffer_pool = Arc::new(BufferPool::with_config(16 * 1024, 4096));
    
        // Connection concurrency limit — prevents OOM under SYN flood / connection storm.
        // 10000 is generous; each connection uses ~64KB (2x 16KB relay buffers + overhead).
        // 10000 connections ≈ 640MB peak memory.
        let max_connections = Arc::new(Semaphore::new(10_000));
    
    // Startup DC ping
    info!("=== Telegram DC Connectivity ===");
    let ping_results = upstream_manager.ping_all_dcs(prefer_ipv6).await;
    for upstream_result in &ping_results {
        info!("  via {}", upstream_result.upstream_name);
        for dc in &upstream_result.results {
            match (&dc.rtt_ms, &dc.error) {
                (Some(rtt), _) => {
                    info!("    DC{} ({:>21}):  {:.0}ms", dc.dc_idx, dc.dc_addr, rtt);
                }
                (None, Some(err)) => {
                    info!("    DC{} ({:>21}):  FAIL ({})", dc.dc_idx, dc.dc_addr, err);
                }
                _ => {
                    info!("    DC{} ({:>21}):  FAIL", dc.dc_idx, dc.dc_addr);
                }
            }
        }
    }
    info!("================================");
    
    // Background tasks
    let um_clone = upstream_manager.clone();
    tokio::spawn(async move { um_clone.run_health_checks(prefer_ipv6).await; });
    
    let rc_clone = replay_checker.clone();
    tokio::spawn(async move { rc_clone.run_periodic_cleanup().await; });

    let detected_ip = detect_ip().await;
    debug!("Detected IPs: v4={:?} v6={:?}", detected_ip.ipv4, detected_ip.ipv6);

    let mut listeners = Vec::new();
    
    for listener_conf in &config.server.listeners {
        let addr = SocketAddr::new(listener_conf.ip, config.server.port);
        let options = ListenOptions {
            ipv6_only: listener_conf.ip.is_ipv6(),
            ..Default::default()
        };
        
        match create_listener(addr, &options) {
            Ok(socket) => {
                let listener = TcpListener::from_std(socket.into())?;
                info!("Listening on {}", addr);
                
                let public_ip = if let Some(ip) = listener_conf.announce_ip {
                    ip
                } else if listener_conf.ip.is_unspecified() {
                    if listener_conf.ip.is_ipv4() {
                        detected_ip.ipv4.unwrap_or(listener_conf.ip)
                    } else {
                        detected_ip.ipv6.unwrap_or(listener_conf.ip)
                    }
                } else {
                    listener_conf.ip
                };

                if !config.show_link.is_empty() {
                    info!("--- Proxy Links ({}) ---", public_ip);
                    for user_name in config.show_link.resolve_users(&config.access.users) {
                        if let Some(secret) = config.access.users.get(user_name) {
                            info!("User: {}", user_name);
                            if config.general.modes.classic {
                                info!("  Classic: tg://proxy?server={}&port={}&secret={}",
                                    public_ip, config.server.port, secret);
                            }
                            if config.general.modes.secure {
                                info!("  DD:      tg://proxy?server={}&port={}&secret=dd{}",
                                    public_ip, config.server.port, secret);
                            }
                            if config.general.modes.tls {
                                let domain_hex = hex::encode(&config.censorship.tls_domain);
                                info!("  EE-TLS:  tg://proxy?server={}&port={}&secret=ee{}{}",
                                    public_ip, config.server.port, secret, domain_hex);
                            }
                        } else {
                            warn!("User '{}' in show_link not found", user_name);
                        }
                    }
                    info!("------------------------");
                }
                
                listeners.push(listener);
            },
            Err(e) => {
                error!("Failed to bind to {}: {}", addr, e);
            }
        }
    }
    
    if listeners.is_empty() {
        error!("No listeners. Exiting.");
        std::process::exit(1);
    }

    // Switch to user-configured log level after startup
    let runtime_filter = if has_rust_log {
        EnvFilter::from_default_env()
    } else {
        EnvFilter::new(effective_log_level.to_filter_str())
    };
    filter_handle.reload(runtime_filter).expect("Failed to switch log filter");

    for listener in listeners {
        let config = config.clone();
        let stats = stats.clone();
        let upstream_manager = upstream_manager.clone();
        let replay_checker = replay_checker.clone();
        let buffer_pool = buffer_pool.clone();
        let rng = rng.clone();
        
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let config = config.clone();
                        let stats = stats.clone();
                        let upstream_manager = upstream_manager.clone();
                        let replay_checker = replay_checker.clone();
                        let buffer_pool = buffer_pool.clone();
                        let rng = rng.clone();
                        
                        tokio::spawn(async move {
                            if let Err(e) = ClientHandler::new(
                                stream, peer_addr, config, stats,
                                upstream_manager, replay_checker, buffer_pool, rng
                            ).run().await {
                                debug!(peer = %peer_addr, error = %e, "Connection error");
                            }
                        });
                    }
                    Err(e) => {
                        error!("Accept error: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }

    match signal::ctrl_c().await {
        Ok(()) => info!("Shutting down..."),
        Err(e) => error!("Signal error: {}", e),
    }

    Ok(())
}