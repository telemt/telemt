//! Telemt - MTProxy on Rust

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{info, error, warn, debug};
use tracing_subscriber::{fmt, EnvFilter};

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
use crate::proxy::middle::{MiddleProxyConfig, MiddleProxyPool};
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
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
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

    let effective_log_level = if cli_silent {
        LogLevel::Silent
    } else if let Some(ref s) = cli_log_level {
        LogLevel::from_str_loose(s)
    } else {
        config.general.log_level.clone()
    };

    let filter = if std::env::var("RUST_LOG").is_ok() {
        EnvFilter::from_default_env()
    } else {
        EnvFilter::new(effective_log_level.to_filter_str())
    };

    fmt().with_env_filter(filter).init();

    info!("Telemt MTProxy v{}", env!("CARGO_PKG_VERSION"));
    info!("Log level: {}", effective_log_level);
    info!("Modes: classic={} secure={} tls={}",
        config.general.modes.classic,
        config.general.modes.secure,
        config.general.modes.tls);
    info!("TLS domain: {}", config.censorship.tls_domain);
    info!("Mask: {} -> {}:{}",
        config.censorship.mask,
        config.censorship.mask_host.as_deref().unwrap_or(&config.censorship.tls_domain),
        config.censorship.mask_port);

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

    // ---- Startup DC Ping ----
    println!("=== Telegram DC Connectivity ===");
    let ping_results = upstream_manager.ping_all_dcs(prefer_ipv6).await;
    for upstream_result in &ping_results {
        println!("  via {}", upstream_result.upstream_name);
        for dc in &upstream_result.results {
            match (&dc.rtt_ms, &dc.error) {
                (Some(rtt), _) => {
                    println!("    DC{} ({:>21}):  {:.0}ms", dc.dc_idx, dc.dc_addr, rtt);
                }
                (None, Some(err)) => {
                    println!("    DC{} ({:>21}):  FAIL ({})", dc.dc_idx, dc.dc_addr, err);
                }
                _ => {
                    println!("    DC{} ({:>21}):  FAIL", dc.dc_idx, dc.dc_addr);
                }
            }
        }
    }
    println!("================================");

    // ---- Background: Upstream Health Checks ----
    let um_health = upstream_manager.clone();
    tokio::spawn(async move { um_health.run_health_checks(prefer_ipv6).await; });

    // ---- Background: Replay Checker Cleanup ----
    let rc_cleanup = replay_checker.clone();
    tokio::spawn(async move { rc_cleanup.run_periodic_cleanup().await; });

    // ---- Detect Public IPs ----
    let detected_ip = detect_ip().await;
    debug!("Detected IPs: v4={:?} v6={:?}", detected_ip.ipv4, detected_ip.ipv6);
    let ip_info = Arc::new(detected_ip.clone());

    // ---- Middle Proxy Pool ----
    let middle_pool: Option<Arc<MiddleProxyPool>> = if config.is_middle_proxy_enabled() {
        let middle_config = Arc::new(MiddleProxyConfig::new());

        // Warn about all-zero ad_tag (proxy will work but no channel displayed)
        if let Some(ref tag_hex) = config.general.ad_tag {
            if tag_hex.chars().all(|c| c == '0') {
                warn!("ad_tag is all zeros — get a real one from @mtproxybot for sponsored channel");
            }
        }

        info!(
            ad_tag = config.general.ad_tag.as_deref().unwrap_or("?"),
            "Middle proxy mode ENABLED — ad_tag will be sent to Telegram"
        );

        // Background: update proxy secret + DC lists periodically
        let mc_update = middle_config.clone();
        tokio::spawn(async move { mc_update.run_update_loop().await; });

        // Create pre-handshaked connection pool
        let pool = Arc::new(MiddleProxyPool::new(
            middle_config,
            upstream_manager.clone(),
            ip_info.clone(),
            rng.clone(),
            prefer_ipv6,
        ));

        // Background: replenish pool
        let pool_replenish = pool.clone();
        tokio::spawn(async move { pool_replenish.run_replenish_loop().await; });

        Some(pool)
    } else {
        if config.general.use_middle_proxy {
            warn!("use_middle_proxy=true but ad_tag is missing/invalid — falling back to direct mode");
        }
        info!("Middle proxy mode DISABLED — direct DC connections");
        None
    };

    // ---- Create Listeners ----
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
                    println!("--- Proxy Links ({}) ---", public_ip);
                    for user_name in &config.show_link {
                        if let Some(secret) = config.access.users.get(user_name) {
                            println!("[{}]", user_name);
                            if config.general.modes.classic {
                                println!("  Classic: tg://proxy?server={}&port={}&secret={}",
                                    public_ip, config.server.port, secret);
                            }
                            if config.general.modes.secure {
                                println!("  DD:      tg://proxy?server={}&port={}&secret=dd{}",
                                    public_ip, config.server.port, secret);
                            }
                            if config.general.modes.tls {
                                let domain_hex = hex::encode(&config.censorship.tls_domain);
                                println!("  EE-TLS:  tg://proxy?server={}&port={}&secret=ee{}{}",
                                    public_ip, config.server.port, secret, domain_hex);
                            }
                        } else {
                            warn!("User '{}' in show_link not found", user_name);
                        }
                    }
                    println!("------------------------");
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

    // ---- Accept Loop ----
    for listener in listeners {
        let config = config.clone();
        let stats = stats.clone();
        let upstream_manager = upstream_manager.clone();
        let replay_checker = replay_checker.clone();
        let buffer_pool = buffer_pool.clone();
        let rng = rng.clone();
        let middle_pool = middle_pool.clone();
        let ip_info = ip_info.clone();

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
                        let middle_pool = middle_pool.clone();
                        let ip_info = ip_info.clone();

                        tokio::spawn(async move {
                            if let Err(e) = ClientHandler::new(
                                stream, peer_addr, config, stats,
                                upstream_manager, replay_checker, buffer_pool, rng,
                                middle_pool, ip_info,
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

    // ---- Graceful Shutdown ----
    match signal::ctrl_c().await {
        Ok(()) => info!("Shutting down..."),
        Err(e) => error!("Signal error: {}", e),
    }

    Ok(())
}