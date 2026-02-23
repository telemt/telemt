//! telemt — Telegram MTProto Proxy

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use rand::Rng;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*, reload};
#[cfg(unix)]
use tokio::net::UnixListener;

mod cli;
mod config;
mod crypto;
mod error;
mod ip_tracker;
mod network;
mod metrics;
mod protocol;
mod proxy;
mod stats;
mod stream;
mod transport;
mod tls_front;
mod util;

use crate::config::{LogLevel, ProxyConfig};
use crate::config::hot_reload::spawn_config_watcher;
use crate::crypto::SecureRandom;
use crate::ip_tracker::UserIpTracker;
use crate::network::probe::{decide_network_capabilities, log_probe_result, run_probe};
use crate::proxy::ClientHandler;
use crate::stats::{ReplayChecker, Stats};
use crate::stream::BufferPool;
use crate::transport::middle_proxy::{
    MePool, fetch_proxy_config, run_me_ping, MePingFamily, MePingSample, format_sample_line,
};
use crate::transport::{ListenOptions, UpstreamManager, create_listener, find_listener_processes};
use crate::tls_front::TlsFrontCache;

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
            "--silent" | "-s" => {
                silent = true;
            }
            "--log-level" => {
                i += 1;
                if i < args.len() {
                    log_level = Some(args[i].clone());
                }
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
                eprintln!(
                    "  --init                  Generate config, install systemd service, start"
                );
                eprintln!("    --port <PORT>          Listen port (default: 443)");
                eprintln!(
                    "    --domain <DOMAIN>      TLS domain for masking (default: www.google.com)"
                );
                eprintln!(
                    "    --secret <HEX>         32-char hex secret (auto-generated if omitted)"
                );
                eprintln!("    --user <NAME>          Username (default: user)");
                eprintln!("    --config-dir <DIR>     Config directory (default: /etc/telemt)");
                eprintln!("    --no-start             Don't start the service after install");
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("telemt {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            s if !s.starts_with('-') => {
                config_path = s.to_string();
            }
            other => {
                eprintln!("Unknown option: {}", other);
            }
        }
        i += 1;
    }

    (config_path, silent, log_level)
}

fn print_proxy_links(host: &str, port: u16, config: &ProxyConfig) {
    info!(target: "telemt::links", "--- Proxy Links ({}) ---", host);
    for user_name in config.general.links.show.resolve_users(&config.access.users) {
        if let Some(secret) = config.access.users.get(user_name) {
            info!(target: "telemt::links", "User: {}", user_name);
            if config.general.modes.classic {
                info!(
                    target: "telemt::links",
                    "  Classic: tg://proxy?server={}&port={}&secret={}",
                    host, port, secret
                );
            }
            if config.general.modes.secure {
                info!(
                    target: "telemt::links",
                    "  DD:      tg://proxy?server={}&port={}&secret=dd{}",
                    host, port, secret
                );
            }
            if config.general.modes.tls {
                let mut domains = Vec::with_capacity(1 + config.censorship.tls_domains.len());
                domains.push(config.censorship.tls_domain.clone());
                for d in &config.censorship.tls_domains {
                    if !domains.contains(d) {
                        domains.push(d.clone());
                    }
                }

                for domain in domains {
                    let domain_hex = hex::encode(&domain);
                    info!(
                        target: "telemt::links",
                        "  EE-TLS:  tg://proxy?server={}&port={}&secret=ee{}{}",
                        host, port, secret, domain_hex
                    );
                }
            }
        } else {
            warn!(target: "telemt::links", "User '{}' in show_link not found", user_name);
        }
    }
    info!(target: "telemt::links", "------------------------");
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (config_path, cli_silent, cli_log_level) = parse_cli();

    let mut config = match ProxyConfig::load(&config_path) {
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

    let (filter_layer, filter_handle) = reload::Layer::new(EnvFilter::new("info"));
    
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

    let probe = run_probe(
        &config.network,
        config.general.middle_proxy_nat_stun.clone(),
        config.general.middle_proxy_nat_probe,
    )
    .await?;
    let decision = decide_network_capabilities(&config.network, &probe);
    log_probe_result(&probe, &decision);

    let prefer_ipv6 = decision.prefer_ipv6();
    let mut use_middle_proxy = config.general.use_middle_proxy && (decision.ipv4_me || decision.ipv6_me);
    let stats = Arc::new(Stats::new());
    let rng = Arc::new(SecureRandom::new());

    // IP Tracker initialization
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.load_limits(&config.access.user_max_unique_ips).await;
    
    if !config.access.user_max_unique_ips.is_empty() {
        info!("IP limits configured for {} users", config.access.user_max_unique_ips.len());
    }

    // Connection concurrency limit
    let max_connections = Arc::new(Semaphore::new(10_000));

    if use_middle_proxy && !decision.ipv4_me && !decision.ipv6_me {
        warn!("No usable IP family for Middle Proxy detected; falling back to direct DC");
        use_middle_proxy = false;
    }

    // =====================================================================
    // Middle Proxy initialization (if enabled)
    // =====================================================================
    let me_pool: Option<Arc<MePool>> = if use_middle_proxy {
        info!("=== Middle Proxy Mode ===");

        // ad_tag (proxy_tag) for advertising
        let proxy_tag = config.general.ad_tag.as_ref().map(|tag| {
            hex::decode(tag).unwrap_or_else(|_| {
                warn!("Invalid ad_tag hex, middle proxy ad_tag will be empty");
                Vec::new()
            })
        });

        // =============================================================
        // CRITICAL: Download Telegram proxy-secret (NOT user secret!)
        //
        // C MTProxy uses TWO separate secrets:
        //   -S flag    = 16-byte user secret for client obfuscation
        //   --aes-pwd  = 32-512 byte binary file for ME RPC auth
        //
        // proxy-secret is from: https://core.telegram.org/getProxySecret
        // =============================================================
        let proxy_secret_path = config.general.proxy_secret_path.as_deref();
match crate::transport::middle_proxy::fetch_proxy_secret(proxy_secret_path).await {
    Ok(proxy_secret) => {
        info!(
            secret_len = proxy_secret.len() as usize,  // ← ЯВНЫЙ ТИП usize
            key_sig = format_args!(
                "0x{:08x}",
                if proxy_secret.len() >= 4 {
                    u32::from_le_bytes([
                        proxy_secret[0],
                        proxy_secret[1],
                        proxy_secret[2],
                        proxy_secret[3],
                    ])
                } else {
                    0
                }
            ),
            "Proxy-secret loaded"
        );

                // Load ME config (v4/v6) + default DC
                let mut cfg_v4 = fetch_proxy_config(
                    "https://core.telegram.org/getProxyConfig",
                )
                .await
                .unwrap_or_default();
                let mut cfg_v6 = fetch_proxy_config(
                    "https://core.telegram.org/getProxyConfigV6",
                )
                .await
                .unwrap_or_default();

                if cfg_v4.map.is_empty() {
                    cfg_v4.map = crate::protocol::constants::TG_MIDDLE_PROXIES_V4.clone();
                }
                if cfg_v6.map.is_empty() {
                    cfg_v6.map = crate::protocol::constants::TG_MIDDLE_PROXIES_V6.clone();
                }

                let pool = MePool::new(
                    proxy_tag,
                    proxy_secret,
                    config.general.middle_proxy_nat_ip,
                    config.general.middle_proxy_nat_probe,
                    config.general.middle_proxy_nat_stun.clone(),
                    config.general.middle_proxy_nat_stun_servers.clone(),
                    probe.detected_ipv6,
                    config.timeouts.me_one_retry,
                    config.timeouts.me_one_timeout_ms,
                    cfg_v4.map.clone(),
                    cfg_v6.map.clone(),
                    cfg_v4.default_dc.or(cfg_v6.default_dc),
                    decision.clone(),
                    rng.clone(),
                    stats.clone(),
                    config.general.me_keepalive_enabled,
                    config.general.me_keepalive_interval_secs,
                    config.general.me_keepalive_jitter_secs,
                    config.general.me_keepalive_payload_random,
                    config.general.me_warmup_stagger_enabled,
                    config.general.me_warmup_step_delay_ms,
                    config.general.me_warmup_step_jitter_ms,
                    config.general.me_reconnect_max_concurrent_per_dc,
                    config.general.me_reconnect_backoff_base_ms,
                    config.general.me_reconnect_backoff_cap_ms,
                    config.general.me_reconnect_fast_retry_count,
                );

                let pool_size = config.general.middle_proxy_pool_size.max(1);
                match pool.init(pool_size, &rng).await {
                    Ok(()) => {
                        info!("Middle-End pool initialized successfully");

                        // Phase 4: Start health monitor
                        let pool_clone = pool.clone();
                        let rng_clone = rng.clone();
                        let min_conns = pool_size;
                        tokio::spawn(async move {
                            crate::transport::middle_proxy::me_health_monitor(
                                pool_clone, rng_clone, min_conns,
                            )
                            .await;
                        });

                        // Periodic ME connection rotation
                        let pool_clone_rot = pool.clone();
                        let rng_clone_rot = rng.clone();
                        tokio::spawn(async move {
                            crate::transport::middle_proxy::me_rotation_task(
                                pool_clone_rot,
                                rng_clone_rot,
                                std::time::Duration::from_secs(1800),
                            )
                            .await;
                        });

                        // Periodic updater: getProxyConfig + proxy-secret
                        let pool_clone2 = pool.clone();
                        let rng_clone2 = rng.clone();
                        tokio::spawn(async move {
                            crate::transport::middle_proxy::me_config_updater(
                                pool_clone2,
                                rng_clone2,
                                std::time::Duration::from_secs(12 * 3600),
                            )
                            .await;
                        });

                        Some(pool)
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to initialize ME pool. Falling back to direct mode.");
                        None
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to fetch proxy-secret. Falling back to direct mode.");
                None
            }
        }
    } else {
        None
    };

    // If ME failed to initialize, force direct-only mode.
    if me_pool.is_some() {
        info!("Transport: Middle-End Proxy - all DC-over-RPC");
    } else {
        use_middle_proxy = false;
        // Make runtime config reflect direct-only mode for handlers.
        config.general.use_middle_proxy = false;
        info!("Transport: Direct DC - TCP - standard DC-over-TCP");
    }

    // Freeze config after possible fallback decision
    let config = Arc::new(config);

    let replay_checker = Arc::new(ReplayChecker::new(
        config.access.replay_check_len,
        Duration::from_secs(config.access.replay_window_secs),
    ));

    let upstream_manager = Arc::new(UpstreamManager::new(config.upstreams.clone()));
    let buffer_pool = Arc::new(BufferPool::with_config(16 * 1024, 4096));

    // TLS front cache (optional emulation)
    let mut tls_domains = Vec::with_capacity(1 + config.censorship.tls_domains.len());
    tls_domains.push(config.censorship.tls_domain.clone());
    for d in &config.censorship.tls_domains {
        if !tls_domains.contains(d) {
            tls_domains.push(d.clone());
        }
    }

    let tls_cache: Option<Arc<TlsFrontCache>> = if config.censorship.tls_emulation {
        let cache = Arc::new(TlsFrontCache::new(
            &tls_domains,
            config.censorship.fake_cert_len,
            &config.censorship.tls_front_dir,
        ));

        cache.load_from_disk().await;

        let port = config.censorship.mask_port;
        let mask_host = config.censorship.mask_host.clone()
            .unwrap_or_else(|| config.censorship.tls_domain.clone());
        // Initial synchronous fetch to warm cache before serving clients.
        for domain in tls_domains.clone() {
            match crate::tls_front::fetcher::fetch_real_tls(
                &mask_host,
                port,
                &domain,
                Duration::from_secs(5),
                Some(upstream_manager.clone()),
            )
            .await
            {
                Ok(res) => cache.update_from_fetch(&domain, res).await,
                Err(e) => warn!(domain = %domain, error = %e, "TLS emulation fetch failed"),
            }
        }

        // Periodic refresh with jitter.
        let cache_clone = cache.clone();
        let domains = tls_domains.clone();
        let upstream_for_task = upstream_manager.clone();
        tokio::spawn(async move {
            loop {
                let base_secs = rand::rng().random_range(4 * 3600..=6 * 3600);
                let jitter_secs = rand::rng().random_range(0..=7200);
                tokio::time::sleep(Duration::from_secs(base_secs + jitter_secs)).await;
                for domain in &domains {
                    match crate::tls_front::fetcher::fetch_real_tls(
                        &mask_host,
                        port,
                        domain,
                        Duration::from_secs(5),
                        Some(upstream_for_task.clone()),
                    )
                    .await
                    {
                        Ok(res) => cache_clone.update_from_fetch(domain, res).await,
                        Err(e) => warn!(domain = %domain, error = %e, "TLS emulation refresh failed"),
                    }
                }
            }
        });

        Some(cache)
    } else {
        None
    };

    // Middle-End ping before DC connectivity
    if let Some(ref pool) = me_pool {
        let me_results = run_me_ping(pool, &rng).await;

        let v4_ok = me_results.iter().any(|r| {
            matches!(r.family, MePingFamily::V4)
                && r.samples.iter().any(|s| s.error.is_none() && s.handshake_ms.is_some())
        });
        let v6_ok = me_results.iter().any(|r| {
            matches!(r.family, MePingFamily::V6)
                && r.samples.iter().any(|s| s.error.is_none() && s.handshake_ms.is_some())
        });

        info!("================= Telegram ME Connectivity =================");
        if v4_ok && v6_ok {
            info!("  IPv4 and IPv6 available");
        } else if v4_ok {
            info!("  IPv4 only / IPv6 unavailable");
        } else if v6_ok {
            info!("  IPv6 only / IPv4 unavailable");
        } else {
            info!("  No ME connectivity");
        }
        info!("  via direct");
        info!("============================================================");

        use std::collections::BTreeMap;
        let mut grouped: BTreeMap<i32, Vec<MePingSample>> = BTreeMap::new();
        for report in me_results {
            for s in report.samples {
                let key = s.dc.abs();
                grouped.entry(key).or_default().push(s);
            }
        }

        let family_order = if prefer_ipv6 {
            vec![(MePingFamily::V6, true), (MePingFamily::V6, false), (MePingFamily::V4, true), (MePingFamily::V4, false)]
        } else {
            vec![(MePingFamily::V4, true), (MePingFamily::V4, false), (MePingFamily::V6, true), (MePingFamily::V6, false)]
        };

        for (dc_abs, samples) in grouped {
            for (family, is_pos) in &family_order {
                let fam_samples: Vec<&MePingSample> = samples
                    .iter()
                    .filter(|s| matches!(s.family, f if &f == family) && (s.dc >= 0) == *is_pos)
                    .collect();
                if fam_samples.is_empty() {
                    continue;
                }

                let fam_label = match family {
                    MePingFamily::V4 => "IPv4",
                    MePingFamily::V6 => "IPv6",
                };
                info!("    DC{} [{}]", dc_abs, fam_label);
                for sample in fam_samples {
                    let line = format_sample_line(sample);
                    info!("{}", line);
                }
            }
        }
        info!("============================================================");
    }

    info!("================= Telegram DC Connectivity =================");

    let ping_results = upstream_manager
        .ping_all_dcs(
            prefer_ipv6,
            &config.dc_overrides,
            decision.ipv4_dc,
            decision.ipv6_dc,
        )
        .await;

	for upstream_result in &ping_results {
		let v6_works = upstream_result
			.v6_results
			.iter()
			.any(|r| r.rtt_ms.is_some());
		let v4_works = upstream_result
			.v4_results
			.iter()
			.any(|r| r.rtt_ms.is_some());
		
		if upstream_result.both_available {
			if prefer_ipv6 {
				info!("  IPv6 in use / IPv4 is fallback");
			} else {
				info!("  IPv4 in use / IPv6 is fallback");
			}
		} else {
			if v6_works && !v4_works {
				info!("  IPv6 only / IPv4 unavailable)");
			} else if v4_works && !v6_works {
				info!("  IPv4 only / IPv6 unavailable)");
			} else if !v6_works && !v4_works {
				info!("  No DC connectivity");
			}
		}

		info!("  via {}", upstream_result.upstream_name);
		info!("============================================================");

		// Print IPv6 results first (only if IPv6 is available)
		if v6_works {
			for dc in &upstream_result.v6_results {
				let addr_str = format!("{}:{}", dc.dc_addr.ip(), dc.dc_addr.port());
				match &dc.rtt_ms {
					Some(rtt) => {
						info!("    DC{} [IPv6] {} - {:.0} ms", dc.dc_idx, addr_str, rtt);
					}
					None => {
						let err = dc.error.as_deref().unwrap_or("fail");
						info!("    DC{} [IPv6] {} - FAIL ({})", dc.dc_idx, addr_str, err);
					}
				}
			}

			info!("============================================================");
		}

		// Print IPv4 results (only if IPv4 is available)
		if v4_works {
			for dc in &upstream_result.v4_results {
				let addr_str = format!("{}:{}", dc.dc_addr.ip(), dc.dc_addr.port());
				match &dc.rtt_ms {
					Some(rtt) => {
						info!(
							"    DC{} [IPv4] {}\t\t\t\t{:.0} ms",
							dc.dc_idx, addr_str, rtt
						);
					}
					None => {
						let err = dc.error.as_deref().unwrap_or("fail");
						info!(
							"    DC{} [IPv4] {}:\t\t\t\tFAIL ({})",
							dc.dc_idx, addr_str, err
						);
					}
				}
			}

			info!("============================================================");
		}
	}

    // Background tasks
    let um_clone = upstream_manager.clone();
    let decision_clone = decision.clone();
    tokio::spawn(async move {
        um_clone
            .run_health_checks(
                prefer_ipv6,
                decision_clone.ipv4_dc,
                decision_clone.ipv6_dc,
            )
            .await;
    });

    let rc_clone = replay_checker.clone();
    tokio::spawn(async move {
        rc_clone.run_periodic_cleanup().await;
    });

    let detected_ip_v4: Option<std::net::IpAddr> = probe
        .reflected_ipv4
        .map(|s| s.ip())
        .or_else(|| probe.detected_ipv4.map(std::net::IpAddr::V4));
    let detected_ip_v6: Option<std::net::IpAddr> = probe
        .reflected_ipv6
        .map(|s| s.ip())
        .or_else(|| probe.detected_ipv6.map(std::net::IpAddr::V6));
    debug!(
        "Detected IPs: v4={:?} v6={:?}",
        detected_ip_v4, detected_ip_v6
    );

    // ── Hot-reload watcher ────────────────────────────────────────────────
    // Uses inotify to detect file changes instantly (SIGHUP also works).
    // detected_ip_v4/v6 are passed so newly added users get correct TG links.
    let (config_rx, mut log_level_rx): (
        tokio::sync::watch::Receiver<Arc<ProxyConfig>>,
        tokio::sync::watch::Receiver<LogLevel>,
    ) = spawn_config_watcher(
        std::path::PathBuf::from(&config_path),
        config.clone(),
        detected_ip_v4,
        detected_ip_v6,
    );

    let mut listeners = Vec::new();

    for listener_conf in &config.server.listeners {
        let addr = SocketAddr::new(listener_conf.ip, config.server.port);
        if addr.is_ipv4() && !decision.ipv4_dc {
            warn!(%addr, "Skipping IPv4 listener: IPv4 disabled by [network]");
            continue;
        }
        if addr.is_ipv6() && !decision.ipv6_dc {
            warn!(%addr, "Skipping IPv6 listener: IPv6 disabled by [network]");
            continue;
        }
        let options = ListenOptions {
            reuse_port: listener_conf.reuse_allow,
            ipv6_only: listener_conf.ip.is_ipv6(),
            ..Default::default()
        };

        match create_listener(addr, &options) {
            Ok(socket) => {
                let listener = TcpListener::from_std(socket.into())?;
                info!("Listening on {}", addr);
                let listener_proxy_protocol =
                    listener_conf.proxy_protocol.unwrap_or(config.server.proxy_protocol);

                // Resolve the public host for link generation
                let public_host = if let Some(ref announce) = listener_conf.announce {
                    announce.clone()  // Use announce (IP or hostname) if explicitly set
                } else if listener_conf.ip.is_unspecified() {
                    // Auto-detect for unspecified addresses
                    if listener_conf.ip.is_ipv4() {
                        detected_ip_v4
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|| listener_conf.ip.to_string())
                    } else {
                        detected_ip_v6
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|| listener_conf.ip.to_string())
                    }
                } else {
                    listener_conf.ip.to_string()
                };

                // Show per-listener proxy links only when public_host is not set
                if config.general.links.public_host.is_none() && !config.general.links.show.is_empty() {
                    let link_port = config.general.links.public_port.unwrap_or(config.server.port);
                    print_proxy_links(&public_host, link_port, &config);
                }

                listeners.push((listener, listener_proxy_protocol));
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::AddrInUse {
                    let owners = find_listener_processes(addr);
                    if owners.is_empty() {
                        error!(
                            %addr,
                            "Failed to bind: address already in use (owner process unresolved)"
                        );
                    } else {
                        for owner in owners {
                            error!(
                                %addr,
                                pid = owner.pid,
                                process = %owner.process,
                                "Failed to bind: address already in use"
                            );
                        }
                    }

                    if !listener_conf.reuse_allow {
                        error!(
                            %addr,
                            "reuse_allow=false; set [[server.listeners]].reuse_allow=true to allow multi-instance listening"
                        );
                    }
                } else {
                    error!("Failed to bind to {}: {}", addr, e);
                }
            }
        }
    }

    // Show proxy links once when public_host is set, OR when there are no TCP listeners
    // (unix-only mode) — use detected IP as fallback
    if !config.general.links.show.is_empty() && (config.general.links.public_host.is_some() || listeners.is_empty()) {
        let (host, port) = if let Some(ref h) = config.general.links.public_host {
            (h.clone(), config.general.links.public_port.unwrap_or(config.server.port))
        } else {
            let ip = detected_ip_v4
                .or(detected_ip_v6)
                .map(|ip| ip.to_string());
            if ip.is_none() {
                warn!("show_link is configured but public IP could not be detected. Set public_host in config.");
            }
            (ip.unwrap_or_else(|| "UNKNOWN".to_string()), config.general.links.public_port.unwrap_or(config.server.port))
        };

        print_proxy_links(&host, port, &config);
    }

    // Unix socket setup (before listeners check so unix-only config works)
    let mut has_unix_listener = false;
    #[cfg(unix)]
    if let Some(ref unix_path) = config.server.listen_unix_sock {
        // Remove stale socket file if present (standard practice)
        let _ = tokio::fs::remove_file(unix_path).await;

        let unix_listener = UnixListener::bind(unix_path)?;

        // Apply socket permissions if configured
        if let Some(ref perm_str) = config.server.listen_unix_sock_perm {
            match u32::from_str_radix(perm_str.trim_start_matches('0'), 8) {
                Ok(mode) => {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(mode);
                    if let Err(e) = std::fs::set_permissions(unix_path, perms) {
                        error!("Failed to set unix socket permissions to {}: {}", perm_str, e);
                    } else {
                        info!("Listening on unix:{} (mode {})", unix_path, perm_str);
                    }
                }
                Err(e) => {
                    warn!("Invalid listen_unix_sock_perm '{}': {}. Ignoring.", perm_str, e);
                    info!("Listening on unix:{}", unix_path);
                }
            }
        } else {
            info!("Listening on unix:{}", unix_path);
        }

        has_unix_listener = true;

        let mut config_rx_unix: tokio::sync::watch::Receiver<Arc<ProxyConfig>> = config_rx.clone();
        let stats = stats.clone();
        let upstream_manager = upstream_manager.clone();
        let replay_checker = replay_checker.clone();
        let buffer_pool = buffer_pool.clone();
        let rng = rng.clone();
        let me_pool = me_pool.clone();
        let tls_cache = tls_cache.clone();
        let ip_tracker = ip_tracker.clone();
        let max_connections_unix = max_connections.clone();

        tokio::spawn(async move {
            let unix_conn_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1));

            loop {
                match unix_listener.accept().await {
                    Ok((stream, _)) => {
                        let permit = match max_connections_unix.clone().acquire_owned().await {
                            Ok(permit) => permit,
                            Err(_) => {
                                error!("Connection limiter is closed");
                                break;
                            }
                        };
                        let conn_id = unix_conn_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let fake_peer = SocketAddr::from(([127, 0, 0, 1], (conn_id % 65535) as u16));

                        let config = config_rx_unix.borrow_and_update().clone();
                        let stats = stats.clone();
                        let upstream_manager = upstream_manager.clone();
                        let replay_checker = replay_checker.clone();
                        let buffer_pool = buffer_pool.clone();
                        let rng = rng.clone();
                        let me_pool = me_pool.clone();
                        let tls_cache = tls_cache.clone();
                        let ip_tracker = ip_tracker.clone();
                        let proxy_protocol_enabled = config.server.proxy_protocol;

                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = crate::proxy::client::handle_client_stream(
                                stream, fake_peer, config, stats,
                                upstream_manager, replay_checker, buffer_pool, rng,
                                me_pool, tls_cache, ip_tracker, proxy_protocol_enabled,
                            ).await {
                                debug!(error = %e, "Unix socket connection error");
                            }
                        });
                    }
                    Err(e) => {
                        error!("Unix socket accept error: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }

    if listeners.is_empty() && !has_unix_listener {
        error!("No listeners. Exiting.");
        std::process::exit(1);
    }

    // Switch to user-configured log level after startup
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

    // Apply log_level changes from hot-reload to the tracing filter.
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

    if let Some(port) = config.server.metrics_port {
        let stats = stats.clone();
        let whitelist = config.server.metrics_whitelist.clone();
        tokio::spawn(async move {
            metrics::serve(port, stats, whitelist).await;
        });
    }

    for (listener, listener_proxy_protocol) in listeners {
        let mut config_rx: tokio::sync::watch::Receiver<Arc<ProxyConfig>> = config_rx.clone();
        let stats = stats.clone();
        let upstream_manager = upstream_manager.clone();
        let replay_checker = replay_checker.clone();
        let buffer_pool = buffer_pool.clone();
        let rng = rng.clone();
        let me_pool = me_pool.clone();
        let tls_cache = tls_cache.clone();
        let ip_tracker = ip_tracker.clone();
        let max_connections_tcp = max_connections.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let permit = match max_connections_tcp.clone().acquire_owned().await {
                            Ok(permit) => permit,
                            Err(_) => {
                                error!("Connection limiter is closed");
                                break;
                            }
                        };
                        let config = config_rx.borrow_and_update().clone();
                        let stats = stats.clone();
                        let upstream_manager = upstream_manager.clone();
                        let replay_checker = replay_checker.clone();
                        let buffer_pool = buffer_pool.clone();
                        let rng = rng.clone();
                        let me_pool = me_pool.clone();
                        let tls_cache = tls_cache.clone();
                        let ip_tracker = ip_tracker.clone();
                        let proxy_protocol_enabled = listener_proxy_protocol;

                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = ClientHandler::new(
                                stream,
                                peer_addr,
                                config,
                                stats,
                                upstream_manager,
                                replay_checker,
                                buffer_pool,
                                rng,
                                me_pool,
                                tls_cache,
                                ip_tracker,
                                proxy_protocol_enabled,
                            )
                            .run()
                            .await
                            {
                                let peer_closed = matches!(
                                    &e,
                                    crate::error::ProxyError::Io(ioe)
                                        if matches!(
                                            ioe.kind(),
                                            std::io::ErrorKind::ConnectionReset
                                                | std::io::ErrorKind::ConnectionAborted
                                                | std::io::ErrorKind::BrokenPipe
                                                | std::io::ErrorKind::NotConnected
                                        )
                                ) || matches!(
                                    &e,
                                    crate::error::ProxyError::Stream(
                                        crate::error::StreamError::Io(ioe)
                                    )
                                        if matches!(
                                            ioe.kind(),
                                            std::io::ErrorKind::ConnectionReset
                                                | std::io::ErrorKind::ConnectionAborted
                                                | std::io::ErrorKind::BrokenPipe
                                                | std::io::ErrorKind::NotConnected
                                        )
                                );

                                let me_closed = matches!(
                                    &e,
                                    crate::error::ProxyError::Proxy(msg) if msg == "ME connection lost"
                                );

                                match (peer_closed, me_closed) {
                                    (true, _) => debug!(peer = %peer_addr, error = %e, "Connection closed by client"),
                                    (_, true) => warn!(peer = %peer_addr, error = %e, "Connection closed: Middle-End dropped session"),
                                    _ => warn!(peer = %peer_addr, error = %e, "Connection closed with error"),
                                }
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
