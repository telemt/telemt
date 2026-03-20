use std::time::Duration;
use std::path::PathBuf;

use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::cli;
use crate::config::ProxyConfig;
use crate::transport::middle_proxy::{
    ProxyConfigData, fetch_proxy_config_with_raw, load_proxy_config_cache, save_proxy_config_cache,
};

pub(crate) fn parse_cli() -> (String, Option<PathBuf>, bool, Option<String>) {
    let mut config_path = "config.toml".to_string();
    let mut data_path: Option<PathBuf> = None;
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
            "--data-path" => {
                i += 1;
                if i < args.len() {
                    data_path = Some(PathBuf::from(args[i].clone()));
                } else {
                    eprintln!("Missing value for --data-path");
                    std::process::exit(0);
                }
            }
            s if s.starts_with("--data-path=") => {
                data_path = Some(PathBuf::from(s.trim_start_matches("--data-path=").to_string()));
            }
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
                eprintln!("  --data-path <DIR>       Set data directory (absolute path; overrides config value)");
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

    (config_path, data_path, silent, log_level)
}

pub(crate) fn print_proxy_links(host: &str, port: u16, config: &ProxyConfig) {
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

pub(crate) async fn write_beobachten_snapshot(path: &str, payload: &str) -> std::io::Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(path, payload).await
}

pub(crate) fn unit_label(value: u64, singular: &'static str, plural: &'static str) -> &'static str {
    if value == 1 { singular } else { plural }
}

pub(crate) fn format_uptime(total_secs: u64) -> String {
    const SECS_PER_MINUTE: u64 = 60;
    const SECS_PER_HOUR: u64 = 60 * SECS_PER_MINUTE;
    const SECS_PER_DAY: u64 = 24 * SECS_PER_HOUR;
    const SECS_PER_MONTH: u64 = 30 * SECS_PER_DAY;
    const SECS_PER_YEAR: u64 = 12 * SECS_PER_MONTH;

    let mut remaining = total_secs;
    let years = remaining / SECS_PER_YEAR;
    remaining %= SECS_PER_YEAR;
    let months = remaining / SECS_PER_MONTH;
    remaining %= SECS_PER_MONTH;
    let days = remaining / SECS_PER_DAY;
    remaining %= SECS_PER_DAY;
    let hours = remaining / SECS_PER_HOUR;
    remaining %= SECS_PER_HOUR;
    let minutes = remaining / SECS_PER_MINUTE;
    let seconds = remaining % SECS_PER_MINUTE;

    let mut parts = Vec::new();
    if total_secs > SECS_PER_YEAR {
        parts.push(format!("{} {}", years, unit_label(years, "year", "years")));
    }
    if total_secs > SECS_PER_MONTH {
        parts.push(format!(
            "{} {}",
            months,
            unit_label(months, "month", "months")
        ));
    }
    if total_secs > SECS_PER_DAY {
        parts.push(format!("{} {}", days, unit_label(days, "day", "days")));
    }
    if total_secs > SECS_PER_HOUR {
        parts.push(format!("{} {}", hours, unit_label(hours, "hour", "hours")));
    }
    if total_secs > SECS_PER_MINUTE {
        parts.push(format!(
            "{} {}",
            minutes,
            unit_label(minutes, "minute", "minutes")
        ));
    }
    parts.push(format!(
        "{} {}",
        seconds,
        unit_label(seconds, "second", "seconds")
    ));

    format!("{} / {} seconds", parts.join(", "), total_secs)
}

#[allow(dead_code)]
pub(crate) async fn wait_until_admission_open(admission_rx: &mut watch::Receiver<bool>) -> bool {
    loop {
        if *admission_rx.borrow() {
            return true;
        }
        if admission_rx.changed().await.is_err() {
            return *admission_rx.borrow();
        }
    }
}

pub(crate) fn is_expected_handshake_eof(err: &crate::error::ProxyError) -> bool {
    err.to_string().contains("expected 64 bytes, got 0")
}

pub(crate) async fn load_startup_proxy_config_snapshot(
    url: &str,
    cache_path: Option<&str>,
    me2dc_fallback: bool,
    label: &'static str,
) -> Option<ProxyConfigData> {
    loop {
        match fetch_proxy_config_with_raw(url).await {
            Ok((cfg, raw)) => {
                if !cfg.map.is_empty() {
                    if let Some(path) = cache_path
                        && let Err(e) = save_proxy_config_cache(path, &raw).await
                    {
                        warn!(error = %e, path, snapshot = label, "Failed to store startup proxy-config cache");
                    }
                    return Some(cfg);
                }

                warn!(snapshot = label, url, "Startup proxy-config is empty; trying disk cache");
                if let Some(path) = cache_path {
                    match load_proxy_config_cache(path).await {
                        Ok(cached) if !cached.map.is_empty() => {
                            info!(
                                snapshot = label,
                                path,
                                proxy_for_lines = cached.proxy_for_lines,
                                "Loaded startup proxy-config from disk cache"
                            );
                            return Some(cached);
                        }
                        Ok(_) => {
                            warn!(
                                snapshot = label,
                                path,
                                "Startup proxy-config cache is empty; ignoring cache file"
                            );
                        }
                        Err(cache_err) => {
                            debug!(
                                snapshot = label,
                                path,
                                error = %cache_err,
                                "Startup proxy-config cache unavailable"
                            );
                        }
                    }
                }

                if me2dc_fallback {
                    error!(
                        snapshot = label,
                        "Startup proxy-config unavailable and no saved config found; falling back to direct mode"
                    );
                    return None;
                }

                warn!(
                    snapshot = label,
                    retry_in_secs = 2,
                    "Startup proxy-config unavailable and no saved config found; retrying because me2dc_fallback=false"
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(fetch_err) => {
                if let Some(path) = cache_path {
                    match load_proxy_config_cache(path).await {
                        Ok(cached) if !cached.map.is_empty() => {
                            info!(
                                snapshot = label,
                                path,
                                proxy_for_lines = cached.proxy_for_lines,
                                "Loaded startup proxy-config from disk cache"
                            );
                            return Some(cached);
                        }
                        Ok(_) => {
                            warn!(
                                snapshot = label,
                                path,
                                "Startup proxy-config cache is empty; ignoring cache file"
                            );
                        }
                        Err(cache_err) => {
                            debug!(
                                snapshot = label,
                                path,
                                error = %cache_err,
                                "Startup proxy-config cache unavailable"
                            );
                        }
                    }
                }

                if me2dc_fallback {
                    error!(
                        snapshot = label,
                        error = %fetch_err,
                        "Startup proxy-config unavailable and no cached data; falling back to direct mode"
                    );
                    return None;
                }

                warn!(
                    snapshot = label,
                    error = %fetch_err,
                    retry_in_secs = 2,
                    "Startup proxy-config unavailable; retrying because me2dc_fallback=false"
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}
