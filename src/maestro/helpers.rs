#![allow(clippy::items_after_test_module)]

use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::cli;
use crate::config::ProxyConfig;
use crate::logging::LogDestination;
use crate::transport::UpstreamManager;
use crate::transport::middle_proxy::{
    ProxyConfigData, fetch_proxy_config_with_raw_via_upstream, load_proxy_config_cache,
    save_proxy_config_cache,
};

pub(crate) fn resolve_runtime_config_path(
    config_path_cli: &str,
    startup_cwd: &std::path::Path,
    config_path_explicit: bool,
) -> PathBuf {
    if config_path_explicit {
        let raw = PathBuf::from(config_path_cli);
        let absolute = if raw.is_absolute() {
            raw
        } else {
            startup_cwd.join(raw)
        };
        return absolute.canonicalize().unwrap_or(absolute);
    }

    let etc_telemt = std::path::Path::new("/etc/telemt");
    let candidates = [
        startup_cwd.join("config.toml"),
        startup_cwd.join("telemt.toml"),
        etc_telemt.join("telemt.toml"),
        etc_telemt.join("config.toml"),
    ];
    for candidate in candidates {
        if candidate.is_file() {
            return candidate.canonicalize().unwrap_or(candidate);
        }
    }

    startup_cwd.join("config.toml")
}

/// Parsed CLI arguments.
pub(crate) struct CliArgs {
    pub config_path: String,
    pub config_path_explicit: bool,
    pub data_path: Option<PathBuf>,
    pub silent: bool,
    pub log_level: Option<String>,
    pub log_destination: LogDestination,
}

pub(crate) fn parse_cli() -> CliArgs {
    let mut config_path = "config.toml".to_string();
    let mut config_path_explicit = false;
    let mut data_path: Option<PathBuf> = None;
    let mut silent = false;
    let mut log_level: Option<String> = None;

    let args: Vec<String> = std::env::args().skip(1).collect();

    // Parse log destination
    let log_destination = crate::logging::parse_log_destination(&args);

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
                data_path = Some(PathBuf::from(
                    s.trim_start_matches("--data-path=").to_string(),
                ));
            }
            "--working-dir" => {
                i += 1;
                if i < args.len() {
                    data_path = Some(PathBuf::from(args[i].clone()));
                } else {
                    eprintln!("Missing value for --working-dir");
                    std::process::exit(0);
                }
            }
            s if s.starts_with("--working-dir=") => {
                data_path = Some(PathBuf::from(
                    s.trim_start_matches("--working-dir=").to_string(),
                ));
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
                print_help();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("telemt {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            // Skip daemon-related flags (already parsed)
            "--daemon" | "-d" | "--foreground" | "-f" => {}
            s if s.starts_with("--pid-file") => {
                if !s.contains('=') {
                    i += 1; // skip value
                }
            }
            s if s.starts_with("--run-as-user") => {
                if !s.contains('=') {
                    i += 1;
                }
            }
            s if s.starts_with("--run-as-group") => {
                if !s.contains('=') {
                    i += 1;
                }
            }
            s if !s.starts_with('-') => {
                if !matches!(s, "run" | "start" | "stop" | "reload" | "status") {
                    config_path = s.to_string();
                    config_path_explicit = true;
                }
            }
            other => {
                eprintln!("Unknown option: {}", other);
            }
        }
        i += 1;
    }

    CliArgs {
        config_path,
        config_path_explicit,
        data_path,
        silent,
        log_level,
        log_destination,
    }
}

fn print_help() {
    eprintln!("Usage: telemt [COMMAND] [OPTIONS] [config.toml]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  run                     Run in foreground (default if no command given)");
    #[cfg(unix)]
    {
        eprintln!("  start                   Start as background daemon");
        eprintln!("  stop                    Stop a running daemon");
        eprintln!("  reload                  Reload configuration (send SIGHUP)");
        eprintln!("  status                  Check if daemon is running");
    }
    eprintln!();
    eprintln!("Options:");
    eprintln!(
        "  --data-path <DIR>       Set data directory (absolute path; overrides config value)"
    );
    eprintln!("  --working-dir <DIR>     Alias for --data-path");
    eprintln!("  --silent, -s            Suppress info logs");
    eprintln!("  --log-level <LEVEL>     debug|verbose|normal|silent");
    eprintln!("  --help, -h              Show this help");
    eprintln!("  --version, -V           Show version");
    eprintln!();
    eprintln!("Logging options:");
    eprintln!("  --log-file <PATH>       Log to file (default: stderr)");
    eprintln!("  --log-file-daily <PATH> Log to file with daily rotation");
    #[cfg(unix)]
    eprintln!("  --syslog                Log to syslog (Unix only)");
    eprintln!();
    #[cfg(unix)]
    {
        eprintln!("Daemon options (Unix only):");
        eprintln!("  --daemon, -d            Fork to background (daemonize)");
        eprintln!("  --foreground, -f        Explicit foreground mode (for systemd)");
        eprintln!("  --pid-file <PATH>       PID file path (default: /var/run/telemt.pid)");
        eprintln!("  --run-as-user <USER>    Drop privileges to this user after binding");
        eprintln!("  --run-as-group <GROUP>  Drop privileges to this group after binding");
        eprintln!("  --working-dir <DIR>     Working directory for daemon mode");
        eprintln!();
    }
    eprintln!("Setup (fire-and-forget):");
    eprintln!("  --init                  Generate config, install systemd service, start");
    eprintln!("    --port <PORT>          Listen port (default: 443)");
    eprintln!("    --domain <DOMAIN>      TLS domain for masking (default: www.google.com)");
    eprintln!("    --secret <HEX>         32-char hex secret (auto-generated if omitted)");
    eprintln!("    --user <NAME>          Username (default: user)");
    eprintln!("    --config-dir <DIR>     Config directory (default: /etc/telemt)");
    eprintln!("    --no-start             Don't start the service after install");
    #[cfg(unix)]
    {
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  telemt config.toml                    Run in foreground");
        eprintln!("  telemt start config.toml              Start as daemon");
        eprintln!("  telemt start --pid-file /tmp/t.pid    Start with custom PID file");
        eprintln!("  telemt stop                           Stop daemon");
        eprintln!("  telemt reload                         Reload configuration");
        eprintln!("  telemt status                         Check daemon status");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        expected_handshake_close_description, is_expected_handshake_eof, peer_close_description,
        resolve_runtime_config_path,
    };
    use crate::error::{ProxyError, StreamError};

    #[test]
    fn resolve_runtime_config_path_anchors_relative_to_startup_cwd() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let startup_cwd = std::env::temp_dir().join(format!("telemt_cfg_path_{nonce}"));
        std::fs::create_dir_all(&startup_cwd).unwrap();
        let target = startup_cwd.join("config.toml");
        std::fs::write(&target, " ").unwrap();

        let resolved = resolve_runtime_config_path("config.toml", &startup_cwd, true);
        assert_eq!(resolved, target.canonicalize().unwrap());

        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_dir(&startup_cwd);
    }

    #[test]
    fn resolve_runtime_config_path_keeps_absolute_for_missing_file() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let startup_cwd = std::env::temp_dir().join(format!("telemt_cfg_path_missing_{nonce}"));
        std::fs::create_dir_all(&startup_cwd).unwrap();

        let resolved = resolve_runtime_config_path("missing.toml", &startup_cwd, true);
        assert_eq!(resolved, startup_cwd.join("missing.toml"));

        let _ = std::fs::remove_dir(&startup_cwd);
    }

    #[test]
    fn resolve_runtime_config_path_uses_startup_candidates_when_not_explicit() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let startup_cwd =
            std::env::temp_dir().join(format!("telemt_cfg_startup_candidates_{nonce}"));
        std::fs::create_dir_all(&startup_cwd).unwrap();
        let telemt = startup_cwd.join("telemt.toml");
        std::fs::write(&telemt, " ").unwrap();

        let resolved = resolve_runtime_config_path("config.toml", &startup_cwd, false);
        assert_eq!(resolved, telemt.canonicalize().unwrap());

        let _ = std::fs::remove_file(&telemt);
        let _ = std::fs::remove_dir(&startup_cwd);
    }

    #[test]
    fn resolve_runtime_config_path_defaults_to_startup_config_when_none_found() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let startup_cwd = std::env::temp_dir().join(format!("telemt_cfg_startup_default_{nonce}"));
        std::fs::create_dir_all(&startup_cwd).unwrap();

        let resolved = resolve_runtime_config_path("config.toml", &startup_cwd, false);
        assert_eq!(resolved, startup_cwd.join("config.toml"));

        let _ = std::fs::remove_dir(&startup_cwd);
    }

    #[test]
    fn expected_handshake_eof_matches_connection_reset() {
        let err = ProxyError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
        assert!(is_expected_handshake_eof(&err));
    }

    #[test]
    fn expected_handshake_eof_matches_stream_io_unexpected_eof() {
        let err = ProxyError::Stream(StreamError::Io(std::io::Error::from(
            std::io::ErrorKind::UnexpectedEof,
        )));
        assert!(is_expected_handshake_eof(&err));
    }

    #[test]
    fn peer_close_description_is_human_readable_for_all_peer_close_kinds() {
        let cases = [
            (
                std::io::ErrorKind::ConnectionReset,
                "Peer reset TCP connection (RST)",
            ),
            (
                std::io::ErrorKind::ConnectionAborted,
                "Peer aborted TCP connection during transport",
            ),
            (
                std::io::ErrorKind::BrokenPipe,
                "Peer closed write side (broken pipe)",
            ),
            (
                std::io::ErrorKind::NotConnected,
                "Socket was already closed by peer",
            ),
        ];

        for (kind, expected) in cases {
            let err = ProxyError::Io(std::io::Error::from(kind));
            assert_eq!(peer_close_description(&err), Some(expected));
        }
    }

    #[test]
    fn handshake_close_description_is_human_readable_for_all_expected_kinds() {
        let cases = [
            (
                ProxyError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
                "Peer closed before sending full 64-byte MTProto handshake",
            ),
            (
                ProxyError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
                "Peer reset TCP connection during initial MTProto handshake",
            ),
            (
                ProxyError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionAborted)),
                "Peer aborted TCP connection during initial MTProto handshake",
            ),
            (
                ProxyError::Io(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
                "Peer closed write side before MTProto handshake completed",
            ),
            (
                ProxyError::Io(std::io::Error::from(std::io::ErrorKind::NotConnected)),
                "Handshake socket was already closed by peer",
            ),
            (
                ProxyError::Stream(StreamError::UnexpectedEof),
                "Peer closed before sending full 64-byte MTProto handshake",
            ),
        ];

        for (err, expected) in cases {
            assert_eq!(expected_handshake_close_description(&err), Some(expected));
        }
    }
}

pub(crate) fn print_proxy_links(host: &str, port: u16, config: &ProxyConfig) {
    info!(target: "telemt::links", "--- Proxy Links ({}) ---", host);
    for user_name in config
        .general
        .links
        .show
        .resolve_users(&config.access.users)
    {
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
    expected_handshake_close_description(err).is_some()
}

pub(crate) fn peer_close_description(err: &crate::error::ProxyError) -> Option<&'static str> {
    fn from_kind(kind: std::io::ErrorKind) -> Option<&'static str> {
        match kind {
            std::io::ErrorKind::ConnectionReset => Some("Peer reset TCP connection (RST)"),
            std::io::ErrorKind::ConnectionAborted => {
                Some("Peer aborted TCP connection during transport")
            }
            std::io::ErrorKind::BrokenPipe => Some("Peer closed write side (broken pipe)"),
            std::io::ErrorKind::NotConnected => Some("Socket was already closed by peer"),
            _ => None,
        }
    }

    match err {
        crate::error::ProxyError::Io(ioe) => from_kind(ioe.kind()),
        crate::error::ProxyError::Stream(crate::error::StreamError::Io(ioe)) => {
            from_kind(ioe.kind())
        }
        _ => None,
    }
}

pub(crate) fn expected_handshake_close_description(
    err: &crate::error::ProxyError,
) -> Option<&'static str> {
    fn from_kind(kind: std::io::ErrorKind) -> Option<&'static str> {
        match kind {
            std::io::ErrorKind::UnexpectedEof => {
                Some("Peer closed before sending full 64-byte MTProto handshake")
            }
            std::io::ErrorKind::ConnectionReset => {
                Some("Peer reset TCP connection during initial MTProto handshake")
            }
            std::io::ErrorKind::ConnectionAborted => {
                Some("Peer aborted TCP connection during initial MTProto handshake")
            }
            std::io::ErrorKind::BrokenPipe => {
                Some("Peer closed write side before MTProto handshake completed")
            }
            std::io::ErrorKind::NotConnected => Some("Handshake socket was already closed by peer"),
            _ => None,
        }
    }

    match err {
        crate::error::ProxyError::Io(ioe) => from_kind(ioe.kind()),
        crate::error::ProxyError::Stream(crate::error::StreamError::UnexpectedEof) => {
            Some("Peer closed before sending full 64-byte MTProto handshake")
        }
        crate::error::ProxyError::Stream(crate::error::StreamError::Io(ioe)) => {
            from_kind(ioe.kind())
        }
        _ => None,
    }
}

pub(crate) async fn load_startup_proxy_config_snapshot(
    url: &str,
    cache_path: Option<&str>,
    me2dc_fallback: bool,
    label: &'static str,
    upstream: Option<std::sync::Arc<UpstreamManager>>,
) -> Option<ProxyConfigData> {
    loop {
        match fetch_proxy_config_with_raw_via_upstream(url, upstream.clone()).await {
            Ok((cfg, raw)) => {
                if !cfg.map.is_empty() {
                    if let Some(path) = cache_path
                        && let Err(e) = save_proxy_config_cache(path, &raw).await
                    {
                        warn!(error = %e, path, snapshot = label, "Failed to store startup proxy-config cache");
                    }
                    return Some(cfg);
                }

                warn!(
                    snapshot = label,
                    url, "Startup proxy-config is empty; trying disk cache"
                );
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
                                path, "Startup proxy-config cache is empty; ignoring cache file"
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
                                path, "Startup proxy-config cache is empty; ignoring cache file"
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
