//! telemt — Telegram MTProto Proxy

#![allow(unused_assignments)]

// Runtime orchestration modules.
// - admission: conditional-cast gate and route mode switching.
// - bootstrap: configuration and tracing initialization.
// - connectivity: startup ME/DC connectivity diagnostics.
// - control_plane: process-owned API, metrics, and signal task lifecycle.
// - generation: runtime generation state and task ownership.
// - helpers: CLI and shared startup/runtime helper routines.
// - listeners: TCP/Unix listener planning, binding, and lifecycle control.
// - me_startup: Middle-End secret/config fetch and pool initialization.
// - orchestrator: process startup, listener activation, and shutdown sequencing.
// - reload: reload command coordination.
// - reload_supervisor: generation and listener transition supervision.
// - runtime_build: reload candidate construction.
// - runtime_startup: initial runtime generation preparation.
// - runtime_tasks: hot-reload and background task orchestration.
// - shutdown: graceful shutdown sequence and uptime logging.
// - tls_bootstrap: TLS front cache bootstrap and refresh tasks.
mod admission;
mod bootstrap;
mod connectivity;
pub(crate) mod control_plane;
pub(crate) mod generation;
mod helpers;
mod listeners;
mod me_startup;
mod orchestrator;
pub(crate) mod reload;
mod reload_supervisor;
pub(crate) mod runtime_build;
mod runtime_startup;
mod runtime_tasks;
mod shutdown;
mod tls_bootstrap;

use tracing::error;

use crate::config::{ProxyConfig, SynLimitMode};

#[cfg(unix)]
use crate::daemon::{DaemonOptions, PidFile, drop_privileges};

/// Runs the full telemt runtime startup pipeline and blocks until shutdown.
///
/// On Unix, daemon options should be handled before calling this function
/// because daemonization must happen before the Tokio runtime starts.
#[cfg(unix)]
pub async fn run_with_daemon(
    daemon_opts: DaemonOptions,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    run_inner(daemon_opts).await
}

/// Runs the full telemt runtime startup pipeline and blocks until shutdown.
///
/// This is the main entry point for non-daemon mode or library callers.
#[allow(dead_code)]
pub async fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let daemon_opts = crate::cli::parse_daemon_args(&args);
        run_inner(daemon_opts).await
    }
    #[cfg(not(unix))]
    {
        run_inner().await
    }
}

fn validate_synlimit_privilege_drop(
    config: &ProxyConfig,
    privilege_drop_requested: bool,
) -> std::io::Result<()> {
    if privilege_drop_requested
        && config
            .server
            .listeners
            .iter()
            .any(|listener| listener.synlimit != SynLimitMode::Off)
    {
        return Err(std::io::Error::other(
            "SYN limiter cannot be combined with --run-as-user or --run-as-group without a privileged firewall helper",
        ));
    }
    Ok(())
}

#[cfg(unix)]
async fn run_inner(
    daemon_opts: DaemonOptions,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Acquire PID file if daemonizing or if explicitly requested.
    // Keep it alive until shutdown for RAII cleanup.
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

    orchestrator::run_telemt_core(user.is_some() || group.is_some(), || {
        if (user.is_some() || group.is_some())
            && let Err(e) = drop_privileges(user.as_deref(), group.as_deref(), _pid_file.as_ref())
        {
            error!(error = %e, "Failed to drop privileges");
            std::process::exit(1);
        }
    })
    .await
}

#[cfg(not(unix))]
async fn run_inner() -> std::result::Result<(), Box<dyn std::error::Error>> {
    orchestrator::run_telemt_core(false, || {}).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ListenerConfig;

    fn listener_with_synlimit(synlimit: SynLimitMode) -> ListenerConfig {
        ListenerConfig {
            ip: "127.0.0.1".parse().unwrap(),
            transport: crate::config::ListenerTransport::Mtproxy,
            port: Some(443),
            client_mss: None,
            synlimit,
            synlimit_seconds: 60,
            synlimit_hitcount: 48,
            synlimit_burst: 24,
            synlimit_ios_seconds: 1,
            synlimit_ios_hitcount: 12,
            synlimit_ios_burst: 24,
            synlimit_hashlimit_expire_ms: 60_000,
            synlimit_hashlimit_size: 32_768,
            announce: None,
            announce_ip: None,
            proxy_protocol: None,
            reuse_allow: false,
            web_client_ip_source: crate::config::WebClientIpSource::XForwardedFor,
            web_trusted_proxy_cidrs: Vec::new(),
        }
    }

    #[test]
    fn privilege_drop_rejects_enabled_synlimit_only() {
        let mut config = ProxyConfig::default();
        config
            .server
            .listeners
            .push(listener_with_synlimit(SynLimitMode::Iptables));

        assert!(validate_synlimit_privilege_drop(&config, true).is_err());
        assert!(validate_synlimit_privilege_drop(&config, false).is_ok());
        config.server.listeners[0].synlimit = SynLimitMode::Off;
        assert!(validate_synlimit_privilege_drop(&config, true).is_ok());
    }
}
