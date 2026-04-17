use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::config::{ConntrackBackend, ConntrackMode, ProxyConfig};
use crate::proxy::middle_relay::note_global_relay_pressure;
use crate::proxy::shared_state::{ConntrackCloseEvent, ConntrackCloseReason, ProxySharedState};
use crate::stats::Stats;

const CONNTRACK_EVENT_QUEUE_CAPACITY: usize = 32_768;
const PRESSURE_RELEASE_TICKS: u8 = 3;
const PRESSURE_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NetfilterBackend {
    Nftables,
    Iptables,
}

#[derive(Clone, Copy)]
struct ConntrackRuntimeSupport {
    netfilter_backend: Option<NetfilterBackend>,
    has_cap_net_admin: bool,
    has_conntrack_binary: bool,
}

#[derive(Clone, Copy)]
struct PressureSample {
    conn_pct: Option<u8>,
    fd_pct: Option<u8>,
    accept_timeout_delta: u64,
    me_queue_pressure_delta: u64,
}

struct PressureState {
    active: bool,
    low_streak: u8,
    prev_accept_timeout_total: u64,
    prev_me_queue_pressure_total: u64,
}

impl PressureState {
    fn new(stats: &Stats) -> Self {
        Self {
            active: false,
            low_streak: 0,
            prev_accept_timeout_total: stats.get_accept_permit_timeout_total(),
            prev_me_queue_pressure_total: stats.get_me_c2me_send_full_total(),
        }
    }
}

pub(crate) fn spawn_conntrack_controller(
    config_rx: watch::Receiver<Arc<ProxyConfig>>,
    stats: Arc<Stats>,
    shared: Arc<ProxySharedState>,
) {
    if !cfg!(target_os = "linux") {
        let cfg = config_rx.borrow();
        let enabled = cfg.server.conntrack_control.inline_conntrack_control;
        stats.set_conntrack_control_enabled(enabled);
        stats.set_conntrack_control_available(false);
        stats.set_conntrack_pressure_active(false);
        stats.set_conntrack_event_queue_depth(0);
        stats.set_conntrack_rule_apply_ok(false);
        shared.disable_conntrack_close_sender();
        shared.set_conntrack_pressure_active(false);
        if enabled
            && cfg
                .server
                .conntrack_control
                .inline_conntrack_control_explicit
        {
            warn!(
                "conntrack control explicitly enabled but unsupported on this OS; disabling runtime worker"
            );
        }
        return;
    }

    let (tx, rx) = mpsc::channel(CONNTRACK_EVENT_QUEUE_CAPACITY);
    shared.set_conntrack_close_sender(tx);
    tokio::spawn(async move {
        run_conntrack_controller(config_rx, stats, shared, rx).await;
    });
}

async fn run_conntrack_controller(
    mut config_rx: watch::Receiver<Arc<ProxyConfig>>,
    stats: Arc<Stats>,
    shared: Arc<ProxySharedState>,
    mut close_rx: mpsc::Receiver<ConntrackCloseEvent>,
) {
    let mut cfg = config_rx.borrow().clone();
    let mut pressure_state = PressureState::new(stats.as_ref());
    let mut delete_budget_tokens = cfg.server.conntrack_control.delete_budget_per_sec;
    let mut runtime_support = probe_runtime_support(cfg.server.conntrack_control.backend);
    let mut effective_enabled = effective_conntrack_enabled(&cfg, runtime_support);

    apply_runtime_state(
        stats.as_ref(),
        shared.as_ref(),
        &cfg,
        runtime_support,
        false,
    );
    reconcile_rules(&cfg, runtime_support, stats.as_ref()).await;

    loop {
        tokio::select! {
            changed = config_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                cfg = config_rx.borrow_and_update().clone();
                runtime_support = probe_runtime_support(cfg.server.conntrack_control.backend);
                effective_enabled = effective_conntrack_enabled(&cfg, runtime_support);
                delete_budget_tokens = cfg.server.conntrack_control.delete_budget_per_sec;
                apply_runtime_state(stats.as_ref(), shared.as_ref(), &cfg, runtime_support, pressure_state.active);
                reconcile_rules(&cfg, runtime_support, stats.as_ref()).await;
            }
            event = close_rx.recv() => {
                let Some(event) = event else {
                    break;
                };
                stats.set_conntrack_event_queue_depth(close_rx.len() as u64);
                if !effective_enabled {
                    continue;
                }
                if !pressure_state.active {
                    continue;
                }
                if !matches!(event.reason, ConntrackCloseReason::Timeout | ConntrackCloseReason::Pressure | ConntrackCloseReason::Reset) {
                    continue;
                }
                if delete_budget_tokens == 0 {
                    continue;
                }
                stats.increment_conntrack_delete_attempt_total();
                match delete_conntrack_entry(event).await {
                    DeleteOutcome::Deleted => {
                        delete_budget_tokens = delete_budget_tokens.saturating_sub(1);
                        stats.increment_conntrack_delete_success_total();
                    }
                    DeleteOutcome::NotFound => {
                        delete_budget_tokens = delete_budget_tokens.saturating_sub(1);
                        stats.increment_conntrack_delete_not_found_total();
                    }
                    DeleteOutcome::Error => {
                        delete_budget_tokens = delete_budget_tokens.saturating_sub(1);
                        stats.increment_conntrack_delete_error_total();
                    }
                }
            }
            _ = tokio::time::sleep(PRESSURE_SAMPLE_INTERVAL) => {
                delete_budget_tokens = cfg.server.conntrack_control.delete_budget_per_sec;
                stats.set_conntrack_event_queue_depth(close_rx.len() as u64);
                let sample = collect_pressure_sample(stats.as_ref(), &cfg, &mut pressure_state);
                update_pressure_state(
                    stats.as_ref(),
                    shared.as_ref(),
                    &cfg,
                    effective_enabled,
                    &sample,
                    &mut pressure_state,
                );
                if pressure_state.active {
                    note_global_relay_pressure(shared.as_ref());
                }
            }
        }
    }

    shared.disable_conntrack_close_sender();
    shared.set_conntrack_pressure_active(false);
    stats.set_conntrack_pressure_active(false);
}

fn apply_runtime_state(
    stats: &Stats,
    shared: &ProxySharedState,
    cfg: &ProxyConfig,
    runtime_support: ConntrackRuntimeSupport,
    pressure_active: bool,
) {
    let enabled = cfg.server.conntrack_control.inline_conntrack_control;
    let available = effective_conntrack_enabled(cfg, runtime_support);
    if enabled
        && !available
        && cfg
            .server
            .conntrack_control
            .inline_conntrack_control_explicit
    {
        warn!(
            has_cap_net_admin = runtime_support.has_cap_net_admin,
            backend_available = runtime_support.netfilter_backend.is_some(),
            conntrack_binary_available = runtime_support.has_conntrack_binary,
            configured_backend = ?cfg.server.conntrack_control.backend,
            "conntrack control explicitly enabled but unavailable; disabling runtime features"
        );
    }
    stats.set_conntrack_control_enabled(enabled);
    stats.set_conntrack_control_available(available);
    shared.set_conntrack_pressure_active(available && pressure_active);
    stats.set_conntrack_pressure_active(available && pressure_active);
}

fn collect_pressure_sample(
    stats: &Stats,
    cfg: &ProxyConfig,
    state: &mut PressureState,
) -> PressureSample {
    let current_connections = stats.get_current_connections_total();
    let conn_pct = if cfg.server.max_connections == 0 {
        None
    } else {
        Some(
            ((current_connections.saturating_mul(100)) / u64::from(cfg.server.max_connections))
                .min(100) as u8,
        )
    };

    let fd_pct = fd_usage_pct();

    let accept_total = stats.get_accept_permit_timeout_total();
    let accept_delta = accept_total.saturating_sub(state.prev_accept_timeout_total);
    state.prev_accept_timeout_total = accept_total;

    let me_total = stats.get_me_c2me_send_full_total();
    let me_delta = me_total.saturating_sub(state.prev_me_queue_pressure_total);
    state.prev_me_queue_pressure_total = me_total;

    PressureSample {
        conn_pct,
        fd_pct,
        accept_timeout_delta: accept_delta,
        me_queue_pressure_delta: me_delta,
    }
}

fn update_pressure_state(
    stats: &Stats,
    shared: &ProxySharedState,
    cfg: &ProxyConfig,
    effective_enabled: bool,
    sample: &PressureSample,
    state: &mut PressureState,
) {
    if !effective_enabled {
        if state.active {
            state.active = false;
            state.low_streak = 0;
            shared.set_conntrack_pressure_active(false);
            stats.set_conntrack_pressure_active(false);
            info!("Conntrack pressure mode deactivated (feature disabled)");
        }
        return;
    }

    let high = cfg.server.conntrack_control.pressure_high_watermark_pct;
    let low = cfg.server.conntrack_control.pressure_low_watermark_pct;

    let high_hit = sample.conn_pct.is_some_and(|v| v >= high)
        || sample.fd_pct.is_some_and(|v| v >= high)
        || sample.accept_timeout_delta > 0
        || sample.me_queue_pressure_delta > 0;

    let low_clear = sample.conn_pct.is_none_or(|v| v <= low)
        && sample.fd_pct.is_none_or(|v| v <= low)
        && sample.accept_timeout_delta == 0
        && sample.me_queue_pressure_delta == 0;

    if !state.active && high_hit {
        state.active = true;
        state.low_streak = 0;
        shared.set_conntrack_pressure_active(true);
        stats.set_conntrack_pressure_active(true);
        info!(
            conn_pct = ?sample.conn_pct,
            fd_pct = ?sample.fd_pct,
            accept_timeout_delta = sample.accept_timeout_delta,
            me_queue_pressure_delta = sample.me_queue_pressure_delta,
            "Conntrack pressure mode activated"
        );
        return;
    }

    if state.active && low_clear {
        state.low_streak = state.low_streak.saturating_add(1);
        if state.low_streak >= PRESSURE_RELEASE_TICKS {
            state.active = false;
            state.low_streak = 0;
            shared.set_conntrack_pressure_active(false);
            stats.set_conntrack_pressure_active(false);
            info!("Conntrack pressure mode deactivated");
        }
        return;
    }

    state.low_streak = 0;
}

async fn reconcile_rules(
    cfg: &ProxyConfig,
    runtime_support: ConntrackRuntimeSupport,
    stats: &Stats,
) {
    if !cfg.server.conntrack_control.inline_conntrack_control {
        clear_notrack_rules_all_backends().await;
        stats.set_conntrack_rule_apply_ok(true);
        return;
    }

    if !effective_conntrack_enabled(cfg, runtime_support) {
        clear_notrack_rules_all_backends().await;
        stats.set_conntrack_rule_apply_ok(false);
        return;
    }

    let backend = runtime_support
        .netfilter_backend
        .expect("netfilter backend must be available for effective conntrack control");

    let apply_result = match backend {
        NetfilterBackend::Nftables => apply_nft_rules(cfg).await,
        NetfilterBackend::Iptables => apply_iptables_rules(cfg).await,
    };

    if let Err(error) = apply_result {
        warn!(error = %error, "Failed to reconcile conntrack/notrack rules");
        stats.set_conntrack_rule_apply_ok(false);
    } else {
        stats.set_conntrack_rule_apply_ok(true);
    }
}

fn probe_runtime_support(configured_backend: ConntrackBackend) -> ConntrackRuntimeSupport {
    ConntrackRuntimeSupport {
        netfilter_backend: pick_backend(configured_backend),
        has_cap_net_admin: has_cap_net_admin(),
        has_conntrack_binary: command_exists("conntrack"),
    }
}

fn effective_conntrack_enabled(
    cfg: &ProxyConfig,
    runtime_support: ConntrackRuntimeSupport,
) -> bool {
    cfg.server.conntrack_control.inline_conntrack_control
        && runtime_support.has_cap_net_admin
        && runtime_support.netfilter_backend.is_some()
        && runtime_support.has_conntrack_binary
}

fn pick_backend(configured: ConntrackBackend) -> Option<NetfilterBackend> {
    match configured {
        ConntrackBackend::Auto => {
            if command_exists("nft") {
                Some(NetfilterBackend::Nftables)
            } else if command_exists("iptables") {
                Some(NetfilterBackend::Iptables)
            } else {
                None
            }
        }
        ConntrackBackend::Nftables => command_exists("nft").then_some(NetfilterBackend::Nftables),
        ConntrackBackend::Iptables => {
            command_exists("iptables").then_some(NetfilterBackend::Iptables)
        }
    }
}

fn command_exists(binary: &str) -> bool {
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path_var).any(|dir| {
        let candidate: PathBuf = dir.join(binary);
        candidate.exists() && candidate.is_file()
    })
}

fn listener_port_set(cfg: &ProxyConfig) -> Vec<u16> {
    let mut ports: BTreeSet<u16> = BTreeSet::new();
    if cfg.server.listeners.is_empty() {
        ports.insert(cfg.server.port);
    } else {
        for listener in &cfg.server.listeners {
            ports.insert(listener.port.unwrap_or(cfg.server.port));
        }
    }
    ports.into_iter().collect()
}

fn notrack_targets(cfg: &ProxyConfig) -> (Vec<(Option<IpAddr>, u16)>, Vec<(Option<IpAddr>, u16)>) {
    let mode = cfg.server.conntrack_control.mode;
    let mut v4_targets: BTreeSet<(Option<IpAddr>, u16)> = BTreeSet::new();
    let mut v6_targets: BTreeSet<(Option<IpAddr>, u16)> = BTreeSet::new();

    match mode {
        ConntrackMode::Tracked => {}
        ConntrackMode::Notrack => {
            if cfg.server.listeners.is_empty() {
                let port = cfg.server.port;
                if let Some(ipv4) = cfg
                    .server
                    .listen_addr_ipv4
                    .as_ref()
                    .and_then(|s| s.parse::<IpAddr>().ok())
                {
                    if ipv4.is_unspecified() {
                        v4_targets.insert((None, port));
                    } else {
                        v4_targets.insert((Some(ipv4), port));
                    }
                }
                if let Some(ipv6) = cfg
                    .server
                    .listen_addr_ipv6
                    .as_ref()
                    .and_then(|s| s.parse::<IpAddr>().ok())
                {
                    if ipv6.is_unspecified() {
                        v6_targets.insert((None, port));
                    } else {
                        v6_targets.insert((Some(ipv6), port));
                    }
                }
            } else {
                for listener in &cfg.server.listeners {
                    let port = listener.port.unwrap_or(cfg.server.port);
                    if listener.ip.is_ipv4() {
                        if listener.ip.is_unspecified() {
                            v4_targets.insert((None, port));
                        } else {
                            v4_targets.insert((Some(listener.ip), port));
                        }
                    } else if listener.ip.is_unspecified() {
                        v6_targets.insert((None, port));
                    } else {
                        v6_targets.insert((Some(listener.ip), port));
                    }
                }
            }
        }
        ConntrackMode::Hybrid => {
            let ports = listener_port_set(cfg);
            for ip in &cfg.server.conntrack_control.hybrid_listener_ips {
                if ip.is_ipv4() {
                    for port in &ports {
                        v4_targets.insert((Some(*ip), *port));
                    }
                } else {
                    for port in &ports {
                        v6_targets.insert((Some(*ip), *port));
                    }
                }
            }
        }
    }

    (
        v4_targets.into_iter().collect(),
        v6_targets.into_iter().collect(),
    )
}

async fn apply_nft_rules(cfg: &ProxyConfig) -> Result<(), String> {
    let _ = run_command(
        "nft",
        &["delete", "table", "inet", "telemt_conntrack"],
        None,
    )
    .await;
    if matches!(cfg.server.conntrack_control.mode, ConntrackMode::Tracked) {
        return Ok(());
    }

    let (v4_targets, v6_targets) = notrack_targets(cfg);
    let mut rules = Vec::new();
    for (ip, port) in v4_targets {
        let rule = if let Some(ip) = ip {
            format!("tcp dport {} ip daddr {} notrack", port, ip)
        } else {
            format!("tcp dport {} notrack", port)
        };
        rules.push(rule);
    }
    for (ip, port) in v6_targets {
        let rule = if let Some(ip) = ip {
            format!("tcp dport {} ip6 daddr {} notrack", port, ip)
        } else {
            format!("tcp dport {} notrack", port)
        };
        rules.push(rule);
    }

    let rule_blob = if rules.is_empty() {
        String::new()
    } else {
        format!("    {}\n", rules.join("\n    "))
    };
    let script = format!(
        "table inet telemt_conntrack {{\n  chain preraw {{\n    type filter hook prerouting priority raw; policy accept;\n{rule_blob}  }}\n}}\n"
    );
    run_command("nft", &["-f", "-"], Some(script)).await
}

async fn apply_iptables_rules(cfg: &ProxyConfig) -> Result<(), String> {
    apply_iptables_rules_for_binary("iptables", cfg, true).await?;
    apply_iptables_rules_for_binary("ip6tables", cfg, false).await?;
    Ok(())
}

async fn apply_iptables_rules_for_binary(
    binary: &str,
    cfg: &ProxyConfig,
    ipv4: bool,
) -> Result<(), String> {
    if !command_exists(binary) {
        return Ok(());
    }
    let chain = "TELEMT_NOTRACK";
    let _ = run_command(
        binary,
        &["-t", "raw", "-D", "PREROUTING", "-j", chain],
        None,
    )
    .await;
    let _ = run_command(binary, &["-t", "raw", "-F", chain], None).await;
    let _ = run_command(binary, &["-t", "raw", "-X", chain], None).await;

    if matches!(cfg.server.conntrack_control.mode, ConntrackMode::Tracked) {
        return Ok(());
    }

    run_command(binary, &["-t", "raw", "-N", chain], None).await?;
    run_command(binary, &["-t", "raw", "-F", chain], None).await?;
    if run_command(
        binary,
        &["-t", "raw", "-C", "PREROUTING", "-j", chain],
        None,
    )
    .await
    .is_err()
    {
        run_command(
            binary,
            &["-t", "raw", "-I", "PREROUTING", "1", "-j", chain],
            None,
        )
        .await?;
    }

    let (v4_targets, v6_targets) = notrack_targets(cfg);
    let selected = if ipv4 { v4_targets } else { v6_targets };
    for (ip, port) in selected {
        let mut args = vec![
            "-t".to_string(),
            "raw".to_string(),
            "-A".to_string(),
            chain.to_string(),
            "-p".to_string(),
            "tcp".to_string(),
            "--dport".to_string(),
            port.to_string(),
        ];
        if let Some(ip) = ip {
            args.push("-d".to_string());
            args.push(ip.to_string());
        }
        args.push("-j".to_string());
        args.push("CT".to_string());
        args.push("--notrack".to_string());
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_command(binary, &arg_refs, None).await?;
    }
    Ok(())
}

async fn clear_notrack_rules_all_backends() {
    let _ = run_command(
        "nft",
        &["delete", "table", "inet", "telemt_conntrack"],
        None,
    )
    .await;
    let _ = run_command(
        "iptables",
        &["-t", "raw", "-D", "PREROUTING", "-j", "TELEMT_NOTRACK"],
        None,
    )
    .await;
    let _ = run_command("iptables", &["-t", "raw", "-F", "TELEMT_NOTRACK"], None).await;
    let _ = run_command("iptables", &["-t", "raw", "-X", "TELEMT_NOTRACK"], None).await;
    let _ = run_command(
        "ip6tables",
        &["-t", "raw", "-D", "PREROUTING", "-j", "TELEMT_NOTRACK"],
        None,
    )
    .await;
    let _ = run_command("ip6tables", &["-t", "raw", "-F", "TELEMT_NOTRACK"], None).await;
    let _ = run_command("ip6tables", &["-t", "raw", "-X", "TELEMT_NOTRACK"], None).await;
}

enum DeleteOutcome {
    Deleted,
    NotFound,
    Error,
}

async fn delete_conntrack_entry(event: ConntrackCloseEvent) -> DeleteOutcome {
    if !command_exists("conntrack") {
        return DeleteOutcome::Error;
    }
    let args = vec![
        "-D".to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "-s".to_string(),
        event.src.ip().to_string(),
        "--sport".to_string(),
        event.src.port().to_string(),
        "-d".to_string(),
        event.dst.ip().to_string(),
        "--dport".to_string(),
        event.dst.port().to_string(),
    ];
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    match run_command("conntrack", &arg_refs, None).await {
        Ok(()) => DeleteOutcome::Deleted,
        Err(error) => {
            if error.contains("0 flow entries have been deleted") {
                DeleteOutcome::NotFound
            } else {
                debug!(error = %error, "conntrack delete failed");
                DeleteOutcome::Error
            }
        }
    }
}

async fn run_command(binary: &str, args: &[&str], stdin: Option<String>) -> Result<(), String> {
    if !command_exists(binary) {
        return Err(format!("{binary} is not available"));
    }
    let mut command = Command::new(binary);
    command.args(args);
    if stdin.is_some() {
        command.stdin(std::process::Stdio::piped());
    }
    command.stdout(std::process::Stdio::null());
    command.stderr(std::process::Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| format!("spawn {binary} failed: {e}"))?;
    if let Some(blob) = stdin
        && let Some(mut writer) = child.stdin.take()
    {
        writer
            .write_all(blob.as_bytes())
            .await
            .map_err(|e| format!("stdin write {binary} failed: {e}"))?;
    }
    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("wait {binary} failed: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(if stderr.is_empty() {
        format!("{binary} exited with status {}", output.status)
    } else {
        stderr
    })
}

fn fd_usage_pct() -> Option<u8> {
    let soft_limit = nofile_soft_limit()?;
    if soft_limit == 0 {
        return None;
    }
    let fd_count = std::fs::read_dir("/proc/self/fd").ok()?.count() as u64;
    Some(((fd_count.saturating_mul(100)) / soft_limit).min(100) as u8)
}

fn nofile_soft_limit() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
        if rc != 0 {
            return None;
        }
        return Some(lim.rlim_cur);
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn has_cap_net_admin() -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
            return false;
        };
        for line in status.lines() {
            if let Some(raw) = line.strip_prefix("CapEff:") {
                let caps = raw.trim();
                if let Ok(bits) = u64::from_str_radix(caps, 16) {
                    const CAP_NET_ADMIN_BIT: u64 = 12;
                    return (bits & (1u64 << CAP_NET_ADMIN_BIT)) != 0;
                }
            }
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyConfig;

    #[test]
    fn pressure_activates_on_accept_timeout_spike() {
        let stats = Stats::new();
        let shared = ProxySharedState::new();
        let mut cfg = ProxyConfig::default();
        cfg.server.conntrack_control.inline_conntrack_control = true;
        let mut state = PressureState::new(&stats);
        let sample = PressureSample {
            conn_pct: Some(10),
            fd_pct: Some(10),
            accept_timeout_delta: 1,
            me_queue_pressure_delta: 0,
        };

        update_pressure_state(&stats, shared.as_ref(), &cfg, true, &sample, &mut state);

        assert!(state.active);
        assert!(shared.conntrack_pressure_active());
        assert!(stats.get_conntrack_pressure_active());
    }

    #[test]
    fn pressure_releases_after_hysteresis_window() {
        let stats = Stats::new();
        let shared = ProxySharedState::new();
        let mut cfg = ProxyConfig::default();
        cfg.server.conntrack_control.inline_conntrack_control = true;
        let mut state = PressureState::new(&stats);

        let high_sample = PressureSample {
            conn_pct: Some(95),
            fd_pct: Some(95),
            accept_timeout_delta: 0,
            me_queue_pressure_delta: 0,
        };
        update_pressure_state(
            &stats,
            shared.as_ref(),
            &cfg,
            true,
            &high_sample,
            &mut state,
        );
        assert!(state.active);

        let low_sample = PressureSample {
            conn_pct: Some(10),
            fd_pct: Some(10),
            accept_timeout_delta: 0,
            me_queue_pressure_delta: 0,
        };
        update_pressure_state(&stats, shared.as_ref(), &cfg, true, &low_sample, &mut state);
        assert!(state.active);
        update_pressure_state(&stats, shared.as_ref(), &cfg, true, &low_sample, &mut state);
        assert!(state.active);
        update_pressure_state(&stats, shared.as_ref(), &cfg, true, &low_sample, &mut state);

        assert!(!state.active);
        assert!(!shared.conntrack_pressure_active());
        assert!(!stats.get_conntrack_pressure_active());
    }

    #[test]
    fn pressure_does_not_activate_when_disabled() {
        let stats = Stats::new();
        let shared = ProxySharedState::new();
        let mut cfg = ProxyConfig::default();
        cfg.server.conntrack_control.inline_conntrack_control = false;
        let mut state = PressureState::new(&stats);
        let sample = PressureSample {
            conn_pct: Some(100),
            fd_pct: Some(100),
            accept_timeout_delta: 10,
            me_queue_pressure_delta: 10,
        };

        update_pressure_state(&stats, shared.as_ref(), &cfg, false, &sample, &mut state);

        assert!(!state.active);
        assert!(!shared.conntrack_pressure_active());
        assert!(!stats.get_conntrack_pressure_active());
    }
}
