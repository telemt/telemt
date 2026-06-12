use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::watch;
use tracing::warn;

use crate::config::{ProxyConfig, SynLimitMode};

const IPTABLES_CHAIN: &str = "TELEMT_SYNLIMIT";
const IPTABLES_HASHLIMIT_NAME: &str = "TELEMT-BUMPER";
const NFT_TABLE: &str = "telemt_synlimit";
const NFT_CHAIN: &str = "input";
type SynLimitTarget = (Option<IpAddr>, u16, u32, u32, u32);

#[derive(Default)]
struct SynLimitTargets {
    iptables_v4: Vec<SynLimitTarget>,
    iptables_v6: Vec<SynLimitTarget>,
    nft_v4: Vec<SynLimitTarget>,
    nft_v6: Vec<SynLimitTarget>,
}

#[derive(Clone, Copy)]
struct NftTableFamilies {
    inet: bool,
    ip: bool,
    ip6: bool,
}

#[derive(Clone, Copy)]
enum NftFamily {
    Inet,
    Ip,
    Ip6,
}

struct NftApplyPlan<'a> {
    family: NftFamily,
    v4_targets: &'a [SynLimitTarget],
    v6_targets: &'a [SynLimitTarget],
}

impl SynLimitTargets {
    fn is_empty(&self) -> bool {
        self.iptables_v4.is_empty()
            && self.iptables_v6.is_empty()
            && self.nft_v4.is_empty()
            && self.nft_v6.is_empty()
    }

    fn has_iptables_targets(&self) -> bool {
        !self.iptables_v4.is_empty() || !self.iptables_v6.is_empty()
    }

    fn has_nft_targets(&self) -> bool {
        !self.nft_v4.is_empty() || !self.nft_v6.is_empty()
    }
}
impl NftFamily {
    fn as_str(self) -> &'static str {
        match self {
            Self::Inet => "inet",
            Self::Ip => "ip",
            Self::Ip6 => "ip6",
        }
    }
}

pub(crate) fn spawn_synlimit_controller(config_rx: watch::Receiver<Arc<ProxyConfig>>) {
    if !cfg!(target_os = "linux") {
        if has_synlimit_config(&config_rx.borrow()) {
            warn!("SYN limiter is configured but unsupported on this OS; skipping netfilter rules");
        }
        return;
    }

    tokio::spawn(async move {
        wait_for_config_channel_close(config_rx).await;
        clear_synlimit_rules_all_backends().await;
    });
}

async fn wait_for_config_channel_close(mut config_rx: watch::Receiver<Arc<ProxyConfig>>) {
    while config_rx.changed().await.is_ok() {
        config_rx.borrow_and_update();
    }
}

pub(crate) async fn reconcile_synlimit_rules(cfg: &ProxyConfig) {
    clear_synlimit_rules_all_backends().await;

    let targets = synlimit_targets(cfg);
    if targets.is_empty() {
        return;
    }
    if !has_cap_net_admin() {
        warn!(
            "SYN limiter configured but CAP_NET_ADMIN is not available; netfilter rules not applied"
        );
        return;
    }

    if targets.has_iptables_targets()
        && let Err(error) = apply_iptables_synlimit_rules(&targets).await
    {
        warn!(error = %error, "Failed to apply iptables SYN limiter rules");
    }
    if targets.has_nft_targets()
        && let Err(error) = apply_nft_synlimit_rules(&targets).await
    {
        warn!(error = %error, "Failed to apply nftables SYN limiter rules");
    }
}

pub(crate) async fn clear_synlimit_rules_all_backends() {
    clear_nft_synlimit_rules_all_families().await;
    clear_iptables_synlimit_rules_for_binary("iptables").await;
    clear_iptables_synlimit_rules_for_binary("ip6tables").await;
}

fn has_synlimit_config(cfg: &ProxyConfig) -> bool {
    cfg.server
        .listeners
        .iter()
        .any(|listener| !matches!(listener.synlimit, SynLimitMode::Off))
}

fn synlimit_targets(cfg: &ProxyConfig) -> SynLimitTargets {
    let mut iptables_v4 = BTreeSet::new();
    let mut iptables_v6 = BTreeSet::new();
    let mut nft_v4 = BTreeSet::new();
    let mut nft_v6 = BTreeSet::new();

    for listener in &cfg.server.listeners {
        let backend = listener.synlimit;
        if matches!(backend, SynLimitMode::Off) {
            continue;
        }
        let port = listener.port.unwrap_or(cfg.server.port);
        let ip = (!listener.ip.is_unspecified()).then_some(listener.ip);
        let seconds = listener.synlimit_seconds;
        let hitcount = listener.synlimit_hitcount;
        let burst = listener.synlimit_burst;

        match (backend, listener.ip.is_ipv4()) {
            (SynLimitMode::Iptables, true) => {
                iptables_v4.insert((ip, port, seconds, hitcount, burst));
            }
            (SynLimitMode::Iptables, false) => {
                iptables_v6.insert((ip, port, seconds, hitcount, burst));
            }
            (SynLimitMode::Nftables, true) => {
                nft_v4.insert((ip, port, seconds, hitcount, burst));
            }
            (SynLimitMode::Nftables, false) => {
                nft_v6.insert((ip, port, seconds, hitcount, burst));
            }
            (SynLimitMode::Off, _) => {}
        }
    }

    SynLimitTargets {
        iptables_v4: iptables_v4.into_iter().collect(),
        iptables_v6: iptables_v6.into_iter().collect(),
        nft_v4: nft_v4.into_iter().collect(),
        nft_v6: nft_v6.into_iter().collect(),
    }
}

async fn apply_iptables_synlimit_rules(targets: &SynLimitTargets) -> Result<(), String> {
    apply_iptables_synlimit_rules_for_binary("iptables", &targets.iptables_v4).await?;
    apply_iptables_synlimit_rules_for_binary("ip6tables", &targets.iptables_v6).await
}

async fn apply_iptables_synlimit_rules_for_binary(
    binary: &str,
    targets: &[SynLimitTarget],
) -> Result<(), String> {
    if targets.is_empty() {
        return Ok(());
    }
    if !command_exists(binary) {
        return Err(format!("{binary} is not available"));
    }

    let _ = run_command(binary, &["-t", "filter", "-N", IPTABLES_CHAIN], None).await;
    run_command(binary, &["-t", "filter", "-F", IPTABLES_CHAIN], None).await?;
    if run_command(
        binary,
        &["-t", "filter", "-C", "INPUT", "-j", IPTABLES_CHAIN],
        None,
    )
    .await
    .is_err()
    {
        run_command(
            binary,
            &["-t", "filter", "-A", "INPUT", "-j", IPTABLES_CHAIN],
            None,
        )
        .await?;
    }

    for (idx, (ip, port, seconds, hitcount, burst)) in targets.iter().enumerate() {
        let hashlimit_name = format!("{IPTABLES_HASHLIMIT_NAME}-{idx}");
        let accept_args = iptables_hashlimit_accept_rule_args(
            ip,
            *port,
            *seconds,
            *hitcount,
            *burst,
            &hashlimit_name,
        );
        let drop_args = iptables_synlimit_drop_rule_args(ip, *port);
        let drop_refs: Vec<&str> = drop_args.iter().map(String::as_str).collect();
        let accept_refs: Vec<&str> = accept_args.iter().map(String::as_str).collect();
        run_command(binary, &accept_refs, None).await?;
        run_command(binary, &drop_refs, None).await?;
    }
    run_command(
        binary,
        &["-t", "filter", "-A", IPTABLES_CHAIN, "-j", "RETURN"],
        None,
    )
    .await?;

    Ok(())
}

fn iptables_hashlimit_accept_rule_args(
    ip: &Option<IpAddr>,
    port: u16,
    seconds: u32,
    hitcount: u32,
    burst: u32,
    hashlimit_name: &str,
) -> Vec<String> {
    let mut args = vec![
        "-t".to_string(),
        "filter".to_string(),
        "-A".to_string(),
        IPTABLES_CHAIN.to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "--syn".to_string(),
    ];
    if let Some(ip) = ip {
        args.push("-d".to_string());
        args.push(ip.to_string());
    }
    let rate = synlimit_rate_arg(seconds, hitcount);
    args.extend([
        "--dport".to_string(),
        port.to_string(),
        "-m".to_string(),
        "hashlimit".to_string(),
        "--hashlimit-name".to_string(),
        hashlimit_name.to_string(),
        "--hashlimit-mode".to_string(),
        "srcip".to_string(),
        "--hashlimit-upto".to_string(),
        rate,
        "--hashlimit-burst".to_string(),
        burst.to_string(),
        "--hashlimit-htable-expire".to_string(),
        "15000".to_string(),
        "-j".to_string(),
        "ACCEPT".to_string(),
    ]);
    args
}

fn iptables_synlimit_drop_rule_args(ip: &Option<IpAddr>, port: u16) -> Vec<String> {
    let mut args = vec![
        "-t".to_string(),
        "filter".to_string(),
        "-A".to_string(),
        IPTABLES_CHAIN.to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "--syn".to_string(),
    ];
    if let Some(ip) = ip {
        args.push("-d".to_string());
        args.push(ip.to_string());
    }
    args.extend([
        "--dport".to_string(),
        port.to_string(),
        "-j".to_string(),
        "DROP".to_string(),
    ]);
    args
}

fn synlimit_rate_arg(seconds: u32, hitcount: u32) -> String {
    let seconds = u64::from(seconds.max(1));
    let hitcount = u64::from(hitcount.max(1));
    for (unit_seconds, unit_name) in [
        (1_u64, "second"),
        (60_u64, "minute"),
        (3_600_u64, "hour"),
        (86_400_u64, "day"),
    ] {
        let amount = hitcount.saturating_mul(unit_seconds);
        if amount >= seconds && amount % seconds == 0 {
            return format!("{}/{}", amount / seconds, unit_name);
        }
    }
    let amount = hitcount.saturating_mul(86_400).saturating_add(seconds - 1) / seconds;
    format!("{}/day", amount.max(1))
}

async fn clear_iptables_synlimit_rules_for_binary(binary: &str) {
    if !command_exists(binary) {
        return;
    }
    for _ in 0..8 {
        if run_command(
            binary,
            &["-t", "filter", "-D", "INPUT", "-j", IPTABLES_CHAIN],
            None,
        )
        .await
        .is_err()
        {
            break;
        }
    }
    let _ = run_command(binary, &["-t", "filter", "-F", IPTABLES_CHAIN], None).await;
    let _ = run_command(binary, &["-t", "filter", "-X", IPTABLES_CHAIN], None).await;
}

async fn apply_nft_synlimit_rules(targets: &SynLimitTargets) -> Result<(), String> {
    if !command_exists("nft") {
        return Err("nft is not available".to_string());
    }

    let families = detect_nft_table_families().await;
    for plan in nft_apply_plan(families, &targets.nft_v4, &targets.nft_v6) {
        let script = nft_synlimit_script(plan);
        run_command("nft", &["-f", "-"], Some(script)).await?;
    }

    Ok(())
}

async fn detect_nft_table_families() -> NftTableFamilies {
    let Ok(output) = run_command_stdout("nft", &["list", "tables"]).await else {
        return NftTableFamilies {
            inet: false,
            ip: false,
            ip6: false,
        };
    };

    let mut families = NftTableFamilies {
        inet: false,
        ip: false,
        ip6: false,
    };
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("table") {
            continue;
        }
        match fields.next() {
            Some("inet") => families.inet = true,
            Some("ip") => families.ip = true,
            Some("ip6") => families.ip6 = true,
            _ => {}
        }
    }
    families
}
fn nft_apply_plan<'a>(
    families: NftTableFamilies,
    v4_targets: &'a [SynLimitTarget],
    v6_targets: &'a [SynLimitTarget],
) -> Vec<NftApplyPlan<'a>> {
    if !v4_targets.is_empty() && !v6_targets.is_empty() {
        return vec![NftApplyPlan {
            family: NftFamily::Inet,
            v4_targets,
            v6_targets,
        }];
    }
    if !v4_targets.is_empty() {
        return vec![NftApplyPlan {
            family: if families.inet || !families.ip {
                NftFamily::Inet
            } else {
                NftFamily::Ip
            },
            v4_targets,
            v6_targets: &[],
        }];
    }
    if !v6_targets.is_empty() {
        return vec![NftApplyPlan {
            family: if families.inet || !families.ip6 {
                NftFamily::Inet
            } else {
                NftFamily::Ip6
            },
            v4_targets: &[],
            v6_targets,
        }];
    }
    Vec::new()
}
fn nft_synlimit_script(plan: NftApplyPlan<'_>) -> String {
    let mut script = String::new();
    script.push_str(&format!("table {} {NFT_TABLE} {{\n", plan.family.as_str()));
    script.push_str(&format!("  chain {NFT_CHAIN} {{\n"));
    script.push_str("    type filter hook input priority filter; policy accept;\n");
    for (idx, (ip, port, seconds, hitcount, burst)) in plan.v4_targets.iter().enumerate() {
        let daddr = ip
            .map(|ip| format!(" ip daddr {ip}"))
            .unwrap_or_else(String::new);
        let rate = synlimit_rate_arg(*seconds, *hitcount);
        script.push_str(&format!(
            "    tcp flags & (fin|syn|rst|ack) == syn{daddr} tcp dport {port} meter telemt_synlimit_v4_{idx} {{ ip saddr limit rate over {rate} burst {burst} packets }} drop\n"
        ));
        script.push_str(&format!(
            "    tcp flags & (fin|syn|rst|ack) == syn{daddr} tcp dport {port} accept\n"
        ));
    }
    for (idx, (ip, port, seconds, hitcount, burst)) in plan.v6_targets.iter().enumerate() {
        let daddr = ip
            .map(|ip| format!(" ip6 daddr {ip}"))
            .unwrap_or_else(String::new);
        let rate = synlimit_rate_arg(*seconds, *hitcount);
        script.push_str(&format!(
            "    tcp flags & (fin|syn|rst|ack) == syn{daddr} tcp dport {port} meter telemt_synlimit_v6_{idx} {{ ip6 saddr limit rate over {rate} burst {burst} packets }} drop\n"
        ));
        script.push_str(&format!(
            "    tcp flags & (fin|syn|rst|ack) == syn{daddr} tcp dport {port} accept\n"
        ));
    }
    script.push_str("  }\n");
    script.push_str("}\n");
    script
}

async fn clear_nft_synlimit_rules_all_families() {
    if !command_exists("nft") {
        return;
    }
    for family in [NftFamily::Inet, NftFamily::Ip, NftFamily::Ip6] {
        let _ = run_command(
            "nft",
            &["delete", "table", family.as_str(), NFT_TABLE],
            None,
        )
        .await;
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

async fn run_command_stdout(binary: &str, args: &[&str]) -> Result<String, String> {
    if !command_exists(binary) {
        return Err(format!("{binary} is not available"));
    }
    let output = Command::new(binary)
        .args(args)
        .output()
        .await
        .map_err(|e| format!("wait {binary} failed: {e}"))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(if stderr.is_empty() {
        format!("{binary} exited with status {}", output.status)
    } else {
        stderr
    })
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
