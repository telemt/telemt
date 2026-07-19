use std::net::IpAddr;

use super::command::{run_command, run_command_stdout};
use super::model::{SynLimitNamespace, SynLimitRule, SynLimitTargets};

const PF_ANCHOR_ROOT: &str = "telemt_synlimit";

pub(super) async fn apply_synlimit_rules(
    targets: &SynLimitTargets,
    namespace: &SynLimitNamespace,
) -> Result<(), String> {
    if !has_pf_anchor_hook().await? {
        return Err(format!(
            "PF anchor hook is not installed; add anchor \"{PF_ANCHOR_ROOT}/*\" to pf.conf"
        ));
    }

    let script = pf_synlimit_script(targets);
    run_command("pfctl", &["-a", namespace.pf_anchor.as_str(), "-f", "-"], Some(script)).await
}

async fn has_pf_anchor_hook() -> Result<bool, String> {
    let rules = run_command_stdout("pfctl", &["-s", "rules"]).await?;
    Ok(rules.lines().any(is_pf_anchor_hook_line))
}

fn is_pf_anchor_hook_line(line: &str) -> bool {
    line.trim().contains("anchor \"telemt_synlimit/*\"")
}

fn pf_synlimit_script(targets: &SynLimitTargets) -> String {
    let mut script = String::new();
    for target in &targets.pf_v4 {
        push_pf_rules(&mut script, target);
    }
    for target in &targets.pf_v6 {
        push_pf_rules(&mut script, target);
    }
    script
}

fn push_pf_rules(script: &mut String, target: &SynLimitRule) {
    let destination = pf_destination(target.ip);
    script.push_str(&format!(
        "pass in quick proto tcp from any to {destination} port {port} flags S/SA keep state (max-src-conn-rate {rate}/{seconds})\n",
        port = target.port,
        rate = target.generic_hitcount,
        seconds = target.generic_seconds,
    ));
    script.push_str(&format!(
        "block return-rst in quick proto tcp from any to {destination} port {port}\n",
        port = target.port,
    ));
}

fn pf_destination(ip: Option<IpAddr>) -> String {
    ip.map(|ip| ip.to_string())
        .unwrap_or_else(|| "any".to_string())
}

pub(super) async fn clear_rules(namespace: &SynLimitNamespace) -> Result<bool, String> {
    match run_command(
        "pfctl",
        &["-a", namespace.pf_anchor.as_str(), "-F", "rules"],
        None,
    )
    .await
    {
        Ok(()) => Ok(true),
        Err(error) if is_missing_command_or_pf_anchor(&error) => Ok(false),
        Err(error) => return Err(format!("pfctl flush anchor rules failed: {error}")),
    }
}

fn is_missing_command_or_pf_anchor(error: &str) -> bool {
    error.contains("pfctl is not available") || error.contains("Anchor does not exist")
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::synlimit_control::model::test_rule;

    #[test]
    fn pf_script_uses_rate_limited_pass_before_reject() {
        let mut targets = SynLimitTargets::default();
        targets.pf_v4 = vec![test_rule(Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))), 443)];
        let script = pf_synlimit_script(&targets);

        assert!(script.contains(
            "pass in quick proto tcp from any to 203.0.113.7 port 443 flags S/SA keep state (max-src-conn-rate 48/60)"
        ));
        assert!(script.contains(
            "block return-rst in quick proto tcp from any to 203.0.113.7 port 443"
        ));
        let pass_idx = script
            .find("pass in quick proto tcp from any to 203.0.113.7 port 443")
            .expect("rate-limited pass rule must be rendered");
        let block_idx = script
            .find("block return-rst in quick proto tcp from any to 203.0.113.7 port 443")
            .expect("reject fallback rule must be rendered");
        assert!(pass_idx < block_idx);
    }

    #[test]
    fn pf_script_supports_wildcard_and_ipv6_destinations() {
        let mut targets = SynLimitTargets::default();
        targets.pf_v4 = vec![test_rule(None, 443)];
        targets.pf_v6 = vec![test_rule(Some(IpAddr::V6(Ipv6Addr::LOCALHOST)), 8443)];
        let script = pf_synlimit_script(&targets);

        assert!(script.contains("to any port 443"));
        assert!(script.contains("to ::1 port 8443"));
    }

    #[test]
    fn pf_anchor_hook_detection_requires_wildcard_hook() {
        assert!(is_pf_anchor_hook_line("anchor \"telemt_synlimit/*\" all"));
        assert!(!is_pf_anchor_hook_line("anchor \"telemt_synlimit\" all"));
        assert!(!is_pf_anchor_hook_line("anchor \"other\" all"));
    }
}
