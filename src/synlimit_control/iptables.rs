use std::net::IpAddr;

use super::command::run_command;
use super::model::{SynLimitRule, SynLimitTargets, synlimit_rate_arg};

const IPTABLES_CHAIN: &str = "TELEMT_SYNLIMIT";
const IPTABLES_HASHLIMIT_PREFIX: &str = "TMT-SYN";
const IPV4_IOS_PACKET_LENGTH: u16 = 64;
const IPV6_IOS_PACKET_LENGTH: u16 = 84;
const IOS_TTL_LIMIT: u8 = 65;

#[derive(Clone, Copy)]
enum IpTablesFamily {
    V4,
    V6,
}

impl IpTablesFamily {
    fn ios_packet_length(self) -> u16 {
        match self {
            Self::V4 => IPV4_IOS_PACKET_LENGTH,
            Self::V6 => IPV6_IOS_PACKET_LENGTH,
        }
    }

    fn ttl_match(self) -> [&'static str; 3] {
        match self {
            Self::V4 => ["-m", "ttl", "--ttl-lt"],
            Self::V6 => ["-m", "hl", "--hl-lt"],
        }
    }

    fn hashlimit_tag(self) -> &'static str {
        match self {
            Self::V4 => "4",
            Self::V6 => "6",
        }
    }
}

pub(super) async fn apply_synlimit_rules(targets: &SynLimitTargets) -> Result<(), String> {
    apply_rules_for_binary("iptables", &targets.iptables_v4, IpTablesFamily::V4).await?;
    apply_rules_for_binary("ip6tables", &targets.iptables_v6, IpTablesFamily::V6).await
}

async fn apply_rules_for_binary(
    binary: &str,
    targets: &[SynLimitRule],
    family: IpTablesFamily,
) -> Result<(), String> {
    if targets.is_empty() {
        return Ok(());
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
            &["-t", "filter", "-I", "INPUT", "1", "-j", IPTABLES_CHAIN],
            None,
        )
        .await?;
    }

    for (idx, target) in targets.iter().enumerate() {
        for rule in iptables_synfix_rule_args(target, idx, family) {
            let refs: Vec<&str> = rule.iter().map(String::as_str).collect();
            run_command(binary, &refs, None).await?;
        }
    }
    run_command(
        binary,
        &["-t", "filter", "-A", IPTABLES_CHAIN, "-j", "RETURN"],
        None,
    )
    .await?;

    Ok(())
}

fn iptables_synfix_rule_args(
    target: &SynLimitRule,
    idx: usize,
    family: IpTablesFamily,
) -> Vec<Vec<String>> {
    vec![
        iptables_ios_accept_rule_args(target, idx, family),
        iptables_ios_reject_rule_args(target, family),
        iptables_generic_accept_rule_args(target, idx, family),
        iptables_generic_reject_rule_args(target),
    ]
}

fn iptables_ios_accept_rule_args(
    target: &SynLimitRule,
    idx: usize,
    family: IpTablesFamily,
) -> Vec<String> {
    let hashlimit_name = format!(
        "{IPTABLES_HASHLIMIT_PREFIX}-I{}-{idx}",
        family.hashlimit_tag()
    );
    let mut args = iptables_base_rule_args(target.ip, target.port);
    args.extend(iptables_ios_match_args(family));
    args.extend(iptables_hashlimit_args(
        &hashlimit_name,
        target.ios_seconds,
        target.ios_hitcount,
        target.ios_burst,
        target.hashlimit_expire_ms,
        target.hashlimit_size,
    ));
    args.extend(["-j".to_string(), "ACCEPT".to_string()]);
    args
}

fn iptables_ios_reject_rule_args(target: &SynLimitRule, family: IpTablesFamily) -> Vec<String> {
    let mut args = iptables_base_rule_args(target.ip, target.port);
    args.extend(iptables_ios_match_args(family));
    args.extend(iptables_reject_args());
    args
}

fn iptables_generic_accept_rule_args(
    target: &SynLimitRule,
    idx: usize,
    family: IpTablesFamily,
) -> Vec<String> {
    let hashlimit_name = format!(
        "{IPTABLES_HASHLIMIT_PREFIX}-G{}-{idx}",
        family.hashlimit_tag()
    );
    let mut args = iptables_base_rule_args(target.ip, target.port);
    args.extend(iptables_hashlimit_args(
        &hashlimit_name,
        target.generic_seconds,
        target.generic_hitcount,
        target.generic_burst,
        target.hashlimit_expire_ms,
        target.hashlimit_size,
    ));
    args.extend(["-j".to_string(), "ACCEPT".to_string()]);
    args
}

fn iptables_generic_reject_rule_args(target: &SynLimitRule) -> Vec<String> {
    let mut args = iptables_base_rule_args(target.ip, target.port);
    args.extend(iptables_reject_args());
    args
}

fn iptables_base_rule_args(ip: Option<IpAddr>, port: u16) -> Vec<String> {
    let mut args = vec![
        "-t".to_string(),
        "filter".to_string(),
        "-A".to_string(),
        IPTABLES_CHAIN.to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "--syn".to_string(),
        "-m".to_string(),
        "tcp".to_string(),
        "--tcp-flags".to_string(),
        "SYN".to_string(),
        "SYN".to_string(),
    ];
    if let Some(ip) = ip {
        args.push("-d".to_string());
        args.push(ip.to_string());
    }
    args.extend(["--dport".to_string(), port.to_string()]);
    args
}

fn iptables_ios_match_args(family: IpTablesFamily) -> Vec<String> {
    let mut args = vec![
        "-m".to_string(),
        "length".to_string(),
        "--length".to_string(),
        family.ios_packet_length().to_string(),
    ];
    args.extend(family.ttl_match().map(str::to_string));
    args.push(IOS_TTL_LIMIT.to_string());
    args
}

fn iptables_hashlimit_args(
    name: &str,
    seconds: u32,
    hitcount: u32,
    burst: u32,
    expire_ms: u32,
    size: u32,
) -> Vec<String> {
    vec![
        "-m".to_string(),
        "hashlimit".to_string(),
        "--hashlimit-name".to_string(),
        name.to_string(),
        "--hashlimit-mode".to_string(),
        "srcip".to_string(),
        "--hashlimit-upto".to_string(),
        synlimit_rate_arg(seconds, hitcount),
        "--hashlimit-burst".to_string(),
        burst.to_string(),
        "--hashlimit-htable-expire".to_string(),
        expire_ms.to_string(),
        "--hashlimit-htable-size".to_string(),
        size.to_string(),
    ]
}

fn iptables_reject_args() -> Vec<String> {
    vec![
        "-j".to_string(),
        "REJECT".to_string(),
        "--reject-with".to_string(),
        "tcp-reset".to_string(),
    ]
}

pub(super) async fn clear_rules_for_binary(binary: &str) -> Result<bool, String> {
    let mut errors = Vec::new();
    let mut removed = false;
    for _ in 0..8 {
        match run_command(
            binary,
            &["-t", "filter", "-D", "INPUT", "-j", IPTABLES_CHAIN],
            None,
        )
        .await
        {
            Ok(()) => {
                removed = true;
            }
            Err(error) if is_missing_command_or_iptables_rule(&error) => break,
            Err(error) => {
                errors.push(format!("{binary} delete INPUT jump failed: {error}"));
                break;
            }
        }
    }
    match run_command(binary, &["-t", "filter", "-F", IPTABLES_CHAIN], None).await {
        Ok(()) => {
            removed = true;
        }
        Err(error) if is_missing_command_or_iptables_rule(&error) => {}
        Err(error) => {
            errors.push(format!("{binary} flush chain failed: {error}"));
        }
    }
    match run_command(binary, &["-t", "filter", "-X", IPTABLES_CHAIN], None).await {
        Ok(()) => {
            removed = true;
        }
        Err(error) if is_missing_command_or_iptables_rule(&error) => {}
        Err(error) => {
            errors.push(format!("{binary} delete chain failed: {error}"));
        }
    }

    if errors.is_empty() {
        Ok(removed)
    } else {
        Err(errors.join(", "))
    }
}

fn is_missing_command_or_iptables_rule(error: &str) -> bool {
    error.contains("is not available")
        || error.contains("No chain/target/match by that name")
        || error.contains("does not exist")
        || error.contains("Couldn't load target")
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::synlimit_control::model::test_rule;

    fn has_pair(args: &[String], key: &str, value: &str) -> bool {
        args.windows(2)
            .any(|pair| pair[0].as_str() == key && pair[1].as_str() == value)
    }

    #[test]
    fn iptables_rules_use_synfix_order_and_rejects() {
        let target = test_rule(Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))), 443);
        let rules = iptables_synfix_rule_args(&target, 0, IpTablesFamily::V4);

        assert_eq!(rules.len(), 4);
        assert!(has_pair(&rules[0], "--length", "64"));
        assert!(has_pair(&rules[0], "--ttl-lt", "65"));
        assert!(has_pair(&rules[0], "--hashlimit-upto", "12/second"));
        assert!(has_pair(&rules[0], "--hashlimit-burst", "24"));
        assert!(has_pair(&rules[0], "--hashlimit-htable-expire", "60000"));
        assert!(has_pair(&rules[0], "--hashlimit-htable-size", "32768"));
        assert!(has_pair(&rules[0], "-j", "ACCEPT"));
        assert!(has_pair(&rules[1], "-j", "REJECT"));
        assert!(has_pair(&rules[1], "--reject-with", "tcp-reset"));
        assert!(has_pair(&rules[2], "--hashlimit-upto", "48/minute"));
        assert!(has_pair(&rules[3], "--reject-with", "tcp-reset"));
    }

    #[test]
    fn ip6tables_rules_use_ipv6_hoplimit_classifier() {
        let target = test_rule(Some(IpAddr::V6(Ipv6Addr::LOCALHOST)), 443);
        let rules = iptables_synfix_rule_args(&target, 0, IpTablesFamily::V6);

        assert!(has_pair(&rules[0], "--length", "84"));
        assert!(has_pair(&rules[0], "--hl-lt", "65"));
        assert!(has_pair(&rules[0], "-d", "::1"));
    }
}
