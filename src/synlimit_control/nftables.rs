use super::command::{run_command, run_command_stdout};
use super::model::{SynLimitNamespace, SynLimitRule, SynLimitTargets, synlimit_rate_arg};

const NFT_CHAIN: &str = "input";
const NFT_INPUT_PRIORITY: i16 = -5;
const IPV4_IOS_PACKET_LENGTH: u16 = 64;
const IPV6_IOS_PACKET_LENGTH: u16 = 84;
const IOS_TTL_LIMIT: u8 = 65;

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
    v4_targets: &'a [SynLimitRule],
    v6_targets: &'a [SynLimitRule],
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

pub(super) async fn apply_synlimit_rules(
    targets: &SynLimitTargets,
    namespace: &SynLimitNamespace,
) -> Result<(), String> {
    let families = detect_nft_table_families().await;
    for plan in nft_apply_plan(families, &targets.nft_v4, &targets.nft_v6) {
        let script = nft_synlimit_script(plan, namespace);
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
    v4_targets: &'a [SynLimitRule],
    v6_targets: &'a [SynLimitRule],
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

fn nft_synlimit_script(plan: NftApplyPlan<'_>, namespace: &SynLimitNamespace) -> String {
    let mut script = String::new();
    script.push_str(&format!(
        "table {} {} {{\n",
        plan.family.as_str(),
        namespace.nft_table
    ));
    script.push_str(&format!("  chain {NFT_CHAIN} {{\n"));
    script.push_str(&format!(
        "    type filter hook input priority {NFT_INPUT_PRIORITY}; policy accept;\n"
    ));
    for (idx, target) in plan.v4_targets.iter().enumerate() {
        push_nft_v4_rules(&mut script, target, idx);
    }
    for (idx, target) in plan.v6_targets.iter().enumerate() {
        push_nft_v6_rules(&mut script, target, idx);
    }
    script.push_str("  }\n");
    script.push_str("}\n");
    script
}

fn push_nft_v4_rules(script: &mut String, target: &SynLimitRule, idx: usize) {
    let daddr = target
        .ip
        .map(|ip| format!(" ip daddr {ip}"))
        .unwrap_or_default();
    let ios_rate = synlimit_rate_arg(target.ios_seconds, target.ios_hitcount);
    let generic_rate = synlimit_rate_arg(target.generic_seconds, target.generic_hitcount);
    script.push_str(&format!(
        "    tcp flags & (fin|syn|rst|ack) == syn{daddr} meta length {IPV4_IOS_PACKET_LENGTH} ip ttl < {IOS_TTL_LIMIT} tcp dport {port} meter telemt_synfix_ios_v4_{idx} {{ ip saddr limit rate over {ios_rate} burst {ios_burst} packets }} reject with tcp reset\n",
        port = target.port,
        ios_burst = target.ios_burst,
    ));
    script.push_str(&format!(
        "    tcp flags & (fin|syn|rst|ack) == syn{daddr} meta length {IPV4_IOS_PACKET_LENGTH} ip ttl < {IOS_TTL_LIMIT} tcp dport {port} accept\n",
        port = target.port,
    ));
    script.push_str(&format!(
        "    tcp flags & (fin|syn|rst|ack) == syn{daddr} tcp dport {port} meter telemt_synfix_v4_{idx} {{ ip saddr limit rate over {generic_rate} burst {generic_burst} packets }} reject with tcp reset\n",
        port = target.port,
        generic_burst = target.generic_burst,
    ));
    script.push_str(&format!(
        "    tcp flags & (fin|syn|rst|ack) == syn{daddr} tcp dport {port} accept\n",
        port = target.port,
    ));
}

fn push_nft_v6_rules(script: &mut String, target: &SynLimitRule, idx: usize) {
    let daddr = target
        .ip
        .map(|ip| format!(" ip6 daddr {ip}"))
        .unwrap_or_default();
    let ios_rate = synlimit_rate_arg(target.ios_seconds, target.ios_hitcount);
    let generic_rate = synlimit_rate_arg(target.generic_seconds, target.generic_hitcount);
    script.push_str(&format!(
        "    tcp flags & (fin|syn|rst|ack) == syn{daddr} meta length {IPV6_IOS_PACKET_LENGTH} ip6 hoplimit < {IOS_TTL_LIMIT} tcp dport {port} meter telemt_synfix_ios_v6_{idx} {{ ip6 saddr limit rate over {ios_rate} burst {ios_burst} packets }} reject with tcp reset\n",
        port = target.port,
        ios_burst = target.ios_burst,
    ));
    script.push_str(&format!(
        "    tcp flags & (fin|syn|rst|ack) == syn{daddr} meta length {IPV6_IOS_PACKET_LENGTH} ip6 hoplimit < {IOS_TTL_LIMIT} tcp dport {port} accept\n",
        port = target.port,
    ));
    script.push_str(&format!(
        "    tcp flags & (fin|syn|rst|ack) == syn{daddr} tcp dport {port} meter telemt_synfix_v6_{idx} {{ ip6 saddr limit rate over {generic_rate} burst {generic_burst} packets }} reject with tcp reset\n",
        port = target.port,
        generic_burst = target.generic_burst,
    ));
    script.push_str(&format!(
        "    tcp flags & (fin|syn|rst|ack) == syn{daddr} tcp dport {port} accept\n",
        port = target.port,
    ));
}

pub(super) async fn clear_rules_all_families(
    namespace: &SynLimitNamespace,
) -> Result<bool, String> {
    let mut errors = Vec::new();
    let mut removed = false;
    let table = namespace.nft_table.as_str();
    for family in [NftFamily::Inet, NftFamily::Ip, NftFamily::Ip6] {
        match run_command("nft", &["delete", "table", family.as_str(), table], None).await {
            Ok(()) => {
                removed = true;
            }
            Err(error) if is_missing_command_or_nft_table(&error) => {}
            Err(error) => {
                errors.push(format!(
                    "nft delete table {} {table} failed: {error}",
                    family.as_str(),
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(removed)
    } else {
        Err(errors.join(", "))
    }
}

fn is_missing_command_or_nft_table(error: &str) -> bool {
    error.contains("is not available") || error.contains("No such file or directory")
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::synlimit_control::model::test_rule;

    fn test_namespace(table: &str) -> SynLimitNamespace {
        SynLimitNamespace {
            nft_table: table.to_string(),
            iptables_chain: "TMT_SYN_TEST".to_string(),
            iptables_hashlimit_prefix: "TMTTEST".to_string(),
        }
    }

    #[test]
    fn nft_script_uses_synfix_v4_rules_and_early_priority() {
        let rule = test_rule(Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))), 443);
        let namespace = test_namespace("telemt_synlimit_test_a");
        let script = nft_synlimit_script(
            NftApplyPlan {
                family: NftFamily::Inet,
                v4_targets: &[rule],
                v6_targets: &[],
            },
            &namespace,
        );

        assert!(script.contains("table inet telemt_synlimit_test_a"));
        assert!(script.contains("type filter hook input priority -5; policy accept;"));
        assert!(script.contains("ip daddr 203.0.113.7"));
        assert!(script.contains("meta length 64 ip ttl < 65"));
        assert!(script.contains("limit rate over 12/second burst 24 packets"));
        assert!(script.contains("limit rate over 48/minute burst 1 packets"));
        assert!(script.contains("reject with tcp reset"));
    }

    #[test]
    fn nft_script_uses_ipv6_hoplimit_classifier() {
        let rule = test_rule(Some(IpAddr::V6(Ipv6Addr::LOCALHOST)), 443);
        let namespace = test_namespace("telemt_synlimit_test_b");
        let script = nft_synlimit_script(
            NftApplyPlan {
                family: NftFamily::Inet,
                v4_targets: &[],
                v6_targets: &[rule],
            },
            &namespace,
        );

        assert!(script.contains("table inet telemt_synlimit_test_b"));
        assert!(script.contains("ip6 daddr ::1"));
        assert!(script.contains("meta length 84 ip6 hoplimit < 65"));
        assert!(script.contains("ip6 saddr limit rate over 12/second burst 24 packets"));
        assert!(script.contains("ip6 saddr limit rate over 48/minute burst 1 packets"));
    }

    #[test]
    fn nft_missing_table_errors_are_cleanup_benign() {
        assert!(is_missing_command_or_nft_table("nft is not available"));
        assert!(is_missing_command_or_nft_table(
            "Error: No such file or directory"
        ));
        assert!(!is_missing_command_or_nft_table(
            "Error: Operation not permitted"
        ));
    }

    #[test]
    fn nft_apply_plan_keeps_dual_stack_rules_in_inet_table() {
        let v4_rule = test_rule(Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))), 443);
        let v6_rule = test_rule(Some(IpAddr::V6(Ipv6Addr::LOCALHOST)), 443);
        let v4_rules = [v4_rule];
        let v6_rules = [v6_rule];
        let plans = nft_apply_plan(
            NftTableFamilies {
                inet: false,
                ip: false,
                ip6: false,
            },
            &v4_rules,
            &v6_rules,
        );

        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].family.as_str(), "inet");
        assert_eq!(plans[0].v4_targets, v4_rules.as_slice());
        assert_eq!(plans[0].v6_targets, v6_rules.as_slice());
    }
}
