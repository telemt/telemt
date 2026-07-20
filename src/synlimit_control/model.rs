use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::config::{ProxyConfig, SynLimitMode};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct SynLimitRule {
    pub(super) ip: Option<IpAddr>,
    pub(super) port: u16,
    pub(super) generic_seconds: u32,
    pub(super) generic_hitcount: u32,
    pub(super) generic_burst: u32,
    pub(super) ios_seconds: u32,
    pub(super) ios_hitcount: u32,
    pub(super) ios_burst: u32,
    pub(super) hashlimit_expire_ms: u32,
    pub(super) hashlimit_size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SynLimitNamespace {
    pub(super) nft_table: String,
    pub(super) iptables_chain: String,
    pub(super) iptables_hashlimit_prefix: String,
    pub(super) pf_anchor: String,
}

#[derive(Default)]
pub(super) struct SynLimitTargets {
    pub(super) iptables_v4: Vec<SynLimitRule>,
    pub(super) iptables_v6: Vec<SynLimitRule>,
    pub(super) nft_v4: Vec<SynLimitRule>,
    pub(super) nft_v6: Vec<SynLimitRule>,
    pub(super) pf_v4: Vec<SynLimitRule>,
    pub(super) pf_v6: Vec<SynLimitRule>,
}

impl SynLimitTargets {
    pub(super) fn is_empty(&self) -> bool {
        self.iptables_v4.is_empty()
            && self.iptables_v6.is_empty()
            && self.nft_v4.is_empty()
            && self.nft_v6.is_empty()
            && self.pf_v4.is_empty()
            && self.pf_v6.is_empty()
    }

    pub(super) fn has_iptables_targets(&self) -> bool {
        !self.iptables_v4.is_empty() || !self.iptables_v6.is_empty()
    }

    pub(super) fn has_nft_targets(&self) -> bool {
        !self.nft_v4.is_empty() || !self.nft_v6.is_empty()
    }

    pub(super) fn has_pf_targets(&self) -> bool {
        !self.pf_v4.is_empty() || !self.pf_v6.is_empty()
    }
}

struct SynLimitNamespaceHasher {
    value: u64,
}

impl SynLimitNamespaceHasher {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    fn new() -> Self {
        Self {
            value: Self::OFFSET,
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.value ^= u64::from(*byte);
            self.value = self.value.wrapping_mul(Self::PRIME);
        }
    }

    fn write_u8(&mut self, value: u8) {
        self.write(&[value]);
    }

    fn write_u16(&mut self, value: u16) {
        self.write(&value.to_le_bytes());
    }

    fn write_u32(&mut self, value: u32) {
        self.write(&value.to_le_bytes());
    }

    fn finish(self) -> u64 {
        self.value
    }
}

pub(super) fn synlimit_targets(cfg: &ProxyConfig) -> SynLimitTargets {
    let mut iptables_v4 = BTreeSet::new();
    let mut iptables_v6 = BTreeSet::new();
    let mut nft_v4 = BTreeSet::new();
    let mut nft_v6 = BTreeSet::new();
    let mut pf_v4 = BTreeSet::new();
    let mut pf_v6 = BTreeSet::new();

    for listener in &cfg.server.listeners {
        let backend = listener.synlimit;
        if matches!(backend, SynLimitMode::Off) {
            continue;
        }
        let target = SynLimitRule {
            ip: (!listener.ip.is_unspecified()).then_some(listener.ip),
            port: listener.port.unwrap_or(cfg.server.port),
            generic_seconds: listener.synlimit_seconds,
            generic_hitcount: listener.synlimit_hitcount,
            generic_burst: listener.synlimit_burst,
            ios_seconds: listener.synlimit_ios_seconds,
            ios_hitcount: listener.synlimit_ios_hitcount,
            ios_burst: listener.synlimit_ios_burst,
            hashlimit_expire_ms: listener.synlimit_hashlimit_expire_ms,
            hashlimit_size: listener.synlimit_hashlimit_size,
        };

        match (backend, listener.ip.is_ipv4()) {
            (SynLimitMode::Iptables, true) => {
                iptables_v4.insert(target);
            }
            (SynLimitMode::Iptables, false) => {
                iptables_v6.insert(target);
            }
            (SynLimitMode::Nftables, true) => {
                nft_v4.insert(target);
            }
            (SynLimitMode::Nftables, false) => {
                nft_v6.insert(target);
            }
            (SynLimitMode::Pf, true) => {
                pf_v4.insert(target);
            }
            (SynLimitMode::Pf, false) => {
                pf_v6.insert(target);
            }
            (SynLimitMode::Off, _) => {}
        }
    }

    SynLimitTargets {
        iptables_v4: iptables_v4.into_iter().collect(),
        iptables_v6: iptables_v6.into_iter().collect(),
        nft_v4: nft_v4.into_iter().collect(),
        nft_v6: nft_v6.into_iter().collect(),
        pf_v4: pf_v4.into_iter().collect(),
        pf_v6: pf_v6.into_iter().collect(),
    }
}

pub(super) fn synlimit_namespace(targets: &SynLimitTargets) -> Option<SynLimitNamespace> {
    if targets.is_empty() {
        return None;
    }

    let mut hasher = SynLimitNamespaceHasher::new();
    write_namespace_rule_group(&mut hasher, b"iptables-v4", &targets.iptables_v4);
    write_namespace_rule_group(&mut hasher, b"iptables-v6", &targets.iptables_v6);
    write_namespace_rule_group(&mut hasher, b"nft-v4", &targets.nft_v4);
    write_namespace_rule_group(&mut hasher, b"nft-v6", &targets.nft_v6);
    write_namespace_rule_group(&mut hasher, b"pf-v4", &targets.pf_v4);
    write_namespace_rule_group(&mut hasher, b"pf-v6", &targets.pf_v6);

    let suffix = format!("{:016x}", hasher.finish());
    let iptables_suffix = &suffix[..12];
    let hashlimit_suffix = &suffix[..10];
    Some(SynLimitNamespace {
        nft_table: format!("telemt_synlimit_{suffix}"),
        iptables_chain: format!("TMT_SYN_{iptables_suffix}"),
        iptables_hashlimit_prefix: format!("TMT{hashlimit_suffix}"),
        pf_anchor: format!("telemt_synlimit/{suffix}"),
    })
}

fn write_namespace_rule_group(
    hasher: &mut SynLimitNamespaceHasher,
    group: &[u8],
    rules: &[SynLimitRule],
) {
    hasher.write(group);
    hasher.write_u32(rules.len() as u32);
    for rule in rules {
        write_namespace_rule(hasher, rule);
    }
}

fn write_namespace_rule(hasher: &mut SynLimitNamespaceHasher, rule: &SynLimitRule) {
    match rule.ip {
        Some(IpAddr::V4(ip)) => {
            hasher.write_u8(4);
            hasher.write(&ip.octets());
        }
        Some(IpAddr::V6(ip)) => {
            hasher.write_u8(6);
            hasher.write(&ip.octets());
        }
        None => {
            hasher.write_u8(0);
        }
    }
    hasher.write_u16(rule.port);
    hasher.write_u32(rule.generic_seconds);
    hasher.write_u32(rule.generic_hitcount);
    hasher.write_u32(rule.generic_burst);
    hasher.write_u32(rule.ios_seconds);
    hasher.write_u32(rule.ios_hitcount);
    hasher.write_u32(rule.ios_burst);
    hasher.write_u32(rule.hashlimit_expire_ms);
    hasher.write_u32(rule.hashlimit_size);
}

pub(super) fn synlimit_rate_arg(seconds: u32, hitcount: u32) -> String {
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

#[cfg(test)]
pub(super) fn test_rule(ip: Option<IpAddr>, port: u16) -> SynLimitRule {
    SynLimitRule {
        ip,
        port,
        generic_seconds: 60,
        generic_hitcount: 48,
        generic_burst: 1,
        ios_seconds: 1,
        ios_hitcount: 12,
        ios_burst: 24,
        hashlimit_expire_ms: 60_000,
        hashlimit_size: 32_768,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::config::ListenerConfig;

    fn listener(ip: IpAddr, port: Option<u16>, synlimit: SynLimitMode) -> ListenerConfig {
        ListenerConfig {
            ip,
            port,
            client_mss: None,
            synlimit,
            synlimit_seconds: 60,
            synlimit_hitcount: 48,
            synlimit_burst: 1,
            synlimit_ios_seconds: 1,
            synlimit_ios_hitcount: 12,
            synlimit_ios_burst: 24,
            synlimit_hashlimit_expire_ms: 60_000,
            synlimit_hashlimit_size: 32_768,
            announce: None,
            announce_ip: None,
            proxy_protocol: None,
            reuse_allow: false,
        }
    }

    #[test]
    fn synlimit_targets_deduplicate_and_use_legacy_port_fallback() {
        let mut cfg = ProxyConfig::default();
        cfg.server.port = 9443;
        cfg.server.listeners = vec![
            listener(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                None,
                SynLimitMode::Iptables,
            ),
            listener(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                None,
                SynLimitMode::Iptables,
            ),
        ];

        let targets = synlimit_targets(&cfg);

        assert_eq!(targets.iptables_v4.len(), 1);
        assert_eq!(targets.iptables_v4[0].ip, None);
        assert_eq!(targets.iptables_v4[0].port, 9443);
        assert!(targets.iptables_v6.is_empty());
        assert!(targets.nft_v4.is_empty());
        assert!(targets.nft_v6.is_empty());
    }

    #[test]
    fn synlimit_targets_separate_backends_and_ip_families() {
        let mut cfg = ProxyConfig::default();
        cfg.server.listeners = vec![
            listener(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                Some(443),
                SynLimitMode::Iptables,
            ),
            listener(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                Some(443),
                SynLimitMode::Iptables,
            ),
            listener(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
                Some(444),
                SynLimitMode::Nftables,
            ),
            listener(
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                Some(444),
                SynLimitMode::Nftables,
            ),
            listener(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3)),
                Some(445),
                SynLimitMode::Pf,
            ),
            listener(
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                Some(445),
                SynLimitMode::Pf,
            ),
        ];

        let targets = synlimit_targets(&cfg);

        assert_eq!(targets.iptables_v4.len(), 1);
        assert_eq!(targets.iptables_v6.len(), 1);
        assert_eq!(targets.nft_v4.len(), 1);
        assert_eq!(targets.nft_v6.len(), 1);
        assert_eq!(targets.pf_v4.len(), 1);
        assert_eq!(targets.pf_v6.len(), 1);
        assert_eq!(
            targets.iptables_v4[0].ip,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)))
        );
        assert_eq!(
            targets.iptables_v6[0].ip,
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(
            targets.nft_v4[0].ip,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)))
        );
        assert_eq!(targets.nft_v6[0].ip, None);
        assert_eq!(
            targets.pf_v4[0].ip,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3)))
        );
        assert_eq!(targets.pf_v6[0].ip, None);
    }

    #[test]
    fn synlimit_namespace_is_stable_and_changes_by_targets() {
        let mut cfg = ProxyConfig::default();
        cfg.server.listeners = vec![listener(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            Some(443),
            SynLimitMode::Nftables,
        )];
        let first = synlimit_namespace(&synlimit_targets(&cfg))
            .expect("configured targets must have a namespace");
        let second = synlimit_namespace(&synlimit_targets(&cfg))
            .expect("configured targets must have a namespace");

        cfg.server.listeners[0].port = Some(444);
        let changed = synlimit_namespace(&synlimit_targets(&cfg))
            .expect("configured targets must have a namespace");

        assert_eq!(first, second);
        assert_ne!(first, changed);
        assert!(first.nft_table.starts_with("telemt_synlimit_"));
        assert!(first.iptables_chain.starts_with("TMT_SYN_"));
        assert!(first.iptables_chain.len() <= 28);
        assert!(first.iptables_hashlimit_prefix.starts_with("TMT"));
        assert!(first.pf_anchor.starts_with("telemt_synlimit/"));
    }

    #[test]
    fn synlimit_rate_arg_uses_native_units_without_fractional_rates() {
        assert_eq!(synlimit_rate_arg(1, 12), "12/second");
        assert_eq!(synlimit_rate_arg(60, 48), "48/minute");
        assert_eq!(synlimit_rate_arg(3600, 121), "121/hour");
        assert_eq!(synlimit_rate_arg(86400, 241), "241/day");
    }
}
