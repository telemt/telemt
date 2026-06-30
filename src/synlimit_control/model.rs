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

#[derive(Default)]
pub(super) struct SynLimitTargets {
    pub(super) iptables_v4: Vec<SynLimitRule>,
    pub(super) iptables_v6: Vec<SynLimitRule>,
    pub(super) nft_v4: Vec<SynLimitRule>,
    pub(super) nft_v6: Vec<SynLimitRule>,
}

impl SynLimitTargets {
    pub(super) fn is_empty(&self) -> bool {
        self.iptables_v4.is_empty()
            && self.iptables_v6.is_empty()
            && self.nft_v4.is_empty()
            && self.nft_v6.is_empty()
    }

    pub(super) fn has_iptables_targets(&self) -> bool {
        !self.iptables_v4.is_empty() || !self.iptables_v6.is_empty()
    }

    pub(super) fn has_nft_targets(&self) -> bool {
        !self.nft_v4.is_empty() || !self.nft_v6.is_empty()
    }
}

pub(super) fn synlimit_targets(cfg: &ProxyConfig) -> SynLimitTargets {
    let mut iptables_v4 = BTreeSet::new();
    let mut iptables_v6 = BTreeSet::new();
    let mut nft_v4 = BTreeSet::new();
    let mut nft_v6 = BTreeSet::new();

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
        ];

        let targets = synlimit_targets(&cfg);

        assert_eq!(targets.iptables_v4.len(), 1);
        assert_eq!(targets.iptables_v6.len(), 1);
        assert_eq!(targets.nft_v4.len(), 1);
        assert_eq!(targets.nft_v6.len(), 1);
        assert_eq!(
            targets.iptables_v4[0].ip,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)))
        );
        assert_eq!(targets.iptables_v6[0].ip, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(
            targets.nft_v4[0].ip,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)))
        );
        assert_eq!(targets.nft_v6[0].ip, None);
    }

    #[test]
    fn synlimit_rate_arg_uses_native_units_without_fractional_rates() {
        assert_eq!(synlimit_rate_arg(1, 12), "12/second");
        assert_eq!(synlimit_rate_arg(60, 48), "48/minute");
        assert_eq!(synlimit_rate_arg(3600, 121), "121/hour");
        assert_eq!(synlimit_rate_arg(86400, 241), "241/day");
    }
}
