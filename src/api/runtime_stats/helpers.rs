use super::*;

pub(super) fn disabled_me_writers(now_epoch_secs: u64, reason: &'static str) -> MeWritersData {
    MeWritersData {
        middle_proxy_enabled: false,
        reason: Some(reason),
        generated_at_epoch_secs: now_epoch_secs,
        summary: MeWritersSummary {
            configured_dc_groups: 0,
            configured_endpoints: 0,
            available_endpoints: 0,
            available_pct: 0.0,
            required_writers: 0,
            alive_writers: 0,
            coverage_pct: 0.0,
            fresh_alive_writers: 0,
            fresh_coverage_pct: 0.0,
        },
        writers: Vec::new(),
    }
}

pub(super) fn disabled_dcs(now_epoch_secs: u64, reason: &'static str) -> DcStatusData {
    DcStatusData {
        middle_proxy_enabled: false,
        reason: Some(reason),
        generated_at_epoch_secs: now_epoch_secs,
        dcs: Vec::new(),
    }
}

pub(super) fn map_route_kind(value: UpstreamRouteKind) -> &'static str {
    match value {
        UpstreamRouteKind::Direct => "direct",
        UpstreamRouteKind::Socks4 => "socks4",
        UpstreamRouteKind::Socks5 => "socks5",
        UpstreamRouteKind::Shadowsocks => "shadowsocks",
    }
}

pub(super) fn map_ip_preference(value: IpPreference) -> &'static str {
    match value {
        IpPreference::Unknown => "unknown",
        IpPreference::PreferV6 => "prefer_v6",
        IpPreference::PreferV4 => "prefer_v4",
        IpPreference::BothWork => "both_work",
        IpPreference::Unavailable => "unavailable",
    }
}

pub(super) fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
