#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::NetworkConfig;
use crate::error::Result;
use crate::network::stun::{stun_probe_dual, DualStunResult, IpFamily, StunProbeResult};

#[derive(Debug, Clone, Default)]
pub struct NetworkProbe {
    pub detected_ipv4: Option<Ipv4Addr>,
    pub detected_ipv6: Option<Ipv6Addr>,
    pub reflected_ipv4: Option<SocketAddr>,
    pub reflected_ipv6: Option<SocketAddr>,
    pub ipv4_is_bogon: bool,
    pub ipv6_is_bogon: bool,
    pub ipv4_nat_detected: bool,
    pub ipv6_nat_detected: bool,
    pub ipv4_usable: bool,
    pub ipv6_usable: bool,
}

#[derive(Debug, Clone, Default)]
pub struct NetworkDecision {
    pub ipv4_dc: bool,
    pub ipv6_dc: bool,
    pub ipv4_me: bool,
    pub ipv6_me: bool,
    pub effective_prefer: u8,
    pub effective_multipath: bool,
}

impl NetworkDecision {
    pub fn prefer_ipv6(&self) -> bool {
        self.effective_prefer == 6
    }

    pub fn me_families(&self) -> Vec<IpFamily> {
        let mut res = Vec::new();
        if self.ipv4_me {
            res.push(IpFamily::V4);
        }
        if self.ipv6_me {
            res.push(IpFamily::V6);
        }
        res
    }
}

const STUN_BATCH_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn run_probe(
    config: &NetworkConfig,
    nat_probe: bool,
    stun_nat_probe_concurrency: usize,
) -> Result<NetworkProbe> {
    let mut probe = NetworkProbe::default();

    probe.detected_ipv4 = detect_local_ip_v4();
    probe.detected_ipv6 = detect_local_ip_v6();

    probe.ipv4_is_bogon = probe.detected_ipv4.map(is_bogon_v4).unwrap_or(false);
    probe.ipv6_is_bogon = probe.detected_ipv6.map(is_bogon_v6).unwrap_or(false);

    let stun_res = if nat_probe {
        let servers = collect_stun_servers(config);
        if servers.is_empty() {
            warn!("STUN probe is enabled but network.stun_servers is empty");
            DualStunResult::default()
        } else {
            probe_stun_servers_parallel(
                &servers,
                stun_nat_probe_concurrency.max(1),
            )
            .await
        }
    } else {
        DualStunResult::default()
    };
    probe.reflected_ipv4 = stun_res.v4.map(|r| r.reflected_addr);
    probe.reflected_ipv6 = stun_res.v6.map(|r| r.reflected_addr);

    // If STUN is blocked but IPv4 is private, try HTTP public-IP fallback.
    if nat_probe
        && probe.reflected_ipv4.is_none()
        && probe.detected_ipv4.map(is_bogon_v4).unwrap_or(false)
    {
        if let Some(public_ip) = detect_public_ipv4_http(&config.http_ip_detect_urls).await {
            probe.reflected_ipv4 = Some(SocketAddr::new(IpAddr::V4(public_ip), 0));
            info!(public_ip = %public_ip, "STUN unavailable, using HTTP public IPv4 fallback");
        }
    }

    probe.ipv4_nat_detected = match (probe.detected_ipv4, probe.reflected_ipv4) {
        (Some(det), Some(reflected)) => det != reflected.ip(),
        _ => false,
    };
    probe.ipv6_nat_detected = match (probe.detected_ipv6, probe.reflected_ipv6) {
        (Some(det), Some(reflected)) => det != reflected.ip(),
        _ => false,
    };

    probe.ipv4_usable = config.ipv4
        && probe.detected_ipv4.is_some()
        && (!probe.ipv4_is_bogon || probe.reflected_ipv4.map(|r| !is_bogon(r.ip())).unwrap_or(false));

    let ipv6_enabled = config.ipv6.unwrap_or(probe.detected_ipv6.is_some());
    probe.ipv6_usable = ipv6_enabled
        && probe.detected_ipv6.is_some()
        && (!probe.ipv6_is_bogon || probe.reflected_ipv6.map(|r| !is_bogon(r.ip())).unwrap_or(false));

    Ok(probe)
}

async fn detect_public_ipv4_http(urls: &[String]) -> Option<Ipv4Addr> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .ok()?;

    for url in urls {
        let response = match client.get(url).send().await {
            Ok(response) => response,
            Err(_) => continue,
        };

        let body = match response.text().await {
            Ok(body) => body,
            Err(_) => continue,
        };

        let Ok(ip) = body.trim().parse::<Ipv4Addr>() else {
            continue;
        };
        if !is_bogon_v4(ip) {
            return Some(ip);
        }
    }

    None
}

fn collect_stun_servers(config: &NetworkConfig) -> Vec<String> {
    let mut out = Vec::new();
    for s in &config.stun_servers {
        if !s.is_empty() && !out.contains(s) {
            out.push(s.clone());
        }
    }
    out
}

async fn probe_stun_servers_parallel(
    servers: &[String],
    concurrency: usize,
) -> DualStunResult {
    let mut join_set = JoinSet::new();
    let mut next_idx = 0usize;
    let mut best_v4_by_ip: HashMap<IpAddr, (usize, StunProbeResult)> = HashMap::new();
    let mut best_v6_by_ip: HashMap<IpAddr, (usize, StunProbeResult)> = HashMap::new();

    while next_idx < servers.len() || !join_set.is_empty() {
        while next_idx < servers.len() && join_set.len() < concurrency {
            let stun_addr = servers[next_idx].clone();
            next_idx += 1;
            join_set.spawn(async move {
                let res = timeout(STUN_BATCH_TIMEOUT, stun_probe_dual(&stun_addr)).await;
                (stun_addr, res)
            });
        }

        let Some(task) = join_set.join_next().await else {
            break;
        };

        match task {
            Ok((stun_addr, Ok(Ok(result)))) => {
                if let Some(v4) = result.v4 {
                    let entry = best_v4_by_ip.entry(v4.reflected_addr.ip()).or_insert((0, v4));
                    entry.0 += 1;
                }
                if let Some(v6) = result.v6 {
                    let entry = best_v6_by_ip.entry(v6.reflected_addr.ip()).or_insert((0, v6));
                    entry.0 += 1;
                }
                if result.v4.is_some() || result.v6.is_some() {
                    debug!(stun = %stun_addr, "STUN server responded within probe timeout");
                }
            }
            Ok((stun_addr, Ok(Err(e)))) => {
                debug!(error = %e, stun = %stun_addr, "STUN probe failed");
            }
            Ok((stun_addr, Err(_))) => {
                debug!(stun = %stun_addr, "STUN probe timeout");
            }
            Err(e) => {
                debug!(error = %e, "STUN probe task join failed");
            }
        }
    }

    let mut out = DualStunResult::default();
    if let Some((_, best)) = best_v4_by_ip
        .into_values()
        .max_by_key(|(count, _)| *count)
    {
        info!("STUN-Quorum reached, IP: {}", best.reflected_addr.ip());
        out.v4 = Some(best);
    }
    if let Some((_, best)) = best_v6_by_ip
        .into_values()
        .max_by_key(|(count, _)| *count)
    {
        info!("STUN-Quorum reached, IP: {}", best.reflected_addr.ip());
        out.v6 = Some(best);
    }
    out
}

pub fn decide_network_capabilities(config: &NetworkConfig, probe: &NetworkProbe) -> NetworkDecision {
    let ipv4_dc = config.ipv4 && probe.detected_ipv4.is_some();
    let ipv6_dc = config.ipv6.unwrap_or(probe.detected_ipv6.is_some()) && probe.detected_ipv6.is_some();

    let ipv4_me = config.ipv4
        && probe.detected_ipv4.is_some()
        && (!probe.ipv4_is_bogon || probe.reflected_ipv4.is_some());

    let ipv6_enabled = config.ipv6.unwrap_or(probe.detected_ipv6.is_some());
    let ipv6_me = ipv6_enabled
        && probe.detected_ipv6.is_some()
        && (!probe.ipv6_is_bogon || probe.reflected_ipv6.is_some());

    let effective_prefer = match config.prefer {
        6 if ipv6_me || ipv6_dc => 6,
        4 if ipv4_me || ipv4_dc => 4,
        6 => {
            warn!("prefer=6 requested but IPv6 unavailable; falling back to IPv4");
            4
        }
        _ => 4,
    };

    let me_families = ipv4_me as u8 + ipv6_me as u8;
    let effective_multipath = config.multipath && me_families >= 2;

    NetworkDecision {
        ipv4_dc,
        ipv6_dc,
        ipv4_me,
        ipv6_me,
        effective_prefer,
        effective_multipath,
    }
}

fn detect_local_ip_v4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

fn detect_local_ip_v6() -> Option<Ipv6Addr> {
    let socket = UdpSocket::bind("[::]:0").ok()?;
    socket.connect("[2001:4860:4860::8888]:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V6(v6) => Some(v6),
        _ => None,
    }
}

pub fn is_bogon(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_bogon_v4(v4),
        IpAddr::V6(v6) => is_bogon_v6(v6),
    }
}

pub fn is_bogon_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    if ip.is_private() || ip.is_loopback() || ip.is_link_local() {
        return true;
    }
    if octets[0] == 0 {
        return true;
    }
    if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
        return true;
    }
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return true;
    }
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return true;
    }
    if octets[0] == 198 && (octets[1] & 0xFE) == 18 {
        return true;
    }
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return true;
    }
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return true;
    }
    if ip.is_multicast() {
        return true;
    }
    if octets[0] >= 240 {
        return true;
    }
    if ip.is_broadcast() {
        return true;
    }
    false
}

pub fn is_bogon_v6(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_unique_local() {
        return true;
    }
    let segs = ip.segments();
    if (segs[0] & 0xFFC0) == 0xFE80 {
        return true;
    }
    if segs[0..5] == [0, 0, 0, 0, 0] && segs[5] == 0xFFFF {
        return true;
    }
    if segs[0] == 0x0100 && segs[1..4] == [0, 0, 0] {
        return true;
    }
    if segs[0] == 0x2001 && segs[1] == 0x0db8 {
        return true;
    }
    if segs[0] == 0x2002 {
        return true;
    }
    if ip.is_multicast() {
        return true;
    }
    false
}

pub fn log_probe_result(probe: &NetworkProbe, decision: &NetworkDecision) {
    info!(
        ipv4 = probe.detected_ipv4.as_ref().map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
        ipv6 = probe.detected_ipv6.as_ref().map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
        reflected_v4 = probe.reflected_ipv4.as_ref().map(|v| v.ip().to_string()).unwrap_or_else(|| "-".into()),
        reflected_v6 = probe.reflected_ipv6.as_ref().map(|v| v.ip().to_string()).unwrap_or_else(|| "-".into()),
        ipv4_bogon = probe.ipv4_is_bogon,
        ipv6_bogon = probe.ipv6_is_bogon,
        ipv4_me = decision.ipv4_me,
        ipv6_me = decision.ipv6_me,
        ipv4_dc = decision.ipv4_dc,
        ipv6_dc = decision.ipv6_dc,
        prefer = decision.effective_prefer,
        multipath = decision.effective_multipath,
        "Network capabilities resolved"
    );
}
