#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use url::Url;

use crate::config::{NetworkConfig, UpstreamConfig, UpstreamType};
use crate::error::Result;
use crate::network::stun::{stun_probe_family_with_bind, DualStunResult, IpFamily, StunProbeResult};
use crate::transport::UpstreamManager;

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
    pub const fn prefer_ipv6(&self) -> bool {
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
    upstreams: &[UpstreamConfig],
    nat_probe: bool,
    stun_nat_probe_concurrency: usize,
) -> Result<NetworkProbe> {
    let mut probe = NetworkProbe::default();
    let servers = collect_stun_servers(config);
    let mut detected_ipv4 = detect_local_ip_v4();
    let mut detected_ipv6 = detect_local_ip_v6();
    let mut explicit_detected_ipv4 = false;
    let mut explicit_detected_ipv6 = false;
    let mut explicit_reflected_ipv4 = false;
    let mut explicit_reflected_ipv6 = false;
    let mut strict_bind_ipv4_requested = false;
    let mut strict_bind_ipv6_requested = false;

    let global_stun_res = if nat_probe && config.stun_use {
        if servers.is_empty() {
            warn!("STUN probe is enabled but network.stun_servers is empty");
            DualStunResult::default()
        } else {
            probe_stun_servers_parallel(
                &servers,
                stun_nat_probe_concurrency.max(1),
                None,
                None,
            )
            .await
        }
    } else if nat_probe {
        info!("STUN probe is disabled by network.stun_use=false");
        DualStunResult::default()
    } else {
        DualStunResult::default()
    };
    let mut reflected_ipv4 = global_stun_res.v4.map(|r| r.reflected_addr);
    let mut reflected_ipv6 = global_stun_res.v6.map(|r| r.reflected_addr);

    for upstream in upstreams.iter().filter(|upstream| upstream.enabled) {
        let UpstreamType::Direct {
            interface,
            bind_addresses,
        } = &upstream.upstream_type else {
            continue;
        };
        if let Some(addrs) = bind_addresses.as_ref().filter(|v| !v.is_empty()) {
            let mut saw_parsed_ip = false;
            for value in addrs {
                if let Ok(ip) = value.parse::<IpAddr>() {
                    saw_parsed_ip = true;
                    if ip.is_ipv4() {
                        strict_bind_ipv4_requested = true;
                    } else {
                        strict_bind_ipv6_requested = true;
                    }
                }
            }
            if !saw_parsed_ip {
                strict_bind_ipv4_requested = true;
                strict_bind_ipv6_requested = true;
            }
        }

        let bind_v4 = UpstreamManager::resolve_bind_address(
            interface,
            bind_addresses,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 443),
            None,
            true,
        );
        let bind_v6 = UpstreamManager::resolve_bind_address(
            interface,
            bind_addresses,
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                443,
            ),
            None,
            true,
        );

        if let Some(IpAddr::V4(ip)) = bind_v4
            && !explicit_detected_ipv4
        {
            detected_ipv4 = Some(ip);
            explicit_detected_ipv4 = true;
        }
        if let Some(IpAddr::V6(ip)) = bind_v6
            && !explicit_detected_ipv6
        {
            detected_ipv6 = Some(ip);
            explicit_detected_ipv6 = true;
        }
        if bind_v4.is_none() && bind_v6.is_none() {
            continue;
        }

        if !(nat_probe && config.stun_use) || servers.is_empty() {
            continue;
        }

        let direct_stun_res = probe_stun_servers_parallel(
            &servers,
            stun_nat_probe_concurrency.max(1),
            bind_v4,
            bind_v6,
        )
        .await;
        if let Some(reflected) = direct_stun_res.v4.map(|r| r.reflected_addr) {
            reflected_ipv4 = Some(reflected);
            explicit_reflected_ipv4 = true;
        }
        if let Some(reflected) = direct_stun_res.v6.map(|r| r.reflected_addr) {
            reflected_ipv6 = Some(reflected);
            explicit_reflected_ipv6 = true;
        }
    }

    if strict_bind_ipv4_requested && !explicit_detected_ipv4 {
        detected_ipv4 = None;
        reflected_ipv4 = None;
    } else if strict_bind_ipv4_requested && !explicit_reflected_ipv4 {
        reflected_ipv4 = None;
    }
    if strict_bind_ipv6_requested && !explicit_detected_ipv6 {
        detected_ipv6 = None;
        reflected_ipv6 = None;
    } else if strict_bind_ipv6_requested && !explicit_reflected_ipv6 {
        reflected_ipv6 = None;
    }

    probe.detected_ipv4 = detected_ipv4;
    probe.detected_ipv6 = detected_ipv6;
    probe.reflected_ipv4 = reflected_ipv4;
    probe.reflected_ipv6 = reflected_ipv6;
    probe.ipv4_is_bogon = probe.detected_ipv4.map(is_bogon_v4).unwrap_or(false);
    probe.ipv6_is_bogon = probe.detected_ipv6.map(is_bogon_v6).unwrap_or(false);

    // If STUN is blocked but IPv4 is private, try HTTP public-IP fallback.
    if nat_probe
        && probe.reflected_ipv4.is_none()
        && probe.detected_ipv4.map(is_bogon_v4).unwrap_or(false)
        && let Some(public_ip) = detect_public_ipv4_http(&config.http_ip_detect_urls).await {
            probe.reflected_ipv4 = Some(SocketAddr::new(IpAddr::V4(public_ip), 0));
            info!(public_ip = %public_ip, "STUN unavailable, using HTTP public IPv4 fallback");
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

    let ipv6_enabled = config
        .ipv6
        .unwrap_or_else(|| probe.detected_ipv6.is_some());
    probe.ipv6_usable = ipv6_enabled
        && probe.detected_ipv6.is_some()
        && (!probe.ipv6_is_bogon || probe.reflected_ipv6.map(|r| !is_bogon(r.ip())).unwrap_or(false));

    Ok(probe)
}

// Validates a user-supplied IP-detect URL before issuing an outbound HTTP request.
// Enforces https-only scheme and standard port to prevent SSRF via config injection.
// Raw IP-literal hosts that fall within bogon ranges (loopback, RFC-1918, APIPA,
// cloud IMDS 169.254.x.x, …) are rejected using the url crate's typed Host enum
// so that IPv6 bracket notation is handled correctly.
// Hostname-based targets are not pre-resolved here to avoid TOCTOU; the response
// body validator already rejects bogon IPs returned by the server.
fn is_ip_detect_url_allowed(url_str: &str) -> bool {
    use url::Host;

    let url = match url_str.parse::<Url>() {
        Ok(u) => u,
        Err(_) => return false,
    };
    if url.scheme() != "https" {
        return false;
    }
    match url.host() {
        None => return false,
        Some(Host::Ipv4(ip)) => {
            if is_bogon(IpAddr::V4(ip)) {
                return false;
            }
        }
        Some(Host::Ipv6(ip)) => {
            // url::Host::Ipv6 holds a parsed Ipv6Addr without brackets,
            // unlike host_str() which returns bracket-enclosed form unparseable by IpAddr.
            if is_bogon(IpAddr::V6(ip)) {
                return false;
            }
        }
        Some(Host::Domain(h)) => {
            // Reject empty host and the loopback alias; the url crate normalises
            // bare-authority URLs (https:///…) to localhost.
            if h.is_empty() || h.eq_ignore_ascii_case("localhost") {
                return false;
            }
            // Hostname-based targets are not pre-resolved (see function comment).
        }
    }
    // Only allow the default HTTPS port (absent = 443) or an explicitly stated 443.
    if let Some(port) = url.port()
        && port != 443
    {
        return false;
    }
    true
}

async fn detect_public_ipv4_http(urls: &[String]) -> Option<Ipv4Addr> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        // Disable redirect following to prevent SSRF via open-redirector chains:
        // a config-supplied URL could redirect to an internal cloud metadata endpoint.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;

    // A bare IPv4 address is at most 15 ASCII characters; allow a small margin for whitespace.
    const MAX_IP_RESPONSE_LEN: usize = 64;

    for url in urls {
        if !is_ip_detect_url_allowed(url) {
            warn!(url = %url, "IP detect URL rejected: must be https:// on port 443 without raw-bogon host");
            continue;
        }
        let response = match client.get(url).send().await {
            Ok(response) => response,
            Err(_) => continue,
        };

        // Reject before reading if the server declares an oversized body.
        if response.content_length().map(|l| l > MAX_IP_RESPONSE_LEN as u64).unwrap_or(false) {
            continue;
        }

        let bytes = match response.bytes().await {
            Ok(b) if b.len() <= MAX_IP_RESPONSE_LEN => b,
            Ok(_) => continue,
            Err(_) => continue,
        };

        let body = match std::str::from_utf8(&bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };

        if let Some(ip) = parse_public_ipv4_response(body.trim()) {
            return Some(ip);
        }
    }

    None
}

fn parse_public_ipv4_response(body: &str) -> Option<Ipv4Addr> {
    let ip = body.parse::<Ipv4Addr>().ok()?;
    if is_bogon_v4(ip) {
        return None;
    }
    Some(ip)
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
    bind_v4: Option<IpAddr>,
    bind_v6: Option<IpAddr>,
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
                let res = timeout(STUN_BATCH_TIMEOUT, async {
                    let v4 = stun_probe_family_with_bind(&stun_addr, IpFamily::V4, bind_v4).await?;
                    let v6 = stun_probe_family_with_bind(&stun_addr, IpFamily::V6, bind_v6).await?;
                    Ok::<DualStunResult, crate::error::ProxyError>(DualStunResult { v4, v6 })
                })
                .await;
                (stun_addr, res)
            });
        }

        let Some(task) = join_set.join_next().await else {
            break;
        };

        match task {
            Ok((stun_addr, Ok(Ok(result)))) => {
                if let Some(v4) = result.v4
                    && !is_bogon(v4.reflected_addr.ip())
                {
                    let entry = best_v4_by_ip.entry(v4.reflected_addr.ip()).or_insert((0, v4));
                    entry.0 += 1;
                }
                if let Some(v6) = result.v6
                    && !is_bogon(v6.reflected_addr.ip())
                {
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

pub fn decide_network_capabilities(
    config: &NetworkConfig,
    probe: &NetworkProbe,
    middle_proxy_nat_ip: Option<IpAddr>,
) -> NetworkDecision {
    let ipv4_dc = config.ipv4 && probe.detected_ipv4.is_some();
    let ipv6_dc = config
        .ipv6
        .unwrap_or_else(|| probe.detected_ipv6.is_some())
        && probe.detected_ipv6.is_some();
    let nat_ip_v4 = matches!(middle_proxy_nat_ip, Some(IpAddr::V4(_)));
    let nat_ip_v6 = matches!(middle_proxy_nat_ip, Some(IpAddr::V6(_)));

    let ipv4_me = config.ipv4
        && probe.detected_ipv4.is_some()
        && (!probe.ipv4_is_bogon || probe.reflected_ipv4.is_some() || nat_ip_v4);

    let ipv6_enabled = config
        .ipv6
        .unwrap_or_else(|| probe.detected_ipv6.is_some());
    let ipv6_me = ipv6_enabled
        && probe.detected_ipv6.is_some()
        && (!probe.ipv6_is_bogon || probe.reflected_ipv6.is_some() || nat_ip_v6);

    let effective_prefer = match config.prefer {
        6 if ipv6_me || ipv6_dc => 6,
        4 if ipv4_me || ipv4_dc => 4,
        6 => {
            warn!("prefer=6 requested but IPv6 unavailable; falling back to IPv4");
            4
        }
        _ => 4,
    };

    let me_families = u8::from(ipv4_me) + u8::from(ipv6_me);
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

pub fn detect_interface_ipv4() -> Option<Ipv4Addr> {
    detect_local_ip_v4()
}

pub fn detect_interface_ipv6() -> Option<Ipv6Addr> {
    detect_local_ip_v6()
}

pub fn is_bogon(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_bogon_v4(v4),
        IpAddr::V6(v6) => is_bogon_v6(v6),
    }
}

pub const fn is_bogon_v4(ip: Ipv4Addr) -> bool {
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

#[cfg(test)]
mod tests {
    use super::{decide_network_capabilities, is_bogon, is_bogon_v4, is_bogon_v6, is_ip_detect_url_allowed, parse_public_ipv4_response, NetworkDecision, NetworkProbe};
    use crate::config::NetworkConfig;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tokio::net::UdpSocket as TokioUdp;

    fn build_stun_binding_response_with_ipv4(txid: &[u8; 12], reflected_ip: [u8; 4]) -> Vec<u8> {
        let magic = 0x2112_A442_u32.to_be_bytes();
        let xored_port = 54321u16 ^ ((u16::from(magic[0]) << 8) | u16::from(magic[1]));
        let xored_ip = [
            reflected_ip[0] ^ magic[0],
            reflected_ip[1] ^ magic[1],
            reflected_ip[2] ^ magic[2],
            reflected_ip[3] ^ magic[3],
        ];

        let mut attr = Vec::new();
        attr.extend_from_slice(&0x0020u16.to_be_bytes());
        attr.extend_from_slice(&8u16.to_be_bytes());
        attr.push(0x00);
        attr.push(0x01);
        attr.extend_from_slice(&xored_port.to_be_bytes());
        attr.extend_from_slice(&xored_ip);

        let mut resp = Vec::with_capacity(20 + attr.len());
        resp.extend_from_slice(&0x0101u16.to_be_bytes());
        resp.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        resp.extend_from_slice(&magic);
        resp.extend_from_slice(txid);
        resp.extend_from_slice(&attr);
        resp
    }

    #[test]
    fn parse_public_ipv4_response_accepts_clean_public_ip() {
        let parsed = parse_public_ipv4_response("1.1.1.1");
        assert_eq!(parsed, Some(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn parse_public_ipv4_response_rejects_bogon_ip() {
        let parsed = parse_public_ipv4_response("10.0.0.7");
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_public_ipv4_response_rejects_multiple_tokens() {
        let parsed = parse_public_ipv4_response("1.1.1.1\n8.8.8.8");
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_public_ipv4_response_rejects_trailing_garbage() {
        let parsed = parse_public_ipv4_response("1.1.1.1 trailing");
        assert!(parsed.is_none());
    }

    // A JSON or HTML response body must never be parsed as a valid IP.
    #[test]
    fn parse_public_ipv4_response_rejects_json_body() {
        assert!(parse_public_ipv4_response(r#"{"ip":"1.2.3.4"}"#).is_none());
    }

    #[test]
    fn parse_public_ipv4_response_rejects_html_body() {
        assert!(parse_public_ipv4_response("<html>1.2.3.4</html>").is_none());
    }

    // Empty input must not panic.
    #[test]
    fn parse_public_ipv4_response_handles_empty_input() {
        assert!(parse_public_ipv4_response("").is_none());
    }

    // === RFC bogon ranges for IPv4 ===

    #[test]
    fn is_bogon_v4_loopback_is_bogon() {
        assert!(is_bogon_v4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn is_bogon_v4_rfc1918_10_is_bogon() {
        assert!(is_bogon_v4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn is_bogon_v4_rfc1918_172_is_bogon() {
        assert!(is_bogon_v4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_bogon_v4(Ipv4Addr::new(172, 31, 255, 255)));
    }

    #[test]
    fn is_bogon_v4_rfc1918_192_168_is_bogon() {
        assert!(is_bogon_v4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    // 0.0.0.0/8 — "this network"
    #[test]
    fn is_bogon_v4_zero_prefix_is_bogon() {
        assert!(is_bogon_v4(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(is_bogon_v4(Ipv4Addr::new(0, 255, 255, 255)));
    }

    // 100.64.0.0/10 — RFC 6598 carrier-grade NAT
    #[test]
    fn is_bogon_v4_cgnat_range_is_bogon() {
        assert!(is_bogon_v4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_bogon_v4(Ipv4Addr::new(100, 127, 255, 255)));
        // Just outside the range must not be bogon
        assert!(!is_bogon_v4(Ipv4Addr::new(100, 128, 0, 1)));
    }

    // 192.0.2.0/24 — TEST-NET-1 (RFC 5737)
    #[test]
    fn is_bogon_v4_test_net_1_is_bogon() {
        assert!(is_bogon_v4(Ipv4Addr::new(192, 0, 2, 1)));
    }

    // 198.51.100.0/24 — TEST-NET-2 (RFC 5737)
    #[test]
    fn is_bogon_v4_test_net_2_is_bogon() {
        assert!(is_bogon_v4(Ipv4Addr::new(198, 51, 100, 0)));
    }

    // 203.0.113.0/24 — TEST-NET-3 (RFC 5737)
    #[test]
    fn is_bogon_v4_test_net_3_is_bogon() {
        assert!(is_bogon_v4(Ipv4Addr::new(203, 0, 113, 1)));
    }

    // 240.0.0.0/4 — reserved (RFC 1112)
    #[test]
    fn is_bogon_v4_reserved_class_e_is_bogon() {
        assert!(is_bogon_v4(Ipv4Addr::new(240, 0, 0, 1)));
        assert!(is_bogon_v4(Ipv4Addr::new(255, 255, 255, 254)));
    }

    // 255.255.255.255 — broadcast
    #[test]
    fn is_bogon_v4_broadcast_is_bogon() {
        assert!(is_bogon_v4(Ipv4Addr::new(255, 255, 255, 255)));
    }

    // 198.18.0.0/15 — benchmarking (RFC 2544)
    #[test]
    fn is_bogon_v4_benchmarking_range_is_bogon() {
        assert!(is_bogon_v4(Ipv4Addr::new(198, 18, 0, 0)));
        assert!(is_bogon_v4(Ipv4Addr::new(198, 19, 255, 255)));
    }

    // Routable IPs must not be classified as bogon.
    #[test]
    fn is_bogon_v4_routable_addresses_not_bogon() {
        assert!(!is_bogon_v4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_bogon_v4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_bogon_v4(Ipv4Addr::new(185, 12, 64, 1)));
        assert!(!is_bogon_v4(Ipv4Addr::new(104, 16, 0, 1)));
    }

    // === IPv6 bogon ranges ===

    #[test]
    fn is_bogon_v6_loopback_is_bogon() {
        assert!(is_bogon_v6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn is_bogon_v6_unspecified_is_bogon() {
        assert!(is_bogon_v6(Ipv6Addr::UNSPECIFIED));
    }

    // fc00::/7 — Unique Local Address (RFC 4193)
    #[test]
    fn is_bogon_v6_unique_local_is_bogon() {
        let ula: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(is_bogon_v6(ula));
    }

    // fe80::/10 — Link-local
    #[test]
    fn is_bogon_v6_link_local_is_bogon() {
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(is_bogon_v6(ll));
    }

    // ::ffff:0:0/96 — IPv4-mapped (RFC 4291)
    #[test]
    fn is_bogon_v6_ipv4_mapped_is_bogon() {
        let mapped: Ipv6Addr = "::ffff:192.168.1.1".parse().unwrap();
        assert!(is_bogon_v6(mapped));
    }

    // 100::/64 — Discard-Only (RFC 6666)
    #[test]
    fn is_bogon_v6_discard_only_prefix_is_bogon() {
        let discard: Ipv6Addr = "100::1".parse().unwrap();
        assert!(is_bogon_v6(discard));
    }

    // 2001:db8::/32 — documentation (RFC 3849)
    #[test]
    fn is_bogon_v6_documentation_prefix_is_bogon() {
        let doc: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(is_bogon_v6(doc));
    }

    // 2002::/16 — 6to4 relay anycast (RFC 3068)
    #[test]
    fn is_bogon_v6_6to4_relay_is_bogon() {
        let relay: Ipv6Addr = "2002::1".parse().unwrap();
        assert!(is_bogon_v6(relay));
    }

    // Routable global unicast must not be bogon.
    #[test]
    fn is_bogon_v6_global_unicast_not_bogon() {
        let global: Ipv6Addr = "2001:b28:f23d:f001::a".parse().unwrap();
        assert!(!is_bogon_v6(global));
    }

    // is_bogon dispatch must agree with the typed variants.
    #[test]
    fn is_bogon_dispatch_matches_typed_variants() {
        let bogon_v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(is_bogon(bogon_v4), is_bogon_v4(Ipv4Addr::new(10, 0, 0, 1)));

        let pub_v4 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(is_bogon(pub_v4), is_bogon_v4(Ipv4Addr::new(1, 1, 1, 1)));
    }

    // === is_ip_detect_url_allowed SSRF prevention tests ===

    // Plain HTTP must be rejected — credentials and response travel in the clear.
    #[test]
    fn ip_detect_url_rejects_http_scheme() {
        assert!(!is_ip_detect_url_allowed("http://ifconfig.me/ip"));
    }

    // Non-HTTP(S) schemes must be rejected.
    #[test]
    fn ip_detect_url_rejects_ftp_scheme() {
        assert!(!is_ip_detect_url_allowed("ftp://ifconfig.me/ip"));
    }

    // Loopback IPv4 as raw IP literal — direct localhost probe.
    #[test]
    fn ip_detect_url_rejects_loopback_ipv4_literal() {
        assert!(!is_ip_detect_url_allowed("https://127.0.0.1/ip"));
        assert!(!is_ip_detect_url_allowed("https://127.255.255.255/ip"));
    }

    // RFC-1918 private ranges as raw IP literals.
    #[test]
    fn ip_detect_url_rejects_rfc1918_ip_literals() {
        assert!(!is_ip_detect_url_allowed("https://10.0.0.1/ip"));
        assert!(!is_ip_detect_url_allowed("https://172.16.0.1/ip"));
        assert!(!is_ip_detect_url_allowed("https://192.168.1.1/ip"));
    }

    // AWS EC2 Instance Metadata Service — primary SSRF target in cloud environments.
    #[test]
    fn ip_detect_url_rejects_aws_imds_ipv4() {
        assert!(!is_ip_detect_url_allowed("https://169.254.169.254/latest/meta-data/"));
        assert!(!is_ip_detect_url_allowed("https://169.254.169.254/"));
    }

    // GCP metadata endpoint shares the same APIPA range.
    #[test]
    fn ip_detect_url_rejects_gcp_metadata_ip() {
        assert!(!is_ip_detect_url_allowed("https://169.254.169.254/computeMetadata/v1/"));
    }

    // Azure IMDS uses the same 169.254.169.254 address.
    #[test]
    fn ip_detect_url_rejects_azure_imds_ip() {
        assert!(!is_ip_detect_url_allowed("https://169.254.169.254/metadata/instance"));
    }

    // IPv6 loopback as raw IP literal.
    #[test]
    fn ip_detect_url_rejects_ipv6_loopback_literal() {
        assert!(!is_ip_detect_url_allowed("https://[::1]/ip"));
    }

    // IPv6 link-local as raw IP literal (zone-ID variant omitted — url crate
    // normalises the percent-encoded zone-ID and may reject it at parse time;
    // the bare form is sufficient to cover the bogon check).
    #[test]
    fn ip_detect_url_rejects_ipv6_link_local_literal() {
        assert!(!is_ip_detect_url_allowed("https://[fe80::1]/ip"));
    }

    // IPv6 ULA (fc00::/7) as raw IP literal.
    #[test]
    fn ip_detect_url_rejects_ipv6_ula_literal() {
        assert!(!is_ip_detect_url_allowed("https://[fd00::1]/ip"));
    }

    // Non-standard ports are an SSRF vector (e.g., internal services on 8080, 8443).
    #[test]
    fn ip_detect_url_rejects_non_standard_port() {
        assert!(!is_ip_detect_url_allowed("https://ifconfig.me:8080/ip"));
        assert!(!is_ip_detect_url_allowed("https://ifconfig.me:8443/ip"));
        assert!(!is_ip_detect_url_allowed("https://ifconfig.me:1/ip"));
        assert!(!is_ip_detect_url_allowed("https://ifconfig.me:65535/ip"));
    }

    // Port 443 stated explicitly must be accepted.
    #[test]
    fn ip_detect_url_accepts_explicit_port_443() {
        assert!(is_ip_detect_url_allowed("https://ifconfig.me:443/ip"));
    }

    // Default HTTPS (no explicit port) must be accepted.
    #[test]
    fn ip_detect_url_accepts_default_https_urls() {
        assert!(is_ip_detect_url_allowed("https://ifconfig.me/ip"));
        assert!(is_ip_detect_url_allowed("https://api.ipify.org"));
        assert!(is_ip_detect_url_allowed("https://api.ipify.org/"));
    }

    // A public routable IP literal (non-bogon) must be accepted.
    #[test]
    fn ip_detect_url_accepts_public_ip_literal() {
        // 1.1.1.1 is Cloudflare's public resolver — routable, non-bogon.
        assert!(is_ip_detect_url_allowed("https://1.1.1.1/ip"));
    }

    // Malformed and empty URLs must be rejected without panic.
    // Note: url crate parses https:///path as https://path/ (host="path");
    // that is a syntactically valid URL and passes the validator as a hostname-based
    // target (TOCTOU boundary — only raw IP literals and localhost are pre-rejected).
    #[test]
    fn ip_detect_url_rejects_malformed_and_empty() {
        assert!(!is_ip_detect_url_allowed("not-a-url"));
        assert!(!is_ip_detect_url_allowed(""));
        assert!(!is_ip_detect_url_allowed("://noscheme/"));
        assert!(!is_ip_detect_url_allowed("https://"));
    }

    // An attacker-crafted URL using a redirect or obfuscation via open redirector
    // on a public hostname still passes the allow-check (hostname-based URLs are not
    // pre-resolved). This is an accepted limitation documented in the function comment;
    // the response body validator ensures only valid public IPv4 is accepted.
    // This test documents and pins that behaviour.
    #[test]
    fn ip_detect_url_hostname_based_not_pre_resolved() {
        // This passes validation because we do not do DNS lookup here.
        assert!(is_ip_detect_url_allowed("https://legitimate-looking-hostname.example/ip"));
    }

    #[tokio::test]
    async fn probe_stun_quorum_rejects_bogon_reflected_ipv4() {
        let server = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_n, src) = server.recv_from(&mut buf).await.unwrap();
            let txid: [u8; 12] = buf[8..20].try_into().unwrap();
            // 10.1.2.3 is RFC1918 and must be ignored by quorum.
            let resp = build_stun_binding_response_with_ipv4(&txid, [10, 1, 2, 3]);
            server.send_to(&resp, src).await.unwrap();
        });

        let result = super::probe_stun_servers_parallel(&[server_addr.to_string()], 1, None, None).await;
        assert!(result.v4.is_none(), "bogon reflected IPv4 must not be selected");
    }

    #[tokio::test]
    async fn probe_stun_quorum_prefers_public_when_bogon_and_public_present() {
        let bogon_server = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let bogon_addr = bogon_server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_n, src) = bogon_server.recv_from(&mut buf).await.unwrap();
            let txid: [u8; 12] = buf[8..20].try_into().unwrap();
            let resp = build_stun_binding_response_with_ipv4(&txid, [192, 168, 1, 1]);
            bogon_server.send_to(&resp, src).await.unwrap();
        });

        let public_server = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let public_addr = public_server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_n, src) = public_server.recv_from(&mut buf).await.unwrap();
            let txid: [u8; 12] = buf[8..20].try_into().unwrap();
            let resp = build_stun_binding_response_with_ipv4(&txid, [1, 1, 1, 1]);
            public_server.send_to(&resp, src).await.unwrap();
        });

        let servers = vec![bogon_addr.to_string(), public_addr.to_string()];
        let result = super::probe_stun_servers_parallel(&servers, 2, None, None).await;
        assert_eq!(
            result.v4.map(|r| r.reflected_addr.ip().to_string()),
            Some("1.1.1.1".to_string()),
            "public reflected IPv4 must win once bogon responses are filtered"
        );
    }

    // === decide_network_capabilities: manual NAT IP override ===

    #[test]
    fn manual_nat_ip_enables_ipv4_me_without_reflection() {
        let config = NetworkConfig {
            ipv4: true,
            ..Default::default()
        };
        let probe = NetworkProbe {
            detected_ipv4: Some(Ipv4Addr::new(10, 0, 0, 10)),
            ipv4_is_bogon: true,
            ..Default::default()
        };

        let decision = decide_network_capabilities(
            &config,
            &probe,
            Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        );

        assert!(decision.ipv4_me);
    }

    // A nat_ip of IPv4 family must not unlock IPv6 ME when IPv6 is bogon.
    #[test]
    fn manual_nat_ip_does_not_enable_other_family() {
        let config = NetworkConfig {
            ipv4: true,
            ipv6: Some(true),
            ..Default::default()
        };
        let probe = NetworkProbe {
            detected_ipv4: Some(Ipv4Addr::new(10, 0, 0, 10)),
            detected_ipv6: Some(Ipv6Addr::LOCALHOST),
            ipv4_is_bogon: true,
            ipv6_is_bogon: true,
            ..Default::default()
        };

        let decision = decide_network_capabilities(
            &config,
            &probe,
            Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        );

        assert!(decision.ipv4_me);
        assert!(!decision.ipv6_me);
    }

    // With no nat_ip and a bogon detected_ipv4 (no reflection), ipv4_me must be false.
    #[test]
    fn no_nat_ip_and_no_reflection_disables_ipv4_me_when_bogon() {
        let config = NetworkConfig {
            ipv4: true,
            ..Default::default()
        };
        let probe = NetworkProbe {
            detected_ipv4: Some(Ipv4Addr::new(10, 0, 0, 10)),
            ipv4_is_bogon: true,
            ..Default::default()
        };
        let decision = decide_network_capabilities(&config, &probe, None);
        assert!(!decision.ipv4_me);
    }

    // Prefer=6 must downgrade to 4 when IPv6 is completely unavailable.
    #[test]
    fn prefer_6_falls_back_to_4_when_ipv6_unavailable() {
        let config = NetworkConfig {
            ipv4: true,
            prefer: 6,
            ..Default::default()
        };
        let probe = NetworkProbe {
            detected_ipv4: Some(Ipv4Addr::new(1, 2, 3, 4)),
            ..Default::default()
        };
        let decision = decide_network_capabilities(&config, &probe, None);
        assert_eq!(decision.effective_prefer, 4);
    }

    // Multipath requires both IPv4 and IPv6 ME paths; single-family must not set it.
    #[test]
    fn multipath_disabled_without_dual_stack() {
        let config = NetworkConfig {
            ipv4: true,
            multipath: true,
            ..Default::default()
        };
        let probe = NetworkProbe {
            detected_ipv4: Some(Ipv4Addr::new(1, 2, 3, 4)),
            ..Default::default()
        };
        let decision: NetworkDecision = decide_network_capabilities(&config, &probe, None);
        assert!(!decision.effective_multipath);
    }
}

