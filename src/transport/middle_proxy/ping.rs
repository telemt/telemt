use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::config::{UpstreamConfig, UpstreamType};
use crate::crypto::SecureRandom;
use crate::error::ProxyError;
use crate::transport::{UpstreamEgressInfo, UpstreamRouteKind};

use super::MePool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MePingFamily {
    V4,
    V6,
}

#[derive(Debug, Clone)]
pub struct MePingSample {
    pub dc: i32,
    pub addr: SocketAddr,
    pub route: Option<String>,
    pub connect_ms: Option<f64>,
    pub handshake_ms: Option<f64>,
    pub error: Option<String>,
    pub family: MePingFamily,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MePingReport {
    pub dc: i32,
    pub family: MePingFamily,
    pub samples: Vec<MePingSample>,
}

pub fn format_sample_line(sample: &MePingSample) -> String {
    let sign = if sample.dc >= 0 { "+" } else { "-" };
    let addr = format!("{}:{}", sample.addr.ip(), sample.addr.port());

    match (sample.connect_ms, sample.handshake_ms.as_ref(), sample.error.as_ref()) {
        (Some(conn), Some(hs), None) => format!(
            "     {sign} {addr}\tPing: {:.0} ms / RPC: {:.0} ms / OK",
            conn, hs
        ),
        (Some(conn), None, Some(err)) => format!(
            "     {sign} {addr}\tPing: {:.0} ms / RPC: FAIL ({err})",
            conn
        ),
        (None, _, Some(err)) => format!("     {sign} {addr}\tPing: FAIL ({err})"),
        (Some(conn), None, None) => format!("     {sign} {addr}\tPing: {:.0} ms / RPC: FAIL", conn),
        _ => format!("     {sign} {addr}\tPing: FAIL"),
    }
}

fn format_direct_with_config(
    interface: &Option<String>,
    bind_addresses: &Option<Vec<String>>,
) -> Option<String> {
    let mut direct_parts: Vec<String> = Vec::new();
    if let Some(dev) = interface.as_deref().filter(|v| !v.is_empty()) {
        direct_parts.push(format!("dev={dev}"));
    }
    if let Some(src) = bind_addresses.as_ref().filter(|v| !v.is_empty()) {
        direct_parts.push(format!("src={}", src.join(",")));
    }
    if direct_parts.is_empty() {
        None
    } else {
        Some(format!("direct {}", direct_parts.join(" ")))
    }
}

fn pick_target_for_family(reports: &[MePingReport], family: MePingFamily) -> Option<SocketAddr> {
    reports.iter().find_map(|report| {
        if report.family != family {
            return None;
        }
        report
            .samples
            .iter()
            .find(|s| s.error.is_none() && s.handshake_ms.is_some())
            .map(|s| s.addr)
    })
}

fn route_from_egress(egress: Option<UpstreamEgressInfo>) -> Option<String> {
    let info = egress?;
    match info.route_kind {
        UpstreamRouteKind::Direct => {
            let src_ip = info
                .direct_bind_ip
                .or_else(|| info.local_addr.map(|addr| addr.ip()));
            let ip = src_ip?;
            let mut parts = Vec::new();
            if let Some(dev) = detect_interface_for_ip(ip) {
                parts.push(format!("dev={dev}"));
            }
            parts.push(format!("src={ip}"));
            Some(format!("direct {}", parts.join(" ")))
        }
        UpstreamRouteKind::Socks4 => {
            let route = info
                .socks_proxy_addr
                .map(|addr| format!("socks4://{addr}"))
                .unwrap_or_else(|| "socks4://unknown".to_string());
            Some(match info.socks_bound_addr {
                Some(bound) => format!("{route} bnd={bound}"),
                None => route,
            })
        }
        UpstreamRouteKind::Socks5 => {
            let route = info
                .socks_proxy_addr
                .map(|addr| format!("socks5://{addr}"))
                .unwrap_or_else(|| "socks5://unknown".to_string());
            Some(match info.socks_bound_addr {
                Some(bound) => format!("{route} bnd={bound}"),
                None => route,
            })
        }
    }
}

#[cfg(unix)]
fn detect_interface_for_ip(ip: IpAddr) -> Option<String> {
    use nix::ifaddrs::getifaddrs;

    if let Ok(addrs) = getifaddrs() {
        for iface in addrs {
            if let Some(address) = iface.address {
                if let Some(v4) = address.as_sockaddr_in() {
                    if IpAddr::V4(v4.ip()) == ip {
                        return Some(iface.interface_name);
                    }
                } else if let Some(v6) = address.as_sockaddr_in6() {
                    if IpAddr::V6(v6.ip()) == ip {
                        return Some(iface.interface_name);
                    }
                }
            }
        }
    }
    None
}

#[cfg(not(unix))]
fn detect_interface_for_ip(_ip: IpAddr) -> Option<String> {
    None
}

async fn detect_direct_route_details(
    reports: &[MePingReport],
    prefer_ipv6: bool,
    v4_ok: bool,
    v6_ok: bool,
) -> Option<String> {
    let target_addr = if prefer_ipv6 && v6_ok {
        pick_target_for_family(reports, MePingFamily::V6)
            .or_else(|| pick_target_for_family(reports, MePingFamily::V4))
    } else if v4_ok {
        pick_target_for_family(reports, MePingFamily::V4)
            .or_else(|| pick_target_for_family(reports, MePingFamily::V6))
    } else {
        pick_target_for_family(reports, MePingFamily::V6)
            .or_else(|| pick_target_for_family(reports, MePingFamily::V4))
    }?;

    let local_ip = if target_addr.is_ipv4() {
        let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
        sock.connect(target_addr).await.ok()?;
        sock.local_addr().ok().map(|a| a.ip())
    } else {
        let sock = UdpSocket::bind("[::]:0").await.ok()?;
        sock.connect(target_addr).await.ok()?;
        sock.local_addr().ok().map(|a| a.ip())
    };

    let mut parts = Vec::new();
    if let Some(ip) = local_ip {
        if let Some(dev) = detect_interface_for_ip(ip) {
            parts.push(format!("dev={dev}"));
        }
        parts.push(format!("src={ip}"));
    }

    if parts.is_empty() {
        None
    } else {
        Some(format!("direct {}", parts.join(" ")))
    }
}

pub async fn format_me_route(
    upstreams: &[UpstreamConfig],
    reports: &[MePingReport],
    prefer_ipv6: bool,
    v4_ok: bool,
    v6_ok: bool,
) -> String {
    if let Some(route) = reports
        .iter()
        .flat_map(|report| report.samples.iter())
        .find(|sample| sample.error.is_none() && sample.handshake_ms.is_some())
        .and_then(|sample| sample.route.clone())
    {
        return route;
    }

    let enabled_upstreams: Vec<_> = upstreams.iter().filter(|u| u.enabled).collect();
    if enabled_upstreams.is_empty() {
        return detect_direct_route_details(reports, prefer_ipv6, v4_ok, v6_ok)
            .await
            .unwrap_or_else(|| "direct".to_string());
    }

    if enabled_upstreams.len() == 1 {
        return match &enabled_upstreams[0].upstream_type {
            UpstreamType::Direct {
                interface,
                bind_addresses,
            } => {
                if let Some(route) = format_direct_with_config(interface, bind_addresses) {
                    route
                } else {
                    detect_direct_route_details(reports, prefer_ipv6, v4_ok, v6_ok)
                        .await
                        .unwrap_or_else(|| "direct".to_string())
                }
            }
            UpstreamType::Socks4 { address, .. } => format!("socks4://{address}"),
            UpstreamType::Socks5 { address, .. } => format!("socks5://{address}"),
        };
    }

    let has_direct = enabled_upstreams
        .iter()
        .any(|u| matches!(u.upstream_type, UpstreamType::Direct { .. }));
    let has_socks4 = enabled_upstreams
        .iter()
        .any(|u| matches!(u.upstream_type, UpstreamType::Socks4 { .. }));
    let has_socks5 = enabled_upstreams
        .iter()
        .any(|u| matches!(u.upstream_type, UpstreamType::Socks5 { .. }));
    let mut kinds = Vec::new();
    if has_direct {
        kinds.push("direct");
    }
    if has_socks4 {
        kinds.push("socks4");
    }
    if has_socks5 {
        kinds.push("socks5");
    }
    format!("mixed upstreams ({})", kinds.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn sample(base: MePingSample) -> MePingSample {
        base
    }

    #[test]
    fn ok_line_contains_both_timings() {
        let s = sample(MePingSample {
            dc: 4,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8888),
            route: Some("direct src=1.2.3.4".to_string()),
            connect_ms: Some(12.3),
            handshake_ms: Some(34.7),
            error: None,
            family: MePingFamily::V4,
        });
        let line = format_sample_line(&s);
        assert!(line.contains("Ping: 12 ms"));
        assert!(line.contains("RPC: 35 ms"));
        assert!(line.contains("OK"));
    }

    #[test]
    fn error_line_mentions_reason() {
        let s = sample(MePingSample {
            dc: -5,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 80),
            route: Some("socks5".to_string()),
            connect_ms: Some(10.0),
            handshake_ms: None,
            error: Some("handshake timeout".to_string()),
            family: MePingFamily::V4,
        });
        let line = format_sample_line(&s);
        assert!(line.contains("- 5.6.7.8:80"));
        assert!(line.contains("handshake timeout"));
    }
}

pub async fn run_me_ping(pool: &Arc<MePool>, rng: &SecureRandom) -> Vec<MePingReport> {
    let mut reports = Vec::new();

    let v4_map = if pool.decision.ipv4_me {
        pool.proxy_map_v4.read().await.clone()
    } else {
        HashMap::new()
    };
    let v6_map = if pool.decision.ipv6_me {
        pool.proxy_map_v6.read().await.clone()
    } else {
        HashMap::new()
    };

    let mut grouped: Vec<(MePingFamily, i32, Vec<(IpAddr, u16)>)> = Vec::new();
    for (dc, addrs) in v4_map {
        grouped.push((MePingFamily::V4, dc, addrs));
    }
    for (dc, addrs) in v6_map {
        grouped.push((MePingFamily::V6, dc, addrs));
    }

    for (family, dc, addrs) in grouped {
        let mut samples = Vec::new();
        for (ip, port) in addrs {
            let addr = SocketAddr::new(ip, port);
            let mut connect_ms = None;
            let mut handshake_ms = None;
            let mut error = None;
            let mut route = None;

            match pool.connect_tcp(addr).await {
                Ok((stream, conn_rtt, upstream_egress)) => {
                    connect_ms = Some(conn_rtt);
                    route = route_from_egress(upstream_egress);
                    match pool.handshake_only(stream, addr, upstream_egress, rng).await {
                        Ok(hs) => {
                            handshake_ms = Some(hs.handshake_ms);
                            // drop halves to close
                            drop(hs.rd);
                            drop(hs.wr);
                        }
                        Err(e) => {
                            error = Some(short_err(&e));
                        }
                    }
                }
                Err(e) => {
                    error = Some(short_err(&e));
                }
            }

            samples.push(MePingSample {
                dc,
                addr,
                route,
                connect_ms,
                handshake_ms,
                error,
                family,
            });
        }

        reports.push(MePingReport {
            dc,
            family,
            samples,
        });
    }

    reports
}

fn short_err(err: &ProxyError) -> String {
    match err {
        ProxyError::ConnectionTimeout { .. } => "connect timeout".to_string(),
        ProxyError::TgHandshakeTimeout => "handshake timeout".to_string(),
        ProxyError::InvalidHandshake(e) => format!("bad handshake: {e}"),
        ProxyError::Crypto(e) => format!("crypto: {e}"),
        ProxyError::Proxy(e) => format!("proxy: {e}"),
        ProxyError::Io(e) => format!("io: {e}"),
        _ => format!("{err}"),
    }
}
