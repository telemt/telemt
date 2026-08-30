#![allow(dead_code)]
#![allow(clippy::items_after_test_module)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::{NetworkConfig, UpstreamConfig, UpstreamType};
use crate::error::Result;
use crate::network::stun::{
    DualStunResult, IpFamily, StunProbeResult,
    stun_probe_family_with_bind_tcp_fallback_and_resolver,
};
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
const STUN_BATCH_TCP_FALLBACK_TIMEOUT: Duration = Duration::from_secs(12);

pub async fn run_probe(
    config: &NetworkConfig,
    upstreams: &[UpstreamConfig],
    nat_probe: bool,
    stun_nat_probe_concurrency: usize,
) -> Result<NetworkProbe> {
    let mut probe = NetworkProbe::default();
    let dns_resolver = Arc::new(
        crate::network::dns_overrides::GenerationDnsResolver::from_entries(&config.dns_overrides)?,
    );
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
                config.stun_tcp_fallback,
                Arc::clone(&dns_resolver),
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
            ..
        } = &upstream.upstream_type
        else {
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
            config.stun_tcp_fallback,
            Arc::clone(&dns_resolver),
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
        && let Some(public_ip) = detect_public_ipv4_http(&config.http_ip_detect_urls).await
    {
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
        && (!probe.ipv4_is_bogon
            || probe
                .reflected_ipv4
                .map(|r| !is_bogon(r.ip()))
                .unwrap_or(false));

    let ipv6_enabled = config.ipv6.unwrap_or(probe.detected_ipv6.is_some());
    probe.ipv6_usable = ipv6_enabled
        && probe.detected_ipv6.is_some()
        && (!probe.ipv6_is_bogon
            || probe
                .reflected_ipv6
                .map(|r| !is_bogon(r.ip()))
                .unwrap_or(false));

    Ok(probe)
}

pub(crate) async fn detect_public_ipv4_http(urls: &[String]) -> Option<Ipv4Addr> {
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
    bind_v4: Option<IpAddr>,
    bind_v6: Option<IpAddr>,
    tcp_fallback: bool,
    dns_resolver: Arc<crate::network::dns_overrides::GenerationDnsResolver>,
) -> DualStunResult {
    let mut join_set = JoinSet::new();
    let mut next_idx = 0usize;
    let mut best_v4_by_ip: HashMap<IpAddr, (usize, StunProbeResult)> = HashMap::new();
    let mut best_v6_by_ip: HashMap<IpAddr, (usize, StunProbeResult)> = HashMap::new();

    while next_idx < servers.len() || !join_set.is_empty() {
        while next_idx < servers.len() && join_set.len() < concurrency {
            let stun_addr = servers[next_idx].clone();
            let dns_resolver = Arc::clone(&dns_resolver);
            next_idx += 1;
            join_set.spawn(async move {
                let batch_timeout = if tcp_fallback {
                    STUN_BATCH_TCP_FALLBACK_TIMEOUT
                } else {
                    STUN_BATCH_TIMEOUT
                };
                let res = timeout(batch_timeout, async {
                    let v4 = stun_probe_family_with_bind_tcp_fallback_and_resolver(
                        &stun_addr,
                        IpFamily::V4,
                        bind_v4,
                        tcp_fallback,
                        Some(dns_resolver.as_ref()),
                    )
                    .await?;
                    let v6 = stun_probe_family_with_bind_tcp_fallback_and_resolver(
                        &stun_addr,
                        IpFamily::V6,
                        bind_v6,
                        tcp_fallback,
                        Some(dns_resolver.as_ref()),
                    )
                    .await?;
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
                if let Some(v4) = result.v4 {
                    let entry = best_v4_by_ip
                        .entry(v4.reflected_addr.ip())
                        .or_insert((0, v4));
                    entry.0 += 1;
                }
                if let Some(v6) = result.v6 {
                    let entry = best_v6_by_ip
                        .entry(v6.reflected_addr.ip())
                        .or_insert((0, v6));
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
    if let Some((_, best)) = best_v4_by_ip.into_values().max_by_key(|(count, _)| *count) {
        info!("STUN-Quorum reached, IP: {}", best.reflected_addr.ip());
        out.v4 = Some(best);
    }
    if let Some((_, best)) = best_v6_by_ip.into_values().max_by_key(|(count, _)| *count) {
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
    let ipv6_dc =
        config.ipv6.unwrap_or(probe.detected_ipv6.is_some()) && probe.detected_ipv6.is_some();
    let nat_ip_v4 = matches!(middle_proxy_nat_ip, Some(IpAddr::V4(_)));
    let nat_ip_v6 = matches!(middle_proxy_nat_ip, Some(IpAddr::V6(_)));

    let ipv4_me = config.ipv4
        && probe.detected_ipv4.is_some()
        && (!probe.ipv4_is_bogon || probe.reflected_ipv4.is_some() || nat_ip_v4);

    let ipv6_enabled = config.ipv6.unwrap_or(probe.detected_ipv6.is_some());
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

// Local interface discovery and bogon classification.
mod local;
pub use local::{
    detect_interface_ipv4, detect_interface_ipv6, is_bogon, is_bogon_v4, is_bogon_v6,
    log_probe_result,
};
use local::{detect_local_ip_v4, detect_local_ip_v6};

#[cfg(test)]
mod tests;
