use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tracing::{info, warn};

use crate::error::{ProxyError, Result};
use crate::network::probe::is_bogon;
use crate::network::stun::{stun_probe_dual, IpFamily, StunProbeResult};

use super::MePool;
use std::time::Instant;
pub async fn stun_probe(stun_addr: Option<String>) -> Result<crate::network::stun::DualStunResult> {
    let stun_addr = stun_addr.unwrap_or_else(|| "stun.l.google.com:19302".to_string());
    stun_probe_dual(&stun_addr).await
}

pub async fn detect_public_ip() -> Option<IpAddr> {
    fetch_public_ipv4_with_retry().await.ok().flatten().map(IpAddr::V4)
}

impl MePool {
    pub(super) fn translate_ip_for_nat(&self, ip: IpAddr) -> IpAddr {
        let nat_ip = self
            .nat_ip_cfg
            .or_else(|| self.nat_ip_detected.try_read().ok().and_then(|g| (*g).clone()));

        let Some(nat_ip) = nat_ip else {
            return ip;
        };

        match (ip, nat_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst))
                if is_bogon(IpAddr::V4(src))
                    || src.is_loopback()
                    || src.is_unspecified() =>
            {
                IpAddr::V4(dst)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) if src.is_loopback() || src.is_unspecified() => {
                IpAddr::V6(dst)
            }
            (orig, _) => orig,
        }
    }

    pub(super) fn translate_our_addr_with_reflection(
        &self,
        addr: std::net::SocketAddr,
        reflected: Option<std::net::SocketAddr>,
    ) -> std::net::SocketAddr {
        let ip = if let Some(r) = reflected {
            // Use reflected IP (not port) only when local address is non-public.
            if is_bogon(addr.ip()) || addr.ip().is_loopback() || addr.ip().is_unspecified() {
                r.ip()
            } else {
                self.translate_ip_for_nat(addr.ip())
            }
        } else {
            self.translate_ip_for_nat(addr.ip())
        };

        // Keep the kernel-assigned TCP source port; STUN port can differ.
        std::net::SocketAddr::new(ip, addr.port())
    }

    pub(super) async fn maybe_detect_nat_ip(&self, local_ip: IpAddr) -> Option<IpAddr> {
        if self.nat_ip_cfg.is_some() {
            return self.nat_ip_cfg;
        }

        if !(is_bogon(local_ip) || local_ip.is_loopback() || local_ip.is_unspecified()) {
            return None;
        }

        if let Some(ip) = self.nat_ip_detected.read().await.clone() {
            return Some(ip);
        }

        match fetch_public_ipv4_with_retry().await {
            Ok(Some(ip)) => {
                {
                    let mut guard = self.nat_ip_detected.write().await;
                    *guard = Some(IpAddr::V4(ip));
                }
                info!(public_ip = %ip, "Auto-detected public IP for NAT translation");
                Some(IpAddr::V4(ip))
            }
            Ok(None) => None,
            Err(e) => {
                warn!(error = %e, "Failed to auto-detect public IP");
                None
            }
        }
    }

    pub(super) async fn maybe_reflect_public_addr(
        &self,
        family: IpFamily,
    ) -> Option<std::net::SocketAddr> {
        const STUN_CACHE_TTL: Duration = Duration::from_secs(600);
        if let Ok(mut cache) = self.nat_reflection_cache.try_lock() {
            let slot = match family {
                IpFamily::V4 => &mut cache.v4,
                IpFamily::V6 => &mut cache.v6,
            };
            if let Some((ts, addr)) = slot {
                if ts.elapsed() < STUN_CACHE_TTL {
                    return Some(*addr);
                }
            }
        }

        let stun_addr = self
            .nat_stun
            .clone()
            .unwrap_or_else(|| "stun.l.google.com:19302".to_string());
        match stun_probe_dual(&stun_addr).await {
            Ok(res) => {
                let picked: Option<StunProbeResult> = match family {
                    IpFamily::V4 => res.v4,
                    IpFamily::V6 => res.v6,
                };
                if let Some(result) = picked {
                    info!(local = %result.local_addr, reflected = %result.reflected_addr, family = ?family, "NAT probe: reflected address");
                    if let Ok(mut cache) = self.nat_reflection_cache.try_lock() {
                        let slot = match family {
                            IpFamily::V4 => &mut cache.v4,
                            IpFamily::V6 => &mut cache.v6,
                        };
                        *slot = Some((Instant::now(), result.reflected_addr));
                    }
                    Some(result.reflected_addr)
                } else {
                    None
                }
            }
            Err(e) => {
                warn!(error = %e, "NAT probe failed");
                None
            }
        }
    }
}

async fn fetch_public_ipv4_with_retry() -> Result<Option<Ipv4Addr>> {
    let providers = [
        "https://checkip.amazonaws.com",
        "http://v4.ident.me",
        "http://ipv4.icanhazip.com",
    ];
    for url in providers {
        if let Ok(Some(ip)) = fetch_public_ipv4_once(url).await {
            return Ok(Some(ip));
        }
    }
    Ok(None)
}

async fn fetch_public_ipv4_once(url: &str) -> Result<Option<Ipv4Addr>> {
    let res = reqwest::get(url).await.map_err(|e| {
        ProxyError::Proxy(format!("public IP detection request failed: {e}"))
    })?;

    let text = res.text().await.map_err(|e| {
        ProxyError::Proxy(format!("public IP detection read failed: {e}"))
    })?;

    let ip = text.trim().parse().ok();
    Ok(ip)
}
