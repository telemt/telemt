use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tracing::{info, warn};

use crate::error::{ProxyError, Result};
use crate::network::probe::is_bogon;
use crate::network::stun::{stun_probe_dual, IpFamily, StunProbeResult};

use super::MePool;
use std::time::Instant;

#[allow(dead_code)]
pub async fn stun_probe(stun_addr: Option<String>) -> Result<crate::network::stun::DualStunResult> {
    let stun_addr = stun_addr.unwrap_or_else(|| "stun.l.google.com:19302".to_string());
    stun_probe_dual(&stun_addr).await
}

#[allow(dead_code)]
pub async fn detect_public_ip() -> Option<IpAddr> {
    fetch_public_ipv4_with_retry().await.ok().flatten().map(IpAddr::V4)
}

impl MePool {
    pub(super) fn translate_ip_for_nat(&self, ip: IpAddr) -> IpAddr {
        let nat_ip = self
            .nat_ip_cfg
            .or_else(|| self.nat_ip_detected.try_read().ok().and_then(|g| *g));

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

        if let Some(ip) = *self.nat_ip_detected.read().await {
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
        // Backoff window
        if let Some(until) = *self.stun_backoff_until.read().await
            && Instant::now() < until
        {
            if let Ok(cache) = self.nat_reflection_cache.try_lock() {
                let slot = match family {
                    IpFamily::V4 => cache.v4,
                    IpFamily::V6 => cache.v6,
                };
                return slot.map(|(_, addr)| addr);
            }
            return None;
        }

        if let Ok(mut cache) = self.nat_reflection_cache.try_lock() {
            let slot = match family {
                IpFamily::V4 => &mut cache.v4,
                IpFamily::V6 => &mut cache.v6,
            };
            if let Some((ts, addr)) = slot
                && ts.elapsed() < STUN_CACHE_TTL
            {
                return Some(*addr);
            }
        }

        let attempt = self.nat_probe_attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let servers = if !self.nat_stun_servers.is_empty() {
            self.nat_stun_servers.clone()
        } else if let Some(s) = &self.nat_stun {
            vec![s.clone()]
        } else {
            vec!["stun.l.google.com:19302".to_string()]
        };

        for stun_addr in servers {
            match stun_probe_dual(&stun_addr).await {
                Ok(res) => {
                    let picked: Option<StunProbeResult> = match family {
                        IpFamily::V4 => res.v4,
                        IpFamily::V6 => res.v6,
                    };
                    if let Some(result) = picked {
                        info!(local = %result.local_addr, reflected = %result.reflected_addr, family = ?family, stun = %stun_addr, "NAT probe: reflected address");
                        self.nat_probe_attempts.store(0, std::sync::atomic::Ordering::Relaxed);
                        if let Ok(mut cache) = self.nat_reflection_cache.try_lock() {
                            let slot = match family {
                                IpFamily::V4 => &mut cache.v4,
                                IpFamily::V6 => &mut cache.v6,
                            };
                            *slot = Some((Instant::now(), result.reflected_addr));
                        }
                        return Some(result.reflected_addr);
                    }
                }
                Err(e) => {
                    warn!(error = %e, stun = %stun_addr, attempt = attempt + 1, "NAT probe failed, trying next server");
                }
            }
        }
        let backoff = Duration::from_secs(60 * 2u64.pow((attempt as u32).min(6)));
        *self.stun_backoff_until.write().await = Some(Instant::now() + backoff);
        None
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
