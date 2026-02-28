use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::error::{ProxyError, Result};
use crate::network::probe::is_bogon;
use crate::network::stun::{stun_probe_dual, IpFamily, StunProbeResult};

use super::MePool;
use std::time::Instant;

const STUN_BATCH_TIMEOUT: Duration = Duration::from_secs(5);

#[allow(dead_code)]
pub async fn stun_probe(stun_addr: Option<String>) -> Result<crate::network::stun::DualStunResult> {
    let stun_addr = stun_addr.unwrap_or_else(|| {
        crate::config::defaults::default_stun_servers()
            .into_iter()
            .next()
            .unwrap_or_default()
    });
    if stun_addr.is_empty() {
        return Err(ProxyError::Proxy("STUN server is not configured".to_string()));
    }
    stun_probe_dual(&stun_addr).await
}

#[allow(dead_code)]
pub async fn detect_public_ip() -> Option<IpAddr> {
    fetch_public_ipv4_with_retry().await.ok().flatten().map(IpAddr::V4)
}

impl MePool {
    fn configured_stun_servers(&self) -> Vec<String> {
        if !self.nat_stun_servers.is_empty() {
            return self.nat_stun_servers.clone();
        }
        if let Some(s) = &self.nat_stun
            && !s.trim().is_empty()
        {
            return vec![s.clone()];
        }
        Vec::new()
    }

    async fn probe_stun_batch_for_family(
        &self,
        servers: &[String],
        family: IpFamily,
        attempt: u8,
    ) -> (Vec<String>, Option<std::net::SocketAddr>) {
        let mut join_set = JoinSet::new();
        let mut next_idx = 0usize;
        let mut live_servers = Vec::new();
        let mut best_by_ip: HashMap<IpAddr, (usize, std::net::SocketAddr)> = HashMap::new();
        let concurrency = self.nat_probe_concurrency.max(1);

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
                Ok((stun_addr, Ok(Ok(res)))) => {
                    let picked: Option<StunProbeResult> = match family {
                        IpFamily::V4 => res.v4,
                        IpFamily::V6 => res.v6,
                    };

                    if let Some(result) = picked {
                        live_servers.push(stun_addr.clone());
                        let entry = best_by_ip
                            .entry(result.reflected_addr.ip())
                            .or_insert((0, result.reflected_addr));
                        entry.0 += 1;
                        debug!(
                            local = %result.local_addr,
                            reflected = %result.reflected_addr,
                            family = ?family,
                            stun = %stun_addr,
                            "NAT probe: reflected address"
                        );
                    }
                }
                Ok((stun_addr, Ok(Err(e)))) => {
                    debug!(
                        error = %e,
                        stun = %stun_addr,
                        attempt = attempt + 1,
                        "NAT probe failed, trying next server"
                    );
                }
                Ok((stun_addr, Err(_))) => {
                    debug!(
                        stun = %stun_addr,
                        attempt = attempt + 1,
                        "NAT probe timeout, trying next server"
                    );
                }
                Err(e) => {
                    debug!(
                        error = %e,
                        attempt = attempt + 1,
                        "NAT probe task join failed"
                    );
                }
            }
        }

        live_servers.sort_unstable();
        live_servers.dedup();
        let best_reflected = best_by_ip
            .into_values()
            .max_by_key(|(count, _)| *count)
            .map(|(_, addr)| addr);

        (live_servers, best_reflected)
    }

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
        let configured_servers = self.configured_stun_servers();
        let live_snapshot = self.nat_stun_live_servers.read().await.clone();
        let primary_servers = if live_snapshot.is_empty() {
            configured_servers.clone()
        } else {
            live_snapshot
        };

        let (mut live_servers, mut selected_reflected) = self
            .probe_stun_batch_for_family(&primary_servers, family, attempt)
            .await;

        if selected_reflected.is_none() && !configured_servers.is_empty() && primary_servers != configured_servers {
            let (rediscovered_live, rediscovered_reflected) = self
                .probe_stun_batch_for_family(&configured_servers, family, attempt)
                .await;
            live_servers = rediscovered_live;
            selected_reflected = rediscovered_reflected;
        }

        let live_server_count = live_servers.len();
        if !live_servers.is_empty() {
            *self.nat_stun_live_servers.write().await = live_servers;
        } else {
            self.nat_stun_live_servers.write().await.clear();
        }

        if let Some(reflected_addr) = selected_reflected {
            self.nat_probe_attempts.store(0, std::sync::atomic::Ordering::Relaxed);
            info!(
                family = ?family,
                live_servers = live_server_count,
                "STUN-Quorum reached, IP: {}",
                reflected_addr.ip()
            );
            if let Ok(mut cache) = self.nat_reflection_cache.try_lock() {
                let slot = match family {
                    IpFamily::V4 => &mut cache.v4,
                    IpFamily::V6 => &mut cache.v6,
                };
                *slot = Some((Instant::now(), reflected_addr));
            }
            return Some(reflected_addr);
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
