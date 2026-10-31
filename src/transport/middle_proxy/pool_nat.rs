use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, info};

use crate::error::{ProxyError, Result};
use crate::network::probe::{detect_public_ipv4_http, is_bogon};
use crate::network::stun::{
    IpFamily, stun_probe_dual_with_tcp_fallback,
    stun_probe_family_with_bind_tcp_fallback_and_resolver,
};

use super::MePool;
use std::time::Instant;

const STUN_BATCH_TIMEOUT: Duration = Duration::from_secs(5);
const STUN_BATCH_TCP_FALLBACK_TIMEOUT: Duration = Duration::from_secs(12);
const STUN_CACHE_TTL: Duration = Duration::from_secs(600);
const HTTP_FAILURE_TTL: Duration = Duration::from_secs(60);

// Discovery ownership and source-bound cache admission for this pool generation.
mod state;
pub(super) use state::NatDiscovery;
// Successful HTTP observations expire independently of failure backoff.
mod http;
pub(super) use http::HttpNatObservation;

// Local network regressions exercise cancellation before discovery publication.
#[cfg(test)]
mod tests;

/// Probes the configured or default STUN endpoint with both address families.
#[allow(dead_code)]
pub async fn stun_probe(stun_addr: Option<String>) -> Result<crate::network::stun::DualStunResult> {
    let stun_addr = stun_addr.unwrap_or_else(|| {
        crate::config::defaults::default_stun_servers()
            .into_iter()
            .next()
            .unwrap_or_default()
    });
    if stun_addr.is_empty() {
        return Err(ProxyError::Proxy(
            "STUN server is not configured".to_string(),
        ));
    }
    stun_probe_dual_with_tcp_fallback(&stun_addr, false).await
}

/// Detects a public IPv4 address using the default HTTP endpoints.
#[allow(dead_code)]
pub async fn detect_public_ip() -> Option<IpAddr> {
    let urls = crate::config::defaults::default_http_ip_detect_urls();
    detect_public_ipv4_http(&urls).await.map(IpAddr::V4)
}

impl MePool {
    fn configured_stun_servers(&self) -> Vec<String> {
        if !self.nat_runtime.nat_stun_servers.is_empty() {
            return self.nat_runtime.nat_stun_servers.clone();
        }
        if let Some(s) = &self.nat_runtime.nat_stun
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
        bind_ip: Option<IpAddr>,
    ) -> (Vec<String>, Option<std::net::SocketAddr>) {
        let mut join_set = JoinSet::new();
        let mut next_idx = 0usize;
        let mut live_servers = Vec::new();
        let mut best_by_ip: HashMap<IpAddr, (usize, std::net::SocketAddr)> = HashMap::new();
        let concurrency = self.nat_runtime.nat_probe_concurrency.max(1);
        let tcp_fallback = self.nat_runtime.stun_tcp_fallback;
        let dns_resolver = self.upstream.as_ref().map(|manager| manager.dns_resolver());

        while next_idx < servers.len() || !join_set.is_empty() {
            while next_idx < servers.len() && join_set.len() < concurrency {
                let stun_addr = servers[next_idx].clone();
                let dns_resolver = dns_resolver.clone();
                next_idx += 1;
                join_set.spawn(async move {
                    let batch_timeout = if tcp_fallback {
                        STUN_BATCH_TCP_FALLBACK_TIMEOUT
                    } else {
                        STUN_BATCH_TIMEOUT
                    };
                    let res = timeout(
                        batch_timeout,
                        stun_probe_family_with_bind_tcp_fallback_and_resolver(
                            &stun_addr,
                            family,
                            bind_ip,
                            tcp_fallback,
                            dns_resolver.as_deref(),
                        ),
                    )
                    .await;
                    (stun_addr, res)
                });
            }

            let Some(task) = join_set.join_next().await else {
                break;
            };

            match task {
                Ok((stun_addr, Ok(Ok(picked)))) => {
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

    /// Applies the configured or HTTP-detected NAT IP to non-public addresses.
    #[cfg(test)]
    pub(super) fn translate_ip_for_nat(&self, ip: IpAddr) -> IpAddr {
        Self::translate_ip_with_nat(
            ip,
            self.nat_runtime
                .nat_ip_cfg
                .or_else(|| self.cached_http_nat_ip()),
        )
    }

    /// Applies a captured NAT observation without rereading mutable discovery state.
    pub(super) fn translate_ip_with_nat(ip: IpAddr, nat_ip: Option<IpAddr>) -> IpAddr {
        let Some(nat_ip) = nat_ip else {
            return ip;
        };

        match (ip, nat_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst))
                if is_bogon(IpAddr::V4(src)) || src.is_loopback() || src.is_unspecified() =>
            {
                IpAddr::V4(dst)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) if src.is_loopback() || src.is_unspecified() => {
                IpAddr::V6(dst)
            }
            (orig, _) => orig,
        }
    }

    /// Selects the NAT source IP without replacing the actual TCP source port.
    pub(super) fn translate_our_addr_with_reflection(
        &self,
        addr: std::net::SocketAddr,
        reflected: Option<std::net::SocketAddr>,
    ) -> std::net::SocketAddr {
        self.translate_our_addr_with_nat(addr, reflected, self.cached_http_nat_ip())
    }

    /// Retains the actual TCP port while using one handshake-local NAT snapshot.
    pub(super) fn translate_our_addr_with_nat(
        &self,
        addr: std::net::SocketAddr,
        reflected: Option<std::net::SocketAddr>,
        detected: Option<IpAddr>,
    ) -> std::net::SocketAddr {
        let ip = if let Some(nat_ip) = self.nat_runtime.nat_ip_cfg {
            match (addr.ip(), nat_ip) {
                (IpAddr::V4(_), IpAddr::V4(dst)) => IpAddr::V4(dst),
                (IpAddr::V6(_), IpAddr::V6(dst)) => IpAddr::V6(dst),
                _ => addr.ip(),
            }
        } else if let Some(r) = reflected {
            // Use reflected IP (not port) only when local address is non-public.
            if is_bogon(addr.ip()) || addr.ip().is_loopback() || addr.ip().is_unspecified() {
                r.ip()
            } else {
                Self::translate_ip_with_nat(addr.ip(), detected)
            }
        } else {
            Self::translate_ip_with_nat(addr.ip(), detected)
        };

        // Keep the kernel-assigned TCP source port; STUN port can differ.
        std::net::SocketAddr::new(ip, addr.port())
    }

    /// Waits for a pool-owned STUN refresh in the exact source-address context.
    pub(super) async fn maybe_reflect_public_addr(
        self: &Arc<Self>,
        family: IpFamily,
        bind_ip: Option<IpAddr>,
    ) -> Option<std::net::SocketAddr> {
        if let Some(bind_ip) = bind_ip {
            return self.reflect_bound_addr(family, bind_ip).await;
        }
        if let Some(cached) = self.cached_shared_reflection(family).await {
            return cached;
        }
        let singleflight = match family {
            IpFamily::V4 => self.nat_runtime.nat_reflection_singleflight_v4.clone(),
            IpFamily::V6 => self.nat_runtime.nat_reflection_singleflight_v6.clone(),
        };
        let flight = singleflight.lock_owned().await;
        if let Some(cached) = self.cached_shared_reflection(family).await {
            return cached;
        }

        let pool = self.clone();
        let (send, receive) = oneshot::channel();
        self.lifecycle
            .spawn_producer(async move {
                let _flight = flight;
                let attempt = pool
                    .nat_runtime
                    .nat_probe_attempts
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let reflected = pool.refresh_stun(family, None, attempt).await;
                if let Some(addr) = reflected {
                    // Cache readers must never cause a completed refresh to be discarded.
                    let mut cache = pool.nat_runtime.nat_reflection_cache.lock().await;
                    let slot = match family {
                        IpFamily::V4 => &mut cache.v4,
                        IpFamily::V6 => &mut cache.v6,
                    };
                    *slot = Some((Instant::now(), addr));
                    pool.nat_runtime
                        .nat_probe_attempts
                        .store(0, std::sync::atomic::Ordering::Relaxed);
                } else {
                    let backoff = Duration::from_secs(60 * 2u64.pow((attempt as u32).min(6)));
                    *pool.nat_runtime.stun_backoff_until.write().await =
                        Some(Instant::now() + backoff);
                }
                let _ = send.send(reflected);
            })
            .ok()?;
        receive.await.ok().flatten()
    }

    async fn cached_shared_reflection(
        &self,
        family: IpFamily,
    ) -> Option<Option<std::net::SocketAddr>> {
        let backoff = self
            .nat_runtime
            .stun_backoff_until
            .read()
            .await
            .is_some_and(|until| Instant::now() < until);
        let cache = self.nat_runtime.nat_reflection_cache.lock().await;
        let slot = match family {
            IpFamily::V4 => cache.v4,
            IpFamily::V6 => cache.v6,
        };
        // Preserve the existing stale-result fallback during shared failure backoff.
        if backoff {
            return Some(slot.map(|(_, addr)| addr));
        }
        slot.filter(|(created, _)| created.elapsed() < STUN_CACHE_TTL)
            .map(|(_, addr)| Some(addr))
    }

    async fn refresh_stun(
        &self,
        family: IpFamily,
        bind_ip: Option<IpAddr>,
        attempt: u8,
    ) -> Option<std::net::SocketAddr> {
        let configured_servers = self.configured_stun_servers();
        let live_snapshot = self.nat_runtime.nat_stun_live_servers.read().await.clone();
        let primary_servers = if live_snapshot.is_empty() {
            configured_servers.clone()
        } else {
            live_snapshot
        };

        let (mut live_servers, mut selected_reflected) = self
            .probe_stun_batch_for_family(&primary_servers, family, attempt, bind_ip)
            .await;

        if selected_reflected.is_none()
            && !configured_servers.is_empty()
            && primary_servers != configured_servers
        {
            let (rediscovered_live, rediscovered_reflected) = self
                .probe_stun_batch_for_family(&configured_servers, family, attempt, bind_ip)
                .await;
            live_servers = rediscovered_live;
            selected_reflected = rediscovered_reflected;
        }

        let live_server_count = live_servers.len();
        if !live_servers.is_empty() {
            *self.nat_runtime.nat_stun_live_servers.write().await = live_servers;
        } else {
            self.nat_runtime.nat_stun_live_servers.write().await.clear();
        }

        if let Some(reflected_addr) = selected_reflected {
            info!(
                family = ?family,
                live_servers = live_server_count,
                "STUN-Quorum reached, IP: {}",
                reflected_addr.ip()
            );
            return Some(reflected_addr);
        }
        None
    }
}
