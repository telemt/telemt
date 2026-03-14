use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::error::{ProxyError, Result};
use crate::network::probe::is_bogon;
use crate::network::stun::{stun_probe_dual, stun_probe_family_with_bind, IpFamily};

use super::MePool;
use std::time::Instant;

const STUN_BATCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Probes a configured STUN server and returns dual-stack reflection data.
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

/// Attempts to detect a public IPv4 address via external HTTP providers.
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
        bind_ip: Option<IpAddr>,
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
                    let res = timeout(
                        STUN_BATCH_TIMEOUT,
                        stun_probe_family_with_bind(&stun_addr, family, bind_ip),
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
        let ip = if let Some(nat_ip) = self.nat_ip_cfg {
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
        bind_ip: Option<IpAddr>,
    ) -> Option<std::net::SocketAddr> {
        const STUN_CACHE_TTL: Duration = Duration::from_secs(600);
        let use_shared_cache = bind_ip.is_none();
        if !use_shared_cache {
            match (family, bind_ip) {
                (IpFamily::V4, Some(IpAddr::V4(_)))
                | (IpFamily::V6, Some(IpAddr::V6(_)))
                | (_, None) => {}
                _ => return None,
            }
        }
        // Backoff window
        if use_shared_cache
            && let Some(until) = *self.stun_backoff_until.read().await
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

        if use_shared_cache
            && let Ok(mut cache) = self.nat_reflection_cache.try_lock()
        {
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

        let _singleflight_guard = if use_shared_cache {
            Some(match family {
                IpFamily::V4 => self.nat_reflection_singleflight_v4.lock().await,
                IpFamily::V6 => self.nat_reflection_singleflight_v6.lock().await,
            })
        } else {
            None
        };

        if use_shared_cache
            && let Some(until) = *self.stun_backoff_until.read().await
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

        if use_shared_cache
            && let Ok(mut cache) = self.nat_reflection_cache.try_lock()
        {
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

        let attempt = if use_shared_cache {
            self.nat_probe_attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        } else {
            0
        };
        let configured_servers = self.configured_stun_servers();
        let live_snapshot = self.nat_stun_live_servers.read().await.clone();
        let primary_servers = if live_snapshot.is_empty() {
            configured_servers.clone()
        } else {
            live_snapshot
        };

        let (mut live_servers, mut selected_reflected) = self
            .probe_stun_batch_for_family(&primary_servers, family, attempt, bind_ip)
            .await;

        let missing_primary_reflection = selected_reflected.is_none();
        let has_configured_servers = !configured_servers.is_empty();
        let primary_differs_from_configured = primary_servers != configured_servers;
        let should_retry_with_configured =
            missing_primary_reflection && has_configured_servers && primary_differs_from_configured;

        if should_retry_with_configured {
            let (rediscovered_live, rediscovered_reflected) = self
                .probe_stun_batch_for_family(&configured_servers, family, attempt, bind_ip)
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
            if use_shared_cache {
                self.nat_probe_attempts.store(0, std::sync::atomic::Ordering::Relaxed);
            }
            info!(
                family = ?family,
                live_servers = live_server_count,
                "STUN-Quorum reached, IP: {}",
                reflected_addr.ip()
            );
            if use_shared_cache
                && let Ok(mut cache) = self.nat_reflection_cache.try_lock()
            {
                let slot = match family {
                    IpFamily::V4 => &mut cache.v4,
                    IpFamily::V6 => &mut cache.v6,
                };
                *slot = Some((Instant::now(), reflected_addr));
            }
            return Some(reflected_addr);
        }

        if use_shared_cache {
            let backoff = Duration::from_secs(60 * 2u64.pow(u32::from(attempt).min(6)));
            *self.stun_backoff_until.write().await = Some(Instant::now() + backoff);
        }
        None
    }
}

async fn fetch_public_ipv4_with_retry() -> Result<Option<Ipv4Addr>> {
    let providers = [
        "https://checkip.amazonaws.com",
        "https://v4.ident.me",
        "https://ipv4.icanhazip.com",
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

    Ok(parse_public_ipv4_response(text.trim()))
}

fn parse_public_ipv4_response(body: &str) -> Option<Ipv4Addr> {
    let ip = body.parse::<Ipv4Addr>().ok()?;
    if is_bogon(IpAddr::V4(ip)) {
        return None;
    }
    Some(ip)
}

#[cfg(test)]
mod tests {
    use super::parse_public_ipv4_response;
    use std::net::Ipv4Addr;

    fn should_retry_with_configured(
        selected_reflected: Option<std::net::SocketAddr>,
        configured_servers: &[String],
        primary_servers: &[String],
    ) -> bool {
        let missing_primary_reflection = selected_reflected.is_none();
        let has_configured_servers = !configured_servers.is_empty();
        let primary_differs_from_configured = primary_servers != configured_servers;

        missing_primary_reflection && has_configured_servers && primary_differs_from_configured
    }

    #[test]
    fn fallback_retry_is_disabled_when_reflection_already_selected() {
        let configured = vec!["stun-a.example:3478".to_string()];
        let primary = vec!["stun-b.example:3478".to_string()];
        let selected = Some(std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 10)),
            44444,
        ));

        assert!(!should_retry_with_configured(selected, &configured, &primary));
    }

    #[test]
    fn fallback_retry_is_disabled_when_no_configured_servers_exist() {
        let configured = Vec::new();
        let primary = vec!["stun-live.example:3478".to_string()];

        assert!(!should_retry_with_configured(None, &configured, &primary));
    }

    #[test]
    fn fallback_retry_is_disabled_when_primary_matches_configured() {
        let configured = vec![
            "stun-a.example:3478".to_string(),
            "stun-b.example:3478".to_string(),
        ];
        let primary = configured.clone();

        assert!(!should_retry_with_configured(None, &configured, &primary));
    }

    #[test]
    fn fallback_retry_is_enabled_only_for_missing_reflection_and_mismatched_server_sets() {
        let configured = vec![
            "stun-a.example:3478".to_string(),
            "stun-b.example:3478".to_string(),
        ];
        let primary = vec!["stun-live.example:3478".to_string()];

        assert!(should_retry_with_configured(None, &configured, &primary));
    }

    #[test]
    fn parse_public_ipv4_response_accepts_public_ipv4() {
        let parsed = parse_public_ipv4_response("1.1.1.1");
        assert_eq!(parsed, Some(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn parse_public_ipv4_response_rejects_bogon_ipv4() {
        let parsed = parse_public_ipv4_response("10.0.0.4");
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_public_ipv4_response_rejects_payload_with_extra_tokens() {
        let parsed = parse_public_ipv4_response("1.1.1.1\n8.8.8.8");
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_public_ipv4_response_rejects_trailing_garbage() {
        let parsed = parse_public_ipv4_response("1.1.1.1 trailing");
        assert!(parsed.is_none());
    }
}
