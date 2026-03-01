//! Upstream Management with per-DC latency-weighted selection
//!
//! IPv6/IPv4 connectivity checks with configurable preference.

#![allow(deprecated)]

use std::collections::{BTreeSet, HashMap};
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::Instant;
use rand::Rng;
use tracing::{debug, warn, info, trace};

use crate::config::{UpstreamConfig, UpstreamType};
use crate::error::{Result, ProxyError};
use crate::network::dns_overrides::{resolve_socket_addr, split_host_port};
use crate::protocol::constants::{TG_DATACENTERS_V4, TG_DATACENTERS_V6, TG_DATACENTER_PORT};
use crate::transport::socket::{create_outgoing_socket_bound, resolve_interface_ip};
use crate::transport::socks::{connect_socks4, connect_socks5};

/// Number of Telegram datacenters
const NUM_DCS: usize = 5;

/// Timeout for individual DC ping attempt
const DC_PING_TIMEOUT_SECS: u64 = 5;
/// Timeout for direct TG DC TCP connect readiness.
const DIRECT_CONNECT_TIMEOUT_SECS: u64 = 10;
/// Interval between upstream health-check cycles.
const HEALTH_CHECK_INTERVAL_SECS: u64 = 30;
/// Timeout for a single health-check connect attempt.
const HEALTH_CHECK_CONNECT_TIMEOUT_SECS: u64 = 10;
/// Upstream is considered healthy when at least this many DC groups are reachable.
const MIN_HEALTHY_DC_GROUPS: usize = 3;

// ============= RTT Tracking =============

#[derive(Debug, Clone, Copy)]
struct LatencyEma {
    value_ms: Option<f64>,
    alpha: f64,
}

impl LatencyEma {
    const fn new(alpha: f64) -> Self {
        Self { value_ms: None, alpha }
    }

    fn update(&mut self, sample_ms: f64) {
        self.value_ms = Some(match self.value_ms {
            None => sample_ms,
            Some(prev) => prev * (1.0 - self.alpha) + sample_ms * self.alpha,
        });
    }

    fn get(&self) -> Option<f64> {
        self.value_ms
    }
}

// ============= Per-DC IP Preference Tracking =============

/// Tracks which IP version works for each DC
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpPreference {
    /// Not yet tested
    #[default]
    Unknown,
    /// IPv6 works
    PreferV6,
    /// Only IPv4 works (IPv6 failed)
    PreferV4,
    /// Both work
    BothWork,
    /// Both failed
    Unavailable,
}

// ============= Upstream State =============

#[derive(Debug)]
struct UpstreamState {
    config: UpstreamConfig,
    healthy: bool,
    fails: u32,
    last_check: std::time::Instant,
    /// Per-DC latency EMA (index 0 = DC1, index 4 = DC5)
    dc_latency: [LatencyEma; NUM_DCS],
    /// Per-DC IP version preference (learned from connectivity tests)
    dc_ip_pref: [IpPreference; NUM_DCS],
    /// Round-robin counter for bind_addresses selection
    bind_rr: Arc<AtomicUsize>,
}

impl UpstreamState {
    fn new(config: UpstreamConfig) -> Self {
        Self {
            config,
            healthy: true,
            fails: 0,
            last_check: std::time::Instant::now(),
            dc_latency: [LatencyEma::new(0.3); NUM_DCS],
            dc_ip_pref: [IpPreference::Unknown; NUM_DCS],
            bind_rr: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Map DC index to latency array slot (0..NUM_DCS).
    fn dc_array_idx(dc_idx: i16) -> Option<usize> {
        let abs_dc = dc_idx.unsigned_abs() as usize;
        if abs_dc == 0 {
            return None;
        }
        if (1..=NUM_DCS).contains(&abs_dc) {
            Some(abs_dc - 1)
        } else {
            // Unknown DC → default cluster (DC 2, index 1)
            Some(1)
        }
    }

    /// Get latency for a specific DC, falling back to average across all known DCs
    fn effective_latency(&self, dc_idx: Option<i16>) -> Option<f64> {
        if let Some(di) = dc_idx.and_then(Self::dc_array_idx)
            && let Some(ms) = self.dc_latency[di].get()
        {
            return Some(ms);
        }

        let (sum, count) = self.dc_latency.iter()
            .filter_map(|l| l.get())
            .fold((0.0, 0u32), |(s, c), v| (s + v, c + 1));

        if count > 0 { Some(sum / count as f64) } else { None }
    }
}

/// Result of a single DC ping
#[derive(Debug, Clone)]
pub struct DcPingResult {
    pub dc_idx: usize,
    pub dc_addr: SocketAddr,
    pub rtt_ms: Option<f64>,
    pub error: Option<String>,
}

/// Result of startup ping for one upstream (separate v6/v4 results)
#[derive(Debug, Clone)]
pub struct StartupPingResult {
    pub v6_results: Vec<DcPingResult>,
    pub v4_results: Vec<DcPingResult>,
    pub upstream_name: String,
    /// True if both IPv6 and IPv4 have at least one working DC
    pub both_available: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamRouteKind {
    Direct,
    Socks4,
    Socks5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamEgressInfo {
    pub route_kind: UpstreamRouteKind,
    pub local_addr: Option<SocketAddr>,
    pub direct_bind_ip: Option<IpAddr>,
    pub socks_bound_addr: Option<SocketAddr>,
    pub socks_proxy_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
struct HealthCheckGroup {
    dc_idx: i16,
    primary: Vec<SocketAddr>,
    fallback: Vec<SocketAddr>,
}

// ============= Upstream Manager =============

#[derive(Clone)]
pub struct UpstreamManager {
    upstreams: Arc<RwLock<Vec<UpstreamState>>>,
    connect_retry_attempts: u32,
    connect_retry_backoff: Duration,
    unhealthy_fail_threshold: u32,
}

impl UpstreamManager {
    pub fn new(
        configs: Vec<UpstreamConfig>,
        connect_retry_attempts: u32,
        connect_retry_backoff_ms: u64,
        unhealthy_fail_threshold: u32,
    ) -> Self {
        let states = configs.into_iter()
            .filter(|c| c.enabled)
            .map(UpstreamState::new)
            .collect();

        Self {
            upstreams: Arc::new(RwLock::new(states)),
            connect_retry_attempts: connect_retry_attempts.max(1),
            connect_retry_backoff: Duration::from_millis(connect_retry_backoff_ms),
            unhealthy_fail_threshold: unhealthy_fail_threshold.max(1),
        }
    }

    #[cfg(unix)]
    fn resolve_interface_addrs(name: &str, want_ipv6: bool) -> Vec<IpAddr> {
        use nix::ifaddrs::getifaddrs;

        let mut out = Vec::new();
        if let Ok(addrs) = getifaddrs() {
            for iface in addrs {
                if iface.interface_name != name {
                    continue;
                }
                if let Some(address) = iface.address {
                    if let Some(v4) = address.as_sockaddr_in() {
                        if !want_ipv6 {
                            out.push(IpAddr::V4(v4.ip()));
                        }
                    } else if let Some(v6) = address.as_sockaddr_in6()
                        && want_ipv6
                    {
                        out.push(IpAddr::V6(v6.ip()));
                    }
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    fn resolve_bind_address(
        interface: &Option<String>,
        bind_addresses: &Option<Vec<String>>,
        target: SocketAddr,
        rr: Option<&AtomicUsize>,
        validate_ip_on_interface: bool,
    ) -> Option<IpAddr> {
        let want_ipv6 = target.is_ipv6();

        if let Some(addrs) = bind_addresses {
            let mut candidates: Vec<IpAddr> = addrs
                .iter()
                .filter_map(|s| s.parse::<IpAddr>().ok())
                .filter(|ip| ip.is_ipv6() == want_ipv6)
                .collect();

            // Explicit bind IP has strict priority over interface auto-selection.
            if validate_ip_on_interface
                && let Some(iface) = interface
                && iface.parse::<IpAddr>().is_err()
            {
                #[cfg(unix)]
                {
                    let iface_addrs = Self::resolve_interface_addrs(iface, want_ipv6);
                    if !iface_addrs.is_empty() {
                        candidates.retain(|ip| {
                            let ok = iface_addrs.contains(ip);
                            if !ok {
                                warn!(
                                    interface = %iface,
                                    bind_ip = %ip,
                                    target = %target,
                                    "Configured bind address is not assigned to interface"
                                );
                            }
                            ok
                        });
                    } else if !candidates.is_empty() {
                        warn!(
                            interface = %iface,
                            target = %target,
                            "Configured interface has no addresses for target family; falling back to direct connect without bind"
                        );
                        candidates.clear();
                    }
                }
            }

            if !candidates.is_empty() {
                if let Some(counter) = rr {
                    let idx = counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
                    return Some(candidates[idx]);
                }
                return candidates.first().copied();
            }

            if validate_ip_on_interface
                && interface
                    .as_ref()
                    .is_some_and(|iface| iface.parse::<IpAddr>().is_err())
            {
                warn!(
                    interface = interface.as_deref().unwrap_or(""),
                    target = %target,
                    "No valid bind_addresses left for interface; falling back to direct connect without bind"
                );
                return None;
            }
        }

        if let Some(iface) = interface {
            if let Ok(ip) = iface.parse::<IpAddr>() {
                if ip.is_ipv6() == want_ipv6 {
                    return Some(ip);
                }
            } else {
                #[cfg(unix)]
                if let Some(ip) = resolve_interface_ip(iface, want_ipv6) {
                    return Some(ip);
                }
            }
        }

        None
    }

    async fn connect_hostname_with_dns_override(
        address: &str,
        connect_timeout: Duration,
    ) -> Result<TcpStream> {
        if let Some((host, port)) = split_host_port(address)
            && let Some(addr) = resolve_socket_addr(&host, port)
        {
            return match tokio::time::timeout(connect_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => Ok(stream),
                Ok(Err(e)) => Err(ProxyError::Io(e)),
                Err(_) => Err(ProxyError::ConnectionTimeout {
                    addr: addr.to_string(),
                }),
            };
        }

        match tokio::time::timeout(connect_timeout, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(ProxyError::Io(e)),
            Err(_) => Err(ProxyError::ConnectionTimeout {
                addr: address.to_string(),
            }),
        }
    }

    /// Select upstream using latency-weighted random selection.
    async fn select_upstream(&self, dc_idx: Option<i16>, scope: Option<&str>) -> Option<usize> {
        let upstreams = self.upstreams.read().await;
        if upstreams.is_empty() {
            return None;
        }
        // Scope filter:
        //   If scope is set: only scoped and matched items
        //   If scope is not set: only unscoped items
        let filtered_upstreams : Vec<usize> = upstreams.iter()
            .enumerate()
            .filter(|(_, u)| {
                scope.map_or(
                    u.config.scopes.is_empty(),
                    |req_scope| {
                        u.config.scopes
                            .split(',')
                            .map(str::trim)
                            .any(|s| s == req_scope)
                    }
                )
            })
            .map(|(i, _)| i)
            .collect();

        // Healthy filter
        let healthy: Vec<usize> = filtered_upstreams.iter()
            .filter(|&&i| upstreams[i].healthy)
            .copied()
            .collect();

        if filtered_upstreams.is_empty() {
            warn!(scope = scope, "No upstreams available! Using first (direct?)");
            return None;
        }

        if healthy.is_empty() {
            warn!(scope = scope, "No healthy upstreams available! Using random.");
            return Some(filtered_upstreams[rand::rng().gen_range(0..filtered_upstreams.len())]);
        }

        if healthy.len() == 1 {
            return Some(healthy[0]);
        }

        let weights: Vec<(usize, f64)> = healthy.iter().map(|&i| {
            let base = upstreams[i].config.weight as f64;
            let latency_factor = upstreams[i].effective_latency(dc_idx)
                .map(|ms| if ms > 1.0 { 1000.0 / ms } else { 1000.0 })
                .unwrap_or(1.0);

            (i, base * latency_factor)
        }).collect();

        let total: f64 = weights.iter().map(|(_, w)| w).sum();

        if total <= 0.0 {
            return Some(healthy[rand::rng().gen_range(0..healthy.len())]);
        }

        let mut choice: f64 = rand::rng().gen_range(0.0..total);

        for &(idx, weight) in &weights {
            if choice < weight {
                trace!(
                    upstream = idx,
                    dc = ?dc_idx,
                    weight = format!("{:.2}", weight),
                    total = format!("{:.2}", total),
                    "Upstream selected"
                );
                return Some(idx);
            }
            choice -= weight;
        }

        Some(healthy[0])
    }

    /// Connect to target through a selected upstream.
    pub async fn connect(&self, target: SocketAddr, dc_idx: Option<i16>, scope: Option<&str>) -> Result<TcpStream> {
        let (stream, _) = self.connect_with_details(target, dc_idx, scope).await?;
        Ok(stream)
    }

    /// Connect to target through a selected upstream and return egress details.
    pub async fn connect_with_details(
        &self,
        target: SocketAddr,
        dc_idx: Option<i16>,
        scope: Option<&str>,
    ) -> Result<(TcpStream, UpstreamEgressInfo)> {
        let idx = self.select_upstream(dc_idx, scope).await
            .ok_or_else(|| ProxyError::Config("No upstreams available".to_string()))?;

        let mut upstream = {
            let guard = self.upstreams.read().await;
            guard[idx].config.clone()
        };

        // Set scope for configuration copy
        if let Some(s) = scope {
            upstream.selected_scope = s.to_string();
        }

        let bind_rr = {
            let guard = self.upstreams.read().await;
            guard.get(idx).map(|u| u.bind_rr.clone())
        };

        let mut last_error: Option<ProxyError> = None;
        for attempt in 1..=self.connect_retry_attempts {
            let start = Instant::now();
            match self
                .connect_via_upstream(&upstream, target, bind_rr.clone())
                .await
            {
                Ok((stream, egress)) => {
                    let rtt_ms = start.elapsed().as_secs_f64() * 1000.0;
                    let mut guard = self.upstreams.write().await;
                    if let Some(u) = guard.get_mut(idx) {
                        if !u.healthy {
                            debug!(rtt_ms = format!("{:.1}", rtt_ms), "Upstream recovered");
                        }
                        if attempt > 1 {
                            debug!(
                                attempt,
                                attempts = self.connect_retry_attempts,
                                rtt_ms = format!("{:.1}", rtt_ms),
                                "Upstream connect recovered after retry"
                            );
                        }
                        u.healthy = true;
                        u.fails = 0;

                        if let Some(di) = dc_idx.and_then(UpstreamState::dc_array_idx) {
                            u.dc_latency[di].update(rtt_ms);
                        }
                    }
                    return Ok((stream, egress));
                }
                Err(e) => {
                    if attempt < self.connect_retry_attempts {
                        debug!(
                            attempt,
                            attempts = self.connect_retry_attempts,
                            target = %target,
                            error = %e,
                            "Upstream connect attempt failed, retrying"
                        );
                        if !self.connect_retry_backoff.is_zero() {
                            tokio::time::sleep(self.connect_retry_backoff).await;
                        }
                    }
                    last_error = Some(e);
                }
            }
        }

        let error = last_error.unwrap_or_else(|| {
            ProxyError::Config("Upstream connect attempts exhausted".to_string())
        });

        let mut guard = self.upstreams.write().await;
        if let Some(u) = guard.get_mut(idx) {
            u.fails += 1;
            warn!(
                fails = u.fails,
                attempts = self.connect_retry_attempts,
                "Upstream failed after retries: {}",
                error
            );
            if u.fails >= self.unhealthy_fail_threshold {
                u.healthy = false;
                warn!(
                    fails = u.fails,
                    threshold = self.unhealthy_fail_threshold,
                    "Upstream marked unhealthy"
                );
            }
        }
        Err(error)
    }

    async fn connect_via_upstream(
        &self,
        config: &UpstreamConfig,
        target: SocketAddr,
        bind_rr: Option<Arc<AtomicUsize>>,
    ) -> Result<(TcpStream, UpstreamEgressInfo)> {
        match &config.upstream_type {
            UpstreamType::Direct { interface, bind_addresses } => {
                let bind_ip = Self::resolve_bind_address(
                    interface,
                    bind_addresses,
                    target,
                    bind_rr.as_deref(),
                    true,
                );

                let socket = create_outgoing_socket_bound(target, bind_ip)?;
                if let Some(ip) = bind_ip {
                    debug!(bind = %ip, target = %target, "Bound outgoing socket");
                } else if interface.is_some() || bind_addresses.is_some() {
                    debug!(target = %target, "No matching bind address for target family");
                }

                socket.set_nonblocking(true)?;
                match socket.connect(&target.into()) {
                    Ok(()) => {},
                    Err(err) if err.raw_os_error() == Some(libc::EINPROGRESS) || err.kind() == std::io::ErrorKind::WouldBlock => {},
                    Err(err) => return Err(ProxyError::Io(err)),
                }

                let std_stream: std::net::TcpStream = socket.into();
                let stream = TcpStream::from_std(std_stream)?;

                let connect_timeout = Duration::from_secs(DIRECT_CONNECT_TIMEOUT_SECS);
                match tokio::time::timeout(connect_timeout, stream.writable()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return Err(ProxyError::Io(e)),
                    Err(_) => {
                        return Err(ProxyError::ConnectionTimeout {
                            addr: target.to_string(),
                        });
                    }
                }
                if let Some(e) = stream.take_error()? {
                    return Err(ProxyError::Io(e));
                }

                let local_addr = stream.local_addr().ok();
                Ok((
                    stream,
                    UpstreamEgressInfo {
                        route_kind: UpstreamRouteKind::Direct,
                        local_addr,
                        direct_bind_ip: bind_ip,
                        socks_bound_addr: None,
                        socks_proxy_addr: None,
                    },
                ))
            },
            UpstreamType::Socks4 { address, interface, user_id } => {
                let connect_timeout = Duration::from_secs(DIRECT_CONNECT_TIMEOUT_SECS);
                // Try to parse as SocketAddr first (IP:port), otherwise treat as hostname:port
                let mut stream = if let Ok(proxy_addr) = address.parse::<SocketAddr>() {
                    // IP:port format - use socket with optional interface binding
                    let bind_ip = Self::resolve_bind_address(
                        interface,
                        &None,
                        proxy_addr,
                        bind_rr.as_deref(),
                        false,
                    );

                    let socket = create_outgoing_socket_bound(proxy_addr, bind_ip)?;

                    socket.set_nonblocking(true)?;
                    match socket.connect(&proxy_addr.into()) {
                        Ok(()) => {},
                        Err(err) if err.raw_os_error() == Some(libc::EINPROGRESS) || err.kind() == std::io::ErrorKind::WouldBlock => {},
                        Err(err) => return Err(ProxyError::Io(err)),
                    }

                    let std_stream: std::net::TcpStream = socket.into();
                    let stream = TcpStream::from_std(std_stream)?;

                    match tokio::time::timeout(connect_timeout, stream.writable()).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => return Err(ProxyError::Io(e)),
                        Err(_) => {
                            return Err(ProxyError::ConnectionTimeout {
                                addr: proxy_addr.to_string(),
                            });
                        }
                    }
                    if let Some(e) = stream.take_error()? {
                        return Err(ProxyError::Io(e));
                    }
                    stream
                } else {
                    // Hostname:port format - use tokio DNS resolution
                    // Note: interface binding is not supported for hostnames
                    if interface.is_some() {
                        warn!("SOCKS4 interface binding is not supported for hostname addresses, ignoring");
                    }
                    Self::connect_hostname_with_dns_override(address, connect_timeout).await?
                };

                // replace socks user_id with config.selected_scope, if set
                let scope: Option<&str> = Some(config.selected_scope.as_str())
                    .filter(|s| !s.is_empty());
                let _user_id: Option<&str> = scope.or(user_id.as_deref());

                let bound = match tokio::time::timeout(
                    connect_timeout,
                    connect_socks4(&mut stream, target, _user_id),
                )
                .await
                {
                    Ok(Ok(bound)) => bound,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(ProxyError::ConnectionTimeout {
                            addr: target.to_string(),
                        });
                    }
                };
                let local_addr = stream.local_addr().ok();
                let socks_proxy_addr = stream.peer_addr().ok();
                Ok((
                    stream,
                    UpstreamEgressInfo {
                        route_kind: UpstreamRouteKind::Socks4,
                        local_addr,
                        direct_bind_ip: None,
                        socks_bound_addr: Some(bound.addr),
                        socks_proxy_addr,
                    },
                ))
            },
            UpstreamType::Socks5 { address, interface, username, password } => {
                let connect_timeout = Duration::from_secs(DIRECT_CONNECT_TIMEOUT_SECS);
                // Try to parse as SocketAddr first (IP:port), otherwise treat as hostname:port
                let mut stream = if let Ok(proxy_addr) = address.parse::<SocketAddr>() {
                    // IP:port format - use socket with optional interface binding
                    let bind_ip = Self::resolve_bind_address(
                        interface,
                        &None,
                        proxy_addr,
                        bind_rr.as_deref(),
                        false,
                    );

                    let socket = create_outgoing_socket_bound(proxy_addr, bind_ip)?;

                    socket.set_nonblocking(true)?;
                    match socket.connect(&proxy_addr.into()) {
                        Ok(()) => {},
                        Err(err) if err.raw_os_error() == Some(libc::EINPROGRESS) || err.kind() == std::io::ErrorKind::WouldBlock => {},
                        Err(err) => return Err(ProxyError::Io(err)),
                    }

                    let std_stream: std::net::TcpStream = socket.into();
                    let stream = TcpStream::from_std(std_stream)?;

                    match tokio::time::timeout(connect_timeout, stream.writable()).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => return Err(ProxyError::Io(e)),
                        Err(_) => {
                            return Err(ProxyError::ConnectionTimeout {
                                addr: proxy_addr.to_string(),
                            });
                        }
                    }
                    if let Some(e) = stream.take_error()? {
                        return Err(ProxyError::Io(e));
                    }
                    stream
                } else {
                    // Hostname:port format - use tokio DNS resolution
                    // Note: interface binding is not supported for hostnames
                    if interface.is_some() {
                        warn!("SOCKS5 interface binding is not supported for hostname addresses, ignoring");
                    }
                    Self::connect_hostname_with_dns_override(address, connect_timeout).await?
                };

                debug!(config = ?config, "Socks5 connection");
                // replace socks user:pass with config.selected_scope, if set
                let scope: Option<&str> = Some(config.selected_scope.as_str())
                    .filter(|s| !s.is_empty());
                let _username: Option<&str> = scope.or(username.as_deref());
                let _password: Option<&str> = scope.or(password.as_deref());

                let bound = match tokio::time::timeout(
                    connect_timeout,
                    connect_socks5(&mut stream, target, _username, _password),
                )
                .await
                {
                    Ok(Ok(bound)) => bound,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(ProxyError::ConnectionTimeout {
                            addr: target.to_string(),
                        });
                    }
                };
                let local_addr = stream.local_addr().ok();
                let socks_proxy_addr = stream.peer_addr().ok();
                Ok((
                    stream,
                    UpstreamEgressInfo {
                        route_kind: UpstreamRouteKind::Socks5,
                        local_addr,
                        direct_bind_ip: None,
                        socks_bound_addr: Some(bound.addr),
                        socks_proxy_addr,
                    },
                ))
            },
        }
    }

    // ============= Startup Ping (test both IPv6 and IPv4) =============

    /// Ping all Telegram DCs through all upstreams.
    /// Tests BOTH IPv6 and IPv4, returns separate results for each.
    pub async fn ping_all_dcs(
        &self,
        _prefer_ipv6: bool,
        dc_overrides: &HashMap<String, Vec<String>>,
        ipv4_enabled: bool,
        ipv6_enabled: bool,
    ) -> Vec<StartupPingResult> {
        let upstreams: Vec<(usize, UpstreamConfig, Arc<AtomicUsize>)> = {
            let guard = self.upstreams.read().await;
            guard.iter().enumerate()
                .map(|(i, u)| (i, u.config.clone(), u.bind_rr.clone()))
                .collect()
        };

        let mut all_results = Vec::new();

        for (upstream_idx, upstream_config, bind_rr) in &upstreams {
            let upstream_name = match &upstream_config.upstream_type {
                UpstreamType::Direct {
                    interface,
                    bind_addresses,
                } => {
                    let mut direct_parts = Vec::new();
                    if let Some(dev) = interface.as_deref().filter(|v| !v.is_empty()) {
                        direct_parts.push(format!("dev={dev}"));
                    }
                    if let Some(src) = bind_addresses.as_ref().filter(|v| !v.is_empty()) {
                        direct_parts.push(format!("src={}", src.join(",")));
                    }
                    if direct_parts.is_empty() {
                        "direct".to_string()
                    } else {
                        format!("direct {}", direct_parts.join(" "))
                    }
                }
                UpstreamType::Socks4 { address, .. } => format!("socks4://{}", address),
                UpstreamType::Socks5 { address, .. } => format!("socks5://{}", address),
            };

            let mut v6_results = Vec::with_capacity(NUM_DCS);
            if ipv6_enabled {
                for dc_zero_idx in 0..NUM_DCS {
                    let dc_v6 = TG_DATACENTERS_V6[dc_zero_idx];
                    let addr_v6 = SocketAddr::new(dc_v6, TG_DATACENTER_PORT);

                    let result = tokio::time::timeout(
                        Duration::from_secs(DC_PING_TIMEOUT_SECS),
                        self.ping_single_dc(upstream_config, Some(bind_rr.clone()), addr_v6)
                    ).await;

                    let ping_result = match result {
                        Ok(Ok(rtt_ms)) => {
                            let mut guard = self.upstreams.write().await;
                            if let Some(u) = guard.get_mut(*upstream_idx) {
                                u.dc_latency[dc_zero_idx].update(rtt_ms);
                            }
                            DcPingResult {
                                dc_idx: dc_zero_idx + 1,
                                dc_addr: addr_v6,
                                rtt_ms: Some(rtt_ms),
                                error: None,
                            }
                        }
                        Ok(Err(e)) => DcPingResult {
                            dc_idx: dc_zero_idx + 1,
                            dc_addr: addr_v6,
                            rtt_ms: None,
                            error: Some(e.to_string()),
                        },
                        Err(_) => DcPingResult {
                            dc_idx: dc_zero_idx + 1,
                            dc_addr: addr_v6,
                            rtt_ms: None,
                            error: Some("timeout".to_string()),
                        },
                    };
                    v6_results.push(ping_result);
                }
            } else {
                for dc_zero_idx in 0..NUM_DCS {
                    let dc_v6 = TG_DATACENTERS_V6[dc_zero_idx];
                    v6_results.push(DcPingResult {
                        dc_idx: dc_zero_idx + 1,
                        dc_addr: SocketAddr::new(dc_v6, TG_DATACENTER_PORT),
                        rtt_ms: None,
                        error: Some("ipv6 disabled".to_string()),
                    });
                }
            }

            let mut v4_results = Vec::with_capacity(NUM_DCS);
            if ipv4_enabled {
                for dc_zero_idx in 0..NUM_DCS {
                    let dc_v4 = TG_DATACENTERS_V4[dc_zero_idx];
                    let addr_v4 = SocketAddr::new(dc_v4, TG_DATACENTER_PORT);

                    let result = tokio::time::timeout(
                        Duration::from_secs(DC_PING_TIMEOUT_SECS),
                        self.ping_single_dc(upstream_config, Some(bind_rr.clone()), addr_v4)
                    ).await;

                    let ping_result = match result {
                        Ok(Ok(rtt_ms)) => {
                            let mut guard = self.upstreams.write().await;
                            if let Some(u) = guard.get_mut(*upstream_idx) {
                                u.dc_latency[dc_zero_idx].update(rtt_ms);
                            }
                            DcPingResult {
                                dc_idx: dc_zero_idx + 1,
                                dc_addr: addr_v4,
                                rtt_ms: Some(rtt_ms),
                                error: None,
                            }
                        }
                        Ok(Err(e)) => DcPingResult {
                            dc_idx: dc_zero_idx + 1,
                            dc_addr: addr_v4,
                            rtt_ms: None,
                            error: Some(e.to_string()),
                        },
                        Err(_) => DcPingResult {
                            dc_idx: dc_zero_idx + 1,
                            dc_addr: addr_v4,
                            rtt_ms: None,
                            error: Some("timeout".to_string()),
                        },
                    };
                    v4_results.push(ping_result);
                }
            } else {
                for dc_zero_idx in 0..NUM_DCS {
                    let dc_v4 = TG_DATACENTERS_V4[dc_zero_idx];
                    v4_results.push(DcPingResult {
                        dc_idx: dc_zero_idx + 1,
                        dc_addr: SocketAddr::new(dc_v4, TG_DATACENTER_PORT),
                        rtt_ms: None,
                        error: Some("ipv4 disabled".to_string()),
                    });
                }
            }

            // === Ping DC overrides (v4/v6) ===
            for (dc_key, addrs) in dc_overrides {
                let dc_num: i16 = match dc_key.parse::<i16>() {
                    Ok(v) if v > 0 => v,
                    Err(_) => {
                        warn!(dc = %dc_key, "Invalid dc_overrides key, skipping");
                        continue;
                    },
                    _ => continue,
                };
                let dc_idx = dc_num as usize;
                for addr_str in addrs {
                    match addr_str.parse::<SocketAddr>() {
                        Ok(addr) => {
                            let is_v6 = addr.is_ipv6();
                            if (is_v6 && !ipv6_enabled) || (!is_v6 && !ipv4_enabled) {
                                continue;
                            }
                            let result = tokio::time::timeout(
                                Duration::from_secs(DC_PING_TIMEOUT_SECS),
                                self.ping_single_dc(upstream_config, Some(bind_rr.clone()), addr)
                            ).await;

                            let ping_result = match result {
                                Ok(Ok(rtt_ms)) => DcPingResult {
                                    dc_idx,
                                    dc_addr: addr,
                                    rtt_ms: Some(rtt_ms),
                                    error: None,
                                },
                                Ok(Err(e)) => DcPingResult {
                                    dc_idx,
                                    dc_addr: addr,
                                    rtt_ms: None,
                                    error: Some(e.to_string()),
                                },
                                Err(_) => DcPingResult {
                                    dc_idx,
                                    dc_addr: addr,
                                    rtt_ms: None,
                                    error: Some("timeout".to_string()),
                                },
                            };

                            if is_v6 {
                                v6_results.push(ping_result);
                            } else {
                                v4_results.push(ping_result);
                            }
                        }
                        Err(_) => warn!(dc = %dc_idx, addr = %addr_str, "Invalid dc_overrides address, skipping"),
                    }
                }
            }

            // Check if both IP versions have at least one working DC
            let v6_has_working = v6_results.iter().any(|r| r.rtt_ms.is_some());
            let v4_has_working = v4_results.iter().any(|r| r.rtt_ms.is_some());
            let both_available = v6_has_working && v4_has_working;

            // Update IP preference for each DC
            {
                let mut guard = self.upstreams.write().await;
                if let Some(u) = guard.get_mut(*upstream_idx) {
                    for dc_zero_idx in 0..NUM_DCS {
                        let v6_ok = v6_results[dc_zero_idx].rtt_ms.is_some();
                        let v4_ok = v4_results[dc_zero_idx].rtt_ms.is_some();

                        u.dc_ip_pref[dc_zero_idx] = match (v6_ok, v4_ok) {
                            (true, true) => IpPreference::BothWork,
                            (true, false) => IpPreference::PreferV6,
                            (false, true) => IpPreference::PreferV4,
                            (false, false) => IpPreference::Unavailable,
                        };
                    }
                }
            }

            all_results.push(StartupPingResult {
                v6_results,
                v4_results,
                upstream_name,
                both_available,
            });
        }

        all_results
    }

    async fn ping_single_dc(
        &self,
        config: &UpstreamConfig,
        bind_rr: Option<Arc<AtomicUsize>>,
        target: SocketAddr,
    ) -> Result<f64> {
        let start = Instant::now();
        let _ = self.connect_via_upstream(config, target, bind_rr).await?;
        Ok(start.elapsed().as_secs_f64() * 1000.0)
    }

    fn required_healthy_group_count(total_groups: usize) -> usize {
        if total_groups == 0 {
            0
        } else {
            total_groups.min(MIN_HEALTHY_DC_GROUPS)
        }
    }

    fn build_health_check_groups(
        prefer_ipv6: bool,
        ipv4_enabled: bool,
        ipv6_enabled: bool,
        dc_overrides: &HashMap<String, Vec<String>>,
    ) -> Vec<HealthCheckGroup> {
        let mut v4_by_dc: HashMap<i16, Vec<SocketAddr>> = HashMap::new();
        let mut v6_by_dc: HashMap<i16, Vec<SocketAddr>> = HashMap::new();

        if ipv4_enabled {
            for (idx, dc_ip) in TG_DATACENTERS_V4.iter().enumerate() {
                let dc_idx = (idx + 1) as i16;
                v4_by_dc
                    .entry(dc_idx)
                    .or_default()
                    .push(SocketAddr::new(*dc_ip, TG_DATACENTER_PORT));
            }
        }

        if ipv6_enabled {
            for (idx, dc_ip) in TG_DATACENTERS_V6.iter().enumerate() {
                let dc_idx = (idx + 1) as i16;
                v6_by_dc
                    .entry(dc_idx)
                    .or_default()
                    .push(SocketAddr::new(*dc_ip, TG_DATACENTER_PORT));
            }
        }

        for (dc_key, addrs) in dc_overrides {
            let dc_idx = match dc_key.parse::<i16>() {
                Ok(v) if v > 0 => v,
                _ => {
                    warn!(dc = %dc_key, "Invalid dc_overrides key for health-check, skipping");
                    continue;
                }
            };

            for addr_str in addrs {
                match addr_str.parse::<SocketAddr>() {
                    Ok(addr) if addr.is_ipv6() => {
                        if ipv6_enabled {
                            v6_by_dc.entry(dc_idx).or_default().push(addr);
                        }
                    }
                    Ok(addr) => {
                        if ipv4_enabled {
                            v4_by_dc.entry(dc_idx).or_default().push(addr);
                        }
                    }
                    Err(_) => {
                        warn!(
                            dc = %dc_idx,
                            addr = %addr_str,
                            "Invalid dc_overrides address for health-check, skipping"
                        );
                    }
                }
            }
        }

        for addrs in v4_by_dc.values_mut() {
            addrs.sort_unstable();
            addrs.dedup();
        }
        for addrs in v6_by_dc.values_mut() {
            addrs.sort_unstable();
            addrs.dedup();
        }

        let mut all_dcs = BTreeSet::new();
        all_dcs.extend(v4_by_dc.keys().copied());
        all_dcs.extend(v6_by_dc.keys().copied());

        let mut groups = Vec::with_capacity(all_dcs.len());
        for dc_idx in all_dcs {
            let v4_endpoints = v4_by_dc.remove(&dc_idx).unwrap_or_default();
            let v6_endpoints = v6_by_dc.remove(&dc_idx).unwrap_or_default();
            let (primary, fallback) = if prefer_ipv6 {
                (v6_endpoints, v4_endpoints)
            } else {
                (v4_endpoints, v6_endpoints)
            };

            if primary.is_empty() && fallback.is_empty() {
                continue;
            }

            groups.push(HealthCheckGroup {
                dc_idx,
                primary,
                fallback,
            });
        }

        groups
    }

    // ============= Health Checks =============

    /// Background health check based on reachable DC groups through each upstream.
    /// Upstream stays healthy while at least `MIN_HEALTHY_DC_GROUPS` groups are reachable.
    pub async fn run_health_checks(
        &self,
        prefer_ipv6: bool,
        ipv4_enabled: bool,
        ipv6_enabled: bool,
        dc_overrides: HashMap<String, Vec<String>>,
    ) {
        let groups = Self::build_health_check_groups(
            prefer_ipv6,
            ipv4_enabled,
            ipv6_enabled,
            &dc_overrides,
        );
        let required_healthy_groups = Self::required_healthy_group_count(groups.len());
        let mut endpoint_rotation: HashMap<(usize, i16, bool), usize> = HashMap::new();

        if groups.is_empty() {
            warn!("No DC groups available for upstream health-checks");
        }

        loop {
            tokio::time::sleep(Duration::from_secs(HEALTH_CHECK_INTERVAL_SECS)).await;

            if groups.is_empty() || required_healthy_groups == 0 {
                continue;
            }

            let count = self.upstreams.read().await.len();
            for i in 0..count {
                let (config, bind_rr) = {
                    let guard = self.upstreams.read().await;
                    let u = &guard[i];
                    (u.config.clone(), u.bind_rr.clone())
                };

                let mut healthy_groups = 0usize;
                let mut latency_updates: Vec<(usize, f64)> = Vec::new();

                for group in &groups {
                    let mut group_ok = false;
                    let mut group_rtt_ms = None;

                    for (is_primary, endpoints) in [(true, &group.primary), (false, &group.fallback)] {
                        if endpoints.is_empty() {
                            continue;
                        }

                        let rotation_key = (i, group.dc_idx, is_primary);
                        let start_idx = *endpoint_rotation.entry(rotation_key).or_insert(0) % endpoints.len();
                        let mut next_idx = (start_idx + 1) % endpoints.len();

                        for step in 0..endpoints.len() {
                            let endpoint_idx = (start_idx + step) % endpoints.len();
                            let endpoint = endpoints[endpoint_idx];

                            let start = Instant::now();
                            let result = tokio::time::timeout(
                                Duration::from_secs(HEALTH_CHECK_CONNECT_TIMEOUT_SECS),
                                self.connect_via_upstream(&config, endpoint, Some(bind_rr.clone())),
                            )
                            .await;

                            match result {
                                Ok(Ok(_stream)) => {
                                    group_ok = true;
                                    group_rtt_ms = Some(start.elapsed().as_secs_f64() * 1000.0);
                                    next_idx = (endpoint_idx + 1) % endpoints.len();
                                    break;
                                }
                                Ok(Err(e)) => {
                                    debug!(
                                        upstream = i,
                                        dc = group.dc_idx,
                                        endpoint = %endpoint,
                                        primary = is_primary,
                                        error = %e,
                                        "Health-check endpoint failed"
                                    );
                                }
                                Err(_) => {
                                    debug!(
                                        upstream = i,
                                        dc = group.dc_idx,
                                        endpoint = %endpoint,
                                        primary = is_primary,
                                        "Health-check endpoint timed out"
                                    );
                                }
                            }
                        }

                        endpoint_rotation.insert(rotation_key, next_idx);

                        if group_ok {
                            break;
                        }
                    }

                    if group_ok {
                        healthy_groups += 1;
                        if let (Some(dc_array_idx), Some(rtt_ms)) =
                            (UpstreamState::dc_array_idx(group.dc_idx), group_rtt_ms)
                        {
                            latency_updates.push((dc_array_idx, rtt_ms));
                        }
                    }
                }

                let mut guard = self.upstreams.write().await;
                let u = &mut guard[i];

                for (dc_array_idx, rtt_ms) in latency_updates {
                    u.dc_latency[dc_array_idx].update(rtt_ms);
                }

                if healthy_groups >= required_healthy_groups {
                    if !u.healthy {
                        info!(
                            upstream = i,
                            healthy_groups,
                            total_groups = groups.len(),
                            required_groups = required_healthy_groups,
                            "Upstream recovered by DC-group health threshold"
                        );
                    }
                    u.healthy = true;
                    u.fails = 0;
                } else {
                    u.fails += 1;
                    debug!(
                        upstream = i,
                        healthy_groups,
                        total_groups = groups.len(),
                        required_groups = required_healthy_groups,
                        fails = u.fails,
                        "Upstream health-check below DC-group threshold"
                    );
                    if u.fails >= self.unhealthy_fail_threshold {
                        u.healthy = false;
                        warn!(
                            upstream = i,
                            healthy_groups,
                            total_groups = groups.len(),
                            required_groups = required_healthy_groups,
                            fails = u.fails,
                            threshold = self.unhealthy_fail_threshold,
                            "Upstream unhealthy (insufficient reachable DC groups)"
                        );
                    }
                }

                u.last_check = std::time::Instant::now();
            }
        }
    }

    /// Get the preferred IP for a DC (for use by other components)
    #[allow(dead_code)]
    pub async fn get_dc_ip_preference(&self, dc_idx: i16) -> Option<IpPreference> {
        let guard = self.upstreams.read().await;
        if guard.is_empty() {
            return None;
        }

        UpstreamState::dc_array_idx(dc_idx)
            .map(|idx| guard[0].dc_ip_pref[idx])
    }

    /// Get preferred DC address based on config preference
    #[allow(dead_code)]
    pub async fn get_dc_addr(&self, dc_idx: i16, prefer_ipv6: bool) -> Option<SocketAddr> {
        let arr_idx = UpstreamState::dc_array_idx(dc_idx)?;

        let ip = if prefer_ipv6 {
            TG_DATACENTERS_V6[arr_idx]
        } else {
            TG_DATACENTERS_V4[arr_idx]
        };

        Some(SocketAddr::new(ip, TG_DATACENTER_PORT))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_healthy_group_count_applies_three_group_threshold() {
        assert_eq!(UpstreamManager::required_healthy_group_count(0), 0);
        assert_eq!(UpstreamManager::required_healthy_group_count(1), 1);
        assert_eq!(UpstreamManager::required_healthy_group_count(2), 2);
        assert_eq!(UpstreamManager::required_healthy_group_count(3), 3);
        assert_eq!(UpstreamManager::required_healthy_group_count(5), 3);
    }

    #[test]
    fn build_health_check_groups_merges_family_endpoints_with_preference() {
        let mut overrides = HashMap::new();
        overrides.insert(
            "2".to_string(),
            vec![
                "203.0.113.10:443".to_string(),
                "203.0.113.11:443".to_string(),
                "[2001:db8::10]:443".to_string(),
            ],
        );

        let groups = UpstreamManager::build_health_check_groups(true, true, true, &overrides);
        let dc2 = groups
            .iter()
            .find(|g| g.dc_idx == 2)
            .expect("dc2 must be present");

        assert!(dc2.primary.iter().all(|addr| addr.is_ipv6()));
        assert!(dc2.fallback.iter().all(|addr| addr.is_ipv4()));
        assert!(dc2
            .primary
            .contains(&"[2001:db8::10]:443".parse::<SocketAddr>().unwrap()));
        assert!(dc2
            .fallback
            .contains(&"203.0.113.10:443".parse::<SocketAddr>().unwrap()));
        assert!(dc2
            .fallback
            .contains(&"203.0.113.11:443".parse::<SocketAddr>().unwrap()));
    }

    #[test]
    fn build_health_check_groups_keeps_multiple_endpoints_per_group() {
        let mut overrides = HashMap::new();
        overrides.insert(
            "9".to_string(),
            vec![
                "198.51.100.1:443".to_string(),
                "198.51.100.2:443".to_string(),
                "198.51.100.1:443".to_string(),
            ],
        );

        let groups = UpstreamManager::build_health_check_groups(false, true, false, &overrides);
        let dc9 = groups
            .iter()
            .find(|g| g.dc_idx == 9)
            .expect("override-only dc group must be present");

        assert_eq!(dc9.primary.len(), 2);
        assert!(dc9
            .primary
            .contains(&"198.51.100.1:443".parse::<SocketAddr>().unwrap()));
        assert!(dc9
            .primary
            .contains(&"198.51.100.2:443".parse::<SocketAddr>().unwrap()));
        assert!(dc9.fallback.is_empty());
    }
}
