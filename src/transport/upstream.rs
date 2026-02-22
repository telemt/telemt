//! Upstream Management with per-DC latency-weighted selection
//! 
//! IPv6/IPv4 connectivity checks with configurable preference.

use std::collections::HashMap;
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
use crate::protocol::constants::{TG_DATACENTERS_V4, TG_DATACENTERS_V6, TG_DATACENTER_PORT};
use crate::transport::socket::{create_outgoing_socket_bound, resolve_interface_ip};
use crate::transport::socks::{connect_socks4, connect_socks5};

/// Number of Telegram datacenters
const NUM_DCS: usize = 5;

/// Timeout for individual DC ping attempt
const DC_PING_TIMEOUT_SECS: u64 = 5;
/// Timeout for direct TG DC TCP connect readiness.
const DIRECT_CONNECT_TIMEOUT_SECS: u64 = 10;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpPreference {
    /// Not yet tested
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

impl Default for IpPreference {
    fn default() -> Self {
        Self::Unknown
    }
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
        if abs_dc >= 1 && abs_dc <= NUM_DCS {
            Some(abs_dc - 1)
        } else {
            // Unknown DC → default cluster (DC 2, index 1)
            Some(1)
        }
    }

    /// Get latency for a specific DC, falling back to average across all known DCs
    fn effective_latency(&self, dc_idx: Option<i16>) -> Option<f64> {
        if let Some(di) = dc_idx.and_then(Self::dc_array_idx) {
            if let Some(ms) = self.dc_latency[di].get() {
                return Some(ms);
            }
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

// ============= Upstream Manager =============

#[derive(Clone)]
pub struct UpstreamManager {
    upstreams: Arc<RwLock<Vec<UpstreamState>>>,
}

impl UpstreamManager {
    pub fn new(configs: Vec<UpstreamConfig>) -> Self {
        let states = configs.into_iter()
            .filter(|c| c.enabled)
            .map(UpstreamState::new)
            .collect();

        Self {
            upstreams: Arc::new(RwLock::new(states)),
        }
    }

    fn resolve_bind_address(
        interface: &Option<String>,
        bind_addresses: &Option<Vec<String>>,
        target: SocketAddr,
        rr: Option<&AtomicUsize>,
    ) -> Option<IpAddr> {
        let want_ipv6 = target.is_ipv6();

        if let Some(addrs) = bind_addresses {
            let candidates: Vec<IpAddr> = addrs
                .iter()
                .filter_map(|s| s.parse::<IpAddr>().ok())
                .filter(|ip| ip.is_ipv6() == want_ipv6)
                .collect();

            if !candidates.is_empty() {
                if let Some(counter) = rr {
                    let idx = counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
                    return Some(candidates[idx]);
                }
                return candidates.first().copied();
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

        let start = Instant::now();

        let bind_rr = {
            let guard = self.upstreams.read().await;
            guard.get(idx).map(|u| u.bind_rr.clone())
        };

        match self.connect_via_upstream(&upstream, target, bind_rr).await {
            Ok(stream) => {
                let rtt_ms = start.elapsed().as_secs_f64() * 1000.0;
                let mut guard = self.upstreams.write().await;
                if let Some(u) = guard.get_mut(idx) {
                    if !u.healthy {
                        debug!(rtt_ms = format!("{:.1}", rtt_ms), "Upstream recovered");
                    }
                    u.healthy = true;
                    u.fails = 0;

                    if let Some(di) = dc_idx.and_then(UpstreamState::dc_array_idx) {
                        u.dc_latency[di].update(rtt_ms);
                    }
                }
                Ok(stream)
            },
            Err(e) => {
                let mut guard = self.upstreams.write().await;
                if let Some(u) = guard.get_mut(idx) {
                    u.fails += 1;
                    warn!(fails = u.fails, "Upstream failed: {}", e);
                    if u.fails > 3 {
                        u.healthy = false;
                        warn!("Upstream marked unhealthy");
                    }
                }
                Err(e)
            }
        }
    }

    async fn connect_via_upstream(
        &self,
        config: &UpstreamConfig,
        target: SocketAddr,
        bind_rr: Option<Arc<AtomicUsize>>,
    ) -> Result<TcpStream> {
        match &config.upstream_type {
            UpstreamType::Direct { interface, bind_addresses } => {
                let bind_ip = Self::resolve_bind_address(
                    interface,
                    bind_addresses,
                    target,
                    bind_rr.as_deref(),
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

                Ok(stream)
            },
            UpstreamType::Socks4 { address, interface, user_id } => {
                // Try to parse as SocketAddr first (IP:port), otherwise treat as hostname:port
                let mut stream = if let Ok(proxy_addr) = address.parse::<SocketAddr>() {
                    // IP:port format - use socket with optional interface binding
                    let bind_ip = Self::resolve_bind_address(
                        interface,
                        &None,
                        proxy_addr,
                        bind_rr.as_deref(),
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

                    stream.writable().await?;
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
                    TcpStream::connect(address).await
                        .map_err(ProxyError::Io)?
                };

                // replace socks user_id with config.selected_scope, if set
                let scope: Option<&str> = Some(config.selected_scope.as_str())
                    .filter(|s| !s.is_empty());
                let _user_id: Option<&str> = scope.or(user_id.as_deref());

                connect_socks4(&mut stream, target, _user_id).await?;
                Ok(stream)
            },
            UpstreamType::Socks5 { address, interface, username, password } => {
                // Try to parse as SocketAddr first (IP:port), otherwise treat as hostname:port
                let mut stream = if let Ok(proxy_addr) = address.parse::<SocketAddr>() {
                    // IP:port format - use socket with optional interface binding
                    let bind_ip = Self::resolve_bind_address(
                        interface,
                        &None,
                        proxy_addr,
                        bind_rr.as_deref(),
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

                    stream.writable().await?;
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
                    TcpStream::connect(address).await
                        .map_err(ProxyError::Io)?
                };

                debug!(config = ?config, "Socks5 connection");
                // replace socks user:pass with config.selected_scope, if set
                let scope: Option<&str> = Some(config.selected_scope.as_str())
                    .filter(|s| !s.is_empty());
                let _username: Option<&str> = scope.or(username.as_deref());
                let _password: Option<&str> = scope.or(password.as_deref());

                connect_socks5(&mut stream, target, _username, _password).await?;
                Ok(stream)
            },
        }
    }

    // ============= Startup Ping (test both IPv6 and IPv4) =============

    /// Ping all Telegram DCs through all upstreams.
    /// Tests BOTH IPv6 and IPv4, returns separate results for each.
    pub async fn ping_all_dcs(
        &self,
        prefer_ipv6: bool,
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
                UpstreamType::Direct { interface, .. } => {
                    format!("direct{}", interface.as_ref().map(|i| format!(" ({})", i)).unwrap_or_default())
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
                        self.ping_single_dc(&upstream_config, Some(bind_rr.clone()), addr_v6)
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
                        self.ping_single_dc(&upstream_config, Some(bind_rr.clone()), addr_v4)
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
                                self.ping_single_dc(&upstream_config, Some(bind_rr.clone()), addr)
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
        let _stream = self.connect_via_upstream(config, target, bind_rr).await?;
        Ok(start.elapsed().as_secs_f64() * 1000.0)
    }

    // ============= Health Checks =============

    /// Background health check: rotates through DCs, 30s interval.
    /// Uses preferred IP version based on config.
    pub async fn run_health_checks(&self, prefer_ipv6: bool, ipv4_enabled: bool, ipv6_enabled: bool) {
        let mut dc_rotation = 0usize;

        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;

            let dc_zero_idx = dc_rotation % NUM_DCS;
            dc_rotation += 1;

            let primary_v6 = SocketAddr::new(TG_DATACENTERS_V6[dc_zero_idx], TG_DATACENTER_PORT);
            let primary_v4 = SocketAddr::new(TG_DATACENTERS_V4[dc_zero_idx], TG_DATACENTER_PORT);
            let dc_addr = if prefer_ipv6 && ipv6_enabled {
                primary_v6
            } else if ipv4_enabled {
                primary_v4
            } else if ipv6_enabled {
                primary_v6
            } else {
                continue;
            };

            let fallback_addr = if dc_addr.is_ipv6() && ipv4_enabled {
                Some(primary_v4)
            } else if dc_addr.is_ipv4() && ipv6_enabled {
                Some(primary_v6)
            } else {
                None
            };

            let count = self.upstreams.read().await.len();

            for i in 0..count {
                let (config, bind_rr) = {
                    let guard = self.upstreams.read().await;
                    let u = &guard[i];
                    (u.config.clone(), u.bind_rr.clone())
                };

                let start = Instant::now();
                let result = tokio::time::timeout(
                    Duration::from_secs(10),
                    self.connect_via_upstream(&config, dc_addr, Some(bind_rr.clone()))
                ).await;

                match result {
                    Ok(Ok(_stream)) => {
                        let rtt_ms = start.elapsed().as_secs_f64() * 1000.0;
                        let mut guard = self.upstreams.write().await;
                        let u = &mut guard[i];
                        u.dc_latency[dc_zero_idx].update(rtt_ms);

                        if !u.healthy {
                            info!(
                                rtt = format!("{:.0} ms", rtt_ms),
                                dc = dc_zero_idx + 1,
                                "Upstream recovered"
                            );
                        }
                        u.healthy = true;
                        u.fails = 0;
                        u.last_check = std::time::Instant::now();
                    }
                    Ok(Err(_)) | Err(_) => {
                        // Try fallback
                        debug!(dc = dc_zero_idx + 1, "Health check failed, trying fallback");

                        if let Some(fallback_addr) = fallback_addr {
                            let start2 = Instant::now();
                            let result2 = tokio::time::timeout(
                                Duration::from_secs(10),
                                self.connect_via_upstream(&config, fallback_addr, Some(bind_rr.clone()))
                            ).await;

                            let mut guard = self.upstreams.write().await;
                            let u = &mut guard[i];

                            match result2 {
                                Ok(Ok(_stream)) => {
                                    let rtt_ms = start2.elapsed().as_secs_f64() * 1000.0;
                                    u.dc_latency[dc_zero_idx].update(rtt_ms);

                                    if !u.healthy {
                                        info!(
                                            rtt = format!("{:.0} ms", rtt_ms),
                                            dc = dc_zero_idx + 1,
                                            "Upstream recovered (fallback)"
                                        );
                                    }
                                    u.healthy = true;
                                    u.fails = 0;
                                }
                                Ok(Err(e)) => {
                                    u.fails += 1;
                                    debug!(dc = dc_zero_idx + 1, fails = u.fails,
                                        "Health check failed (both): {}", e);
                                    if u.fails > 3 {
                                        u.healthy = false;
                                        warn!("Upstream unhealthy (fails)");
                                    }
                                }
                                Err(_) => {
                                    u.fails += 1;
                                    debug!(dc = dc_zero_idx + 1, fails = u.fails,
                                        "Health check timeout (both)");
                                    if u.fails > 3 {
                                        u.healthy = false;
                                        warn!("Upstream unhealthy (timeout)");
                                    }
                                }
                            }
                            u.last_check = std::time::Instant::now();
                            continue;
                        }

                        let mut guard = self.upstreams.write().await;
                        let u = &mut guard[i];
                        u.fails += 1;
                        if u.fails > 3 {
                            u.healthy = false;
                            warn!("Upstream unhealthy (no fallback family)");
                        }
                        u.last_check = std::time::Instant::now();
                    }
                }
            }
        }
    }

    /// Get the preferred IP for a DC (for use by other components)
    pub async fn get_dc_ip_preference(&self, dc_idx: i16) -> Option<IpPreference> {
        let guard = self.upstreams.read().await;
        if guard.is_empty() {
            return None;
        }

        UpstreamState::dc_array_idx(dc_idx)
            .map(|idx| guard[0].dc_ip_pref[idx])
    }

    /// Get preferred DC address based on config preference
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
