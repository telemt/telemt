//! Upstream Management with per-DC latency-weighted selection
//!
//! IPv6/IPv4 connectivity checks with configurable preference.

#![allow(deprecated)]

use rand::RngExt;
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::Instant;
use tracing::{debug, info, trace, warn};

use crate::config::{UpstreamConfig, UpstreamType};
use crate::error::{ProxyError, Result};
use crate::network::dns_overrides::{GenerationDnsResolver, split_host_port};
use crate::protocol::constants::{TG_DATACENTER_PORT, TG_DATACENTERS_V4, TG_DATACENTERS_V6};
use crate::stats::Stats;
use crate::transport::shadowsocks::{
    ShadowsocksStream, connect_shadowsocks, sanitize_shadowsocks_url,
};
use crate::transport::socket::{
    bind_outgoing_socket_to_device, create_outgoing_socket_bound, resolve_interface_ip,
};
use crate::transport::socks::{connect_socks4, connect_socks5};

/// Number of Telegram datacenters
const NUM_DCS: usize = 5;

/// Timeout for individual DC ping attempt
const DC_PING_TIMEOUT_SECS: u64 = 5;
/// Interval between upstream health-check cycles.
const HEALTH_CHECK_INTERVAL_SECS: u64 = 30;
/// Timeout for a single health-check connect attempt.
const HEALTH_CHECK_CONNECT_TIMEOUT_SECS: u64 = 10;
/// Upstream is considered healthy when at least this many DC groups are reachable.
const MIN_HEALTHY_DC_GROUPS: usize = 3;
const DNS_RESULT_MAX_ADDRESSES: usize = 64;

// ============= RTT Tracking =============

#[derive(Debug, Clone, Copy)]
struct LatencyEma {
    value_ms: Option<f64>,
    alpha: f64,
}

impl LatencyEma {
    const fn new(alpha: f64) -> Self {
        Self {
            value_ms: None,
            alpha,
        }
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

        let (sum, count) = self
            .dc_latency
            .iter()
            .filter_map(|l| l.get())
            .fold((0.0, 0u32), |(s, c), v| (s + v, c + 1));

        if count > 0 {
            Some(sum / count as f64)
        } else {
            None
        }
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
    pub prefer_ipv6: bool,
    /// True if both IPv6 and IPv4 have at least one working DC
    pub both_available: bool,
}

pub enum UpstreamStream {
    Tcp(TcpStream),
    Shadowsocks(Box<ShadowsocksStream>),
}

impl std::fmt::Debug for UpstreamStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(_) => f.write_str("UpstreamStream::Tcp(..)"),
            Self::Shadowsocks(_) => f.write_str("UpstreamStream::Shadowsocks(..)"),
        }
    }
}

impl UpstreamStream {
    pub fn into_tcp(self) -> Result<TcpStream> {
        match self {
            Self::Tcp(stream) => Ok(stream),
            Self::Shadowsocks(_) => Err(ProxyError::Config(
                "shadowsocks upstreams are not supported when general.use_middle_proxy = true"
                    .to_string(),
            )),
        }
    }
}

impl AsyncRead for UpstreamStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Shadowsocks(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Shadowsocks(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Shadowsocks(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Shadowsocks(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamRouteKind {
    Direct,
    Socks4,
    Socks5,
    Shadowsocks,
}

#[derive(Debug, Clone)]
pub struct UpstreamApiDcSnapshot {
    pub dc: i16,
    pub latency_ema_ms: Option<f64>,
    pub ip_preference: IpPreference,
}

#[derive(Debug, Clone)]
pub struct UpstreamApiItemSnapshot {
    pub upstream_id: usize,
    pub route_kind: UpstreamRouteKind,
    pub address: String,
    pub weight: u16,
    pub scopes: String,
    pub healthy: bool,
    pub fails: u32,
    pub last_check_age_secs: u64,
    pub effective_latency_ms: Option<f64>,
    pub dc: Vec<UpstreamApiDcSnapshot>,
}

#[derive(Debug, Clone, Default)]
pub struct UpstreamApiSummarySnapshot {
    pub configured_total: usize,
    pub healthy_total: usize,
    pub unhealthy_total: usize,
    pub direct_total: usize,
    pub socks4_total: usize,
    pub socks5_total: usize,
    pub shadowsocks_total: usize,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UpstreamApiHealthSummary {
    pub configured_total: usize,
    pub healthy_total: usize,
}

#[derive(Debug, Clone)]
pub struct UpstreamApiSnapshot {
    pub summary: UpstreamApiSummarySnapshot,
    pub upstreams: Vec<UpstreamApiItemSnapshot>,
}

#[derive(Debug, Clone, Copy)]
pub struct UpstreamApiPolicySnapshot {
    pub connect_retry_attempts: u32,
    pub connect_retry_backoff_ms: u64,
    pub connect_budget_ms: u64,
    pub unhealthy_fail_threshold: u32,
    pub connect_failfast_hard_errors: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamEgressInfo {
    pub upstream_id: usize,
    pub route_kind: UpstreamRouteKind,
    pub local_addr: Option<SocketAddr>,
    pub direct_bind_ip: Option<IpAddr>,
    pub socks_bound_addr: Option<SocketAddr>,
    pub socks_proxy_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
struct HealthCheckGroup {
    dc_idx: i16,
    v4_endpoints: Vec<SocketAddr>,
    v6_endpoints: Vec<SocketAddr>,
}

// ============= Upstream Manager =============

#[derive(Clone)]
pub struct UpstreamManager {
    upstreams: Arc<RwLock<Vec<UpstreamState>>>,
    connect_retry_attempts: u32,
    connect_retry_backoff: Duration,
    connect_budget: Duration,
    /// Per-attempt TCP connect timeout to Telegram DC (`[general] tg_connect`, seconds).
    tg_connect_timeout_secs: u64,
    unhealthy_fail_threshold: u32,
    connect_failfast_hard_errors: bool,
    no_upstreams_warn_epoch_ms: Arc<AtomicU64>,
    no_healthy_warn_epoch_ms: Arc<AtomicU64>,
    stats: Arc<Stats>,
    dns_resolver: Arc<GenerationDnsResolver>,
}

// Upstream manager configuration, DNS resolution, and API snapshots.
mod manager_config;
// Latency- and scope-aware upstream selection.
mod selection;
// Direct and proxied connection establishment.
mod connect;
// Startup Telegram DC connectivity probes.
mod startup_probe;
// Periodic upstream health checks.
mod health_checks;
#[cfg(test)]
mod tests;
