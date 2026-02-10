//! Pre-handshaked connection pool for Middle Proxy
//!
//! Maintains a small pool of already-handshaked connections per DC index
//! so that client connections can be served without handshake latency
//! (target: < 2 second connect time).
//!
//! - Connections idle for more than [`MAX_CONN_AGE`] are discarded.
//! - A background task replenishes the pool every [`REPLENISH_INTERVAL`].
//! - On-demand fallback when pool is empty.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use tracing::{debug, info, warn, trace};

use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::transport::UpstreamManager;
use crate::util::ip::IpInfo;

use super::config::MiddleProxyConfig;
use super::connection::HandshakedMiddleConnection;
use super::handshake::handshake_middle_proxy;

/// Maximum age of a pooled connection before it is discarded
const MAX_CONN_AGE: Duration = Duration::from_secs(120);

/// Target number of pre-handshaked connections per DC index
const TARGET_PER_DC: usize = 2;

/// Interval between replenish rounds
const REPLENISH_INTERVAL: Duration = Duration::from_secs(30);

/// Timeout for creating a single pooled connection (handshake included)
const POOL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

// ============= Pool Entry =============

struct PoolEntry {
    conn: HandshakedMiddleConnection,
    created_at: Instant,
}

impl PoolEntry {
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > MAX_CONN_AGE
    }
}

// ============= MiddleProxyPool =============

/// Connection pool for pre-handshaked middle proxy connections.
///
/// Thread-safe: uses [`DashMap`] for lock-free concurrent access.
pub struct MiddleProxyPool {
    /// Pooled connections per DC index
    entries: DashMap<i32, VecDeque<PoolEntry>>,
    /// Runtime middle proxy configuration (secret, DC lists)
    middle_config: Arc<MiddleProxyConfig>,
    /// Upstream manager for TCP connections
    upstream_manager: Arc<UpstreamManager>,
    /// Detected public IPs (for KDF)
    ip_info: Arc<IpInfo>,
    /// Secure RNG
    rng: Arc<SecureRandom>,
    /// IPv6 preference
    prefer_ipv6: bool,
}

impl MiddleProxyPool {
    /// Create a new pool.
    pub fn new(
        middle_config: Arc<MiddleProxyConfig>,
        upstream_manager: Arc<UpstreamManager>,
        ip_info: Arc<IpInfo>,
        rng: Arc<SecureRandom>,
        prefer_ipv6: bool,
    ) -> Self {
        Self {
            entries: DashMap::new(),
            middle_config,
            upstream_manager,
            ip_info,
            rng,
            prefer_ipv6,
        }
    }

    /// Get a pre-handshaked connection for the given DC, or create one on-demand.
    ///
    /// Tries the pool first. If empty or all expired, falls back to on-demand creation.
    pub async fn get_or_create(&self, dc_idx: i32) -> Result<HandshakedMiddleConnection> {
        // Try pool first
        if let Some(conn) = self.take_from_pool(dc_idx) {
            debug!(dc = dc_idx, "Reused pooled middle proxy connection");
            return Ok(conn);
        }

        // Pool empty — create on-demand
        debug!(dc = dc_idx, "Pool empty for DC, creating on-demand connection");
        self.create_connection(dc_idx).await
    }

    /// Take a non-expired connection from the pool for the given DC.
    fn take_from_pool(&self, dc_idx: i32) -> Option<HandshakedMiddleConnection> {
        let mut queue = self.entries.entry(dc_idx).or_default();
        while let Some(entry) = queue.pop_front() {
            if !entry.is_expired() {
                return Some(entry.conn);
            }
            trace!(dc = dc_idx, "Discarded expired pooled connection");
        }
        None
    }

    /// Count non-expired connections for a DC.
    fn count_live(&self, dc_idx: i32) -> usize {
        self.entries
            .get(&dc_idx)
            .map(|queue| queue.iter().filter(|e| !e.is_expired()).count())
            .unwrap_or(0)
    }

    /// Create a fresh connection to the middle proxy for the given DC.
    ///
    /// Includes TCP connect + full nonce/KDF/CBC handshake.
    async fn create_connection(&self, dc_idx: i32) -> Result<HandshakedMiddleConnection> {
        // Pick a middle proxy address
        let (mp_ip, mp_port) = self.middle_config
            .get_middle_proxy_addr(dc_idx, self.prefer_ipv6, &self.rng)
            .await
            .ok_or_else(|| ProxyError::Config(
                format!("No middle proxy address for DC {}", dc_idx),
            ))?;

        let mp_addr = SocketAddr::new(mp_ip, mp_port);

        // TCP connect with timeout
        let tcp_stream = tokio::time::timeout(
            POOL_HANDSHAKE_TIMEOUT,
            self.upstream_manager.connect(mp_addr, Some(dc_idx as i16)),
        )
        .await
        .map_err(|_| ProxyError::ConnectionTimeout {
            addr: mp_addr.to_string(),
        })??;

        // Middle proxy handshake with timeout
        let proxy_secret = self.middle_config.get_proxy_secret().await;

        let handshaked_conn = tokio::time::timeout(
            POOL_HANDSHAKE_TIMEOUT,
            handshake_middle_proxy(
                tcp_stream,
                &proxy_secret,
                &self.ip_info,
                self.prefer_ipv6,
                &self.rng,
            ),
        )
        .await
        .map_err(|_| ProxyError::TgHandshakeTimeout)??;

        Ok(handshaked_conn)
    }

    /// Try to add one connection to the pool for a DC (best-effort, no error propagation).
    async fn try_add_one(&self, dc_idx: i32) {
        match self.create_connection(dc_idx).await {
            Ok(conn) => {
                let mut queue = self.entries.entry(dc_idx).or_default();
                queue.push_back(PoolEntry {
                    conn,
                    created_at: Instant::now(),
                });
                trace!(dc = dc_idx, pool_size = queue.len(), "Added connection to pool");
            }
            Err(e) => {
                trace!(dc = dc_idx, error = %e, "Failed to pre-create pooled connection");
            }
        }
    }

    /// Evict all expired entries across all DCs.
    fn cleanup_expired(&self) {
        for mut entry in self.entries.iter_mut() {
            let before = entry.value().len();
            entry.value_mut().retain(|e| !e.is_expired());
            let removed = before - entry.value().len();
            if removed > 0 {
                trace!(dc = *entry.key(), removed = removed, "Cleaned expired pool entries");
            }
        }
    }

    // ============= Background Task =============

    /// Background loop: clean expired connections + replenish to target.
    ///
    /// Spawn with `tokio::spawn(pool.clone().run_replenish_loop())`.
    pub async fn run_replenish_loop(self: Arc<Self>) {
        // Initial warm-up delay
        tokio::time::sleep(Duration::from_secs(10)).await;
        info!("Middle proxy pool: initial warm-up starting");
        self.replenish_round().await;

        loop {
            tokio::time::sleep(REPLENISH_INTERVAL).await;
            self.cleanup_expired();
            self.replenish_round().await;
        }
    }

    /// One replenish round: top up all known DCs to TARGET_PER_DC.
    async fn replenish_round(&self) {
        let dc_indices = self.middle_config.known_dc_indices().await;

        for dc_idx in dc_indices {
            let current = self.count_live(dc_idx);
            if current < TARGET_PER_DC {
                let needed = TARGET_PER_DC - current;
                for _ in 0..needed {
                    self.try_add_one(dc_idx).await;
                }
            }
        }
    }

    /// Get pool statistics snapshot for logging/metrics.
    pub fn stats(&self) -> PoolStats {
        let mut total = 0;
        let mut by_dc = Vec::new();
        for entry in self.entries.iter() {
            let live = entry.value().iter().filter(|e| !e.is_expired()).count();
            total += live;
            by_dc.push((*entry.key(), live));
        }
        by_dc.sort_by_key(|(dc, _)| *dc);
        PoolStats { total, by_dc }
    }
}

/// Pool statistics snapshot.
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total: usize,
    pub by_dc: Vec<(i32, usize)>,
}

impl std::fmt::Display for PoolStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "total={}", self.total)?;
        for (dc, n) in &self.by_dc {
            write!(f, " DC{}={}", dc, n)?;
        }
        Ok(())
    }
}