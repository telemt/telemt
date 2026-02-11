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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use dashmap::DashMap;
use tracing::{debug, info, trace};

use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::transport::UpstreamManager;
use crate::util::ip::IpInfo;

use super::config::MiddleProxyConfig;
use super::connection::HandshakedMiddleConnection;
use super::handshake::handshake_middle_proxy;

/// Maximum age of a pooled connection before it is discarded.
const MAX_CONN_AGE: Duration = Duration::from_secs(60);

/// Keep enough hot connections for parallel media uploads.
/// Telegram clients can open several concurrent MTProto sockets.
const TARGET_PER_DC: usize = 3;

/// Interval between replenish rounds.
const REPLENISH_INTERVAL: Duration = Duration::from_secs(5);

/// How long a DC stays "active" for background replenishment after last use.
const ACTIVE_DC_TTL: Duration = Duration::from_secs(30 * 60);

/// Timeout for creating a single pooled connection (handshake included).
const POOL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Small wait window to reuse a connection that is already being pre-created.
const EMPTY_POOL_WAIT_TOTAL: Duration = Duration::from_millis(2000);
const EMPTY_POOL_WAIT_STEP: Duration = Duration::from_millis(200); 

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
    /// Last successfully used middle-proxy endpoint per DC.
    /// Used to repeat successful routes first.
    last_success: DashMap<i32, SocketAddr>,
    /// Recently used DCs (last access timestamp).
    /// Replenishment runs only for active DCs to avoid warming every known DC.
    active_dcs: DashMap<i32, Instant>,
    /// In-flight pre-create tasks per DC.
    /// Prevents both underfill (sequential top-up) and uncontrolled dial storms.
    inflight: DashMap<i32, Arc<AtomicUsize>>,
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
            last_success: DashMap::new(),
            active_dcs: DashMap::new(),
            inflight: DashMap::new(),
        }
    }

    /// Get a pre-handshaked connection for the given DC, or create one on-demand.
    ///
    /// Tries the pool first. If empty or all expired, falls back to on-demand creation.
    pub async fn get_or_create(self: &Arc<Self>, dc_idx: i32) -> Result<HandshakedMiddleConnection> {
        self.mark_active_dc(dc_idx);

        // Try pool first
        if let Some(conn) = self.take_from_pool(dc_idx) {
            debug!(dc = dc_idx, "Reused pooled middle proxy connection");
            self.schedule_topup(dc_idx);
            return Ok(conn);
        }

        // Pool is empty: request top-up and briefly wait for in-flight preconnect.
        self.schedule_topup(dc_idx);
        if let Some(conn) = self.wait_for_inflight_connection(dc_idx).await {
            debug!(dc = dc_idx, "Obtained connection from in-flight top-up");
            self.schedule_topup(dc_idx);
            return Ok(conn);
        }

        // Pool empty — create on-demand
        debug!(dc = dc_idx, "Pool empty for DC, creating on-demand connection");
        let conn = self.create_connection(dc_idx).await?;
        // Replenish in background for the next burst.
        self.schedule_topup(dc_idx);
        Ok(conn)
    }

    fn mark_active_dc(&self, dc_idx: i32) {
        self.active_dcs.insert(dc_idx, Instant::now());
    }

    fn count_inflight(&self, dc_idx: i32) -> usize {
        self.inflight
            .get(&dc_idx)
            .map(|v| v.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    fn inflight_counter(&self, dc_idx: i32) -> Arc<AtomicUsize> {
        self.inflight
            .entry(dc_idx)
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone()
    }

    /// Ensure there are enough ready + in-flight pooled connections.
    ///
    /// Matching `mtprotoproxy.py` behavior, this schedules multiple concurrent
    /// pre-creates instead of serially waiting one-by-one.
    fn schedule_topup(self: &Arc<Self>, dc_idx: i32) {
        let counter = self.inflight_counter(dc_idx);

        loop {
            let live = self.count_live(dc_idx);
            let inflight = counter.load(Ordering::Acquire);
            let target_inflight = TARGET_PER_DC.saturating_sub(live);

            if inflight >= target_inflight {
                return;
            }

            let needed = target_inflight - inflight;
            if counter
                .compare_exchange(
                    inflight,
                    inflight + needed,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                continue;
            }

            for _ in 0..needed {
                let pool = Arc::clone(self);
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    pool.try_add_one(dc_idx).await;
                    counter.fetch_sub(1, Ordering::AcqRel);
                });
            }
            return;
        }
    }

    /// Briefly wait for one in-flight pooled connection to complete.
    async fn wait_for_inflight_connection(&self, dc_idx: i32) -> Option<HandshakedMiddleConnection> {
        if self.count_inflight(dc_idx) == 0 {
            return None;
        }

        let deadline = Instant::now() + EMPTY_POOL_WAIT_TOTAL;
        while Instant::now() < deadline {
            if let Some(conn) = self.take_from_pool(dc_idx) {
                return Some(conn);
            }
            if self.count_inflight(dc_idx) == 0 {
                break;
            }
            tokio::time::sleep(EMPTY_POOL_WAIT_STEP).await;
        }
        None
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
        const MAX_CONNECT_ATTEMPTS: usize = 2;

        let mut candidates: Vec<SocketAddr> = self
            .middle_config
            .get_middle_proxy_addrs(dc_idx, self.prefer_ipv6)
            .await
            .into_iter()
            .map(|(ip, port)| SocketAddr::new(ip, port))
            .collect();

        if candidates.is_empty() {
            return Err(ProxyError::Config(format!(
                "No middle proxy address for DC {}",
                dc_idx
            )));
        }

        let mut has_preferred = false;
        if let Some(preferred) = self.last_success.get(&dc_idx).map(|entry| *entry) {
            if let Some(pos) = candidates.iter().position(|addr| *addr == preferred) {
                candidates.swap(0, pos);
                has_preferred = true;
            }
        }

        if candidates.len() > 1 {
            let shuffle_from = if has_preferred { 1 } else { 0 };
            self.rng.shuffle(&mut candidates[shuffle_from..]);
        }

        if candidates.len() > MAX_CONNECT_ATTEMPTS {
            candidates.truncate(MAX_CONNECT_ATTEMPTS);
        }
        // When Telegram provides only one endpoint for a DC, retry it once
        // before failing (faster failover vs. long client-side stall).
        if candidates.len() == 1 {
            while candidates.len() < MAX_CONNECT_ATTEMPTS {
                candidates.push(candidates[0]);
            }
        }

        let total = candidates.len();
        let mut last_err: Option<ProxyError> = None;

        for (idx, mp_addr) in candidates.into_iter().enumerate() {
            debug!(
                dc = dc_idx,
                addr = %mp_addr,
                attempt = idx + 1,
                total_attempts = total,
                "Trying middle proxy candidate"
            );

            match self.create_connection_to_addr(dc_idx, mp_addr).await {
                Ok(conn) => {
                    self.last_success.insert(dc_idx, mp_addr);
                    return Ok(conn);
                }
                Err(e) => {
                    trace!(
                        dc = dc_idx,
                        addr = %mp_addr,
                        error = %e,
                        "Middle proxy candidate failed"
                    );
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            ProxyError::Config(format!("No reachable middle proxy for DC {}", dc_idx))
        }))
    }

    /// Create a connection to a specific middle-proxy address.
    async fn create_connection_to_addr(
        &self,
        dc_idx: i32,
        mp_addr: SocketAddr,
    ) -> Result<HandshakedMiddleConnection> {
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
        tokio::time::timeout(
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
        .map_err(|_| ProxyError::TgHandshakeTimeout)?
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

    fn cleanup_inactive_dcs(&self) {
        let now = Instant::now();
        let inactive: Vec<i32> = self
            .active_dcs
            .iter()
            .filter_map(|entry| {
                if now.duration_since(*entry.value()) > ACTIVE_DC_TTL {
                    Some(*entry.key())
                } else {
                    None
                }
            })
            .collect();

        for dc_idx in inactive {
            self.active_dcs.remove(&dc_idx);
            self.entries.remove(&dc_idx);
            self.inflight.remove(&dc_idx);
        }
    }

    // ============= Background Task =============

    /// Background loop: clean expired connections + replenish to target.
    ///
    /// Spawn with `tokio::spawn(pool.clone().run_replenish_loop())`.
    pub async fn run_replenish_loop(self: Arc<Self>) {
        // Give startup some time before background dialing.
        tokio::time::sleep(Duration::from_secs(10)).await;
        info!("Middle proxy pool: active-DC replenisher started");

        loop {
            tokio::time::sleep(REPLENISH_INTERVAL).await;
            self.cleanup_expired();
            self.cleanup_inactive_dcs();
            self.replenish_round();
        }
    }

    /// One replenish round: top up active DCs to TARGET_PER_DC.
    fn replenish_round(self: &Arc<Self>) {
        let dc_indices: Vec<i32> = self.active_dcs.iter().map(|entry| *entry.key()).collect();

        for dc_idx in dc_indices {
            self.schedule_topup(dc_idx);
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