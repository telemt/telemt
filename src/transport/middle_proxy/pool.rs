use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
use bytes::BytesMut;
use rand::Rng;
use rand::seq::SliceRandom;
use tokio::sync::{Mutex, RwLock, mpsc, Notify};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use std::time::{Duration, Instant};

use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::network::probe::NetworkDecision;
use crate::network::IpFamily;
use crate::protocol::constants::*;

use super::ConnRegistry;
use super::registry::{BoundConn, ConnMeta};
use super::codec::{RpcWriter, WriterCommand};
use super::reader::reader_loop;
use super::MeResponse;
const ME_ACTIVE_PING_SECS: u64 = 25;
const ME_ACTIVE_PING_JITTER_SECS: i64 = 5;

#[derive(Clone)]
pub struct MeWriter {
    pub id: u64,
    pub addr: SocketAddr,
    pub tx: mpsc::Sender<WriterCommand>,
    pub cancel: CancellationToken,
    pub degraded: Arc<AtomicBool>,
    pub draining: Arc<AtomicBool>,
}

pub struct MePool {
    pub(super) registry: Arc<ConnRegistry>,
    pub(super) writers: Arc<RwLock<Vec<MeWriter>>>,
    pub(super) rr: AtomicU64,
    pub(super) decision: NetworkDecision,
    pub(super) rng: Arc<SecureRandom>,
    pub(super) proxy_tag: Option<Vec<u8>>,
    pub(super) proxy_secret: Arc<RwLock<Vec<u8>>>,
    pub(super) nat_ip_cfg: Option<IpAddr>,
    pub(super) nat_ip_detected: Arc<RwLock<Option<IpAddr>>>,
    pub(super) nat_probe: bool,
    pub(super) nat_stun: Option<String>,
    pub(super) nat_stun_servers: Vec<String>,
    pub(super) detected_ipv6: Option<Ipv6Addr>,
    pub(super) nat_probe_attempts: std::sync::atomic::AtomicU8,
    pub(super) nat_probe_disabled: std::sync::atomic::AtomicBool,
    pub(super) stun_backoff_until: Arc<RwLock<Option<Instant>>>,
    pub(super) me_one_retry: u8,
    pub(super) me_one_timeout: Duration,
    pub(super) me_keepalive_enabled: bool,
    pub(super) me_keepalive_interval: Duration,
    pub(super) me_keepalive_jitter: Duration,
    pub(super) me_keepalive_payload_random: bool,
    pub(super) me_warmup_stagger_enabled: bool,
    pub(super) me_warmup_step_delay: Duration,
    pub(super) me_warmup_step_jitter: Duration,
    pub(super) me_reconnect_max_concurrent_per_dc: u32,
    pub(super) me_reconnect_backoff_base: Duration,
    pub(super) me_reconnect_backoff_cap: Duration,
    pub(super) me_reconnect_fast_retry_count: u32,
    pub(super) proxy_map_v4: Arc<RwLock<HashMap<i32, Vec<(IpAddr, u16)>>>>,
    pub(super) proxy_map_v6: Arc<RwLock<HashMap<i32, Vec<(IpAddr, u16)>>>>,
    pub(super) default_dc: AtomicI32,
    pub(super) next_writer_id: AtomicU64,
    pub(super) ping_tracker: Arc<Mutex<HashMap<i64, (std::time::Instant, u64)>>>,
    pub(super) rtt_stats: Arc<Mutex<HashMap<u64, (f64, f64)>>>,
    pub(super) nat_reflection_cache: Arc<Mutex<NatReflectionCache>>,
    pub(super) writer_available: Arc<Notify>,
    pub(super) conn_count: AtomicUsize,
    pub(super) stats: Arc<crate::stats::Stats>,
    pool_size: usize,
}

#[derive(Debug, Default)]
pub struct NatReflectionCache {
    pub v4: Option<(std::time::Instant, std::net::SocketAddr)>,
    pub v6: Option<(std::time::Instant, std::net::SocketAddr)>,
}

impl MePool {
    pub fn new(
        proxy_tag: Option<Vec<u8>>,
        proxy_secret: Vec<u8>,
        nat_ip: Option<IpAddr>,
        nat_probe: bool,
        nat_stun: Option<String>,
        nat_stun_servers: Vec<String>,
        detected_ipv6: Option<Ipv6Addr>,
        me_one_retry: u8,
        me_one_timeout_ms: u64,
        proxy_map_v4: HashMap<i32, Vec<(IpAddr, u16)>>,
        proxy_map_v6: HashMap<i32, Vec<(IpAddr, u16)>>,
        default_dc: Option<i32>,
        decision: NetworkDecision,
        rng: Arc<SecureRandom>,
        stats: Arc<crate::stats::Stats>,
        me_keepalive_enabled: bool,
        me_keepalive_interval_secs: u64,
        me_keepalive_jitter_secs: u64,
        me_keepalive_payload_random: bool,
        me_warmup_stagger_enabled: bool,
        me_warmup_step_delay_ms: u64,
        me_warmup_step_jitter_ms: u64,
        me_reconnect_max_concurrent_per_dc: u32,
        me_reconnect_backoff_base_ms: u64,
        me_reconnect_backoff_cap_ms: u64,
        me_reconnect_fast_retry_count: u32,
    ) -> Arc<Self> {
        Arc::new(Self {
            registry: Arc::new(ConnRegistry::new()),
            writers: Arc::new(RwLock::new(Vec::new())),
            rr: AtomicU64::new(0),
            decision,
            rng,
            proxy_tag,
            proxy_secret: Arc::new(RwLock::new(proxy_secret)),
            nat_ip_cfg: nat_ip,
            nat_ip_detected: Arc::new(RwLock::new(None)),
            nat_probe,
            nat_stun,
            nat_stun_servers,
            detected_ipv6,
            nat_probe_attempts: std::sync::atomic::AtomicU8::new(0),
            nat_probe_disabled: std::sync::atomic::AtomicBool::new(false),
            stun_backoff_until: Arc::new(RwLock::new(None)),
            me_one_retry,
            me_one_timeout: Duration::from_millis(me_one_timeout_ms),
            stats,
            me_keepalive_enabled,
            me_keepalive_interval: Duration::from_secs(me_keepalive_interval_secs),
            me_keepalive_jitter: Duration::from_secs(me_keepalive_jitter_secs),
            me_keepalive_payload_random,
            me_warmup_stagger_enabled,
            me_warmup_step_delay: Duration::from_millis(me_warmup_step_delay_ms),
            me_warmup_step_jitter: Duration::from_millis(me_warmup_step_jitter_ms),
            me_reconnect_max_concurrent_per_dc,
            me_reconnect_backoff_base: Duration::from_millis(me_reconnect_backoff_base_ms),
            me_reconnect_backoff_cap: Duration::from_millis(me_reconnect_backoff_cap_ms),
            me_reconnect_fast_retry_count,
            pool_size: 2,
            proxy_map_v4: Arc::new(RwLock::new(proxy_map_v4)),
            proxy_map_v6: Arc::new(RwLock::new(proxy_map_v6)),
            default_dc: AtomicI32::new(default_dc.unwrap_or(0)),
            next_writer_id: AtomicU64::new(1),
            ping_tracker: Arc::new(Mutex::new(HashMap::new())),
            rtt_stats: Arc::new(Mutex::new(HashMap::new())),
            nat_reflection_cache: Arc::new(Mutex::new(NatReflectionCache::default())),
            writer_available: Arc::new(Notify::new()),
            conn_count: AtomicUsize::new(0),
        })
    }

    pub fn has_proxy_tag(&self) -> bool {
        self.proxy_tag.is_some()
    }

    pub fn reset_stun_state(&self) {
        self.nat_probe_attempts.store(0, Ordering::Relaxed);
        self.nat_probe_disabled.store(false, Ordering::Relaxed);
    }

    pub fn translate_our_addr(&self, addr: SocketAddr) -> SocketAddr {
        let ip = self.translate_ip_for_nat(addr.ip());
        SocketAddr::new(ip, addr.port())
    }

    pub fn registry(&self) -> &Arc<ConnRegistry> {
        &self.registry
    }

    fn writers_arc(&self) -> Arc<RwLock<Vec<MeWriter>>> {
        self.writers.clone()
    }

    pub async fn reconcile_connections(self: &Arc<Self>, rng: &SecureRandom) {
        use std::collections::HashSet;
        let writers = self.writers.read().await;
        let current: HashSet<SocketAddr> = writers
            .iter()
            .filter(|w| !w.draining.load(Ordering::Relaxed))
            .map(|w| w.addr)
            .collect();
        drop(writers);

        for family in self.family_order() {
            let map = self.proxy_map_for_family(family).await;
            for (_dc, addrs) in map.iter() {
                let dc_addrs: Vec<SocketAddr> = addrs
                    .iter()
                    .map(|(ip, port)| SocketAddr::new(*ip, *port))
                    .collect();
                if !dc_addrs.iter().any(|a| current.contains(a)) {
                    let mut shuffled = dc_addrs.clone();
                    shuffled.shuffle(&mut rand::rng());
                    for addr in shuffled {
                        if self.connect_one(addr, rng).await.is_ok() {
                            break;
                        }
                    }
                }
            }
            if !self.decision.effective_multipath && !current.is_empty() {
                break;
            }
        }
    }

    pub async fn update_proxy_maps(
        &self,
        new_v4: HashMap<i32, Vec<(IpAddr, u16)>>,
        new_v6: Option<HashMap<i32, Vec<(IpAddr, u16)>>>,
    ) -> bool {
        let mut changed = false;
        {
            let mut guard = self.proxy_map_v4.write().await;
            if !new_v4.is_empty() && *guard != new_v4 {
                *guard = new_v4;
                changed = true;
            }
        }
        if let Some(v6) = new_v6 {
            let mut guard = self.proxy_map_v6.write().await;
            if !v6.is_empty() && *guard != v6 {
                *guard = v6;
                changed = true;
            }
        }
        // Ensure negative DC entries mirror positives when absent (Telegram convention).
        {
            let mut guard = self.proxy_map_v4.write().await;
            let keys: Vec<i32> = guard.keys().cloned().collect();
            for k in keys.iter().cloned().filter(|k| *k > 0) {
                if !guard.contains_key(&-k) {
                    if let Some(addrs) = guard.get(&k).cloned() {
                        guard.insert(-k, addrs);
                    }
                }
            }
        }
        {
            let mut guard = self.proxy_map_v6.write().await;
            let keys: Vec<i32> = guard.keys().cloned().collect();
            for k in keys.iter().cloned().filter(|k| *k > 0) {
                if !guard.contains_key(&-k) {
                    if let Some(addrs) = guard.get(&k).cloned() {
                        guard.insert(-k, addrs);
                    }
                }
            }
        }
        changed
    }

    pub async fn update_secret(self: &Arc<Self>, new_secret: Vec<u8>) -> bool {
        if new_secret.len() < 32 {
            warn!(len = new_secret.len(), "proxy-secret update ignored (too short)");
            return false;
        }
        let mut guard = self.proxy_secret.write().await;
        if *guard != new_secret {
            *guard = new_secret;
            drop(guard);
            self.reconnect_all().await;
            return true;
        }
        false
    }

    pub async fn reconnect_all(self: &Arc<Self>) {
        let ws = self.writers.read().await.clone();
        for w in ws {
            if let Ok(()) = self.connect_one(w.addr, self.rng.as_ref()).await {
                self.mark_writer_draining(w.id).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }

    pub(super) async fn key_selector(&self) -> u32 {
        let secret = self.proxy_secret.read().await;
        if secret.len() >= 4 {
            u32::from_le_bytes([secret[0], secret[1], secret[2], secret[3]])
        } else {
            0
        }
    }

    pub(super) fn family_order(&self) -> Vec<IpFamily> {
        let mut order = Vec::new();
        if self.decision.prefer_ipv6() {
            if self.decision.ipv6_me {
                order.push(IpFamily::V6);
            }
            if self.decision.ipv4_me {
                order.push(IpFamily::V4);
            }
        } else {
            if self.decision.ipv4_me {
                order.push(IpFamily::V4);
            }
            if self.decision.ipv6_me {
                order.push(IpFamily::V6);
            }
        }
        order
    }

    async fn proxy_map_for_family(&self, family: IpFamily) -> HashMap<i32, Vec<(IpAddr, u16)>> {
        match family {
            IpFamily::V4 => self.proxy_map_v4.read().await.clone(),
            IpFamily::V6 => self.proxy_map_v6.read().await.clone(),
        }
    }

    pub async fn init(self: &Arc<Self>, pool_size: usize, rng: &Arc<SecureRandom>) -> Result<()> {
        let family_order = self.family_order();
        let ks = self.key_selector().await;
        info!(
            me_servers = self.proxy_map_v4.read().await.len(),
            pool_size,
            key_selector = format_args!("0x{ks:08x}"),
            secret_len = self.proxy_secret.read().await.len(),
            "Initializing ME pool"
        );

        for family in family_order {
            let map = self.proxy_map_for_family(family).await;
            let dc_addrs: Vec<(i32, Vec<(IpAddr, u16)>)> = map
                .iter()
                .map(|(dc, addrs)| (*dc, addrs.clone()))
                .collect();

            // Ensure at least one connection per DC; run DCs in parallel.
            let mut join = tokio::task::JoinSet::new();
            let mut dc_failures = 0usize;
            for (dc, addrs) in dc_addrs.iter().cloned() {
                if addrs.is_empty() {
                    continue;
                }
                let pool = Arc::clone(self);
                let rng_clone = Arc::clone(rng);
                join.spawn(async move {
                    pool.connect_primary_for_dc(dc, addrs, rng_clone).await
                });
            }
            while let Some(res) = join.join_next().await {
                if let Ok(false) = res {
                    dc_failures += 1;
                }
            }
            if dc_failures > 2 {
                return Err(ProxyError::Proxy("Too many ME DC init failures, falling back to direct".into()));
            }

        // Additional connections up to pool_size total (round-robin across DCs), staggered to de-phase lifecycles.
        if self.me_warmup_stagger_enabled {
            for (dc, addrs) in dc_addrs.iter() {
                for (ip, port) in addrs {
                    if self.connection_count() >= pool_size {
                        break;
                    }
                    let addr = SocketAddr::new(*ip, *port);
                    let jitter = rand::rng().random_range(0..=self.me_warmup_step_jitter.as_millis() as u64);
                    let delay_ms = self.me_warmup_step_delay.as_millis() as u64 + jitter;
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    if let Err(e) = self.connect_one(addr, rng.as_ref()).await {
                        debug!(%addr, dc = %dc, error = %e, "Extra ME connect failed (staggered)");
                    }
                }
            }
        } else {
            for (dc, addrs) in dc_addrs.iter() {
                for (ip, port) in addrs {
                    if self.connection_count() >= pool_size {
                        break;
                    }
                    let addr = SocketAddr::new(*ip, *port);
                    if let Err(e) = self.connect_one(addr, rng.as_ref()).await {
                        debug!(%addr, dc = %dc, error = %e, "Extra ME connect failed");
                    }
                }
                if self.connection_count() >= pool_size {
                    break;
                }
            }
        }

            if !self.decision.effective_multipath && self.connection_count() > 0 {
                break;
            }
        }

        if self.writers.read().await.is_empty() {
            return Err(ProxyError::Proxy("No ME connections".into()));
        }
        Ok(())
    }

    pub(crate) async fn connect_one(self: &Arc<Self>, addr: SocketAddr, rng: &SecureRandom) -> Result<()> {
        let secret_len = self.proxy_secret.read().await.len();
        if secret_len < 32 {
            return Err(ProxyError::Proxy("proxy-secret too short for ME auth".into()));
        }

        let (stream, _connect_ms) = self.connect_tcp(addr).await?;
        let hs = self.handshake_only(stream, addr, rng).await?;

        let writer_id = self.next_writer_id.fetch_add(1, Ordering::Relaxed);
        let cancel = CancellationToken::new();
        let degraded = Arc::new(AtomicBool::new(false));
        let draining = Arc::new(AtomicBool::new(false));
        let (tx, mut rx) = mpsc::channel::<WriterCommand>(4096);
        let tx_for_keepalive = tx.clone();
        let stats = self.stats.clone();
        let mut rpc_writer = RpcWriter {
            writer: hs.wr,
            key: hs.write_key,
            iv: hs.write_iv,
            seq_no: 0,
        };
        let cancel_wr = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    cmd = rx.recv() => {
                        match cmd {
                            Some(WriterCommand::Data(payload)) => {
                                if rpc_writer.send(&payload).await.is_err() { break; }
                            }
                            Some(WriterCommand::DataAndFlush(payload)) => {
                                if rpc_writer.send_and_flush(&payload).await.is_err() { break; }
                            }
                            Some(WriterCommand::Keepalive) => {
                                match rpc_writer.send_keepalive().await {
                                    Ok(()) => {
                                        stats.increment_me_keepalive_sent();
                                    }
                                    Err(_) => {
                                        stats.increment_me_keepalive_failed();
                                        break;
                                    }
                                }
                            }
                            Some(WriterCommand::Close) | None => break,
                        }
                    }
                    _ = cancel_wr.cancelled() => break,
                }
            }
        });
        let writer = MeWriter {
            id: writer_id,
            addr,
            tx: tx.clone(),
            cancel: cancel.clone(),
            degraded: degraded.clone(),
            draining: draining.clone(),
        };
        self.writers.write().await.push(writer.clone());
        self.conn_count.fetch_add(1, Ordering::Relaxed);
        self.writer_available.notify_waiters();

        let reg = self.registry.clone();
        let writers_arc = self.writers_arc();
        let ping_tracker = self.ping_tracker.clone();
        let rtt_stats = self.rtt_stats.clone();
        let pool = Arc::downgrade(self);
        let cancel_ping = cancel.clone();
        let tx_ping = tx.clone();
        let ping_tracker_ping = ping_tracker.clone();
        let cleanup_done = Arc::new(AtomicBool::new(false));
        let cleanup_for_reader = cleanup_done.clone();
        let cleanup_for_ping = cleanup_done.clone();
        let keepalive_enabled = self.me_keepalive_enabled;
        let keepalive_interval = self.me_keepalive_interval;
        let keepalive_jitter = self.me_keepalive_jitter;
        let cancel_reader_token = cancel.clone();
        let cancel_ping_token = cancel_ping.clone();
        let cancel_keepalive_token = cancel.clone();

        tokio::spawn(async move {
            let res = reader_loop(
                hs.rd,
                hs.read_key,
                hs.read_iv,
                reg.clone(),
                BytesMut::new(),
                BytesMut::new(),
                tx.clone(),
                ping_tracker.clone(),
                rtt_stats.clone(),
                writer_id,
                degraded.clone(),
                cancel_reader_token.clone(),
            )
            .await;
            if let Some(pool) = pool.upgrade() {
                if cleanup_for_reader
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
                {
                    pool.remove_writer_and_close_clients(writer_id).await;
                }
            }
            if let Err(e) = res {
                warn!(error = %e, "ME reader ended");
            }
            let mut ws = writers_arc.write().await;
            ws.retain(|w| w.id != writer_id);
            info!(remaining = ws.len(), "Dead ME writer removed from pool");
        });

        let pool_ping = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut ping_id: i64 = rand::random::<i64>();
            loop {
                let jitter = rand::rng()
                    .random_range(-ME_ACTIVE_PING_JITTER_SECS..=ME_ACTIVE_PING_JITTER_SECS);
                let wait = (ME_ACTIVE_PING_SECS as i64 + jitter).max(5) as u64;
                tokio::select! {
                    _ = cancel_ping_token.cancelled() => {
                        break;
                    }
                    _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
                }
                let sent_id = ping_id;
                let mut p = Vec::with_capacity(12);
                p.extend_from_slice(&RPC_PING_U32.to_le_bytes());
                p.extend_from_slice(&sent_id.to_le_bytes());
                {
                    let mut tracker = ping_tracker_ping.lock().await;
                    tracker.retain(|_, (ts, _)| ts.elapsed() < Duration::from_secs(120));
                    tracker.insert(sent_id, (std::time::Instant::now(), writer_id));
                }
                ping_id = ping_id.wrapping_add(1);
                if tx_ping.send(WriterCommand::DataAndFlush(p)).await.is_err() {
                    debug!("Active ME ping failed, removing dead writer");
                    cancel_ping.cancel();
                    if let Some(pool) = pool_ping.upgrade() {
                        if cleanup_for_ping
                            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                            .is_ok()
                        {
                            pool.remove_writer_and_close_clients(writer_id).await;
                        }
                    }
                    break;
                }
            }
        });

        if keepalive_enabled {
            let tx_keepalive = tx_for_keepalive;
            let cancel_keepalive = cancel_keepalive_token;
            tokio::spawn(async move {
                // Per-writer jittered start to avoid phase sync.
                let jitter_cap_ms = keepalive_interval.as_millis() / 2;
                let effective_jitter_ms = keepalive_jitter.as_millis().min(jitter_cap_ms).max(1);
                let initial_jitter_ms = rand::rng().random_range(0..=effective_jitter_ms as u64);
                tokio::time::sleep(Duration::from_millis(initial_jitter_ms)).await;
                loop {
                    tokio::select! {
                        _ = cancel_keepalive.cancelled() => break,
                        _ = tokio::time::sleep(keepalive_interval + Duration::from_millis(rand::rng().random_range(0..=effective_jitter_ms as u64))) => {}
                    }
                    if tx_keepalive.send(WriterCommand::Keepalive).await.is_err() {
                        break;
                    }
                }
            });
        }

        Ok(())
    }

    async fn connect_primary_for_dc(
        self: Arc<Self>,
        dc: i32,
        mut addrs: Vec<(IpAddr, u16)>,
        rng: Arc<SecureRandom>,
    ) -> bool {
        if addrs.is_empty() {
            return false;
        }
        addrs.shuffle(&mut rand::rng());
        for (ip, port) in addrs {
            let addr = SocketAddr::new(ip, port);
            match self.connect_one(addr, rng.as_ref()).await {
                Ok(()) => {
                    info!(%addr, dc = %dc, "ME connected");
                    return true;
                }
                Err(e) => warn!(%addr, dc = %dc, error = %e, "ME connect failed, trying next"),
            }
        }
        warn!(dc = %dc, "All ME servers for DC failed at init");
        false
    }

    pub(crate) async fn remove_writer_and_close_clients(self: &Arc<Self>, writer_id: u64) {
        let conns = self.remove_writer_only(writer_id).await;
        for bound in conns {
            let _ = self.registry.route(bound.conn_id, super::MeResponse::Close).await;
            let _ = self.registry.unregister(bound.conn_id).await;
        }
    }

    async fn remove_writer_only(&self, writer_id: u64) -> Vec<BoundConn> {
        {
            let mut ws = self.writers.write().await;
            if let Some(pos) = ws.iter().position(|w| w.id == writer_id) {
                let w = ws.remove(pos);
                w.cancel.cancel();
                let _ = w.tx.send(WriterCommand::Close).await;
                self.conn_count.fetch_sub(1, Ordering::Relaxed);
            }
        }
        self.rtt_stats.lock().await.remove(&writer_id);
        self.registry.writer_lost(writer_id).await
    }

    pub(crate) async fn mark_writer_draining(self: &Arc<Self>, writer_id: u64) {
        {
            let mut ws = self.writers.write().await;
            if let Some(w) = ws.iter_mut().find(|w| w.id == writer_id) {
                w.draining.store(true, Ordering::Relaxed);
            }
        }

        let pool = Arc::downgrade(self);
        tokio::spawn(async move {
            let deadline = Instant::now() + Duration::from_secs(300);
            loop {
                if let Some(p) = pool.upgrade() {
                    if Instant::now() >= deadline {
                        warn!(writer_id, "Drain timeout, force-closing");
                        let _ = p.remove_writer_and_close_clients(writer_id).await;
                        break;
                    }
                    if p.registry.is_writer_empty(writer_id).await {
                        let _ = p.remove_writer_only(writer_id).await;
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                } else {
                    break;
                }
            }
        });
    }

}

fn hex_dump(data: &[u8]) -> String {
    const MAX: usize = 64;
    let mut out = String::with_capacity(data.len() * 2 + 3);
    for (i, b) in data.iter().take(MAX).enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{b:02x}"));
    }
    if data.len() > MAX {
        out.push_str(" …");
    }
    out
}
