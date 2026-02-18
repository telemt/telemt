use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use bytes::BytesMut;
use rand::Rng;
use rand::seq::SliceRandom;
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use std::time::Duration;

use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::network::probe::NetworkDecision;
use crate::network::IpFamily;
use crate::protocol::constants::*;

use super::ConnRegistry;
use super::registry::{BoundConn, ConnMeta};
use super::codec::RpcWriter;
use super::reader::reader_loop;
use super::MeResponse;

const ME_ACTIVE_PING_SECS: u64 = 25;
const ME_ACTIVE_PING_JITTER_SECS: i64 = 5;

#[derive(Clone)]
pub struct MeWriter {
    pub id: u64,
    pub addr: SocketAddr,
    pub writer: Arc<Mutex<RpcWriter>>,
    pub cancel: CancellationToken,
    pub degraded: Arc<AtomicBool>,
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
    pub(super) proxy_map_v4: Arc<RwLock<HashMap<i32, Vec<(IpAddr, u16)>>>>,
    pub(super) proxy_map_v6: Arc<RwLock<HashMap<i32, Vec<(IpAddr, u16)>>>>,
    pub(super) default_dc: AtomicI32,
    pub(super) next_writer_id: AtomicU64,
    pub(super) ping_tracker: Arc<Mutex<HashMap<i64, (std::time::Instant, u64)>>>,
    pub(super) rtt_stats: Arc<Mutex<HashMap<u64, (f64, f64)>>>,
    pub(super) nat_reflection_cache: Arc<Mutex<NatReflectionCache>>,
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
        proxy_map_v4: HashMap<i32, Vec<(IpAddr, u16)>>,
        proxy_map_v6: HashMap<i32, Vec<(IpAddr, u16)>>,
        default_dc: Option<i32>,
        decision: NetworkDecision,
        rng: Arc<SecureRandom>,
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
            pool_size: 2,
            proxy_map_v4: Arc::new(RwLock::new(proxy_map_v4)),
            proxy_map_v6: Arc::new(RwLock::new(proxy_map_v6)),
            default_dc: AtomicI32::new(default_dc.unwrap_or(0)),
            next_writer_id: AtomicU64::new(1),
            ping_tracker: Arc::new(Mutex::new(HashMap::new())),
            rtt_stats: Arc::new(Mutex::new(HashMap::new())),
            nat_reflection_cache: Arc::new(Mutex::new(NatReflectionCache::default())),
        })
    }

    pub fn has_proxy_tag(&self) -> bool {
        self.proxy_tag.is_some()
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
        let current: HashSet<SocketAddr> = writers.iter().map(|w| w.addr).collect();
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
            }
        }
        changed
    }

    pub async fn update_secret(&self, new_secret: Vec<u8>) -> bool {
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

    pub async fn reconnect_all(&self) {
        // Graceful: do not drop all at once. New connections will use updated secret.
        // Existing writers remain until health monitor replaces them.
        // No-op here to avoid total outage.
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
            for (dc, addrs) in dc_addrs.iter().cloned() {
                if addrs.is_empty() {
                    continue;
                }
                let pool = Arc::clone(self);
                let rng_clone = Arc::clone(rng);
                join.spawn(async move {
                    pool.connect_primary_for_dc(dc, addrs, rng_clone).await;
                });
            }
            while let Some(_res) = join.join_next().await {}

            // Additional connections up to pool_size total (round-robin across DCs)
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
        let rpc_w = Arc::new(Mutex::new(RpcWriter {
            writer: hs.wr,
            key: hs.write_key,
            iv: hs.write_iv,
            seq_no: 0,
        }));
        let writer = MeWriter {
            id: writer_id,
            addr,
            writer: rpc_w.clone(),
            cancel: cancel.clone(),
            degraded: degraded.clone(),
        };
        self.writers.write().await.push(writer.clone());

        let reg = self.registry.clone();
        let writers_arc = self.writers_arc();
        let ping_tracker = self.ping_tracker.clone();
        let rtt_stats = self.rtt_stats.clone();
        let pool = Arc::downgrade(self);
        let cancel_ping = cancel.clone();
        let rpc_w_ping = rpc_w.clone();
        let ping_tracker_ping = ping_tracker.clone();

        tokio::spawn(async move {
            let cancel_reader = cancel.clone();
            let res = reader_loop(
                hs.rd,
                hs.read_key,
                hs.read_iv,
                reg.clone(),
                BytesMut::new(),
                BytesMut::new(),
                rpc_w.clone(),
                ping_tracker.clone(),
                rtt_stats.clone(),
                writer_id,
                degraded.clone(),
                cancel_reader.clone(),
            )
            .await;
            if let Some(pool) = pool.upgrade() {
                pool.remove_writer_and_reroute(writer_id).await;
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
                    _ = cancel_ping.cancelled() => {
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
                    tracker.insert(sent_id, (std::time::Instant::now(), writer_id));
                }
                ping_id = ping_id.wrapping_add(1);
                if let Err(e) = rpc_w_ping.lock().await.send(&p).await {
                    debug!(error = %e, "Active ME ping failed, removing dead writer");
                    cancel_ping.cancel();
                    if let Some(pool) = pool_ping.upgrade() {
                        pool.remove_writer_and_reroute(writer_id).await;
                    }
                    break;
                }
            }
        });

        Ok(())
    }

    async fn connect_primary_for_dc(
        self: Arc<Self>,
        dc: i32,
        mut addrs: Vec<(IpAddr, u16)>,
        rng: Arc<SecureRandom>,
    ) {
        if addrs.is_empty() {
            return;
        }
        addrs.shuffle(&mut rand::rng());
        for (ip, port) in addrs {
            let addr = SocketAddr::new(ip, port);
            match self.connect_one(addr, rng.as_ref()).await {
                Ok(()) => {
                    info!(%addr, dc = %dc, "ME connected");
                    return;
                }
                Err(e) => warn!(%addr, dc = %dc, error = %e, "ME connect failed, trying next"),
            }
        }
        warn!(dc = %dc, "All ME servers for DC failed at init");
    }

    pub(crate) async fn remove_writer_and_reroute(&self, writer_id: u64) {
        let mut queue = self.remove_writer_only(writer_id).await;
        while let Some(bound) = queue.pop() {
            if !self.reroute_conn(&bound, &mut queue).await {
                let _ = self.registry.route(bound.conn_id, super::MeResponse::Close).await;
            }
        }
    }

    async fn remove_writer_only(&self, writer_id: u64) -> Vec<BoundConn> {
        {
            let mut ws = self.writers.write().await;
            if let Some(pos) = ws.iter().position(|w| w.id == writer_id) {
                let w = ws.remove(pos);
                w.cancel.cancel();
            }
        }
        self.registry.writer_lost(writer_id).await
    }

    async fn reroute_conn(&self, bound: &BoundConn, backlog: &mut Vec<BoundConn>) -> bool {
        let payload = super::wire::build_proxy_req_payload(
            bound.conn_id,
            bound.meta.client_addr,
            bound.meta.our_addr,
            &[],
            self.proxy_tag.as_deref(),
            bound.meta.proto_flags,
        );

        let mut attempts = 0;
        loop {
            let writers_snapshot = {
                let ws = self.writers.read().await;
                if ws.is_empty() {
                    return false;
                }
                ws.clone()
            };
            let mut candidates = self.candidate_indices_for_dc(&writers_snapshot, bound.meta.target_dc).await;
            if candidates.is_empty() {
                return false;
            }
            candidates.sort_by_key(|idx| {
                writers_snapshot[*idx]
                    .degraded
                    .load(Ordering::Relaxed)
                    .then_some(1usize)
                    .unwrap_or(0)
            });
            let start = self.rr.fetch_add(1, Ordering::Relaxed) as usize % candidates.len();

            for offset in 0..candidates.len() {
                let idx = candidates[(start + offset) % candidates.len()];
                let w = &writers_snapshot[idx];
                if let Ok(mut guard) = w.writer.try_lock() {
                    let send_res = guard.send(&payload).await;
                    drop(guard);
                    match send_res {
                        Ok(()) => {
                            self.registry
                                .bind_writer(bound.conn_id, w.id, w.writer.clone(), bound.meta.clone())
                                .await;
                            return true;
                        }
                        Err(e) => {
                            warn!(error = %e, writer_id = w.id, "ME reroute send failed");
                            backlog.extend(self.remove_writer_only(w.id).await);
                        }
                    }
                    continue;
                }
            }

            let w = writers_snapshot[candidates[start]].clone();
            match w.writer.lock().await.send(&payload).await {
                Ok(()) => {
                    self.registry
                        .bind_writer(bound.conn_id, w.id, w.writer.clone(), bound.meta.clone())
                        .await;
                    return true;
                }
                Err(e) => {
                    warn!(error = %e, writer_id = w.id, "ME reroute send failed (blocking)");
                    backlog.extend(self.remove_writer_only(w.id).await);
                }
            }

            attempts += 1;
            if attempts > 3 {
                return false;
            }
        }
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
