use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{mpsc, RwLock};
use tokio::sync::mpsc::error::TrySendError;

use super::codec::WriterCommand;
use super::MeResponse;

const ROUTE_CHANNEL_CAPACITY: usize = 4096;
const ROUTE_BACKPRESSURE_BASE_TIMEOUT_MS: u64 = 25;
const ROUTE_BACKPRESSURE_HIGH_TIMEOUT_MS: u64 = 120;
const ROUTE_BACKPRESSURE_HIGH_WATERMARK_PCT: u8 = 80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteResult {
    Routed,
    NoConn,
    ChannelClosed,
    QueueFullBase,
    QueueFullHigh,
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct ConnMeta {
    pub target_dc: i16,
    pub client_addr: SocketAddr,
    pub our_addr: SocketAddr,
    pub proto_flags: u32,
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct BoundConn {
    pub conn_id: u64,
    pub meta: ConnMeta,
}

#[derive(Clone)]
pub struct ConnWriter {
    pub writer_id: u64,
    pub tx: mpsc::Sender<WriterCommand>,
}

struct RegistryInner {
    map: HashMap<u64, mpsc::Sender<MeResponse>>,
    writers: HashMap<u64, mpsc::Sender<WriterCommand>>,
    writer_for_conn: HashMap<u64, u64>,
    conns_for_writer: HashMap<u64, HashSet<u64>>,
    meta: HashMap<u64, ConnMeta>,
}

impl RegistryInner {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            writers: HashMap::new(),
            writer_for_conn: HashMap::new(),
            conns_for_writer: HashMap::new(),
            meta: HashMap::new(),
        }
    }
}

pub struct ConnRegistry {
    inner: RwLock<RegistryInner>,
    next_id: AtomicU64,
    route_backpressure_base_timeout_ms: AtomicU64,
    route_backpressure_high_timeout_ms: AtomicU64,
    route_backpressure_high_watermark_pct: AtomicU8,
}

impl ConnRegistry {
    pub fn new() -> Self {
        let start = rand::random::<u64>() | 1;
        Self {
            inner: RwLock::new(RegistryInner::new()),
            next_id: AtomicU64::new(start),
            route_backpressure_base_timeout_ms: AtomicU64::new(
                ROUTE_BACKPRESSURE_BASE_TIMEOUT_MS,
            ),
            route_backpressure_high_timeout_ms: AtomicU64::new(
                ROUTE_BACKPRESSURE_HIGH_TIMEOUT_MS,
            ),
            route_backpressure_high_watermark_pct: AtomicU8::new(
                ROUTE_BACKPRESSURE_HIGH_WATERMARK_PCT,
            ),
        }
    }

    pub fn update_route_backpressure_policy(
        &self,
        base_timeout_ms: u64,
        high_timeout_ms: u64,
        high_watermark_pct: u8,
    ) {
        let base = base_timeout_ms.max(1);
        let high = high_timeout_ms.max(base);
        let watermark = high_watermark_pct.clamp(1, 100);
        self.route_backpressure_base_timeout_ms
            .store(base, Ordering::Relaxed);
        self.route_backpressure_high_timeout_ms
            .store(high, Ordering::Relaxed);
        self.route_backpressure_high_watermark_pct
            .store(watermark, Ordering::Relaxed);
    }

    pub async fn register(&self) -> (u64, mpsc::Receiver<MeResponse>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(ROUTE_CHANNEL_CAPACITY);
        self.inner.write().await.map.insert(id, tx);
        (id, rx)
    }

    /// Unregister connection, returning associated writer_id if any.
    pub async fn unregister(&self, id: u64) -> Option<u64> {
        let mut inner = self.inner.write().await;
        inner.map.remove(&id);
        inner.meta.remove(&id);
        if let Some(writer_id) = inner.writer_for_conn.remove(&id) {
            if let Some(set) = inner.conns_for_writer.get_mut(&writer_id) {
                set.remove(&id);
            }
            return Some(writer_id);
        }
        None
    }

    pub async fn route(&self, id: u64, resp: MeResponse) -> RouteResult {
        let tx = {
            let inner = self.inner.read().await;
            inner.map.get(&id).cloned()
        };

        let Some(tx) = tx else {
            return RouteResult::NoConn;
        };

        match tx.try_send(resp) {
            Ok(()) => RouteResult::Routed,
            Err(TrySendError::Closed(_)) => RouteResult::ChannelClosed,
            Err(TrySendError::Full(resp)) => {
                // Absorb short bursts without dropping/closing the session immediately.
                let base_timeout_ms =
                    self.route_backpressure_base_timeout_ms.load(Ordering::Relaxed).max(1);
                let high_timeout_ms = self
                    .route_backpressure_high_timeout_ms
                    .load(Ordering::Relaxed)
                    .max(base_timeout_ms);
                let high_watermark_pct = self
                    .route_backpressure_high_watermark_pct
                    .load(Ordering::Relaxed)
                    .clamp(1, 100);
                let used = ROUTE_CHANNEL_CAPACITY.saturating_sub(tx.capacity());
                let used_pct = if ROUTE_CHANNEL_CAPACITY == 0 {
                    100
                } else {
                    (used.saturating_mul(100) / ROUTE_CHANNEL_CAPACITY) as u8
                };
                let high_profile = used_pct >= high_watermark_pct;
                let timeout_ms = if high_profile {
                    high_timeout_ms
                } else {
                    base_timeout_ms
                };
                let timeout_dur = Duration::from_millis(timeout_ms);

                match tokio::time::timeout(timeout_dur, tx.send(resp)).await {
                    Ok(Ok(())) => RouteResult::Routed,
                    Ok(Err(_)) => RouteResult::ChannelClosed,
                    Err(_) => {
                        if high_profile {
                            RouteResult::QueueFullHigh
                        } else {
                            RouteResult::QueueFullBase
                        }
                    }
                }
            }
        }
    }

    pub async fn bind_writer(
        &self,
        conn_id: u64,
        writer_id: u64,
        tx: mpsc::Sender<WriterCommand>,
        meta: ConnMeta,
    ) {
        let mut inner = self.inner.write().await;
        inner.meta.entry(conn_id).or_insert(meta);
        inner.writer_for_conn.insert(conn_id, writer_id);
        inner.writers.entry(writer_id).or_insert_with(|| tx.clone());
        inner
            .conns_for_writer
            .entry(writer_id)
            .or_insert_with(HashSet::new)
            .insert(conn_id);
    }

    pub async fn get_writer(&self, conn_id: u64) -> Option<ConnWriter> {
        let inner = self.inner.read().await;
        let writer_id = inner.writer_for_conn.get(&conn_id).cloned()?;
        let writer = inner.writers.get(&writer_id).cloned()?;
        Some(ConnWriter { writer_id, tx: writer })
    }

    pub async fn writer_lost(&self, writer_id: u64) -> Vec<BoundConn> {
        let mut inner = self.inner.write().await;
        inner.writers.remove(&writer_id);
        let conns = inner
            .conns_for_writer
            .remove(&writer_id)
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();

        let mut out = Vec::new();
        for conn_id in conns {
            inner.writer_for_conn.remove(&conn_id);
            if let Some(m) = inner.meta.get(&conn_id) {
                out.push(BoundConn {
                    conn_id,
                    meta: m.clone(),
                });
            }
        }
        out
    }

    #[allow(dead_code)]
    pub async fn get_meta(&self, conn_id: u64) -> Option<ConnMeta> {
        let inner = self.inner.read().await;
        inner.meta.get(&conn_id).cloned()
    }

    pub async fn is_writer_empty(&self, writer_id: u64) -> bool {
        let inner = self.inner.read().await;
        inner
            .conns_for_writer
            .get(&writer_id)
            .map(|s| s.is_empty())
            .unwrap_or(true)
    }
}
