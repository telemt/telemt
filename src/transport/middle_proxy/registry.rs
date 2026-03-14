use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, RwLock};
use tokio::sync::mpsc::error::TrySendError;

use super::codec::WriterCommand;
use super::MeResponse;

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

#[derive(Clone, Debug, Default)]
pub(super) struct WriterActivitySnapshot {
    pub bound_clients_by_writer: HashMap<u64, usize>,
    pub active_sessions_by_target_dc: HashMap<i16, usize>,
}

struct RegistryInner {
    map: HashMap<u64, mpsc::Sender<MeResponse>>,
    writers: HashMap<u64, mpsc::Sender<WriterCommand>>,
    writer_for_conn: HashMap<u64, u64>,
    conns_for_writer: HashMap<u64, HashSet<u64>>,
    meta: HashMap<u64, ConnMeta>,
    last_meta_for_writer: HashMap<u64, ConnMeta>,
    writer_idle_since_epoch_secs: HashMap<u64, u64>,
}

impl RegistryInner {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            writers: HashMap::new(),
            writer_for_conn: HashMap::new(),
            conns_for_writer: HashMap::new(),
            meta: HashMap::new(),
            last_meta_for_writer: HashMap::new(),
            writer_idle_since_epoch_secs: HashMap::new(),
        }
    }
}

pub struct ConnRegistry {
    inner: RwLock<RegistryInner>,
    next_id: AtomicU64,
    route_channel_capacity: usize,
    route_backpressure_base_timeout_ms: AtomicU64,
    route_backpressure_high_timeout_ms: AtomicU64,
    route_backpressure_high_watermark_pct: AtomicU8,
}

impl ConnRegistry {
    fn now_epoch_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub fn with_route_channel_capacity(route_channel_capacity: usize) -> Self {
        let start = rand::random::<u64>() | 1;
        Self {
            inner: RwLock::new(RegistryInner::new()),
            next_id: AtomicU64::new(start),
            route_channel_capacity: route_channel_capacity.max(1),
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

    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_route_channel_capacity(4096)
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
        let (tx, rx) = mpsc::channel(self.route_channel_capacity);
        self.inner.write().await.map.insert(id, tx);
        (id, rx)
    }

/// Unregister connection, returning associated `writer_id` if any.
    pub async fn unregister(&self, id: u64) -> Option<u64> {
        let mut inner = self.inner.write().await;
        inner.map.remove(&id);
        inner.meta.remove(&id);
        if let Some(writer_id) = inner.writer_for_conn.remove(&id) {
            let became_empty = if let Some(set) = inner.conns_for_writer.get_mut(&writer_id) {
                set.remove(&id);
                set.is_empty()
            } else {
                false
            };
            if became_empty {
                inner
                    .writer_idle_since_epoch_secs
                    .insert(writer_id, Self::now_epoch_secs());
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
                let used = self.route_channel_capacity.saturating_sub(tx.capacity());
                let used_pct = if self.route_channel_capacity == 0 {
                    100
                } else {
                    (used.saturating_mul(100) / self.route_channel_capacity) as u8
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

    pub async fn route_nowait(&self, id: u64, resp: MeResponse) -> RouteResult {
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
            Err(TrySendError::Full(_)) => RouteResult::QueueFullBase,
        }
    }

    pub async fn route_with_timeout(
        &self,
        id: u64,
        resp: MeResponse,
        timeout_ms: u64,
    ) -> RouteResult {
        if timeout_ms == 0 {
            return self.route_nowait(id, resp).await;
        }

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
                let high_watermark_pct = self
                    .route_backpressure_high_watermark_pct
                    .load(Ordering::Relaxed)
                    .clamp(1, 100);
                let used = self.route_channel_capacity.saturating_sub(tx.capacity());
                let used_pct = if self.route_channel_capacity == 0 {
                    100
                } else {
                    (used.saturating_mul(100) / self.route_channel_capacity) as u8
                };
                let high_profile = used_pct >= high_watermark_pct;
                let timeout_dur = Duration::from_millis(timeout_ms.max(1));

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
        inner.meta.entry(conn_id).or_insert(meta.clone());
        inner.writer_for_conn.insert(conn_id, writer_id);
        inner.last_meta_for_writer.insert(writer_id, meta);
        inner.writer_idle_since_epoch_secs.remove(&writer_id);
        inner.writers.entry(writer_id).or_insert_with(|| tx.clone());
        inner
            .conns_for_writer
            .entry(writer_id)
            .or_insert_with(HashSet::new)
            .insert(conn_id);
    }

    pub async fn mark_writer_idle(&self, writer_id: u64) {
        let mut inner = self.inner.write().await;
        inner.conns_for_writer.entry(writer_id).or_insert_with(HashSet::new);
        inner
            .writer_idle_since_epoch_secs
            .entry(writer_id)
            .or_insert(Self::now_epoch_secs());
    }

    pub async fn get_last_writer_meta(&self, writer_id: u64) -> Option<ConnMeta> {
        let inner = self.inner.read().await;
        inner.last_meta_for_writer.get(&writer_id).cloned()
    }

    pub async fn writer_idle_since_snapshot(&self) -> HashMap<u64, u64> {
        let inner = self.inner.read().await;
        inner.writer_idle_since_epoch_secs.clone()
    }

    pub async fn writer_idle_since_for_writer_ids(
        &self,
        writer_ids: &[u64],
    ) -> HashMap<u64, u64> {
        let inner = self.inner.read().await;
        let mut out = HashMap::<u64, u64>::with_capacity(writer_ids.len());
        for writer_id in writer_ids {
            if let Some(idle_since) = inner.writer_idle_since_epoch_secs.get(writer_id).copied() {
                out.insert(*writer_id, idle_since);
            }
        }
        out
    }

    pub(super) async fn writer_activity_snapshot(&self) -> WriterActivitySnapshot {
        let inner = self.inner.read().await;
        let mut bound_clients_by_writer = HashMap::<u64, usize>::new();
        let mut active_sessions_by_target_dc = HashMap::<i16, usize>::new();

        for (writer_id, conn_ids) in &inner.conns_for_writer {
            bound_clients_by_writer.insert(*writer_id, conn_ids.len());
        }
        for conn_meta in inner.meta.values() {
            if conn_meta.target_dc == 0 {
                continue;
            }
            *active_sessions_by_target_dc
                .entry(conn_meta.target_dc)
                .or_insert(0) += 1;
        }

        WriterActivitySnapshot {
            bound_clients_by_writer,
            active_sessions_by_target_dc,
        }
    }

    pub async fn get_writer(&self, conn_id: u64) -> Option<ConnWriter> {
        let inner = self.inner.read().await;
        let writer_id = inner.writer_for_conn.get(&conn_id).cloned()?;
        let writer = inner.writers.get(&writer_id).cloned()?;
        Some(ConnWriter { writer_id, tx: writer })
    }

    pub async fn active_conn_ids(&self) -> Vec<u64> {
        let inner = self.inner.read().await;
        inner.writer_for_conn.keys().copied().collect()
    }

    pub async fn writer_lost(&self, writer_id: u64) -> Vec<BoundConn> {
        let mut inner = self.inner.write().await;
        inner.writers.remove(&writer_id);
        inner.last_meta_for_writer.remove(&writer_id);
        inner.writer_idle_since_epoch_secs.remove(&writer_id);
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::ConnMeta;
    use super::ConnRegistry;

    #[tokio::test]
    async fn writer_activity_snapshot_tracks_writer_and_dc_load() {
        let registry = ConnRegistry::new();

        let (conn_a, _rx_a) = registry.register().await;
        let (conn_b, _rx_b) = registry.register().await;
        let (conn_c, _rx_c) = registry.register().await;
        let (writer_tx_a, _writer_rx_a) = tokio::sync::mpsc::channel(8);
        let (writer_tx_b, _writer_rx_b) = tokio::sync::mpsc::channel(8);

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        registry
            .bind_writer(
                conn_a,
                10,
                writer_tx_a.clone(),
                ConnMeta {
                    target_dc: 2,
                    client_addr: addr,
                    our_addr: addr,
                    proto_flags: 0,
                },
            )
            .await;
        registry
            .bind_writer(
                conn_b,
                10,
                writer_tx_a,
                ConnMeta {
                    target_dc: -2,
                    client_addr: addr,
                    our_addr: addr,
                    proto_flags: 0,
                },
            )
            .await;
        registry
            .bind_writer(
                conn_c,
                20,
                writer_tx_b,
                ConnMeta {
                    target_dc: 4,
                    client_addr: addr,
                    our_addr: addr,
                    proto_flags: 0,
                },
            )
            .await;

        let snapshot = registry.writer_activity_snapshot().await;
        assert_eq!(snapshot.bound_clients_by_writer.get(&10), Some(&2));
        assert_eq!(snapshot.bound_clients_by_writer.get(&20), Some(&1));
        assert_eq!(snapshot.active_sessions_by_target_dc.get(&2), Some(&1));
        assert_eq!(snapshot.active_sessions_by_target_dc.get(&-2), Some(&1));
        assert_eq!(snapshot.active_sessions_by_target_dc.get(&4), Some(&1));
    }
}
