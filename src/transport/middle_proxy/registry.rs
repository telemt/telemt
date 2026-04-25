use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Mutex, Semaphore, mpsc};

use super::codec::WriterCommand;
use super::{MeResponse, RouteBytePermit};

const ROUTE_BACKPRESSURE_BASE_TIMEOUT_MS: u64 = 25;
const ROUTE_BACKPRESSURE_HIGH_TIMEOUT_MS: u64 = 120;
const ROUTE_BACKPRESSURE_HIGH_WATERMARK_PCT: u8 = 80;
const ROUTE_QUEUED_BYTE_PERMIT_UNIT: usize = 16 * 1024;
const ROUTE_QUEUED_PERMITS_PER_SLOT: usize = 4;
const ROUTE_QUEUED_MAX_FRAME_PERMITS: usize = 1024;

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

struct RoutingTable {
    map: DashMap<u64, mpsc::Sender<MeResponse>>,
    byte_budget: DashMap<u64, Arc<Semaphore>>,
}

struct WriterTable {
    map: DashMap<u64, mpsc::Sender<WriterCommand>>,
}

#[derive(Clone)]
struct HotConnBinding {
    writer_id: u64,
    meta: ConnMeta,
}

struct HotBindingTable {
    map: DashMap<u64, HotConnBinding>,
}

struct BindingState {
    inner: Mutex<BindingInner>,
}

struct BindingInner {
    writers: HashMap<u64, mpsc::Sender<WriterCommand>>,
    writer_for_conn: HashMap<u64, u64>,
    conns_for_writer: HashMap<u64, HashSet<u64>>,
    meta: HashMap<u64, ConnMeta>,
    last_meta_for_writer: HashMap<u64, ConnMeta>,
    writer_idle_since_epoch_secs: HashMap<u64, u64>,
}

impl BindingInner {
    fn new() -> Self {
        Self {
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
    routing: RoutingTable,
    writers: WriterTable,
    hot_binding: HotBindingTable,
    binding: BindingState,
    next_id: AtomicU64,
    route_channel_capacity: usize,
    route_backpressure_base_timeout_ms: AtomicU64,
    route_backpressure_high_timeout_ms: AtomicU64,
    route_backpressure_high_watermark_pct: AtomicU8,
    route_byte_permits_per_conn: usize,
}

impl ConnRegistry {
    fn now_epoch_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub fn with_route_channel_capacity(route_channel_capacity: usize) -> Self {
        let route_channel_capacity = route_channel_capacity.max(1);
        Self::with_route_limits(
            route_channel_capacity,
            Self::route_byte_permit_budget(route_channel_capacity),
        )
    }

    fn with_route_limits(
        route_channel_capacity: usize,
        route_byte_permits_per_conn: usize,
    ) -> Self {
        let start = rand::random::<u64>() | 1;
        let route_channel_capacity = route_channel_capacity.max(1);
        Self {
            routing: RoutingTable {
                map: DashMap::new(),
                byte_budget: DashMap::new(),
            },
            writers: WriterTable {
                map: DashMap::new(),
            },
            hot_binding: HotBindingTable {
                map: DashMap::new(),
            },
            binding: BindingState {
                inner: Mutex::new(BindingInner::new()),
            },
            next_id: AtomicU64::new(start),
            route_channel_capacity,
            route_backpressure_base_timeout_ms: AtomicU64::new(ROUTE_BACKPRESSURE_BASE_TIMEOUT_MS),
            route_backpressure_high_timeout_ms: AtomicU64::new(ROUTE_BACKPRESSURE_HIGH_TIMEOUT_MS),
            route_backpressure_high_watermark_pct: AtomicU8::new(
                ROUTE_BACKPRESSURE_HIGH_WATERMARK_PCT,
            ),
            route_byte_permits_per_conn: route_byte_permits_per_conn.max(1),
        }
    }

    fn route_data_permits(data_len: usize) -> u32 {
        data_len
            .max(1)
            .div_ceil(ROUTE_QUEUED_BYTE_PERMIT_UNIT)
            .min(u32::MAX as usize) as u32
    }

    fn route_byte_permit_budget(route_channel_capacity: usize) -> usize {
        route_channel_capacity
            .saturating_mul(ROUTE_QUEUED_PERMITS_PER_SLOT)
            .max(ROUTE_QUEUED_MAX_FRAME_PERMITS)
            .max(1)
    }

    pub fn route_channel_capacity(&self) -> usize {
        self.route_channel_capacity
    }

    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_route_channel_capacity(4096)
    }

    #[cfg(test)]
    fn with_route_byte_permits_for_tests(
        route_channel_capacity: usize,
        route_byte_permits_per_conn: usize,
    ) -> Self {
        Self::with_route_limits(route_channel_capacity, route_byte_permits_per_conn)
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
        self.routing.map.insert(id, tx);
        self.routing.byte_budget.insert(
            id,
            Arc::new(Semaphore::new(self.route_byte_permits_per_conn)),
        );
        (id, rx)
    }

    pub async fn register_writer(&self, writer_id: u64, tx: mpsc::Sender<WriterCommand>) {
        let mut binding = self.binding.inner.lock().await;
        binding.writers.insert(writer_id, tx.clone());
        binding
            .conns_for_writer
            .entry(writer_id)
            .or_insert_with(HashSet::new);
        self.writers.map.insert(writer_id, tx);
    }

    /// Unregister connection, returning associated writer_id if any.
    pub async fn unregister(&self, id: u64) -> Option<u64> {
        self.routing.map.remove(&id);
        self.routing.byte_budget.remove(&id);
        self.hot_binding.map.remove(&id);
        let mut binding = self.binding.inner.lock().await;
        binding.meta.remove(&id);
        if let Some(writer_id) = binding.writer_for_conn.remove(&id) {
            let became_empty = if let Some(set) = binding.conns_for_writer.get_mut(&writer_id) {
                set.remove(&id);
                set.is_empty()
            } else {
                false
            };
            if became_empty {
                binding
                    .writer_idle_since_epoch_secs
                    .insert(writer_id, Self::now_epoch_secs());
            }
            return Some(writer_id);
        }
        None
    }

    async fn attach_route_byte_permit(
        &self,
        id: u64,
        resp: MeResponse,
        timeout_ms: Option<u64>,
    ) -> std::result::Result<MeResponse, RouteResult> {
        let MeResponse::Data {
            flags,
            data,
            route_permit,
        } = resp
        else {
            return Ok(resp);
        };

        if route_permit.is_some() {
            return Ok(MeResponse::Data {
                flags,
                data,
                route_permit,
            });
        }

        let Some(semaphore) = self
            .routing
            .byte_budget
            .get(&id)
            .map(|entry| entry.value().clone())
        else {
            return Err(RouteResult::NoConn);
        };
        let permits = Self::route_data_permits(data.len());
        let permit = match timeout_ms {
            Some(0) => semaphore
                .try_acquire_many_owned(permits)
                .map_err(|_| RouteResult::QueueFullHigh)?,
            Some(timeout_ms) => {
                let acquire = semaphore.acquire_many_owned(permits);
                match tokio::time::timeout(Duration::from_millis(timeout_ms.max(1)), acquire).await
                {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(_)) => return Err(RouteResult::ChannelClosed),
                    Err(_) => return Err(RouteResult::QueueFullHigh),
                }
            }
            None => semaphore
                .acquire_many_owned(permits)
                .await
                .map_err(|_| RouteResult::ChannelClosed)?,
        };

        Ok(MeResponse::Data {
            flags,
            data,
            route_permit: Some(RouteBytePermit::new(permit)),
        })
    }

    #[allow(dead_code)]
    pub async fn route(&self, id: u64, resp: MeResponse) -> RouteResult {
        let tx = self.routing.map.get(&id).map(|entry| entry.value().clone());

        let Some(tx) = tx else {
            return RouteResult::NoConn;
        };

        let base_timeout_ms = self
            .route_backpressure_base_timeout_ms
            .load(Ordering::Relaxed)
            .max(1);
        let resp = match self
            .attach_route_byte_permit(id, resp, Some(base_timeout_ms))
            .await
        {
            Ok(resp) => resp,
            Err(result) => return result,
        };

        match tx.try_send(resp) {
            Ok(()) => RouteResult::Routed,
            Err(TrySendError::Closed(_)) => RouteResult::ChannelClosed,
            Err(TrySendError::Full(resp)) => {
                // Absorb short bursts without dropping/closing the session immediately.
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
        let tx = self.routing.map.get(&id).map(|entry| entry.value().clone());

        let Some(tx) = tx else {
            return RouteResult::NoConn;
        };
        let resp = match self.attach_route_byte_permit(id, resp, Some(0)).await {
            Ok(resp) => resp,
            Err(result) => return result,
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

        let tx = self.routing.map.get(&id).map(|entry| entry.value().clone());

        let Some(tx) = tx else {
            return RouteResult::NoConn;
        };
        let resp = match self
            .attach_route_byte_permit(id, resp, Some(timeout_ms))
            .await
        {
            Ok(resp) => resp,
            Err(result) => return result,
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

    pub async fn bind_writer(&self, conn_id: u64, writer_id: u64, meta: ConnMeta) -> bool {
        let mut binding = self.binding.inner.lock().await;
        // ROUTING IS THE SOURCE OF TRUTH:
        // never keep/attach writer binding for a connection that is already
        // absent from the routing table.
        if !self.routing.map.contains_key(&conn_id) {
            return false;
        }
        if !binding.writers.contains_key(&writer_id) {
            return false;
        }

        let previous_writer_id = binding.writer_for_conn.insert(conn_id, writer_id);
        if let Some(previous_writer_id) = previous_writer_id
            && previous_writer_id != writer_id
        {
            let became_empty =
                if let Some(set) = binding.conns_for_writer.get_mut(&previous_writer_id) {
                    set.remove(&conn_id);
                    set.is_empty()
                } else {
                    false
                };
            if became_empty {
                binding
                    .writer_idle_since_epoch_secs
                    .insert(previous_writer_id, Self::now_epoch_secs());
            }
        }

        binding.meta.insert(conn_id, meta.clone());
        binding.last_meta_for_writer.insert(writer_id, meta.clone());
        binding.writer_idle_since_epoch_secs.remove(&writer_id);
        binding
            .conns_for_writer
            .entry(writer_id)
            .or_insert_with(HashSet::new)
            .insert(conn_id);
        self.hot_binding
            .map
            .insert(conn_id, HotConnBinding { writer_id, meta });
        true
    }

    pub async fn mark_writer_idle(&self, writer_id: u64) {
        let mut binding = self.binding.inner.lock().await;
        binding
            .conns_for_writer
            .entry(writer_id)
            .or_insert_with(HashSet::new);
        binding
            .writer_idle_since_epoch_secs
            .entry(writer_id)
            .or_insert(Self::now_epoch_secs());
    }

    pub async fn get_last_writer_meta(&self, writer_id: u64) -> Option<ConnMeta> {
        let binding = self.binding.inner.lock().await;
        binding.last_meta_for_writer.get(&writer_id).cloned()
    }

    pub async fn writer_idle_since_snapshot(&self) -> HashMap<u64, u64> {
        let binding = self.binding.inner.lock().await;
        binding.writer_idle_since_epoch_secs.clone()
    }

    pub async fn writer_idle_since_for_writer_ids(&self, writer_ids: &[u64]) -> HashMap<u64, u64> {
        let binding = self.binding.inner.lock().await;
        let mut out = HashMap::<u64, u64>::with_capacity(writer_ids.len());
        for writer_id in writer_ids {
            if let Some(idle_since) = binding.writer_idle_since_epoch_secs.get(writer_id).copied() {
                out.insert(*writer_id, idle_since);
            }
        }
        out
    }

    pub(super) async fn writer_activity_snapshot(&self) -> WriterActivitySnapshot {
        let binding = self.binding.inner.lock().await;
        let mut bound_clients_by_writer = HashMap::<u64, usize>::new();
        let mut active_sessions_by_target_dc = HashMap::<i16, usize>::new();

        for (writer_id, conn_ids) in &binding.conns_for_writer {
            bound_clients_by_writer.insert(*writer_id, conn_ids.len());
        }
        for conn_meta in binding.meta.values() {
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
        if !self.routing.map.contains_key(&conn_id) {
            return None;
        }

        let writer_id = self
            .hot_binding
            .map
            .get(&conn_id)
            .map(|entry| entry.writer_id)?;
        let writer = self
            .writers
            .map
            .get(&writer_id)
            .map(|entry| entry.value().clone())?;
        Some(ConnWriter {
            writer_id,
            tx: writer,
        })
    }

    pub async fn active_conn_ids(&self) -> Vec<u64> {
        let binding = self.binding.inner.lock().await;
        binding.writer_for_conn.keys().copied().collect()
    }

    pub async fn writer_lost(&self, writer_id: u64) -> Vec<BoundConn> {
        let mut binding = self.binding.inner.lock().await;
        binding.writers.remove(&writer_id);
        self.writers.map.remove(&writer_id);
        binding.last_meta_for_writer.remove(&writer_id);
        binding.writer_idle_since_epoch_secs.remove(&writer_id);
        let conns = binding
            .conns_for_writer
            .remove(&writer_id)
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();

        let mut out = Vec::new();
        for conn_id in conns {
            if binding.writer_for_conn.get(&conn_id).copied() != Some(writer_id) {
                continue;
            }
            binding.writer_for_conn.remove(&conn_id);
            let remove_hot = self
                .hot_binding
                .map
                .get(&conn_id)
                .map(|hot| hot.writer_id == writer_id)
                .unwrap_or(false);
            if remove_hot {
                self.hot_binding.map.remove(&conn_id);
            }
            if let Some(m) = binding.meta.get(&conn_id) {
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
        self.hot_binding
            .map
            .get(&conn_id)
            .map(|entry| entry.meta.clone())
    }

    pub async fn is_writer_empty(&self, writer_id: u64) -> bool {
        let binding = self.binding.inner.lock().await;
        binding
            .conns_for_writer
            .get(&writer_id)
            .map(|s| s.is_empty())
            .unwrap_or(true)
    }

    #[allow(dead_code)]
    pub async fn unregister_writer_if_empty(&self, writer_id: u64) -> bool {
        let mut binding = self.binding.inner.lock().await;
        let Some(conn_ids) = binding.conns_for_writer.get(&writer_id) else {
            // Writer is already absent from the registry.
            return true;
        };
        if !conn_ids.is_empty() {
            return false;
        }

        binding.writers.remove(&writer_id);
        self.writers.map.remove(&writer_id);
        binding.last_meta_for_writer.remove(&writer_id);
        binding.writer_idle_since_epoch_secs.remove(&writer_id);
        binding.conns_for_writer.remove(&writer_id);
        true
    }

    #[allow(dead_code)]
    pub(super) async fn non_empty_writer_ids(&self, writer_ids: &[u64]) -> HashSet<u64> {
        let binding = self.binding.inner.lock().await;
        let mut out = HashSet::<u64>::with_capacity(writer_ids.len());
        for writer_id in writer_ids {
            if let Some(conns) = binding.conns_for_writer.get(writer_id)
                && !conns.is_empty()
            {
                out.insert(*writer_id);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use bytes::Bytes;

    use super::{ConnMeta, ConnRegistry, RouteResult};
    use crate::transport::middle_proxy::MeResponse;

    #[tokio::test]
    async fn writer_activity_snapshot_tracks_writer_and_dc_load() {
        let registry = ConnRegistry::new();

        let (conn_a, _rx_a) = registry.register().await;
        let (conn_b, _rx_b) = registry.register().await;
        let (conn_c, _rx_c) = registry.register().await;
        let (writer_tx_a, _writer_rx_a) = tokio::sync::mpsc::channel(8);
        let (writer_tx_b, _writer_rx_b) = tokio::sync::mpsc::channel(8);
        registry.register_writer(10, writer_tx_a.clone()).await;
        registry.register_writer(20, writer_tx_b.clone()).await;

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        assert!(
            registry
                .bind_writer(
                    conn_a,
                    10,
                    ConnMeta {
                        target_dc: 2,
                        client_addr: addr,
                        our_addr: addr,
                        proto_flags: 0,
                    },
                )
                .await
        );
        assert!(
            registry
                .bind_writer(
                    conn_b,
                    10,
                    ConnMeta {
                        target_dc: -2,
                        client_addr: addr,
                        our_addr: addr,
                        proto_flags: 0,
                    },
                )
                .await
        );
        assert!(
            registry
                .bind_writer(
                    conn_c,
                    20,
                    ConnMeta {
                        target_dc: 4,
                        client_addr: addr,
                        our_addr: addr,
                        proto_flags: 0,
                    },
                )
                .await
        );

        let snapshot = registry.writer_activity_snapshot().await;
        assert_eq!(snapshot.bound_clients_by_writer.get(&10), Some(&2));
        assert_eq!(snapshot.bound_clients_by_writer.get(&20), Some(&1));
        assert_eq!(snapshot.active_sessions_by_target_dc.get(&2), Some(&1));
        assert_eq!(snapshot.active_sessions_by_target_dc.get(&-2), Some(&1));
        assert_eq!(snapshot.active_sessions_by_target_dc.get(&4), Some(&1));
    }

    #[tokio::test]
    async fn route_data_is_bounded_by_byte_permits_before_channel_capacity() {
        let registry = ConnRegistry::with_route_byte_permits_for_tests(4, 1);
        let (conn_id, mut rx) = registry.register().await;
        let routed = registry
            .route_nowait(
                conn_id,
                MeResponse::Data {
                    flags: 0,
                    data: Bytes::from_static(&[0xAA]),
                    route_permit: None,
                },
            )
            .await;
        assert!(matches!(routed, RouteResult::Routed));

        let blocked = registry
            .route_nowait(
                conn_id,
                MeResponse::Data {
                    flags: 0,
                    data: Bytes::from_static(&[0xBB]),
                    route_permit: None,
                },
            )
            .await;
        assert!(
            matches!(blocked, RouteResult::QueueFullHigh),
            "byte budget must reject data before count capacity is exhausted"
        );

        drop(rx.recv().await);

        let routed_after_drain = registry
            .route_nowait(
                conn_id,
                MeResponse::Data {
                    flags: 0,
                    data: Bytes::from_static(&[0xCC]),
                    route_permit: None,
                },
            )
            .await;
        assert!(
            matches!(routed_after_drain, RouteResult::Routed),
            "receiving queued data must release byte permits"
        );
    }

    #[tokio::test]
    async fn bind_writer_rebinds_conn_atomically() {
        let registry = ConnRegistry::new();
        let (conn_id, _rx) = registry.register().await;
        let (writer_tx_a, _writer_rx_a) = tokio::sync::mpsc::channel(8);
        let (writer_tx_b, _writer_rx_b) = tokio::sync::mpsc::channel(8);
        registry.register_writer(10, writer_tx_a).await;
        registry.register_writer(20, writer_tx_b).await;

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let first_our_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
        let second_our_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), 443);

        assert!(
            registry
                .bind_writer(
                    conn_id,
                    10,
                    ConnMeta {
                        target_dc: 2,
                        client_addr,
                        our_addr: first_our_addr,
                        proto_flags: 1,
                    },
                )
                .await
        );
        assert!(
            registry
                .bind_writer(
                    conn_id,
                    20,
                    ConnMeta {
                        target_dc: 2,
                        client_addr,
                        our_addr: second_our_addr,
                        proto_flags: 2,
                    },
                )
                .await
        );

        let writer = registry.get_writer(conn_id).await.expect("writer binding");
        assert_eq!(writer.writer_id, 20);

        let meta = registry.get_meta(conn_id).await.expect("conn meta");
        assert_eq!(meta.our_addr, second_our_addr);
        assert_eq!(meta.proto_flags, 2);

        let snapshot = registry.writer_activity_snapshot().await;
        assert_eq!(snapshot.bound_clients_by_writer.get(&10), Some(&0));
        assert_eq!(snapshot.bound_clients_by_writer.get(&20), Some(&1));
        assert!(
            registry
                .writer_idle_since_snapshot()
                .await
                .contains_key(&10)
        );
    }

    #[tokio::test]
    async fn writer_lost_does_not_drop_rebound_conn() {
        let registry = ConnRegistry::new();
        let (conn_id, _rx) = registry.register().await;
        let (writer_tx_a, _writer_rx_a) = tokio::sync::mpsc::channel(8);
        let (writer_tx_b, _writer_rx_b) = tokio::sync::mpsc::channel(8);
        registry.register_writer(10, writer_tx_a).await;
        registry.register_writer(20, writer_tx_b).await;

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        assert!(
            registry
                .bind_writer(
                    conn_id,
                    10,
                    ConnMeta {
                        target_dc: 2,
                        client_addr: addr,
                        our_addr: addr,
                        proto_flags: 0,
                    },
                )
                .await
        );
        assert!(
            registry
                .bind_writer(
                    conn_id,
                    20,
                    ConnMeta {
                        target_dc: 2,
                        client_addr: addr,
                        our_addr: addr,
                        proto_flags: 1,
                    },
                )
                .await
        );

        let lost = registry.writer_lost(10).await;
        assert!(lost.is_empty());
        assert_eq!(
            registry
                .get_writer(conn_id)
                .await
                .expect("writer")
                .writer_id,
            20
        );

        let removed_writer = registry.unregister(conn_id).await;
        assert_eq!(removed_writer, Some(20));
        assert!(registry.is_writer_empty(20).await);
    }

    #[tokio::test]
    async fn bind_writer_rejects_unregistered_writer() {
        let registry = ConnRegistry::new();
        let (conn_id, _rx) = registry.register().await;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);

        assert!(
            !registry
                .bind_writer(
                    conn_id,
                    10,
                    ConnMeta {
                        target_dc: 2,
                        client_addr: addr,
                        our_addr: addr,
                        proto_flags: 0,
                    },
                )
                .await
        );
        assert!(registry.get_writer(conn_id).await.is_none());
    }

    #[tokio::test]
    async fn non_empty_writer_ids_returns_only_writers_with_bound_clients() {
        let registry = ConnRegistry::new();
        let (conn_id, _rx) = registry.register().await;
        let (writer_tx_a, _writer_rx_a) = tokio::sync::mpsc::channel(8);
        let (writer_tx_b, _writer_rx_b) = tokio::sync::mpsc::channel(8);
        registry.register_writer(10, writer_tx_a).await;
        registry.register_writer(20, writer_tx_b).await;

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        assert!(
            registry
                .bind_writer(
                    conn_id,
                    10,
                    ConnMeta {
                        target_dc: 2,
                        client_addr: addr,
                        our_addr: addr,
                        proto_flags: 0,
                    },
                )
                .await
        );

        let non_empty = registry.non_empty_writer_ids(&[10, 20, 30]).await;
        assert!(non_empty.contains(&10));
        assert!(!non_empty.contains(&20));
        assert!(!non_empty.contains(&30));
    }
}
