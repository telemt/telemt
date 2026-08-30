use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tokio::sync::{Mutex, Semaphore, mpsc};

use super::MeResponse;
use super::codec::WriterCommand;

const ROUTE_BACKPRESSURE_BASE_TIMEOUT_MS: u64 = 25;
const ROUTE_BACKPRESSURE_HIGH_TIMEOUT_MS: u64 = 120;
const ROUTE_BACKPRESSURE_HIGH_WATERMARK_PCT: u8 = 80;
const ROUTE_QUEUED_BYTE_PERMIT_UNIT: usize = 16 * 1024;
const ROUTE_QUEUED_PERMITS_PER_SLOT: usize = 4;
const ROUTE_QUEUED_MAX_FRAME_PERMITS: usize = 1024;

mod writer;

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
    /// Writer-local memory budget used by the hot bound-client route.
    pub byte_budget: Arc<Semaphore>,
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
    map: DashMap<u64, WriterRoute>,
}

#[derive(Clone)]
struct WriterRoute {
    tx: mpsc::Sender<WriterCommand>,
    byte_budget: Arc<Semaphore>,
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
    writer_idle_since_epoch_secs: DashMap<u64, u64>,
    bound_clients_by_writer: DashMap<u64, usize>,
    active_sessions_by_target_dc: DashMap<i16, usize>,
    last_meta_for_writer: DashMap<u64, ConnMeta>,
}

struct BindingInner {
    writer_for_conn: HashMap<u64, u64>,
    conns_for_writer: HashMap<u64, HashSet<u64>>,
    meta: HashMap<u64, ConnMeta>,
}

impl BindingInner {
    fn new() -> Self {
        Self {
            writer_for_conn: HashMap::new(),
            conns_for_writer: HashMap::new(),
            meta: HashMap::new(),
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
    cleanup_tx: mpsc::Sender<u64>,
    cleanup_rx: StdMutex<Option<mpsc::Receiver<u64>>>,
}

/// Cancellation-safe ownership of one registered ME client route.
pub(crate) struct ConnLease {
    registry: Arc<ConnRegistry>,
    conn_id: u64,
    cleanup_permit: Option<mpsc::OwnedPermit<u64>>,
}

impl ConnLease {
    /// Returns the stable connection identifier owned by this lease.
    pub(crate) fn conn_id(&self) -> u64 {
        self.conn_id
    }

    /// Completes asynchronous registry cleanup and disarms drop cleanup.
    pub(crate) async fn unregister(mut self) {
        self.registry.unregister(self.conn_id).await;
        self.cleanup_permit.take();
    }
}

impl Drop for ConnLease {
    fn drop(&mut self) {
        let Some(permit) = self.cleanup_permit.take() else {
            return;
        };
        self.registry.remove_route_now(self.conn_id);
        permit.send(self.conn_id);
    }
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
            16_384,
        )
    }

    pub(crate) fn with_route_and_cleanup_capacity(
        route_channel_capacity: usize,
        connection_cleanup_capacity: usize,
    ) -> Self {
        let route_channel_capacity = route_channel_capacity.max(1);
        Self::with_route_limits(
            route_channel_capacity,
            Self::route_byte_permit_budget(route_channel_capacity),
            connection_cleanup_capacity,
        )
    }

    fn with_route_limits(
        route_channel_capacity: usize,
        route_byte_permits_per_conn: usize,
        connection_cleanup_capacity: usize,
    ) -> Self {
        let start = rand::random::<u64>() | 1;
        let route_channel_capacity = route_channel_capacity.max(1);
        let (cleanup_tx, cleanup_rx) = mpsc::channel(connection_cleanup_capacity.max(1));
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
                writer_idle_since_epoch_secs: DashMap::new(),
                bound_clients_by_writer: DashMap::new(),
                active_sessions_by_target_dc: DashMap::new(),
                last_meta_for_writer: DashMap::new(),
            },
            next_id: AtomicU64::new(start),
            route_channel_capacity,
            route_backpressure_base_timeout_ms: AtomicU64::new(ROUTE_BACKPRESSURE_BASE_TIMEOUT_MS),
            route_backpressure_high_timeout_ms: AtomicU64::new(ROUTE_BACKPRESSURE_HIGH_TIMEOUT_MS),
            route_backpressure_high_watermark_pct: AtomicU8::new(
                ROUTE_BACKPRESSURE_HIGH_WATERMARK_PCT,
            ),
            route_byte_permits_per_conn: route_byte_permits_per_conn.max(1),
            cleanup_tx,
            cleanup_rx: StdMutex::new(Some(cleanup_rx)),
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
        Self::with_route_limits(route_channel_capacity, route_byte_permits_per_conn, 16_384)
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
        self.register_route()
    }

    pub(crate) async fn register_leased(
        self: &Arc<Self>,
    ) -> Option<(ConnLease, mpsc::Receiver<MeResponse>)> {
        let cleanup_permit = self.cleanup_tx.clone().reserve_owned().await.ok()?;
        let (conn_id, rx) = self.register_route();
        Some((
            ConnLease {
                registry: Arc::clone(self),
                conn_id,
                cleanup_permit: Some(cleanup_permit),
            },
            rx,
        ))
    }

    pub(super) fn take_cleanup_receiver(&self) -> Option<mpsc::Receiver<u64>> {
        self.cleanup_rx.lock().ok()?.take()
    }

    fn register_route(&self) -> (u64, mpsc::Receiver<MeResponse>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(self.route_channel_capacity);
        self.routing.map.insert(id, tx);
        self.routing.byte_budget.insert(
            id,
            Arc::new(Semaphore::new(self.route_byte_permits_per_conn)),
        );
        (id, rx)
    }

    fn remove_route_now(&self, id: u64) {
        self.routing.map.remove(&id);
        self.routing.byte_budget.remove(&id);
        self.hot_binding.map.remove(&id);
    }
}

#[cfg(test)]
mod tests;
