use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{mpsc, RwLock};
use tokio::sync::mpsc::error::TrySendError;

use super::codec::WriterCommand;
use super::MeResponse;

const ROUTE_CHANNEL_CAPACITY: usize = 4096;
const ROUTE_BACKPRESSURE_TIMEOUT: Duration = Duration::from_millis(25);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteResult {
    Routed,
    NoConn,
    ChannelClosed,
    QueueFull,
}

#[derive(Clone)]
pub struct ConnMeta {
    pub target_dc: i16,
    pub client_addr: SocketAddr,
    pub our_addr: SocketAddr,
    pub proto_flags: u32,
}

#[derive(Clone)]
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
}

impl ConnRegistry {
    pub fn new() -> Self {
        let start = rand::random::<u64>() | 1;
        Self {
            inner: RwLock::new(RegistryInner::new()),
            next_id: AtomicU64::new(start),
        }
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
                match tokio::time::timeout(ROUTE_BACKPRESSURE_TIMEOUT, tx.send(resp)).await {
                    Ok(Ok(())) => RouteResult::Routed,
                    Ok(Err(_)) => RouteResult::ChannelClosed,
                    Err(_) => RouteResult::QueueFull,
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
