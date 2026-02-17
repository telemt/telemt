use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex, RwLock};

use super::codec::RpcWriter;
use super::MeResponse;

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
    pub writer: Arc<Mutex<RpcWriter>>,
}

pub struct ConnRegistry {
    map: RwLock<HashMap<u64, mpsc::Sender<MeResponse>>>,
    writers: RwLock<HashMap<u64, Arc<Mutex<RpcWriter>>>>,
    writer_for_conn: RwLock<HashMap<u64, u64>>,
    conns_for_writer: RwLock<HashMap<u64, Vec<u64>>>,
    meta: RwLock<HashMap<u64, ConnMeta>>,
    next_id: AtomicU64,
}

impl ConnRegistry {
    pub fn new() -> Self {
        let start = rand::random::<u64>() | 1;
        Self {
            map: RwLock::new(HashMap::new()),
            writers: RwLock::new(HashMap::new()),
            writer_for_conn: RwLock::new(HashMap::new()),
            conns_for_writer: RwLock::new(HashMap::new()),
            meta: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(start),
        }
    }

    pub async fn register(&self) -> (u64, mpsc::Receiver<MeResponse>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(1024);
        self.map.write().await.insert(id, tx);
        (id, rx)
    }

    pub async fn unregister(&self, id: u64) {
        self.map.write().await.remove(&id);
        self.meta.write().await.remove(&id);
        if let Some(writer_id) = self.writer_for_conn.write().await.remove(&id) {
            if let Some(list) = self.conns_for_writer.write().await.get_mut(&writer_id) {
                list.retain(|c| *c != id);
            }
        }
    }

    pub async fn route(&self, id: u64, resp: MeResponse) -> bool {
        let m = self.map.read().await;
        if let Some(tx) = m.get(&id) {
            tx.try_send(resp).is_ok()
        } else {
            false
        }
    }

    pub async fn bind_writer(
        &self,
        conn_id: u64,
        writer_id: u64,
        writer: Arc<Mutex<RpcWriter>>,
        meta: ConnMeta,
    ) {
        self.meta.write().await.entry(conn_id).or_insert(meta);
        self.writer_for_conn.write().await.insert(conn_id, writer_id);
        self.writers.write().await.entry(writer_id).or_insert_with(|| writer.clone());
        self.conns_for_writer
            .write()
            .await
            .entry(writer_id)
            .or_insert_with(Vec::new)
            .push(conn_id);
    }

    pub async fn get_writer(&self, conn_id: u64) -> Option<ConnWriter> {
        let writer_id = {
            let guard = self.writer_for_conn.read().await;
            guard.get(&conn_id).cloned()
        }?;
        let writer = {
            let guard = self.writers.read().await;
            guard.get(&writer_id).cloned()
        }?;
        Some(ConnWriter { writer_id, writer })
    }

    pub async fn writer_lost(&self, writer_id: u64) -> Vec<BoundConn> {
        self.writers.write().await.remove(&writer_id);
        let conns = self.conns_for_writer.write().await.remove(&writer_id).unwrap_or_default();

        let mut out = Vec::new();
        let mut writer_for_conn = self.writer_for_conn.write().await;
        let meta = self.meta.read().await;

        for conn_id in conns {
            writer_for_conn.remove(&conn_id);
            if let Some(m) = meta.get(&conn_id) {
                out.push(BoundConn {
                    conn_id,
                    meta: m.clone(),
                });
            }
        }
        out
    }

    pub async fn get_meta(&self, conn_id: u64) -> Option<ConnMeta> {
        let guard = self.meta.read().await;
        guard.get(&conn_id).cloned()
    }
}
