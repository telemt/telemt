use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{RwLock, mpsc};

use super::MeResponse;
use super::codec::RpcWriter;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct ConnRegistry {
    map: RwLock<HashMap<u64, mpsc::UnboundedSender<MeResponse>>>,
    writers: RwLock<HashMap<u64, Arc<Mutex<RpcWriter>>>>,
    next_id: AtomicU64,
}

impl ConnRegistry {
    pub fn new() -> Self {
        // Avoid fully predictable conn_id sequence from 1.
        let start = rand::random::<u64>() | 1;
        Self {
            map: RwLock::new(HashMap::new()),
            writers: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(start),
        }
    }

    pub async fn register(&self) -> (u64, mpsc::UnboundedReceiver<MeResponse>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        // Unbounded per-connection queue prevents reader-loop HOL blocking on
        // slow clients: routing stays non-blocking and preserves message order.
        let (tx, rx) = mpsc::unbounded_channel();
        self.map.write().await.insert(id, tx);
        (id, rx)
    }

    pub async fn unregister(&self, id: u64) {
        self.map.write().await.remove(&id);
        self.writers.write().await.remove(&id);
    }

    pub async fn route(&self, id: u64, resp: MeResponse) -> bool {
        let m = self.map.read().await;
        if let Some(tx) = m.get(&id) {
            tx.send(resp).is_ok()
        } else {
            false
        }
    }

    pub async fn set_writer(&self, id: u64, w: Arc<Mutex<RpcWriter>>) {
        let mut guard = self.writers.write().await;
        guard.entry(id).or_insert_with(|| w);
    }

    pub async fn get_writer(&self, id: u64) -> Option<Arc<Mutex<RpcWriter>>> {
        let guard = self.writers.read().await;
        guard.get(&id).cloned()
    }
}
