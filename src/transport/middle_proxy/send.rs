use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::error::{ProxyError, Result};
use crate::protocol::constants::{RPC_CLOSE_EXT_U32};

use super::MePool;
use super::codec::RpcWriter;
use super::wire::build_proxy_req_payload;

impl MePool {
    pub async fn send_proxy_req(
        &self,
        conn_id: u64,
        target_dc: i16,
        client_addr: SocketAddr,
        our_addr: SocketAddr,
        data: &[u8],
        proto_flags: u32,
    ) -> Result<()> {
        let payload = build_proxy_req_payload(
            conn_id,
            client_addr,
            our_addr,
            data,
            self.proxy_tag.as_deref(),
            proto_flags,
        );

        loop {
            let ws = self.writers.read().await;
            if ws.is_empty() {
                return Err(ProxyError::Proxy("All ME connections dead".into()));
            }
            let writers: Vec<(SocketAddr, Arc<Mutex<RpcWriter>>)> = ws.iter().cloned().collect();
            drop(ws);

            let candidate_indices = self.candidate_indices_for_dc(&writers, target_dc).await;
            if candidate_indices.is_empty() {
                return Err(ProxyError::Proxy("No ME writers available for target DC".into()));
            }
            let start = self.rr.fetch_add(1, Ordering::Relaxed) as usize % candidate_indices.len();

            // Prefer immediately available writer to avoid waiting on stalled connection.
            for offset in 0..candidate_indices.len() {
                let cidx = (start + offset) % candidate_indices.len();
                let idx = candidate_indices[cidx];
                let w = writers[idx].1.clone();
                if let Ok(mut guard) = w.try_lock() {
                    let send_res = guard.send(&payload).await;
                    drop(guard);
                    match send_res {
                        Ok(()) => return Ok(()),
                        Err(e) => {
                            warn!(error = %e, "ME write failed, removing dead conn");
                            let mut ws = self.writers.write().await;
                            ws.retain(|(_, o)| !Arc::ptr_eq(o, &w));
                            if ws.is_empty() {
                                return Err(ProxyError::Proxy("All ME connections dead".into()));
                            }
                            continue;
                        }
                    }
                }
            }

            // All writers are currently busy, wait for the selected one.
            let w = writers[candidate_indices[start]].1.clone();
            match w.lock().await.send(&payload).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(error = %e, "ME write failed, removing dead conn");
                    let mut ws = self.writers.write().await;
                    ws.retain(|(_, o)| !Arc::ptr_eq(o, &w));
                    if ws.is_empty() {
                        return Err(ProxyError::Proxy("All ME connections dead".into()));
                    }
                }
            }
        }
    }

    pub async fn send_close(&self, conn_id: u64) -> Result<()> {
        let ws = self.writers.read().await;
        if !ws.is_empty() {
            let w = ws[0].1.clone();
            drop(ws);
            let mut p = Vec::with_capacity(12);
            p.extend_from_slice(&RPC_CLOSE_EXT_U32.to_le_bytes());
            p.extend_from_slice(&conn_id.to_le_bytes());
            if let Err(e) = w.lock().await.send(&p).await {
                debug!(error = %e, "ME close write failed");
                let mut ws = self.writers.write().await;
                ws.retain(|(_, o)| !Arc::ptr_eq(o, &w));
            }
        }

        self.registry.unregister(conn_id).await;
        Ok(())
    }

    pub fn connection_count(&self) -> usize {
        self.writers.try_read().map(|w| w.len()).unwrap_or(0)
    }
    
    pub(super) async fn candidate_indices_for_dc(
        &self,
        writers: &[(SocketAddr, Arc<Mutex<RpcWriter>>)],
        target_dc: i16,
    ) -> Vec<usize> {
        let mut preferred = Vec::<SocketAddr>::new();
        let key = target_dc as i32;
        let map = self.proxy_map_v4.read().await;

        if let Some(v) = map.get(&key) {
            preferred.extend(v.iter().map(|(ip, port)| SocketAddr::new(*ip, *port)));
        }
        if preferred.is_empty() {
            let abs = key.abs();
            if let Some(v) = map.get(&abs) {
                preferred.extend(v.iter().map(|(ip, port)| SocketAddr::new(*ip, *port)));
            }
        }
        if preferred.is_empty() {
            let abs = key.abs();
            if let Some(v) = map.get(&-abs) {
                preferred.extend(v.iter().map(|(ip, port)| SocketAddr::new(*ip, *port)));
            }
        }
        if preferred.is_empty() {
            let def = self.default_dc.load(Ordering::Relaxed);
            if def != 0 {
                if let Some(v) = map.get(&def) {
                    preferred.extend(v.iter().map(|(ip, port)| SocketAddr::new(*ip, *port)));
                }
            }
        }

        if preferred.is_empty() {
            return (0..writers.len()).collect();
        }

        let mut out = Vec::new();
        for (idx, (addr, _)) in writers.iter().enumerate() {
            if preferred.iter().any(|p| p == addr) {
                out.push(idx);
            }
        }
        if out.is_empty() {
            return (0..writers.len()).collect();
        }
        out
    }

}
