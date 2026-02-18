use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tracing::{debug, warn};

use crate::error::{ProxyError, Result};
use crate::network::IpFamily;
use crate::protocol::constants::RPC_CLOSE_EXT_U32;

use super::MePool;
use super::wire::build_proxy_req_payload;
use rand::seq::SliceRandom;
use super::registry::ConnMeta;

impl MePool {
    pub async fn send_proxy_req(
        self: &Arc<Self>,
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
        let meta = ConnMeta {
            target_dc,
            client_addr,
            our_addr,
            proto_flags,
        };
        let mut emergency_attempts = 0;

        loop {
            if let Some(current) = self.registry.get_writer(conn_id).await {
                let send_res = {
                    if let Ok(mut guard) = current.writer.try_lock() {
                        let r = guard.send(&payload).await;
                        drop(guard);
                        r
                    } else {
                        current.writer.lock().await.send(&payload).await
                    }
                };
                match send_res {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        warn!(error = %e, writer_id = current.writer_id, "ME write failed");
                        self.remove_writer_and_reroute(current.writer_id).await;
                        continue;
                    }
                }
            }

            let mut writers_snapshot = {
                let ws = self.writers.read().await;
                if ws.is_empty() {
                    return Err(ProxyError::Proxy("All ME connections dead".into()));
                }
                ws.clone()
            };

            let mut candidate_indices = self.candidate_indices_for_dc(&writers_snapshot, target_dc).await;
            if candidate_indices.is_empty() {
                // Emergency connect-on-demand
                if emergency_attempts >= 3 {
                    return Err(ProxyError::Proxy("No ME writers available for target DC".into()));
                }
                emergency_attempts += 1;
                let map = self.proxy_map_v4.read().await;
                if let Some(addrs) = map.get(&(target_dc as i32)) {
                    let mut shuffled = addrs.clone();
                    shuffled.shuffle(&mut rand::rng());
                    drop(map);
                    for (ip, port) in shuffled {
                        let addr = SocketAddr::new(ip, port);
                        if self.connect_one(addr, self.rng.as_ref()).await.is_ok() {
                            break;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(100 * emergency_attempts)).await;
                    let ws2 = self.writers.read().await;
                    writers_snapshot = ws2.clone();
                    drop(ws2);
                    candidate_indices = self.candidate_indices_for_dc(&writers_snapshot, target_dc).await;
                }
                if candidate_indices.is_empty() {
                    return Err(ProxyError::Proxy("No ME writers available for target DC".into()));
                }
            }

            candidate_indices.sort_by_key(|idx| {
                writers_snapshot[*idx]
                    .degraded
                    .load(Ordering::Relaxed)
                    .then_some(1usize)
                    .unwrap_or(0)
            });

            let start = self.rr.fetch_add(1, Ordering::Relaxed) as usize % candidate_indices.len();

            for offset in 0..candidate_indices.len() {
                let idx = candidate_indices[(start + offset) % candidate_indices.len()];
                let w = &writers_snapshot[idx];
                if let Ok(mut guard) = w.writer.try_lock() {
                    let send_res = guard.send(&payload).await;
                    drop(guard);
                    match send_res {
                        Ok(()) => {
                            self.registry
                                .bind_writer(conn_id, w.id, w.writer.clone(), meta.clone())
                                .await;
                            return Ok(());
                        }
                        Err(e) => {
                            warn!(error = %e, writer_id = w.id, "ME write failed");
                            self.remove_writer_and_reroute(w.id).await;
                            continue;
                        }
                    }
                }
            }

            let w = writers_snapshot[candidate_indices[start]].clone();
            match w.writer.lock().await.send(&payload).await {
                Ok(()) => {
                    self.registry
                        .bind_writer(conn_id, w.id, w.writer.clone(), meta.clone())
                        .await;
                    return Ok(());
                }
                Err(e) => {
                    warn!(error = %e, writer_id = w.id, "ME write failed (blocking)");
                    self.remove_writer_and_reroute(w.id).await;
                }
            }
        }
    }

    pub async fn send_close(self: &Arc<Self>, conn_id: u64) -> Result<()> {
        if let Some(w) = self.registry.get_writer(conn_id).await {
            let mut p = Vec::with_capacity(12);
            p.extend_from_slice(&RPC_CLOSE_EXT_U32.to_le_bytes());
            p.extend_from_slice(&conn_id.to_le_bytes());
            if let Err(e) = w.writer.lock().await.send(&p).await {
                debug!(error = %e, "ME close write failed");
                self.remove_writer_and_reroute(w.writer_id).await;
            }
        } else {
            debug!(conn_id, "ME close skipped (writer missing)");
        }

        self.registry.unregister(conn_id).await;
        Ok(())
    }

    pub fn connection_count(&self) -> usize {
        self.writers.try_read().map(|w| w.len()).unwrap_or(0)
    }
    
    pub(super) async fn candidate_indices_for_dc(
        &self,
        writers: &[super::pool::MeWriter],
        target_dc: i16,
    ) -> Vec<usize> {
        let key = target_dc as i32;
        let mut preferred = Vec::<SocketAddr>::new();

        for family in self.family_order() {
            let map_guard = match family {
                IpFamily::V4 => self.proxy_map_v4.read().await,
                IpFamily::V6 => self.proxy_map_v6.read().await,
            };

            if let Some(v) = map_guard.get(&key) {
                preferred.extend(v.iter().map(|(ip, port)| SocketAddr::new(*ip, *port)));
            }
            if preferred.is_empty() {
                let abs = key.abs();
                if let Some(v) = map_guard.get(&abs) {
                    preferred.extend(v.iter().map(|(ip, port)| SocketAddr::new(*ip, *port)));
                }
            }
            if preferred.is_empty() {
                let abs = key.abs();
                if let Some(v) = map_guard.get(&-abs) {
                    preferred.extend(v.iter().map(|(ip, port)| SocketAddr::new(*ip, *port)));
                }
            }
            if preferred.is_empty() {
                let def = self.default_dc.load(Ordering::Relaxed);
                if def != 0 {
                    if let Some(v) = map_guard.get(&def) {
                        preferred.extend(v.iter().map(|(ip, port)| SocketAddr::new(*ip, *port)));
                    }
                }
            }

            drop(map_guard);

            if !preferred.is_empty() && !self.decision.effective_multipath {
                break;
            }
        }

        if preferred.is_empty() {
            return (0..writers.len()).collect();
        }

        let mut out = Vec::new();
        for (idx, w) in writers.iter().enumerate() {
            if preferred.iter().any(|p| *p == w.addr) {
                out.push(idx);
            }
        }
        if out.is_empty() {
            return (0..writers.len()).collect();
        }
        out
    }

}
