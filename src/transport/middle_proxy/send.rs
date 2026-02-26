use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tracing::{debug, warn};

use crate::error::{ProxyError, Result};
use crate::network::IpFamily;
use crate::protocol::constants::RPC_CLOSE_EXT_U32;

use super::MePool;
use super::codec::WriterCommand;
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
                    current
                        .tx
                        .send(WriterCommand::Data(payload.clone()))
                        .await
                };
                match send_res {
                    Ok(()) => return Ok(()),
                    Err(_) => {
                        warn!(writer_id = current.writer_id, "ME writer channel closed");
                        self.remove_writer_and_close_clients(current.writer_id).await;
                        continue;
                    }
                }
            }

            let mut writers_snapshot = {
                let ws = self.writers.read().await;
                if ws.is_empty() {
                    // Create waiter before recovery attempts so notify_one permits are not missed.
                    let waiter = self.writer_available.notified();
                    drop(ws);
                    for family in self.family_order() {
                        let map = match family {
                            IpFamily::V4 => self.proxy_map_v4.read().await.clone(),
                            IpFamily::V6 => self.proxy_map_v6.read().await.clone(),
                        };
                        for (_dc, addrs) in map.iter() {
                            for (ip, port) in addrs {
                                let addr = SocketAddr::new(*ip, *port);
                                if self.connect_one(addr, self.rng.as_ref()).await.is_ok() {
                                    self.writer_available.notify_one();
                                    break;
                                }
                            }
                        }
                    }
                    if !self.writers.read().await.is_empty() {
                        continue;
                    }
                    if tokio::time::timeout(Duration::from_secs(3), waiter).await.is_err() {
                        if !self.writers.read().await.is_empty() {
                            continue;
                        }
                        return Err(ProxyError::Proxy("All ME connections dead (waited 3s)".into()));
                    }
                    continue;
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
                for family in self.family_order() {
                    let map_guard = match family {
                        IpFamily::V4 => self.proxy_map_v4.read().await,
                        IpFamily::V6 => self.proxy_map_v6.read().await,
                    };
                    if let Some(addrs) = map_guard.get(&(target_dc as i32)) {
                        let mut shuffled = addrs.clone();
                        shuffled.shuffle(&mut rand::rng());
                        drop(map_guard);
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
                        if !candidate_indices.is_empty() {
                            break;
                        }
                    }
                }
                if candidate_indices.is_empty() {
                    return Err(ProxyError::Proxy("No ME writers available for target DC".into()));
                }
            }

            candidate_indices.sort_by_key(|idx| {
                let w = &writers_snapshot[*idx];
                let degraded = w.degraded.load(Ordering::Relaxed);
                let stale = (w.generation < self.current_generation()) as usize;
                (stale, degraded as usize)
            });

            let start = self.rr.fetch_add(1, Ordering::Relaxed) as usize % candidate_indices.len();

            for offset in 0..candidate_indices.len() {
                let idx = candidate_indices[(start + offset) % candidate_indices.len()];
                let w = &writers_snapshot[idx];
                if !self.writer_accepts_new_binding(w) {
                    continue;
                }
                if w.tx.send(WriterCommand::Data(payload.clone())).await.is_ok() {
                    self.registry
                        .bind_writer(conn_id, w.id, w.tx.clone(), meta.clone())
                        .await;
                    if w.generation < self.current_generation() {
                        self.stats.increment_pool_stale_pick_total();
                        debug!(
                            conn_id,
                            writer_id = w.id,
                            writer_generation = w.generation,
                            current_generation = self.current_generation(),
                            "Selected stale ME writer for fallback bind"
                        );
                    }
                    return Ok(());
                } else {
                    warn!(writer_id = w.id, "ME writer channel closed");
                    self.remove_writer_and_close_clients(w.id).await;
                    continue;
                }
            }

            let w = writers_snapshot[candidate_indices[start]].clone();
            if !self.writer_accepts_new_binding(&w) {
                continue;
            }
            match w.tx.send(WriterCommand::Data(payload.clone())).await {
                Ok(()) => {
                    self.registry
                        .bind_writer(conn_id, w.id, w.tx.clone(), meta.clone())
                        .await;
                    if w.generation < self.current_generation() {
                        self.stats.increment_pool_stale_pick_total();
                    }
                    return Ok(());
                }
                Err(_) => {
                    warn!(writer_id = w.id, "ME writer channel closed (blocking)");
                    self.remove_writer_and_close_clients(w.id).await;
                }
            }
        }
    }

    pub async fn send_close(self: &Arc<Self>, conn_id: u64) -> Result<()> {
        if let Some(w) = self.registry.get_writer(conn_id).await {
            let mut p = Vec::with_capacity(12);
            p.extend_from_slice(&RPC_CLOSE_EXT_U32.to_le_bytes());
            p.extend_from_slice(&conn_id.to_le_bytes());
            if w.tx.send(WriterCommand::DataAndFlush(p)).await.is_err() {
                debug!("ME close write failed");
                self.remove_writer_and_close_clients(w.writer_id).await;
            }
        } else {
            debug!(conn_id, "ME close skipped (writer missing)");
        }

        self.registry.unregister(conn_id).await;
        Ok(())
    }

    pub fn connection_count(&self) -> usize {
        self.conn_count.load(Ordering::Relaxed)
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
                if def != 0
                    && let Some(v) = map_guard.get(&def)
                {
                    preferred.extend(v.iter().map(|(ip, port)| SocketAddr::new(*ip, *port)));
                }
            }

            drop(map_guard);

            if !preferred.is_empty() && !self.decision.effective_multipath {
                break;
            }
        }

        if preferred.is_empty() {
            return (0..writers.len())
                .filter(|i| self.writer_accepts_new_binding(&writers[*i]))
                .collect();
        }

        let mut out = Vec::new();
        for (idx, w) in writers.iter().enumerate() {
            if !self.writer_accepts_new_binding(w) {
                continue;
            }
            if preferred.contains(&w.addr) {
                out.push(idx);
            }
        }
        if out.is_empty() {
            return (0..writers.len())
                .filter(|i| self.writer_accepts_new_binding(&writers[*i]))
                .collect();
        }
        out
    }

}
