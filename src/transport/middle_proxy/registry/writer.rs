use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use super::super::codec::WriterCommand;
use super::super::{MeResponse, RouteBytePermit};
use super::{
    BoundConn, ConnMeta, ConnRegistry, ConnWriter, HotConnBinding, RouteResult,
    WriterActivitySnapshot,
};

impl ConnRegistry {
    fn set_writer_bound_count(&self, writer_id: u64, count: usize) {
        self.binding
            .bound_clients_by_writer
            .insert(writer_id, count);
        if count == 0 {
            self.binding
                .writer_idle_since_epoch_secs
                .entry(writer_id)
                .or_insert_with(Self::now_epoch_secs);
        } else {
            self.binding.writer_idle_since_epoch_secs.remove(&writer_id);
        }
    }

    fn adjust_active_target_dc(&self, target_dc: i16, delta: isize) {
        if target_dc == 0 || delta == 0 {
            return;
        }
        if delta > 0 {
            self.binding
                .active_sessions_by_target_dc
                .entry(target_dc)
                .and_modify(|count| *count = count.saturating_add(delta as usize))
                .or_insert(delta as usize);
            return;
        }

        let remove = if let Some(mut count) = self
            .binding
            .active_sessions_by_target_dc
            .get_mut(&target_dc)
        {
            let decrement = delta.unsigned_abs();
            *count = count.saturating_sub(decrement);
            *count == 0
        } else {
            false
        };
        if remove {
            self.binding.active_sessions_by_target_dc.remove(&target_dc);
        }
    }

    pub async fn register_writer(&self, writer_id: u64, tx: mpsc::Sender<WriterCommand>) {
        let mut binding = self.binding.inner.lock().await;
        binding
            .conns_for_writer
            .entry(writer_id)
            .or_insert_with(HashSet::new);
        self.binding
            .bound_clients_by_writer
            .entry(writer_id)
            .or_insert(0);
        self.binding
            .writer_idle_since_epoch_secs
            .entry(writer_id)
            .or_insert_with(Self::now_epoch_secs);
        self.writers.map.insert(writer_id, tx);
    }

    /// Unregister connection, returning associated writer_id if any.
    pub async fn unregister(&self, id: u64) -> Option<u64> {
        self.routing.map.remove(&id);
        self.routing.byte_budget.remove(&id);
        self.hot_binding.map.remove(&id);
        let mut binding = self.binding.inner.lock().await;
        let previous_meta = binding.meta.remove(&id);
        if let Some(meta) = previous_meta.as_ref() {
            self.adjust_active_target_dc(meta.target_dc, -1);
        }
        if let Some(writer_id) = binding.writer_for_conn.remove(&id) {
            let next_count = if let Some(set) = binding.conns_for_writer.get_mut(&writer_id) {
                set.remove(&id);
                set.len()
            } else {
                0
            };
            self.set_writer_bound_count(writer_id, next_count);
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
        if !self.writers.map.contains_key(&writer_id) {
            return false;
        }

        let previous_writer_id = binding.writer_for_conn.insert(conn_id, writer_id);
        if let Some(previous_writer_id) = previous_writer_id
            && previous_writer_id != writer_id
        {
            let next_count =
                if let Some(set) = binding.conns_for_writer.get_mut(&previous_writer_id) {
                    set.remove(&conn_id);
                    set.len()
                } else {
                    0
                };
            self.set_writer_bound_count(previous_writer_id, next_count);
        }

        if let Some(previous_meta) = binding.meta.insert(conn_id, meta.clone()) {
            self.adjust_active_target_dc(previous_meta.target_dc, -1);
        }
        self.adjust_active_target_dc(meta.target_dc, 1);
        self.binding
            .last_meta_for_writer
            .insert(writer_id, meta.clone());
        let next_count = {
            let set = binding
                .conns_for_writer
                .entry(writer_id)
                .or_insert_with(HashSet::new);
            set.insert(conn_id);
            set.len()
        };
        self.set_writer_bound_count(writer_id, next_count);
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
        let count = binding
            .conns_for_writer
            .get(&writer_id)
            .map(|set| set.len())
            .unwrap_or(0);
        self.set_writer_bound_count(writer_id, count);
    }

    pub async fn get_last_writer_meta(&self, writer_id: u64) -> Option<ConnMeta> {
        self.binding
            .last_meta_for_writer
            .get(&writer_id)
            .map(|entry| entry.value().clone())
    }

    pub async fn writer_idle_since_snapshot(&self) -> HashMap<u64, u64> {
        self.binding
            .writer_idle_since_epoch_secs
            .iter()
            .map(|entry| (*entry.key(), *entry.value()))
            .collect()
    }

    pub async fn writer_idle_since_for_writer_ids(&self, writer_ids: &[u64]) -> HashMap<u64, u64> {
        let mut out = HashMap::<u64, u64>::with_capacity(writer_ids.len());
        for writer_id in writer_ids {
            if let Some(idle_since) = self
                .binding
                .writer_idle_since_epoch_secs
                .get(writer_id)
                .map(|entry| *entry.value())
            {
                out.insert(*writer_id, idle_since);
            }
        }
        out
    }

    pub(in crate::transport::middle_proxy) async fn writer_activity_snapshot(
        &self,
    ) -> WriterActivitySnapshot {
        WriterActivitySnapshot {
            bound_clients_by_writer: self
                .binding
                .bound_clients_by_writer
                .iter()
                .map(|entry| (*entry.key(), *entry.value()))
                .collect(),
            active_sessions_by_target_dc: self
                .binding
                .active_sessions_by_target_dc
                .iter()
                .map(|entry| (*entry.key(), *entry.value()))
                .collect(),
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

    /// Returns the active writer and routing metadata from one hot-binding lookup.
    pub async fn get_writer_with_meta(&self, conn_id: u64) -> Option<(ConnWriter, ConnMeta)> {
        if !self.routing.map.contains_key(&conn_id) {
            return None;
        }

        let hot = self.hot_binding.map.get(&conn_id)?;
        let writer_id = hot.writer_id;
        let meta = hot.meta.clone();
        let writer = self
            .writers
            .map
            .get(&writer_id)
            .map(|entry| entry.value().clone())?;
        Some((
            ConnWriter {
                writer_id,
                tx: writer,
            },
            meta,
        ))
    }

    pub async fn active_conn_ids(&self) -> Vec<u64> {
        let binding = self.binding.inner.lock().await;
        binding.writer_for_conn.keys().copied().collect()
    }

    pub async fn writer_lost(&self, writer_id: u64) -> Vec<BoundConn> {
        let mut binding = self.binding.inner.lock().await;
        self.writers.map.remove(&writer_id);
        self.binding.last_meta_for_writer.remove(&writer_id);
        self.binding.writer_idle_since_epoch_secs.remove(&writer_id);
        self.binding.bound_clients_by_writer.remove(&writer_id);
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
            let meta = binding.meta.remove(&conn_id);
            if let Some(meta) = meta.as_ref() {
                self.adjust_active_target_dc(meta.target_dc, -1);
            }
            let remove_hot = self
                .hot_binding
                .map
                .get(&conn_id)
                .map(|hot| hot.writer_id == writer_id)
                .unwrap_or(false);
            if remove_hot {
                self.hot_binding.map.remove(&conn_id);
            }
            if let Some(m) = meta {
                out.push(BoundConn { conn_id, meta: m });
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
        self.binding
            .bound_clients_by_writer
            .get(&writer_id)
            .map(|count| *count.value() == 0)
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

        self.writers.map.remove(&writer_id);
        self.binding.last_meta_for_writer.remove(&writer_id);
        self.binding.writer_idle_since_epoch_secs.remove(&writer_id);
        self.binding.bound_clients_by_writer.remove(&writer_id);
        binding.conns_for_writer.remove(&writer_id);
        true
    }

    #[allow(dead_code)]
    pub(super) async fn non_empty_writer_ids(&self, writer_ids: &[u64]) -> HashSet<u64> {
        let mut out = HashSet::<u64>::with_capacity(writer_ids.len());
        for writer_id in writer_ids {
            if let Some(count) = self.binding.bound_clients_by_writer.get(writer_id)
                && *count.value() > 0
            {
                out.insert(*writer_id);
            }
        }
        out
    }
}
