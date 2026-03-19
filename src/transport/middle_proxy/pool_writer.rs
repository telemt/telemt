use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::io::ErrorKind;

use bytes::Bytes;
use bytes::BytesMut;
use rand::Rng;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::MeBindStaleMode;
use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::protocol::constants::{RPC_CLOSE_EXT_U32, RPC_PING_U32};

use super::codec::{RpcWriter, WriterCommand};
use super::pool::{MePool, MeWriter, WriterContour};
use super::reader::reader_loop;
use super::registry::BoundConn;
use super::wire::build_proxy_req_payload;

const ME_ACTIVE_PING_SECS: u64 = 25;
const ME_ACTIVE_PING_JITTER_SECS: i64 = 5;
const ME_IDLE_KEEPALIVE_MAX_SECS: u64 = 5;
const ME_RPC_PROXY_REQ_RESPONSE_WAIT_MS: u64 = 700;

fn is_me_peer_closed_error(error: &ProxyError) -> bool {
    matches!(error, ProxyError::Io(ioe) if ioe.kind() == ErrorKind::UnexpectedEof)
}

impl MePool {
    pub(crate) async fn prune_closed_writers(self: &Arc<Self>) {
        let closed_writer_ids: Vec<u64> = {
            let ws = self.writers.read().await;
            ws.iter().filter(|w| w.tx.is_closed()).map(|w| w.id).collect()
        };
        if closed_writer_ids.is_empty() {
            return;
        }

        for writer_id in closed_writer_ids {
            if self.registry.is_writer_empty(writer_id).await {
                let _ = self.remove_writer_only(writer_id).await;
            } else {
                let _ = self.remove_writer_and_close_clients(writer_id).await;
            }
        }
    }

    pub(crate) async fn connect_one_for_dc(
        self: &Arc<Self>,
        addr: SocketAddr,
        writer_dc: i32,
        rng: &SecureRandom,
    ) -> Result<()> {
        self.connect_one_with_generation_contour(
            addr,
            rng,
            self.current_generation(),
            WriterContour::Active,
            writer_dc,
        )
        .await
    }

    pub(super) async fn connect_one_with_generation_contour(
        self: &Arc<Self>,
        addr: SocketAddr,
        rng: &SecureRandom,
        generation: u64,
        contour: WriterContour,
        writer_dc: i32,
    ) -> Result<()> {
        self.connect_one_with_generation_contour_for_dc(addr, rng, generation, contour, writer_dc)
            .await
    }

    pub(super) async fn connect_one_with_generation_contour_for_dc(
        self: &Arc<Self>,
        addr: SocketAddr,
        rng: &SecureRandom,
        generation: u64,
        contour: WriterContour,
        writer_dc: i32,
    ) -> Result<()> {
        self.connect_one_with_generation_contour_for_dc_with_cap_policy(
            addr,
            rng,
            generation,
            contour,
            writer_dc,
            false,
        )
        .await
    }

    pub(super) async fn connect_one_with_generation_contour_for_dc_with_cap_policy(
        self: &Arc<Self>,
        addr: SocketAddr,
        rng: &SecureRandom,
        generation: u64,
        contour: WriterContour,
        writer_dc: i32,
        allow_coverage_override: bool,
    ) -> Result<()> {
        if !self
            .can_open_writer_for_contour(contour, allow_coverage_override)
            .await
        {
            return Err(ProxyError::Proxy(format!(
                "ME {contour:?} writer cap reached"
            )));
        }

        let secret_len = self.proxy_secret.read().await.secret.len();
        if secret_len < 32 {
            return Err(ProxyError::Proxy("proxy-secret too short for ME auth".into()));
        }

        let dc_idx = i16::try_from(writer_dc).ok();
        let (stream, _connect_ms, upstream_egress) = self.connect_tcp(addr, dc_idx).await?;
        let hs = self.handshake_only(stream, addr, upstream_egress, rng).await?;

        let writer_id = self.next_writer_id.fetch_add(1, Ordering::Relaxed);
        let contour = Arc::new(AtomicU8::new(contour.as_u8()));
        let cancel = CancellationToken::new();
        let degraded = Arc::new(AtomicBool::new(false));
        let rtt_ema_ms_x10 = Arc::new(AtomicU32::new(0));
        let draining = Arc::new(AtomicBool::new(false));
        let draining_started_at_epoch_secs = Arc::new(AtomicU64::new(0));
        let drain_deadline_epoch_secs = Arc::new(AtomicU64::new(0));
        let allow_drain_fallback = Arc::new(AtomicBool::new(false));
        let (tx, mut rx) = mpsc::channel::<WriterCommand>(self.writer_cmd_channel_capacity);
        let mut rpc_writer = RpcWriter {
            writer: hs.wr,
            key: hs.write_key,
            iv: hs.write_iv,
            seq_no: 0,
            crc_mode: hs.crc_mode,
        };
        let cancel_wr = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    cmd = rx.recv() => {
                        match cmd {
                            Some(WriterCommand::Data(payload)) => {
                                if rpc_writer.send(&payload).await.is_err() { break; }
                            }
                            Some(WriterCommand::DataAndFlush(payload)) => {
                                if rpc_writer.send_and_flush(&payload).await.is_err() { break; }
                            }
                            Some(WriterCommand::Close) | None => break,
                        }
                    }
                    _ = cancel_wr.cancelled() => break,
                }
            }
        });
        let writer = MeWriter {
            id: writer_id,
            addr,
            source_ip: hs.source_ip,
            writer_dc,
            generation,
            contour: contour.clone(),
            created_at: Instant::now(),
            tx: tx.clone(),
            cancel: cancel.clone(),
            degraded: degraded.clone(),
            rtt_ema_ms_x10: rtt_ema_ms_x10.clone(),
            draining: draining.clone(),
            draining_started_at_epoch_secs: draining_started_at_epoch_secs.clone(),
            drain_deadline_epoch_secs: drain_deadline_epoch_secs.clone(),
            allow_drain_fallback: allow_drain_fallback.clone(),
        };
        self.writers.write().await.push(writer.clone());
        self.registry.register_writer(writer_id, tx.clone()).await;
        self.registry.mark_writer_idle(writer_id).await;
        self.conn_count.fetch_add(1, Ordering::Relaxed);
        self.writer_available.notify_one();

        let reg = self.registry.clone();
        let writers_arc = self.writers_arc();
        let ping_tracker = self.ping_tracker.clone();
        let ping_tracker_reader = ping_tracker.clone();
        let rtt_stats = self.rtt_stats.clone();
        let stats_reader = self.stats.clone();
        let stats_reader_close = self.stats.clone();
        let stats_ping = self.stats.clone();
        let pool = Arc::downgrade(self);
        let cancel_ping = cancel.clone();
        let tx_ping = tx.clone();
        let ping_tracker_ping = ping_tracker.clone();
        let cleanup_done = Arc::new(AtomicBool::new(false));
        let cleanup_for_reader = cleanup_done.clone();
        let cleanup_for_ping = cleanup_done.clone();
        let keepalive_enabled = self.me_keepalive_enabled;
        let keepalive_interval = self.me_keepalive_interval;
        let keepalive_jitter = self.me_keepalive_jitter;
        let rpc_proxy_req_every_secs = self.rpc_proxy_req_every_secs.load(Ordering::Relaxed);
        let tx_signal = tx.clone();
        let stats_signal = self.stats.clone();
        let cancel_signal = cancel.clone();
        let cleanup_for_signal = cleanup_done.clone();
        let pool_signal = Arc::downgrade(self);
        let keepalive_jitter_signal = self.me_keepalive_jitter;
        let cancel_reader_token = cancel.clone();
        let cancel_ping_token = cancel_ping.clone();
        let reader_route_data_wait_ms = self.me_reader_route_data_wait_ms.clone();

        tokio::spawn(async move {
            let res = reader_loop(
                hs.rd,
                hs.read_key,
                hs.read_iv,
                hs.crc_mode,
                reg.clone(),
                BytesMut::new(),
                BytesMut::new(),
                tx.clone(),
                ping_tracker_reader,
                rtt_stats.clone(),
                stats_reader,
                writer_id,
                degraded.clone(),
                rtt_ema_ms_x10.clone(),
                reader_route_data_wait_ms,
                cancel_reader_token.clone(),
            )
            .await;
            let idle_close_by_peer = if let Err(e) = res.as_ref() {
                is_me_peer_closed_error(e) && reg.is_writer_empty(writer_id).await
            } else {
                false
            };
            if idle_close_by_peer {
                stats_reader_close.increment_me_idle_close_by_peer_total();
                info!(writer_id, "ME socket closed by peer on idle writer");
            }
            if let Some(pool) = pool.upgrade()
                && cleanup_for_reader
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                pool.remove_writer_and_close_clients(writer_id).await;
            }
            if let Err(e) = res {
                if !idle_close_by_peer {
                    warn!(error = %e, "ME reader ended");
                }
            }
            let mut ws = writers_arc.write().await;
            ws.retain(|w| w.id != writer_id);
            info!(remaining = ws.len(), "Dead ME writer removed from pool");
        });

        let pool_ping = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut ping_id: i64 = rand::random::<i64>();
            let idle_interval_cap = Duration::from_secs(ME_IDLE_KEEPALIVE_MAX_SECS);
            // Per-writer jittered start to avoid phase sync.
            let startup_jitter = if keepalive_enabled {
                let mut interval = keepalive_interval;
                if let Some(pool) = pool_ping.upgrade() {
                    if pool.registry.is_writer_empty(writer_id).await {
                        interval = interval.min(idle_interval_cap);
                    }
                } else {
                    return;
                }
                let jitter_cap_ms = interval.as_millis() / 2;
                let effective_jitter_ms = keepalive_jitter.as_millis().min(jitter_cap_ms).max(1);
                Duration::from_millis(rand::rng().random_range(0..=effective_jitter_ms as u64))
            } else {
                let jitter = rand::rng().random_range(-ME_ACTIVE_PING_JITTER_SECS..=ME_ACTIVE_PING_JITTER_SECS);
                let wait = (ME_ACTIVE_PING_SECS as i64 + jitter).max(5) as u64;
                Duration::from_secs(wait)
            };
            tokio::select! {
                _ = cancel_ping_token.cancelled() => return,
                _ = tokio::time::sleep(startup_jitter) => {}
            }
            loop {
                let wait = if keepalive_enabled {
                    let mut interval = keepalive_interval;
                    if let Some(pool) = pool_ping.upgrade() {
                        if pool.registry.is_writer_empty(writer_id).await {
                            interval = interval.min(idle_interval_cap);
                        }
                    } else {
                        break;
                    }
                    let jitter_cap_ms = interval.as_millis() / 2;
                    let effective_jitter_ms = keepalive_jitter.as_millis().min(jitter_cap_ms).max(1);
                    interval + Duration::from_millis(rand::rng().random_range(0..=effective_jitter_ms as u64))
                } else {
                    let jitter = rand::rng().random_range(-ME_ACTIVE_PING_JITTER_SECS..=ME_ACTIVE_PING_JITTER_SECS);
                    let secs = (ME_ACTIVE_PING_SECS as i64 + jitter).max(5) as u64;
                    Duration::from_secs(secs)
                };
                tokio::select! {
                    _ = cancel_ping_token.cancelled() => {
                        break;
                    }
                    _ = tokio::time::sleep(wait) => {}
                }
                let sent_id = ping_id;
                let mut p = Vec::with_capacity(12);
                p.extend_from_slice(&RPC_PING_U32.to_le_bytes());
                p.extend_from_slice(&sent_id.to_le_bytes());
                let now_epoch_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let mut run_cleanup = false;
                if let Some(pool) = pool_ping.upgrade() {
                    let last_cleanup_ms = pool
                        .ping_tracker_last_cleanup_epoch_ms
                        .load(Ordering::Relaxed);
                    if now_epoch_ms.saturating_sub(last_cleanup_ms) >= 30_000
                        && pool
                            .ping_tracker_last_cleanup_epoch_ms
                            .compare_exchange(
                                last_cleanup_ms,
                                now_epoch_ms,
                                Ordering::AcqRel,
                                Ordering::Relaxed,
                            )
                            .is_ok()
                    {
                        run_cleanup = true;
                    }
                }
                ping_id = ping_id.wrapping_add(1);
                stats_ping.increment_me_keepalive_sent();
                if tx_ping
                    .send(WriterCommand::DataAndFlush(Bytes::from(p)))
                    .await
                    .is_err()
                {
                    stats_ping.increment_me_keepalive_failed();
                    debug!("ME ping failed, removing dead writer");
                    cancel_ping.cancel();
                    if let Some(pool) = pool_ping.upgrade()
                        && cleanup_for_ping
                            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                            .is_ok()
                    {
                        pool.remove_writer_and_close_clients(writer_id).await;
                    }
                    break;
                }
                let mut tracker = ping_tracker_ping.lock().await;
                if run_cleanup {
                    let before = tracker.len();
                    tracker.retain(|_, (ts, _)| ts.elapsed() < Duration::from_secs(120));
                    let expired = before.saturating_sub(tracker.len());
                    if expired > 0 {
                        stats_ping.increment_me_keepalive_timeout_by(expired as u64);
                    }
                }
                tracker.insert(sent_id, (std::time::Instant::now(), writer_id));
            }
        });

        tokio::spawn(async move {
            if rpc_proxy_req_every_secs == 0 {
                return;
            }

            let interval = Duration::from_secs(rpc_proxy_req_every_secs);
            let startup_jitter_ms = {
                let jitter_cap_ms = interval.as_millis() / 2;
                let effective_jitter_ms = keepalive_jitter_signal
                    .as_millis()
                    .min(jitter_cap_ms)
                    .max(1);
                rand::rng().random_range(0..=effective_jitter_ms as u64)
            };

            tokio::select! {
                _ = cancel_signal.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_millis(startup_jitter_ms)) => {}
            }

            loop {
                let wait = {
                    let jitter_cap_ms = interval.as_millis() / 2;
                    let effective_jitter_ms = keepalive_jitter_signal
                        .as_millis()
                        .min(jitter_cap_ms)
                        .max(1);
                    interval + Duration::from_millis(rand::rng().random_range(0..=effective_jitter_ms as u64))
                };

                tokio::select! {
                    _ = cancel_signal.cancelled() => break,
                    _ = tokio::time::sleep(wait) => {}
                }

                let Some(pool) = pool_signal.upgrade() else {
                    break;
                };

                let Some(meta) = pool.registry.get_last_writer_meta(writer_id).await else {
                    stats_signal.increment_me_rpc_proxy_req_signal_skipped_no_meta_total();
                    continue;
                };

                let (conn_id, mut service_rx) = pool.registry.register().await;
                if !pool
                    .registry
                    .bind_writer(conn_id, writer_id, meta.clone())
                    .await
                {
                    let _ = pool.registry.unregister(conn_id).await;
                    stats_signal.increment_me_rpc_proxy_req_signal_skipped_no_meta_total();
                    continue;
                }

                let payload = build_proxy_req_payload(
                    conn_id,
                    meta.client_addr,
                    meta.our_addr,
                    &[],
                    pool.proxy_tag.as_deref(),
                    meta.proto_flags,
                );

                if tx_signal
                    .send(WriterCommand::DataAndFlush(payload))
                    .await
                    .is_err()
                {
                    stats_signal.increment_me_rpc_proxy_req_signal_failed_total();
                    let _ = pool.registry.unregister(conn_id).await;
                    cancel_signal.cancel();
                    if cleanup_for_signal
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok()
                    {
                        pool.remove_writer_and_close_clients(writer_id).await;
                    }
                    break;
                }

                stats_signal.increment_me_rpc_proxy_req_signal_sent_total();

                if matches!(
                    tokio::time::timeout(
                        Duration::from_millis(ME_RPC_PROXY_REQ_RESPONSE_WAIT_MS),
                        service_rx.recv(),
                    )
                    .await,
                    Ok(Some(_))
                ) {
                    stats_signal.increment_me_rpc_proxy_req_signal_response_total();
                }

                let mut close_payload = Vec::with_capacity(12);
                close_payload.extend_from_slice(&RPC_CLOSE_EXT_U32.to_le_bytes());
                close_payload.extend_from_slice(&conn_id.to_le_bytes());

                if tx_signal
                    .send(WriterCommand::DataAndFlush(Bytes::from(close_payload)))
                    .await
                    .is_err()
                {
                    stats_signal.increment_me_rpc_proxy_req_signal_failed_total();
                    let _ = pool.registry.unregister(conn_id).await;
                    cancel_signal.cancel();
                    if cleanup_for_signal
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok()
                    {
                        pool.remove_writer_and_close_clients(writer_id).await;
                    }
                    break;
                }

                stats_signal.increment_me_rpc_proxy_req_signal_close_sent_total();
                let _ = pool.registry.unregister(conn_id).await;
            }
        });

        Ok(())
    }

    pub(crate) async fn remove_writer_and_close_clients(self: &Arc<Self>, writer_id: u64) {
        // Full client cleanup now happens inside `registry.writer_lost` to keep
        // writer reap/remove paths strictly non-blocking per connection.
        let _ = self.remove_writer_only(writer_id).await;
    }

    async fn remove_writer_only(self: &Arc<Self>, writer_id: u64) -> Vec<BoundConn> {
        let mut close_tx: Option<mpsc::Sender<WriterCommand>> = None;
        let mut removed_addr: Option<SocketAddr> = None;
        let mut removed_dc: Option<i32> = None;
        let mut removed_uptime: Option<Duration> = None;
        let mut trigger_refill = false;
        {
            let mut ws = self.writers.write().await;
            if let Some(pos) = ws.iter().position(|w| w.id == writer_id) {
                let w = ws.remove(pos);
                let was_draining = w.draining.load(Ordering::Relaxed);
                if was_draining {
                    self.stats.decrement_pool_drain_active();
                }
                self.stats.increment_me_writer_removed_total();
                w.cancel.cancel();
                removed_addr = Some(w.addr);
                removed_dc = Some(w.writer_dc);
                removed_uptime = Some(w.created_at.elapsed());
                trigger_refill = !was_draining;
                if trigger_refill {
                    self.stats.increment_me_writer_removed_unexpected_total();
                }
                close_tx = Some(w.tx.clone());
                self.conn_count.fetch_sub(1, Ordering::Relaxed);
            }
        }
        // State invariant:
        // - writer is removed from `self.writers` (pool visibility),
        // - writer is removed from registry routing/binding maps via `writer_lost`.
        // The close command below is only a best-effort accelerator for task shutdown.
        // Cleanup progress must never depend on command-channel availability.
        let conns = self.registry.writer_lost(writer_id).await;
        {
            let mut tracker = self.ping_tracker.lock().await;
            tracker.retain(|_, (_, wid)| *wid != writer_id);
        }
        self.rtt_stats.lock().await.remove(&writer_id);
        if let Some(tx) = close_tx {
            match tx.try_send(WriterCommand::Close) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    self.stats.increment_me_writer_close_signal_drop_total();
                    self.stats
                        .increment_me_writer_close_signal_channel_full_total();
                    debug!(
                        writer_id,
                        "Skipping close signal for removed writer: command channel is full"
                    );
                }
                Err(TrySendError::Closed(_)) => {
                    self.stats.increment_me_writer_close_signal_drop_total();
                    debug!(
                        writer_id,
                        "Skipping close signal for removed writer: command channel is closed"
                    );
                }
            }
        }
        if trigger_refill
            && let Some(addr) = removed_addr
            && let Some(writer_dc) = removed_dc
        {
            if let Some(uptime) = removed_uptime {
                self.maybe_quarantine_flapping_endpoint(addr, uptime).await;
            }
            self.trigger_immediate_refill_for_dc(addr, writer_dc);
        }
        conns
    }

    pub(crate) async fn mark_writer_draining_with_timeout(
        self: &Arc<Self>,
        writer_id: u64,
        timeout: Option<Duration>,
        allow_drain_fallback: bool,
    ) {
        let timeout = timeout.filter(|d| !d.is_zero());
        let found = {
            let mut ws = self.writers.write().await;
            if let Some(w) = ws.iter_mut().find(|w| w.id == writer_id) {
                let already_draining = w.draining.swap(true, Ordering::Relaxed);
                w.allow_drain_fallback
                    .store(allow_drain_fallback, Ordering::Relaxed);
                let now_epoch_secs = Self::now_epoch_secs();
                w.draining_started_at_epoch_secs
                    .store(now_epoch_secs, Ordering::Relaxed);
                let drain_deadline_epoch_secs = timeout
                    .map(|duration| now_epoch_secs.saturating_add(duration.as_secs()))
                    .unwrap_or(0);
                w.drain_deadline_epoch_secs
                    .store(drain_deadline_epoch_secs, Ordering::Relaxed);
                if !already_draining {
                    self.stats.increment_pool_drain_active();
                }
                w.contour
                    .store(WriterContour::Draining.as_u8(), Ordering::Relaxed);
                w.draining.store(true, Ordering::Relaxed);
                true
            } else {
                false
            }
        };

        if !found {
            return;
        }

        let timeout_secs = timeout.map(|d| d.as_secs()).unwrap_or(0);
        debug!(
            writer_id,
            timeout_secs,
            allow_drain_fallback,
            "ME writer marked draining"
        );
    }

    pub(crate) async fn mark_writer_draining(self: &Arc<Self>, writer_id: u64) {
        self.mark_writer_draining_with_timeout(writer_id, Some(Duration::from_secs(300)), false)
            .await;
    }

    pub(super) fn writer_accepts_new_binding(&self, writer: &MeWriter) -> bool {
        if !writer.draining.load(Ordering::Relaxed) {
            return true;
        }
        if !writer.allow_drain_fallback.load(Ordering::Relaxed) {
            return false;
        }

        match self.bind_stale_mode() {
            MeBindStaleMode::Never => false,
            MeBindStaleMode::Always => true,
            MeBindStaleMode::Ttl => {
                let ttl_secs = self.me_bind_stale_ttl_secs.load(Ordering::Relaxed);
                if ttl_secs == 0 {
                    return true;
                }

                let started = writer.draining_started_at_epoch_secs.load(Ordering::Relaxed);
                if started == 0 {
                    return false;
                }

                Self::now_epoch_secs().saturating_sub(started) <= ttl_secs
            }
        }
    }
}
