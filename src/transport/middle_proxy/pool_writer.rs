use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use rand::Rng;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::protocol::constants::RPC_PING_U32;

use super::codec::{RpcWriter, WriterCommand};
use super::pool::{MePool, MeWriter};
use super::reader::reader_loop;
use super::registry::BoundConn;

const ME_ACTIVE_PING_SECS: u64 = 25;
const ME_ACTIVE_PING_JITTER_SECS: i64 = 5;
const ME_IDLE_KEEPALIVE_MAX_SECS: u64 = 5;

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

    pub(crate) async fn connect_one(self: &Arc<Self>, addr: SocketAddr, rng: &SecureRandom) -> Result<()> {
        let secret_len = self.proxy_secret.read().await.len();
        if secret_len < 32 {
            return Err(ProxyError::Proxy("proxy-secret too short for ME auth".into()));
        }

        let (stream, _connect_ms) = self.connect_tcp(addr).await?;
        let hs = self.handshake_only(stream, addr, rng).await?;

        let writer_id = self.next_writer_id.fetch_add(1, Ordering::Relaxed);
        let generation = self.current_generation();
        let cancel = CancellationToken::new();
        let degraded = Arc::new(AtomicBool::new(false));
        let draining = Arc::new(AtomicBool::new(false));
        let draining_started_at_epoch_secs = Arc::new(AtomicU64::new(0));
        let allow_drain_fallback = Arc::new(AtomicBool::new(false));
        let (tx, mut rx) = mpsc::channel::<WriterCommand>(4096);
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
            generation,
            tx: tx.clone(),
            cancel: cancel.clone(),
            degraded: degraded.clone(),
            draining: draining.clone(),
            draining_started_at_epoch_secs: draining_started_at_epoch_secs.clone(),
            allow_drain_fallback: allow_drain_fallback.clone(),
        };
        self.writers.write().await.push(writer.clone());
        self.conn_count.fetch_add(1, Ordering::Relaxed);
        self.writer_available.notify_one();

        let reg = self.registry.clone();
        let writers_arc = self.writers_arc();
        let ping_tracker = self.ping_tracker.clone();
        let ping_tracker_reader = ping_tracker.clone();
        let rtt_stats = self.rtt_stats.clone();
        let stats_reader = self.stats.clone();
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
        let cancel_reader_token = cancel.clone();
        let cancel_ping_token = cancel_ping.clone();

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
                cancel_reader_token.clone(),
            )
            .await;
            if let Some(pool) = pool.upgrade()
                && cleanup_for_reader
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                pool.remove_writer_and_close_clients(writer_id).await;
            }
            if let Err(e) = res {
                warn!(error = %e, "ME reader ended");
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
                {
                    let mut tracker = ping_tracker_ping.lock().await;
                    let before = tracker.len();
                    tracker.retain(|_, (ts, _)| ts.elapsed() < Duration::from_secs(120));
                    let expired = before.saturating_sub(tracker.len());
                    if expired > 0 {
                        stats_ping.increment_me_keepalive_timeout_by(expired as u64);
                    }
                    tracker.insert(sent_id, (std::time::Instant::now(), writer_id));
                }
                ping_id = ping_id.wrapping_add(1);
                stats_ping.increment_me_keepalive_sent();
                if tx_ping.send(WriterCommand::DataAndFlush(p)).await.is_err() {
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
            }
        });

        Ok(())
    }

    pub(crate) async fn remove_writer_and_close_clients(self: &Arc<Self>, writer_id: u64) {
        let conns = self.remove_writer_only(writer_id).await;
        for bound in conns {
            let _ = self.registry.route(bound.conn_id, super::MeResponse::Close).await;
            let _ = self.registry.unregister(bound.conn_id).await;
        }
    }

    async fn remove_writer_only(self: &Arc<Self>, writer_id: u64) -> Vec<BoundConn> {
        let mut close_tx: Option<mpsc::Sender<WriterCommand>> = None;
        let mut removed_addr: Option<SocketAddr> = None;
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
                trigger_refill = !was_draining;
                if trigger_refill {
                    self.stats.increment_me_writer_removed_unexpected_total();
                }
                close_tx = Some(w.tx.clone());
                self.conn_count.fetch_sub(1, Ordering::Relaxed);
            }
        }
        if let Some(tx) = close_tx {
            let _ = tx.send(WriterCommand::Close).await;
        }
        if trigger_refill
            && let Some(addr) = removed_addr
        {
            self.trigger_immediate_refill(addr);
        }
        self.rtt_stats.lock().await.remove(&writer_id);
        self.registry.writer_lost(writer_id).await
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
                w.draining_started_at_epoch_secs
                    .store(Self::now_epoch_secs(), Ordering::Relaxed);
                if !already_draining {
                    self.stats.increment_pool_drain_active();
                }
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

        let pool = Arc::downgrade(self);
        tokio::spawn(async move {
            let deadline = timeout.map(|t| Instant::now() + t);
            while let Some(p) = pool.upgrade() {
                if let Some(deadline_at) = deadline
                    && Instant::now() >= deadline_at
                {
                    warn!(writer_id, "Drain timeout, force-closing");
                    p.stats.increment_pool_force_close_total();
                    let _ = p.remove_writer_and_close_clients(writer_id).await;
                    break;
                }
                if p.registry.is_writer_empty(writer_id).await {
                    let _ = p.remove_writer_only(writer_id).await;
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
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

        let ttl_secs = self.me_pool_drain_ttl_secs.load(Ordering::Relaxed);
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
