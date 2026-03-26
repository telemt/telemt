use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use bytes::BytesMut;
use rand::RngExt;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::MeBindStaleMode;
use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::protocol::constants::{RPC_CLOSE_EXT_U32, RPC_PING_U32};

use super::codec::{RpcWriter, WriterCommand};
use super::pool::{MePool, MeWriter, WriterContour};
use super::reader::reader_loop;
use super::wire::build_proxy_req_payload;

const ME_ACTIVE_PING_SECS: u64 = 25;
const ME_ACTIVE_PING_JITTER_SECS: i64 = 5;
const ME_IDLE_KEEPALIVE_MAX_SECS: u64 = 5;
const ME_RPC_PROXY_REQ_RESPONSE_WAIT_MS: u64 = 700;
const ME_PING_TRACKER_CLEANUP_EVERY: u32 = 32;

#[derive(Clone, Copy)]
enum WriterTeardownMode {
    Any,
    DrainingOnly,
}

fn is_me_peer_closed_error(error: &ProxyError) -> bool {
    matches!(error, ProxyError::Io(ioe) if ioe.kind() == ErrorKind::UnexpectedEof)
}

enum WriterLifecycleExit {
    Reader(Result<()>),
    Writer(Result<()>),
    Ping,
    Signal,
    Cancelled,
}

async fn writer_command_loop(
    mut rx: mpsc::Receiver<WriterCommand>,
    mut rpc_writer: RpcWriter,
    cancel: CancellationToken,
) -> Result<()> {
    loop {
        tokio::select! {
            cmd = rx.recv() => {
                match cmd {
                    Some(WriterCommand::Data(payload)) => {
                        rpc_writer.send(&payload).await?;
                    }
                    Some(WriterCommand::DataAndFlush(payload)) => {
                        rpc_writer.send_and_flush(&payload).await?;
                    }
                    Some(WriterCommand::Close) | None => return Ok(()),
                }
            }
            _ = cancel.cancelled() => return Ok(()),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn ping_loop(
    pool_ping: std::sync::Weak<MePool>,
    writer_id: u64,
    tx_ping: mpsc::Sender<WriterCommand>,
    ping_tracker_ping: Arc<tokio::sync::Mutex<HashMap<i64, Instant>>>,
    stats_ping: Arc<crate::stats::Stats>,
    keepalive_enabled: bool,
    keepalive_interval: Duration,
    keepalive_jitter: Duration,
    cancel_ping_token: CancellationToken,
) {
    let mut ping_id: i64 = rand::random::<i64>();
    let mut cleanup_tick: u32 = 0;
    let idle_interval_cap = Duration::from_secs(ME_IDLE_KEEPALIVE_MAX_SECS);
    // Per-writer jittered start to avoid phase sync.
    let startup_jitter = if keepalive_enabled {
        let mut interval = keepalive_interval;
        let Some(pool) = pool_ping.upgrade() else {
            return;
        };
        if pool.registry.is_writer_empty(writer_id).await {
            interval = interval.min(idle_interval_cap);
        }
        let jitter_cap_ms = interval.as_millis() / 2;
        let effective_jitter_ms = keepalive_jitter.as_millis().min(jitter_cap_ms).max(1);
        Duration::from_millis(rand::rng().random_range(0..=effective_jitter_ms as u64))
    } else {
        let jitter =
            rand::rng().random_range(-ME_ACTIVE_PING_JITTER_SECS..=ME_ACTIVE_PING_JITTER_SECS);
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
            let Some(pool) = pool_ping.upgrade() else {
                return;
            };
            if pool.registry.is_writer_empty(writer_id).await {
                interval = interval.min(idle_interval_cap);
            }
            let jitter_cap_ms = interval.as_millis() / 2;
            let effective_jitter_ms = keepalive_jitter.as_millis().min(jitter_cap_ms).max(1);
            interval
                + Duration::from_millis(rand::rng().random_range(0..=effective_jitter_ms as u64))
        } else {
            let jitter =
                rand::rng().random_range(-ME_ACTIVE_PING_JITTER_SECS..=ME_ACTIVE_PING_JITTER_SECS);
            let secs = (ME_ACTIVE_PING_SECS as i64 + jitter).max(5) as u64;
            Duration::from_secs(secs)
        };
        tokio::select! {
            _ = cancel_ping_token.cancelled() => return,
            _ = tokio::time::sleep(wait) => {}
        }
        let sent_id = ping_id;
        let mut p = Vec::with_capacity(12);
        p.extend_from_slice(&RPC_PING_U32.to_le_bytes());
        p.extend_from_slice(&sent_id.to_le_bytes());
        {
            let mut tracker = ping_tracker_ping.lock().await;
            cleanup_tick = cleanup_tick.wrapping_add(1);
            if cleanup_tick.is_multiple_of(ME_PING_TRACKER_CLEANUP_EVERY) {
                let before = tracker.len();
                tracker.retain(|_, ts| ts.elapsed() < Duration::from_secs(120));
                let expired = before.saturating_sub(tracker.len());
                if expired > 0 {
                    stats_ping.increment_me_keepalive_timeout_by(expired as u64);
                }
            }
            tracker.insert(sent_id, std::time::Instant::now());
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
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn rpc_proxy_req_signal_loop(
    pool_signal: std::sync::Weak<MePool>,
    writer_id: u64,
    tx_signal: mpsc::Sender<WriterCommand>,
    stats_signal: Arc<crate::stats::Stats>,
    cancel_signal: CancellationToken,
    keepalive_jitter_signal: Duration,
    rpc_proxy_req_every_secs: u64,
) {
    if rpc_proxy_req_every_secs == 0 {
        // Disabled service signal loop must stay parked until writer cancellation.
        // Returning immediately here would complete `select!` and tear down writer lifecycle.
        cancel_signal.cancelled().await;
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
            interval
                + Duration::from_millis(rand::rng().random_range(0..=effective_jitter_ms as u64))
        };

        tokio::select! {
            _ = cancel_signal.cancelled() => return,
            _ = tokio::time::sleep(wait) => {}
        }

        let Some(pool) = pool_signal.upgrade() else {
            return;
        };

        let Some(meta) = pool.registry.get_last_writer_meta(writer_id).await else {
            stats_signal.increment_me_rpc_proxy_req_signal_skipped_no_meta_total();
            continue;
        };

        let (conn_id, mut service_rx) = pool.registry.register().await;
        // Service RPC_PROXY_REQ signal path is intentionally route-only:
        // do not bind synthetic conn_id into regular writer/client accounting.

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
            return;
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
            return;
        }

        stats_signal.increment_me_rpc_proxy_req_signal_close_sent_total();
        let _ = pool.registry.unregister(conn_id).await;
    }
}

impl MePool {
    pub(crate) async fn prune_closed_writers(self: &Arc<Self>) {
        let closed_writer_ids: Vec<u64> = {
            let ws = self.writers.read().await;
            ws.iter()
                .filter(|w| w.tx.is_closed())
                .map(|w| w.id)
                .collect()
        };
        if closed_writer_ids.is_empty() {
            return;
        }

        for writer_id in closed_writer_ids {
            let _ = self.remove_writer_and_close_clients(writer_id).await;
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
            addr, rng, generation, contour, writer_dc, false,
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
            return Err(ProxyError::Proxy(
                "proxy-secret too short for ME auth".into(),
            ));
        }

        let dc_idx = i16::try_from(writer_dc).ok();
        let (stream, _connect_ms, upstream_egress) = self.connect_tcp(addr, dc_idx).await?;
        let hs = self
            .handshake_only(stream, addr, upstream_egress, rng)
            .await?;

        let writer_id = self.next_writer_id.fetch_add(1, Ordering::Relaxed);
        let contour = Arc::new(AtomicU8::new(contour.as_u8()));
        let cancel = CancellationToken::new();
        let degraded = Arc::new(AtomicBool::new(false));
        let rtt_ema_ms_x10 = Arc::new(AtomicU32::new(0));
        let draining = Arc::new(AtomicBool::new(false));
        let draining_started_at_epoch_secs = Arc::new(AtomicU64::new(0));
        let drain_deadline_epoch_secs = Arc::new(AtomicU64::new(0));
        let allow_drain_fallback = Arc::new(AtomicBool::new(false));
        let (tx, rx) =
            mpsc::channel::<WriterCommand>(self.writer_lifecycle.writer_cmd_channel_capacity);
        let rpc_writer = RpcWriter {
            writer: hs.wr,
            key: hs.write_key,
            iv: hs.write_iv,
            seq_no: 0,
            crc_mode: hs.crc_mode,
        };
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
        self.writers
            .update(|writers| writers.push(writer.clone()))
            .await;
        self.registry.register_writer(writer_id, tx.clone()).await;
        self.registry.mark_writer_idle(writer_id).await;
        self.conn_count.fetch_add(1, Ordering::Relaxed);
        self.notify_writer_epoch();

        let reg = self.registry.clone();
        let writers_arc = self.writers_arc();
        let ping_tracker = Arc::new(tokio::sync::Mutex::new(HashMap::<i64, Instant>::new()));
        let ping_tracker_reader = ping_tracker.clone();
        let ping_tracker_ping = ping_tracker.clone();
        let rtt_stats = self.rtt_stats.clone();
        let stats_reader = self.stats.clone();
        let stats_reader_close = self.stats.clone();
        let stats_ping = self.stats.clone();
        let stats_signal = self.stats.clone();
        let pool_lifecycle = Arc::downgrade(self);
        let pool_ping = Arc::downgrade(self);
        let pool_signal = Arc::downgrade(self);
        let tx_reader = tx.clone();
        let tx_ping = tx.clone();
        let tx_signal = tx.clone();
        let keepalive_enabled = self.writer_lifecycle.me_keepalive_enabled;
        let keepalive_interval = self.writer_lifecycle.me_keepalive_interval;
        let keepalive_jitter = self.writer_lifecycle.me_keepalive_jitter;
        let keepalive_jitter_signal = self.writer_lifecycle.me_keepalive_jitter;
        let rpc_proxy_req_every_secs = self
            .writer_lifecycle
            .rpc_proxy_req_every_secs
            .load(Ordering::Relaxed);
        let cancel_reader = cancel.clone();
        let cancel_writer = cancel.clone();
        let cancel_ping = cancel.clone();
        let cancel_signal = cancel.clone();
        let cancel_select = cancel.clone();
        let cancel_cleanup = cancel.clone();
        let reader_route_data_wait_ms = self.transport_policy.me_reader_route_data_wait_ms.clone();

        tokio::spawn(async move {
            // Reader MUST be the first branch in biased select! to avoid read starvation.
            let exit = tokio::select! {
                biased;

                reader_res = reader_loop(
                    hs.rd,
                    hs.read_key,
                    hs.read_iv,
                    hs.crc_mode,
                    reg.clone(),
                    BytesMut::new(),
                    BytesMut::new(),
                    tx_reader,
                    ping_tracker_reader,
                    rtt_stats,
                    stats_reader,
                    writer_id,
                    degraded,
                    rtt_ema_ms_x10,
                    reader_route_data_wait_ms,
                    cancel_reader,
                ) => WriterLifecycleExit::Reader(reader_res),
                writer_res = writer_command_loop(rx, rpc_writer, cancel_writer) => {
                    WriterLifecycleExit::Writer(writer_res)
                }
                _ = ping_loop(
                    pool_ping,
                    writer_id,
                    tx_ping,
                    ping_tracker_ping,
                    stats_ping,
                    keepalive_enabled,
                    keepalive_interval,
                    keepalive_jitter,
                    cancel_ping,
                ) => WriterLifecycleExit::Ping,
                _ = rpc_proxy_req_signal_loop(
                    pool_signal,
                    writer_id,
                    tx_signal,
                    stats_signal,
                    cancel_signal,
                    keepalive_jitter_signal,
                    rpc_proxy_req_every_secs,
                ) => WriterLifecycleExit::Signal,
                _ = cancel_select.cancelled() => WriterLifecycleExit::Cancelled,
            };

            match exit {
                WriterLifecycleExit::Reader(res) => {
                    let idle_close_by_peer = if let Err(e) = res.as_ref() {
                        is_me_peer_closed_error(e) && reg.is_writer_empty(writer_id).await
                    } else {
                        false
                    };
                    if idle_close_by_peer {
                        stats_reader_close.increment_me_idle_close_by_peer_total();
                        info!(writer_id, "ME socket closed by peer on idle writer");
                    }
                    if let Err(e) = res
                        && !idle_close_by_peer
                    {
                        warn!(error = %e, "ME reader ended");
                    }
                }
                WriterLifecycleExit::Writer(res) => {
                    if let Err(e) = res {
                        warn!(error = %e, "ME writer command loop ended");
                    }
                }
                WriterLifecycleExit::Ping => {
                    debug!(writer_id, "ME ping loop finished");
                }
                WriterLifecycleExit::Signal => {
                    debug!(writer_id, "ME rpc_proxy_req signal loop finished");
                }
                WriterLifecycleExit::Cancelled => {}
            }

            if let Some(pool) = pool_lifecycle.upgrade() {
                pool.remove_writer_and_close_clients(writer_id).await;
            } else {
                // Fallback for shutdown races: make lifecycle exit observable by prune.
                cancel_cleanup.cancel();
            }

            let remaining = writers_arc.read().await.len();
            debug!(writer_id, remaining, "ME writer lifecycle task finished");
        });

        Ok(())
    }

    pub(crate) async fn remove_writer_and_close_clients(self: &Arc<Self>, writer_id: u64) {
        // Full client cleanup now happens inside `registry.writer_lost` to keep
        // writer reap/remove paths strictly non-blocking per connection.
        let _ = self
            .remove_writer_with_mode(writer_id, WriterTeardownMode::Any)
            .await;
    }

    pub(super) async fn remove_draining_writer_hard_detach(
        self: &Arc<Self>,
        writer_id: u64,
    ) -> bool {
        self.remove_writer_with_mode(writer_id, WriterTeardownMode::DrainingOnly)
            .await
    }

    #[allow(dead_code)]
    async fn remove_writer_only(self: &Arc<Self>, writer_id: u64) -> bool {
        self.remove_writer_with_mode(writer_id, WriterTeardownMode::Any)
            .await
    }

    // Authoritative teardown primitive shared by normal cleanup and watchdog path.
    // Lock-order invariant:
    // 1) mutate `writers` under pool write lock,
    // 2) release pool lock,
    // 3) run registry/metrics/refill side effects.
    // `registry.writer_lost` must never run while `writers` lock is held.
    async fn remove_writer_with_mode(
        self: &Arc<Self>,
        writer_id: u64,
        mode: WriterTeardownMode,
    ) -> bool {
        let mut close_tx: Option<mpsc::Sender<WriterCommand>> = None;
        let mut removed_addr: Option<SocketAddr> = None;
        let mut removed_dc: Option<i32> = None;
        let mut removed_uptime: Option<Duration> = None;
        let mut trigger_refill = false;
        let mut removed = false;
        {
            let mut ws = self.writers.write().await;
            if let Some(pos) = ws.iter().position(|w| w.id == writer_id) {
                if matches!(mode, WriterTeardownMode::DrainingOnly)
                    && !ws[pos].draining.load(Ordering::Relaxed)
                {
                    return false;
                }
                let w = ws.remove(pos);
                let was_draining = w.draining.load(Ordering::Relaxed);
                if was_draining {
                    self.stats.decrement_pool_drain_active();
                    self.decrement_draining_active_runtime();
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
                removed = true;
            }
        }
        // State invariant:
        // - writer is removed from `self.writers` (pool visibility),
        // - writer is removed from registry routing/binding maps via `writer_lost`.
        // The close command below is only a best-effort accelerator for task shutdown.
        // Cleanup progress must never depend on command-channel availability.
        let _ = self.registry.writer_lost(writer_id).await;
        self.rtt_stats.lock().await.remove(&writer_id);
        if let Some(tx) = close_tx {
            // Keep teardown critical path non-blocking: close is best-effort only.
            let _ = tx.try_send(WriterCommand::Close);
        }
        if let Some(addr) = removed_addr {
            if let Some(uptime) = removed_uptime {
                // Quarantine contract: only unexpected removals are considered endpoint flap.
                if trigger_refill {
                    self.stats
                        .increment_me_endpoint_quarantine_unexpected_total();
                    self.maybe_quarantine_flapping_endpoint(addr, uptime, "unexpected")
                        .await;
                } else {
                    self.stats
                        .increment_me_endpoint_quarantine_draining_suppressed_total();
                    debug!(
                        %addr,
                        uptime_ms = uptime.as_millis(),
                        "Skipping endpoint quarantine for draining writer removal"
                    );
                }
            }
            if trigger_refill && let Some(writer_dc) = removed_dc {
                self.trigger_immediate_refill_for_dc(addr, writer_dc);
            }
        }
        if removed {
            self.notify_writer_epoch();
        }
        removed
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
                    self.increment_draining_active_runtime();
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
            timeout_secs, allow_drain_fallback, "ME writer marked draining"
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
                let ttl_secs = self
                    .binding_policy
                    .me_bind_stale_ttl_secs
                    .load(Ordering::Relaxed);
                if ttl_secs == 0 {
                    return true;
                }

                let started = writer
                    .draining_started_at_epoch_secs
                    .load(Ordering::Relaxed);
                if started == 0 {
                    return false;
                }

                Self::now_epoch_secs().saturating_sub(started) <= ttl_secs
            }
        }
    }
}
