use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use rand::RngExt;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::MeBindStaleMode;
use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::protocol::constants::{RPC_CLOSE_EXT_U32, RPC_PING_U32};

use super::codec::{RpcWriter, WriterCommand, build_control_payload};
use super::pool::{MePool, MeWriter, WriterContour};
use super::reader::reader_loop;
use super::wire::build_proxy_req_payload;

// Writer admission, teardown, and drain-state transitions.
mod runtime;

const ME_ACTIVE_PING_SECS: u64 = 25;
const ME_ACTIVE_PING_JITTER_SECS: i64 = 5;
const ME_IDLE_KEEPALIVE_MAX_SECS: u64 = 5;
const ME_RPC_PROXY_REQ_RESPONSE_WAIT_MS: u64 = 700;
const ME_PING_TRACKER_CLEANUP_EVERY: u32 = 32;
const ME_SERVICE_SIGNAL_SEND_TIMEOUT_MS: u64 = 50;

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

enum ServiceWriterCommandSendError {
    Closed,
    TimedOut,
}

async fn writer_command_loop(
    mut rx: mpsc::Receiver<WriterCommand>,
    mut rpc_writer: RpcWriter,
    cancel: CancellationToken,
) -> Result<()> {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            cmd = rx.recv() => {
                match cmd {
                    Some(WriterCommand::Data {
                        payload,
                        _permit,
                        mut writer_permit,
                    }) => {
                        writer_permit.mark_inflight();
                        rpc_writer.send(&payload).await?;
                    }
                    Some(WriterCommand::DataAndFlush(payload)) => {
                        rpc_writer.send_and_flush(&payload).await?;
                    }
                    Some(WriterCommand::ProxyReq(mut command)) => {
                        command.writer_permit.mark_inflight();
                        rpc_writer.send_proxy_req(&command).await?;
                    }
                    Some(WriterCommand::ControlAndFlush(payload)) => {
                        rpc_writer.send_and_flush(&payload).await?;
                    }
                    Some(WriterCommand::Close) | None => return Ok(()),
                }
            }
        }
    }
}

async fn send_service_writer_command(
    tx: &mpsc::Sender<WriterCommand>,
    cmd: WriterCommand,
) -> std::result::Result<(), ServiceWriterCommandSendError> {
    match tx.try_send(cmd) {
        Ok(()) => Ok(()),
        Err(TrySendError::Closed(_)) => Err(ServiceWriterCommandSendError::Closed),
        Err(TrySendError::Full(cmd)) => {
            let wait = Duration::from_millis(ME_SERVICE_SIGNAL_SEND_TIMEOUT_MS);
            match tokio::time::timeout(wait, tx.reserve()).await {
                Ok(Ok(permit)) => {
                    permit.send(cmd);
                    Ok(())
                }
                Ok(Err(_)) => Err(ServiceWriterCommandSendError::Closed),
                Err(_) => Err(ServiceWriterCommandSendError::TimedOut),
            }
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
        biased;
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
            biased;
            _ = cancel_ping_token.cancelled() => return,
            _ = tokio::time::sleep(wait) => {}
        }
        let sent_id = ping_id;
        let payload = build_control_payload(RPC_PING_U32, sent_id as u64);
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
        if let Err(error) =
            send_service_writer_command(&tx_ping, WriterCommand::ControlAndFlush(payload)).await
        {
            {
                let mut tracker = ping_tracker_ping.lock().await;
                tracker.remove(&sent_id);
            }
            stats_ping.increment_me_keepalive_failed();
            match error {
                ServiceWriterCommandSendError::Closed => {
                    debug!("ME ping failed, removing dead writer");
                    return;
                }
                ServiceWriterCommandSendError::TimedOut => {
                    debug!("ME ping skipped: writer command channel is full");
                    continue;
                }
            }
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
        biased;
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
            biased;
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

        let Some((conn_lease, mut service_rx)) = pool.register_connection().await else {
            return;
        };
        let conn_id = conn_lease.conn_id();
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

        if let Err(error) =
            send_service_writer_command(&tx_signal, WriterCommand::DataAndFlush(payload)).await
        {
            stats_signal.increment_me_rpc_proxy_req_signal_failed_total();
            conn_lease.unregister().await;
            match error {
                ServiceWriterCommandSendError::Closed => return,
                ServiceWriterCommandSendError::TimedOut => continue,
            }
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

        let close_payload = build_control_payload(RPC_CLOSE_EXT_U32, conn_id);

        if let Err(error) =
            send_service_writer_command(&tx_signal, WriterCommand::ControlAndFlush(close_payload))
                .await
        {
            stats_signal.increment_me_rpc_proxy_req_signal_failed_total();
            conn_lease.unregister().await;
            match error {
                ServiceWriterCommandSendError::Closed => return,
                ServiceWriterCommandSendError::TimedOut => continue,
            }
        }

        stats_signal.increment_me_rpc_proxy_req_signal_close_sent_total();
        conn_lease.unregister().await;
    }
}
