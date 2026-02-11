//! Frame-level bidirectional relay for Middle Proxy mode
//!
//! In direct mode the proxy does a raw byte-level relay (AsyncRead ↔ AsyncWrite).
//! In middle-proxy mode the relay is **frame-oriented**:
//!
//! ```text
//!  Client ←[Frame Codec]→  Proxy  ←[RPC + CBC Frames]→ Middle Proxy
//! ```
//!
//! Two concurrent tasks:
//! - **C→TG**: read frame from client → wrap in RPC_PROXY_REQ → send to middle proxy
//! - **TG→C**: read RPC response → unwrap → write frame to client
//!
//! ## Drain policy (critical for throughput)
//!
//! Python reference uses `writer.write()` (instant buffer) + `await drain()`
//! on every write.
//!
//! The official C MTProxy uses epoll: data is queued in a write buffer and
//! flushed by the event loop when the socket is writable — never per-frame.
//!
//! We call `flush()` after each frame write to ensure all data is pushed
//! through the entire layered writer stack (CryptoWriter → FakeTlsWriter → TCP).
//! This is critical for large payloads (photos, videos) where data can get
//! stuck in intermediate buffers (CryptoWriter pending, FakeTlsWriter
//! WritingRecord) if not explicitly flushed.

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use tracing::{debug, trace, warn};

use crate::crypto::SecureRandom;
use crate::error::Result;
use crate::protocol::constants::ProtoTag;
use crate::stats::Stats;
use crate::stream::frame_stream::{FrameReaderKind, FrameWriterKind};
use crate::stream::traits::FrameMeta;

use super::codec::RpcResponse;
use super::connection::{MiddleProxyReader, MiddleProxyWriter, MiddleProxyStream};

/// Activity timeout — drop connection if no data flows for this long.
const ACTIVITY_TIMEOUT: Duration = Duration::from_secs(1800); // 30 minutes

/// Periodic telemetry log interval for TG→C relay.
const TG2C_TELEMETRY_INTERVAL: Duration = Duration::from_secs(10);
/// Warn when a single frame write takes longer than this.
const TG2C_SLOW_WRITE_WARN: Duration = Duration::from_millis(200);
/// Warn when a single drain call takes longer than this.
const TG2C_SLOW_DRAIN_WARN: Duration = Duration::from_millis(200);

#[derive(Debug, Default)]
struct TgToClientTelemetry {
    proxy_ans_count: u64,
    proxy_ans_bytes: u64,
    simple_ack_count: u64,
    simple_ack_bytes: u64,
    read_total: Duration,
    write_total: Duration,
    drain_total: Duration,
    read_max: Duration,
    write_max: Duration,
    drain_max: Duration,
    slow_write_count: u64,
    slow_drain_count: u64,
}

impl TgToClientTelemetry {
    fn record_proxy_ans(
        &mut self,
        bytes: usize,
        read_elapsed: Duration,
        write_elapsed: Duration,
        drain_elapsed: Duration,
    ) {
        self.proxy_ans_count += 1;
        self.proxy_ans_bytes += bytes as u64;
        self.record_common(read_elapsed, write_elapsed, drain_elapsed);
    }

    fn record_simple_ack(
        &mut self,
        bytes: usize,
        read_elapsed: Duration,
        write_elapsed: Duration,
        drain_elapsed: Duration,
    ) {
        self.simple_ack_count += 1;
        self.simple_ack_bytes += bytes as u64;
        self.record_common(read_elapsed, write_elapsed, drain_elapsed);
    }

    fn record_common(
        &mut self,
        read_elapsed: Duration,
        write_elapsed: Duration,
        drain_elapsed: Duration,
    ) {
        self.read_total += read_elapsed;
        self.write_total += write_elapsed;
        self.drain_total += drain_elapsed;
        self.read_max = self.read_max.max(read_elapsed);
        self.write_max = self.write_max.max(write_elapsed);
        self.drain_max = self.drain_max.max(drain_elapsed);

        if write_elapsed >= TG2C_SLOW_WRITE_WARN {
            self.slow_write_count += 1;
        }
        if drain_elapsed >= TG2C_SLOW_DRAIN_WARN {
            self.slow_drain_count += 1;
        }
    }

    fn total_msgs(&self) -> u64 {
        self.proxy_ans_count + self.simple_ack_count
    }
}

fn log_tg2c_telemetry(user: &str, telemetry: &TgToClientTelemetry, final_log: bool) {
    let total_msgs = telemetry.total_msgs();
    if total_msgs == 0 {
        return;
    }

    let avg_read_ms = telemetry.read_total.as_secs_f64() * 1000.0 / total_msgs as f64;
    let avg_write_ms = telemetry.write_total.as_secs_f64() * 1000.0 / total_msgs as f64;
    let avg_drain_ms = telemetry.drain_total.as_secs_f64() * 1000.0 / total_msgs as f64;

    debug!(
        user = %user,
        msgs = total_msgs,
        proxy_ans_msgs = telemetry.proxy_ans_count,
        proxy_ans_bytes = telemetry.proxy_ans_bytes,
        simple_ack_msgs = telemetry.simple_ack_count,
        simple_ack_bytes = telemetry.simple_ack_bytes,
        avg_read_ms = avg_read_ms,
        avg_write_ms = avg_write_ms,
        avg_drain_ms = avg_drain_ms,
        max_read_ms = telemetry.read_max.as_secs_f64() * 1000.0,
        max_write_ms = telemetry.write_max.as_secs_f64() * 1000.0,
        max_drain_ms = telemetry.drain_max.as_secs_f64() * 1000.0,
        slow_write_count = telemetry.slow_write_count,
        slow_drain_count = telemetry.slow_drain_count,
        final_log = final_log,
        "TG→C relay telemetry"
    );
}

/// Flush the entire layered writer stack: FrameWriter → CryptoWriter → FakeTlsWriter → TCP.
///
/// This is the Rust equivalent of Python's `await writer.drain()`.
///
/// **Why `flush()` and not `write(&[])`?**
///
/// `flush()` calls `poll_flush` which propagates through ALL layers:
///   1. CryptoWriter flushes its pending ciphertext buffer
///   2. FakeTlsWriter flushes any partial TLS record (WritingRecord state)
///   3. TCP flush (no-op in tokio, but completes the chain)
///
/// A zero-length `write(&[])` only drives CryptoWriter's pending→FakeTlsWriter
/// path, but does NOT guarantee FakeTlsWriter's internal partial record is
/// fully delivered to TCP. For small payloads (GIFs) this works by accident,
/// but for large payloads (photos, videos) that produce many TLS records,
/// data can get stuck in FakeTlsWriter's WritingRecord buffer.
async fn flush_frame_writer<W: AsyncWrite + Unpin>(
    frame_writer: &mut FrameWriterKind<W>,
) -> Result<()> {
    frame_writer.flush().await?;
    Ok(())
}

/// Relay traffic between a client and a Telegram Middle Proxy.
///
/// `client_reader` / `client_writer` are already decrypted (AES-CTR layer done).
/// They get wrapped with the appropriate frame codec (abridged / intermediate / secure).
///
/// `middle_stream` is a fully-handshaked middle proxy connection.
pub async fn relay_middle_proxy<CR, CW>(
    client_reader: CR,
    client_writer: CW,
    middle_stream: MiddleProxyStream,
    proto_tag: ProtoTag,
    user: String,
    stats: Arc<Stats>,
    rng: Arc<SecureRandom>,
) -> Result<()>
where
    CR: AsyncRead + Unpin + Send + 'static,
    CW: AsyncWrite + Unpin + Send + 'static,
{
    let (mp_reader, mp_writer) = middle_stream.into_split();

    let clt_frame_reader = FrameReaderKind::new(client_reader, proto_tag);
    let clt_frame_writer = FrameWriterKind::new(client_writer, proto_tag, rng);

    let user_c2t = user.clone();
    let user_t2c = user.clone();
    let stats_c2t = stats.clone();
    let stats_t2c = stats.clone();

    // ---- Client → Telegram (via Middle Proxy) ----
    let mut c2t = tokio::spawn(async move {
        relay_client_to_tg(clt_frame_reader, mp_writer, &user_c2t, &stats_c2t).await
    });

    // ---- Telegram (via Middle Proxy) → Client ----
    let mut t2c = tokio::spawn(async move {
        relay_tg_to_client(mp_reader, clt_frame_writer, &user_t2c, &stats_t2c).await
    });

    // Wait for either direction to finish, then stop the opposite direction.
    tokio::select! {
        res = &mut c2t => {
            if let Err(e) = res {
                warn!(error = %e, "C→TG relay task panicked");
            }
            t2c.abort();
            let _ = t2c.await;
        }
        res = &mut t2c => {
            if let Err(e) = res {
                warn!(error = %e, "TG→C relay task panicked");
            }
            c2t.abort();
            let _ = c2t.await;
        }
    }

    debug!(user = %user, "Middle proxy relay finished");
    Ok(())
}

// ============= C → TG Direction =============

/// Read frames from the client and forward them as RPC_PROXY_REQ to the middle proxy.
async fn relay_client_to_tg<R: AsyncRead + Unpin>(
    mut frame_reader: FrameReaderKind<R>,
    mut mp_writer: MiddleProxyWriter,
    user: &str,
    stats: &Stats,
) {
    let mut total_bytes: u64 = 0;
    let mut msg_count: u64 = 0;
    let mut last_activity = Instant::now();

    loop {
        // Read with activity timeout
        let read_result = tokio::time::timeout(
            ACTIVITY_TIMEOUT,
            frame_reader.read_frame(),
        )
        .await;

        match read_result {
            // Timeout — no data from client
            Err(_) => {
                warn!(
                    user = %user,
                    total_bytes = total_bytes,
                    idle_secs = last_activity.elapsed().as_secs(),
                    "C→TG activity timeout"
                );
                mp_writer.shutdown().await;
                break;
            }

            // Frame read error (EOF, protocol error, etc.)
            Ok(Err(e)) => {
                debug!(user = %user, error = %e, total_bytes = total_bytes, "C→TG read error");
                mp_writer.shutdown().await;
                break;
            }

            // Empty frame — treat as EOF
            Ok(Ok((data, _meta))) if data.is_empty() => {
                debug!(user = %user, total_bytes = total_bytes, "C→TG client sent empty frame");
                mp_writer.shutdown().await;
                break;
            }

            // Normal frame
            Ok(Ok((data, meta))) => {
                total_bytes += data.len() as u64;
                msg_count += 1;
                last_activity = Instant::now();

                stats.add_user_octets_from(user, data.len() as u64);
                stats.increment_user_msgs_from(user);

                trace!(
                    user = %user,
                    bytes = data.len(),
                    quickack = meta.quickack,
                    msg = msg_count,
                    "C→TG frame"
                );

                if let Err(e) = mp_writer.write_proxy_req(&data, meta.quickack).await {
                    debug!(user = %user, error = %e, "C→TG write to middle proxy failed");
                    break;
                }
                // No flush needed here: MiddleProxyWriter.write_proxy_req() calls
                // write_all() on OwnedWriteHalf (unbuffered TCP stream), which pushes
                // CBC-encrypted bytes directly into the kernel send buffer.
            }
        }
    }

    debug!(
        user = %user,
        total_bytes = total_bytes,
        msgs = msg_count,
        "C→TG direction finished"
    );
}

// ============= TG → C Direction =============

/// Read RPC responses from the middle proxy and forward them as frames to the client.
async fn relay_tg_to_client<W: AsyncWrite + Unpin>(
    mut mp_reader: MiddleProxyReader,
    mut frame_writer: FrameWriterKind<W>,
    user: &str,
    stats: &Stats,
) {
    let mut total_bytes: u64 = 0;
    let mut msg_count: u64 = 0;
    let mut last_activity = Instant::now();
    let mut telemetry = TgToClientTelemetry::default();
    let mut last_telemetry_log = Instant::now();

    loop {
        let read_started = Instant::now();
        let read_result = tokio::time::timeout(
            ACTIVITY_TIMEOUT,
            mp_reader.read_rpc(),
        )
        .await;
        let read_elapsed = read_started.elapsed();

        match read_result {
            // Timeout
            Err(_) => {
                warn!(
                    user = %user,
                    total_bytes = total_bytes,
                    idle_secs = last_activity.elapsed().as_secs(),
                    "TG→C activity timeout"
                );
                break;
            }

            // Read error
            Ok(Err(e)) => {
                debug!(user = %user, error = %e, total_bytes = total_bytes, "TG→C read error");
                break;
            }

            // RPC_PROXY_ANS — data from DC to forward to client
            Ok(Ok(RpcResponse::ProxyAns { data, .. })) => {
                if data.is_empty() {
                    continue;
                }

                total_bytes += data.len() as u64;
                msg_count += 1;
                last_activity = Instant::now();

                stats.add_user_octets_to(user, data.len() as u64);
                stats.increment_user_msgs_to(user);

                trace!(
                    user = %user,
                    bytes = data.len(),
                    msg = msg_count,
                    "TG→C proxy_ans"
                );

                let meta = FrameMeta::new();
                let write_started = Instant::now();
                if let Err(e) = frame_writer.write_frame(&data, &meta).await {
                    debug!(user = %user, error = %e, "TG→C write to client failed");
                    break;
                }
                let write_elapsed = write_started.elapsed();

                // CRITICAL: flush() the entire layered writer stack after each frame.
                //
                // write_frame() calls write_all() which pushes plaintext through:
                //   FrameWriter → CryptoWriter (AES-CTR encrypt) → FakeTlsWriter (TLS wrap) → TCP
                //
                // For large payloads (photos/videos), CryptoWriter may buffer ciphertext
                // in its `pending` buffer, and FakeTlsWriter may have a partial TLS record
                // in its `WritingRecord` state.  Without flush(), this buffered data is NOT
                // guaranteed to reach TCP before we read the next frame from the middle proxy.
                //
                // For small payloads (GIFs, text), data fits in a single TLS record and
                // passes through on the first poll_write — so the bug is invisible.
                //
                // flush() calls poll_flush on each layer in sequence, ensuring ALL pending
                // data reaches the TCP kernel buffer.  This matches Python's `await wr.drain()`.
                let drain_started = Instant::now();
                if let Err(e) = flush_frame_writer(&mut frame_writer).await {
                    debug!(user = %user, error = %e, "TG→C flush failed");
                    break;
                }
                let drain_elapsed = drain_started.elapsed();

                telemetry.record_proxy_ans(
                    data.len(),
                    read_elapsed,
                    write_elapsed,
                    drain_elapsed,
                );

                if write_elapsed >= TG2C_SLOW_WRITE_WARN {
                    warn!(
                        user = %user,
                        bytes = data.len(),
                        msg = msg_count,
                        read_wait_ms = read_elapsed.as_secs_f64() * 1000.0,
                        write_ms = write_elapsed.as_secs_f64() * 1000.0,
                        "TG→C slow write_frame"
                    );
                }
                if drain_elapsed >= TG2C_SLOW_DRAIN_WARN {
                    warn!(
                        user = %user,
                        bytes = data.len(),
                        msg = msg_count,
                        read_wait_ms = read_elapsed.as_secs_f64() * 1000.0,
                        drain_ms = drain_elapsed.as_secs_f64() * 1000.0,
                        "TG→C slow flush"
                    );
                }

                if last_telemetry_log.elapsed() >= TG2C_TELEMETRY_INTERVAL {
                    log_tg2c_telemetry(user, &telemetry, false);
                    last_telemetry_log = Instant::now();
                }
            }

            // RPC_SIMPLE_ACK — forward 4-byte confirmation to client
            Ok(Ok(RpcResponse::SimpleAck { confirm, .. })) => {
                last_activity = Instant::now();

                trace!(user = %user, confirm = ?confirm, "TG→C simple_ack");

                let meta = FrameMeta {
                    simple_ack: true,
                    ..Default::default()
                };
                let write_started = Instant::now();
                if let Err(e) = frame_writer.write_frame(&confirm, &meta).await {
                    debug!(user = %user, error = %e, "TG→C write simple_ack failed");
                    break;
                }
                let write_elapsed = write_started.elapsed();

                let drain_started = Instant::now();
                if let Err(e) = flush_frame_writer(&mut frame_writer).await {
                    debug!(user = %user, error = %e, "TG→C flush simple_ack failed");
                    break;
                }
                let drain_elapsed = drain_started.elapsed();

                telemetry.record_simple_ack(
                    confirm.len(),
                    read_elapsed,
                    write_elapsed,
                    drain_elapsed,
                );

                if drain_elapsed >= TG2C_SLOW_DRAIN_WARN {
                    warn!(
                        user = %user,
                        msg = msg_count,
                        read_wait_ms = read_elapsed.as_secs_f64() * 1000.0,
                        drain_ms = drain_elapsed.as_secs_f64() * 1000.0,
                        "TG→C slow flush for simple_ack"
                    );
                }

                if last_telemetry_log.elapsed() >= TG2C_TELEMETRY_INTERVAL {
                    log_tg2c_telemetry(user, &telemetry, false);
                    last_telemetry_log = Instant::now();
                }
            }

            // RPC_CLOSE_EXT — middle proxy closed the connection
            Ok(Ok(RpcResponse::Close)) => {
                debug!(user = %user, "TG→C middle proxy closed (RPC_CLOSE_EXT)");
                break;
            }

            // RPC_UNKNOWN — skip, do not forward
            Ok(Ok(RpcResponse::Unknown(tag))) => {
                trace!(user = %user, tag = tag, "TG→C unknown RPC type, skipping");
                continue;
            }
        }
    }

    // Final flush before shutdown — push any remaining buffered data to TCP.
    let _ = flush_frame_writer(&mut frame_writer).await;
    log_tg2c_telemetry(user, &telemetry, true);

    debug!(
        user = %user,
        total_bytes = total_bytes,
        msgs = msg_count,
        "TG→C direction finished"
    );
}