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
//! ## Flush policy (critical for throughput)
//!
//! Python reference uses `writer.write()` (instant buffer) + `await drain()`
//! which only blocks when buffer > 64 KB (high watermark).
//!
//! The official C MTProxy uses epoll: data is queued in a write buffer and
//! flushed by the event loop when the socket is writable — never per-frame.
//!
//! We follow the same principle: **no per-frame flush**.  Data flows through
//! `write_all` which pushes bytes through CryptoWriter → FakeTlsWriter → TCP.
//! Internal layers drain pending data on each `poll_write`.  Explicit flush
//! is called only after a batch of writes when the reader would block, or
//! when the connection is closing.

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;
use tracing::{debug, info, trace, warn};

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
    let c2t = tokio::spawn(async move {
        relay_client_to_tg(clt_frame_reader, mp_writer, &user_c2t, &stats_c2t).await
    });

    // ---- Telegram (via Middle Proxy) → Client ----
    let t2c = tokio::spawn(async move {
        relay_tg_to_client(mp_reader, clt_frame_writer, &user_t2c, &stats_t2c).await
    });

    // Wait for either direction to finish
    tokio::select! {
        res = c2t => {
            if let Err(e) = res {
                warn!(error = %e, "C→TG relay task panicked");
            }
        }
        res = t2c => {
            if let Err(e) = res {
                warn!(error = %e, "TG→C relay task panicked");
            }
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
                // No flush — MiddleProxyWriter writes directly to TCP
                // (OwnedWriteHalf).  TCP has no userspace buffer, so
                // write_all already pushes bytes into the kernel send
                // buffer.  flush() on TcpStream is a no-op in tokio.
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
    let mut unflushed_bytes: usize = 0;

    /// High watermark: flush only after accumulating this many bytes.
    /// Matches Python asyncio's default high_water (64 KB).
    /// This prevents per-frame flush from serialising writes through
    /// CryptoWriter → FakeTlsWriter → TCP, which kills throughput
    /// for media (hundreds of frames per second, mobile TCP windows).
    const FLUSH_WATERMARK: usize = 65536;

    loop {
        let read_result = tokio::time::timeout(
            ACTIVITY_TIMEOUT,
            mp_reader.read_rpc(),
        )
        .await;

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
                if let Err(e) = frame_writer.write_frame(&data, &meta).await {
                    debug!(user = %user, error = %e, "TG→C write to client failed");
                    break;
                }

                // Watermark-based flush — mimics Python's drain() semantics.
                // write_all already pushes data through the layer stack;
                // CryptoWriter and FakeTlsWriter drain pending on each
                // poll_write.  We only call flush explicitly when enough
                // data has accumulated to ensure it reaches the kernel.
                unflushed_bytes += data.len();
                if unflushed_bytes >= FLUSH_WATERMARK {
                    if let Err(e) = frame_writer.flush().await {
                        debug!(user = %user, error = %e, "TG→C flush to client failed");
                        break;
                    }
                    unflushed_bytes = 0;
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
                if let Err(e) = frame_writer.write_frame(&confirm, &meta).await {
                    debug!(user = %user, error = %e, "TG→C write simple_ack failed");
                    break;
                }
                // ACKs are small (4 bytes) — write_all pushes them
                // through immediately in the common case.  No flush
                // needed; the next ProxyAns write will drain any
                // pending data from FakeTlsWriter.
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

    // Final flush: push any remaining data in CryptoWriter / FakeTlsWriter
    // buffers to the client before the connection closes.
    let _ = frame_writer.flush().await;

    debug!(
        user = %user,
        total_bytes = total_bytes,
        msgs = msg_count,
        "TG→C direction finished"
    );
}