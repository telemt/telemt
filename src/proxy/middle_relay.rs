use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, trace, warn};

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::protocol::constants::{*, secure_padding_len};
use crate::proxy::handshake::HandshakeSuccess;
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader, CryptoWriter};
use crate::transport::middle_proxy::{MePool, MeResponse, proto_flags_for_tag};

enum C2MeCommand {
    Data { payload: Vec<u8>, flags: u32 },
    Close,
}

const DESYNC_DEDUP_WINDOW: Duration = Duration::from_secs(60);
const DESYNC_ERROR_CLASS: &str = "frame_too_large_crypto_desync";
static DESYNC_DEDUP: OnceLock<Mutex<HashMap<u64, Instant>>> = OnceLock::new();

struct RelayForensicsState {
    trace_id: u64,
    conn_id: u64,
    user: String,
    peer: SocketAddr,
    peer_hash: u64,
    started_at: Instant,
    bytes_c2me: u64,
    bytes_me2c: Arc<AtomicU64>,
    desync_all_full: bool,
}

fn hash_value<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn hash_ip(ip: IpAddr) -> u64 {
    hash_value(&ip)
}

fn should_emit_full_desync(key: u64, all_full: bool, now: Instant) -> bool {
    if all_full {
        return true;
    }

    let dedup = DESYNC_DEDUP.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = dedup.lock().expect("desync dedup mutex poisoned");
    guard.retain(|_, seen_at| now.duration_since(*seen_at) < DESYNC_DEDUP_WINDOW);

    match guard.get_mut(&key) {
        Some(seen_at) => {
            if now.duration_since(*seen_at) >= DESYNC_DEDUP_WINDOW {
                *seen_at = now;
                true
            } else {
                false
            }
        }
        None => {
            guard.insert(key, now);
            true
        }
    }
}

fn report_desync_frame_too_large(
    state: &RelayForensicsState,
    proto_tag: ProtoTag,
    frame_counter: u64,
    max_frame: usize,
    len: usize,
    raw_len_bytes: Option<[u8; 4]>,
    stats: &Stats,
) -> ProxyError {
    let len_buf = raw_len_bytes.unwrap_or((len as u32).to_le_bytes());
    let looks_like_tls = raw_len_bytes
        .map(|b| b[0] == 0x16 && b[1] == 0x03)
        .unwrap_or(false);
    let looks_like_http = raw_len_bytes
        .map(|b| matches!(b[0], b'G' | b'P' | b'H' | b'C' | b'D'))
        .unwrap_or(false);
    let now = Instant::now();
    let dedup_key = hash_value(&(
        state.user.as_str(),
        state.peer_hash,
        proto_tag,
        DESYNC_ERROR_CLASS,
    ));
    let emit_full = should_emit_full_desync(dedup_key, state.desync_all_full, now);
    let duration_ms = state.started_at.elapsed().as_millis() as u64;
    let bytes_me2c = state.bytes_me2c.load(Ordering::Relaxed);

    stats.increment_desync_total();
    stats.observe_desync_frames_ok(frame_counter);
    if emit_full {
        stats.increment_desync_full_logged();
        warn!(
            trace_id = format_args!("0x{:016x}", state.trace_id),
            conn_id = state.conn_id,
            user = %state.user,
            peer_hash = format_args!("0x{:016x}", state.peer_hash),
            proto = ?proto_tag,
            mode = "middle_proxy",
            is_tls = true,
            duration_ms,
            bytes_c2me = state.bytes_c2me,
            bytes_me2c,
            raw_len = len,
            raw_len_hex = format_args!("0x{:08x}", len),
            raw_bytes = format_args!(
                "{:02x} {:02x} {:02x} {:02x}",
                len_buf[0], len_buf[1], len_buf[2], len_buf[3]
            ),
            max_frame,
            tls_like = looks_like_tls,
            http_like = looks_like_http,
            frames_ok = frame_counter,
            dedup_window_secs = DESYNC_DEDUP_WINDOW.as_secs(),
            desync_all_full = state.desync_all_full,
            full_reason = if state.desync_all_full { "desync_all_full" } else { "first_in_dedup_window" },
            error_class = DESYNC_ERROR_CLASS,
            "Frame too large — crypto desync forensics"
        );
        debug!(
            trace_id = format_args!("0x{:016x}", state.trace_id),
            conn_id = state.conn_id,
            user = %state.user,
            peer = %state.peer,
            "Frame too large forensic peer detail"
        );
    } else {
        stats.increment_desync_suppressed();
        debug!(
            trace_id = format_args!("0x{:016x}", state.trace_id),
            conn_id = state.conn_id,
            user = %state.user,
            peer_hash = format_args!("0x{:016x}", state.peer_hash),
            proto = ?proto_tag,
            duration_ms,
            bytes_c2me = state.bytes_c2me,
            bytes_me2c,
            raw_len = len,
            frames_ok = frame_counter,
            dedup_window_secs = DESYNC_DEDUP_WINDOW.as_secs(),
            error_class = DESYNC_ERROR_CLASS,
            "Frame too large — crypto desync forensic suppressed"
        );
    }

    ProxyError::Proxy(format!(
        "Frame too large: {len} (max {max_frame}), frames_ok={frame_counter}, conn_id={}, trace_id=0x{:016x}",
        state.conn_id,
        state.trace_id
    ))
}

pub(crate) async fn handle_via_middle_proxy<R, W>(
    mut crypto_reader: CryptoReader<R>,
    crypto_writer: CryptoWriter<W>,
    success: HandshakeSuccess,
    me_pool: Arc<MePool>,
    stats: Arc<Stats>,
    config: Arc<ProxyConfig>,
    _buffer_pool: Arc<BufferPool>,
    local_addr: SocketAddr,
    rng: Arc<SecureRandom>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let user = success.user.clone();
    let peer = success.peer;
    let proto_tag = success.proto_tag;

    info!(
        user = %user,
        peer = %peer,
        dc = success.dc_idx,
        proto = ?proto_tag,
        mode = "middle_proxy",
        "Routing via Middle-End"
    );

    let (conn_id, me_rx) = me_pool.registry().register().await;
    let trace_id = conn_id;
    let bytes_me2c = Arc::new(AtomicU64::new(0));
    let mut forensics = RelayForensicsState {
        trace_id,
        conn_id,
        user: user.clone(),
        peer,
        peer_hash: hash_ip(peer.ip()),
        started_at: Instant::now(),
        bytes_c2me: 0,
        bytes_me2c: bytes_me2c.clone(),
        desync_all_full: config.general.desync_all_full,
    };

    stats.increment_user_connects(&user);
    stats.increment_user_curr_connects(&user);

    let proto_flags = proto_flags_for_tag(proto_tag, me_pool.has_proxy_tag());
    debug!(
        trace_id = format_args!("0x{:016x}", trace_id),
        user = %user,
        conn_id,
        peer_hash = format_args!("0x{:016x}", forensics.peer_hash),
        desync_all_full = forensics.desync_all_full,
        proto_flags = format_args!("0x{:08x}", proto_flags),
        "ME relay started"
    );

    let translated_local_addr = me_pool.translate_our_addr(local_addr);

    let frame_limit = config.general.max_client_frame;

    let (c2me_tx, mut c2me_rx) = mpsc::channel::<C2MeCommand>(1024);
    let me_pool_c2me = me_pool.clone();
    let c2me_sender = tokio::spawn(async move {
        while let Some(cmd) = c2me_rx.recv().await {
            match cmd {
                C2MeCommand::Data { payload, flags } => {
                    me_pool_c2me.send_proxy_req(
                        conn_id,
                        success.dc_idx,
                        peer,
                        translated_local_addr,
                        &payload,
                        flags,
                    ).await?;
                }
                C2MeCommand::Close => {
                    let _ = me_pool_c2me.send_close(conn_id).await;
                    return Ok(());
                }
            }
        }
        Ok(())
    });

    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
    let mut me_rx_task = me_rx;
    let stats_clone = stats.clone();
    let rng_clone = rng.clone();
    let user_clone = user.clone();
    let bytes_me2c_clone = bytes_me2c.clone();
    let me_writer = tokio::spawn(async move {
        let mut writer = crypto_writer;
        let mut frame_buf = Vec::with_capacity(16 * 1024);
        loop {
            tokio::select! {
                msg = me_rx_task.recv() => {
                    match msg {
                        Some(MeResponse::Data { flags, data }) => {
                            trace!(conn_id, bytes = data.len(), flags, "ME->C data");
                            bytes_me2c_clone.fetch_add(data.len() as u64, Ordering::Relaxed);
                            stats_clone.add_user_octets_to(&user_clone, data.len() as u64);
                            write_client_payload(
                                &mut writer,
                                proto_tag,
                                flags,
                                &data,
                                rng_clone.as_ref(),
                                &mut frame_buf,
                            )
                            .await?;

                            // Drain all immediately queued ME responses and flush once.
                            while let Ok(next) = me_rx_task.try_recv() {
                                match next {
                                    MeResponse::Data { flags, data } => {
                                        trace!(conn_id, bytes = data.len(), flags, "ME->C data (batched)");
                                        bytes_me2c_clone.fetch_add(data.len() as u64, Ordering::Relaxed);
                                        stats_clone.add_user_octets_to(&user_clone, data.len() as u64);
                                        write_client_payload(
                                            &mut writer,
                                            proto_tag,
                                            flags,
                                            &data,
                                            rng_clone.as_ref(),
                                            &mut frame_buf,
                                        ).await?;
                                    }
                                    MeResponse::Ack(confirm) => {
                                        trace!(conn_id, confirm, "ME->C quickack (batched)");
                                        write_client_ack(&mut writer, proto_tag, confirm).await?;
                                    }
                                    MeResponse::Close => {
                                        debug!(conn_id, "ME sent close (batched)");
                                        let _ = writer.flush().await;
                                        return Ok(());
                                    }
                                }
                            }

                            writer.flush().await.map_err(ProxyError::Io)?;
                        }
                        Some(MeResponse::Ack(confirm)) => {
                            trace!(conn_id, confirm, "ME->C quickack");
                            write_client_ack(&mut writer, proto_tag, confirm).await?;
                        }
                        Some(MeResponse::Close) => {
                            debug!(conn_id, "ME sent close");
                            let _ = writer.flush().await;
                            return Ok(());
                        }
                        None => {
                            debug!(conn_id, "ME channel closed");
                            return Err(ProxyError::Proxy("ME connection lost".into()));
                        }
                    }
                }
                _ = &mut stop_rx => {
                    debug!(conn_id, "ME writer stop signal");
                    return Ok(());
                }
            }
        }
    });

    let mut main_result: Result<()> = Ok(());
    let mut client_closed = false;
    let mut frame_counter: u64 = 0;
    loop {
        match read_client_payload(
            &mut crypto_reader,
            proto_tag,
            frame_limit,
            &forensics,
            &mut frame_counter,
            &stats,
        ).await {
            Ok(Some((payload, quickack))) => {
                trace!(conn_id, bytes = payload.len(), "C->ME frame");
                forensics.bytes_c2me = forensics
                    .bytes_c2me
                    .saturating_add(payload.len() as u64);
                stats.add_user_octets_from(&user, payload.len() as u64);
                let mut flags = proto_flags;
                if quickack {
                    flags |= RPC_FLAG_QUICKACK;
                }
                if payload.len() >= 8 && payload[..8].iter().all(|b| *b == 0) {
                    flags |= RPC_FLAG_NOT_ENCRYPTED;
                }
                // Keep client read loop lightweight: route heavy ME send path via a dedicated task.
                if c2me_tx
                    .send(C2MeCommand::Data { payload, flags })
                    .await
                    .is_err()
                {
                    main_result = Err(ProxyError::Proxy("ME sender channel closed".into()));
                    break;
                }
            }
            Ok(None) => {
                debug!(conn_id, "Client EOF");
                client_closed = true;
                let _ = c2me_tx.send(C2MeCommand::Close).await;
                break;
            }
            Err(e) => {
                main_result = Err(e);
                break;
            }
        }
    }

    drop(c2me_tx);
    let c2me_result = c2me_sender
        .await
        .unwrap_or_else(|e| Err(ProxyError::Proxy(format!("ME sender join error: {e}"))));

    let _ = stop_tx.send(());
    let mut writer_result = me_writer
        .await
        .unwrap_or_else(|e| Err(ProxyError::Proxy(format!("ME writer join error: {e}"))));

    // When client closes, but ME channel stopped as unregistered - it isnt error
    if client_closed {
        if matches!(
            writer_result,
            Err(ProxyError::Proxy(ref msg)) if msg == "ME connection lost"
        ) {
            writer_result = Ok(());
        }
    }

    let result = match (main_result, c2me_result, writer_result) {
        (Ok(()), Ok(()), Ok(())) => Ok(()),
        (Err(e), _, _) => Err(e),
        (_, Err(e), _) => Err(e),
        (_, _, Err(e)) => Err(e),
    };

    debug!(
        user = %user,
        conn_id,
        trace_id = format_args!("0x{:016x}", trace_id),
        duration_ms = forensics.started_at.elapsed().as_millis() as u64,
        bytes_c2me = forensics.bytes_c2me,
        bytes_me2c = forensics.bytes_me2c.load(Ordering::Relaxed),
        frames_ok = frame_counter,
        "ME relay cleanup"
    );
    me_pool.registry().unregister(conn_id).await;
    stats.decrement_user_curr_connects(&user);
    result
}

async fn read_client_payload<R>(
    client_reader: &mut CryptoReader<R>,
    proto_tag: ProtoTag,
    max_frame: usize,
    forensics: &RelayForensicsState,
    frame_counter: &mut u64,
    stats: &Stats,
) -> Result<Option<(Vec<u8>, bool)>>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    loop {
        let (len, quickack, raw_len_bytes) = match proto_tag {
            ProtoTag::Abridged => {
                let mut first = [0u8; 1];
                match client_reader.read_exact(&mut first).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
                    Err(e) => return Err(ProxyError::Io(e)),
                }

                let quickack = (first[0] & 0x80) != 0;
                let len_words = if (first[0] & 0x7f) == 0x7f {
                    let mut ext = [0u8; 3];
                    client_reader
                        .read_exact(&mut ext)
                        .await
                        .map_err(ProxyError::Io)?;
                    u32::from_le_bytes([ext[0], ext[1], ext[2], 0]) as usize
                } else {
                    (first[0] & 0x7f) as usize
                };

                let len = len_words
                    .checked_mul(4)
                    .ok_or_else(|| ProxyError::Proxy("Abridged frame length overflow".into()))?;
                (len, quickack, None)
            }
            ProtoTag::Intermediate | ProtoTag::Secure => {
                let mut len_buf = [0u8; 4];
                match client_reader.read_exact(&mut len_buf).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
                    Err(e) => return Err(ProxyError::Io(e)),
                }
                let quickack = (len_buf[3] & 0x80) != 0;
                (
                    (u32::from_le_bytes(len_buf) & 0x7fff_ffff) as usize,
                    quickack,
                    Some(len_buf),
                )
            }
        };

        if len == 0 {
            continue;
        }
        if len < 4 && proto_tag != ProtoTag::Abridged {
            warn!(
                trace_id = format_args!("0x{:016x}", forensics.trace_id),
                conn_id = forensics.conn_id,
                user = %forensics.user,
                len,
                proto = ?proto_tag,
                "Frame too small — corrupt or probe"
            );
            return Err(ProxyError::Proxy(format!("Frame too small: {len}")));
        }

        if len > max_frame {
            return Err(report_desync_frame_too_large(
                forensics,
                proto_tag,
                *frame_counter,
                max_frame,
                len,
                raw_len_bytes,
                stats,
            ));
        }

        let secure_payload_len = if proto_tag == ProtoTag::Secure {
            match secure_payload_len_from_wire_len(len) {
                Some(payload_len) => payload_len,
                None => {
                    stats.increment_secure_padding_invalid();
                    return Err(ProxyError::Proxy(format!(
                        "Invalid secure frame length: {len}"
                    )));
                }
            }
        } else {
            len
        };

        let mut payload = vec![0u8; len];
        client_reader
            .read_exact(&mut payload)
            .await
            .map_err(ProxyError::Io)?;

        // Secure Intermediate: strip validated trailing padding bytes.
        if proto_tag == ProtoTag::Secure {
            payload.truncate(secure_payload_len);
        }
        *frame_counter += 1;
        return Ok(Some((payload, quickack)));
    }
}

async fn write_client_payload<W>(
    client_writer: &mut CryptoWriter<W>,
    proto_tag: ProtoTag,
    flags: u32,
    data: &[u8],
    rng: &SecureRandom,
    frame_buf: &mut Vec<u8>,
) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let quickack = (flags & RPC_FLAG_QUICKACK) != 0;

    match proto_tag {
        ProtoTag::Abridged => {
            if data.len() % 4 != 0 {
                return Err(ProxyError::Proxy(format!(
                    "Abridged payload must be 4-byte aligned, got {}",
                    data.len()
                )));
            }

            let len_words = data.len() / 4;
            if len_words < 0x7f {
                let mut first = len_words as u8;
                if quickack {
                    first |= 0x80;
                }
                frame_buf.clear();
                frame_buf.reserve(1 + data.len());
                frame_buf.push(first);
                frame_buf.extend_from_slice(data);
                client_writer
                    .write_all(&frame_buf)
                    .await
                    .map_err(ProxyError::Io)?;
            } else if len_words < (1 << 24) {
                let mut first = 0x7fu8;
                if quickack {
                    first |= 0x80;
                }
                let lw = (len_words as u32).to_le_bytes();
                frame_buf.clear();
                frame_buf.reserve(4 + data.len());
                frame_buf.extend_from_slice(&[first, lw[0], lw[1], lw[2]]);
                frame_buf.extend_from_slice(data);
                client_writer
                    .write_all(&frame_buf)
                    .await
                    .map_err(ProxyError::Io)?;
            } else {
                return Err(ProxyError::Proxy(format!(
                    "Abridged frame too large: {}",
                    data.len()
                )));
            }
        }
        ProtoTag::Intermediate | ProtoTag::Secure => {
            let padding_len = if proto_tag == ProtoTag::Secure {
                if !is_valid_secure_payload_len(data.len()) {
                    return Err(ProxyError::Proxy(format!(
                        "Secure payload must be 4-byte aligned, got {}",
                        data.len()
                    )));
                }
                secure_padding_len(data.len(), rng)
            } else {
                0
            };
            let mut len_val = (data.len() + padding_len) as u32;
            if quickack {
                len_val |= 0x8000_0000;
            }
            let total = 4 + data.len() + padding_len;
            frame_buf.clear();
            frame_buf.reserve(total);
            frame_buf.extend_from_slice(&len_val.to_le_bytes());
            frame_buf.extend_from_slice(data);
            if padding_len > 0 {
                let start = frame_buf.len();
                frame_buf.resize(start + padding_len, 0);
                rng.fill(&mut frame_buf[start..]);
            }
            client_writer
                .write_all(&frame_buf)
                .await
                .map_err(ProxyError::Io)?;
        }
    }

    Ok(())
}

async fn write_client_ack<W>(
    client_writer: &mut CryptoWriter<W>,
    proto_tag: ProtoTag,
    confirm: u32,
) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let bytes = if proto_tag == ProtoTag::Abridged {
        confirm.to_be_bytes()
    } else {
        confirm.to_le_bytes()
    };
    client_writer
        .write_all(&bytes)
        .await
        .map_err(ProxyError::Io)?;
    // ACK should remain low-latency.
    client_writer.flush().await.map_err(ProxyError::Io)
}
