use std::collections::HashMap;

use std::io::ErrorKind;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::crypto::AesCbc;
use crate::error::{ProxyError, Result};
use crate::protocol::constants::*;
use crate::stats::Stats;

use super::codec::{RpcChecksumMode, WriterCommand, rpc_crc};
use super::registry::RouteResult;
use super::{ConnRegistry, MeResponse};

pub(crate) async fn reader_loop(
    mut rd: tokio::io::ReadHalf<TcpStream>,
    dk: [u8; 32],
    mut div: [u8; 16],
    crc_mode: RpcChecksumMode,
    reg: Arc<ConnRegistry>,
    enc_leftover: BytesMut,
    mut dec: BytesMut,
    tx: mpsc::Sender<WriterCommand>,
    ping_tracker: Arc<Mutex<HashMap<i64, (Instant, u64)>>>,
    rtt_stats: Arc<Mutex<HashMap<u64, (f64, f64)>>>,
    stats: Arc<Stats>,
    _writer_id: u64,
    degraded: Arc<AtomicBool>,
    writer_rtt_ema_ms_x10: Arc<AtomicU32>,
    reader_route_data_wait_ms: Arc<AtomicU64>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut raw = enc_leftover;
    let mut expected_seq: i32 = 0;

    loop {
        let mut tmp = [0u8; 16_384];
        let n = tokio::select! {
            res = rd.read(&mut tmp) => res.map_err(ProxyError::Io)?,
            _ = cancel.cancelled() => return Ok(()),
        };
        if n == 0 {
            stats.increment_me_reader_eof_total();
            return Err(ProxyError::Io(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "ME socket closed by peer",
            )));
        }
        raw.extend_from_slice(&tmp[..n]);

        let blocks = raw.len() / 16 * 16;
        if blocks > 0 {
            let mut chunk = raw.split_to(blocks);
            let mut new_iv = [0u8; 16];
            new_iv.copy_from_slice(&chunk[blocks - 16..blocks]);
            AesCbc::new(dk, div)
                .decrypt_in_place(&mut chunk[..])
                .map_err(|e| ProxyError::Crypto(format!("{e}")))?;
            div = new_iv;
            dec.extend_from_slice(&chunk);
        }

        while dec.len() >= 12 {
            let mut fl_bytes = [0u8; 4];
            fl_bytes.copy_from_slice(&dec[0..4]);
            let fl = u32::from_le_bytes(fl_bytes) as usize;
            if fl == 4 {
                let _ = dec.split_to(4);
                continue;
            }
            if !(12..=(1 << 24)).contains(&fl) {
                warn!(frame_len = fl, "Invalid RPC frame len");
                dec.clear();
                break;
            }
            if dec.len() < fl {
                break;
            }

            let frame = dec.split_to(fl).freeze();
            let pe = fl - 4;
            let mut ec_bytes = [0u8; 4];
            ec_bytes.copy_from_slice(&frame[pe..pe + 4]);
            let ec = u32::from_le_bytes(ec_bytes);
            let actual_crc = rpc_crc(crc_mode, &frame[..pe]);
            if actual_crc != ec {
                stats.increment_me_crc_mismatch();
                warn!(
                    frame_len = fl,
                    "CRC mismatch — CBC crypto desync, aborting ME connection"
                );
                return Err(ProxyError::Proxy("CRC mismatch (crypto desync)".into()));
            }

            let mut seq_bytes = [0u8; 4];
            seq_bytes.copy_from_slice(&frame[4..8]);
            let seq_no = i32::from_le_bytes(seq_bytes);
            if seq_no != expected_seq {
                stats.increment_me_seq_mismatch();
                warn!(seq_no, expected = expected_seq, "ME RPC seq mismatch");
                return Err(ProxyError::SeqNoMismatch {
                    expected: expected_seq,
                    got: seq_no,
                });
            }
            expected_seq = expected_seq.wrapping_add(1);

            let payload = frame.slice(8..pe);
            if payload.len() < 4 {
                continue;
            }

            let mut pt_bytes = [0u8; 4];
            pt_bytes.copy_from_slice(&payload[0..4]);
            let pt = u32::from_le_bytes(pt_bytes);
            let body = payload.slice(4..);

            if pt == RPC_PROXY_ANS_U32 && body.len() >= 12 {
                let mut flags_bytes = [0u8; 4];
                flags_bytes.copy_from_slice(&body[0..4]);
                let flags = u32::from_le_bytes(flags_bytes);
                let mut cid_bytes = [0u8; 8];
                cid_bytes.copy_from_slice(&body[4..12]);
                let cid = u64::from_le_bytes(cid_bytes);
                let data = body.slice(12..);
                trace!(cid, flags, len = data.len(), "RPC_PROXY_ANS");

                let data_wait_ms = reader_route_data_wait_ms.load(Ordering::Relaxed);
                let routed = if data_wait_ms == 0 {
                    reg.route_nowait(cid, MeResponse::Data { flags, data }).await
                } else {
                    reg.route_with_timeout(cid, MeResponse::Data { flags, data }, data_wait_ms)
                        .await
                };
                if !matches!(routed, RouteResult::Routed) {
                    match routed {
                        RouteResult::NoConn => stats.increment_me_route_drop_no_conn(),
                        RouteResult::ChannelClosed => stats.increment_me_route_drop_channel_closed(),
                        RouteResult::QueueFullBase => {
                            stats.increment_me_route_drop_queue_full();
                            stats.increment_me_route_drop_queue_full_base();
                        }
                        RouteResult::QueueFullHigh => {
                            stats.increment_me_route_drop_queue_full();
                            stats.increment_me_route_drop_queue_full_high();
                        }
                        RouteResult::Routed => {}
                    }
                    reg.unregister(cid).await;
                    send_close_conn(&tx, cid).await;
                }
            } else if pt == RPC_SIMPLE_ACK_U32 && body.len() >= 12 {
                let mut cid_bytes = [0u8; 8];
                cid_bytes.copy_from_slice(&body[0..8]);
                let cid = u64::from_le_bytes(cid_bytes);
                let mut cfm_bytes = [0u8; 4];
                cfm_bytes.copy_from_slice(&body[8..12]);
                let cfm = u32::from_le_bytes(cfm_bytes);
                trace!(cid, cfm, "RPC_SIMPLE_ACK");

                let routed = reg.route_nowait(cid, MeResponse::Ack(cfm)).await;
                if !matches!(routed, RouteResult::Routed) {
                    match routed {
                        RouteResult::NoConn => stats.increment_me_route_drop_no_conn(),
                        RouteResult::ChannelClosed => stats.increment_me_route_drop_channel_closed(),
                        RouteResult::QueueFullBase => {
                            stats.increment_me_route_drop_queue_full();
                            stats.increment_me_route_drop_queue_full_base();
                        }
                        RouteResult::QueueFullHigh => {
                            stats.increment_me_route_drop_queue_full();
                            stats.increment_me_route_drop_queue_full_high();
                        }
                        RouteResult::Routed => {}
                    }
                    reg.unregister(cid).await;
                    send_close_conn(&tx, cid).await;
                }
            } else if pt == RPC_CLOSE_EXT_U32 && body.len() >= 8 {
                let mut cid_bytes = [0u8; 8];
                cid_bytes.copy_from_slice(&body[0..8]);
                let cid = u64::from_le_bytes(cid_bytes);
                debug!(cid, "RPC_CLOSE_EXT from ME");
                reg.route(cid, MeResponse::Close).await;
                reg.unregister(cid).await;
            } else if pt == RPC_CLOSE_CONN_U32 && body.len() >= 8 {
                let mut cid_bytes = [0u8; 8];
                cid_bytes.copy_from_slice(&body[0..8]);
                let cid = u64::from_le_bytes(cid_bytes);
                debug!(cid, "RPC_CLOSE_CONN from ME");
                reg.route(cid, MeResponse::Close).await;
                reg.unregister(cid).await;
            } else if pt == RPC_PING_U32 && body.len() >= 8 {
                let mut ping_id_bytes = [0u8; 8];
                ping_id_bytes.copy_from_slice(&body[0..8]);
                let ping_id = i64::from_le_bytes(ping_id_bytes);
                trace!(ping_id, "RPC_PING -> RPC_PONG");
                let mut pong = Vec::with_capacity(12);
                pong.extend_from_slice(&RPC_PONG_U32.to_le_bytes());
                pong.extend_from_slice(&ping_id.to_le_bytes());
                if tx
                    .send(WriterCommand::DataAndFlush(Bytes::from(pong)))
                    .await
                    .is_err()
                {
                    warn!("PONG send failed");
                    break;
                }
            } else if pt == RPC_PONG_U32 && body.len() >= 8 {
                let mut ping_id_bytes = [0u8; 8];
                ping_id_bytes.copy_from_slice(&body[0..8]);
                let ping_id = i64::from_le_bytes(ping_id_bytes);
                stats.increment_me_keepalive_pong();
                if let Some((sent, wid)) = {
                    let mut guard = ping_tracker.lock().await;
                    guard.remove(&ping_id)
                } {
                    let rtt = sent.elapsed().as_secs_f64() * 1000.0;
                    let mut stats = rtt_stats.lock().await;
                    let entry = stats.entry(wid).or_insert((rtt, rtt));
                    entry.1 = entry.1.mul_add(0.8, rtt * 0.2);
                    if rtt < entry.0 {
                        entry.0 = rtt;
                    } else {
                        // allow slow baseline drift upward to avoid stale minimum
                        entry.0 = entry.0.mul_add(0.99, rtt * 0.01);
                    }
                    let degraded_now = entry.1 > entry.0 * 2.0;
                    degraded.store(degraded_now, Ordering::Relaxed);
                    writer_rtt_ema_ms_x10
                        .store((entry.1 * 10.0).clamp(0.0, f64::from(u32::MAX)) as u32, Ordering::Relaxed);
                    trace!(writer_id = wid, rtt_ms = rtt, ema_ms = entry.1, base_ms = entry.0, degraded = degraded_now, "ME RTT sample");
                }
            } else {
                debug!(
                    rpc_type = format_args!("0x{pt:08x}"),
                    len = body.len(),
                    "Unknown RPC"
                );
            }
        }
    }
}

async fn send_close_conn(tx: &mpsc::Sender<WriterCommand>, conn_id: u64) {
    let mut p = Vec::with_capacity(12);
    p.extend_from_slice(&RPC_CLOSE_CONN_U32.to_le_bytes());
    p.extend_from_slice(&conn_id.to_le_bytes());

    let _ = tx.send(WriterCommand::DataAndFlush(Bytes::from(p))).await;
}
