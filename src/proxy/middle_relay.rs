use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info, trace};

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::protocol::constants::*;
use crate::proxy::handshake::HandshakeSuccess;
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader, CryptoWriter};
use crate::transport::middle_proxy::{MePool, MeResponse, proto_flags_for_tag};

pub(crate) async fn handle_via_middle_proxy<R, W>(
    mut crypto_reader: CryptoReader<R>,
    mut crypto_writer: CryptoWriter<W>,
    success: HandshakeSuccess,
    me_pool: Arc<MePool>,
    stats: Arc<Stats>,
    _config: Arc<ProxyConfig>,
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

    let (conn_id, mut me_rx) = me_pool.registry().register().await;

    stats.increment_user_connects(&user);
    stats.increment_user_curr_connects(&user);

    let proto_flags = proto_flags_for_tag(proto_tag, me_pool.has_proxy_tag());
    debug!(
        user = %user,
        conn_id,
        proto_flags = format_args!("0x{:08x}", proto_flags),
        "ME relay started"
    );

    let translated_local_addr = me_pool.translate_our_addr(local_addr);

    let result: Result<()> = loop {
        tokio::select! {
            client_frame = read_client_payload(&mut crypto_reader, proto_tag) => {
                match client_frame {
                    Ok(Some((payload, quickack))) => {
                        trace!(conn_id, bytes = payload.len(), "C->ME frame");
                        stats.add_user_octets_from(&user, payload.len() as u64);
                        let mut flags = proto_flags;
                        if quickack {
                            flags |= RPC_FLAG_QUICKACK;
                        }
                        if payload.len() >= 8 && payload[..8].iter().all(|b| *b == 0) {
                            flags |= RPC_FLAG_NOT_ENCRYPTED;
                        }
                        me_pool.send_proxy_req(
                            conn_id,
                            success.dc_idx,
                            peer,
                            translated_local_addr,
                            &payload,
                            flags,
                        ).await?;
                    }
                    Ok(None) => {
                        debug!(conn_id, "Client EOF");
                        let _ = me_pool.send_close(conn_id).await;
                        break Ok(());
                    }
                    Err(e) => break Err(e),
                }
            }
            me_msg = me_rx.recv() => {
                match me_msg {
                    Some(MeResponse::Data { flags, data }) => {
                        trace!(conn_id, bytes = data.len(), flags, "ME->C data");
                        stats.add_user_octets_to(&user, data.len() as u64);
                        write_client_payload(&mut crypto_writer, proto_tag, flags, &data, rng.as_ref()).await?;
                    }
                    Some(MeResponse::Ack(confirm)) => {
                        trace!(conn_id, confirm, "ME->C quickack");
                        write_client_ack(&mut crypto_writer, proto_tag, confirm).await?;
                    }
                    Some(MeResponse::Close) => {
                        debug!(conn_id, "ME sent close");
                        break Ok(());
                    }
                    None => {
                        debug!(conn_id, "ME channel closed");
                        break Err(ProxyError::Proxy("ME connection lost".into()));
                    }
                }
            }
        }
    };

    debug!(user = %user, conn_id, "ME relay cleanup");
    me_pool.registry().unregister(conn_id).await;
    stats.decrement_user_curr_connects(&user);
    result
}

async fn read_client_payload<R>(
    client_reader: &mut CryptoReader<R>,
    proto_tag: ProtoTag,
) -> Result<Option<(Vec<u8>, bool)>>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let (len, quickack) = match proto_tag {
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
            (len, quickack)
        }
        ProtoTag::Intermediate | ProtoTag::Secure => {
            let mut len_buf = [0u8; 4];
            match client_reader.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(ProxyError::Io(e)),
            }
            let quickack = (len_buf[3] & 0x80) != 0;
            ((u32::from_le_bytes(len_buf) & 0x7fff_ffff) as usize, quickack)
        }
    };

    if len > 16 * 1024 * 1024 {
        return Err(ProxyError::Proxy(format!("Frame too large: {len}")));
    }

    let mut payload = vec![0u8; len];
    client_reader
        .read_exact(&mut payload)
        .await
        .map_err(ProxyError::Io)?;

    // Secure Intermediate: remove random padding (last len%4 bytes)
    if proto_tag == ProtoTag::Secure {
        let rem = len % 4;
        if rem != 0 && payload.len() >= rem {
            payload.truncate(len - rem);
        }
    }
    Ok(Some((payload, quickack)))
}

async fn write_client_payload<W>(
    client_writer: &mut CryptoWriter<W>,
    proto_tag: ProtoTag,
    flags: u32,
    data: &[u8],
    rng: &SecureRandom,
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
                client_writer
                    .write_all(&[first])
                    .await
                    .map_err(ProxyError::Io)?;
            } else if len_words < (1 << 24) {
                let mut first = 0x7fu8;
                if quickack {
                    first |= 0x80;
                }
                let lw = (len_words as u32).to_le_bytes();
                client_writer
                    .write_all(&[first, lw[0], lw[1], lw[2]])
                    .await
                    .map_err(ProxyError::Io)?;
            } else {
                return Err(ProxyError::Proxy(format!(
                    "Abridged frame too large: {}",
                    data.len()
                )));
            }

            client_writer
                .write_all(data)
                .await
                .map_err(ProxyError::Io)?;
        }
        ProtoTag::Intermediate | ProtoTag::Secure => {
            let padding_len = if proto_tag == ProtoTag::Secure {
                (rng.bytes(1)[0] % 4) as usize
            } else {
                0
            };
            let mut len = (data.len() + padding_len) as u32;
            if quickack {
                len |= 0x8000_0000;
            }
            client_writer
                .write_all(&len.to_le_bytes())
                .await
                .map_err(ProxyError::Io)?;
            client_writer
                .write_all(data)
                .await
                .map_err(ProxyError::Io)?;
            if padding_len > 0 {
                let pad = rng.bytes(padding_len);
                client_writer
                    .write_all(&pad)
                    .await
                    .map_err(ProxyError::Io)?;
            }
        }
    }

    // Avoid unconditional per-frame flush (throughput killer on large downloads).
    // Flush only when low-latency ack semantics are requested or when
    // CryptoWriter has buffered pending ciphertext that must be drained.
    if quickack || client_writer.has_pending() {
        client_writer.flush().await.map_err(ProxyError::Io)?;
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
