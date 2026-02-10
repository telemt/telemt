//! Middle Proxy handshake: nonce exchange → KDF → AES-CBC → RPC handshake
//!
//! Two public entry points:
//! - [`handshake_middle_proxy`] — returns [`HandshakedMiddleConnection`] (poolable)
//! - [`connect_middle_proxy`]   — convenience: handshake + wrap for specific client

use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, trace};

use crate::crypto::{AesCbcChain, SecureRandom, crc32, derive_middleproxy_keys};
use crate::error::{ProxyError, Result};
use crate::protocol::constants::*;
use crate::util::ip::IpInfo;

use super::codec::*;
use super::connection::{HandshakedMiddleConnection, MiddleProxyStream};

/// Sequence number for the first frame (protocol-mandated).
const START_SEQ_NO: i32 = -2;

/// Perform the middle-proxy handshake, returning a poolable connection.
///
/// The returned [`HandshakedMiddleConnection`] has completed:
/// 1. Nonce exchange (plain MTProto frames)
/// 2. Key derivation (MD5 + SHA1 KDF)
/// 3. RPC handshake (through AES-CBC)
///
/// Call [`HandshakedMiddleConnection::into_stream`] to bind to a specific client.
pub async fn handshake_middle_proxy(
    mut stream: TcpStream,
    proxy_secret: &[u8],
    ip_info: &IpInfo,
    prefer_ipv6: bool,
    rng: &SecureRandom,
) -> Result<HandshakedMiddleConnection> {
    let peer_addr = stream.peer_addr().map_err(ProxyError::Io)?;
    let local_addr = stream.local_addr().map_err(ProxyError::Io)?;
    let is_ipv6 = peer_addr.is_ipv6();

    debug!(
        peer = %peer_addr,
        local = %local_addr,
        ipv6 = is_ipv6,
        "Middle proxy handshake starting"
    );

    // ---- Key selector (first 4 bytes of proxy secret) ----
    if proxy_secret.len() < 4 {
        return Err(ProxyError::Crypto("Proxy secret too short".into()));
    }
    let key_selector: [u8; 4] = proxy_secret[..4].try_into().unwrap();

    // ---- Generate client nonce ----
    let nonce: [u8; NONCE_LEN] = rng.bytes(NONCE_LEN)
        .try_into()
        .map_err(|_| ProxyError::Internal("nonce generation failed".into()))?;

    // ---- Phase 1: Send RPC_NONCE (plain MTProto frame, no CBC) ----
    let nonce_msg = build_nonce_request(&key_selector, &nonce);
    let crypto_ts: [u8; 4] = nonce_msg[12..16].try_into().unwrap();

    let mut write_seq = START_SEQ_NO;
    let frame = build_mtproto_frame(&nonce_msg, write_seq);
    write_seq += 1;

    stream.write_all(&frame).await.map_err(ProxyError::Io)?;
    stream.flush().await.map_err(ProxyError::Io)?;

    // ---- Phase 2: Read RPC_NONCE response (plain MTProto frame) ----
    let mut read_seq = START_SEQ_NO;
    let nonce_ans = read_plain_mtproto_frame(&mut stream, &mut read_seq).await?;

    let nonce_resp = NonceResponse::parse(&nonce_ans)
        .ok_or_else(|| ProxyError::InvalidHandshake(
            format!("Bad nonce response length: {}", nonce_ans.len()),
        ))?;

    if !nonce_resp.validate(&key_selector) {
        return Err(ProxyError::InvalidHandshake(
            "Nonce response validation failed (type/selector/schema mismatch)".into(),
        ));
    }

    // ---- Phase 3: Key derivation ----
    let my_ip = override_with_public_ip(local_addr.ip(), ip_info, is_ipv6);
    let my_port = local_addr.port();
    let tg_ip = peer_addr.ip();
    let tg_port = peer_addr.port();

    let my_addr_for_kdf = SocketAddr::new(my_ip, my_port);
    let tg_addr_for_kdf = SocketAddr::new(tg_ip, tg_port);

    let (tg_v4, tg_v6, tg_port_le) = encode_ip_for_kdf(tg_addr_for_kdf);
    let (my_v4, my_v6, my_port_le) = encode_ip_for_kdf(my_addr_for_kdf);

    let (enc_key, enc_iv) = derive_middleproxy_keys(
        &nonce_resp.server_nonce, &nonce, &crypto_ts,
        tg_v4.as_deref(), &my_port_le, b"CLIENT", my_v4.as_deref(), &tg_port_le,
        proxy_secret, my_v6.as_ref(), tg_v6.as_ref(),
    );

    let (dec_key, dec_iv) = derive_middleproxy_keys(
        &nonce_resp.server_nonce, &nonce, &crypto_ts,
        tg_v4.as_deref(), &my_port_le, b"SERVER", my_v4.as_deref(), &tg_port_le,
        proxy_secret, my_v6.as_ref(), tg_v6.as_ref(),
    );

    trace!(
        "Middle proxy keys derived (enc_key[0..4]={:02x?}, dec_key[0..4]={:02x?})",
        &enc_key[..4],
        &dec_key[..4]
    );

    // ---- Phase 4: Send RPC_HANDSHAKE through CBC ----
    let mut enc_chain = AesCbcChain::new(enc_key, enc_iv);
    let mut dec_chain = AesCbcChain::new(dec_key, dec_iv);

    let handshake_msg = build_handshake_request();
    let handshake_frame = build_mtproto_frame(&handshake_msg, write_seq);
    write_seq += 1;

    let encrypted_handshake = enc_chain.encrypt(&handshake_frame)
        .map_err(|e| ProxyError::Crypto(format!("CBC encrypt handshake: {}", e)))?;
    stream.write_all(&encrypted_handshake).await.map_err(ProxyError::Io)?;
    stream.flush().await.map_err(ProxyError::Io)?;

    // ---- Phase 5: Read RPC_HANDSHAKE response through CBC ----
    let mut dec_buf = Vec::new();
    let handshake_ans = read_cbc_mtproto_frame(
        &mut stream, &mut dec_chain, &mut dec_buf, &mut read_seq,
    ).await?;

    if !validate_handshake_response(&handshake_ans) {
        return Err(ProxyError::InvalidHandshake(
            format!("Bad handshake answer (len={})", handshake_ans.len()),
        ));
    }

    info!(peer = %peer_addr, "Middle proxy handshake complete");

    Ok(HandshakedMiddleConnection {
        stream,
        enc_chain,
        dec_chain,
        write_seq,
        read_seq,
        my_ip,
        my_port,
    })
}

/// Convenience: handshake + wrap for a specific client in one call.
///
/// Equivalent to calling `handshake_middle_proxy` then `into_stream`.
pub async fn connect_middle_proxy(
    stream: TcpStream,
    proxy_secret: &[u8],
    ad_tag: &[u8; 16],
    proto_tag: ProtoTag,
    client_addr: SocketAddr,
    ip_info: &IpInfo,
    rng: &SecureRandom,
) -> Result<MiddleProxyStream> {
    let conn = handshake_middle_proxy(stream, proxy_secret, ip_info, false, rng).await?;
    Ok(conn.into_stream(client_addr, proto_tag, *ad_tag, rng))
}

// ============= Internal Helpers =============

/// Override local IP with detected public IP when behind NAT.
fn override_with_public_ip(local_ip: IpAddr, ip_info: &IpInfo, is_ipv6: bool) -> IpAddr {
    if is_ipv6 {
        ip_info.ipv6.unwrap_or(local_ip)
    } else {
        ip_info.ipv4.unwrap_or(local_ip)
    }
}

/// Read a **plain** (non-CBC) MTProto full frame from a TCP stream.
///
/// Handles padding-only frames (length == 4) by skipping them.
async fn read_plain_mtproto_frame(
    stream: &mut TcpStream,
    seq_no: &mut i32,
) -> Result<Vec<u8>> {
    loop {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.map_err(ProxyError::Io)?;
        let msg_len = u32::from_le_bytes(len_buf) as usize;

        // Skip padding pseudo-frames
        if msg_len == 4 {
            continue;
        }

        if msg_len < MIN_MSG_LEN || msg_len > MAX_MSG_LEN || msg_len % PADDING_FILLER.len() != 0 {
            return Err(ProxyError::InvalidHandshake(
                format!("Bad MTProto frame length: {}", msg_len),
            ));
        }

        // Read remaining: seq(4) + data(msg_len-12) + crc(4)
        let remaining = msg_len - 4;
        let mut buf = vec![0u8; remaining];
        stream.read_exact(&mut buf).await.map_err(ProxyError::Io)?;

        let msg_seq = i32::from_le_bytes(buf[0..4].try_into().unwrap());
        if msg_seq != *seq_no {
            return Err(ProxyError::SeqNoMismatch { expected: *seq_no, got: msg_seq });
        }
        *seq_no += 1;

        let data_len = msg_len - 12;
        let data = &buf[4..4 + data_len];
        let crc_bytes: [u8; 4] = buf[4 + data_len..8 + data_len].try_into().unwrap();
        let expected_crc = u32::from_le_bytes(crc_bytes);

        let mut crc_input = Vec::with_capacity(8 + data_len);
        crc_input.extend_from_slice(&len_buf);
        crc_input.extend_from_slice(&buf[0..4]); // seq
        crc_input.extend_from_slice(data);
        let computed_crc = crc32(&crc_input);

        if computed_crc != expected_crc {
            return Err(ProxyError::ChecksumMismatch {
                expected: expected_crc,
                got: computed_crc,
            });
        }

        return Ok(data.to_vec());
    }
}

/// Read one MTProto full frame through AES-CBC decryption.
///
/// `dec_buf` carries buffered decrypted bytes across calls.
async fn read_cbc_mtproto_frame(
    stream: &mut TcpStream,
    dec_chain: &mut AesCbcChain,
    dec_buf: &mut Vec<u8>,
    seq_no: &mut i32,
) -> Result<Vec<u8>> {
    loop {
        // Read 4 bytes (length) through CBC
        let len_bytes = read_cbc_exact(stream, dec_chain, dec_buf, 4).await?;
        let msg_len = u32::from_le_bytes(len_bytes[0..4].try_into().unwrap()) as usize;

        if msg_len == 4 {
            continue; // padding
        }

        if msg_len < MIN_MSG_LEN || msg_len > MAX_MSG_LEN || msg_len % PADDING_FILLER.len() != 0 {
            return Err(ProxyError::InvalidHandshake(
                format!("Bad CBC MTProto frame length: {}", msg_len),
            ));
        }

        let remaining = msg_len - 4;
        let rest = read_cbc_exact(stream, dec_chain, dec_buf, remaining).await?;

        let msg_seq = i32::from_le_bytes(rest[0..4].try_into().unwrap());
        if msg_seq != *seq_no {
            return Err(ProxyError::SeqNoMismatch { expected: *seq_no, got: msg_seq });
        }
        *seq_no += 1;

        let data_len = msg_len - 12;
        let data = &rest[4..4 + data_len];
        let crc_bytes: [u8; 4] = rest[4 + data_len..8 + data_len].try_into().unwrap();
        let expected_crc = u32::from_le_bytes(crc_bytes);

        let mut crc_input = Vec::with_capacity(8 + data_len);
        crc_input.extend_from_slice(&len_bytes);
        crc_input.extend_from_slice(&rest[0..4]); // seq
        crc_input.extend_from_slice(data);
        let computed_crc = crc32(&crc_input);

        if computed_crc != expected_crc {
            return Err(ProxyError::ChecksumMismatch {
                expected: expected_crc,
                got: computed_crc,
            });
        }

        return Ok(data.to_vec());
    }
}

/// Read exactly `n` bytes through AES-CBC decryption layer.
///
/// Reads block-aligned (16 bytes) chunks from TCP, decrypts, and buffers excess.
async fn read_cbc_exact(
    stream: &mut TcpStream,
    dec_chain: &mut AesCbcChain,
    dec_buf: &mut Vec<u8>,
    n: usize,
) -> Result<Vec<u8>> {
    while dec_buf.len() < n {
        let needed = n - dec_buf.len();
        // Round up to next 16-byte boundary
        let aligned = if needed % 16 == 0 { needed } else { needed + (16 - needed % 16) };
        let mut encrypted = vec![0u8; aligned];
        stream.read_exact(&mut encrypted).await.map_err(ProxyError::Io)?;
        let decrypted = dec_chain.decrypt(&encrypted)
            .map_err(|e| ProxyError::Crypto(format!("CBC decrypt: {}", e)))?;
        dec_buf.extend_from_slice(&decrypted);
    }

    let result = dec_buf[..n].to_vec();
    *dec_buf = dec_buf[n..].to_vec();
    Ok(result)
}