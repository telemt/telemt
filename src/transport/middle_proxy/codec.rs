use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::crypto::{AesCbc, crc32};
use crate::error::{ProxyError, Result};
use crate::protocol::constants::*;

/// Commands sent to dedicated writer tasks to avoid mutex contention on TCP writes.
pub(crate) enum WriterCommand {
    Data(Vec<u8>),
    DataAndFlush(Vec<u8>),
    Keepalive,
    Close,
}

pub(crate) fn build_rpc_frame(seq_no: i32, payload: &[u8]) -> Vec<u8> {
    let total_len = (4 + 4 + payload.len() + 4) as u32;
    let mut frame = Vec::with_capacity(total_len as usize);
    frame.extend_from_slice(&total_len.to_le_bytes());
    frame.extend_from_slice(&seq_no.to_le_bytes());
    frame.extend_from_slice(payload);
    let c = crc32(&frame);
    frame.extend_from_slice(&c.to_le_bytes());
    frame
}

pub(crate) async fn read_rpc_frame_plaintext(
    rd: &mut (impl AsyncReadExt + Unpin),
) -> Result<(i32, Vec<u8>)> {
    let mut len_buf = [0u8; 4];
    rd.read_exact(&mut len_buf).await.map_err(ProxyError::Io)?;
    let total_len = u32::from_le_bytes(len_buf) as usize;

    if !(12..=(1 << 24)).contains(&total_len) {
        return Err(ProxyError::InvalidHandshake(format!(
            "Bad RPC frame length: {total_len}"
        )));
    }

    let mut rest = vec![0u8; total_len - 4];
    rd.read_exact(&mut rest).await.map_err(ProxyError::Io)?;

    let mut full = Vec::with_capacity(total_len);
    full.extend_from_slice(&len_buf);
    full.extend_from_slice(&rest);

    let crc_offset = total_len - 4;
    let expected_crc = u32::from_le_bytes(full[crc_offset..crc_offset + 4].try_into().unwrap());
    let actual_crc = crc32(&full[..crc_offset]);
    if expected_crc != actual_crc {
        return Err(ProxyError::InvalidHandshake(format!(
            "CRC mismatch: 0x{expected_crc:08x} vs 0x{actual_crc:08x}"
        )));
    }

    let seq_no = i32::from_le_bytes(full[4..8].try_into().unwrap());
    let payload = full[8..crc_offset].to_vec();
    Ok((seq_no, payload))
}

pub(crate) fn build_nonce_payload(key_selector: u32, crypto_ts: u32, nonce: &[u8; 16]) -> [u8; 32] {
    let mut p = [0u8; 32];
    p[0..4].copy_from_slice(&RPC_NONCE_U32.to_le_bytes());
    p[4..8].copy_from_slice(&key_selector.to_le_bytes());
    p[8..12].copy_from_slice(&RPC_CRYPTO_AES_U32.to_le_bytes());
    p[12..16].copy_from_slice(&crypto_ts.to_le_bytes());
    p[16..32].copy_from_slice(nonce);
    p
}

pub(crate) fn parse_nonce_payload(d: &[u8]) -> Result<(u32, u32, u32, [u8; 16])> {
    if d.len() < 32 {
        return Err(ProxyError::InvalidHandshake(format!(
            "Nonce payload too short: {} bytes",
            d.len()
        )));
    }

    let t = u32::from_le_bytes(d[0..4].try_into().unwrap());
    if t != RPC_NONCE_U32 {
        return Err(ProxyError::InvalidHandshake(format!(
            "Expected RPC_NONCE 0x{RPC_NONCE_U32:08x}, got 0x{t:08x}"
        )));
    }

    let key_select = u32::from_le_bytes(d[4..8].try_into().unwrap());
    let schema = u32::from_le_bytes(d[8..12].try_into().unwrap());
    let ts = u32::from_le_bytes(d[12..16].try_into().unwrap());
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&d[16..32]);
    Ok((key_select, schema, ts, nonce))
}

pub(crate) fn build_handshake_payload(
    our_ip: [u8; 4],
    our_port: u16,
    peer_ip: [u8; 4],
    peer_port: u16,
) -> [u8; 32] {
    let mut p = [0u8; 32];
    p[0..4].copy_from_slice(&RPC_HANDSHAKE_U32.to_le_bytes());

    // Keep C memory layout compatibility for PID IPv4 bytes.
    p[8..12].copy_from_slice(&our_ip);
    p[12..14].copy_from_slice(&our_port.to_le_bytes());
    let pid = (std::process::id() & 0xffff) as u16;
    p[14..16].copy_from_slice(&pid.to_le_bytes());
    let utime = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    p[16..20].copy_from_slice(&utime.to_le_bytes());

    p[20..24].copy_from_slice(&peer_ip);
    p[24..26].copy_from_slice(&peer_port.to_le_bytes());
    p
}

pub(crate) fn cbc_encrypt_padded(
    key: &[u8; 32],
    iv: &[u8; 16],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16])> {
    let pad = (16 - (plaintext.len() % 16)) % 16;
    let mut buf = plaintext.to_vec();
    let pad_pattern: [u8; 4] = [0x04, 0x00, 0x00, 0x00];
    for i in 0..pad {
        buf.push(pad_pattern[i % 4]);
    }

    let cipher = AesCbc::new(*key, *iv);
    cipher
        .encrypt_in_place(&mut buf)
        .map_err(|e| ProxyError::Crypto(format!("CBC encrypt: {e}")))?;

    let mut new_iv = [0u8; 16];
    if buf.len() >= 16 {
        new_iv.copy_from_slice(&buf[buf.len() - 16..]);
    }
    Ok((buf, new_iv))
}

pub(crate) fn cbc_decrypt_inplace(
    key: &[u8; 32],
    iv: &[u8; 16],
    data: &mut [u8],
) -> Result<[u8; 16]> {
    let mut new_iv = [0u8; 16];
    if data.len() >= 16 {
        new_iv.copy_from_slice(&data[data.len() - 16..]);
    }

    AesCbc::new(*key, *iv)
        .decrypt_in_place(data)
        .map_err(|e| ProxyError::Crypto(format!("CBC decrypt: {e}")))?;
    Ok(new_iv)
}

pub(crate) struct RpcWriter {
    pub(crate) writer: tokio::io::WriteHalf<tokio::net::TcpStream>,
    pub(crate) key: [u8; 32],
    pub(crate) iv: [u8; 16],
    pub(crate) seq_no: i32,
}

impl RpcWriter {
    pub(crate) async fn send(&mut self, payload: &[u8]) -> Result<()> {
        let frame = build_rpc_frame(self.seq_no, payload);
        self.seq_no += 1;

        let pad = (16 - (frame.len() % 16)) % 16;
        let mut buf = frame;
        let pad_pattern: [u8; 4] = [0x04, 0x00, 0x00, 0x00];
        for i in 0..pad {
            buf.push(pad_pattern[i % 4]);
        }

        let cipher = AesCbc::new(self.key, self.iv);
        cipher
            .encrypt_in_place(&mut buf)
            .map_err(|e| ProxyError::Crypto(format!("{e}")))?;

        if buf.len() >= 16 {
            self.iv.copy_from_slice(&buf[buf.len() - 16..]);
        }
        self.writer.write_all(&buf).await.map_err(ProxyError::Io)
    }

    pub(crate) async fn send_and_flush(&mut self, payload: &[u8]) -> Result<()> {
        self.send(payload).await?;
        self.writer.flush().await.map_err(ProxyError::Io)
    }

    /// Sends a 4-byte keepalive marker directly into the CBC stream.
    /// This is not an RPC frame and must not consume sequence numbers.
    pub(crate) async fn send_keepalive(&mut self) -> Result<()> {
        let mut buf = [0u8; 16];
        for i in 0..4 {
            let start = i * 4;
            let end = start + 4;
            buf[start..end].copy_from_slice(&PADDING_FILLER);
        }

        let cipher = AesCbc::new(self.key, self.iv);
        let mut v = buf.to_vec();
        cipher
            .encrypt_in_place(&mut v)
            .map_err(|e| ProxyError::Crypto(format!("{e}")))?;

        if v.len() >= 16 {
            self.iv.copy_from_slice(&v[v.len() - 16..]);
        }
        self.writer.write_all(&v).await.map_err(ProxyError::Io)?;
        self.writer.flush().await.map_err(ProxyError::Io)
    }
}
