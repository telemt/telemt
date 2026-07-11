use bytes::Bytes;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::OwnedSemaphorePermit;

use crate::crypto::{AesCbc, crc32, crc32c};
use crate::error::{ProxyError, Result};
use crate::protocol::constants::*;
use crate::stats::Stats;
use crate::stream::PooledBuffer;

use super::wire::{append_proxy_req_payload_into, proxy_req_payload_len};

const RPC_WRITER_FRAME_BUF_SHRINK_THRESHOLD: usize = 256 * 1024;
const RPC_WRITER_FRAME_BUF_RETAIN: usize = 64 * 1024;

enum WriterBytePermitState {
    Queued,
    Inflight,
}

/// Holds one writer memory reservation through queueing and socket write completion.
pub(crate) struct WriterBytePermit {
    _permit: OwnedSemaphorePermit,
    reserved_bytes: u64,
    stats: Arc<Stats>,
    state: WriterBytePermitState,
}

impl WriterBytePermit {
    /// Creates a queued reservation and publishes its rounded resident-byte cost.
    pub(crate) fn new(
        permit: OwnedSemaphorePermit,
        reserved_bytes: usize,
        stats: Arc<Stats>,
    ) -> Self {
        let reserved_bytes = reserved_bytes as u64;
        stats.add_me_writer_byte_budget_queued_bytes(reserved_bytes);
        Self {
            _permit: permit,
            reserved_bytes,
            stats,
            state: WriterBytePermitState::Queued,
        }
    }

    /// Moves the reservation from queued to in-flight accounting exactly once.
    pub(crate) fn mark_inflight(&mut self) {
        if matches!(self.state, WriterBytePermitState::Queued) {
            self.stats
                .move_me_writer_byte_budget_to_inflight(self.reserved_bytes);
            self.state = WriterBytePermitState::Inflight;
        }
    }
}

impl Drop for WriterBytePermit {
    fn drop(&mut self) {
        match self.state {
            WriterBytePermitState::Queued => self
                .stats
                .release_me_writer_byte_budget_queued_bytes(self.reserved_bytes),
            WriterBytePermitState::Inflight => self
                .stats
                .release_me_writer_byte_budget_inflight_bytes(self.reserved_bytes),
        }
    }
}

/// Commands sent to dedicated writer tasks to avoid mutex contention on TCP writes.
pub(crate) enum WriterCommand {
    Data {
        payload: Bytes,
        _permit: Option<OwnedSemaphorePermit>,
        writer_permit: WriterBytePermit,
    },
    DataAndFlush(Bytes),
    ProxyReq(ProxyReqCommand),
    ControlAndFlush([u8; 12]),
    Close,
}

/// Structured proxy request command that lets the writer encode directly into its frame buffer.
pub(crate) struct ProxyReqCommand {
    pub(crate) conn_id: u64,
    pub(crate) client_addr: std::net::SocketAddr,
    pub(crate) our_addr: std::net::SocketAddr,
    pub(crate) proto_flags: u32,
    pub(crate) proxy_tag: Option<[u8; 16]>,
    pub(crate) payload: PooledBuffer,
    pub(crate) _permit: OwnedSemaphorePermit,
    pub(crate) writer_permit: WriterBytePermit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RpcChecksumMode {
    Crc32,
    Crc32c,
}

impl RpcChecksumMode {
    pub(crate) fn from_handshake_flags(flags: u32) -> Self {
        if (flags & rpc_crypto_flags::USE_CRC32C) != 0 {
            Self::Crc32c
        } else {
            Self::Crc32
        }
    }

    pub(crate) fn advertised_flags(self) -> u32 {
        match self {
            Self::Crc32 => 0,
            Self::Crc32c => rpc_crypto_flags::USE_CRC32C,
        }
    }
}

pub(crate) fn rpc_crc(mode: RpcChecksumMode, data: &[u8]) -> u32 {
    match mode {
        RpcChecksumMode::Crc32 => crc32(data),
        RpcChecksumMode::Crc32c => crc32c(data),
    }
}

/// Builds a fixed-size control payload without heap allocation.
pub(crate) fn build_control_payload(tag: u32, value: u64) -> [u8; 12] {
    let mut payload = [0u8; 12];
    payload[..4].copy_from_slice(&tag.to_le_bytes());
    payload[4..].copy_from_slice(&value.to_le_bytes());
    payload
}

pub(crate) fn build_rpc_frame(seq_no: i32, payload: &[u8], crc_mode: RpcChecksumMode) -> Vec<u8> {
    let mut frame = Vec::new();
    build_rpc_frame_into(&mut frame, seq_no, payload, crc_mode);
    frame
}

fn build_rpc_frame_into(
    frame: &mut Vec<u8>,
    seq_no: i32,
    payload: &[u8],
    crc_mode: RpcChecksumMode,
) {
    let total_len = 4 + 4 + payload.len() + 4;
    frame.clear();
    frame.reserve_exact(total_len + 15);
    let total_len = total_len as u32;
    frame.extend_from_slice(&total_len.to_le_bytes());
    frame.extend_from_slice(&seq_no.to_le_bytes());
    frame.extend_from_slice(payload);
    let c = rpc_crc(crc_mode, &frame);
    frame.extend_from_slice(&c.to_le_bytes());
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
    let actual_crc = rpc_crc(RpcChecksumMode::Crc32, &full[..crc_offset]);
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
    flags: u32,
) -> [u8; 32] {
    let mut p = [0u8; 32];
    p[0..4].copy_from_slice(&RPC_HANDSHAKE_U32.to_le_bytes());
    p[4..8].copy_from_slice(&flags.to_le_bytes());

    // process_id sender_pid
    p[8..12].copy_from_slice(&our_ip);
    p[12..14].copy_from_slice(&our_port.to_le_bytes());
    p[14..16].copy_from_slice(&process_pid16().to_le_bytes());
    p[16..20].copy_from_slice(&process_utime().to_le_bytes());

    // process_id peer_pid
    p[20..24].copy_from_slice(&peer_ip);
    p[24..26].copy_from_slice(&peer_port.to_le_bytes());
    p[26..28].copy_from_slice(&0u16.to_le_bytes());
    p[28..32].copy_from_slice(&0u32.to_le_bytes());
    p
}

pub(crate) fn parse_handshake_flags(payload: &[u8]) -> Result<u32> {
    if payload.len() != 32 {
        return Err(ProxyError::InvalidHandshake(format!(
            "Bad handshake payload len: {}",
            payload.len()
        )));
    }
    let hs_type = u32::from_le_bytes(payload[0..4].try_into().unwrap());
    if hs_type != RPC_HANDSHAKE_U32 {
        return Err(ProxyError::InvalidHandshake(format!(
            "Expected HANDSHAKE 0x{RPC_HANDSHAKE_U32:08x}, got 0x{hs_type:08x}"
        )));
    }
    Ok(u32::from_le_bytes(payload[4..8].try_into().unwrap()))
}

fn process_pid16() -> u16 {
    (std::process::id() & 0xffff) as u16
}

fn process_utime() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
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
    pub(crate) crc_mode: RpcChecksumMode,
    pub(crate) frame_buf: Vec<u8>,
}

impl RpcWriter {
    pub(crate) async fn send(&mut self, payload: &[u8]) -> Result<()> {
        build_rpc_frame_into(&mut self.frame_buf, self.seq_no, payload, self.crc_mode);
        self.seq_no = self.seq_no.wrapping_add(1);
        self.encrypt_and_write_frame().await
    }

    pub(crate) async fn send_proxy_req(&mut self, command: &ProxyReqCommand) -> Result<()> {
        let payload_len = proxy_req_payload_len(
            command.payload.len(),
            command.proxy_tag.as_ref().map(|tag| tag.as_slice()),
            command.proto_flags,
        );
        let total_len = 4 + 4 + payload_len + 4;
        self.frame_buf.clear();
        self.frame_buf.reserve_exact(total_len + 15);
        self.frame_buf
            .extend_from_slice(&(total_len as u32).to_le_bytes());
        self.frame_buf.extend_from_slice(&self.seq_no.to_le_bytes());
        append_proxy_req_payload_into(
            &mut self.frame_buf,
            command.conn_id,
            command.client_addr,
            command.our_addr,
            command.payload.as_ref(),
            command.proxy_tag.as_ref().map(|tag| tag.as_slice()),
            command.proto_flags,
        );
        let c = rpc_crc(self.crc_mode, &self.frame_buf);
        self.frame_buf.extend_from_slice(&c.to_le_bytes());
        self.seq_no = self.seq_no.wrapping_add(1);
        self.encrypt_and_write_frame().await
    }

    async fn encrypt_and_write_frame(&mut self) -> Result<()> {
        let pad = (16 - (self.frame_buf.len() % 16)) % 16;
        let pad_pattern: [u8; 4] = [0x04, 0x00, 0x00, 0x00];
        for i in 0..pad {
            self.frame_buf.push(pad_pattern[i % 4]);
        }

        let cipher = AesCbc::new(self.key, self.iv);
        cipher
            .encrypt_in_place(&mut self.frame_buf)
            .map_err(|e| ProxyError::Crypto(format!("{e}")))?;

        if self.frame_buf.len() >= 16 {
            self.iv
                .copy_from_slice(&self.frame_buf[self.frame_buf.len() - 16..]);
        }
        let write_result = self.writer.write_all(&self.frame_buf).await;
        if self.frame_buf.capacity() > RPC_WRITER_FRAME_BUF_SHRINK_THRESHOLD {
            self.frame_buf.clear();
            self.frame_buf.shrink_to(RPC_WRITER_FRAME_BUF_RETAIN);
        }
        write_result.map_err(ProxyError::Io)
    }

    pub(crate) async fn send_and_flush(&mut self, payload: &[u8]) -> Result<()> {
        self.send(payload).await?;
        self.writer.flush().await.map_err(ProxyError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Semaphore;

    #[test]
    fn writer_byte_permit_tracks_queued_and_inflight_lifecycle() {
        let stats = Arc::new(Stats::default());
        let semaphore = Arc::new(Semaphore::new(2));
        let permit = semaphore
            .clone()
            .try_acquire_many_owned(2)
            .expect("writer byte permits must be available");
        let mut writer_permit = WriterBytePermit::new(permit, 32 * 1024, stats.clone());

        assert_eq!(stats.get_me_writer_byte_budget_queued_bytes_gauge(), 32 * 1024);
        assert_eq!(stats.get_me_writer_byte_budget_inflight_bytes_gauge(), 0);

        writer_permit.mark_inflight();
        assert_eq!(stats.get_me_writer_byte_budget_queued_bytes_gauge(), 0);
        assert_eq!(
            stats.get_me_writer_byte_budget_inflight_bytes_gauge(),
            32 * 1024
        );

        drop(writer_permit);
        assert_eq!(stats.get_me_writer_byte_budget_queued_bytes_gauge(), 0);
        assert_eq!(stats.get_me_writer_byte_budget_inflight_bytes_gauge(), 0);
        assert_eq!(semaphore.available_permits(), 2);
    }
}
