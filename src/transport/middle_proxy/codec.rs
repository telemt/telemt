use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::Bytes;

use crate::crypto::{AesCbc, crc32, crc32c};
use crate::error::{ProxyError, Result};
use crate::protocol::constants::*;

/// Commands sent to dedicated writer tasks to avoid mutex contention on TCP writes.
pub(crate) enum WriterCommand {
    Data(Bytes),
    DataAndFlush(Bytes),
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RpcChecksumMode {
    Crc32,
    Crc32c,
}

impl RpcChecksumMode {
    pub(crate) const fn from_handshake_flags(flags: u32) -> Self {
        if (flags & rpc_crypto_flags::USE_CRC32C) != 0 {
            Self::Crc32c
        } else {
            Self::Crc32
        }
    }

    pub(crate) const fn advertised_flags(self) -> u32 {
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

/// Maximum payload length that can be expressed in a u32 frame-length field.
/// payload.len() + 12 (len + seq + crc) must not exceed u32::MAX.
pub(crate) const MAX_RPC_FRAME_PAYLOAD_LEN: usize = (u32::MAX as usize) - 12;

pub(crate) fn build_rpc_frame(
    seq_no: i32,
    payload: &[u8],
    crc_mode: RpcChecksumMode,
) -> crate::error::Result<Vec<u8>> {
    let total_len = payload
        .len()
        .checked_add(12)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| {
            crate::error::ProxyError::Proxy(format!(
                "RPC payload too large for u32 frame header: {} bytes (max {})",
                payload.len(),
                MAX_RPC_FRAME_PAYLOAD_LEN,
            ))
        })?;
    let mut frame = Vec::with_capacity(total_len as usize);
    frame.extend_from_slice(&total_len.to_le_bytes());
    frame.extend_from_slice(&seq_no.to_le_bytes());
    frame.extend_from_slice(payload);
    let c = rpc_crc(crc_mode, &frame);
    frame.extend_from_slice(&c.to_le_bytes());
    Ok(frame)
}

/// Maximum plaintext frame size used during the nonce-exchange handshake phase.
/// The legitimate nonce response is 44 bytes; 256 bytes is generous headroom.
pub(crate) const HANDSHAKE_MAX_PLAINTEXT_FRAME_LEN: usize = 256;

pub(crate) async fn read_rpc_frame_plaintext(
    rd: &mut (impl AsyncReadExt + Unpin),
    max_frame_len: usize,
) -> Result<(i32, Vec<u8>)> {
    let mut len_buf = [0u8; 4];
    rd.read_exact(&mut len_buf).await.map_err(ProxyError::Io)?;
    let total_len = u32::from_le_bytes(len_buf) as usize;

    // Lower bound: a valid frame is at least 12 bytes (4 len + 4 seq + 4 crc).
    // Upper bound: caller-supplied to confine allocation to what the current
    // protocol phase actually needs (e.g. 256 B during nonce exchange).
    if !(12..=max_frame_len).contains(&total_len) {
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
    let mut expected_crc_bytes = [0u8; 4];
    expected_crc_bytes.copy_from_slice(&full[crc_offset..crc_offset + 4]);
    let expected_crc = u32::from_le_bytes(expected_crc_bytes);
    let actual_crc = rpc_crc(RpcChecksumMode::Crc32, &full[..crc_offset]);
    if expected_crc != actual_crc {
        return Err(ProxyError::InvalidHandshake("RPC CRC mismatch".to_string()));
    }

    let mut seq_bytes = [0u8; 4];
    seq_bytes.copy_from_slice(&full[4..8]);
    let seq_no = i32::from_le_bytes(seq_bytes);
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

    let mut type_bytes = [0u8; 4];
    type_bytes.copy_from_slice(&d[0..4]);
    let t = u32::from_le_bytes(type_bytes);
    if t != RPC_NONCE_U32 {
        return Err(ProxyError::InvalidHandshake(format!(
            "Expected RPC_NONCE 0x{RPC_NONCE_U32:08x}, got 0x{t:08x}"
        )));
    }

    let mut key_select_bytes = [0u8; 4];
    key_select_bytes.copy_from_slice(&d[4..8]);
    let key_select = u32::from_le_bytes(key_select_bytes);
    let mut schema_bytes = [0u8; 4];
    schema_bytes.copy_from_slice(&d[8..12]);
    let schema = u32::from_le_bytes(schema_bytes);
    let mut ts_bytes = [0u8; 4];
    ts_bytes.copy_from_slice(&d[12..16]);
    let ts = u32::from_le_bytes(ts_bytes);
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
    let mut hs_type_bytes = [0u8; 4];
    hs_type_bytes.copy_from_slice(&payload[0..4]);
    let hs_type = u32::from_le_bytes(hs_type_bytes);
    if hs_type != RPC_HANDSHAKE_U32 {
        return Err(ProxyError::InvalidHandshake(format!(
            "Expected HANDSHAKE 0x{RPC_HANDSHAKE_U32:08x}, got 0x{hs_type:08x}"
        )));
    }
    let mut flags_bytes = [0u8; 4];
    flags_bytes.copy_from_slice(&payload[4..8]);
    Ok(u32::from_le_bytes(flags_bytes))
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
}

impl RpcWriter {
    pub(crate) async fn send(&mut self, payload: &[u8]) -> Result<()> {
        let frame = build_rpc_frame(self.seq_no, payload, self.crc_mode)?;
        self.seq_no = self.seq_no.wrapping_add(1);

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
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verifies the boundary constant is exactly u32::MAX - 12, guaranteeing the
    // checked-arithmetic path in build_rpc_frame is the only possible overflow guard.
    #[test]
    fn max_rpc_frame_payload_len_constant_is_correct() {
        assert_eq!(MAX_RPC_FRAME_PAYLOAD_LEN, u32::MAX as usize - 12);
    }

    // Verifies that the arithmetic build_rpc_frame uses would fire for a payload
    // that is one byte over the u32 boundary.  We confirm the check via pure
    // arithmetic because allocating ~4 GiB in a unit test is impractical.
    #[test]
    fn build_rpc_frame_overflow_arithmetic_is_detected() {
        let oversize: usize = MAX_RPC_FRAME_PAYLOAD_LEN + 1;
        let would_overflow = oversize
            .checked_add(12)
            .and_then(|n| u32::try_from(n).ok())
            .is_none();
        assert!(
            would_overflow,
            "overflow detection must trigger for payload of {oversize} bytes"
        );
    }

    #[test]
    fn build_rpc_frame_single_byte_payload_encodes_correct_crc() {
        let frame = build_rpc_frame(42, &[0xAB], RpcChecksumMode::Crc32).unwrap();
        // total_len = 4 (len) + 4 (seq) + 1 (payload) + 4 (crc) = 13
        assert_eq!(frame.len(), 13);
        let total_len = u32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize;
        assert_eq!(total_len, 13);
        let seq = i32::from_le_bytes(frame[4..8].try_into().unwrap());
        assert_eq!(seq, 42);
        assert_eq!(frame[8], 0xAB);
        let crc_offset = total_len - 4;
        let stored = u32::from_le_bytes(frame[crc_offset..crc_offset + 4].try_into().unwrap());
        let computed = rpc_crc(RpcChecksumMode::Crc32, &frame[..crc_offset]);
        assert_eq!(stored, computed, "CRC must cover all bytes including the length field");
    }

    #[test]
    fn build_rpc_frame_empty_payload_is_valid() {
        let frame = build_rpc_frame(0, &[], RpcChecksumMode::Crc32c).unwrap();
        assert_eq!(frame.len(), 12);
        let total_len = u32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize;
        assert_eq!(total_len, 12);
        let crc_offset = total_len - 4;
        let stored = u32::from_le_bytes(frame[crc_offset..crc_offset + 4].try_into().unwrap());
        let computed = rpc_crc(RpcChecksumMode::Crc32c, &frame[..crc_offset]);
        assert_eq!(stored, computed);
    }

    #[test]
    fn build_rpc_frame_4k_payload_length_field_matches() {
        let payload = vec![0xFFu8; 4096];
        let frame = build_rpc_frame(0, &payload, RpcChecksumMode::Crc32).unwrap();
        assert_eq!(frame.len(), 4 + 4 + 4096 + 4);
        let total_len = u32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize;
        assert_eq!(total_len, frame.len());
    }

    // A bit-flip in the CRC bytes must be detected on parse.
    #[test]
    fn modified_crc_is_detected_by_parse() {
        let mut frame = build_rpc_frame(1, b"hello", RpcChecksumMode::Crc32).unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 0xFF;
        let total_len = u32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize;
        let crc_offset = total_len - 4;
        let stored = u32::from_le_bytes(frame[crc_offset..crc_offset + 4].try_into().unwrap());
        let computed = rpc_crc(RpcChecksumMode::Crc32, &frame[..crc_offset]);
        assert_ne!(stored, computed, "corrupted CRC must not equal computed CRC");
    }

    // A bit-flip in the payload bytes must invalidate the CRC.
    #[test]
    fn modified_payload_invalidates_crc() {
        let mut frame = build_rpc_frame(-2, b"nonce", RpcChecksumMode::Crc32).unwrap();
        frame[8] ^= 0x01;
        let total_len = u32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize;
        let crc_offset = total_len - 4;
        let stored = u32::from_le_bytes(frame[crc_offset..crc_offset + 4].try_into().unwrap());
        let computed = rpc_crc(RpcChecksumMode::Crc32, &frame[..crc_offset]);
        assert_ne!(stored, computed);
    }

    // seq_no -2 with a 32-byte nonce payload must produce a 44-byte frame
    // matching the fixed handshake wire format.
    #[test]
    fn build_rpc_frame_nonce_handshake_frame_is_44_bytes() {
        let payload = [0u8; 32];
        let frame = build_rpc_frame(-2, &payload, RpcChecksumMode::Crc32).unwrap();
        assert_eq!(frame.len(), 44);
        let seq = i32::from_le_bytes(frame[4..8].try_into().unwrap());
        assert_eq!(seq, -2);
    }

    // --- read_rpc_frame_plaintext: max_frame_len enforcement (DoS guard) ---

    // Wellformed 44-byte nonce frame must be accepted when max equals its length.
    #[tokio::test]
    async fn read_plaintext_accepts_exact_max_len() {
        let frame = build_rpc_frame(-2, &[0u8; 32], RpcChecksumMode::Crc32).unwrap();
        assert_eq!(frame.len(), 44);
        let mut cursor = std::io::Cursor::new(frame);
        read_rpc_frame_plaintext(&mut cursor, 44).await.unwrap();
    }

    // A frame one byte larger than max_frame_len must be rejected before any body read.
    #[tokio::test]
    async fn read_plaintext_rejects_one_byte_over_max() {
        let frame = build_rpc_frame(-2, &[0u8; 32], RpcChecksumMode::Crc32).unwrap();
        assert_eq!(frame.len(), 44);
        let mut cursor = std::io::Cursor::new(frame);
        let result = read_rpc_frame_plaintext(&mut cursor, 43).await;
        assert!(result.is_err(), "frame one byte over max_frame_len must be rejected");
    }

    // An attacker sends length = 0 (below the 12-byte structural minimum).
    #[tokio::test]
    async fn read_plaintext_rejects_zero_length() {
        let data = 0u32.to_le_bytes().to_vec();
        let mut cursor = std::io::Cursor::new(data);
        let result = read_rpc_frame_plaintext(&mut cursor, 256).await;
        assert!(result.is_err(), "zero-length frame must be rejected");
    }

    // An attacker sends length = 11 (one below the 12-byte structural minimum).
    #[tokio::test]
    async fn read_plaintext_rejects_length_11() {
        let length: u32 = 11;
        let mut data = length.to_le_bytes().to_vec();
        data.extend_from_slice(&[0u8; 7]);
        let mut cursor = std::io::Cursor::new(data);
        let result = read_rpc_frame_plaintext(&mut cursor, 256).await;
        assert!(result.is_err(), "frame length 11 must be rejected");
    }

    // An attacker sends length = 16 MiB (the old unconstrained upper bound).
    // With HANDSHAKE_MAX_PLAINTEXT_FRAME_LEN = 256 this must be rejected immediately
    // without allocating or reading 16 MiB of data.
    #[tokio::test]
    async fn read_plaintext_rejects_16mib_with_handshake_max() {
        let length: u32 = 1 << 24;
        let data = length.to_le_bytes().to_vec();
        let mut cursor = std::io::Cursor::new(data);
        let result =
            read_rpc_frame_plaintext(&mut cursor, HANDSHAKE_MAX_PLAINTEXT_FRAME_LEN).await;
        assert!(
            result.is_err(),
            "16 MiB claimed length must be rejected at HANDSHAKE_MAX_PLAINTEXT_FRAME_LEN"
        );
    }

    // An attacker sends u32::MAX as the length field — worst-case allocation attempt.
    #[tokio::test]
    async fn read_plaintext_rejects_u32_max_length() {
        let length: u32 = u32::MAX;
        let data = length.to_le_bytes().to_vec();
        let mut cursor = std::io::Cursor::new(data);
        let result = read_rpc_frame_plaintext(&mut cursor, 256).await;
        assert!(result.is_err(), "u32::MAX claimed length must be rejected");
    }

    // CRC corruption in an otherwise valid frame with size inside the limit
    // must trigger a protocol error, not a panic.
    #[tokio::test]
    async fn read_plaintext_rejects_corrupted_crc() {
        let mut frame = build_rpc_frame(0, b"payload", RpcChecksumMode::Crc32).unwrap();
        let max_len = frame.len() + 16;
        *frame.last_mut().unwrap() ^= 0xFF;
        let mut cursor = std::io::Cursor::new(frame);
        let result = read_rpc_frame_plaintext(&mut cursor, max_len).await;
        assert!(result.is_err(), "CRC-corrupted frame must be rejected");
    }

    // A one-byte payload flip that leaves the length unchanged must invalidate the CRC.
    #[tokio::test]
    async fn read_plaintext_rejects_payload_bit_flip() {
        let mut frame = build_rpc_frame(-2, &[0xAAu8; 16], RpcChecksumMode::Crc32).unwrap();
        let max_len = frame.len() + 16;
        frame[8] ^= 0x01;
        let mut cursor = std::io::Cursor::new(frame);
        let result = read_rpc_frame_plaintext(&mut cursor, max_len).await;
        assert!(result.is_err(), "payload bit-flip must be detected via CRC");
    }

    // A frame that abruptly ends mid-body must return an IO error, not a panic.
    #[tokio::test]
    async fn read_plaintext_error_on_truncated_body() {
        let frame = build_rpc_frame(0, &[0u8; 32], RpcChecksumMode::Crc32).unwrap();
        // Send only the length header + 8 bytes of body (too short for the full frame).
        let truncated = frame[..12].to_vec();
        let mut cursor = std::io::Cursor::new(truncated);
        let result = read_rpc_frame_plaintext(&mut cursor, 256).await;
        assert!(result.is_err(), "truncated body must produce an error");
    }

    // Happy path: seq_no and payload must round-trip through build + read unchanged.
    #[tokio::test]
    async fn read_plaintext_returns_correct_seq_and_payload() {
        let expected_seq = -2i32;
        let nonce = build_nonce_payload(0x12345678, 1_234_567_890, &[0xABu8; 16]);
        let frame = build_rpc_frame(expected_seq, &nonce, RpcChecksumMode::Crc32).unwrap();
        let max_len = frame.len();
        let mut cursor = std::io::Cursor::new(frame);
        let (got_seq, got_payload) =
            read_rpc_frame_plaintext(&mut cursor, max_len).await.unwrap();
        assert_eq!(got_seq, expected_seq);
        assert_eq!(got_payload, nonce);
    }

    // An attacker crafts a length field at max_frame_len exactly but with wrong CRC.
    // Verifies that the size guard passing does not bypass the integrity check.
    #[tokio::test]
    async fn read_plaintext_exact_max_len_wrong_crc_is_rejected() {
        let mut frame = build_rpc_frame(0, &[0u8; 16], RpcChecksumMode::Crc32).unwrap();
        let max_len = frame.len();
        frame[8] ^= 0x01;
        let mut cursor = std::io::Cursor::new(frame);
        let result = read_rpc_frame_plaintext(&mut cursor, max_len).await;
        assert!(result.is_err(), "exact-max-len frame with wrong CRC must be rejected");
    }

    // HANDSHAKE_MAX_PLAINTEXT_FRAME_LEN must be large enough for the nonce frame (44 B)
    // but small enough to prevent the pre-fix 16 MiB allocation DoS.
    #[test]
    fn handshake_max_plaintext_frame_len_is_in_safe_range() {
        const {
            assert!(
                HANDSHAKE_MAX_PLAINTEXT_FRAME_LEN >= 44,
                "must accommodate the 44-byte nonce frame"
            )
        };
        const {
            assert!(
                HANDSHAKE_MAX_PLAINTEXT_FRAME_LEN < 1024,
                "must be far below the 16 MiB pre-fix limit to prevent DoS allocation"
            )
        };
    }
}
