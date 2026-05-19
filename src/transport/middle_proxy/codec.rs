use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

pub(crate) fn build_rpc_frame(seq_no: i32, payload: &[u8], crc_mode: RpcChecksumMode) -> Vec<u8> {
    let total_len = (4 + 4 + payload.len() + 4) as u32;
    let mut frame = Vec::with_capacity(total_len as usize);
    frame.extend_from_slice(&total_len.to_le_bytes());
    frame.extend_from_slice(&seq_no.to_le_bytes());
    frame.extend_from_slice(payload);
    let c = rpc_crc(crc_mode, &frame);
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
}

impl RpcWriter {
    pub(crate) async fn send(&mut self, payload: &[u8]) -> Result<()> {
        let frame = build_rpc_frame(self.seq_no, payload, self.crc_mode);
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

    #[test]
    fn checksum_mode_from_flags_round_trips_through_advertised() {
        // advertised_flags(x) must round-trip through from_handshake_flags(x).
        let crc32 = RpcChecksumMode::Crc32;
        let crc32c = RpcChecksumMode::Crc32c;
        assert_eq!(
            RpcChecksumMode::from_handshake_flags(crc32.advertised_flags()),
            crc32
        );
        assert_eq!(
            RpcChecksumMode::from_handshake_flags(crc32c.advertised_flags()),
            crc32c
        );
        // Plus the actual bit value: Crc32 → 0, Crc32c → USE_CRC32C bit set.
        assert_eq!(crc32.advertised_flags(), 0);
        assert_eq!(crc32c.advertised_flags(), rpc_crypto_flags::USE_CRC32C);
    }

    #[test]
    fn checksum_mode_ignores_unrelated_bits() {
        // Other flag bits next to USE_CRC32C must not flip the result.
        let other = 0xFFFF_FFFFu32 ^ rpc_crypto_flags::USE_CRC32C;
        assert_eq!(
            RpcChecksumMode::from_handshake_flags(other),
            RpcChecksumMode::Crc32
        );
        assert_eq!(
            RpcChecksumMode::from_handshake_flags(other | rpc_crypto_flags::USE_CRC32C),
            RpcChecksumMode::Crc32c
        );
    }

    #[test]
    fn rpc_crc_matches_underlying_crate() {
        let data = b"middleproxy frame";
        assert_eq!(rpc_crc(RpcChecksumMode::Crc32, data), crc32(data));
        assert_eq!(rpc_crc(RpcChecksumMode::Crc32c, data), crc32c(data));
        // The two algorithms must NOT agree on arbitrary input — that's
        // the whole reason the mode flag exists.
        assert_ne!(
            rpc_crc(RpcChecksumMode::Crc32, data),
            rpc_crc(RpcChecksumMode::Crc32c, data)
        );
    }

    #[test]
    fn build_rpc_frame_layout() {
        let payload = b"\x01\x02\x03\x04";
        let frame = build_rpc_frame(42, payload, RpcChecksumMode::Crc32);

        // total_len = 4 (len) + 4 (seq) + 4 (payload) + 4 (crc) = 16.
        assert_eq!(frame.len(), 16);
        assert_eq!(&frame[0..4], &16u32.to_le_bytes());
        assert_eq!(&frame[4..8], &42i32.to_le_bytes());
        assert_eq!(&frame[8..12], payload);
        // CRC is computed over the first 12 bytes.
        let expected_crc = crc32(&frame[..12]);
        assert_eq!(&frame[12..16], &expected_crc.to_le_bytes());
    }

    #[test]
    fn build_rpc_frame_uses_selected_crc_mode() {
        let payload = b"abcde\x00\x00\x00"; // 8 bytes for alignment
        let f1 = build_rpc_frame(0, payload, RpcChecksumMode::Crc32);
        let f2 = build_rpc_frame(0, payload, RpcChecksumMode::Crc32c);
        // Length, seq, payload identical — only trailing CRC bytes differ.
        assert_eq!(&f1[..f1.len() - 4], &f2[..f2.len() - 4]);
        assert_ne!(&f1[f1.len() - 4..], &f2[f2.len() - 4..]);
    }

    #[test]
    fn build_then_parse_nonce_payload_round_trips() {
        let nonce = [0xABu8; 16];
        let payload = build_nonce_payload(0x1234_5678, 0x90AB_CDEF, &nonce);
        assert_eq!(payload.len(), 32);

        let (key_select, schema, ts, got_nonce) = parse_nonce_payload(&payload).unwrap();
        assert_eq!(key_select, 0x1234_5678);
        assert_eq!(schema, RPC_CRYPTO_AES_U32);
        assert_eq!(ts, 0x90AB_CDEF);
        assert_eq!(got_nonce, nonce);

        // The first 4 bytes must be the RPC_NONCE marker.
        assert_eq!(&payload[0..4], &RPC_NONCE_U32.to_le_bytes());
    }

    #[test]
    fn parse_nonce_payload_rejects_too_short() {
        assert!(parse_nonce_payload(&[0u8; 0]).is_err());
        assert!(parse_nonce_payload(&[0u8; 31]).is_err());
    }

    #[test]
    fn parse_nonce_payload_rejects_wrong_marker() {
        let mut p = [0u8; 32];
        // Marker is anything other than RPC_NONCE.
        p[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(parse_nonce_payload(&p).is_err());
    }

    #[test]
    fn build_handshake_payload_starts_with_handshake_marker_and_flags() {
        let p = build_handshake_payload([1, 2, 3, 4], 1000, [5, 6, 7, 8], 2000, 0x800);
        assert_eq!(p.len(), 32);
        assert_eq!(&p[0..4], &RPC_HANDSHAKE_U32.to_le_bytes());
        assert_eq!(&p[4..8], &0x800u32.to_le_bytes());
        assert_eq!(&p[8..12], &[1, 2, 3, 4]);
        assert_eq!(&p[12..14], &1000u16.to_le_bytes());
        assert_eq!(&p[20..24], &[5, 6, 7, 8]);
        assert_eq!(&p[24..26], &2000u16.to_le_bytes());
    }

    #[test]
    fn parse_handshake_flags_extracts_flags_field() {
        let flags = 0x8042u32;
        let payload = build_handshake_payload([0; 4], 0, [0; 4], 0, flags);
        let parsed = parse_handshake_flags(&payload).unwrap();
        assert_eq!(parsed, flags);
    }

    #[test]
    fn parse_handshake_flags_rejects_wrong_length() {
        assert!(parse_handshake_flags(&[0u8; 0]).is_err());
        assert!(parse_handshake_flags(&[0u8; 31]).is_err());
        assert!(parse_handshake_flags(&[0u8; 33]).is_err());
    }

    #[test]
    fn parse_handshake_flags_rejects_wrong_marker() {
        let mut p = [0u8; 32];
        p[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(parse_handshake_flags(&p).is_err());
    }

    #[test]
    fn cbc_encrypt_decrypt_round_trip_with_known_padding() {
        let key = [0x42u8; 32];
        let iv = [0x99u8; 16];

        // Input not aligned to 16 bytes — should be padded to next multiple.
        let plaintext = b"hello-rpc-frame-payload-21-bytes";
        let (ct, _new_iv_enc) = cbc_encrypt_padded(&key, &iv, plaintext).unwrap();
        // Encrypted length must be padded up to the next 16-byte boundary.
        assert_eq!(ct.len() % 16, 0);
        assert!(ct.len() >= plaintext.len());

        let mut buf = ct.clone();
        cbc_decrypt_inplace(&key, &iv, &mut buf).unwrap();
        // The original plaintext must appear as a prefix of the decryption.
        assert_eq!(&buf[..plaintext.len()], plaintext);
    }

    #[test]
    fn cbc_encrypt_padded_uses_canonical_padding_pattern() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        // 13-byte input → 3 bytes of padding (16 - 13 % 16).
        // Padding pattern is [0x04, 0x00, 0x00, 0x00] cycling.
        let plaintext = b"thirteenchars";

        // Manually re-derive padding via decrypt → strip → compare suffix.
        let (ct, _) = cbc_encrypt_padded(&key, &iv, plaintext).unwrap();
        let mut decrypted = ct.clone();
        cbc_decrypt_inplace(&key, &iv, &mut decrypted).unwrap();

        assert_eq!(&decrypted[..plaintext.len()], plaintext);
        assert_eq!(&decrypted[plaintext.len()..], &[0x04, 0x00, 0x00][..]);
    }

    #[test]
    fn cbc_encrypt_padded_aligned_input_adds_no_padding() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let plaintext = [0xAB; 32]; // already a multiple of 16
        let (ct, _) = cbc_encrypt_padded(&key, &iv, &plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len());
    }

    #[test]
    fn cbc_encrypt_then_decrypt_iv_chains_match() {
        // The new IV after encrypt is the last 16 bytes of ciphertext.
        // Decrypt with the SAME starting IV must also surface that as its
        // chained-IV output.
        let key = [0xCDu8; 32];
        let iv = [0x12u8; 16];
        let plaintext = vec![0u8; 64];

        let (ct, iv_after_enc) = cbc_encrypt_padded(&key, &iv, &plaintext).unwrap();
        let mut buf = ct.clone();
        let iv_after_dec = cbc_decrypt_inplace(&key, &iv, &mut buf).unwrap();
        assert_eq!(iv_after_enc, iv_after_dec);
        // And both equal the last 16 bytes of the ciphertext.
        assert_eq!(&iv_after_enc[..], &ct[ct.len() - 16..]);
    }

    #[tokio::test]
    async fn read_rpc_frame_plaintext_round_trips_built_frame() {
        use tokio::io::AsyncReadExt;
        let payload = b"payload-bytes--XXX";
        let frame = build_rpc_frame(7, payload, RpcChecksumMode::Crc32);

        let mut cursor = std::io::Cursor::new(frame);
        // `read_rpc_frame_plaintext` is generic over `AsyncReadExt + Unpin`.
        let (seq, got) = read_rpc_frame_plaintext(&mut cursor).await.unwrap();
        assert_eq!(seq, 7);
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn read_rpc_frame_plaintext_rejects_bad_crc() {
        let payload = b"AAAA";
        let mut frame = build_rpc_frame(1, payload, RpcChecksumMode::Crc32);
        // Corrupt the CRC.
        let last = frame.len() - 1;
        frame[last] ^= 0xFF;

        let mut cursor = std::io::Cursor::new(frame);
        assert!(read_rpc_frame_plaintext(&mut cursor).await.is_err());
    }

    #[tokio::test]
    async fn read_rpc_frame_plaintext_rejects_oversized_length() {
        // total_len = 0x02000000 → 32 MB, above the 1<<24 cap.
        let bad_len = (1u32 << 25).to_le_bytes();
        let mut cursor = std::io::Cursor::new(bad_len.to_vec());
        assert!(read_rpc_frame_plaintext(&mut cursor).await.is_err());
    }

    #[tokio::test]
    async fn read_rpc_frame_plaintext_rejects_undersized_length() {
        // total_len = 11 → below the 12-byte minimum.
        let bad_len = 11u32.to_le_bytes();
        let mut cursor = std::io::Cursor::new(bad_len.to_vec());
        assert!(read_rpc_frame_plaintext(&mut cursor).await.is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn rpc_frame_roundtrip_crc32(
            seq_no in any::<i32>(),
            payload in proptest::collection::vec(any::<u8>(), 0..4096),
        ) {
            let frame = build_rpc_frame(seq_no, &payload, RpcChecksumMode::Crc32);
            let total_len = u32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize;
            assert_eq!(total_len, frame.len());
            assert_eq!(&frame[4..8], &seq_no.to_le_bytes());
            assert_eq!(&frame[8..frame.len() - 4], &payload);
            let expected = crc32(&frame[..frame.len() - 4]);
            assert_eq!(&frame[frame.len() - 4..], &expected.to_le_bytes());
        }

        #[test]
        fn rpc_frame_roundtrip_crc32c(
            seq_no in any::<i32>(),
            payload in proptest::collection::vec(any::<u8>(), 0..4096),
        ) {
            let frame = build_rpc_frame(seq_no, &payload, RpcChecksumMode::Crc32c);
            let total_len = u32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize;
            assert_eq!(total_len, frame.len());
            let expected = crc32c(&frame[..frame.len() - 4]);
            assert_eq!(&frame[frame.len() - 4..], &expected.to_le_bytes());
        }

        #[test]
        fn nonce_payload_roundtrip(
            key_selector in any::<u32>(),
            crypto_ts in any::<u32>(),
            nonce in any::<[u8; 16]>(),
        ) {
            let payload = build_nonce_payload(key_selector, crypto_ts, &nonce);
            let (ks, schema, ts, got_nonce) = parse_nonce_payload(&payload).unwrap();
            assert_eq!(ks, key_selector);
            assert_eq!(schema, RPC_CRYPTO_AES_U32);
            assert_eq!(ts, crypto_ts);
            assert_eq!(got_nonce, nonce);
        }
    }
}
