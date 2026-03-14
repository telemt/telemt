//! `MTProto` frame stream wrappers

#![allow(dead_code)]

use bytes::Bytes;
use std::io::{Error, ErrorKind, Result};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use crate::protocol::constants::*;
use crate::crypto::{crc32, SecureRandom};
use std::sync::Arc;
use super::traits::{FrameMeta, LayeredStream};

/// Upper bound for transport frame payloads to prevent memory exhaustion.
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

// ============= Abridged (Compact) Frame =============

/// Reader for abridged `MTProto` framing
pub struct AbridgedFrameReader<R> {
    upstream: R,
}

impl<R> AbridgedFrameReader<R> {
    pub const fn new(upstream: R) -> Self {
        Self { upstream }
    }
}

impl<R: AsyncRead + Unpin> AbridgedFrameReader<R> {
    /// Read a frame and return (data, metadata)
    pub async fn read_frame(&mut self) -> Result<(Bytes, FrameMeta)> {
        let mut meta = FrameMeta::new();
        
        // Read length byte
        let mut len_byte = [0u8];
        self.upstream.read_exact(&mut len_byte).await?;
        
        let mut len = len_byte[0] as usize;
        
        // Check QuickACK flag (high bit)
        if len >= 0x80 {
            meta.quickack = true;
            len -= 0x80;
        }
        
        // Extended length (3 bytes)
        if len == 0x7f {
            let mut len_bytes = [0u8; 3];
            self.upstream.read_exact(&mut len_bytes).await?;
            len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], 0]) as usize;
        }
        
        // Length is in 4-byte words
        let byte_len = len.checked_mul(4).ok_or_else(|| {
            Error::new(ErrorKind::InvalidData, "Abridged frame length overflow")
        })?;

        if byte_len > MAX_FRAME_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Abridged frame too large: {} bytes", byte_len),
            ));
        }
        
        // Read data
        let mut data = vec![0u8; byte_len];
        self.upstream.read_exact(&mut data).await?;
        
        Ok((Bytes::from(data), meta))
    }
}

impl<R> LayeredStream<R> for AbridgedFrameReader<R> {
    fn upstream(&self) -> &R { &self.upstream }
    fn upstream_mut(&mut self) -> &mut R { &mut self.upstream }
    fn into_upstream(self) -> R { self.upstream }
}

/// Writer for abridged `MTProto` framing
pub struct AbridgedFrameWriter<W> {
    upstream: W,
}

impl<W> AbridgedFrameWriter<W> {
    pub const fn new(upstream: W) -> Self {
        Self { upstream }
    }
}

impl<W: AsyncWrite + Unpin> AbridgedFrameWriter<W> {
    /// Write a frame
    pub async fn write_frame(&mut self, data: &[u8], meta: &FrameMeta) -> Result<()> {
        if !data.len().is_multiple_of(4) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Abridged frame must be aligned to 4 bytes, got {}", data.len()),
            ));
        }

        if data.len() > MAX_FRAME_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Abridged frame too large: {} bytes", data.len()),
            ));
        }
        
        // Simple ACK: send reversed data
        if meta.simple_ack {
            let reversed: Vec<u8> = data.iter().rev().copied().collect();
            self.upstream.write_all(&reversed).await?;
            return Ok(());
        }
        
        let len_div_4 = data.len() / 4;
        
        if len_div_4 < 0x7f {
            // Short length (1 byte)
            let mut len_byte = len_div_4 as u8;
            if meta.quickack {
                len_byte |= 0x80;
            }
            self.upstream.write_all(&[len_byte]).await?;
        } else if len_div_4 < (1 << 24) {
            // Long length (4 bytes: 0x7f + 3 bytes)
            let mut header = [0x7f, 0, 0, 0];
            if meta.quickack {
                header[0] |= 0x80;
            }
            header[1..4].copy_from_slice(&(len_div_4 as u32).to_le_bytes()[..3]);
            self.upstream.write_all(&header).await?;
        } else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Frame too large: {} bytes", data.len()),
            ));
        }
        
        self.upstream.write_all(data).await?;
        Ok(())
    }
    
    pub async fn flush(&mut self) -> Result<()> {
        self.upstream.flush().await
    }
}

impl<W> LayeredStream<W> for AbridgedFrameWriter<W> {
    fn upstream(&self) -> &W { &self.upstream }
    fn upstream_mut(&mut self) -> &mut W { &mut self.upstream }
    fn into_upstream(self) -> W { self.upstream }
}

// ============= Intermediate Frame =============

/// Reader for intermediate `MTProto` framing
pub struct IntermediateFrameReader<R> {
    upstream: R,
}

impl<R> IntermediateFrameReader<R> {
    pub const fn new(upstream: R) -> Self {
        Self { upstream }
    }
}

impl<R: AsyncRead + Unpin> IntermediateFrameReader<R> {
    pub async fn read_frame(&mut self) -> Result<(Bytes, FrameMeta)> {
        let mut meta = FrameMeta::new();
        
        // Read 4-byte length
        let mut len_bytes = [0u8; 4];
        self.upstream.read_exact(&mut len_bytes).await?;
        
        let mut len = u32::from_le_bytes(len_bytes);
        
        // Check QuickACK flag (high bit)
        if len >= 0x8000_0000 {
            meta.quickack = true;
            len -= 0x8000_0000;
        }

        let len = len as usize;

        if len > MAX_FRAME_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Intermediate frame too large: {} bytes", len),
            ));
        }
        
        // Read data
        let mut data = vec![0u8; len];
        self.upstream.read_exact(&mut data).await?;
        
        Ok((Bytes::from(data), meta))
    }
}

impl<R> LayeredStream<R> for IntermediateFrameReader<R> {
    fn upstream(&self) -> &R { &self.upstream }
    fn upstream_mut(&mut self) -> &mut R { &mut self.upstream }
    fn into_upstream(self) -> R { self.upstream }
}

/// Writer for intermediate `MTProto` framing
pub struct IntermediateFrameWriter<W> {
    upstream: W,
}

impl<W> IntermediateFrameWriter<W> {
    pub const fn new(upstream: W) -> Self {
        Self { upstream }
    }
}

impl<W: AsyncWrite + Unpin> IntermediateFrameWriter<W> {
    pub async fn write_frame(&mut self, data: &[u8], meta: &FrameMeta) -> Result<()> {
        if data.len() > MAX_FRAME_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Intermediate frame too large: {} bytes", data.len()),
            ));
        }

        if meta.simple_ack {
            self.upstream.write_all(data).await?;
        } else {
            let mut len = data.len() as u32;
            if meta.quickack {
                len |= 0x8000_0000;
            }
            let len_bytes = len.to_le_bytes();
            self.upstream.write_all(&len_bytes).await?;
            self.upstream.write_all(data).await?;
        }
        Ok(())
    }
    
    pub async fn flush(&mut self) -> Result<()> {
        self.upstream.flush().await
    }
}

impl<W> LayeredStream<W> for IntermediateFrameWriter<W> {
    fn upstream(&self) -> &W { &self.upstream }
    fn upstream_mut(&mut self) -> &mut W { &mut self.upstream }
    fn into_upstream(self) -> W { self.upstream }
}

// ============= Secure Intermediate Frame =============

/// Reader for secure intermediate `MTProto` framing (with padding)
pub struct SecureIntermediateFrameReader<R> {
    upstream: R,
}

impl<R> SecureIntermediateFrameReader<R> {
    pub const fn new(upstream: R) -> Self {
        Self { upstream }
    }
}

impl<R: AsyncRead + Unpin> SecureIntermediateFrameReader<R> {
    pub async fn read_frame(&mut self) -> Result<(Bytes, FrameMeta)> {
        let mut meta = FrameMeta::new();
        
        // Read 4-byte length
        let mut len_bytes = [0u8; 4];
        self.upstream.read_exact(&mut len_bytes).await?;
        
        let mut len = u32::from_le_bytes(len_bytes);
        
        // Check QuickACK flag
        if len >= 0x8000_0000 {
            meta.quickack = true;
            len -= 0x8000_0000;
        }

        let len = len as usize;

        if len > MAX_FRAME_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Secure intermediate frame too large: {} bytes", len),
            ));
        }

        // Validate the Secure Intermediate invariant (wire_len % 4 != 0) BEFORE
        // allocating the body buffer and reading from the socket.  A censor can
        // send a header whose wire_len is divisible by 4 and never send the body;
        // or send MAX_FRAME_SIZE (16 MB) divisible-by-4 bytes that must be
        // consumed before the invariant is checked, burning bandwidth.
        // Early rejection here costs zero body I/O.
        let payload_len = secure_payload_len_from_wire_len(len).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                format!("Invalid secure frame length: {len}"),
            )
        })?;

        // Read data (including padding)
        let mut data = vec![0u8; len];
        self.upstream.read_exact(&mut data).await?;
        data.truncate(payload_len);
        
        Ok((Bytes::from(data), meta))
    }
}

impl<R> LayeredStream<R> for SecureIntermediateFrameReader<R> {
    fn upstream(&self) -> &R { &self.upstream }
    fn upstream_mut(&mut self) -> &mut R { &mut self.upstream }
    fn into_upstream(self) -> R { self.upstream }
}

/// Writer for secure intermediate `MTProto` framing
pub struct SecureIntermediateFrameWriter<W> {
    upstream: W,
    rng: Arc<SecureRandom>,
}

impl<W> SecureIntermediateFrameWriter<W> {
    pub const fn new(upstream: W, rng: Arc<SecureRandom>) -> Self {
        Self { upstream, rng }
    }
}

impl<W: AsyncWrite + Unpin> SecureIntermediateFrameWriter<W> {
    pub async fn write_frame(&mut self, data: &[u8], meta: &FrameMeta) -> Result<()> {
        if meta.simple_ack {
            self.upstream.write_all(data).await?;
            return Ok(());
        }

        // Secure mode always adds 1..=3 bytes of random padding, so payload
        // must leave room under the configured wire-size limit.
        if data.len() > MAX_FRAME_SIZE.saturating_sub(3) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Secure intermediate frame too large: {} bytes", data.len()),
            ));
        }
        
        if !is_valid_secure_payload_len(data.len()) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Secure payload must be 4-byte aligned, got {}", data.len()),
            ));
        }

        // Add padding so total length is never divisible by 4 (MTProto Secure)
        let padding_len = secure_padding_len(data.len(), &self.rng);
        let padding = self.rng.bytes(padding_len);

        let total_len = data.len().checked_add(padding_len).ok_or_else(|| {
            Error::new(ErrorKind::InvalidInput, "Secure intermediate frame length overflow")
        })?;
        if total_len > MAX_FRAME_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Secure intermediate frame too large: {} bytes", total_len),
            ));
        }

        let mut len = total_len as u32;
        if meta.quickack {
            len |= 0x8000_0000;
        }
        let len_bytes = len.to_le_bytes();
        
        self.upstream.write_all(&len_bytes).await?;
        self.upstream.write_all(data).await?;
        self.upstream.write_all(&padding).await?;
        
        Ok(())
    }
    
    pub async fn flush(&mut self) -> Result<()> {
        self.upstream.flush().await
    }
}

impl<W> LayeredStream<W> for SecureIntermediateFrameWriter<W> {
    fn upstream(&self) -> &W { &self.upstream }
    fn upstream_mut(&mut self) -> &mut W { &mut self.upstream }
    fn into_upstream(self) -> W { self.upstream }
}

// ============= Full MTProto Frame (with CRC) =============

/// Reader for full `MTProto` framing with sequence numbers and CRC32
pub struct MtprotoFrameReader<R> {
    upstream: R,
    seq_no: i32,
}

impl<R> MtprotoFrameReader<R> {
    pub const fn new(upstream: R, start_seq: i32) -> Self {
        Self { upstream, seq_no: start_seq }
    }
}

impl<R: AsyncRead + Unpin> MtprotoFrameReader<R> {
    pub async fn read_frame(&mut self) -> Result<Bytes> {
        loop {
            // Read length (4 bytes)
            let mut len_bytes = [0u8; 4];
            self.upstream.read_exact(&mut len_bytes).await?;
            let len = u32::from_le_bytes(len_bytes) as usize;
            
            // Skip padding-only messages
            if len == 4 {
                continue;
            }
            
            // Validate length
            if !(MIN_MSG_LEN..=MAX_MSG_LEN).contains(&len) || !len.is_multiple_of(PADDING_FILLER.len()) {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Invalid message length: {}", len),
                ));
            }
            
            // Read sequence number
            let mut seq_bytes = [0u8; 4];
            self.upstream.read_exact(&mut seq_bytes).await?;
            let msg_seq = i32::from_le_bytes(seq_bytes);
            
            if msg_seq != self.seq_no {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Sequence mismatch: expected {}, got {}", self.seq_no, msg_seq),
                ));
            }
            self.seq_no += 1;
            
            // Read data (length - 4 len - 4 seq - 4 crc = len - 12)
            let data_len = len - 12;
            let mut data = vec![0u8; data_len];
            self.upstream.read_exact(&mut data).await?;
            
            // Read and verify CRC32
            let mut crc_bytes = [0u8; 4];
            self.upstream.read_exact(&mut crc_bytes).await?;
            let expected_crc = u32::from_le_bytes(crc_bytes);
            
            // Compute CRC over len + seq + data
            let mut crc_input = Vec::with_capacity(8 + data_len);
            crc_input.extend_from_slice(&len_bytes);
            crc_input.extend_from_slice(&seq_bytes);
            crc_input.extend_from_slice(&data);
            let computed_crc = crc32(&crc_input);
            
            if computed_crc != expected_crc {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("CRC mismatch: expected {:08x}, got {:08x}", expected_crc, computed_crc),
                ));
            }
            
            return Ok(Bytes::from(data));
        }
    }
}

/// Writer for full `MTProto` framing
pub struct MtprotoFrameWriter<W> {
    upstream: W,
    seq_no: i32,
}

impl<W> MtprotoFrameWriter<W> {
    pub const fn new(upstream: W, start_seq: i32) -> Self {
        Self { upstream, seq_no: start_seq }
    }
}

impl<W: AsyncWrite + Unpin> MtprotoFrameWriter<W> {
    pub async fn write_frame(&mut self, msg: &[u8]) -> Result<()> {
        // Total length: 4 (len) + 4 (seq) + data + 4 (crc)
        let len = msg.len() + 12;
        
        let len_bytes = (len as u32).to_le_bytes();
        let seq_bytes = self.seq_no.to_le_bytes();
        self.seq_no += 1;
        
        // Compute CRC
        let mut crc_input = Vec::with_capacity(8 + msg.len());
        crc_input.extend_from_slice(&len_bytes);
        crc_input.extend_from_slice(&seq_bytes);
        crc_input.extend_from_slice(msg);
        let checksum = crc32(&crc_input);
        let crc_bytes = checksum.to_le_bytes();
        
        // Calculate padding for CBC alignment
        let total_len = len_bytes.len() + seq_bytes.len() + msg.len() + crc_bytes.len();
        let padding_needed = (CBC_PADDING - (total_len % CBC_PADDING)) % CBC_PADDING;
        let padding_count = padding_needed / PADDING_FILLER.len();
        
        // Write everything
        self.upstream.write_all(&len_bytes).await?;
        self.upstream.write_all(&seq_bytes).await?;
        self.upstream.write_all(msg).await?;
        self.upstream.write_all(&crc_bytes).await?;
        
        for _ in 0..padding_count {
            self.upstream.write_all(&PADDING_FILLER).await?;
        }
        
        Ok(())
    }
    
    pub async fn flush(&mut self) -> Result<()> {
        self.upstream.flush().await
    }
}

// ============= Frame Type Enum =============

/// Enum for different frame stream types
pub enum FrameReaderKind<R> {
    Abridged(AbridgedFrameReader<R>),
    Intermediate(IntermediateFrameReader<R>),
    SecureIntermediate(SecureIntermediateFrameReader<R>),
}

impl<R: AsyncRead + Unpin> FrameReaderKind<R> {
    pub const fn new(upstream: R, proto_tag: ProtoTag) -> Self {
        match proto_tag {
            ProtoTag::Abridged => Self::Abridged(AbridgedFrameReader::new(upstream)),
            ProtoTag::Intermediate => Self::Intermediate(IntermediateFrameReader::new(upstream)),
            ProtoTag::Secure => Self::SecureIntermediate(SecureIntermediateFrameReader::new(upstream)),
        }
    }
    
    pub async fn read_frame(&mut self) -> Result<(Bytes, FrameMeta)> {
        match self {
            Self::Abridged(r) => r.read_frame().await,
            Self::Intermediate(r) => r.read_frame().await,
            Self::SecureIntermediate(r) => r.read_frame().await,
        }
    }
}

pub enum FrameWriterKind<W> {
    Abridged(AbridgedFrameWriter<W>),
    Intermediate(IntermediateFrameWriter<W>),
    SecureIntermediate(SecureIntermediateFrameWriter<W>),
}

impl<W: AsyncWrite + Unpin> FrameWriterKind<W> {
    pub fn new(upstream: W, proto_tag: ProtoTag, rng: Arc<SecureRandom>) -> Self {
        match proto_tag {
            ProtoTag::Abridged => Self::Abridged(AbridgedFrameWriter::new(upstream)),
            ProtoTag::Intermediate => Self::Intermediate(IntermediateFrameWriter::new(upstream)),
            ProtoTag::Secure => Self::SecureIntermediate(SecureIntermediateFrameWriter::new(upstream, rng)),
        }
    }
    
    pub async fn write_frame(&mut self, data: &[u8], meta: &FrameMeta) -> Result<()> {
        match self {
            Self::Abridged(w) => w.write_frame(data, meta).await,
            Self::Intermediate(w) => w.write_frame(data, meta).await,
            Self::SecureIntermediate(w) => w.write_frame(data, meta).await,
        }
    }
    
    pub async fn flush(&mut self) -> Result<()> {
        match self {
            Self::Abridged(w) => w.flush().await,
            Self::Intermediate(w) => w.flush().await,
            Self::SecureIntermediate(w) => w.flush().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use tokio::io::AsyncWriteExt;
    use std::sync::Arc;
    use crate::crypto::SecureRandom;
    
    #[tokio::test]
    async fn test_abridged_roundtrip() {
        let (client, server) = duplex(1024);
        
        let mut writer = AbridgedFrameWriter::new(client);
        let mut reader = AbridgedFrameReader::new(server);
        
        // Short frame
        let data = vec![1u8, 2, 3, 4]; // 4 bytes = 1 word
        writer.write_frame(&data, &FrameMeta::new()).await.unwrap();
        writer.flush().await.unwrap();
        
        let (received, _meta) = reader.read_frame().await.unwrap();
        assert_eq!(&received[..], &data[..]);
    }
    
    #[tokio::test]
    async fn test_abridged_long_frame() {
        let (client, server) = duplex(65536);
        
        let mut writer = AbridgedFrameWriter::new(client);
        let mut reader = AbridgedFrameReader::new(server);
        
        // Long frame (> 0x7f words = 508 bytes)
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let padded_len = data.len().div_ceil(4) * 4;
        let mut padded = data.clone();
        padded.resize(padded_len, 0);
        
        writer.write_frame(&padded, &FrameMeta::new()).await.unwrap();
        writer.flush().await.unwrap();
        
        let (received, _meta) = reader.read_frame().await.unwrap();
        assert_eq!(&received[..], &padded[..]);
    }
    
    #[tokio::test]
    async fn test_intermediate_roundtrip() {
        let (client, server) = duplex(1024);
        
        let mut writer = IntermediateFrameWriter::new(client);
        let mut reader = IntermediateFrameReader::new(server);
        
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        writer.write_frame(&data, &FrameMeta::new()).await.unwrap();
        writer.flush().await.unwrap();
        
        let (received, _meta) = reader.read_frame().await.unwrap();
        assert_eq!(&received[..], &data[..]);
    }
    
    #[tokio::test]
    async fn test_secure_intermediate_padding() {
        let (client, server) = duplex(1024);
        
        let mut writer = SecureIntermediateFrameWriter::new(client, Arc::new(SecureRandom::new()));
        let mut reader = SecureIntermediateFrameReader::new(server);
        
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        writer.write_frame(&data, &FrameMeta::new()).await.unwrap();
        writer.flush().await.unwrap();
        
        let (received, _meta) = reader.read_frame().await.unwrap();
        assert_eq!(received.len(), data.len());
    }
    
    #[tokio::test]
    async fn test_mtproto_frame_roundtrip() {
        let (client, server) = duplex(1024);
        
        let mut writer = MtprotoFrameWriter::new(client, 0);
        let mut reader = MtprotoFrameReader::new(server, 0);
        
        // Message must be padded properly
        let data = vec![0u8; 16]; // Aligned to 4 and CBC_PADDING
        writer.write_frame(&data).await.unwrap();
        writer.flush().await.unwrap();
        
        let received = reader.read_frame().await.unwrap();
        assert_eq!(&received[..], &data[..]);
    }
    
    #[tokio::test]
    async fn test_frame_reader_kind() {
        let (client, server) = duplex(1024);
        
        let mut writer = FrameWriterKind::new(client, ProtoTag::Intermediate, Arc::new(SecureRandom::new()));
        let mut reader = FrameReaderKind::new(server, ProtoTag::Intermediate);
        
        let data = vec![1u8, 2, 3, 4];
        writer.write_frame(&data, &FrameMeta::new()).await.unwrap();
        writer.flush().await.unwrap();
        
        let (received, _) = reader.read_frame().await.unwrap();
        assert_eq!(&received[..], &data[..]);
    }

    #[tokio::test]
    async fn test_intermediate_quickack_boundary_header_is_treated_as_quickack() {
        let (mut client, server) = duplex(1024);
        client
            .write_all(&0x8000_0000_u32.to_le_bytes())
            .await
            .unwrap();
        client.flush().await.unwrap();
        drop(client);

        let mut reader = IntermediateFrameReader::new(server);
        let (data, meta) = reader.read_frame().await.unwrap();
        assert!(meta.quickack);
        assert!(data.is_empty());
    }

    #[tokio::test]
    async fn test_intermediate_reader_rejects_oversized_length_before_body_allocation() {
        let (mut client, server) = duplex(1024);
        client
            .write_all(&((MAX_FRAME_SIZE as u32) + 1).to_le_bytes())
            .await
            .unwrap();
        client.flush().await.unwrap();
        drop(client);

        let mut reader = IntermediateFrameReader::new(server);
        let err = reader.read_frame().await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_secure_reader_rejects_oversized_length_before_body_allocation() {
        let (mut client, server) = duplex(1024);
        client
            .write_all(&((MAX_FRAME_SIZE as u32) + 1).to_le_bytes())
            .await
            .unwrap();
        client.flush().await.unwrap();
        drop(client);

        let mut reader = SecureIntermediateFrameReader::new(server);
        let err = reader.read_frame().await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_abridged_reader_rejects_oversized_length_before_body_allocation() {
        let len_words = (MAX_FRAME_SIZE / 4) + 1;
        let mut header = vec![0x7f_u8];
        header.extend_from_slice(&(len_words as u32).to_le_bytes()[..3]);

        let (mut client, server) = duplex(1024);
        client.write_all(&header).await.unwrap();
        client.flush().await.unwrap();
        drop(client);

        let mut reader = AbridgedFrameReader::new(server);
        let err = reader.read_frame().await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_intermediate_writer_sets_quickack_flag() {
        let (client, mut server) = duplex(1024);
        let mut writer = IntermediateFrameWriter::new(client);

        writer
            .write_frame(&[1, 2, 3, 4], &FrameMeta::new().with_quickack())
            .await
            .unwrap();
        writer.flush().await.unwrap();

        let mut len_bytes = [0u8; 4];
        server.read_exact(&mut len_bytes).await.unwrap();
        assert_eq!(u32::from_le_bytes(len_bytes), 0x8000_0004);
    }

    #[tokio::test]
    async fn test_secure_writer_sets_quickack_flag() {
        let (client, mut server) = duplex(1024);
        let mut writer = SecureIntermediateFrameWriter::new(client, Arc::new(SecureRandom::new()));

        writer
            .write_frame(&[1, 2, 3, 4], &FrameMeta::new().with_quickack())
            .await
            .unwrap();
        writer.flush().await.unwrap();

        let mut len_bytes = [0u8; 4];
        server.read_exact(&mut len_bytes).await.unwrap();
        assert!(u32::from_le_bytes(len_bytes) >= 0x8000_0000);
    }

    #[tokio::test]
    async fn test_abridged_writer_sets_quickack_flag() {
        let (client, mut server) = duplex(1024);
        let mut writer = AbridgedFrameWriter::new(client);

        writer
            .write_frame(&[1, 2, 3, 4], &FrameMeta::new().with_quickack())
            .await
            .unwrap();
        writer.flush().await.unwrap();

        let mut first = [0u8; 1];
        server.read_exact(&mut first).await.unwrap();
        assert_eq!(first[0], 0x81);
    }

    #[tokio::test]
    async fn test_secure_writer_rejects_payload_without_padding_headroom() {
        let (client, _server) = duplex(1024);
        let mut writer = SecureIntermediateFrameWriter::new(client, Arc::new(SecureRandom::new()));

        let data = vec![0u8; MAX_FRAME_SIZE];
        let err = writer
            .write_frame(&data, &FrameMeta::new())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn test_secure_intermediate_reader_rejects_zero_padding_frame() {
        // wire_len = 8: 8 % 4 == 0 => zero padding, protocol violation.
        let (mut client, server) = duplex(1024);
        client.write_all(&8u32.to_le_bytes()).await.unwrap();
        client.write_all(&[0xAA_u8; 8]).await.unwrap();
        client.flush().await.unwrap();
        drop(client);

        let mut reader = SecureIntermediateFrameReader::new(server);
        let err = reader.read_frame().await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_secure_intermediate_reader_rejects_wire_len_4_zero_padding() {
        // wire_len = 4: smallest divisible-by-4 case (4 bytes data, 0 padding).
        let (mut client, server) = duplex(1024);
        client.write_all(&4u32.to_le_bytes()).await.unwrap();
        client.write_all(&[0xBB_u8; 4]).await.unwrap();
        client.flush().await.unwrap();
        drop(client);

        let mut reader = SecureIntermediateFrameReader::new(server);
        let err = reader.read_frame().await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_secure_intermediate_reader_accepts_all_valid_padding_sizes() {
        for padding in 1u8..=3 {
            let data = vec![0xCC_u8; 4];
            let wire_len = 4u32 + u32::from(padding);

            let (mut client, server) = duplex(64);
            client.write_all(&wire_len.to_le_bytes()).await.unwrap();
            client.write_all(&data).await.unwrap();
            client.write_all(&vec![0xFF_u8; padding as usize]).await.unwrap();
            client.flush().await.unwrap();
            drop(client);

            let mut reader = SecureIntermediateFrameReader::new(server);
            let (received, _meta) = reader.read_frame().await.unwrap_or_else(|e| {
                panic!("should accept padding={padding}: {e}")
            });
            assert_eq!(&received[..], &data[..], "padding={padding}");
        }
    }

    // A censor probing with a Secure Intermediate header where wire_len is
    // divisible by 4 (zero-padding, invariant violation) must be rejected
    // BEFORE the body is read.  Sending only the 4-byte header and immediately
    // closing the write-end proves that the reader does not block waiting for
    // a body that will never arrive: the fixed code returns InvalidData
    // immediately from the header, while the buggy (pre-fix) code would block
    // on read_exact and eventually return UnexpectedEof.
    #[tokio::test]
    async fn test_secure_reader_rejects_invariant_violation_before_reading_body() {
        // wire_len = 8 (divisible by 4, violates Secure Intermediate invariant).
        // Only the 4-byte header is sent; the body is withheld.
        let (mut client, server) = duplex(64);
        client.write_all(&8u32.to_le_bytes()).await.unwrap();
        client.flush().await.unwrap();
        // Drop the write end — body never arrives.
        drop(client);

        let mut reader = SecureIntermediateFrameReader::new(server);
        let err = reader.read_frame().await.unwrap_err();

        // InvalidData means the invariant was checked before read_exact.
        // UnexpectedEof would mean the reader blocked waiting for a body.
        assert_eq!(
            err.kind(),
            ErrorKind::InvalidData,
            "must reject via InvalidData before reading body, not block for UnexpectedEof"
        );
    }

    // Reject a wire_len of MAX_FRAME_SIZE that happens to be divisible by 4
    // without reading the body.  Without early validation, this forces the proxy
    // to allocate and read up to 16 MB of garbage per probe connection.
    #[tokio::test]
    async fn test_secure_reader_rejects_large_divisible_by_4_without_body_read() {
        let wire_len = MAX_FRAME_SIZE as u32; // 16 MB, divisible by 4

        let (mut client, server) = duplex(64);
        client.write_all(&wire_len.to_le_bytes()).await.unwrap();
        client.flush().await.unwrap();
        drop(client);

        let mut reader = SecureIntermediateFrameReader::new(server);
        let err = reader.read_frame().await.unwrap_err();

        assert_eq!(
            err.kind(),
            ErrorKind::InvalidData,
            "must reject wire_len={wire_len} (divisible by 4) before reading body"
        );
    }

    // Verify the legacy reader strips padding bytes and never exposes them.
    // Padding bytes are random—if they leak into the payload, the MTProto layer
    // above will either crash or silently process garbage data.
    #[tokio::test]
    async fn test_secure_reader_padding_bytes_never_exposed_in_payload() {
        let payload = [0x11u8, 0x22, 0x33, 0x44];
        let padding = [0xDE, 0xAD, 0xBE]; // 3 distinct bytes, obviously not payload

        let (mut client, server) = duplex(64);
        client.write_all(&7u32.to_le_bytes()).await.unwrap(); // wire_len = 4 + 3 = 7
        client.write_all(&payload).await.unwrap();
        client.write_all(&padding).await.unwrap();
        client.flush().await.unwrap();
        drop(client);

        let mut reader = SecureIntermediateFrameReader::new(server);
        let (received, _meta) = reader.read_frame().await.unwrap();

        assert_eq!(received.len(), 4, "payload must be 4 bytes, padding must be stripped");
        assert_eq!(&received[..], &payload, "decoded payload must match exactly");
        assert!(
            !received.windows(3).any(|w| w == padding),
            "padding bytes must not appear in decoded payload"
        );
    }

    // Two consecutive Secure Intermediate frames must be decoded without
    // cross-frame contamination.  A bug in padding stripping or position tracking
    // would leak bytes from one frame into the next.
    #[tokio::test]
    async fn test_secure_reader_consecutive_frames_no_cross_contamination() {
        let (mut client, server) = duplex(256);

        // Frame 1: 4 data bytes + 1 padding byte (wire_len = 5)
        client.write_all(&5u32.to_le_bytes()).await.unwrap();
        client.write_all(&[0x11, 0x22, 0x33, 0x44]).await.unwrap();
        client.write_all(&[0xFF]).await.unwrap(); // padding

        // Frame 2: 8 data bytes + 3 padding bytes (wire_len = 11)
        client.write_all(&11u32.to_le_bytes()).await.unwrap();
        client.write_all(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02]).await.unwrap();
        client.write_all(&[0x7E, 0x7F, 0x80]).await.unwrap(); // padding
        client.flush().await.unwrap();
        drop(client);

        let mut reader = SecureIntermediateFrameReader::new(server);

        let (frame1, _) = reader.read_frame().await.unwrap();
        assert_eq!(&frame1[..], &[0x11, 0x22, 0x33, 0x44], "frame1 corrupted");

        let (frame2, _) = reader.read_frame().await.unwrap();
        assert_eq!(
            &frame2[..],
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02],
            "frame2 corrupted — possible cross-frame leakage"
        );
    }

    // wire_len values 1, 2, 3 are below the 4-byte minimum data size and must
    // all be rejected with InvalidData by the early invariant check, without
    // reading from the socket.
    #[tokio::test]
    async fn test_secure_reader_rejects_wire_len_1_2_3() {
        for wire_len in [1u32, 2, 3] {
            let (mut client, server) = duplex(64);
            client.write_all(&wire_len.to_le_bytes()).await.unwrap();
            client.flush().await.unwrap();
            drop(client);

            let mut reader = SecureIntermediateFrameReader::new(server);
            let err = reader.read_frame().await.unwrap_err();
            assert_eq!(
                err.kind(),
                ErrorKind::InvalidData,
                "wire_len={wire_len} must be rejected as InvalidData before body read"
            );
        }
    }
}
