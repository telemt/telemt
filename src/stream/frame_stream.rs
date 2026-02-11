//! MTProto frame stream wrappers

use bytes::{Bytes, BytesMut};
use std::io::{Error, ErrorKind, Result};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use crate::protocol::constants::*;
use crate::crypto::{crc32, SecureRandom};
use std::sync::Arc;
use super::traits::{FrameMeta, LayeredStream};

/// Maximum frame payload size (defense-in-depth against corrupted length fields).
///
/// Even when AES-CTR decryption is correct, TCP corruption or implementation
/// bugs could produce a garbage length.  Without this check, such a length
/// (up to 4 GB for u32) would cause an OOM-killing allocation.
///
/// 16 MB matches MAX_MSG_LEN and the default `max_frame_size` used by the
/// tokio-util codec variants in `frame_codec.rs`.
const MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024; // 16 MB

// ============= Abridged (Compact) Frame =============

/// Reader for abridged MTProto framing
pub struct AbridgedFrameReader<R> {
    upstream: R,
}

impl<R> AbridgedFrameReader<R> {
    pub fn new(upstream: R) -> Self {
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
            Error::new(ErrorKind::InvalidData, "abridged frame length overflow")
        })?;
        
        // Validate frame size
        if byte_len > MAX_FRAME_PAYLOAD {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Abridged frame too large: {} bytes (max {}). \
                     Likely corrupted stream (AES-CTR desync or bad data).",
                    byte_len, MAX_FRAME_PAYLOAD
                ),
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

/// Writer for abridged MTProto framing
pub struct AbridgedFrameWriter<W> {
    upstream: W,
}

impl<W> AbridgedFrameWriter<W> {
    pub fn new(upstream: W) -> Self {
        Self { upstream }
    }
}

impl<W: AsyncWrite + Unpin> AbridgedFrameWriter<W> {
    /// Write a frame
    ///
    /// The entire frame (header + data) is concatenated into a single buffer
    /// and written in one `write_all` call.  This is critical for the
    /// FakeTLS path: the CryptoWriter encrypts the buffer in one shot and
    /// the FakeTlsWriter wraps it in a **single** TLS Application Data record.
    ///
    /// Splitting into multiple writes would produce multiple TLS records for
    /// one MTProto frame, which some Telegram clients (notably iOS) do not
    /// handle correctly — they expect record-aligned frames.
    pub async fn write_frame(&mut self, data: &[u8], meta: &FrameMeta) -> Result<()> {
        if data.len() % 4 != 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Abridged frame must be aligned to 4 bytes, got {}", data.len()),
            ));
        }
        
        // Simple ACK: send reversed data
        if meta.simple_ack {
            let reversed: Vec<u8> = data.iter().rev().copied().collect();
            self.upstream.write_all(&reversed).await?;
            return Ok(());
        }
        
        let len_div_4 = data.len() / 4;
        
        // Build entire frame into one buffer to produce a single TLS record
        let mut frame = Vec::with_capacity(4 + data.len());
        
        if len_div_4 < 0x7f {
            // Short length (1 byte)
            frame.push(len_div_4 as u8);
        } else if len_div_4 < (1 << 24) {
            // Long length (4 bytes: 0x7f + 3 bytes)
            frame.push(0x7f);
            frame.extend_from_slice(&(len_div_4 as u32).to_le_bytes()[..3]);
        } else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Frame too large: {} bytes", data.len()),
            ));
        }
        
        frame.extend_from_slice(data);
        
        self.upstream.write_all(&frame).await?;
        Ok(())
    }
    
    pub async fn flush(&mut self) -> Result<()> {
        self.upstream.flush().await
    }

    /// Flush all pending data through the layered writer stack.
    ///
    /// Equivalent to Python's `await writer.drain()`.
    pub async fn drain_pending(&mut self) -> Result<()> {
        self.upstream.flush().await
    }
}

impl<W> LayeredStream<W> for AbridgedFrameWriter<W> {
    fn upstream(&self) -> &W { &self.upstream }
    fn upstream_mut(&mut self) -> &mut W { &mut self.upstream }
    fn into_upstream(self) -> W { self.upstream }
}

// ============= Intermediate Frame =============

/// Reader for intermediate MTProto framing
pub struct IntermediateFrameReader<R> {
    upstream: R,
}

impl<R> IntermediateFrameReader<R> {
    pub fn new(upstream: R) -> Self {
        Self { upstream }
    }
}

impl<R: AsyncRead + Unpin> IntermediateFrameReader<R> {
    pub async fn read_frame(&mut self) -> Result<(Bytes, FrameMeta)> {
        let mut meta = FrameMeta::new();
        
        // Read 4-byte length
        let mut len_bytes = [0u8; 4];
        self.upstream.read_exact(&mut len_bytes).await?;
        
        let mut len = u32::from_le_bytes(len_bytes) as usize;
        
        // Check QuickACK flag (high bit)
        if len > 0x80000000 {
            meta.quickack = true;
            len -= 0x80000000;
        }
        
        // Validate frame size
        if len > MAX_FRAME_PAYLOAD {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Intermediate frame too large: {} bytes (max {}). \
                     Likely corrupted stream (AES-CTR desync or bad data).",
                    len, MAX_FRAME_PAYLOAD
                ),
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

/// Writer for intermediate MTProto framing
pub struct IntermediateFrameWriter<W> {
    upstream: W,
}

impl<W> IntermediateFrameWriter<W> {
    pub fn new(upstream: W) -> Self {
        Self { upstream }
    }
}

impl<W: AsyncWrite + Unpin> IntermediateFrameWriter<W> {
    /// Write a frame
    ///
    /// See [`AbridgedFrameWriter::write_frame`] for why we use a single write.
    pub async fn write_frame(&mut self, data: &[u8], meta: &FrameMeta) -> Result<()> {
        if meta.simple_ack {
            self.upstream.write_all(data).await?;
        } else {
            // Single buffer → single encrypt → single TLS record
            let mut frame = Vec::with_capacity(4 + data.len());
            frame.extend_from_slice(&(data.len() as u32).to_le_bytes());
            frame.extend_from_slice(data);
            self.upstream.write_all(&frame).await?;
        }
        Ok(())
    }
    
    pub async fn flush(&mut self) -> Result<()> {
        self.upstream.flush().await
    }

    /// Flush all pending data through the layered writer stack.
    ///
    /// Equivalent to Python's `await writer.drain()`.
    pub async fn drain_pending(&mut self) -> Result<()> {
        self.upstream.flush().await
    }
}

impl<W> LayeredStream<W> for IntermediateFrameWriter<W> {
    fn upstream(&self) -> &W { &self.upstream }
    fn upstream_mut(&mut self) -> &mut W { &mut self.upstream }
    fn into_upstream(self) -> W { self.upstream }
}

// ============= Secure Intermediate Frame =============

/// Reader for secure intermediate MTProto framing (with padding)
pub struct SecureIntermediateFrameReader<R> {
    upstream: R,
}

impl<R> SecureIntermediateFrameReader<R> {
    pub fn new(upstream: R) -> Self {
        Self { upstream }
    }
}

impl<R: AsyncRead + Unpin> SecureIntermediateFrameReader<R> {
    pub async fn read_frame(&mut self) -> Result<(Bytes, FrameMeta)> {
        let mut meta = FrameMeta::new();
        
        // Read 4-byte length
        let mut len_bytes = [0u8; 4];
        self.upstream.read_exact(&mut len_bytes).await?;
        
        let mut len = u32::from_le_bytes(len_bytes) as usize;
        
        // Check QuickACK flag
        if len > 0x80000000 {
            meta.quickack = true;
            len -= 0x80000000;
        }
        
        // Validate frame size
        if len > MAX_FRAME_PAYLOAD {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Secure intermediate frame too large: {} bytes (max {}). \
                     Likely corrupted stream (AES-CTR desync or bad data).",
                    len, MAX_FRAME_PAYLOAD
                ),
            ));
        }
        
        // Read data (including padding)
        let mut data = vec![0u8; len];
        self.upstream.read_exact(&mut data).await?;
        
        // Strip padding (not aligned to 4)
        if len % 4 != 0 {
            let actual_len = len - (len % 4);
            data.truncate(actual_len);
        }
        
        Ok((Bytes::from(data), meta))
    }
}

impl<R> LayeredStream<R> for SecureIntermediateFrameReader<R> {
    fn upstream(&self) -> &R { &self.upstream }
    fn upstream_mut(&mut self) -> &mut R { &mut self.upstream }
    fn into_upstream(self) -> R { self.upstream }
}

/// Writer for secure intermediate MTProto framing
pub struct SecureIntermediateFrameWriter<W> {
    upstream: W,
    rng: Arc<SecureRandom>,
}

impl<W> SecureIntermediateFrameWriter<W> {
    pub fn new(upstream: W, rng: Arc<SecureRandom>) -> Self {
        Self { upstream, rng }
    }
}

impl<W: AsyncWrite + Unpin> SecureIntermediateFrameWriter<W> {
    /// Write a frame
    ///
    /// See [`AbridgedFrameWriter::write_frame`] for why we use a single write.
    pub async fn write_frame(&mut self, data: &[u8], meta: &FrameMeta) -> Result<()> {
        if meta.simple_ack {
            self.upstream.write_all(data).await?;
            return Ok(());
        }
        
        // Add random padding (0-3 bytes)
        let padding_len = self.rng.range(4);
        let padding = self.rng.bytes(padding_len);
        
        let total_len = data.len() + padding_len;
        
        // Single buffer → single encrypt → single TLS record
        let mut frame = Vec::with_capacity(4 + total_len);
        frame.extend_from_slice(&(total_len as u32).to_le_bytes());
        frame.extend_from_slice(data);
        frame.extend_from_slice(&padding);
        
        self.upstream.write_all(&frame).await?;
        
        Ok(())
    }
    
    pub async fn flush(&mut self) -> Result<()> {
        self.upstream.flush().await
    }

    /// Flush all pending data through the layered writer stack.
    ///
    /// Equivalent to Python's `await writer.drain()`.
    pub async fn drain_pending(&mut self) -> Result<()> {
        self.upstream.flush().await
    }
}

impl<W> LayeredStream<W> for SecureIntermediateFrameWriter<W> {
    fn upstream(&self) -> &W { &self.upstream }
    fn upstream_mut(&mut self) -> &mut W { &mut self.upstream }
    fn into_upstream(self) -> W { self.upstream }
}

// ============= Full MTProto Frame (with CRC) =============

/// Reader for full MTProto framing with sequence numbers and CRC32
pub struct MtprotoFrameReader<R> {
    upstream: R,
    seq_no: i32,
}

impl<R> MtprotoFrameReader<R> {
    pub fn new(upstream: R, start_seq: i32) -> Self {
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
            if len < MIN_MSG_LEN || len > MAX_MSG_LEN || len % PADDING_FILLER.len() != 0 {
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

/// Writer for full MTProto framing
pub struct MtprotoFrameWriter<W> {
    upstream: W,
    seq_no: i32,
}

impl<W> MtprotoFrameWriter<W> {
    pub fn new(upstream: W, start_seq: i32) -> Self {
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
        
        // Build entire frame into one buffer and write in one call
        let frame_len = total_len + padding_count * PADDING_FILLER.len();
        let mut frame = Vec::with_capacity(frame_len);
        frame.extend_from_slice(&len_bytes);
        frame.extend_from_slice(&seq_bytes);
        frame.extend_from_slice(msg);
        frame.extend_from_slice(&crc_bytes);
        for _ in 0..padding_count {
            frame.extend_from_slice(&PADDING_FILLER);
        }
        
        self.upstream.write_all(&frame).await?;
        
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
    pub fn new(upstream: R, proto_tag: ProtoTag) -> Self {
        match proto_tag {
            ProtoTag::Abridged => FrameReaderKind::Abridged(AbridgedFrameReader::new(upstream)),
            ProtoTag::Intermediate => FrameReaderKind::Intermediate(IntermediateFrameReader::new(upstream)),
            ProtoTag::Secure => FrameReaderKind::SecureIntermediate(SecureIntermediateFrameReader::new(upstream)),
        }
    }
    
    pub async fn read_frame(&mut self) -> Result<(Bytes, FrameMeta)> {
        match self {
            FrameReaderKind::Abridged(r) => r.read_frame().await,
            FrameReaderKind::Intermediate(r) => r.read_frame().await,
            FrameReaderKind::SecureIntermediate(r) => r.read_frame().await,
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
            ProtoTag::Abridged => FrameWriterKind::Abridged(AbridgedFrameWriter::new(upstream)),
            ProtoTag::Intermediate => FrameWriterKind::Intermediate(IntermediateFrameWriter::new(upstream)),
            ProtoTag::Secure => FrameWriterKind::SecureIntermediate(SecureIntermediateFrameWriter::new(upstream, rng)),
        }
    }
    
    pub async fn write_frame(&mut self, data: &[u8], meta: &FrameMeta) -> Result<()> {
        match self {
            FrameWriterKind::Abridged(w) => w.write_frame(data, meta).await,
            FrameWriterKind::Intermediate(w) => w.write_frame(data, meta).await,
            FrameWriterKind::SecureIntermediate(w) => w.write_frame(data, meta).await,
        }
    }
    
    pub async fn flush(&mut self) -> Result<()> {
        match self {
            FrameWriterKind::Abridged(w) => w.flush().await,
            FrameWriterKind::Intermediate(w) => w.flush().await,
            FrameWriterKind::SecureIntermediate(w) => w.flush().await,
        }
    }

    pub async fn drain_pending(&mut self) -> Result<()> {
        match self {
            FrameWriterKind::Abridged(w) => w.drain_pending().await,
            FrameWriterKind::Intermediate(w) => w.drain_pending().await,
            FrameWriterKind::SecureIntermediate(w) => w.drain_pending().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
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
        let padded_len = (data.len() + 3) / 4 * 4;
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
        // Received should have padding stripped to align to 4
        let expected_len = (data.len() / 4) * 4;
        assert_eq!(received.len(), expected_len);
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
    async fn test_intermediate_frame_too_large() {
        let (client, server) = duplex(1024);
        
        // Manually write a frame header claiming a huge length
        let mut writer = client;
        let huge_len: u32 = (MAX_FRAME_PAYLOAD + 1) as u32;
        writer.write_all(&huge_len.to_le_bytes()).await.unwrap();
        writer.flush().await.unwrap();
        
        let mut reader = IntermediateFrameReader::new(server);
        let result = reader.read_frame().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }
    
    #[tokio::test]
    async fn test_abridged_frame_too_large() {
        let (client, server) = duplex(1024);
        
        // Extended length format: 0x7f + 3 bytes LE
        let mut writer = client;
        let words: u32 = (MAX_FRAME_PAYLOAD / 4) + 1;
        let mut header = [0x7fu8, 0, 0, 0];
        header[1..4].copy_from_slice(&words.to_le_bytes()[..3]);
        writer.write_all(&header).await.unwrap();
        writer.flush().await.unwrap();
        
        let mut reader = AbridgedFrameReader::new(server);
        let result = reader.read_frame().await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_secure_frame_too_large() {
        let (client, server) = duplex(1024);
        
        let mut writer = client;
        let huge_len: u32 = (MAX_FRAME_PAYLOAD + 1) as u32;
        writer.write_all(&huge_len.to_le_bytes()).await.unwrap();
        writer.flush().await.unwrap();
        
        let mut reader = SecureIntermediateFrameReader::new(server);
        let result = reader.read_frame().await;
        assert!(result.is_err());
    }
}
