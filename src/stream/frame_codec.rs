//! tokio-util codec integration for MTProto frames
//!
//! This module provides Encoder/Decoder implementations compatible
//! with tokio-util's Framed wrapper for easy async frame I/O.

#![allow(dead_code)]

use bytes::{BytesMut, BufMut};
use std::io::{self, Error, ErrorKind};
use std::sync::Arc;
use tokio_util::codec::{Decoder, Encoder};

use crate::protocol::constants::{
    ProtoTag, is_valid_secure_payload_len, secure_padding_len, secure_payload_len_from_wire_len,
};
use crate::crypto::SecureRandom;
use super::frame::{Frame, FrameMeta, FrameCodec as FrameCodecTrait};

// ============= Unified Codec =============

/// Unified frame codec that wraps all protocol variants
///
/// This codec implements tokio-util's Encoder and Decoder traits,
/// allowing it to be used with `Framed` for async frame I/O.
pub struct FrameCodec {
    /// Protocol variant
    proto_tag: ProtoTag,
    /// Maximum allowed frame size
    max_frame_size: usize,
    /// RNG for secure padding
    rng: Arc<SecureRandom>,
}

impl FrameCodec {
    /// Create a new codec for the given protocol
    pub const fn new(proto_tag: ProtoTag, rng: Arc<SecureRandom>) -> Self {
        Self {
            proto_tag,
            max_frame_size: 16 * 1024 * 1024, // 16MB default
            rng,
        }
    }
    
    /// Set maximum frame size
    pub const fn with_max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }
    
    /// Get protocol tag
    pub const fn proto_tag(&self) -> ProtoTag {
        self.proto_tag
    }
}

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = Error;
    
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.proto_tag {
            ProtoTag::Abridged => decode_abridged(src, self.max_frame_size),
            ProtoTag::Intermediate => decode_intermediate(src, self.max_frame_size),
            ProtoTag::Secure => decode_secure(src, self.max_frame_size),
        }
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = Error;
    
    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        validate_outbound_payload_size(self.proto_tag, frame.data.len(), self.max_frame_size)?;
        match self.proto_tag {
            ProtoTag::Abridged => encode_abridged(&frame, dst),
            ProtoTag::Intermediate => encode_intermediate(&frame, dst),
            ProtoTag::Secure => encode_secure(&frame, dst, &self.rng),
        }
    }
}

// ============= Abridged Protocol =============

fn decode_abridged(src: &mut BytesMut, max_size: usize) -> io::Result<Option<Frame>> {
    if src.is_empty() {
        return Ok(None);
    }
    
    let mut meta = FrameMeta::new();
    let first_byte = src[0];
    
    // Extract length and quickack flag
    let mut len_words = (first_byte & 0x7f) as usize;
    if first_byte >= 0x80 {
        meta.quickack = true;
    }
    
    let header_len;
    
    if len_words == 0x7f {
        // Extended length (3 more bytes needed)
        if src.len() < 4 {
            return Ok(None);
        }
        len_words = u32::from_le_bytes([src[1], src[2], src[3], 0]) as usize;
        header_len = 4;
    } else {
        header_len = 1;
    }
    
    // Length is in 4-byte words
    let byte_len = len_words.checked_mul(4).ok_or_else(|| {
        Error::new(ErrorKind::InvalidData, "frame length overflow")
    })?;
    
    // Validate size
    if byte_len > max_size {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("frame too large: {} bytes (max {})", byte_len, max_size)
        ));
    }
    
    let total_len = header_len + byte_len;
    
    if src.len() < total_len {
        // Reserve space for the rest of the frame
        src.reserve(total_len - src.len());
        return Ok(None);
    }
    
    // Extract data
    let _ = src.split_to(header_len);
    let data = src.split_to(byte_len).freeze();
    
    Ok(Some(Frame::with_meta(data, meta)))
}

fn encode_abridged(frame: &Frame, dst: &mut BytesMut) -> io::Result<()> {
    let data = &frame.data;
    
    // Validate alignment
    if !data.len().is_multiple_of(4) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("abridged frame must be 4-byte aligned, got {} bytes", data.len())
        ));
    }
    
    // Simple ACK: send reversed data without header
    if frame.meta.simple_ack {
        dst.reserve(data.len());
        for byte in data.iter().rev() {
            dst.put_u8(*byte);
        }
        return Ok(());
    }
    
    let len_words = data.len() / 4;
    
    if len_words < 0x7f {
        // Short header
        dst.reserve(1 + data.len());
        let mut len_byte = len_words as u8;
        if frame.meta.quickack {
            len_byte |= 0x80;
        }
        dst.put_u8(len_byte);
    } else if len_words < (1 << 24) {
        // Extended header
        dst.reserve(4 + data.len());
        let mut first = 0x7fu8;
        if frame.meta.quickack {
            first |= 0x80;
        }
        dst.put_u8(first);
        let len_bytes = (len_words as u32).to_le_bytes();
        dst.extend_from_slice(&len_bytes[..3]);
    } else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("frame too large: {} bytes", data.len())
        ));
    }
    
    dst.extend_from_slice(data);
    Ok(())
}

// ============= Intermediate Protocol =============

fn decode_intermediate(src: &mut BytesMut, max_size: usize) -> io::Result<Option<Frame>> {
    if src.len() < 4 {
        return Ok(None);
    }
    
    let mut meta = FrameMeta::new();
    let mut len = u32::from_le_bytes([src[0], src[1], src[2], src[3]]) as usize;
    
    // Check QuickACK flag
    if len >= 0x8000_0000 {
        meta.quickack = true;
        len -= 0x8000_0000;
    }
    
    // Validate size
    if len > max_size {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("frame too large: {} bytes (max {})", len, max_size)
        ));
    }
    
    let total_len = 4 + len;
    
    if src.len() < total_len {
        src.reserve(total_len - src.len());
        return Ok(None);
    }
    
    // Extract data
    let _ = src.split_to(4);
    let data = src.split_to(len).freeze();
    
    Ok(Some(Frame::with_meta(data, meta)))
}

fn encode_intermediate(frame: &Frame, dst: &mut BytesMut) -> io::Result<()> {
    let data = &frame.data;
    
    // Simple ACK: just send data
    if frame.meta.simple_ack {
        dst.reserve(data.len());
        dst.extend_from_slice(data);
        return Ok(());
    }
    
    dst.reserve(4 + data.len());
    
    let mut len = data.len() as u32;
    if frame.meta.quickack {
        len |= 0x8000_0000;
    }
    
    dst.extend_from_slice(&len.to_le_bytes());
    dst.extend_from_slice(data);
    
    Ok(())
}

// ============= Secure Intermediate Protocol =============

fn decode_secure(src: &mut BytesMut, max_size: usize) -> io::Result<Option<Frame>> {
    if src.len() < 4 {
        return Ok(None);
    }
    
    let mut meta = FrameMeta::new();
    let mut len = u32::from_le_bytes([src[0], src[1], src[2], src[3]]) as usize;
    
    // Check QuickACK flag
    if len >= 0x8000_0000 {
        meta.quickack = true;
        len -= 0x8000_0000;
    }
    
    // Validate size
    if len > max_size {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("frame too large: {} bytes (max {})", len, max_size)
        ));
    }

    // Validate the Secure Intermediate invariant before consuming the buffer:
    // padding is always 1–3 bytes, so wire_len % 4 must be non-zero.
    // Checking here (before split_to) leaves src intact on error.
    let data_len = secure_payload_len_from_wire_len(len).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            format!("invalid secure frame length: {len}"),
        )
    })?;

    let total_len = 4 + len;

    if src.len() < total_len {
        src.reserve(total_len - src.len());
        return Ok(None);
    }

    let padding_len = len - data_len;
    meta.padding_len = padding_len as u8;

    // Consume header, extract payload without copying, then discard padding.
    // split_to(n).freeze() is zero-copy: it promotes the BytesMut slice to a
    // reference-counted Bytes without allocating a new backing buffer.
    let _ = src.split_to(4);
    let data = src.split_to(data_len).freeze();
    let _ = src.split_to(padding_len);

    Ok(Some(Frame::with_meta(data, meta)))
}

fn encode_secure(frame: &Frame, dst: &mut BytesMut, rng: &SecureRandom) -> io::Result<()> {
    let data = &frame.data;
    
    // Simple ACK: just send data
    if frame.meta.simple_ack {
        dst.reserve(data.len());
        dst.extend_from_slice(data);
        return Ok(());
    }
    
    if !is_valid_secure_payload_len(data.len()) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("secure payload must be 4-byte aligned, got {}", data.len()),
        ));
    }

    // Generate padding that keeps total length non-divisible by 4.
    let padding_len = secure_padding_len(data.len(), rng);
    
    let total_len = data.len() + padding_len;
    dst.reserve(4 + total_len);
    
    let mut len = total_len as u32;
    if frame.meta.quickack {
        len |= 0x8000_0000;
    }
    
    dst.extend_from_slice(&len.to_le_bytes());
    dst.extend_from_slice(data);
    
    if padding_len > 0 {
        let padding = rng.bytes(padding_len);
        dst.extend_from_slice(&padding);
    }
    
    Ok(())
}

fn validate_outbound_payload_size(
    proto_tag: ProtoTag,
    payload_len: usize,
    max_frame_size: usize,
) -> io::Result<()> {
    match proto_tag {
        ProtoTag::Abridged | ProtoTag::Intermediate => {
            if payload_len > max_frame_size {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("frame too large: {} bytes (max {})", payload_len, max_frame_size),
                ));
            }
        }
        ProtoTag::Secure => {
            if payload_len > max_frame_size.saturating_sub(3) {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "secure frame too large: payload {} leaves no room for required padding (max wire {})",
                        payload_len,
                        max_frame_size
                    ),
                ));
            }
        }
    }
    Ok(())
}

// ============= Typed Codecs =============

/// Abridged protocol codec
pub struct AbridgedCodec {
    max_frame_size: usize,
}

impl AbridgedCodec {
    pub const fn new() -> Self {
        Self {
            max_frame_size: 16 * 1024 * 1024,
        }
    }

    pub const fn with_max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }
}

impl Default for AbridgedCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for AbridgedCodec {
    type Item = Frame;
    type Error = Error;
    
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        decode_abridged(src, self.max_frame_size)
    }
}

impl Encoder<Frame> for AbridgedCodec {
    type Error = Error;
    
    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        validate_outbound_payload_size(ProtoTag::Abridged, frame.data.len(), self.max_frame_size)?;
        encode_abridged(&frame, dst)
    }
}

impl FrameCodecTrait for AbridgedCodec {
    fn proto_tag(&self) -> ProtoTag {
        ProtoTag::Abridged
    }

    fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    fn encode(&self, frame: &Frame, dst: &mut BytesMut) -> io::Result<usize> {
        validate_outbound_payload_size(ProtoTag::Abridged, frame.data.len(), self.max_frame_size)?;
        let before = dst.len();
        encode_abridged(frame, dst)?;
        Ok(dst.len() - before)
    }

    fn decode(&self, src: &mut BytesMut) -> io::Result<Option<Frame>> {
        decode_abridged(src, self.max_frame_size)
    }

    fn min_header_size(&self) -> usize {
        1
    }
}

/// Intermediate protocol codec
pub struct IntermediateCodec {
    max_frame_size: usize,
}

impl IntermediateCodec {
    pub const fn new() -> Self {
        Self {
            max_frame_size: 16 * 1024 * 1024,
        }
    }

    pub const fn with_max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }
}

impl Default for IntermediateCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for IntermediateCodec {
    type Item = Frame;
    type Error = Error;
    
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        decode_intermediate(src, self.max_frame_size)
    }
}

impl Encoder<Frame> for IntermediateCodec {
    type Error = Error;
    
    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        validate_outbound_payload_size(
            ProtoTag::Intermediate,
            frame.data.len(),
            self.max_frame_size,
        )?;
        encode_intermediate(&frame, dst)
    }
}

impl FrameCodecTrait for IntermediateCodec {
    fn proto_tag(&self) -> ProtoTag {
        ProtoTag::Intermediate
    }

    fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    fn encode(&self, frame: &Frame, dst: &mut BytesMut) -> io::Result<usize> {
        validate_outbound_payload_size(ProtoTag::Intermediate, frame.data.len(), self.max_frame_size)?;
        let before = dst.len();
        encode_intermediate(frame, dst)?;
        Ok(dst.len() - before)
    }

    fn decode(&self, src: &mut BytesMut) -> io::Result<Option<Frame>> {
        decode_intermediate(src, self.max_frame_size)
    }

    fn min_header_size(&self) -> usize {
        4
    }
}

/// Secure Intermediate protocol codec
pub struct SecureCodec {
    max_frame_size: usize,
    rng: Arc<SecureRandom>,
}

impl SecureCodec {
    pub const fn new(rng: Arc<SecureRandom>) -> Self {
        Self {
            max_frame_size: 16 * 1024 * 1024,
            rng,
        }
    }

    pub fn with_max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }
}

impl Default for SecureCodec {
    fn default() -> Self {
        Self::new(Arc::new(SecureRandom::new()))
    }
}

impl Decoder for SecureCodec {
    type Item = Frame;
    type Error = Error;
    
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        decode_secure(src, self.max_frame_size)
    }
}

impl Encoder<Frame> for SecureCodec {
    type Error = Error;
    
    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        validate_outbound_payload_size(ProtoTag::Secure, frame.data.len(), self.max_frame_size)?;
        encode_secure(&frame, dst, &self.rng)
    }
}

impl FrameCodecTrait for SecureCodec {
    fn proto_tag(&self) -> ProtoTag {
        ProtoTag::Secure
    }

    fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    fn encode(&self, frame: &Frame, dst: &mut BytesMut) -> io::Result<usize> {
        validate_outbound_payload_size(ProtoTag::Secure, frame.data.len(), self.max_frame_size)?;
        let before = dst.len();
        encode_secure(frame, dst, &self.rng)?;
        Ok(dst.len() - before)
    }

    fn decode(&self, src: &mut BytesMut) -> io::Result<Option<Frame>> {
        decode_secure(src, self.max_frame_size)
    }

    fn min_header_size(&self) -> usize {
        4
    }
}

// ============= Tests =============

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use tokio_util::codec::{FramedRead, FramedWrite};
    use tokio::io::duplex;
    use futures::{SinkExt, StreamExt};
    use crate::crypto::SecureRandom;
    use std::sync::Arc;
    
    #[tokio::test]
    async fn test_framed_abridged() {
        let (client, server) = duplex(4096);
        
        let mut writer = FramedWrite::new(client, AbridgedCodec::new());
        let mut reader = FramedRead::new(server, AbridgedCodec::new());
        
        // Write a frame
        let frame = Frame::new(Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8]));
        writer.send(frame).await.unwrap();
        
        // Read it back
        let received = reader.next().await.unwrap().unwrap();
        assert_eq!(&received.data[..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }
    
    #[tokio::test]
    async fn test_framed_intermediate() {
        let (client, server) = duplex(4096);
        
        let mut writer = FramedWrite::new(client, IntermediateCodec::new());
        let mut reader = FramedRead::new(server, IntermediateCodec::new());
        
        let frame = Frame::new(Bytes::from_static(b"hello world"));
        writer.send(frame).await.unwrap();
        
        let received = reader.next().await.unwrap().unwrap();
        assert_eq!(&received.data[..], b"hello world");
    }
    
    #[tokio::test]
    async fn test_framed_secure() {
        let (client, server) = duplex(4096);
        
        let mut writer = FramedWrite::new(client, SecureCodec::new(Arc::new(SecureRandom::new())));
        let mut reader = FramedRead::new(server, SecureCodec::new(Arc::new(SecureRandom::new())));
        
        let original = Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let frame = Frame::new(original.clone());
        writer.send(frame).await.unwrap();
        
        let received = reader.next().await.unwrap().unwrap();
        assert_eq!(&received.data[..], &original[..]);
    }
    
    #[tokio::test]
    async fn test_unified_codec() {
        for proto_tag in [ProtoTag::Abridged, ProtoTag::Intermediate, ProtoTag::Secure] {
            let (client, server) = duplex(4096);
            
            let mut writer = FramedWrite::new(client, FrameCodec::new(proto_tag, Arc::new(SecureRandom::new())));
            let mut reader = FramedRead::new(server, FrameCodec::new(proto_tag, Arc::new(SecureRandom::new())));
            
            // Use 4-byte aligned data for abridged compatibility
            let original = Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8]);
            let frame = Frame::new(original.clone());
            writer.send(frame).await.unwrap();
            
            let received = reader.next().await.unwrap().unwrap();
            assert_eq!(received.data.len(), 8);
        }
    }
    
    #[tokio::test]
    async fn test_multiple_frames() {
        let (client, server) = duplex(4096);
        
        let mut writer = FramedWrite::new(client, IntermediateCodec::new());
        let mut reader = FramedRead::new(server, IntermediateCodec::new());
        
        // Send multiple frames
        for i in 0..10 {
            let data: Vec<u8> = (0..((i + 1) * 10)).map(|j| (j % 256) as u8).collect();
            let frame = Frame::new(Bytes::from(data));
            writer.send(frame).await.unwrap();
        }
        
        // Receive them
        for i in 0..10 {
            let received = reader.next().await.unwrap().unwrap();
            assert_eq!(received.data.len(), (i + 1) * 10);
        }
    }
    
    #[tokio::test]
    async fn test_quickack_flag() {
        let (client, server) = duplex(4096);
        
        let mut writer = FramedWrite::new(client, IntermediateCodec::new());
        let mut reader = FramedRead::new(server, IntermediateCodec::new());
        
        let frame = Frame::quickack(Bytes::from_static(b"urgent"));
        writer.send(frame).await.unwrap();
        
        let received = reader.next().await.unwrap().unwrap();
        assert!(received.meta.quickack);
    }
    
    #[test]
    fn test_frame_too_large() {
        let mut codec = FrameCodec::new(ProtoTag::Intermediate, Arc::new(SecureRandom::new()))
            .with_max_frame_size(100);
        
        // Create a "frame" that claims to be very large
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&1000u32.to_le_bytes()); // length = 1000
        buf.extend_from_slice(&[0u8; 10]); // partial data
        
        let result = codec.decode(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn decode_intermediate_accepts_quickack_bit_at_boundary() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&0x8000_0000_u32.to_le_bytes());
        let decoded = decode_intermediate(&mut buf, 1024).unwrap().unwrap();
        assert!(decoded.meta.quickack);
        assert!(decoded.data.is_empty());
    }

    #[test]
    fn decode_secure_rejects_zero_padding_with_quickack() {
        // wire_len = 4: padding would be 0, violates the Secure Intermediate invariant.
        // The QuickACK bit must not change this outcome.
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&0x8000_0004_u32.to_le_bytes());
        buf.extend_from_slice(&[1, 2, 3, 4]);
        let err = decode_secure(&mut buf, 1024).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        // Buffer must remain unconsumed on validation failure.
        assert_eq!(buf.len(), 8, "buffer must not be consumed on error");
    }

    #[test]
    fn decode_secure_quickack_with_valid_padding() {
        // wire_len = 5 = 4 data + 1 padding, with QuickACK flag.
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&0x8000_0005_u32.to_le_bytes());
        buf.extend_from_slice(&[1, 2, 3, 4, 0xFF]); // 4 data + 1 padding byte
        let decoded = decode_secure(&mut buf, 1024).unwrap().unwrap();
        assert!(decoded.meta.quickack);
        assert_eq!(&decoded.data[..], &[1, 2, 3, 4]);
    }

    #[test]
    fn decode_secure_rejects_wire_len_zero() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&0u32.to_le_bytes());
        let err = decode_secure(&mut buf, 1024).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn decode_secure_rejects_wire_len_less_than_4() {
        for wire_len in [1u32, 2, 3] {
            let mut buf = BytesMut::new();
            buf.extend_from_slice(&wire_len.to_le_bytes());
            buf.extend_from_slice(&vec![0xAA_u8; wire_len as usize]);
            let err = decode_secure(&mut buf, 1024).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidData, "wire_len={wire_len}");
        }
    }

    #[test]
    fn decode_secure_rejects_all_multiples_of_four() {
        for wire_len_words in [1u32, 2, 3, 16, 100] {
            let wire_len = wire_len_words * 4;
            let mut buf = BytesMut::new();
            buf.extend_from_slice(&wire_len.to_le_bytes());
            buf.extend_from_slice(&vec![0xBB_u8; wire_len as usize]);
            let err = decode_secure(&mut buf, wire_len as usize + 8).unwrap_err();
            assert_eq!(
                err.kind(),
                ErrorKind::InvalidData,
                "should reject wire_len={wire_len} (divisible by 4 = no padding)"
            );
        }
    }

    #[test]
    fn decode_secure_accepts_all_valid_padding_sizes() {
        for padding in 1u8..=3 {
            let data = vec![0xAA_u8; 4];
            let wire_len = 4u32 + u32::from(padding);
            let mut buf = BytesMut::new();
            buf.extend_from_slice(&wire_len.to_le_bytes());
            buf.extend_from_slice(&data);
            buf.extend_from_slice(&vec![0xFF_u8; padding as usize]);

            let frame = decode_secure(&mut buf, 1024).unwrap().unwrap();
            assert_eq!(&frame.data[..], &data[..], "padding={padding}");
            assert_eq!(frame.meta.padding_len, padding, "padding={padding}");
            assert!(buf.is_empty(), "buffer should be fully consumed, padding={padding}");
        }
    }

    #[test]
    fn decode_secure_does_not_consume_buffer_on_invariant_violation() {
        // Attacker sends wire_len = 8 (divisible by 4, no padding).
        // The buffer must stay intact so the connection can be rejected cleanly.
        let body = vec![0xCC_u8; 8];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&8u32.to_le_bytes());
        buf.extend_from_slice(&body);
        let original_len = buf.len();

        let err = decode_secure(&mut buf, 1024).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(buf.len(), original_len, "buffer must be unchanged on error");
    }

    #[test]
    fn decode_secure_needs_more_data_for_valid_frame() {
        // Valid frame header (wire_len = 5), but body not yet arrived.
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&5u32.to_le_bytes()); // only header
        let result = decode_secure(&mut buf, 1024).unwrap();
        assert!(result.is_none(), "should return None when body not yet available");
        assert_eq!(buf.len(), 4, "header bytes must remain in buffer");
    }

    #[test]
    fn frame_codec_secure_encode_rejects_payload_without_padding_headroom() {
        let mut codec = FrameCodec::new(ProtoTag::Secure, Arc::new(SecureRandom::new()))
            .with_max_frame_size(16);
        let frame = Frame::new(Bytes::from(vec![0u8; 16]));
        let mut dst = BytesMut::new();

        let err = codec.encode(frame, &mut dst).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    // QuickACK bit (0x80) occupies the same byte as the extended-length marker
    // (0x7F).  When both are set (0xFF), the decoder must parse the 3-byte
    // extended length correctly AND set meta.quickack = true.  A bug here would
    // silently lose the QuickACK signal on large frames.
    #[test]
    fn decode_abridged_quickack_preserved_with_extended_length() {
        // Build a frame with 0x7F words (508 bytes) and QuickACK bit.
        let data = vec![0xAB_u8; 0x7F * 4]; // Exactly 508 bytes
        let mut buf = BytesMut::new();
        // Extended-length header: first byte = 0x7F | 0x80 = 0xFF (quickack + extended marker)
        buf.put_u8(0xFF);
        // 3-byte LE length in words: 0x7F = 127
        buf.put_u8(0x7F);
        buf.put_u8(0x00);
        buf.put_u8(0x00);
        buf.extend_from_slice(&data);

        let frame = decode_abridged(&mut buf, 1024 * 1024).unwrap().unwrap();
        assert!(frame.meta.quickack, "QuickACK bit must survive extended-length header");
        assert_eq!(frame.data.len(), 508);
        assert!(buf.is_empty(), "buffer must be fully consumed");
    }

    // Verify that two back-to-back Secure frames both decode correctly out of a
    // single buffer.  This validates that split_to calls in decode_secure leave
    // the buffer positioned exactly at the start of the next frame, preventing
    // any cross-frame data corruption.
    #[test]
    fn decode_secure_two_consecutive_frames_no_cross_contamination() {
        let mut buf = BytesMut::new();

        // Frame 1: 4 data bytes + 1 padding byte  (wire_len = 5)
        buf.extend_from_slice(&5u32.to_le_bytes());
        buf.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // payload
        buf.extend_from_slice(&[0xFF]); // padding

        // Frame 2: 8 data bytes + 2 padding bytes (wire_len = 10)
        buf.extend_from_slice(&10u32.to_le_bytes());
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02]); // payload
        buf.extend_from_slice(&[0x7E, 0x7F]); // padding

        let frame1 = decode_secure(&mut buf, 1024).unwrap().unwrap();
        assert_eq!(&frame1.data[..], &[0x11, 0x22, 0x33, 0x44], "frame1 payload corrupted");
        assert_eq!(frame1.meta.padding_len, 1);

        let frame2 = decode_secure(&mut buf, 1024).unwrap().unwrap();
        assert_eq!(
            &frame2.data[..],
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02],
            "frame2 payload corrupted — possible cross-frame data leakage"
        );
        assert_eq!(frame2.meta.padding_len, 2);

        assert!(buf.is_empty(), "buffer must be fully consumed after two frames");
    }

    // decode_secure must strip padding bytes and never include them in the
    // returned frame payload.  This verifies that padding bytes — which are
    // random data generated by the peer — are never exposed to the
    // application layer as legitimate payload.
    #[test]
    fn decode_secure_padding_bytes_excluded_from_payload() {
        let payload = [0x01u8, 0x02, 0x03, 0x04]; // 4 bytes, 4-byte aligned
        let padding = [0xDE, 0xAD, 0xBE]; // 3 bytes of obviously distinct padding

        let mut buf = BytesMut::new();
        buf.extend_from_slice(&7u32.to_le_bytes()); // wire_len = 4 + 3 = 7
        buf.extend_from_slice(&payload);
        buf.extend_from_slice(&padding);

        let frame = decode_secure(&mut buf, 1024).unwrap().unwrap();

        assert_eq!(frame.data.len(), 4, "payload must be 4 bytes, not include padding");
        assert_eq!(&frame.data[..], &payload, "decoded payload must match original");
        // If padding leaked into the payload, this would catch it.
        assert!(
            !frame.data.windows(3).any(|w| w == padding),
            "padding bytes must not appear in decoded payload"
        );
    }

    // An attacker can send a valid 4-byte header claiming a huge body (just
    // under the limit) but never send the body.  The decoder must return
    // Ok(None) without allocating the full body buffer until the data arrives.
    // This test verifies the decoder does not panic and leaves the header
    // bytes untouched in the buffer for the next poll.
    #[test]
    fn decode_secure_returns_none_and_preserves_header_when_body_not_arrived() {
        let wire_len: u32 = 4096 * 4 + 1; // large but valid (not divisible by 4)
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&wire_len.to_le_bytes()); // only the 4-byte header

        let initial_len = buf.len();
        let result = decode_secure(&mut buf, 1024 * 1024).unwrap();

        assert!(result.is_none(), "must return None when body has not arrived");
        assert_eq!(buf.len(), initial_len, "header bytes must be preserved in buffer");
    }

    // Abridged frames must be 4-byte aligned.  An encoder receiving a payload
    // whose length is not a multiple of 4 must return InvalidInput.
    #[test]
    fn encode_abridged_rejects_unaligned_payload() {
        let mut codec = AbridgedCodec::new();
        let frame = Frame::new(Bytes::from(vec![0x01, 0x02, 0x03])); // 3 bytes, unaligned
        let mut dst = BytesMut::new();
        // tokio_util Encoder<Frame> takes ownership; FrameCodecTrait::encode borrows.
        let err = Encoder::encode(&mut codec, frame, &mut dst).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput, "unaligned abridged payload must be rejected");
    }

    // A 0-byte payload is a multiple of 4, so is_valid_secure_payload_len(0) = true.
    // The encoder accepts it; the resulting wire_len = padding = 1..=3, which is
    // always < 4.  The decoder rejects wire_len < 4 via the `wire_len < 4` guard.
    // This asymmetry documents that 0-byte Secure payloads are encode-only;
    // they cannot round-trip.  MTProto never uses 0-byte frames in practice, but
    // the test pins this behavior so any future change to the invariant is visible.
    #[test]
    fn decode_secure_rejects_wire_len_produced_by_zero_byte_payload_encode() {
        // Simulated output of encoding a 0-byte Secure payload: wire_len = 1, 2, or 3.
        for wire_len in [1u32, 2, 3] {
            let mut buf = BytesMut::new();
            buf.extend_from_slice(&wire_len.to_le_bytes());
            buf.extend_from_slice(&vec![0xFF_u8; wire_len as usize]);

            let err = decode_secure(&mut buf, 1024).unwrap_err();
            assert_eq!(
                err.kind(),
                ErrorKind::InvalidData,
                "wire_len={wire_len} (from 0-byte payload encode) must be rejected"
            );
        }
    }

    // decode_abridged must accept a zero-length frame (len_words = 0) and return
    // an empty payload.  This is a corner case but must not panic or corrupt the
    // decoder state.
    #[test]
    fn decode_abridged_zero_length_frame_returns_empty_payload() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x00); // len_words = 0, no quickack
        let frame = decode_abridged(&mut buf, 1024).unwrap().unwrap();
        assert!(frame.data.is_empty(), "zero-length abridged frame must return empty payload");
        assert!(!frame.meta.quickack);
        assert!(buf.is_empty(), "header byte must be consumed");
    }

    // decode_intermediate must accept a zero-length frame (len = 0) and return
    // an empty payload.
    #[test]
    fn decode_intermediate_zero_length_frame_returns_empty_payload() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // len = 0
        let frame = decode_intermediate(&mut buf, 1024).unwrap().unwrap();
        assert!(frame.data.is_empty());
        assert!(buf.is_empty());
    }

    // Intermediate: the QuickACK flag and length field must be handled independently.
    // A frame with the maximum non-QuickACK length (0x7FFFFFFF) must decode normally.
    #[test]
    fn decode_intermediate_max_non_quickack_len_is_rejected_as_too_large() {
        let mut buf = BytesMut::new();
        // 0x7FFFFFFF = 2147483647 bytes — well above max_size=1024
        buf.extend_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
        let err = decode_intermediate(&mut buf, 1024).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    // encode_secure with max_frame_size on a payload that leaves room for padding.
    // max_frame_size = 16 means payload must be <= 13 (leaving 3 bytes for padding).
    #[test]
    fn encode_secure_payload_exactly_at_max_minus_3_is_accepted() {
        // max_frame_size = 16; payload must be 4-aligned and <= 16 - 3 = 13.
        // Largest valid 4-aligned payload is 12 bytes.
        let mut codec = FrameCodec::new(ProtoTag::Secure, Arc::new(SecureRandom::new()))
            .with_max_frame_size(16);
        let frame = Frame::new(Bytes::from(vec![0xAA_u8; 12]));
        let mut dst = BytesMut::new();
        codec.encode(frame, &mut dst).unwrap();

        // Wire: 4-byte header + 12 payload + 1..=3 padding. Total <= 19 bytes.
        // Header wire_len = 12 + padding. Must be accepted by decoder.
        let decoded = decode_secure(&mut dst, 16).unwrap().unwrap();
        assert_eq!(decoded.data.len(), 12);
    }

    // Verify that decode_secure correctly handles the largest valid wire length
    // (one below max_size, not divisible by 4).
    #[test]
    fn decode_secure_accepts_largest_valid_wire_len_below_max_size() {
        let max_size = 1024usize;
        // Find largest wire_len < max_size that is not divisible by 4.
        let wire_len = if !(max_size - 1).is_multiple_of(4) {
            max_size - 1
        } else if !(max_size - 2).is_multiple_of(4) {
            max_size - 2
        } else {
            max_size - 3
        };
        assert!(wire_len % 4 != 0, "test setup: wire_len must not be divisible by 4");

        let data_len = wire_len - (wire_len % 4);
        let padding_len = wire_len - data_len;

        let mut buf = BytesMut::new();
        buf.extend_from_slice(&(wire_len as u32).to_le_bytes());
        buf.extend_from_slice(&vec![0x55_u8; data_len]);
        buf.extend_from_slice(&vec![0xFF_u8; padding_len]);

        let frame = decode_secure(&mut buf, max_size).unwrap().unwrap();
        assert_eq!(frame.data.len(), data_len);
        assert!(buf.is_empty());
    }

    // decode_abridged with extended-length header and len_words = 0 must decode
    // to an empty frame without panicking or corrupting decoder state.
    #[test]
    fn decode_abridged_extended_header_zero_len_words() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x7F); // extended length marker, no quickack
        buf.put_u8(0x00); // len_words[0] = 0
        buf.put_u8(0x00); // len_words[1] = 0
        buf.put_u8(0x00); // len_words[2] = 0 → len_words = 0 → byte_len = 0
        let frame = decode_abridged(&mut buf, 1024).unwrap().unwrap();
        assert!(frame.data.is_empty(), "zero extended-length frame must produce empty payload");
        assert!(buf.is_empty());
    }

    // decode_intermediate: a frame header that arrives with only 3 of 4 bytes
    // must return None and leave the buffer unchanged (no partial consumption).
    #[test]
    fn decode_intermediate_partial_header_returns_none_without_consuming() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x00, 0x00, 0x10]); // only 3 of 4 header bytes
        let initial_len = buf.len();
        let result = decode_intermediate(&mut buf, 1024).unwrap();
        assert!(result.is_none());
        assert_eq!(buf.len(), initial_len, "partial header must not be consumed");
    }

    // ============= FrameCodecTrait::encode validation tests =============
    //
    // These tests verify that the FrameCodecTrait::encode path (used via
    // Box<dyn FrameCodec> from create_codec()) enforces the same size limits
    // as the Encoder<Frame> tokio-util path.  Without the validate call, an
    // attacker-controlled large payload could trigger dst.reserve(huge) → OOM.

    // Abridged: payload exceeding max_frame_size must be rejected via trait path.
    // dst must be empty after rejection (no partial write).
    #[test]
    fn frame_codec_trait_abridged_encode_rejects_oversized_payload() {
        let codec = AbridgedCodec::new().with_max_frame_size(16);
        // 20 bytes > 16 (max_frame_size).  Must be rejected before dst.reserve().
        let frame = Frame::new(Bytes::from(vec![0xAA_u8; 20]));
        let mut dst = BytesMut::new();
        let err = <AbridgedCodec as FrameCodecTrait>::encode(&codec, &frame, &mut dst)
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput, "abridged oversize must be InvalidInput");
        assert!(dst.is_empty(), "dst must be empty — no partial write on rejection");
    }

    // Intermediate: payload exactly at the limit must pass; one byte over must fail.
    #[test]
    fn frame_codec_trait_intermediate_encode_boundary_exactly_at_limit() {
        let codec = IntermediateCodec::new().with_max_frame_size(16);

        // Exactly 16 bytes: must succeed.
        let frame_ok = Frame::new(Bytes::from(vec![0x00_u8; 16]));
        let mut dst = BytesMut::new();
        <IntermediateCodec as FrameCodecTrait>::encode(&codec, &frame_ok, &mut dst).unwrap();
        assert_eq!(dst.len(), 4 + 16, "encode must write header + payload");
        dst.clear();

        // 17 bytes: must fail.
        let frame_over = Frame::new(Bytes::from(vec![0x00_u8; 17]));
        let err = <IntermediateCodec as FrameCodecTrait>::encode(&codec, &frame_over, &mut dst)
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(dst.is_empty(), "dst must be empty on rejection");
    }

    // Secure: payload must leave at least 3 bytes of headroom for maximum padding.
    // max_frame_size=16 → payload must be <= 13. Largest aligned payload is 12.
    #[test]
    fn frame_codec_trait_secure_encode_rejects_payload_without_padding_headroom() {
        let codec = SecureCodec::new(Arc::new(SecureRandom::new())).with_max_frame_size(16);

        // 16-byte payload: 16 + 3 (max padding) = 19 > 16 → must be rejected.
        let frame = Frame::new(Bytes::from(vec![0x00_u8; 16]));
        let mut dst = BytesMut::new();
        let err = <SecureCodec as FrameCodecTrait>::encode(&codec, &frame, &mut dst)
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(dst.is_empty(), "dst must be empty on rejection");
    }

    // Secure: 12-byte payload with max_frame_size=16 is exactly within bounds.
    #[test]
    fn frame_codec_trait_secure_encode_accepts_payload_with_padding_headroom() {
        let codec = SecureCodec::new(Arc::new(SecureRandom::new())).with_max_frame_size(16);

        // 12 bytes (4-aligned): 12 + 3 (max padding) = 15 <= 16 → must succeed.
        let frame = Frame::new(Bytes::from(vec![0xBB_u8; 12]));
        let mut dst = BytesMut::new();
        <SecureCodec as FrameCodecTrait>::encode(&codec, &frame, &mut dst).unwrap();
        // Wire: 4-byte header + 12 payload + 1..=3 padding.
        assert!(dst.len() > 4 + 12, "encoded output must include header + payload + padding");
    }

    // The FrameCodecTrait::max_frame_size() must reflect the configured value,
    // not the hardcoded trait default (16 MB).  This ensures dynamic-dispatch
    // callers can query the effective limit.
    #[test]
    fn frame_codec_trait_max_frame_size_reflects_configured_value() {
        let abridged = AbridgedCodec::new().with_max_frame_size(1024);
        let intermediate = IntermediateCodec::new().with_max_frame_size(2048);
        let secure = SecureCodec::new(Arc::new(SecureRandom::new())).with_max_frame_size(4096);

        assert_eq!(<AbridgedCodec as FrameCodecTrait>::max_frame_size(&abridged), 1024);
        assert_eq!(<IntermediateCodec as FrameCodecTrait>::max_frame_size(&intermediate), 2048);
        assert_eq!(<SecureCodec as FrameCodecTrait>::max_frame_size(&secure), 4096);
    }

    // Via Box<dyn FrameCodecTrait> (the create_codec() path), encode must still
    // enforce a configured size limit.  This simulates the real dynamic-dispatch
    // usage pattern where a crate-external caller holds a trait object.
    #[test]
    fn frame_codec_trait_dyn_dispatch_encode_enforces_limit() {
        // Default limit is 16 MB; create a codec with a tiny limit and test via dyn.
        let boxed: Box<dyn FrameCodecTrait> = Box::new(
            IntermediateCodec::new().with_max_frame_size(32)
        );

        // 32 bytes is the limit — must succeed.
        let frame_ok = Frame::new(Bytes::from(vec![0xFF_u8; 32]));
        let mut dst = BytesMut::new();
        boxed.encode(&frame_ok, &mut dst).unwrap();
        dst.clear();

        // 33 bytes is one over — must fail.
        let frame_over = Frame::new(Bytes::from(vec![0xFF_u8; 33]));
        let err = boxed.encode(&frame_over, &mut dst).unwrap_err();
        assert_eq!(
            err.kind(),
            ErrorKind::InvalidInput,
            "dyn FrameCodecTrait encode must enforce max_frame_size via validate"
        );
        assert!(dst.is_empty(), "no bytes must be written on rejection");
    }

    // Encoder<Frame> path and FrameCodecTrait path must produce identical errors
    // for the same oversized payload, proving validate_outbound_payload_size is
    // called consistently in both code paths.
    #[test]
    fn encoder_trait_and_frame_codec_trait_produce_consistent_errors() {
        let rng = Arc::new(SecureRandom::new());
        let oversized = Frame::new(Bytes::from(vec![0x00_u8; 20]));

        // Encoder<Frame> path (tokio-util).
        let mut tokio_codec = SecureCodec::new(Arc::clone(&rng)).with_max_frame_size(16);
        let mut dst_tokio = BytesMut::new();
        let tokio_err = tokio_util::codec::Encoder::encode(
            &mut tokio_codec,
            oversized.clone(),
            &mut dst_tokio,
        )
        .unwrap_err();

        // FrameCodecTrait path (trait object / direct dispatch).
        let trait_codec = SecureCodec::new(rng).with_max_frame_size(16);
        let mut dst_trait = BytesMut::new();
        let trait_err = <SecureCodec as FrameCodecTrait>::encode(&trait_codec, &oversized, &mut dst_trait)
            .unwrap_err();

        assert_eq!(tokio_err.kind(), trait_err.kind(), "both paths must produce the same ErrorKind");
        assert!(dst_tokio.is_empty());
        assert!(dst_trait.is_empty());
    }
}

