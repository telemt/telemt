//! tokio-util codec integration for MTProto frames
//!
//! This module provides Encoder/Decoder implementations compatible
//! with tokio-util's Framed wrapper for easy async frame I/O.

#![allow(dead_code)]

use bytes::{Bytes, BytesMut, BufMut};
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
    pub fn new(proto_tag: ProtoTag, rng: Arc<SecureRandom>) -> Self {
        Self {
            proto_tag,
            max_frame_size: 16 * 1024 * 1024, // 16MB default
            rng,
        }
    }
    
    /// Set maximum frame size
    pub fn with_max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }
    
    /// Get protocol tag
    pub fn proto_tag(&self) -> ProtoTag {
        self.proto_tag
    }
}

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = io::Error;
    
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.proto_tag {
            ProtoTag::Abridged => decode_abridged(src, self.max_frame_size),
            ProtoTag::Intermediate => decode_intermediate(src, self.max_frame_size),
            ProtoTag::Secure => decode_secure(src, self.max_frame_size),
        }
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = io::Error;
    
    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
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
    if len >= 0x80000000 {
        meta.quickack = true;
        len -= 0x80000000;
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
        len |= 0x80000000;
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
    if len >= 0x80000000 {
        meta.quickack = true;
        len -= 0x80000000;
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
    
    let data_len = secure_payload_len_from_wire_len(len).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            format!("invalid secure frame length: {len}"),
        )
    })?;
    let padding_len = len - data_len;
    
    meta.padding_len = padding_len as u8;
    
    // Extract data (excluding padding)
    let _ = src.split_to(4);
    let all_data = src.split_to(len);
    // Copy only the data portion, excluding padding
    let data = Bytes::copy_from_slice(&all_data[..data_len]);
    
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
        len |= 0x80000000;
    }
    
    dst.extend_from_slice(&len.to_le_bytes());
    dst.extend_from_slice(data);
    
    if padding_len > 0 {
        let padding = rng.bytes(padding_len);
        dst.extend_from_slice(&padding);
    }
    
    Ok(())
}

// ============= Typed Codecs =============

/// Abridged protocol codec
pub struct AbridgedCodec {
    max_frame_size: usize,
}

impl AbridgedCodec {
    pub fn new() -> Self {
        Self {
            max_frame_size: 16 * 1024 * 1024,
        }
    }
}

impl Default for AbridgedCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for AbridgedCodec {
    type Item = Frame;
    type Error = io::Error;
    
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        decode_abridged(src, self.max_frame_size)
    }
}

impl Encoder<Frame> for AbridgedCodec {
    type Error = io::Error;
    
    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        encode_abridged(&frame, dst)
    }
}

impl FrameCodecTrait for AbridgedCodec {
    fn proto_tag(&self) -> ProtoTag {
        ProtoTag::Abridged
    }
    
    fn encode(&self, frame: &Frame, dst: &mut BytesMut) -> io::Result<usize> {
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
    pub fn new() -> Self {
        Self {
            max_frame_size: 16 * 1024 * 1024,
        }
    }
}

impl Default for IntermediateCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for IntermediateCodec {
    type Item = Frame;
    type Error = io::Error;
    
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        decode_intermediate(src, self.max_frame_size)
    }
}

impl Encoder<Frame> for IntermediateCodec {
    type Error = io::Error;
    
    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        encode_intermediate(&frame, dst)
    }
}

impl FrameCodecTrait for IntermediateCodec {
    fn proto_tag(&self) -> ProtoTag {
        ProtoTag::Intermediate
    }
    
    fn encode(&self, frame: &Frame, dst: &mut BytesMut) -> io::Result<usize> {
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
    pub fn new(rng: Arc<SecureRandom>) -> Self {
        Self {
            max_frame_size: 16 * 1024 * 1024,
            rng,
        }
    }
}

impl Default for SecureCodec {
    fn default() -> Self {
        Self::new(Arc::new(SecureRandom::new()))
    }
}

impl Decoder for SecureCodec {
    type Item = Frame;
    type Error = io::Error;
    
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        decode_secure(src, self.max_frame_size)
    }
}

impl Encoder<Frame> for SecureCodec {
    type Error = io::Error;
    
    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        encode_secure(&frame, dst, &self.rng)
    }
}

impl FrameCodecTrait for SecureCodec {
    fn proto_tag(&self) -> ProtoTag {
        ProtoTag::Secure
    }
    
    fn encode(&self, frame: &Frame, dst: &mut BytesMut) -> io::Result<usize> {
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
}
