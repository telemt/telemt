//! MTProto frame types and traits
//!
//! This module defines the common types and traits used by all
//! frame encoding/decoding implementations.

#![allow(dead_code)]

use bytes::{Bytes, BytesMut};
use std::io::Result;
use std::sync::Arc;

use crate::protocol::constants::ProtoTag;
use crate::crypto::SecureRandom;

// ============= Frame Types =============

/// A decoded MTProto frame
#[derive(Debug, Clone)]
pub struct Frame {
    /// Frame payload data
    pub data: Bytes,
    /// Frame metadata
    pub meta: FrameMeta,
}

impl Frame {
    /// Create a new frame with data and default metadata
    pub fn new(data: Bytes) -> Self {
        Self {
            data,
            meta: FrameMeta::default(),
        }
    }
    
    /// Create a new frame with data and metadata
    pub fn with_meta(data: Bytes, meta: FrameMeta) -> Self {
        Self { data, meta }
    }
    
    /// Create an empty frame
    pub fn empty() -> Self {
        Self::new(Bytes::new())
    }
    
    /// Check if frame is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    
    /// Get frame length
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    /// Create a QuickAck request frame
    pub fn quickack(data: Bytes) -> Self {
        Self {
            data,
            meta: FrameMeta {
                quickack: true,
                ..Default::default()
            },
        }
    }
    
    /// Create a simple ACK frame
    pub fn simple_ack(data: Bytes) -> Self {
        Self {
            data,
            meta: FrameMeta {
                simple_ack: true,
                ..Default::default()
            },
        }
    }
}

/// Frame metadata
#[derive(Debug, Clone, Default)]
pub struct FrameMeta {
    /// Quick ACK requested - client wants immediate acknowledgment
    pub quickack: bool,
    /// This is a simple ACK message (reversed data)
    pub simple_ack: bool,
    /// Original padding length (for secure mode)
    pub padding_len: u8,
}

impl FrameMeta {
    /// Create new empty metadata
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Create with quickack flag
    pub fn with_quickack(mut self) -> Self {
        self.quickack = true;
        self
    }
    
    /// Create with simple_ack flag
    pub fn with_simple_ack(mut self) -> Self {
        self.simple_ack = true;
        self
    }
    
    /// Create with padding length
    pub fn with_padding(mut self, len: u8) -> Self {
        self.padding_len = len;
        self
    }
    
    /// Check if any special flags are set
    pub fn has_flags(&self) -> bool {
        self.quickack || self.simple_ack
    }
}

// ============= Codec Trait =============

/// Trait for frame codecs that can encode and decode frames
pub trait FrameCodec: Send + Sync {
    /// Get the protocol tag for this codec
    fn proto_tag(&self) -> ProtoTag;
    
    /// Encode a frame into the destination buffer
    ///
    /// Returns the number of bytes written.
    fn encode(&self, frame: &Frame, dst: &mut BytesMut) -> Result<usize>;
    
    /// Try to decode a frame from the source buffer
    ///
    /// Returns:
    /// - `Ok(Some(frame))` if a complete frame was decoded
    /// - `Ok(None)` if more data is needed
    /// - `Err(e)` if an error occurred
    ///
    /// On success, the consumed bytes are removed from `src`.
    fn decode(&self, src: &mut BytesMut) -> Result<Option<Frame>>;
    
    /// Get the minimum bytes needed to determine frame length
    fn min_header_size(&self) -> usize;
    
    /// Get the maximum allowed frame size
    fn max_frame_size(&self) -> usize {
        // Default: 16MB
        16 * 1024 * 1024
    }
}

// ============= Codec Factory =============

/// Create a frame codec for the given protocol tag
pub fn create_codec(proto_tag: ProtoTag, rng: Arc<SecureRandom>) -> Box<dyn FrameCodec> {
    match proto_tag {
        ProtoTag::Abridged => Box::new(crate::stream::frame_codec::AbridgedCodec::new()),
        ProtoTag::Intermediate => Box::new(crate::stream::frame_codec::IntermediateCodec::new()),
        ProtoTag::Secure => Box::new(crate::stream::frame_codec::SecureCodec::new(rng)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_frame_creation() {
        let frame = Frame::new(Bytes::from_static(b"test"));
        assert_eq!(frame.len(), 4);
        assert!(!frame.is_empty());
        assert!(!frame.meta.quickack);
        
        let frame = Frame::empty();
        assert!(frame.is_empty());
        
        let frame = Frame::quickack(Bytes::from_static(b"ack"));
        assert!(frame.meta.quickack);
    }
    
    #[test]
    fn test_frame_meta() {
        let meta = FrameMeta::new()
            .with_quickack()
            .with_padding(3);
        
        assert!(meta.quickack);
        assert!(!meta.simple_ack);
        assert_eq!(meta.padding_len, 3);
        assert!(meta.has_flags());
    }
}