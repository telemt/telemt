//! MTProto frame types and metadata

#![allow(dead_code)]

use std::collections::HashMap;

/// Extra metadata associated with a frame
#[derive(Debug, Clone, Default)]
pub struct FrameExtra {
    /// Quick ACK flag - request immediate acknowledgment
    pub quickack: bool,
    /// Simple ACK - this is an acknowledgment message
    pub simple_ack: bool,
    /// Skip sending - internal flag to skip forwarding
    pub skip_send: bool,
    /// Custom key-value metadata
    pub custom: HashMap<String, String>,
}

impl FrameExtra {
    /// Create new empty frame extra
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Create with quickack flag set
    pub fn with_quickack() -> Self {
        Self {
            quickack: true,
            ..Default::default()
        }
    }
    
    /// Create with simple_ack flag set
    pub fn with_simple_ack() -> Self {
        Self {
            simple_ack: true,
            ..Default::default()
        }
    }
    
    /// Check if any flags are set
    pub fn has_flags(&self) -> bool {
        self.quickack || self.simple_ack || self.skip_send
    }
}

/// Result of reading a frame
#[derive(Debug)]
pub enum FrameReadResult {
    /// Successfully read a frame with data and metadata
    Data(Vec<u8>, FrameExtra),
    /// Connection closed normally
    Closed,
    /// Need more data (for non-blocking reads)
    WouldBlock,
}

/// Frame encoding/decoding mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameMode {
    /// Abridged - 1 or 4 byte length prefix
    Abridged,
    /// Intermediate - 4 byte length prefix
    Intermediate,
    /// Secure Intermediate - 4 byte length with padding
    SecureIntermediate,
    /// Full MTProto - with seq_no and CRC32
    Full,
}

impl FrameMode {
    /// Get maximum overhead for this frame mode
    pub fn max_overhead(&self) -> usize {
        match self {
            FrameMode::Abridged => 4,
            FrameMode::Intermediate => 4,
            FrameMode::SecureIntermediate => 4 + 3, // length + padding
            FrameMode::Full => 12 + 16, // header + max CBC padding
        }
    }
}

/// Validate message length for MTProto
pub fn validate_message_length(len: usize) -> bool {
    use super::constants::{MIN_MSG_LEN, MAX_MSG_LEN, PADDING_FILLER};
    
    (MIN_MSG_LEN..=MAX_MSG_LEN).contains(&len) && len.is_multiple_of(PADDING_FILLER.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_frame_extra_default() {
        let extra = FrameExtra::default();
        assert!(!extra.quickack);
        assert!(!extra.simple_ack);
        assert!(!extra.skip_send);
        assert!(!extra.has_flags());
    }
    
    #[test]
    fn test_frame_extra_flags() {
        let extra = FrameExtra::with_quickack();
        assert!(extra.quickack);
        assert!(extra.has_flags());
        
        let extra = FrameExtra::with_simple_ack();
        assert!(extra.simple_ack);
        assert!(extra.has_flags());
    }
    
    #[test]
    fn test_validate_message_length() {
        assert!(validate_message_length(12)); // MIN_MSG_LEN
        assert!(validate_message_length(16));
        assert!(!validate_message_length(8)); // Too small
        assert!(!validate_message_length(13)); // Not aligned to 4
    }
}