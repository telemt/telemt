//! `MTProto` frame types and metadata

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
    
/// Create with `simple_ack` flag set
    pub fn with_simple_ack() -> Self {
        Self {
            simple_ack: true,
            ..Default::default()
        }
    }
    
    /// Check if any flags are set
    pub const fn has_flags(&self) -> bool {
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
/// Full `MTProto` - with `seq_no` and CRC32
    Full,
}

impl FrameMode {
    /// Get maximum overhead for this frame mode
    pub const fn max_overhead(&self) -> usize {
        match self {
            Self::Abridged => 4,
            Self::Intermediate => 4,
            Self::SecureIntermediate => 4 + 3, // length + padding
            Self::Full => 12 + 16, // header + max CBC padding
        }
    }
}

/// Validate message length for `MTProto`
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

    // 16 MB is the maximum valid length (1 << 24 = 16_777_216 = multiple of 4).
    #[test]
    fn test_validate_message_length_max_boundary_valid() {
        assert!(validate_message_length(1 << 24));
    }

    // One alignment unit past the max must be rejected.
    #[test]
    fn test_validate_message_length_max_plus_four_invalid() {
        assert!(!validate_message_length((1 << 24) + 4));
    }

    // Zero is below MIN_MSG_LEN and must be rejected.
    #[test]
    fn test_validate_message_length_zero_invalid() {
        assert!(!validate_message_length(0));
    }

    // usize::MAX must not overflow any internal arithmetic.
    #[test]
    fn test_validate_message_length_usize_max_invalid() {
        assert!(!validate_message_length(usize::MAX));
    }

    // Every misalignment within the minimum block must be rejected.
    #[test]
    fn test_validate_message_length_all_misalignments_at_min() {
        use super::super::constants::MIN_MSG_LEN;
        assert!(validate_message_length(MIN_MSG_LEN)); // base case: aligned
        assert!(!validate_message_length(MIN_MSG_LEN + 1));
        assert!(!validate_message_length(MIN_MSG_LEN + 2));
        assert!(!validate_message_length(MIN_MSG_LEN + 3));
    }

    // Just below maximum must still be valid if aligned.
    #[test]
    fn test_validate_message_length_below_max_aligned_valid() {
        let just_below = (1usize << 24) - 4;
        assert!(validate_message_length(just_below));
    }
}
