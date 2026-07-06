//! Shared MTProto transport framing helpers.

use crate::crypto::SecureRandom;

/// QuickACK marker bit used by Intermediate and Secure Intermediate headers.
pub(crate) const INTERMEDIATE_QUICKACK_FLAG: u32 = 0x8000_0000;

/// Payload length mask used by Intermediate and Secure Intermediate headers.
pub(crate) const INTERMEDIATE_WIRE_LEN_MASK: u32 = 0x7fff_ffff;

/// Maximum outbound Secure tail length that keeps wire lengths non-aligned.
pub(crate) const SECURE_VERSION_D_PADDING_MAX: usize = 3;

/// Parsed Intermediate/Secure Intermediate length header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IntermediateHeader {
    /// Payload length on the wire, excluding the four-byte header.
    pub(crate) wire_len: usize,
    /// Whether the QuickACK marker bit was set in the length header.
    pub(crate) quickack: bool,
}

/// Parse an Intermediate/Secure Intermediate length header.
pub(crate) fn parse_intermediate_header(header: [u8; 4]) -> IntermediateHeader {
    let raw = u32::from_le_bytes(header);
    IntermediateHeader {
        wire_len: (raw & INTERMEDIATE_WIRE_LEN_MASK) as usize,
        quickack: (raw & INTERMEDIATE_QUICKACK_FLAG) != 0,
    }
}

/// Encode an Intermediate/Secure Intermediate length header.
pub(crate) fn encode_intermediate_header(wire_len: usize, quickack: bool) -> Option<u32> {
    if wire_len > INTERMEDIATE_WIRE_LEN_MASK as usize {
        return None;
    }

    let mut raw = u32::try_from(wire_len).ok()?;
    if quickack {
        raw |= INTERMEDIATE_QUICKACK_FLAG;
    }
    Some(raw)
}

/// Recover the VersionD body length visible to MTProto from the encrypted wire length.
pub(crate) fn secure_version_d_body_len_from_wire_len(wire_len: usize) -> Option<usize> {
    if wire_len < 4 {
        return None;
    }

    Some(wire_len - (wire_len % 4))
}

/// Generate outbound Secure tail length without ambiguous full-word padding.
pub(crate) fn secure_version_d_padding_len(rng: &SecureRandom) -> usize {
    rng.range(SECURE_VERSION_D_PADDING_MAX) + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intermediate_header_roundtrip_preserves_quickack_zero_length() {
        let encoded = encode_intermediate_header(0, true).unwrap();
        assert_eq!(encoded, INTERMEDIATE_QUICKACK_FLAG);

        let parsed = parse_intermediate_header(encoded.to_le_bytes());
        assert_eq!(parsed.wire_len, 0);
        assert!(parsed.quickack);
    }

    #[test]
    fn intermediate_header_rejects_lengths_above_31_bits() {
        assert_eq!(
            encode_intermediate_header(INTERMEDIATE_WIRE_LEN_MASK as usize, false),
            Some(INTERMEDIATE_WIRE_LEN_MASK)
        );
        assert_eq!(
            encode_intermediate_header(INTERMEDIATE_WIRE_LEN_MASK as usize + 1, false),
            None
        );
    }

    #[test]
    fn secure_version_d_body_len_strips_only_non_word_tail() {
        assert_eq!(secure_version_d_body_len_from_wire_len(3), None);
        assert_eq!(secure_version_d_body_len_from_wire_len(8), Some(8));
        assert_eq!(secure_version_d_body_len_from_wire_len(11), Some(8));
        assert_eq!(secure_version_d_body_len_from_wire_len(12), Some(12));
    }
}
