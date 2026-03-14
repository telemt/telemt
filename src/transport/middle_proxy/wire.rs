use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use bytes::Bytes;

use crate::protocol::constants::{
    RPC_FLAG_ABRIDGED,
    RPC_FLAG_EXTMODE2,
    RPC_FLAG_HAS_AD_TAG,
    RPC_FLAG_INTERMEDIATE,
    RPC_FLAG_MAGIC,
    RPC_FLAG_PAD,
    RPC_PROXY_REQ_U32,
    TL_PROXY_TAG_U32,
};

#[derive(Clone, Copy)]
pub(crate) enum IpMaterial {
    V4([u8; 4]),
    V6([u8; 16]),
}

pub(crate) const fn extract_ip_material(addr: SocketAddr) -> IpMaterial {
    match addr.ip() {
        IpAddr::V4(v4) => IpMaterial::V4(v4.octets()),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpMaterial::V4(v4.octets()),
            None => IpMaterial::V6(v6.octets()),
        },

    }
}

fn ipv4_to_mapped_v6_c_compat(ip: Ipv4Addr) -> [u8; 16] {
    let mut buf = [0u8; 16];

    // Matches tl_store_long(0) + tl_store_int(-0x10000).
    buf[8..12].copy_from_slice(&(-0x10000i32).to_le_bytes());

    // Matches tl_store_int(htonl(remote_ip_host_order)).
    buf[12..16].copy_from_slice(&ip.octets());

    buf
}

fn append_mapped_addr_and_port(buf: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(v4) => buf.extend_from_slice(&ipv4_to_mapped_v6_c_compat(v4)),
        IpAddr::V6(v6) => buf.extend_from_slice(&v6.octets()),
    }
    buf.extend_from_slice(&u32::from(addr.port()).to_le_bytes());
}

pub(crate) fn build_proxy_req_payload(
    conn_id: u64,
    client_addr: SocketAddr,
    our_addr: SocketAddr,
    data: &[u8],
    proxy_tag: Option<&[u8]>,
    proto_flags: u32,
) -> Bytes {
    let mut b = Vec::with_capacity(128 + data.len());

    b.extend_from_slice(&RPC_PROXY_REQ_U32.to_le_bytes());
    b.extend_from_slice(&proto_flags.to_le_bytes());
    b.extend_from_slice(&conn_id.to_le_bytes());

    append_mapped_addr_and_port(&mut b, client_addr);
    append_mapped_addr_and_port(&mut b, our_addr);

    if proto_flags & RPC_FLAG_HAS_AD_TAG != 0 {
        let extra_start = b.len();
        b.extend_from_slice(&0u32.to_le_bytes());

        if let Some(tag) = proxy_tag {
            let tag_start = b.len();
            // TL bytes encoding: short form (1-byte length) for < 254 B;
            // long form (0xFE marker + 3-byte length) for 254 B to 16,777,215 B (0xFFFFFF).
            // Tags exceeding the 3-byte limit cannot be represented and are silently dropped
            // so the extra block remains empty rather than carrying a truncated length.
            if tag.len() <= 0xFF_FF_FF {
                b.extend_from_slice(&TL_PROXY_TAG_U32.to_le_bytes());

                if tag.len() < 254 {
                    b.push(tag.len() as u8);
                    b.extend_from_slice(tag);
                    let pad = (4 - ((1 + tag.len()) % 4)) % 4;
                    b.extend(std::iter::repeat_n(0u8, pad));
                } else {
                    b.push(0xfe);
                    b.extend_from_slice(&(tag.len() as u32).to_le_bytes()[..3]);
                    b.extend_from_slice(tag);
                    let pad = (4 - (tag.len() % 4)) % 4;
                    b.extend(std::iter::repeat_n(0u8, pad));
                }
            } else {
                // Keep extra block empty when the tag cannot be represented in TL bytes length.
                b.truncate(tag_start);
            }
        }

        // On overflow (buffer > 4 GiB, unreachable in practice) keep the extra block
        // empty by truncating the data back to the length-field position and writing 0,
        // so the wire representation remains consistent (length field matches content).
        match u32::try_from(b.len() - extra_start - 4) {
            Ok(extra_bytes) => {
                b[extra_start..extra_start + 4].copy_from_slice(&extra_bytes.to_le_bytes());
            }
            Err(_) => {
                b.truncate(extra_start + 4);
                b[extra_start..extra_start + 4].copy_from_slice(&0u32.to_le_bytes());
            }
        }
    }

    b.extend_from_slice(data);
    Bytes::from(b)
}

pub const fn proto_flags_for_tag(tag: crate::protocol::constants::ProtoTag, has_proxy_tag: bool) -> u32 {
    use crate::protocol::constants::ProtoTag;

    let mut flags = RPC_FLAG_MAGIC | RPC_FLAG_EXTMODE2;
    if has_proxy_tag {
        flags |= RPC_FLAG_HAS_AD_TAG;
    }

    match tag {
        ProtoTag::Abridged => flags | RPC_FLAG_ABRIDGED,
        ProtoTag::Intermediate => flags | RPC_FLAG_INTERMEDIATE,
        ProtoTag::Secure => flags | RPC_FLAG_PAD | RPC_FLAG_INTERMEDIATE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV6};

    #[test]
    fn test_ipv4_mapped_encoding() {
        let ip = Ipv4Addr::new(149, 154, 175, 50);
        let buf = ipv4_to_mapped_v6_c_compat(ip);
        assert_eq!(&buf[0..10], &[0u8; 10]);
        assert_eq!(&buf[10..12], &[0xff, 0xff]);
        assert_eq!(&buf[12..16], &[149, 154, 175, 50]);
    }

    #[test]
    fn test_extract_ip_material_collapses_v4_mapped_ipv6() {
        let mapped = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201),
            443,
            0,
            0,
        ));

        match extract_ip_material(mapped) {
            IpMaterial::V4(v4) => assert_eq!(v4, [192, 0, 2, 1]),
            IpMaterial::V6(_) => panic!("expected v4 material for v4-mapped IPv6"),
        }
    }

    #[test]
    fn test_build_proxy_req_payload_short_tag_encodes_tl_bytes_and_padding() {
        let client = SocketAddr::from(([198, 51, 100, 10], 12345));
        let ours = SocketAddr::from(([203, 0, 113, 50], 443));
        let payload = build_proxy_req_payload(
            7,
            client,
            ours,
            b"abc",
            Some(&[1, 2, 3]),
            RPC_FLAG_HAS_AD_TAG,
        );

        let raw = payload.as_ref();
        let fixed_header_len = 4 + 4 + 8 + 20 + 20;
        let extra_len = u32::from_le_bytes(
            raw[fixed_header_len..fixed_header_len + 4]
                .try_into()
                .unwrap_or([0; 4]),
        ) as usize;

        // TL object + short-bytes header + tag + padding to 4-byte boundary.
        assert_eq!(extra_len, 4 + 1 + 3);
        assert_eq!(&raw[fixed_header_len + 4..fixed_header_len + 8], &TL_PROXY_TAG_U32.to_le_bytes());
        assert_eq!(raw[fixed_header_len + 8], 3);
        assert_eq!(&raw[fixed_header_len + 9..fixed_header_len + 12], &[1, 2, 3]);
        assert_eq!(&raw[raw.len() - 3..], b"abc");
    }

    #[test]
    fn test_build_proxy_req_payload_long_tag_uses_0xfe_length_header() {
        let client = SocketAddr::from(([198, 51, 100, 11], 23456));
        let ours = SocketAddr::from(([203, 0, 113, 51], 443));
        let long_tag = vec![0xAA; 300];
        let payload = build_proxy_req_payload(
            9,
            client,
            ours,
            b"z",
            Some(&long_tag),
            RPC_FLAG_HAS_AD_TAG,
        );

        let raw = payload.as_ref();
        let fixed_header_len = 4 + 4 + 8 + 20 + 20;
        let extra_len = u32::from_le_bytes(
            raw[fixed_header_len..fixed_header_len + 4]
                .try_into()
                .unwrap_or([0; 4]),
        ) as usize;

        assert_eq!(raw[fixed_header_len + 8], 0xfe);
        assert_eq!(&raw[fixed_header_len + 9..fixed_header_len + 12], &[44, 1, 0]);
        assert_eq!(extra_len, 4 + 4 + 300);
        assert_eq!(&raw[raw.len() - 1..], b"z");
    }
    // Tag of exactly 253 bytes uses the 1-byte short-form TL encoding.
    #[test]
    fn test_build_proxy_req_payload_tag_at_short_form_max_boundary() {
        let client = SocketAddr::from(([198, 51, 100, 20], 11111));
        let ours = SocketAddr::from(([203, 0, 113, 20], 443));
        let tag = vec![0xBBu8; 253];
        let payload = build_proxy_req_payload(7, client, ours, b"x", Some(&tag), RPC_FLAG_HAS_AD_TAG);
        let raw = payload.as_ref();
        let fixed = 4 + 4 + 8 + 20 + 20;
        let extra_len = u32::from_le_bytes(raw[fixed..fixed + 4].try_into().unwrap()) as usize;
        // TL object (4) + length byte (1) + 253-byte tag + padding to 4-byte boundary.
        // (1 + 253) = 254; 254 % 4 = 2; pad = (4 - 2) % 4 = 2.
        assert_eq!(extra_len, 4 + 1 + 253 + 2);
        // The length byte must be 253 (short form, not 0xfe).
        assert_eq!(raw[fixed + 8], 253u8);
    }

    // Tag of exactly 254 bytes uses the 0xFE long-form TL encoding.
    #[test]
    fn test_build_proxy_req_payload_tag_at_long_form_min_boundary() {
        let client = SocketAddr::from(([198, 51, 100, 21], 22222));
        let ours = SocketAddr::from(([203, 0, 113, 21], 443));
        let tag = vec![0xCCu8; 254];
        let payload = build_proxy_req_payload(8, client, ours, b"y", Some(&tag), RPC_FLAG_HAS_AD_TAG);
        let raw = payload.as_ref();
        let fixed = 4 + 4 + 8 + 20 + 20;
        let extra_len = u32::from_le_bytes(raw[fixed..fixed + 4].try_into().unwrap()) as usize;
        // TL object (4) + 0xfe (1) + 3-byte length + 254 bytes + padding.
        // 254 % 4 = 2; pad = (4 - 2) % 4 = 2.
        assert_eq!(extra_len, 4 + 1 + 3 + 254 + 2);
        assert_eq!(raw[fixed + 8], 0xfeu8, "must use long-form 0xFE marker at 254 bytes");
        // 3-byte LE encoding of 254 = [0xFE, 0x00, 0x00].
        assert_eq!(&raw[fixed + 9..fixed + 12], &[254u8, 0, 0]);
    }

    // Tags exceeding the 3-byte TL length limit (> 0xFFFFFF = 16,777,215 bytes)
    // must produce an empty extra block rather than a truncated/corrupt length.
    #[ignore = "allocates ~16 MiB; run only in a dedicated large-tests profile/CI job"]
    #[test]
    fn test_build_proxy_req_payload_tag_exceeds_tl_long_form_limit_produces_empty_extra() {
        let client = SocketAddr::from(([198, 51, 100, 22], 33333));
        let ours = SocketAddr::from(([203, 0, 113, 22], 443));
        // 0x1000000 = 16,777,216 bytes — one byte over the 3-byte TL limit.
        let oversized_tag = vec![0u8; 0x1000000];
        let payload = build_proxy_req_payload(
            9,
            client,
            ours,
            b"data",
            Some(&oversized_tag),
            RPC_FLAG_HAS_AD_TAG,
        );
        let raw = payload.as_ref();
        let fixed = 4 + 4 + 8 + 20 + 20;
        let extra_len = u32::from_le_bytes(raw[fixed..fixed + 4].try_into().unwrap()) as usize;
        assert_eq!(
            extra_len, 0,
            "oversized tag must leave extra block empty, not encode a truncated length"
        );
    }

    // The prior guard was `tag_len_u32.is_some()` which passed for tags up to u32::MAX.
    // Verify boundary at exactly 0xFFFFFF: must succeed and encode at 3 bytes.
    #[ignore = "allocates ~16 MiB; run only in a dedicated large-tests profile/CI job"]
    #[test]
    fn test_build_proxy_req_payload_tag_at_tl_long_form_max_boundary_encodes() {
        // 0xFFFFFF = 16,777,215 bytes — maximum representable by 3-byte TL length.
        // Allocating 16 MiB in a test is intentional: this is the exact boundary.
        let tag = vec![0xAAu8; 0xFF_FF_FF];
        let client = SocketAddr::from(([198, 51, 100, 23], 44444));
        let ours = SocketAddr::from(([203, 0, 113, 23], 443));
        let payload = build_proxy_req_payload(
            10,
            client,
            ours,
            b"",
            Some(&tag),
            RPC_FLAG_HAS_AD_TAG,
        );
        let raw = payload.as_ref();
        let fixed = 4 + 4 + 8 + 20 + 20;
        let extra_len = u32::from_le_bytes(raw[fixed..fixed + 4].try_into().unwrap()) as usize;
        // extra block must not be empty for a valid 0xFFFFFF-byte tag.
        assert!(extra_len > 0, "tag at limit 0xFFFFFF must be encoded, not dropped");
        assert_eq!(raw[fixed + 8], 0xfeu8, "must use long-form 0xFE marker");
        // 3-byte LE of 0xFFFFFF = [0xFF, 0xFF, 0xFF].
        assert_eq!(&raw[fixed + 9..fixed + 12], &[0xFF, 0xFF, 0xFF]);
    }

    // No-tag path: HAS_AD_TAG set but proxy_tag = None must produce an empty extra block.
    #[test]
    fn test_build_proxy_req_payload_no_tag_produces_empty_extra_block() {
        let client = SocketAddr::from(([198, 51, 100, 30], 55555));
        let ours = SocketAddr::from(([203, 0, 113, 30], 443));
        let payload =
            build_proxy_req_payload(11, client, ours, b"abc", None, RPC_FLAG_HAS_AD_TAG);
        let raw = payload.as_ref();
        let fixed = 4 + 4 + 8 + 20 + 20;
        let extra_len = u32::from_le_bytes(raw[fixed..fixed + 4].try_into().unwrap()) as usize;
        assert_eq!(extra_len, 0);
    }

    // ── Protocol wire-consistency invariant tests ─────────────────────────────

    // The extra-block length field must ALWAYS equal the number of bytes that
    // actually follow it in the buffer. A censor or MitM that parses the wire
    // representation must not be able to trigger desync by providing adversarial
    // input that causes the length to say 0 while data bytes are present.
    #[test]
    fn extra_block_length_field_always_matches_actual_content_length() {
        let client = SocketAddr::from(([198, 51, 100, 40], 10000));
        let ours = SocketAddr::from(([203, 0, 113, 40], 443));
        let fixed = 4 + 4 + 8 + 20 + 20;

        // Helper: assert wire consistency for a given tag.
        let check = |tag: Option<&[u8]>, data: &[u8]| {
            let p = build_proxy_req_payload(1, client, ours, data, tag, RPC_FLAG_HAS_AD_TAG);
            let raw = p.as_ref();
            let declared =
                u32::from_le_bytes(raw[fixed..fixed + 4].try_into().unwrap()) as usize;
            let actual = raw.len() - fixed - 4 - data.len();
            assert_eq!(
                declared, actual,
                "extra-block length field ({declared}) must equal actual byte count ({actual})"
            );
        };

        check(None, b"data");
        check(Some(b""), b"data"); // zero-length tag
        check(Some(&[0xABu8; 1]), b"");   // 1-byte tag
        check(Some(&[0xABu8; 253]), b"x"); // short-form max
        check(Some(&[0xCCu8; 254]), b"y"); // long-form min
        check(Some(&[0xDDu8; 500]), b"z"); // mid-range long-form
    }

    // Zero-length tag: must encode with short-form length byte 0 and 4-byte
    // alignment padding, not be dropped as if tag were None.
    #[test]
    fn test_build_proxy_req_payload_zero_length_tag_encodes_correctly() {
        let client = SocketAddr::from(([198, 51, 100, 50], 20000));
        let ours = SocketAddr::from(([203, 0, 113, 50], 443));
        let payload = build_proxy_req_payload(
            12,
            client,
            ours,
            b"payload",
            Some(&[]),
            RPC_FLAG_HAS_AD_TAG,
        );
        let raw = payload.as_ref();
        let fixed = 4 + 4 + 8 + 20 + 20;
        let extra_len = u32::from_le_bytes(raw[fixed..fixed + 4].try_into().unwrap()) as usize;
        // TL object (4) + length-byte 0 (1) + 0 data bytes + padding to 4-byte boundary.
        // (1 + 0) % 4 = 1; pad = (4 - 1) % 4 = 3.
        assert_eq!(extra_len, 4 + 1 + 3, "zero-length tag must produce TL header + padding");
        // Length byte must be 0 (short-form).
        assert_eq!(raw[fixed + 8], 0u8);
    }

    // HAS_AD_TAG absent: extra block must NOT appear in the wire output at all.
    #[test]
    fn test_build_proxy_req_payload_without_has_ad_tag_flag_has_no_extra_block() {
        let client = SocketAddr::from(([198, 51, 100, 60], 30000));
        let ours = SocketAddr::from(([203, 0, 113, 60], 443));
        let payload = build_proxy_req_payload(
            13,
            client,
            ours,
            b"data",
            Some(&[1, 2, 3]),
            0, // no HAS_AD_TAG flag
        );
        let fixed = 4 + 4 + 8 + 20 + 20;
        let raw = payload.as_ref();
        // Without the flag, extra block is skipped; payload follows immediately after headers.
        assert_eq!(raw.len(), fixed + 4, "no extra block when HAS_AD_TAG is absent");
        assert_eq!(&raw[fixed..], b"data");
    }

    // Tag with all-0xFF bytes: the TL length encoding must not be confused by
    // the 0xFF marker byte that the tag itself might contain.
    #[test]
    fn test_build_proxy_req_payload_tag_containing_0xfe_byte_encodes_correctly() {
        let client = SocketAddr::from(([198, 51, 100, 70], 40000));
        let ours = SocketAddr::from(([203, 0, 113, 70], 443));
        // 10-byte tag whose first byte is 0xFE (the long-form marker value).
        // At length 10 the short-form encoding applies; the 0xFE data byte must
        // not be confused with the length marker.
        let tag = vec![0xFEu8; 10];
        let payload = build_proxy_req_payload(14, client, ours, b"", Some(&tag), RPC_FLAG_HAS_AD_TAG);
        let raw = payload.as_ref();
        let fixed = 4 + 4 + 8 + 20 + 20;
        // Length byte must be 10 (short form), not 0xFE.
        assert_eq!(raw[fixed + 8], 10u8, "short-form length byte must be 10, not the 0xFE marker");
        // The actual tag bytes must follow immediately.
        assert_eq!(&raw[fixed + 9..fixed + 19], &[0xFEu8; 10]);
    }
}
