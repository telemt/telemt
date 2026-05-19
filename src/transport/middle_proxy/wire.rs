use bytes::Bytes;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::protocol::constants::*;

#[derive(Clone, Copy)]
pub(crate) enum IpMaterial {
    V4([u8; 4]),
    V6([u8; 16]),
}

pub(crate) fn extract_ip_material(addr: SocketAddr) -> IpMaterial {
    match addr.ip() {
        IpAddr::V4(v4) => IpMaterial::V4(v4.octets()),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpMaterial::V4(v4.octets())
            } else {
                IpMaterial::V6(v6.octets())
            }
        }
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
    buf.extend_from_slice(&(addr.port() as u32).to_le_bytes());
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
            b.extend_from_slice(&TL_PROXY_TAG_U32.to_le_bytes());

            if tag.len() < 254 {
                b.push(tag.len() as u8);
                b.extend_from_slice(tag);
                let pad = (4 - ((1 + tag.len()) % 4)) % 4;
                b.extend(std::iter::repeat_n(0u8, pad));
            } else {
                b.push(0xfe);
                let len_bytes = (tag.len() as u32).to_le_bytes();
                b.extend_from_slice(&len_bytes[..3]);
                b.extend_from_slice(tag);
                let pad = (4 - (tag.len() % 4)) % 4;
                b.extend(std::iter::repeat_n(0u8, pad));
            }
        }

        let extra_bytes = (b.len() - extra_start - 4) as u32;
        b[extra_start..extra_start + 4].copy_from_slice(&extra_bytes.to_le_bytes());
    }

    b.extend_from_slice(data);
    Bytes::from(b)
}

pub fn proto_flags_for_tag(tag: crate::protocol::constants::ProtoTag, has_proxy_tag: bool) -> u32 {
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
    use crate::protocol::constants::ProtoTag;
    use std::net::Ipv6Addr;

    #[test]
    fn test_ipv4_mapped_encoding() {
        let ip = Ipv4Addr::new(149, 154, 175, 50);
        let buf = ipv4_to_mapped_v6_c_compat(ip);
        assert_eq!(&buf[0..10], &[0u8; 10]);
        assert_eq!(&buf[10..12], &[0xff, 0xff]);
        assert_eq!(&buf[12..16], &[149, 154, 175, 50]);
    }

    #[test]
    fn ipv4_mapped_zero_address() {
        let buf = ipv4_to_mapped_v6_c_compat(Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(&buf[0..10], &[0u8; 10]);
        assert_eq!(&buf[10..12], &[0xff, 0xff]);
        assert_eq!(&buf[12..16], &[0, 0, 0, 0]);
    }

    #[test]
    fn ipv4_mapped_all_ones() {
        let buf = ipv4_to_mapped_v6_c_compat(Ipv4Addr::new(255, 255, 255, 255));
        // Bytes 8..12 encode -0x10000 in little-endian (matches Telegram's
        // C reference `tl_store_int(-0x10000)`).
        let expected_marker = (-0x10000i32).to_le_bytes();
        assert_eq!(&buf[8..12], &expected_marker);
        assert_eq!(&buf[12..16], &[0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn extract_ip_material_v4() {
        let addr: SocketAddr = "10.0.0.5:12345".parse().unwrap();
        match extract_ip_material(addr) {
            IpMaterial::V4(o) => assert_eq!(o, [10, 0, 0, 5]),
            IpMaterial::V6(_) => panic!("expected V4"),
        }
    }

    #[test]
    fn extract_ip_material_v6_native() {
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let addr = SocketAddr::new(IpAddr::V6(v6), 443);
        match extract_ip_material(addr) {
            IpMaterial::V6(o) => assert_eq!(o, v6.octets()),
            IpMaterial::V4(_) => panic!("expected V6"),
        }
    }

    #[test]
    fn extract_ip_material_ipv4_mapped_v6_collapses_to_v4() {
        // ::ffff:1.2.3.4 must be returned as V4 octets, NOT V6 — this is
        // the contract for the proxy-req payload (Telegram's middle proxy
        // expects native v4 octets in such cases).
        let v4 = Ipv4Addr::new(1, 2, 3, 4);
        let mapped: Ipv6Addr = v4.to_ipv6_mapped();
        let addr = SocketAddr::new(IpAddr::V6(mapped), 80);
        match extract_ip_material(addr) {
            IpMaterial::V4(o) => assert_eq!(o, [1, 2, 3, 4]),
            IpMaterial::V6(_) => panic!("expected ipv4-mapped to collapse to V4"),
        }
    }

    #[test]
    fn proto_flags_for_tag_sets_protocol_bits() {
        let a = proto_flags_for_tag(ProtoTag::Abridged, false);
        assert!(a & RPC_FLAG_ABRIDGED != 0);
        assert!(a & RPC_FLAG_INTERMEDIATE == 0);
        assert!(a & RPC_FLAG_PAD == 0);
        assert!(a & RPC_FLAG_MAGIC != 0);
        assert!(a & RPC_FLAG_EXTMODE2 != 0);
        assert!(a & RPC_FLAG_HAS_AD_TAG == 0);

        let i = proto_flags_for_tag(ProtoTag::Intermediate, false);
        assert!(i & RPC_FLAG_INTERMEDIATE != 0);
        assert!(i & RPC_FLAG_ABRIDGED == 0);
        assert!(i & RPC_FLAG_PAD == 0);

        let s = proto_flags_for_tag(ProtoTag::Secure, false);
        // Secure layers PAD on top of intermediate framing.
        assert!(s & RPC_FLAG_INTERMEDIATE != 0);
        assert!(s & RPC_FLAG_PAD != 0);
        assert!(s & RPC_FLAG_ABRIDGED == 0);
    }

    #[test]
    fn proto_flags_for_tag_with_ad_tag_sets_ad_tag_bit() {
        for tag in [ProtoTag::Abridged, ProtoTag::Intermediate, ProtoTag::Secure] {
            let without = proto_flags_for_tag(tag, false);
            let with = proto_flags_for_tag(tag, true);
            assert_eq!(without & RPC_FLAG_HAS_AD_TAG, 0);
            assert_ne!(with & RPC_FLAG_HAS_AD_TAG, 0);
            // The only difference between the two must be the AD_TAG bit.
            assert_eq!(without | RPC_FLAG_HAS_AD_TAG, with);
        }
    }

    #[test]
    fn build_proxy_req_payload_header_layout() {
        let conn_id: u64 = 0x0102_0304_0506_0708;
        let client: SocketAddr = "10.1.2.3:1024".parse().unwrap();
        let our: SocketAddr = "10.4.5.6:2048".parse().unwrap();
        let data = b"hello";
        // No AD_TAG bit → no extra block, payload follows addresses directly.
        let flags = proto_flags_for_tag(ProtoTag::Intermediate, false);
        let out = build_proxy_req_payload(conn_id, client, our, data, None, flags);

        // [0..4]   RPC_PROXY_REQ marker
        assert_eq!(&out[0..4], &RPC_PROXY_REQ_U32.to_le_bytes());
        // [4..8]   flags (LE)
        assert_eq!(&out[4..8], &flags.to_le_bytes());
        // [8..16]  conn_id (LE)
        assert_eq!(&out[8..16], &conn_id.to_le_bytes());
        // [16..36] client mapped-v6 (16 bytes) + port-u32 (4 bytes)
        assert_eq!(&out[28..32], &[10, 1, 2, 3]);
        assert_eq!(&out[32..36], &(1024u32).to_le_bytes());
        // [36..56] our mapped-v6 (16 bytes) + port-u32 (4 bytes)
        assert_eq!(&out[48..52], &[10, 4, 5, 6]);
        assert_eq!(&out[52..56], &(2048u32).to_le_bytes());
        // Trailing bytes are the user data.
        assert_eq!(&out[out.len() - data.len()..], data);
    }

    #[test]
    fn build_proxy_req_payload_inline_short_ad_tag() {
        let client: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let our: SocketAddr = "10.0.0.2:2".parse().unwrap();
        let data = b"\xAA\xBB";
        let flags = proto_flags_for_tag(ProtoTag::Abridged, true);
        let tag = b"short-tag";
        let out =
            build_proxy_req_payload(7, client, our, data, Some(tag.as_ref()), flags);

        // Trailing user data must still be intact at the very end.
        assert_eq!(&out[out.len() - data.len()..], data);
        // The TL_PROXY_TAG marker must appear somewhere in the extra block.
        let marker = TL_PROXY_TAG_U32.to_le_bytes();
        let has_marker = out.windows(4).any(|w| w == marker);
        assert!(has_marker, "expected TL_PROXY_TAG marker in extra block");
        // The tag bytes must appear in the output verbatim.
        let has_tag = out.windows(tag.len()).any(|w| w == tag);
        assert!(has_tag, "expected the tag bytes verbatim in the payload");
    }

    #[test]
    fn build_proxy_req_payload_length_grows_with_data() {
        let client: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let our: SocketAddr = "10.0.0.2:2".parse().unwrap();
        let flags = proto_flags_for_tag(ProtoTag::Abridged, false);
        let small = build_proxy_req_payload(0, client, our, b"x", None, flags).len();
        let large = build_proxy_req_payload(0, client, our, &[0u8; 1024], None, flags).len();
        assert_eq!(large - small, 1023);
    }

    // ============= Magic constant assertions =============

    #[test]
    fn rpc_proxy_req_magic_is_known_hex() {
        assert_eq!(RPC_PROXY_REQ_U32, 0x36cef1ee);
    }

    #[test]
    fn tl_proxy_tag_magic_is_known_hex() {
        assert_eq!(TL_PROXY_TAG_U32, 0xdb1e26ae);
    }

    #[test]
    fn rpc_flag_bit_positions() {
        assert_eq!(RPC_FLAG_MAGIC, 0x1000);
        assert_eq!(RPC_FLAG_EXTMODE2, 0x20000);
        assert_eq!(RPC_FLAG_HAS_AD_TAG, 0x8);
        assert_eq!(RPC_FLAG_ABRIDGED, 0x40000000);
        assert_eq!(RPC_FLAG_INTERMEDIATE, 0x20000000);
        assert_eq!(RPC_FLAG_PAD, 0x8000000);
    }

    // ============= append_mapped_addr_and_port =============

    #[test]
    fn append_mapped_addr_and_port_v6_native_layout() {
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let addr = SocketAddr::new(IpAddr::V6(v6), 443);
        let mut buf = Vec::new();
        append_mapped_addr_and_port(&mut buf, addr);
        // 16 bytes for the v6 address + 4 bytes for the port (LE u32).
        assert_eq!(buf.len(), 20);
        assert_eq!(&buf[0..16], &v6.octets());
        assert_eq!(&buf[16..20], &443u32.to_le_bytes());
    }

    #[test]
    fn append_mapped_addr_and_port_v4_port_encoding() {
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let mut buf = Vec::new();
        append_mapped_addr_and_port(&mut buf, addr);
        // Last 4 bytes are the port as LE u32.
        let port_bytes = &buf[16..20];
        assert_eq!(u32::from_le_bytes(port_bytes.try_into().unwrap()), 8080);
    }

    // ============= ipv4_to_mapped_v6_c_compat: zero-prefix =============

    #[test]
    fn ipv4_mapped_first_eight_bytes_are_zero() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let buf = ipv4_to_mapped_v6_c_compat(ip);
        assert_eq!(&buf[0..8], &[0u8; 8]);
    }

    // ============= build_proxy_req_payload: long ad-tag (≥254 bytes) =============

    #[test]
    fn build_proxy_req_payload_long_ad_tag_hits_fe_branch() {
        let client: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let our: SocketAddr = "10.0.0.2:2".parse().unwrap();
        let data = b"\xCC\xDD";
        let flags = proto_flags_for_tag(ProtoTag::Abridged, true);
        // 256-byte tag triggers the 0xfe long-length encoding path.
        let tag = vec![0xABu8; 256];
        let out = build_proxy_req_payload(42, client, our, data, Some(&tag), flags);
        // Trailing user data must be intact.
        assert_eq!(&out[out.len() - data.len()..], data);
        // TL_PROXY_TAG marker must appear.
        let marker = TL_PROXY_TAG_U32.to_le_bytes();
        let has_marker = out.windows(4).any(|w| w == marker);
        assert!(has_marker, "expected TL_PROXY_TAG marker in extra block");
        // Tag bytes must appear verbatim in the output.
        let has_tag = out.windows(tag.len()).any(|w| w == tag);
        assert!(has_tag, "expected 256-byte tag verbatim in payload");
    }

    // ============= build_proxy_req_payload: empty data =============

    #[test]
    fn build_proxy_req_payload_empty_data() {
        let client: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let our: SocketAddr = "10.0.0.2:2".parse().unwrap();
        let flags = proto_flags_for_tag(ProtoTag::Intermediate, false);
        let out = build_proxy_req_payload(99, client, our, b"", None, flags);
        // Header = 4 (marker) + 4 (flags) + 8 (conn_id) + 20 (client) + 20 (our) = 56.
        assert_eq!(out.len(), 56);
    }

    // ============= build_proxy_req_payload: extra block length field =============

    #[test]
    fn build_proxy_req_payload_extra_block_length_is_correct() {
        let client: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let our: SocketAddr = "10.0.0.2:2".parse().unwrap();
        let data = b"payload";
        let flags = proto_flags_for_tag(ProtoTag::Abridged, true);
        let tag = b"adtag123";
        let out = build_proxy_req_payload(1, client, our, data, Some(tag.as_ref()), flags);

        // Extra block starts right after the two mapped addresses (offset 56).
        // Layout: [4 bytes extra_len][4 bytes TL_PROXY_TAG][1 byte tag_len][tag][padding]
        let extra_len = u32::from_le_bytes(out[56..60].try_into().unwrap()) as usize;
        let header_size = 56 + 4;
        let extra_end = header_size + extra_len;
        // Data starts after the extra block.
        assert_eq!(&out[extra_end..], data);
    }

    // ============= build_proxy_req_payload: ad-tag flag not set, tag ignored =============

    #[test]
    fn build_proxy_req_payload_tag_ignored_without_ad_flag() {
        let client: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let our: SocketAddr = "10.0.0.2:2".parse().unwrap();
        let data = b"data";
        // Force flags without AD_TAG, but pass Some(tag) — tag must be ignored.
        let flags = proto_flags_for_tag(ProtoTag::Intermediate, false);
        assert_eq!(flags & RPC_FLAG_HAS_AD_TAG, 0);
        let out_with = build_proxy_req_payload(1, client, our, data, Some(b"tag"), flags);
        let out_without = build_proxy_req_payload(1, client, our, data, None, flags);
        assert_eq!(out_with.len(), out_without.len());
        assert_eq!(out_with, out_without);
    }

    // ============= ProtoTag repr assertions =============

    #[test]
    fn proto_tag_discriminant_values() {
        assert_eq!(ProtoTag::Abridged as u32, 0xefefefef);
        assert_eq!(ProtoTag::Intermediate as u32, 0xeeeeeeee);
        assert_eq!(ProtoTag::Secure as u32, 0xdddddddd);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn extract_ip_material_v4_roundtrip(
            a in any::<u8>(),
            b in any::<u8>(),
            c in any::<u8>(),
            d in any::<u8>(),
            port in 1u16..65535u16
        ) {
            let ip = Ipv4Addr::new(a, b, c, d);
            let addr = SocketAddr::new(IpAddr::V4(ip), port);
            match extract_ip_material(addr) {
                IpMaterial::V4(octets) => prop_assert_eq!(octets, [a, b, c, d]),
                IpMaterial::V6(_) => panic!("V4 addr must extract as V4"),
            }
        }

        #[test]
        fn ipv4_mapped_v6_c_compat_preserves_octets(
            a in any::<u8>(),
            b in any::<u8>(),
            c in any::<u8>(),
            d in any::<u8>()
        ) {
            let ip = Ipv4Addr::new(a, b, c, d);
            let mapped = ipv4_to_mapped_v6_c_compat(ip);
            // The last 4 bytes must be the original IPv4 octets.
            prop_assert_eq!(&mapped[12..16], &[a, b, c, d]);
            // First 8 bytes must be zero.
            prop_assert_eq!(&mapped[0..8], &[0u8; 8]);
            // Bytes 10..12 must be 0xff 0xff.
            prop_assert_eq!(&mapped[10..12], &[0xff, 0xff]);
        }

        #[test]
        fn proto_flags_for_tag_magic_and_extmode2_always_set(
            tag in proptest::sample::select(vec![
                ProtoTag::Abridged,
                ProtoTag::Intermediate,
                ProtoTag::Secure,
            ]),
            has_ad_tag in any::<bool>()
        ) {
            let flags = proto_flags_for_tag(tag, has_ad_tag);
            prop_assert!(flags & RPC_FLAG_MAGIC != 0, "MAGIC must be set");
            prop_assert!(flags & RPC_FLAG_EXTMODE2 != 0, "EXTMODE2 must be set");
        }

        #[test]
        fn build_proxy_req_payload_preserves_trailing_data(
            data in proptest::collection::vec(any::<u8>(), 0..256)
        ) {
            let client: SocketAddr = "10.0.0.1:1234".parse().unwrap();
            let our: SocketAddr = "10.0.0.2:5678".parse().unwrap();
            let flags = proto_flags_for_tag(ProtoTag::Intermediate, false);
            let out = build_proxy_req_payload(42, client, our, &data, None, flags);
            prop_assert_eq!(&out[out.len() - data.len()..], &data[..]);
        }
    }
}
