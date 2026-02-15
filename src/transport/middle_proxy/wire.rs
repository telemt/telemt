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
) -> Vec<u8> {
    let mut b = Vec::with_capacity(128 + data.len());

    b.extend_from_slice(&RPC_PROXY_REQ_U32.to_le_bytes());
    b.extend_from_slice(&proto_flags.to_le_bytes());
    b.extend_from_slice(&conn_id.to_le_bytes());

    append_mapped_addr_and_port(&mut b, client_addr);
    append_mapped_addr_and_port(&mut b, our_addr);

    if proto_flags & 12 != 0 {
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
    b
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

    #[test]
    fn test_ipv4_mapped_encoding() {
        let ip = Ipv4Addr::new(149, 154, 175, 50);
        let buf = ipv4_to_mapped_v6_c_compat(ip);
        assert_eq!(&buf[0..10], &[0u8; 10]);
        assert_eq!(&buf[10..12], &[0xff, 0xff]);
        assert_eq!(&buf[12..16], &[149, 154, 175, 50]);
    }
}
