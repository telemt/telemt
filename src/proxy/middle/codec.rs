//! RPC message encoding / decoding for Middle Proxy protocol
//!
//! Covers:
//! - Nonce exchange messages (RPC_NONCE)
//! - Handshake messages (RPC_HANDSHAKE)
//! - Proxy request / response (RPC_PROXY_REQ / RPC_PROXY_ANS)
//! - MTProto full-frame helpers (CRC32 frames with padding)
//! - IP/port encoding helpers for KDF and RPC

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use crate::crypto::crc32;
use crate::protocol::constants::*;

// ============= Constants =============

/// Crypto scheme: AES
pub const CRYPTO_AES: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// RPC flags (all zeros in handshake phase)
pub const RPC_FLAGS_ZERO: [u8; 4] = [0x00; 4];

/// Sender / Peer PID used in the handshake
pub const SENDER_PID: &[u8; 12] = b"IPIPPRPDTIME";
pub const PEER_PID: &[u8; 12] = b"IPIPPRPDTIME";

/// Size of the "extra" block in RPC_PROXY_REQ (always 24 when ad_tag is 16 bytes)
pub const EXTRA_SIZE: u32 = 0x18; // 24

/// PROXY_TAG marker inside the extra block
pub const PROXY_TAG: [u8; 4] = [0xae, 0x26, 0x1e, 0xdb];

/// 3-byte zero aligner after ad_tag
pub const FOUR_BYTES_ALIGNER: [u8; 3] = [0x00; 3];

/// Length of the nonce
pub const NONCE_LEN: usize = 16;

/// Expected lengths
pub const RPC_NONCE_ANS_LEN: usize = 32;
pub const RPC_HANDSHAKE_ANS_LEN: usize = 32;

/// MTProto frame padding (aligns total to CBC block size = 16)
pub const FRAME_CBC_ALIGN: usize = 16;
pub const FRAME_PADDING_FILLER: [u8; 4] = PADDING_FILLER;

// ============= Nonce Messages =============

/// Build the RPC_NONCE request message (32 bytes).
///
/// Layout: `RPC_NONCE(4) + key_selector(4) + CRYPTO_AES(4) + crypto_ts(4) + nonce(16)`
pub fn build_nonce_request(key_selector: &[u8; 4], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let crypto_ts = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32)
        .to_le_bytes();

    let mut msg = Vec::with_capacity(32);
    msg.extend_from_slice(&RPC_NONCE);
    msg.extend_from_slice(key_selector);
    msg.extend_from_slice(&CRYPTO_AES);
    msg.extend_from_slice(&crypto_ts);
    msg.extend_from_slice(nonce);
    msg
}

/// Parsed RPC_NONCE response.
#[derive(Debug)]
pub struct NonceResponse {
    pub rpc_type: [u8; 4],
    pub key_selector: [u8; 4],
    pub schema: [u8; 4],
    pub crypto_ts: [u8; 4],
    pub server_nonce: [u8; NONCE_LEN],
}

impl NonceResponse {
    /// Parse from exactly 32 bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != RPC_NONCE_ANS_LEN {
            return None;
        }
        Some(Self {
            rpc_type: data[0..4].try_into().unwrap(),
            key_selector: data[4..8].try_into().unwrap(),
            schema: data[8..12].try_into().unwrap(),
            crypto_ts: data[12..16].try_into().unwrap(),
            server_nonce: data[16..32].try_into().unwrap(),
        })
    }

    /// Validate that the response matches our request parameters.
    pub fn validate(&self, expected_key_selector: &[u8; 4]) -> bool {
        self.rpc_type == RPC_NONCE
            && self.key_selector == *expected_key_selector
            && self.schema == CRYPTO_AES
    }
}

// ============= Handshake Messages =============

/// Build the RPC_HANDSHAKE request (32 bytes).
///
/// Layout: `RPC_HANDSHAKE(4) + flags(4) + SENDER_PID(12) + PEER_PID(12)`
pub fn build_handshake_request() -> Vec<u8> {
    let mut msg = Vec::with_capacity(32);
    msg.extend_from_slice(&RPC_HANDSHAKE);
    msg.extend_from_slice(&RPC_FLAGS_ZERO);
    msg.extend_from_slice(SENDER_PID);
    msg.extend_from_slice(PEER_PID);
    msg
}

/// Validate handshake answer (32 bytes).
///
/// Returns `true` if the answer is a valid RPC_HANDSHAKE with
/// `peer_pid == SENDER_PID`.
pub fn validate_handshake_response(data: &[u8]) -> bool {
    if data.len() != RPC_HANDSHAKE_ANS_LEN {
        return false;
    }
    let rpc_type = &data[0..4];
    let _flags = &data[4..8];
    let _sender = &data[8..20];
    let peer = &data[20..32];
    rpc_type == RPC_HANDSHAKE && peer == SENDER_PID
}

// ============= RPC_PROXY_REQ =============

/// Build an RPC_PROXY_REQ message wrapping `payload`.
///
/// The full layout (84 + payload bytes):
/// ```text
/// RPC_PROXY_REQ(4) + flags(4) + out_conn_id(8)
/// + remote_ip_port(20) + our_ip_port(20)
/// + EXTRA_SIZE(4) + PROXY_TAG(4)
/// + ad_tag_len(1) + ad_tag(16) + aligner(3)
/// + payload
/// ```
pub fn build_proxy_req(
    out_conn_id: &[u8; 8],
    remote_ip_port: &[u8; 20],
    our_ip_port: &[u8; 20],
    proto_tag: ProtoTag,
    ad_tag: &[u8; 16],
    payload: &[u8],
    quickack: bool,
) -> Vec<u8> {
    let mut flags: u32 = rpc_flags::FLAG_HAS_AD_TAG
        | rpc_flags::FLAG_MAGIC
        | rpc_flags::FLAG_EXTMODE2;

    match proto_tag {
        ProtoTag::Abridged => flags |= rpc_flags::FLAG_ABRIDGED,
        ProtoTag::Intermediate => flags |= rpc_flags::FLAG_INTERMEDIATE,
        ProtoTag::Secure => flags |= rpc_flags::FLAG_INTERMEDIATE | rpc_flags::FLAG_PAD,
    }

    if quickack {
        flags |= rpc_flags::FLAG_QUICKACK;
    }

    // Check if unencrypted (starts with 8 zero bytes)
    if payload.len() >= 8 && payload[..8].iter().all(|&b| b == 0) {
        flags |= rpc_flags::FLAG_NOT_ENCRYPTED;
    }

    let header_len = 4 + 4 + 8 + 20 + 20 + 4 + 4 + 1 + 16 + 3; // = 84
    let mut msg = Vec::with_capacity(header_len + payload.len());

    msg.extend_from_slice(&RPC_PROXY_REQ);
    msg.extend_from_slice(&flags.to_le_bytes());
    msg.extend_from_slice(out_conn_id);
    msg.extend_from_slice(remote_ip_port);
    msg.extend_from_slice(our_ip_port);
    msg.extend_from_slice(&EXTRA_SIZE.to_le_bytes());
    msg.extend_from_slice(&PROXY_TAG);
    msg.push(ad_tag.len() as u8); // always 16
    msg.extend_from_slice(ad_tag);
    msg.extend_from_slice(&FOUR_BYTES_ALIGNER);
    msg.extend_from_slice(payload);

    msg
}

// ============= RPC Response Parsing =============

/// Parsed RPC response from the middle proxy.
#[derive(Debug)]
pub enum RpcResponse {
    /// Data from Telegram DC to forward to the client.
    ProxyAns {
        flags: u32,
        conn_id: [u8; 8],
        data: Vec<u8>,
    },
    /// Acknowledgment (4 bytes to forward as-is with SIMPLE_ACK flag).
    SimpleAck {
        conn_id: [u8; 8],
        confirm: [u8; 4],
    },
    /// Connection closed by middle proxy.
    Close,
    /// Unknown RPC type — skip, do not forward.
    Unknown(u32),
}

impl RpcResponse {
    /// Parse from a raw MTProto frame payload.
    pub fn parse(data: &[u8]) -> std::io::Result<Self> {
        if data.len() < 4 {
            return Ok(Self::Close);
        }

        let rpc_type: [u8; 4] = data[0..4].try_into().unwrap();

        if rpc_type == RPC_CLOSE_EXT {
            return Ok(Self::Close);
        }

        if rpc_type == RPC_PROXY_ANS {
            if data.len() < 16 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("RPC_PROXY_ANS too short: {} bytes", data.len()),
                ));
            }
            let flags = u32::from_le_bytes(data[4..8].try_into().unwrap());
            let conn_id: [u8; 8] = data[8..16].try_into().unwrap();
            let payload = data[16..].to_vec();
            return Ok(Self::ProxyAns {
                flags,
                conn_id,
                data: payload,
            });
        }

        if rpc_type == RPC_SIMPLE_ACK {
            if data.len() < 16 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("RPC_SIMPLE_ACK too short: {} bytes", data.len()),
                ));
            }
            let conn_id: [u8; 8] = data[4..12].try_into().unwrap();
            let confirm: [u8; 4] = data[12..16].try_into().unwrap();
            return Ok(Self::SimpleAck { conn_id, confirm });
        }

        if rpc_type == RPC_UNKNOWN {
            return Ok(Self::Unknown(u32::from_le_bytes(rpc_type)));
        }

        Ok(Self::Unknown(u32::from_le_bytes(rpc_type)))
    }
}

// ============= MTProto Full Frame Helpers =============

/// Build an MTProto full frame with CRC32 and padding.
///
/// Frame layout:
/// ```text
/// [len: 4 LE] [seq_no: 4 LE signed] [data...] [CRC32: 4 LE] [padding...]
/// ```
/// - `len` = 4 + 4 + data.len() + 4 = data.len() + 12
/// - padding aligns total output to 16 bytes using `PADDING_FILLER`
pub fn build_mtproto_frame(data: &[u8], seq_no: i32) -> Vec<u8> {
    let msg_len = (data.len() + 12) as u32;
    let len_bytes = msg_len.to_le_bytes();
    let seq_bytes = seq_no.to_le_bytes();

    // CRC covers len + seq + data
    let mut crc_input = Vec::with_capacity(8 + data.len());
    crc_input.extend_from_slice(&len_bytes);
    crc_input.extend_from_slice(&seq_bytes);
    crc_input.extend_from_slice(data);
    let checksum = crc32(&crc_input).to_le_bytes();

    let unpadded_len = len_bytes.len() + seq_bytes.len() + data.len() + checksum.len();
    let padding_needed = (FRAME_CBC_ALIGN - (unpadded_len % FRAME_CBC_ALIGN)) % FRAME_CBC_ALIGN;
    let padding_count = padding_needed / FRAME_PADDING_FILLER.len();

    let total = unpadded_len + padding_count * FRAME_PADDING_FILLER.len();
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&len_bytes);
    frame.extend_from_slice(&seq_bytes);
    frame.extend_from_slice(data);
    frame.extend_from_slice(&checksum);
    for _ in 0..padding_count {
        frame.extend_from_slice(&FRAME_PADDING_FILLER);
    }

    frame
}

// ============= IP / Port Encoding =============

/// Encode an IP:port pair for the KDF function.
///
/// **IPv4**: 4 bytes in **reversed** byte order (LE octets).
/// **IPv6**: 16 bytes in native order.
/// Port: 2 bytes little-endian.
pub fn encode_ip_for_kdf(addr: SocketAddr) -> (Option<Vec<u8>>, Option<[u8; 16]>, [u8; 2]) {
    let port_le = addr.port().to_le_bytes();
    match addr.ip() {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Reversed byte order as per Python: inet_pton(...)[::-1]
            let reversed = vec![octets[3], octets[2], octets[1], octets[0]];
            (Some(reversed), None, port_le)
        }
        IpAddr::V6(v6) => {
            (None, Some(v6.octets()), port_le)
        }
    }
}

/// Encode a client / proxy IP:port for the RPC_PROXY_REQ message.
///
/// Format: 16 bytes IP (IPv4-mapped if v4) + 4 bytes port LE.
/// Total: 20 bytes.
///
/// **Note**: IP is NOT reversed here (unlike KDF).
pub fn encode_ip_port_for_rpc(addr: SocketAddr) -> [u8; 20] {
    let mut result = [0u8; 20];
    match addr.ip() {
        IpAddr::V4(v4) => {
            // IPv4-mapped IPv6: ::ffff:x.x.x.x
            result[10] = 0xff;
            result[11] = 0xff;
            result[12..16].copy_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            result[0..16].copy_from_slice(&v6.octets());
        }
    }
    result[16..20].copy_from_slice(&(addr.port() as u32).to_le_bytes());
    result
}

// ============= Tests =============

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_nonce_request() {
        let key_sel = [0xc4, 0xf9, 0xfa, 0xca];
        let nonce = [0x42u8; 16];
        let msg = build_nonce_request(&key_sel, &nonce);
        assert_eq!(msg.len(), 32);
        assert_eq!(&msg[0..4], &RPC_NONCE);
        assert_eq!(&msg[4..8], &key_sel);
        assert_eq!(&msg[8..12], &CRYPTO_AES);
        assert_eq!(&msg[16..32], &nonce);
    }

    #[test]
    fn test_nonce_response_parse() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&RPC_NONCE);
        data[4..8].copy_from_slice(&[0xc4, 0xf9, 0xfa, 0xca]);
        data[8..12].copy_from_slice(&CRYPTO_AES);
        let resp = NonceResponse::parse(&data).unwrap();
        assert!(resp.validate(&[0xc4, 0xf9, 0xfa, 0xca]));
    }

    #[test]
    fn test_build_handshake_request() {
        let msg = build_handshake_request();
        assert_eq!(msg.len(), 32);
        assert_eq!(&msg[0..4], &RPC_HANDSHAKE);
    }

    #[test]
    fn test_validate_handshake_response() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&RPC_HANDSHAKE);
        data[20..32].copy_from_slice(SENDER_PID);
        assert!(validate_handshake_response(&data));
    }

    #[test]
    fn test_build_proxy_req() {
        let conn_id = [0x11u8; 8];
        let remote = [0x22u8; 20];
        let our = [0x33u8; 20];
        let ad_tag = [0x44u8; 16];
        let payload = b"hello";
        let msg = build_proxy_req(&conn_id, &remote, &our, ProtoTag::Secure, &ad_tag, payload, false);
        // Header: 84 bytes + payload 5 = 89
        assert_eq!(msg.len(), 89);
        assert_eq!(&msg[0..4], &RPC_PROXY_REQ);
    }

    #[test]
    fn test_rpc_response_parse_proxy_ans() {
        let mut data = vec![0u8; 20];
        data[0..4].copy_from_slice(&RPC_PROXY_ANS);
        data[16..20].copy_from_slice(b"test");
        let resp = RpcResponse::parse(&data).unwrap();
        match resp {
            RpcResponse::ProxyAns { data: d, .. } => assert_eq!(&d, b"test"),
            _ => panic!("Expected ProxyAns"),
        }
    }

    #[test]
    fn test_rpc_response_parse_close() {
        let mut data = vec![0u8; 4];
        data[0..4].copy_from_slice(&RPC_CLOSE_EXT);
        let resp = RpcResponse::parse(&data).unwrap();
        assert!(matches!(resp, RpcResponse::Close));
    }

    #[test]
    fn test_rpc_response_parse_simple_ack() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&RPC_SIMPLE_ACK);
        data[12..16].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let resp = RpcResponse::parse(&data).unwrap();
        match resp {
            RpcResponse::SimpleAck { confirm, .. } => {
                assert_eq!(confirm, [0xAA, 0xBB, 0xCC, 0xDD]);
            }
            _ => panic!("Expected SimpleAck"),
        }
    }

    #[test]
    fn test_build_mtproto_frame() {
        let data = [0xAA; 20]; // 20 bytes of data
        let frame = build_mtproto_frame(&data, -2);
        // len = 20 + 12 = 32; frame = 4+4+20+4 = 32; 32 % 16 = 0, no padding
        assert_eq!(frame.len(), 32);
        let msg_len = u32::from_le_bytes(frame[0..4].try_into().unwrap());
        assert_eq!(msg_len, 32);
        let seq = i32::from_le_bytes(frame[4..8].try_into().unwrap());
        assert_eq!(seq, -2);
    }

    #[test]
    fn test_build_mtproto_frame_with_padding() {
        // 32 bytes data → len = 44 → frame = 44 bytes → 44 % 16 = 12 → need 4 bytes padding
        let data = [0xBB; 32];
        let frame = build_mtproto_frame(&data, 0);
        assert_eq!(frame.len(), 48); // 44 + 4 padding
        let msg_len = u32::from_le_bytes(frame[0..4].try_into().unwrap());
        assert_eq!(msg_len, 44);
        // Verify padding is PADDING_FILLER
        assert_eq!(&frame[44..48], &FRAME_PADDING_FILLER);
    }

    #[test]
    fn test_encode_ipv4_for_kdf() {
        let addr: SocketAddr = "149.154.175.50:8888".parse().unwrap();
        let (v4_bytes, v6_bytes, port) = encode_ip_for_kdf(addr);
        // Reversed: [50, 175, 154, 149]
        assert_eq!(v4_bytes.unwrap(), vec![50, 175, 154, 149]);
        assert!(v6_bytes.is_none());
        assert_eq!(port, 8888u16.to_le_bytes());
    }

    #[test]
    fn test_encode_ipv6_for_kdf() {
        let addr: SocketAddr = "[2001:b28:f23d:f001::d]:8888".parse().unwrap();
        let (v4_bytes, v6_bytes, _port) = encode_ip_for_kdf(addr);
        assert!(v4_bytes.is_none());
        assert!(v6_bytes.is_some());
        assert_eq!(v6_bytes.unwrap().len(), 16);
    }

    #[test]
    fn test_encode_ip_port_for_rpc_v4() {
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let encoded = encode_ip_port_for_rpc(addr);
        assert_eq!(encoded.len(), 20);
        // First 10 bytes zero
        assert_eq!(&encoded[0..10], &[0u8; 10]);
        // ff ff
        assert_eq!(&encoded[10..12], &[0xff, 0xff]);
        // IP bytes (NOT reversed)
        assert_eq!(&encoded[12..16], &[192, 168, 1, 1]);
        // Port as u32 LE
        assert_eq!(u32::from_le_bytes(encoded[16..20].try_into().unwrap()), 12345);
    }

    #[test]
    fn test_encode_ip_port_for_rpc_v6() {
        let addr: SocketAddr = "[::1]:443".parse().unwrap();
        let encoded = encode_ip_port_for_rpc(addr);
        assert_eq!(encoded[15], 1); // ::1
        assert_eq!(u32::from_le_bytes(encoded[16..20].try_into().unwrap()), 443);
    }
}