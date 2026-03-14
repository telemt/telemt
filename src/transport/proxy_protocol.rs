//! `HAProxy` PROXY protocol V1/V2

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt};
use crate::error::{ProxyError, Result};

/// PROXY protocol v1 signature
const PROXY_V1_SIGNATURE: &[u8] = b"PROXY ";

/// PROXY protocol v2 signature
const PROXY_V2_SIGNATURE: &[u8] = &[
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 
    0x51, 0x55, 0x49, 0x54, 0x0a
];

/// Minimum length for v1 detection
const PROXY_V1_MIN_LEN: usize = 6;

/// Minimum length for v2 header
const PROXY_V2_MIN_LEN: usize = 16;

/// Maximum address data length for V2 (AF_UNIX holds the largest union at 216 bytes per spec).
/// Rejecting an oversized addr_len before allocation prevents a 65 535-byte heap spike
/// per connection when proxy_protocol_enabled is true.
const PROXY_V2_MAX_ADDR_LEN: usize = 216;

/// Address families for v2
mod address_family {
    pub const UNSPEC: u8 = 0x0;
    pub const INET: u8 = 0x1;
    pub const INET6: u8 = 0x2;
}

/// Information extracted from PROXY protocol header
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ProxyProtocolInfo {
    /// Source (client) address
    pub src_addr: SocketAddr,
    /// Destination address (optional)
    pub dst_addr: Option<SocketAddr>,
    /// Protocol version used (1 or 2)
    pub version: u8,
}

#[allow(dead_code)]
impl ProxyProtocolInfo {
    /// Create info with just source address
    pub const fn new(src_addr: SocketAddr) -> Self {
        Self {
            src_addr,
            dst_addr: None,
            version: 0,
        }
    }
}

/// Parse PROXY protocol header from a stream
/// 
/// Returns the parsed info or an error if the header is invalid.
/// The stream position is advanced past the header.
pub async fn parse_proxy_protocol<R: AsyncRead + Unpin>(
    reader: &mut R,
    default_peer: SocketAddr,
) -> Result<ProxyProtocolInfo> {
    // Read enough bytes to detect version
    let mut header = [0u8; PROXY_V2_MIN_LEN];
    reader.read_exact(&mut header[..PROXY_V1_MIN_LEN]).await
        .map_err(|_| ProxyError::InvalidProxyProtocol)?;
    
    // Check for v1
    if header[..PROXY_V1_MIN_LEN] == PROXY_V1_SIGNATURE[..] {
        return parse_v1(reader, default_peer).await;
    }
    
    // Read rest for v2 detection
    reader.read_exact(&mut header[PROXY_V1_MIN_LEN..]).await
        .map_err(|_| ProxyError::InvalidProxyProtocol)?;
    
    // Check for v2
    if header[..12] == PROXY_V2_SIGNATURE[..] {
        return parse_v2(reader, &header, default_peer).await;
    }
    
    Err(ProxyError::InvalidProxyProtocol)
}

/// Parse PROXY protocol v1
async fn parse_v1<R: AsyncRead + Unpin>(
    reader: &mut R,
    default_peer: SocketAddr,
) -> Result<ProxyProtocolInfo> {
    // Read until CRLF (max 107 bytes total for v1)
    let mut line = Vec::with_capacity(128);
    line.extend_from_slice(PROXY_V1_SIGNATURE);
    
    loop {
        let mut byte = [0u8];
        reader.read_exact(&mut byte).await
            .map_err(|_| ProxyError::InvalidProxyProtocol)?;
        line.push(byte[0]);

        // PROXY protocol v1 defines a strict maximum line length of 108 bytes.
        // Length is checked before CRLF detection: without this ordering a 109-byte
        // line whose CRLF falls at bytes 108–109 would pass the break before the
        // length guard runs, silently exceeding the spec limit.
        if line.len() > 108 {
            return Err(ProxyError::InvalidProxyProtocol);
        }

        if line.ends_with(b"\r\n") {
            break;
        }
    }
    
    // Parse the line: PROXY TCP4/TCP6/UNKNOWN src_ip dst_ip src_port dst_port
    let line_str = std::str::from_utf8(&line[PROXY_V1_MIN_LEN..line.len() - 2])
        .map_err(|_| ProxyError::InvalidProxyProtocol)?;
    
    let parts: Vec<&str> = line_str.split_whitespace().collect();
    
    if parts.is_empty() {
        return Err(ProxyError::InvalidProxyProtocol);
    }
    
    match parts[0] {
        "TCP4" if parts.len() >= 5 => {
            let src_ip: IpAddr = parts[1].parse()
                .map_err(|_| ProxyError::InvalidProxyProtocol)?;
            let dst_ip: IpAddr = parts[2].parse()
                .map_err(|_| ProxyError::InvalidProxyProtocol)?;
            // TCP4 requires both addresses to be IPv4; IPv4-mapped IPv6 (::ffff:x.x.x.x)
            // parses as IpAddr::V6 so it is correctly rejected here.
            if !src_ip.is_ipv4() || !dst_ip.is_ipv4() {
                return Err(ProxyError::InvalidProxyProtocol);
            }
            let src_port: u16 = parts[3].parse()
                .map_err(|_| ProxyError::InvalidProxyProtocol)?;
            let dst_port: u16 = parts[4].parse()
                .map_err(|_| ProxyError::InvalidProxyProtocol)?;

            Ok(ProxyProtocolInfo {
                src_addr: SocketAddr::new(src_ip, src_port),
                dst_addr: Some(SocketAddr::new(dst_ip, dst_port)),
                version: 1,
            })
        }
        "TCP6" if parts.len() >= 5 => {
            let src_ip: IpAddr = parts[1].parse()
                .map_err(|_| ProxyError::InvalidProxyProtocol)?;
            let dst_ip: IpAddr = parts[2].parse()
                .map_err(|_| ProxyError::InvalidProxyProtocol)?;
            if !src_ip.is_ipv6() || !dst_ip.is_ipv6() {
                return Err(ProxyError::InvalidProxyProtocol);
            }
            let src_port: u16 = parts[3].parse()
                .map_err(|_| ProxyError::InvalidProxyProtocol)?;
            let dst_port: u16 = parts[4].parse()
                .map_err(|_| ProxyError::InvalidProxyProtocol)?;

            Ok(ProxyProtocolInfo {
                src_addr: SocketAddr::new(src_ip, src_port),
                dst_addr: Some(SocketAddr::new(dst_ip, dst_port)),
                version: 1,
            })
        }
        "UNKNOWN" => {
            // UNKNOWN means no address info, use default
            Ok(ProxyProtocolInfo {
                src_addr: default_peer,
                dst_addr: None,
                version: 1,
            })
        }
        _ => Err(ProxyError::InvalidProxyProtocol),
    }
}

/// Parse PROXY protocol v2
async fn parse_v2<R: AsyncRead + Unpin>(
    reader: &mut R,
    header: &[u8; PROXY_V2_MIN_LEN],
    default_peer: SocketAddr,
) -> Result<ProxyProtocolInfo> {
    let version_command = header[12];
    let version = version_command >> 4;
    let command = version_command & 0x0f;
    
    // Must be version 2
    if version != 2 {
        return Err(ProxyError::InvalidProxyProtocol);
    }
    
    let family_protocol = header[13];
    let addr_len = u16::from_be_bytes([header[14], header[15]]) as usize;

    // Reject before allocating or reading: the spec maximum is 216 bytes (AF_UNIX union).
    // Without this guard an attacker can send addr_len=65535 with no body, forcing a
    // 64 KB heap allocation and a blocked read_exact per connection.
    if addr_len > PROXY_V2_MAX_ADDR_LEN {
        return Err(ProxyError::InvalidProxyProtocol);
    }

    // Read address data
    let mut addr_data = vec![0u8; addr_len];
    if addr_len > 0 {
        reader.read_exact(&mut addr_data).await
            .map_err(|_| ProxyError::InvalidProxyProtocol)?;
    }
    
    // LOCAL command (0x0) - use default peer
    if command == 0 {
        return Ok(ProxyProtocolInfo {
            src_addr: default_peer,
            dst_addr: None,
            version: 2,
        });
    }
    
    // PROXY command (0x1) - parse addresses
    if command != 1 {
        return Err(ProxyError::InvalidProxyProtocol);
    }
    
    let family = family_protocol >> 4;
    
    match family {
        address_family::INET if addr_len >= 12 => {
            // IPv4: 4 + 4 + 2 + 2 = 12 bytes
            let src_ip = Ipv4Addr::new(
                addr_data[0], addr_data[1], 
                addr_data[2], addr_data[3]
            );
            let dst_ip = Ipv4Addr::new(
                addr_data[4], addr_data[5],
                addr_data[6], addr_data[7]
            );
            let src_port = u16::from_be_bytes([addr_data[8], addr_data[9]]);
            let dst_port = u16::from_be_bytes([addr_data[10], addr_data[11]]);
            
            Ok(ProxyProtocolInfo {
                src_addr: SocketAddr::new(IpAddr::V4(src_ip), src_port),
                dst_addr: Some(SocketAddr::new(IpAddr::V4(dst_ip), dst_port)),
                version: 2,
            })
        }
        address_family::INET6 if addr_len >= 36 => {
            // IPv6: 16 + 16 + 2 + 2 = 36 bytes
            let mut src_octets = [0u8; 16];
            src_octets.copy_from_slice(&addr_data[0..16]);
            let src_ip = Ipv6Addr::from(src_octets);
            let mut dst_octets = [0u8; 16];
            dst_octets.copy_from_slice(&addr_data[16..32]);
            let dst_ip = Ipv6Addr::from(dst_octets);
            let src_port = u16::from_be_bytes([addr_data[32], addr_data[33]]);
            let dst_port = u16::from_be_bytes([addr_data[34], addr_data[35]]);
            
            Ok(ProxyProtocolInfo {
                src_addr: SocketAddr::new(IpAddr::V6(src_ip), src_port),
                dst_addr: Some(SocketAddr::new(IpAddr::V6(dst_ip), dst_port)),
                version: 2,
            })
        }
        address_family::UNSPEC => {
            Ok(ProxyProtocolInfo {
                src_addr: default_peer,
                dst_addr: None,
                version: 2,
            })
        }
        _ => Err(ProxyError::InvalidProxyProtocol),
    }
}

/// Builder for PROXY protocol v1 header
pub struct ProxyProtocolV1Builder {
    family: &'static str,
    src_addr: Option<SocketAddr>,
    dst_addr: Option<SocketAddr>,
}

impl ProxyProtocolV1Builder {
    pub const fn new() -> Self {
        Self {
            family: "UNKNOWN",
            src_addr: None,
            dst_addr: None,
        }
    }
    
    pub const fn tcp4(mut self, src: SocketAddr, dst: SocketAddr) -> Self {
        self.family = "TCP4";
        self.src_addr = Some(src);
        self.dst_addr = Some(dst);
        self
    }
    
    pub const fn tcp6(mut self, src: SocketAddr, dst: SocketAddr) -> Self {
        self.family = "TCP6";
        self.src_addr = Some(src);
        self.dst_addr = Some(dst);
        self
    }
    
    pub fn build(&self) -> Vec<u8> {
        match (self.src_addr, self.dst_addr) {
            (Some(src), Some(dst)) => {
                format!(
                    "PROXY {} {} {} {} {}\r\n",
                    self.family,
                    src.ip(),
                    dst.ip(),
                    src.port(),
                    dst.port()
                ).into_bytes()
            }
            _ => b"PROXY UNKNOWN\r\n".to_vec(),
        }
    }
}

impl Default for ProxyProtocolV1Builder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for PROXY protocol v2 header
pub struct ProxyProtocolV2Builder {
    src: Option<SocketAddr>,
    dst: Option<SocketAddr>,
}

impl Default for ProxyProtocolV2Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyProtocolV2Builder {
    pub const fn new() -> Self {
        Self { src: None, dst: None }
    }

    pub const fn with_addrs(mut self, src: SocketAddr, dst: SocketAddr) -> Self {
        self.src = Some(src);
        self.dst = Some(dst);
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(PROXY_V2_SIGNATURE);
        // version 2, PROXY command
        header.push(0x21);

        match (self.src, self.dst) {
            (Some(SocketAddr::V4(src)), Some(SocketAddr::V4(dst))) => {
                header.push(0x11); // INET + STREAM
                header.extend_from_slice(&(12u16).to_be_bytes());
                header.extend_from_slice(&src.ip().octets());
                header.extend_from_slice(&dst.ip().octets());
                header.extend_from_slice(&src.port().to_be_bytes());
                header.extend_from_slice(&dst.port().to_be_bytes());
            }
            (Some(SocketAddr::V6(src)), Some(SocketAddr::V6(dst))) => {
                header.push(0x21); // INET6 + STREAM
                header.extend_from_slice(&(36u16).to_be_bytes());
                header.extend_from_slice(&src.ip().octets());
                header.extend_from_slice(&dst.ip().octets());
                header.extend_from_slice(&src.port().to_be_bytes());
                header.extend_from_slice(&dst.port().to_be_bytes());
            }
            _ => {
                // LOCAL/UNSPEC: no address information
                header[12] = 0x20; // version 2, LOCAL command
                header.push(0x00);
                header.extend_from_slice(&0u16.to_be_bytes());
            }
        }

        header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn valid_v2_ipv4_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 16 + 12];
        packet[..12].copy_from_slice(PROXY_V2_SIGNATURE);
        packet[12] = 0x21; // version=2, PROXY command
        packet[13] = 0x11; // INET + STREAM
        packet[14] = 0x00;
        packet[15] = 0x0c; // 12 bytes
        // src=203.0.113.10:12345, dst=198.51.100.20:443
        packet[16..20].copy_from_slice(&[203, 0, 113, 10]);
        packet[20..24].copy_from_slice(&[198, 51, 100, 20]);
        packet[24..26].copy_from_slice(&12345u16.to_be_bytes());
        packet[26..28].copy_from_slice(&443u16.to_be_bytes());
        packet
    }
    
    #[tokio::test]
    async fn test_parse_v1_tcp4() {
        let header = b"PROXY TCP4 192.168.1.1 10.0.0.1 12345 443\r\n";
        let mut cursor = Cursor::new(&header[PROXY_V1_MIN_LEN..]);
        let default = "0.0.0.0:0".parse().unwrap();
        
        // Simulate that we've already read the signature
        let info = parse_v1(&mut cursor, default).await.unwrap();
        
        assert_eq!(info.version, 1);
        assert_eq!(info.src_addr.ip().to_string(), "192.168.1.1");
        assert_eq!(info.src_addr.port(), 12345);
        assert!(info.dst_addr.is_some());
    }
    
    #[tokio::test]
    async fn test_parse_v1_unknown() {
        let header = b"PROXY UNKNOWN\r\n";
        let mut cursor = Cursor::new(&header[PROXY_V1_MIN_LEN..]);
        let default: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        
        let info = parse_v1(&mut cursor, default).await.unwrap();
        
        assert_eq!(info.version, 1);
        assert_eq!(info.src_addr, default);
    }
    
    #[tokio::test]
    async fn test_parse_v2_tcp4() {
        // v2 header for TCP4
        let mut header = [0u8; 16];
        header[..12].copy_from_slice(PROXY_V2_SIGNATURE);
        header[12] = 0x21; // v2, PROXY command
        header[13] = 0x11; // AF_INET, STREAM
        header[14] = 0x00;
        header[15] = 0x0c; // 12 bytes of address data
        
        let addr_data = [
            192, 168, 1, 1,     // src IP
            10, 0, 0, 1,       // dst IP
            0x30, 0x39,        // src port (12345)
            0x01, 0xbb,        // dst port (443)
        ];
        
        let mut cursor = Cursor::new(addr_data.to_vec());
        let default = "0.0.0.0:0".parse().unwrap();
        
        let info = parse_v2(&mut cursor, &header, default).await.unwrap();
        
        assert_eq!(info.version, 2);
        assert_eq!(info.src_addr.ip().to_string(), "192.168.1.1");
        assert_eq!(info.src_addr.port(), 12345);
    }

    #[tokio::test]
    async fn test_parse_v2_tcp6() {
        let mut header = [0u8; 16];
        header[..12].copy_from_slice(PROXY_V2_SIGNATURE);
        header[12] = 0x21; // v2, PROXY command
        header[13] = 0x21; // AF_INET6, STREAM
        header[14] = 0x00;
        header[15] = 0x24; // 36 bytes of address data

        let src_ip = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let dst_ip = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 2,
        ];
        let mut addr_data = Vec::with_capacity(36);
        addr_data.extend_from_slice(&src_ip);
        addr_data.extend_from_slice(&dst_ip);
        addr_data.extend_from_slice(&12345u16.to_be_bytes());
        addr_data.extend_from_slice(&443u16.to_be_bytes());

        let mut cursor = Cursor::new(addr_data);
        let default = "0.0.0.0:0".parse().unwrap();

        let info = parse_v2(&mut cursor, &header, default).await.unwrap();

        assert_eq!(info.version, 2);
        assert_eq!(info.src_addr.port(), 12345);
        assert_eq!(info.dst_addr.map(|v| v.port()), Some(443));
        assert!(info.src_addr.is_ipv6());
    }
    
    #[tokio::test]
    async fn test_parse_v2_local() {
        let mut header = [0u8; 16];
        header[..12].copy_from_slice(PROXY_V2_SIGNATURE);
        header[12] = 0x20; // v2, LOCAL command
        header[13] = 0x00;
        header[14] = 0x00;
        header[15] = 0x00; // 0 bytes of address data
        
        let mut cursor = Cursor::new(Vec::new());
        let default: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        
        let info = parse_v2(&mut cursor, &header, default).await.unwrap();
        
        assert_eq!(info.version, 2);
        assert_eq!(info.src_addr, default);
    }
    
    #[test]
    fn test_v1_builder() {
        let src: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let dst: SocketAddr = "10.0.0.1:443".parse().unwrap();
        
        let header = ProxyProtocolV1Builder::new()
            .tcp4(src, dst)
            .build();
        
        let expected = b"PROXY TCP4 192.168.1.1 10.0.0.1 12345 443\r\n";
        assert_eq!(header, expected);
    }
    
    #[test]
    fn test_v1_builder_unknown() {
        let header = ProxyProtocolV1Builder::new().build();
        assert_eq!(header, b"PROXY UNKNOWN\r\n");
    }

    #[tokio::test]
    async fn test_parse_v2_rejects_invalid_version_nibble() {
        let mut header = [0u8; 16];
        header[..12].copy_from_slice(PROXY_V2_SIGNATURE);
        header[12] = 0x11; // version=1, command=PROXY
        header[13] = 0x11; // INET + STREAM
        header[14] = 0x00;
        header[15] = 0x0c;

        let mut cursor = Cursor::new(vec![0u8; 12]);
        let default: SocketAddr = "127.0.0.1:1".parse().unwrap_or(SocketAddr::from(([127, 0, 0, 1], 1)));
        let result = parse_v2(&mut cursor, &header, default).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_parse_v2_rejects_unknown_command() {
        let mut header = [0u8; 16];
        header[..12].copy_from_slice(PROXY_V2_SIGNATURE);
        header[12] = 0x22; // version=2, unsupported command=2
        header[13] = 0x11;
        header[14] = 0x00;
        header[15] = 0x0c;

        let mut cursor = Cursor::new(vec![0u8; 12]);
        let default = SocketAddr::from(([127, 0, 0, 1], 1));
        let result = parse_v2(&mut cursor, &header, default).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_parse_v2_rejects_inet_family_with_short_addr_len() {
        let mut header = [0u8; 16];
        header[..12].copy_from_slice(PROXY_V2_SIGNATURE);
        header[12] = 0x21;
        header[13] = 0x11; // INET + STREAM
        header[14] = 0x00;
        header[15] = 0x08; // shorter than required 12

        let mut cursor = Cursor::new(vec![0u8; 8]);
        let default = SocketAddr::from(([127, 0, 0, 1], 1));
        let result = parse_v2(&mut cursor, &header, default).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_parse_v2_rejects_inet6_family_with_short_addr_len() {
        let mut header = [0u8; 16];
        header[..12].copy_from_slice(PROXY_V2_SIGNATURE);
        header[12] = 0x21;
        header[13] = 0x21; // INET6 + STREAM
        header[14] = 0x00;
        header[15] = 0x20; // shorter than required 36

        let mut cursor = Cursor::new(vec![0u8; 32]);
        let default = SocketAddr::from(([127, 0, 0, 1], 1));
        let result = parse_v2(&mut cursor, &header, default).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_parse_v2_rejects_truncated_addr_payload() {
        let mut header = [0u8; 16];
        header[..12].copy_from_slice(PROXY_V2_SIGNATURE);
        header[12] = 0x21;
        header[13] = 0x11;
        header[14] = 0x00;
        header[15] = 0x0c;

        let mut cursor = Cursor::new(vec![0u8; 11]); // one byte short
        let default = SocketAddr::from(([127, 0, 0, 1], 1));
        let result = parse_v2(&mut cursor, &header, default).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_parse_proxy_protocol_rejects_malformed_v2_permutations() {
        let default = SocketAddr::from(([127, 0, 0, 1], 1));
        let base = valid_v2_ipv4_packet();

        let flips = [0usize, 3, 5, 8, 10, 12, 13, 14, 15, 16, 20, 24, 27];
        for (idx, bit_pos) in flips.iter().enumerate() {
            let mut mutated = base.clone();
            let byte_pos = bit_pos / 8;
            let bit_in_byte = bit_pos % 8;
            if let Some(byte) = mutated.get_mut(byte_pos) {
                *byte ^= 1u8 << bit_in_byte;
            }

            let mut cursor = Cursor::new(mutated);
            let result = parse_proxy_protocol(&mut cursor, default).await;
            if idx == 0 {
                // Signature-corrupt mutations must fail hard.
                assert!(result.is_err());
            } else {
                // Any accepted mutation must still be v2 and never panic or produce v1.
                if let Ok(info) = result {
                    assert_eq!(info.version, 2);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_parse_proxy_protocol_v2_table_driven_malformed_inputs() {
        let default = SocketAddr::from(([127, 0, 0, 1], 1));
        let base = valid_v2_ipv4_packet();

        let mut cases: Vec<Vec<u8>> = Vec::new();

        // Bad signature byte.
        let mut bad_sig = base.clone();
        bad_sig[0] ^= 0xff;
        cases.push(bad_sig);

        // Unsupported command.
        let mut bad_cmd = base.clone();
        bad_cmd[12] = 0x22;
        cases.push(bad_cmd);

        // Wrong version nibble.
        let mut bad_ver = base.clone();
        bad_ver[12] = 0x11;
        cases.push(bad_ver);

        // INET with too-short advertised length.
        let mut short_len = base.clone();
        short_len[15] = 0x08;
        short_len.truncate(16 + 8);
        cases.push(short_len);

        // Truncated payload despite 12-byte advertised length.
        let mut trunc = base.clone();
        trunc.truncate(16 + 11);
        cases.push(trunc);

        // Unknown family nibble.
        let mut bad_family = base.clone();
        bad_family[13] = 0x51;
        cases.push(bad_family);

        for malformed in cases {
            let mut cursor = Cursor::new(malformed);
            let result = parse_proxy_protocol(&mut cursor, default).await;
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn test_parse_proxy_protocol_v2_deterministic_bitflip_corpus() {
        let default = SocketAddr::from(([127, 0, 0, 1], 1));
        let base = valid_v2_ipv4_packet();

        for i in 0..base.len() {
            let mut mutated = base.clone();
            mutated[i] ^= 0b0101_1010;

            let mut cursor = Cursor::new(mutated);
            let result = parse_proxy_protocol(&mut cursor, default).await;

            if let Ok(info) = result {
                // Any accepted mutation must still decode as v2 and keep bounded ports.
                assert_eq!(info.version, 2);
                assert!(info.src_addr.is_ipv4() || info.src_addr.is_ipv6());
            }
        }
    }

    // ===== T-1: V2 addr_len cap regression tests =====

    #[tokio::test]
    async fn test_parse_v2_rejects_addr_len_65535_before_body_read() {
        // Attacker sends a 16-byte header with addr_len=65535 and no body.
        // Without the cap the parser would block on read_exact waiting for 64 KB.
        let default = SocketAddr::from(([127, 0, 0, 1], 1));
        let mut header = [0u8; 16];
        header[..12].copy_from_slice(PROXY_V2_SIGNATURE);
        header[12] = 0x21; // v2, PROXY command
        header[13] = 0x11; // INET + STREAM
        header[14] = 0xff;
        header[15] = 0xff; // addr_len = 65535

        // Cursor contains only the 16-byte header — no body follows.
        let mut cursor = Cursor::new(header.to_vec());
        let result = parse_v2(&mut cursor, &header, default).await;
        assert!(result.is_err(), "addr_len=65535 must be rejected without reading body");
    }

    #[tokio::test]
    async fn test_parse_v2_rejects_addr_len_just_over_maximum() {
        let default = SocketAddr::from(([127, 0, 0, 1], 1));
        let mut header = [0u8; 16];
        header[..12].copy_from_slice(PROXY_V2_SIGNATURE);
        header[12] = 0x21;
        header[13] = 0x11;
        let len: u16 = (PROXY_V2_MAX_ADDR_LEN + 1) as u16;
        header[14..16].copy_from_slice(&len.to_be_bytes());

        let mut cursor = Cursor::new(vec![0u8; PROXY_V2_MAX_ADDR_LEN + 1]);
        let result = parse_v2(&mut cursor, &header, default).await;
        assert!(result.is_err(), "addr_len={} must be rejected", PROXY_V2_MAX_ADDR_LEN + 1);
    }

    #[tokio::test]
    async fn test_parse_v2_inet6_addr_len_65535_rejected() {
        let default = SocketAddr::from(([127, 0, 0, 1], 1));
        let mut header = [0u8; 16];
        header[..12].copy_from_slice(PROXY_V2_SIGNATURE);
        header[12] = 0x21;
        header[13] = 0x21; // INET6 + STREAM
        header[14] = 0xff;
        header[15] = 0xff; // 65535
        // No body — verify rejection before any read attempt.
        let mut cursor = Cursor::new(Vec::new());
        let result = parse_v2(&mut cursor, &header, default).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_parse_v2_addr_len_at_exact_max_does_not_panic() {
        // addr_len == PROXY_V2_MAX_ADDR_LEN must not be rejected for length alone.
        // Using AF_UNSPEC so address parsing is a no-op; we only verify no length panic.
        let default = SocketAddr::from(([127, 0, 0, 1], 1));
        let mut header = [0u8; 16];
        header[..12].copy_from_slice(PROXY_V2_SIGNATURE);
        header[12] = 0x21;
        header[13] = 0x00; // AF_UNSPEC
        let len: u16 = PROXY_V2_MAX_ADDR_LEN as u16;
        header[14..16].copy_from_slice(&len.to_be_bytes());

        let mut cursor = Cursor::new(vec![0u8; PROXY_V2_MAX_ADDR_LEN]);
        // Result may be Ok or Err for semantic reasons; it must not panic or hang.
        let _ = parse_v2(&mut cursor, &header, default).await;
    }

    #[tokio::test]
    async fn test_parse_proxy_protocol_v2_oversized_addr_len_no_body_hang() {
        // End-to-end variant: parse_proxy_protocol must reject the full 16-byte envelope
        // when addr_len=65535 and no body is present.
        let default = SocketAddr::from(([127, 0, 0, 1], 1));
        let mut packet = Vec::with_capacity(16);
        packet.extend_from_slice(PROXY_V2_SIGNATURE);
        packet.push(0x21);
        packet.push(0x11);
        packet.push(0xff);
        packet.push(0xff); // addr_len = 65535

        let mut cursor = Cursor::new(packet);
        let result = parse_proxy_protocol(&mut cursor, default).await;
        assert!(result.is_err());
    }

    // ===== T-2: V1 TCP4/TCP6 address-family validation tests =====

    #[tokio::test]
    async fn test_parse_v1_tcp4_with_ipv6_src_rejected() {
        let addr_line = b"TCP4 2001:db8::1 10.0.0.2 12345 443\r\n";
        let mut cursor = Cursor::new(addr_line.to_vec());
        let default = "0.0.0.0:0".parse().unwrap();
        assert!(parse_v1(&mut cursor, default).await.is_err());
    }

    #[tokio::test]
    async fn test_parse_v1_tcp4_with_ipv6_dst_rejected() {
        let addr_line = b"TCP4 192.168.1.1 2001:db8::2 12345 443\r\n";
        let mut cursor = Cursor::new(addr_line.to_vec());
        let default = "0.0.0.0:0".parse().unwrap();
        assert!(parse_v1(&mut cursor, default).await.is_err());
    }

    #[tokio::test]
    async fn test_parse_v1_tcp6_with_ipv4_src_rejected() {
        let addr_line = b"TCP6 10.0.0.1 2001:db8::2 12345 443\r\n";
        let mut cursor = Cursor::new(addr_line.to_vec());
        let default = "0.0.0.0:0".parse().unwrap();
        assert!(parse_v1(&mut cursor, default).await.is_err());
    }

    #[tokio::test]
    async fn test_parse_v1_tcp6_with_ipv4_dst_rejected() {
        let addr_line = b"TCP6 2001:db8::1 192.168.1.1 12345 443\r\n";
        let mut cursor = Cursor::new(addr_line.to_vec());
        let default = "0.0.0.0:0".parse().unwrap();
        assert!(parse_v1(&mut cursor, default).await.is_err());
    }

    #[tokio::test]
    async fn test_parse_v1_tcp4_with_ipv4_mapped_ipv6_rejected() {
        // "::ffff:x.x.x.x" parses as IpAddr::V6, not IpAddr::V4 — must be rejected for TCP4.
        let addr_line = b"TCP4 ::ffff:1.2.3.4 ::ffff:5.6.7.8 12345 443\r\n";
        let mut cursor = Cursor::new(addr_line.to_vec());
        let default = "0.0.0.0:0".parse().unwrap();
        assert!(parse_v1(&mut cursor, default).await.is_err());
    }

    #[tokio::test]
    async fn test_parse_v1_tcp6_valid_accepted_and_family_preserved() {
        let addr_line = b"TCP6 2001:db8::1 2001:db8::2 12345 443\r\n";
        let mut cursor = Cursor::new(addr_line.to_vec());
        let default = "0.0.0.0:0".parse().unwrap();
        let info = parse_v1(&mut cursor, default).await.unwrap();
        assert!(info.src_addr.is_ipv6());
        assert!(info.dst_addr.unwrap().is_ipv6());
    }

    #[tokio::test]
    async fn test_parse_v1_tcp4_both_addresses_must_be_ipv4() {
        // Both addresses are IPv6 with TCP4 — must be rejected.
        let addr_line = b"TCP4 fe80::1 fe80::2 12345 443\r\n";
        let mut cursor = Cursor::new(addr_line.to_vec());
        let default = "0.0.0.0:0".parse().unwrap();
        assert!(parse_v1(&mut cursor, default).await.is_err());
    }

    // ===== T-5: V1 line-length cap (spec maximum 108 bytes) =====

    #[tokio::test]
    async fn test_parse_v1_line_exceeding_spec_maximum_rejected() {
        // Build a payload of 103 non-CRLF bytes; with the "PROXY " prefix (6 bytes)
        // the total line reaches 109 bytes, which exceeds the 108-byte spec ceiling.
        let mut body = b"TCP4 1.2.3.4 5.6.7.8 12345 80 ".to_vec();
        while body.len() < 103 {
            body.push(b'X');
        }
        body.extend_from_slice(b"\r\n");
        let mut cursor = Cursor::new(body);
        let default = "0.0.0.0:0".parse().unwrap();
        assert!(parse_v1(&mut cursor, default).await.is_err());
    }

    #[tokio::test]
    async fn test_parse_v1_maximum_valid_ipv6_line_accepted() {
        // Longest valid TCP6 line is ~104 bytes total, well within the 108-byte cap.
        let addr_line =
            b"TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff \
              ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe 65535 65535\r\n";
        let mut cursor = Cursor::new(addr_line.to_vec());
        let default = "0.0.0.0:0".parse().unwrap();
        assert!(parse_v1(&mut cursor, default).await.is_ok());
    }

    #[tokio::test]
    async fn test_parse_v1_exactly_108_byte_line_accepted() {
        // Construct a line that totals exactly 108 bytes (including "PROXY " and CRLF).
        // Payload starts at offset 6; adding CRLF, total = 6 + payload_len + 2 = 108
        // → payload_len = 100 bytes.  Use a valid TCP4 header padded with spaces.
        let base = b"TCP4 1.2.3.4 5.6.7.8 1 1";
        let mut body = base.to_vec();
        while body.len() < 100 {
            body.push(b' ');
        }
        body.extend_from_slice(b"\r\n");
        assert_eq!(
            body.len(),
            102,
            "payload + CRLF must be 102 bytes so total line = 108"
        );
        let mut cursor = Cursor::new(body);
        let default = "0.0.0.0:0".parse().unwrap();
        // Parsing succeeds (extra trailing spaces are ignored by split_whitespace).
        assert!(parse_v1(&mut cursor, default).await.is_ok());
    }

    // ===== T-6: V1 line-length off-by-one regression (CRLF at exactly bytes 108-109) =====

    /// A 109-byte line where CRLF falls at the final two bytes (108-109) must be rejected.
    ///
    /// The spec maximum is 108 bytes inclusive. Previously the CRLF break fired before
    /// the length guard, allowing this one-byte-over case to pass silently.
    #[tokio::test]
    async fn test_parse_v1_109_byte_line_crlf_at_boundary_rejected() {
        // Reader payload: 101 non-CRLF bytes followed by "\r\n" = 103 bytes.
        // `line` already holds the 6-byte PROXY prefix, so total = 6 + 101 + 2 = 109.
        let mut body: Vec<u8> = b"TCP4 1.2.3.4 5.6.7.8 1 1".to_vec();
        while body.len() < 101 {
            body.push(b' ');
        }
        body.extend_from_slice(b"\r\n");
        assert_eq!(body.len(), 103, "reader must supply exactly 103 bytes");

        let mut cursor = Cursor::new(body);
        let default = "0.0.0.0:0".parse().unwrap();
        assert!(
            parse_v1(&mut cursor, default).await.is_err(),
            "109-byte line (CRLF at bytes 108-109) must be rejected; spec max is 108 bytes"
        );
    }

    /// Boundary check: a 108-byte line (CRLF at bytes 107-108) must still be accepted.
    #[tokio::test]
    async fn test_parse_v1_108_byte_line_crlf_at_boundary_accepted() {
        // Reader: 100 non-CRLF bytes + "\r\n" = 102 bytes.
        // Total with PROXY prefix: 6 + 100 + 2 = 108 — exactly at the spec limit.
        let mut body: Vec<u8> = b"TCP4 1.2.3.4 5.6.7.8 1 1".to_vec();
        while body.len() < 100 {
            body.push(b' ');
        }
        body.extend_from_slice(b"\r\n");
        assert_eq!(body.len(), 102);

        let mut cursor = Cursor::new(body);
        let default = "0.0.0.0:0".parse().unwrap();
        assert!(
            parse_v1(&mut cursor, default).await.is_ok(),
            "108-byte line must be accepted as it is at the spec limit"
        );
    }
}

