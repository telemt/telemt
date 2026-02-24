//! HAProxy PROXY protocol V1/V2

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
    pub fn new(src_addr: SocketAddr) -> Self {
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
        
        if line.ends_with(b"\r\n") {
            break;
        }
        
        if line.len() > 256 {
            return Err(ProxyError::InvalidProxyProtocol);
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
        "TCP4" | "TCP6" if parts.len() >= 5 => {
            let src_ip: IpAddr = parts[1].parse()
                .map_err(|_| ProxyError::InvalidProxyProtocol)?;
            let dst_ip: IpAddr = parts[2].parse()
                .map_err(|_| ProxyError::InvalidProxyProtocol)?;
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
            let src_ip = Ipv6Addr::from(
                <[u8; 16]>::try_from(&addr_data[0..16]).unwrap()
            );
            let dst_ip = Ipv6Addr::from(
                <[u8; 16]>::try_from(&addr_data[16..32]).unwrap()
            );
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
#[allow(dead_code)]
pub struct ProxyProtocolV1Builder {
    family: &'static str,
    src_addr: Option<SocketAddr>,
    dst_addr: Option<SocketAddr>,
}

#[allow(dead_code)]
impl ProxyProtocolV1Builder {
    pub fn new() -> Self {
        Self {
            family: "UNKNOWN",
            src_addr: None,
            dst_addr: None,
        }
    }
    
    pub fn tcp4(mut self, src: SocketAddr, dst: SocketAddr) -> Self {
        self.family = "TCP4";
        self.src_addr = Some(src);
        self.dst_addr = Some(dst);
        self
    }
    
    pub fn tcp6(mut self, src: SocketAddr, dst: SocketAddr) -> Self {
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
#[allow(dead_code)]
pub struct ProxyProtocolV2Builder {
    src: Option<SocketAddr>,
    dst: Option<SocketAddr>,
}

#[allow(dead_code)]
impl ProxyProtocolV2Builder {
    pub fn new() -> Self {
        Self { src: None, dst: None }
    }

    pub fn with_addrs(mut self, src: SocketAddr, dst: SocketAddr) -> Self {
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
}
