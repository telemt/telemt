//! SOCKS4/5 Client Implementation

use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::error::{ProxyError, Result};

#[derive(Debug, Clone, Copy)]
pub struct SocksBoundAddr {
    pub addr: SocketAddr,
}

pub async fn connect_socks4(
    stream: &mut TcpStream,
    target: SocketAddr,
    user_id: Option<&str>,
) -> Result<SocksBoundAddr> {
    let ip = match target.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return Err(ProxyError::Proxy("SOCKS4 does not support IPv6".to_string())),
    };
    
    let port = target.port();
    let user = user_id.unwrap_or("").as_bytes();
    
    // VN (4) | CD (1) | DSTPORT (2) | DSTIP (4) | USERID (variable) | NULL (1)
    let mut buf = Vec::with_capacity(9 + user.len());
    buf.push(4); // VN
    buf.push(1); // CD (CONNECT)
    buf.extend_from_slice(&port.to_be_bytes());
    buf.extend_from_slice(&ip.octets());
    buf.extend_from_slice(user);
    buf.push(0); // NULL
    
    stream.write_all(&buf).await.map_err(ProxyError::Io)?;
    
    // Response: VN (1) | CD (1) | DSTPORT (2) | DSTIP (4)
    let mut resp = [0u8; 8];
    stream.read_exact(&mut resp).await.map_err(ProxyError::Io)?;
    
    if resp[1] != 90 {
        return Err(ProxyError::Proxy(format!("SOCKS4 request rejected: code {}", resp[1])));
    }

    let bound_port = u16::from_be_bytes([resp[2], resp[3]]);
    let bound_ip = IpAddr::from([resp[4], resp[5], resp[6], resp[7]]);

    Ok(SocksBoundAddr {
        addr: SocketAddr::new(bound_ip, bound_port),
    })
}

pub async fn connect_socks5(
    stream: &mut TcpStream,
    target: SocketAddr,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<SocksBoundAddr> {
    // 1. Auth negotiation
    // VER (1) | NMETHODS (1) | METHODS (variable)
    let mut methods = vec![0u8]; // No auth
    if username.is_some() {
        methods.push(2u8); // Username/Password
    }
    
    let mut buf = vec![5u8, methods.len() as u8];
    buf.extend_from_slice(&methods);
    
    stream.write_all(&buf).await.map_err(ProxyError::Io)?;
    
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.map_err(ProxyError::Io)?;
    
    if resp[0] != 5 {
        return Err(ProxyError::Proxy("Invalid SOCKS5 version".to_string()));
    }
    
    match resp[1] {
        0 => {}, // No auth
        2 => {
            // Username/Password auth
            if let (Some(u), Some(p)) = (username, password) {
                let u_bytes = u.as_bytes();
                let p_bytes = p.as_bytes();
                
                let mut auth_buf = Vec::with_capacity(3 + u_bytes.len() + p_bytes.len());
                auth_buf.push(1); // VER
                auth_buf.push(u_bytes.len() as u8);
                auth_buf.extend_from_slice(u_bytes);
                auth_buf.push(p_bytes.len() as u8);
                auth_buf.extend_from_slice(p_bytes);
                
                stream.write_all(&auth_buf).await.map_err(ProxyError::Io)?;
                
                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).await.map_err(ProxyError::Io)?;
                
                if auth_resp[1] != 0 {
                    return Err(ProxyError::Proxy("SOCKS5 authentication failed".to_string()));
                }
            } else {
                return Err(ProxyError::Proxy("SOCKS5 server requires authentication".to_string()));
            }
        },
        _ => return Err(ProxyError::Proxy("Unsupported SOCKS5 auth method".to_string())),
    }
    
    // 2. Connection request
    // VER (1) | CMD (1) | RSV (1) | ATYP (1) | DST.ADDR (variable) | DST.PORT (2)
    let mut req = vec![5u8, 1u8, 0u8]; // CONNECT
    
    match target {
        SocketAddr::V4(v4) => {
            req.push(1u8); // IPv4
            req.extend_from_slice(&v4.ip().octets());
        },
        SocketAddr::V6(v6) => {
            req.push(4u8); // IPv6
            req.extend_from_slice(&v6.ip().octets());
        },
    }
    
    req.extend_from_slice(&target.port().to_be_bytes());
    
    stream.write_all(&req).await.map_err(ProxyError::Io)?;
    
    // Response
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(ProxyError::Io)?;
    
    if head[1] != 0 {
        return Err(ProxyError::Proxy(format!("SOCKS5 request failed: code {}", head[1])));
    }
    
    // Parse bound address from response.
    let bound_addr = match head[3] {
        1 => { // IPv4
            let mut addr = [0u8; 4 + 2];
            stream.read_exact(&mut addr).await.map_err(ProxyError::Io)?;
            let ip = IpAddr::from([addr[0], addr[1], addr[2], addr[3]]);
            let port = u16::from_be_bytes([addr[4], addr[5]]);
            SocketAddr::new(ip, port)
        },
        3 => { // Domain
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(ProxyError::Io)?;
            let mut addr = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut addr).await.map_err(ProxyError::Io)?;
            // Domain-bound response is not useful for KDF IP material.
            let port_pos = addr.len().saturating_sub(2);
            let port = u16::from_be_bytes([addr[port_pos], addr[port_pos + 1]]);
            SocketAddr::new(IpAddr::from([0, 0, 0, 0]), port)
        },
        4 => { // IPv6
            let mut addr = [0u8; 16 + 2];
            stream.read_exact(&mut addr).await.map_err(ProxyError::Io)?;
            let ip = IpAddr::from(<[u8; 16]>::try_from(&addr[..16]).map_err(|_| {
                ProxyError::Proxy("Invalid SOCKS5 IPv6 bound address".to_string())
            })?);
            let port = u16::from_be_bytes([addr[16], addr[17]]);
            SocketAddr::new(ip, port)
        },
        _ => return Err(ProxyError::Proxy("Invalid address type in SOCKS5 response".to_string())),
    };

    Ok(SocksBoundAddr { addr: bound_addr })
}
