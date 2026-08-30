#![allow(unreachable_code)]
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, UdpSocket, lookup_host};
use tokio::time::{Duration, sleep, timeout};

use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::network::dns_overrides::{GenerationDnsResolver, split_host_port};

fn stun_rng() -> &'static SecureRandom {
    static STUN_RNG: OnceLock<SecureRandom> = OnceLock::new();
    STUN_RNG.get_or_init(SecureRandom::new)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpFamily {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy)]
pub struct StunProbeResult {
    pub local_addr: SocketAddr,
    pub reflected_addr: SocketAddr,
    pub family: IpFamily,
}

#[derive(Debug, Default, Clone)]
pub struct DualStunResult {
    pub v4: Option<StunProbeResult>,
    pub v6: Option<StunProbeResult>,
}

pub async fn stun_probe_dual(stun_addr: &str) -> Result<DualStunResult> {
    stun_probe_dual_with_tcp_fallback(stun_addr, false).await
}

pub async fn stun_probe_dual_with_tcp_fallback(
    stun_addr: &str,
    tcp_fallback: bool,
) -> Result<DualStunResult> {
    let (v4, v6) = tokio::join!(
        stun_probe_family_with_tcp_fallback(stun_addr, IpFamily::V4, tcp_fallback),
        stun_probe_family_with_tcp_fallback(stun_addr, IpFamily::V6, tcp_fallback),
    );

    Ok(DualStunResult { v4: v4?, v6: v6? })
}

pub async fn stun_probe_family(
    stun_addr: &str,
    family: IpFamily,
) -> Result<Option<StunProbeResult>> {
    stun_probe_family_with_tcp_fallback(stun_addr, family, false).await
}

pub async fn stun_probe_family_with_tcp_fallback(
    stun_addr: &str,
    family: IpFamily,
    tcp_fallback: bool,
) -> Result<Option<StunProbeResult>> {
    stun_probe_family_with_bind_and_tcp_fallback(stun_addr, family, None, tcp_fallback).await
}

pub async fn stun_probe_family_with_bind(
    stun_addr: &str,
    family: IpFamily,
    bind_ip: Option<IpAddr>,
) -> Result<Option<StunProbeResult>> {
    stun_probe_family_with_bind_and_tcp_fallback(stun_addr, family, bind_ip, false).await
}

pub async fn stun_probe_family_with_bind_and_tcp_fallback(
    stun_addr: &str,
    family: IpFamily,
    bind_ip: Option<IpAddr>,
    tcp_fallback: bool,
) -> Result<Option<StunProbeResult>> {
    stun_probe_family_with_bind_tcp_fallback_and_resolver(
        stun_addr,
        family,
        bind_ip,
        tcp_fallback,
        None,
    )
    .await
}

/// Probes one STUN family with an optional generation-owned DNS resolver.
pub async fn stun_probe_family_with_bind_tcp_fallback_and_resolver(
    stun_addr: &str,
    family: IpFamily,
    bind_ip: Option<IpAddr>,
    tcp_fallback: bool,
    dns_resolver: Option<&GenerationDnsResolver>,
) -> Result<Option<StunProbeResult>> {
    let udp_attempts = if tcp_fallback { 1 } else { 3 };
    let udp_result =
        stun_probe_family_udp(stun_addr, family, bind_ip, udp_attempts, dns_resolver).await?;
    if udp_result.is_some() || !tcp_fallback {
        return Ok(udp_result);
    }
    stun_probe_family_tcp(stun_addr, family, bind_ip, dns_resolver).await
}

async fn stun_probe_family_udp(
    stun_addr: &str,
    family: IpFamily,
    bind_ip: Option<IpAddr>,
    max_attempts: u8,
    dns_resolver: Option<&GenerationDnsResolver>,
) -> Result<Option<StunProbeResult>> {
    let bind_addr = match (family, bind_ip) {
        (IpFamily::V4, Some(IpAddr::V4(ip))) => SocketAddr::new(IpAddr::V4(ip), 0),
        (IpFamily::V6, Some(IpAddr::V6(ip))) => SocketAddr::new(IpAddr::V6(ip), 0),
        (IpFamily::V4, Some(IpAddr::V6(_))) | (IpFamily::V6, Some(IpAddr::V4(_))) => {
            return Ok(None);
        }
        (IpFamily::V4, None) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        (IpFamily::V6, None) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };

    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(socket) => socket,
        Err(_) if bind_ip.is_some() => return Ok(None),
        Err(e) => return Err(ProxyError::Proxy(format!("STUN bind failed: {e}"))),
    };

    let target_addr = resolve_stun_addr(stun_addr, family, dns_resolver).await?;
    if let Some(addr) = target_addr {
        match socket.connect(addr).await {
            Ok(()) => {}
            Err(e)
                if family == IpFamily::V6
                    && matches!(
                        e.kind(),
                        std::io::ErrorKind::NetworkUnreachable
                            | std::io::ErrorKind::HostUnreachable
                            | std::io::ErrorKind::Unsupported
                            | std::io::ErrorKind::NetworkDown
                    ) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(ProxyError::Proxy(format!("STUN connect failed: {e}"))),
        }
    } else {
        return Ok(None);
    }

    let req = build_binding_request();
    let mut buf = [0u8; 256];
    let mut attempt = 0;
    let mut backoff = Duration::from_secs(1);
    loop {
        socket
            .send(&req)
            .await
            .map_err(|e| ProxyError::Proxy(format!("STUN send failed: {e}")))?;

        let recv_res = timeout(Duration::from_secs(3), socket.recv(&mut buf)).await;
        let n = match recv_res {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(ProxyError::Proxy(format!("STUN recv failed: {e}"))),
            Err(_) => {
                attempt += 1;
                if attempt >= max_attempts {
                    return Ok(None);
                }
                sleep(backoff).await;
                backoff *= 2;
                continue;
            }
        };

        if n < 20 {
            return Ok(None);
        }

        let txid = &req[8..20];
        if let Some(reflected_addr) = parse_reflected_addr(&buf[..n], txid) {
            let local_addr = socket
                .local_addr()
                .map_err(|e| ProxyError::Proxy(format!("STUN local_addr failed: {e}")))?;
            return Ok(Some(StunProbeResult {
                local_addr,
                reflected_addr,
                family,
            }));
        }
    }

    Ok(None)
}

async fn stun_probe_family_tcp(
    stun_addr: &str,
    family: IpFamily,
    bind_ip: Option<IpAddr>,
    dns_resolver: Option<&GenerationDnsResolver>,
) -> Result<Option<StunProbeResult>> {
    let target_addr = match resolve_stun_addr(stun_addr, family, dns_resolver).await? {
        Some(addr) => addr,
        None => return Ok(None),
    };
    let socket = match family {
        IpFamily::V4 => TcpSocket::new_v4(),
        IpFamily::V6 => TcpSocket::new_v6(),
    }
    .map_err(|e| ProxyError::Proxy(format!("STUN TCP socket failed: {e}")))?;
    match (family, bind_ip) {
        (IpFamily::V4, Some(IpAddr::V4(ip))) => {
            if socket.bind(SocketAddr::new(IpAddr::V4(ip), 0)).is_err() {
                return Ok(None);
            }
        }
        (IpFamily::V6, Some(IpAddr::V6(ip))) => {
            if socket.bind(SocketAddr::new(IpAddr::V6(ip), 0)).is_err() {
                return Ok(None);
            }
        }
        (IpFamily::V4, Some(IpAddr::V6(_))) | (IpFamily::V6, Some(IpAddr::V4(_))) => {
            return Ok(None);
        }
        (_, None) => {}
    }

    let connect_res = timeout(Duration::from_secs(3), socket.connect(target_addr)).await;
    let mut stream = match connect_res {
        Ok(Ok(stream)) => stream,
        Ok(Err(e))
            if family == IpFamily::V6
                && matches!(
                    e.kind(),
                    std::io::ErrorKind::NetworkUnreachable
                        | std::io::ErrorKind::HostUnreachable
                        | std::io::ErrorKind::Unsupported
                        | std::io::ErrorKind::NetworkDown
                ) =>
        {
            return Ok(None);
        }
        Ok(Err(e)) => return Err(ProxyError::Proxy(format!("STUN TCP connect failed: {e}"))),
        Err(_) => return Ok(None),
    };

    let req = build_binding_request();
    timeout(Duration::from_secs(3), stream.write_all(&req))
        .await
        .map_err(|_| ProxyError::Proxy("STUN TCP send timeout".to_string()))?
        .map_err(|e| ProxyError::Proxy(format!("STUN TCP send failed: {e}")))?;

    let mut header = [0u8; 20];
    timeout(Duration::from_secs(3), stream.read_exact(&mut header))
        .await
        .map_err(|_| ProxyError::Proxy("STUN TCP header timeout".to_string()))?
        .map_err(|e| ProxyError::Proxy(format!("STUN TCP header read failed: {e}")))?;
    let body_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if body_len > 236 {
        return Ok(None);
    }
    let mut buf = [0u8; 256];
    buf[..20].copy_from_slice(&header);
    if body_len > 0 {
        timeout(
            Duration::from_secs(3),
            stream.read_exact(&mut buf[20..20 + body_len]),
        )
        .await
        .map_err(|_| ProxyError::Proxy("STUN TCP body timeout".to_string()))?
        .map_err(|e| ProxyError::Proxy(format!("STUN TCP body read failed: {e}")))?;
    }

    let txid = &req[8..20];
    let Some(reflected_addr) = parse_reflected_addr(&buf[..20 + body_len], txid) else {
        return Ok(None);
    };
    let local_addr = stream
        .local_addr()
        .map_err(|e| ProxyError::Proxy(format!("STUN TCP local_addr failed: {e}")))?;
    Ok(Some(StunProbeResult {
        local_addr,
        reflected_addr,
        family,
    }))
}

fn build_binding_request() -> [u8; 20] {
    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
    req[2..4].copy_from_slice(&0u16.to_be_bytes());
    req[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());
    stun_rng().fill(&mut req[8..20]);
    req
}

fn parse_reflected_addr(buf: &[u8], txid: &[u8]) -> Option<SocketAddr> {
    if buf.len() < 20 {
        return None;
    }

    let magic = 0x2112A442u32.to_be_bytes();
    let mut idx = 20;
    while idx + 4 <= buf.len() {
        let atype = u16::from_be_bytes(buf[idx..idx + 2].try_into().ok()?);
        let alen = u16::from_be_bytes(buf[idx + 2..idx + 4].try_into().ok()?) as usize;
        idx += 4;
        if idx + alen > buf.len() {
            break;
        }

        match atype {
            0x0020 | 0x0001 => {
                if alen < 8 {
                    break;
                }
                let family_byte = buf[idx + 1];
                let port_bytes = [buf[idx + 2], buf[idx + 3]];
                let len_check = match family_byte {
                    0x01 => 4,
                    0x02 => 16,
                    _ => 0,
                };
                if len_check == 0 || alen < 4 + len_check {
                    break;
                }

                let raw_ip = &buf[idx + 4..idx + 4 + len_check];
                let mut port = u16::from_be_bytes(port_bytes);
                let reflected_ip = if atype == 0x0020 {
                    port ^= ((magic[0] as u16) << 8) | magic[1] as u16;
                    match family_byte {
                        0x01 => {
                            let ip = [
                                raw_ip[0] ^ magic[0],
                                raw_ip[1] ^ magic[1],
                                raw_ip[2] ^ magic[2],
                                raw_ip[3] ^ magic[3],
                            ];
                            IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))
                        }
                        0x02 => {
                            let mut ip = [0u8; 16];
                            let mut xor_key = [0u8; 16];
                            xor_key[..4].copy_from_slice(&magic);
                            xor_key[4..].copy_from_slice(txid.get(..12)?);
                            for (i, b) in raw_ip.iter().enumerate().take(16) {
                                ip[i] = *b ^ xor_key[i];
                            }
                            IpAddr::V6(Ipv6Addr::from(ip))
                        }
                        _ => {
                            idx += (alen + 3) & !3;
                            continue;
                        }
                    }
                } else {
                    match family_byte {
                        0x01 => {
                            IpAddr::V4(Ipv4Addr::new(raw_ip[0], raw_ip[1], raw_ip[2], raw_ip[3]))
                        }
                        0x02 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(raw_ip).ok()?)),
                        _ => {
                            idx += (alen + 3) & !3;
                            continue;
                        }
                    }
                };
                return Some(SocketAddr::new(reflected_ip, port));
            }
            _ => {}
        }

        idx += (alen + 3) & !3;
    }
    None
}

async fn resolve_stun_addr(
    stun_addr: &str,
    family: IpFamily,
    dns_resolver: Option<&GenerationDnsResolver>,
) -> Result<Option<SocketAddr>> {
    if let Ok(addr) = stun_addr.parse::<SocketAddr>() {
        return Ok(match (addr.is_ipv4(), family) {
            (true, IpFamily::V4) | (false, IpFamily::V6) => Some(addr),
            _ => None,
        });
    }

    if let Some((host, port)) = split_host_port(stun_addr)
        && let Some(addr) =
            dns_resolver.and_then(|resolver| resolver.resolve_socket_addr(&host, port))
    {
        return Ok(match (addr.is_ipv4(), family) {
            (true, IpFamily::V4) | (false, IpFamily::V6) => Some(addr),
            _ => None,
        });
    }

    let mut addrs = lookup_host(stun_addr)
        .await
        .map_err(|e| ProxyError::Proxy(format!("STUN resolve failed: {e}")))?;

    let target = addrs.find(|a| {
        matches!(
            (a.is_ipv4(), family),
            (true, IpFamily::V4) | (false, IpFamily::V6)
        )
    });
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reflected_addr_reads_mapped_ipv4() {
        let txid = [0u8; 12];
        let mut response = [0u8; 32];
        response[0..2].copy_from_slice(&0x0101u16.to_be_bytes());
        response[2..4].copy_from_slice(&12u16.to_be_bytes());
        response[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());
        response[20..22].copy_from_slice(&0x0001u16.to_be_bytes());
        response[22..24].copy_from_slice(&8u16.to_be_bytes());
        response[25] = 0x01;
        response[26..28].copy_from_slice(&443u16.to_be_bytes());
        response[28..32].copy_from_slice(&[203, 0, 113, 9]);

        let reflected = parse_reflected_addr(&response, &txid).unwrap();
        assert_eq!(
            reflected,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 443)
        );
    }

    #[test]
    fn parse_reflected_addr_reads_xor_mapped_ipv4() {
        let txid = [0u8; 12];
        let magic = 0x2112A442u32.to_be_bytes();
        let port = 443u16;
        let ip = [203u8, 0, 113, 9];
        let xport = port ^ (((magic[0] as u16) << 8) | magic[1] as u16);
        let xip = [
            ip[0] ^ magic[0],
            ip[1] ^ magic[1],
            ip[2] ^ magic[2],
            ip[3] ^ magic[3],
        ];
        let mut response = [0u8; 32];
        response[0..2].copy_from_slice(&0x0101u16.to_be_bytes());
        response[2..4].copy_from_slice(&12u16.to_be_bytes());
        response[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());
        response[20..22].copy_from_slice(&0x0020u16.to_be_bytes());
        response[22..24].copy_from_slice(&8u16.to_be_bytes());
        response[25] = 0x01;
        response[26..28].copy_from_slice(&xport.to_be_bytes());
        response[28..32].copy_from_slice(&xip);

        let reflected = parse_reflected_addr(&response, &txid).unwrap();
        assert_eq!(
            reflected,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 443)
        );
    }
}
