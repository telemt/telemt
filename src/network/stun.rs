#![allow(unreachable_code)]
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::net::{lookup_host, UdpSocket};
use tokio::time::{timeout, Duration, sleep};

use crate::error::{ProxyError, Result};

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
    let (v4, v6) = tokio::join!(
        stun_probe_family(stun_addr, IpFamily::V4),
        stun_probe_family(stun_addr, IpFamily::V6),
    );

    Ok(DualStunResult {
        v4: v4?,
        v6: v6?,
    })
}

pub async fn stun_probe_family(stun_addr: &str, family: IpFamily) -> Result<Option<StunProbeResult>> {
    use rand::RngCore;

    let bind_addr = match family {
        IpFamily::V4 => "0.0.0.0:0",
        IpFamily::V6 => "[::]:0",
    };

    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| ProxyError::Proxy(format!("STUN bind failed: {e}")))?;

    let target_addr = resolve_stun_addr(stun_addr, family).await?;
    if let Some(addr) = target_addr {
        match socket.connect(addr).await {
            Ok(()) => {}
            Err(e) if family == IpFamily::V6 && matches!(
                e.kind(),
                std::io::ErrorKind::NetworkUnreachable
                | std::io::ErrorKind::HostUnreachable
                | std::io::ErrorKind::Unsupported
                | std::io::ErrorKind::NetworkDown
            ) => return Ok(None),
            Err(e) => return Err(ProxyError::Proxy(format!("STUN connect failed: {e}"))),
        }
    } else {
        return Ok(None);
    }

    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&0x0001u16.to_be_bytes()); // Binding Request
    req[2..4].copy_from_slice(&0u16.to_be_bytes()); // length
    req[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes()); // magic cookie
    rand::rng().fill_bytes(&mut req[8..20]); // transaction ID

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
                if attempt >= 3 {
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

        let magic = 0x2112A442u32.to_be_bytes();
        let txid = &req[8..20];
    let mut idx = 20;
    while idx + 4 <= n {
        let atype = u16::from_be_bytes(buf[idx..idx + 2].try_into().unwrap());
        let alen = u16::from_be_bytes(buf[idx + 2..idx + 4].try_into().unwrap()) as usize;
        idx += 4;
        if idx + alen > n {
            break;
        }

        match atype {
            0x0020 /* XOR-MAPPED-ADDRESS */ | 0x0001 /* MAPPED-ADDRESS */ => {
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
                            let xor_key = [magic.as_slice(), txid].concat();
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
                        0x01 => IpAddr::V4(Ipv4Addr::new(raw_ip[0], raw_ip[1], raw_ip[2], raw_ip[3])),
                        0x02 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(raw_ip).unwrap())),
                        _ => {
                            idx += (alen + 3) & !3;
                            continue;
                        }
                    }
                };

                let reflected_addr = SocketAddr::new(reflected_ip, port);
                let local_addr = socket
                    .local_addr()
                    .map_err(|e| ProxyError::Proxy(format!("STUN local_addr failed: {e}")))?;

                return Ok(Some(StunProbeResult {
                    local_addr,
                    reflected_addr,
                    family,
                }));
            }
            _ => {}
        }

        idx += (alen + 3) & !3;
    }

    }

    Ok(None)
}

async fn resolve_stun_addr(stun_addr: &str, family: IpFamily) -> Result<Option<SocketAddr>> {
    if let Ok(addr) = stun_addr.parse::<SocketAddr>() {
        return Ok(match (addr.is_ipv4(), family) {
            (true, IpFamily::V4) | (false, IpFamily::V6) => Some(addr),
            _ => None,
        });
    }

    let mut addrs = lookup_host(stun_addr)
        .await
        .map_err(|e| ProxyError::Proxy(format!("STUN resolve failed: {e}")))?;

    let target = addrs
        .find(|a| matches!((a.is_ipv4(), family), (true, IpFamily::V4) | (false, IpFamily::V6)));
    Ok(target)
}
