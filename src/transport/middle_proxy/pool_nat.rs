use std::net::{IpAddr, Ipv4Addr};

use tracing::{info, warn};

use crate::error::{ProxyError, Result};

use super::MePool;

#[derive(Debug, Clone, Copy)]
pub struct StunProbeResult {
    pub local_addr: std::net::SocketAddr,
    pub reflected_addr: std::net::SocketAddr,
}

pub async fn stun_probe(stun_addr: Option<String>) -> Result<Option<StunProbeResult>> {
    let stun_addr = stun_addr.unwrap_or_else(|| "stun.l.google.com:19302".to_string());
    fetch_stun_binding(&stun_addr).await
}

impl MePool {
    pub(super) fn translate_ip_for_nat(&self, ip: IpAddr) -> IpAddr {
        let nat_ip = self
            .nat_ip_cfg
            .or_else(|| self.nat_ip_detected.try_read().ok().and_then(|g| (*g).clone()));

        let Some(nat_ip) = nat_ip else {
            return ip;
        };

        match (ip, nat_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst))
                if is_privateish(IpAddr::V4(src))
                    || src.is_loopback()
                    || src.is_unspecified() =>
            {
                IpAddr::V4(dst)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) if src.is_loopback() || src.is_unspecified() => {
                IpAddr::V6(dst)
            }
            (orig, _) => orig,
        }
    }

    pub(super) fn translate_our_addr_with_reflection(
        &self,
        addr: std::net::SocketAddr,
        reflected: Option<std::net::SocketAddr>,
    ) -> std::net::SocketAddr {
        let ip = if let Some(r) = reflected {
            // Use reflected IP (not port) only when local address is non-public.
            if is_privateish(addr.ip()) || addr.ip().is_loopback() || addr.ip().is_unspecified() {
                r.ip()
            } else {
                self.translate_ip_for_nat(addr.ip())
            }
        } else {
            self.translate_ip_for_nat(addr.ip())
        };

        // Keep the kernel-assigned TCP source port; STUN port can differ.
        std::net::SocketAddr::new(ip, addr.port())
    }

    pub(super) async fn maybe_detect_nat_ip(&self, local_ip: IpAddr) -> Option<IpAddr> {
        if self.nat_ip_cfg.is_some() {
            return self.nat_ip_cfg;
        }

        if !(is_privateish(local_ip) || local_ip.is_loopback() || local_ip.is_unspecified()) {
            return None;
        }

        if let Some(ip) = self.nat_ip_detected.read().await.clone() {
            return Some(ip);
        }

        match fetch_public_ipv4_with_retry().await {
            Ok(Some(ip)) => {
                {
                    let mut guard = self.nat_ip_detected.write().await;
                    *guard = Some(IpAddr::V4(ip));
                }
                info!(public_ip = %ip, "Auto-detected public IP for NAT translation");
                Some(IpAddr::V4(ip))
            }
            Ok(None) => None,
            Err(e) => {
                warn!(error = %e, "Failed to auto-detect public IP");
                None
            }
        }
    }

    pub(super) async fn maybe_reflect_public_addr(&self) -> Option<std::net::SocketAddr> {
        let stun_addr = self
            .nat_stun
            .clone()
            .unwrap_or_else(|| "stun.l.google.com:19302".to_string());
        match fetch_stun_binding(&stun_addr).await {
            Ok(sa) => {
                if let Some(result) = sa {
                    info!(local = %result.local_addr, reflected = %result.reflected_addr, "NAT probe: reflected address");
                    Some(result.reflected_addr)
                } else {
                    None
                }
            }
            Err(e) => {
                warn!(error = %e, "NAT probe failed");
                None
            }
        }
    }
}

async fn fetch_public_ipv4_with_retry() -> Result<Option<Ipv4Addr>> {
    let providers = [
        "https://checkip.amazonaws.com",
        "http://v4.ident.me",
        "http://ipv4.icanhazip.com",
    ];
    for url in providers {
        if let Ok(Some(ip)) = fetch_public_ipv4_once(url).await {
            return Ok(Some(ip));
        }
    }
    Ok(None)
}

async fn fetch_public_ipv4_once(url: &str) -> Result<Option<Ipv4Addr>> {
    let res = reqwest::get(url).await.map_err(|e| {
        ProxyError::Proxy(format!("public IP detection request failed: {e}"))
    })?;

    let text = res.text().await.map_err(|e| {
        ProxyError::Proxy(format!("public IP detection read failed: {e}"))
    })?;

    let ip = text.trim().parse().ok();
    Ok(ip)
}

async fn fetch_stun_binding(stun_addr: &str) -> Result<Option<StunProbeResult>> {
    use rand::RngCore;
    use tokio::net::UdpSocket;

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| ProxyError::Proxy(format!("STUN bind failed: {e}")))?;
    socket
        .connect(stun_addr)
        .await
        .map_err(|e| ProxyError::Proxy(format!("STUN connect failed: {e}")))?;

    // Build minimal Binding Request.
    let mut req = vec![0u8; 20];
    req[0..2].copy_from_slice(&0x0001u16.to_be_bytes()); // Binding Request
    req[2..4].copy_from_slice(&0u16.to_be_bytes()); // length
    req[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes()); // magic cookie
    rand::rng().fill_bytes(&mut req[8..20]);

    socket
        .send(&req)
        .await
        .map_err(|e| ProxyError::Proxy(format!("STUN send failed: {e}")))?;

    let mut buf = [0u8; 128];
    let n = socket
        .recv(&mut buf)
        .await
        .map_err(|e| ProxyError::Proxy(format!("STUN recv failed: {e}")))?;
    if n < 20 {
        return Ok(None);
    }

    // Parse attributes.
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
                let family = buf[idx + 1];
                if family != 0x01 {
                    // only IPv4 supported here
                    break;
                }
                let port_bytes = [buf[idx + 2], buf[idx + 3]];
                let ip_bytes = [buf[idx + 4], buf[idx + 5], buf[idx + 6], buf[idx + 7]];

                let (port, ip) = if atype == 0x0020 {
                    let magic = 0x2112A442u32.to_be_bytes();
                    let port = u16::from_be_bytes(port_bytes) ^ ((magic[0] as u16) << 8 | magic[1] as u16);
                    let ip = [
                        ip_bytes[0] ^ magic[0],
                        ip_bytes[1] ^ magic[1],
                        ip_bytes[2] ^ magic[2],
                        ip_bytes[3] ^ magic[3],
                    ];
                    (port, ip)
                } else {
                    (u16::from_be_bytes(port_bytes), ip_bytes)
                };
                let reflected = std::net::SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
                    port,
                );
                let local_addr = socket.local_addr().map_err(|e| {
                    ProxyError::Proxy(format!("STUN local_addr failed: {e}"))
                })?;
                return Ok(Some(StunProbeResult {
                    local_addr,
                    reflected_addr: reflected,
                }));
            }
            _ => {}
        }
        idx += (alen + 3) & !3; // 4-byte alignment
    }

    Ok(None)
}

fn is_privateish(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_unique_local(),
    }
}
