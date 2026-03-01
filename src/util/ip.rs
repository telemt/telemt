//! IP Addr Detect

use std::net::{IpAddr, UdpSocket};
use std::time::Duration;
use tracing::{debug, warn};

/// Detected IP addresses
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct IpInfo {
    pub ipv4: Option<IpAddr>,
    pub ipv6: Option<IpAddr>,
}

#[allow(dead_code)]
impl IpInfo {
    /// Check if any IP is detected
    pub fn has_any(&self) -> bool {
        self.ipv4.is_some() || self.ipv6.is_some()
    }

    /// Get preferred IP (IPv6 if available and preferred)
    pub fn preferred(&self, prefer_ipv6: bool) -> Option<IpAddr> {
        if prefer_ipv6 {
            self.ipv6.or(self.ipv4)
        } else {
            self.ipv4.or(self.ipv6)
        }
    }
}

/// URLs for IP detection
#[allow(dead_code)]
const IPV4_URLS: &[&str] = &[
    "http://v4.ident.me/",
    "http://ipv4.icanhazip.com/",
    "http://api.ipify.org/",
];

#[allow(dead_code)]
const IPV6_URLS: &[&str] = &[
    "http://v6.ident.me/",
    "http://ipv6.icanhazip.com/",
    "http://api6.ipify.org/",
];

/// Detect local IP address by connecting to a public DNS
/// This does not actually send any packets
#[allow(dead_code)]
fn get_local_ip(target: &str) -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect(target).ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}

#[allow(dead_code)]
fn get_local_ipv6(target: &str) -> Option<IpAddr> {
    let socket = UdpSocket::bind("[::]:0").ok()?;
    socket.connect(target).ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}

/// Detect public IP addresses
#[allow(dead_code)]
pub async fn detect_ip() -> IpInfo {
    let mut info = IpInfo::default();

    // Try to get local interface IP first (default gateway interface)
    // We connect to Google DNS to find out which interface is used for routing
    if let Some(ip) = get_local_ip("8.8.8.8:80")
        && ip.is_ipv4()
        && !ip.is_loopback()
    {
        info.ipv4 = Some(ip);
        debug!(ip = %ip, "Detected local IPv4 address via routing");
    }

    if let Some(ip) = get_local_ipv6("[2001:4860:4860::8888]:80")
        && ip.is_ipv6()
        && !ip.is_loopback()
    {
        info.ipv6 = Some(ip);
        debug!(ip = %ip, "Detected local IPv6 address via routing");
    }

    // If local detection failed or returned private IP (and we want public),
    // or just as a fallback/verification, we might want to check external services.
    // However, the requirement is: "if IP for listening is not set... it should be IP from interface...
    // if impossible - request external resources".

    // So if we found a local IP, we might be good. But often servers are behind NAT.
    // If the local IP is private, we probably want the public IP for the tg:// link.
    // Let's check if the detected IPs are private.

    let need_external_v4 = info.ipv4.is_none_or(is_private_ip);
    let need_external_v6 = info.ipv6.is_none_or(is_private_ip);

    if need_external_v4 {
        debug!("Local IPv4 is private or missing, checking external services...");
        for url in IPV4_URLS {
            if let Some(ip) = fetch_ip(url).await
                && ip.is_ipv4()
            {
                info.ipv4 = Some(ip);
                debug!(ip = %ip, "Detected public IPv4 address");
                break;
            }
        }
    }

    if need_external_v6 {
        debug!("Local IPv6 is private or missing, checking external services...");
        for url in IPV6_URLS {
            if let Some(ip) = fetch_ip(url).await
                && ip.is_ipv6()
            {
                info.ipv6 = Some(ip);
                debug!(ip = %ip, "Detected public IPv6 address");
                break;
            }
        }
    }
    
    if !info.has_any() {
        warn!("Failed to detect public IP address");
    }
    
    info
}

#[allow(dead_code)]
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || (ipv6.segments()[0] & 0xfe00) == 0xfc00 // Unique Local
        }
    }
}

/// Fetch IP from URL
#[allow(dead_code)]
async fn fetch_ip(url: &str) -> Option<IpAddr> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;

    let response = client.get(url).send().await.ok()?;
    let text = response.text().await.ok()?;

    text.trim().parse().ok()
}

/// Synchronous IP detection (for startup)
#[allow(dead_code)]
pub fn detect_ip_sync() -> IpInfo {
    tokio::runtime::Handle::current().block_on(detect_ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ip_info() {
        let info = IpInfo::default();
        assert!(!info.has_any());
        
        let info = IpInfo {
            ipv4: Some("1.2.3.4".parse().unwrap()),
            ipv6: None,
        };
        assert!(info.has_any());
        assert_eq!(info.preferred(false), Some("1.2.3.4".parse().unwrap()));
        assert_eq!(info.preferred(true), Some("1.2.3.4".parse().unwrap()));
        
        let info = IpInfo {
            ipv4: Some("1.2.3.4".parse().unwrap()),
            ipv6: Some("::1".parse().unwrap()),
        };
        assert_eq!(info.preferred(false), Some("1.2.3.4".parse().unwrap()));
        assert_eq!(info.preferred(true), Some("::1".parse().unwrap()));
    }
}