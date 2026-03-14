//! IP Addr Detect

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
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
    pub const fn has_any(&self) -> bool {
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
    "https://v4.ident.me/",
    "https://ipv4.icanhazip.com/",
    "https://api.ipify.org/",
];

#[allow(dead_code)]
const IPV6_URLS: &[&str] = &[
    "https://v6.ident.me/",
    "https://ipv6.icanhazip.com/",
    "https://api6.ipify.org/",
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
const fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
        }
        IpAddr::V6(ipv6) => {
            let segs = ipv6.segments();
            let seg0 = segs[0];
            // IPv4-mapped addresses (::ffff:x.x.x.x, i.e. ::ffff:0:0/96) must be
            // classified using the embedded IPv4 rules.  Without this check,
            // ::ffff:192.168.1.1 is treated as a public IPv6 address, causing the
            // proxy to publish a private RFC-1918 address in its external-IP link.
            let is_v4_mapped = segs[0] == 0 && segs[1] == 0 && segs[2] == 0
                && segs[3] == 0 && segs[4] == 0 && segs[5] == 0xffff;
            if is_v4_mapped {
                let v4 = Ipv4Addr::new(
                    (segs[6] >> 8) as u8, segs[6] as u8,
                    (segs[7] >> 8) as u8, segs[7] as u8,
                );
                return v4.is_private() || v4.is_loopback() || v4.is_link_local();
            }
            ipv6.is_loopback()
                || (seg0 & 0xfe00) == 0xfc00 // Unique Local (fc00::/7)
                || (seg0 & 0xffc0) == 0xfe80 // Link-Local (fe80::/10)
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

    // ===== T-4: is_private_ip IPv6 link-local regression tests =====

    #[test]
    fn test_is_private_ip_ipv6_link_local_detected() {
        // fe80::/10 covers fe80:: through febf::.
        assert!(is_private_ip("fe80::1".parse().unwrap()), "fe80::1 is link-local");
        assert!(is_private_ip("fe80::".parse().unwrap()), "fe80:: is link-local");
        assert!(
            is_private_ip("fe80::ffff:ffff:ffff:ffff".parse().unwrap()),
            "fe80::ffff:... is link-local"
        );
        assert!(
            is_private_ip("febf::ffff".parse().unwrap()),
            "febf::ffff is the last address in fe80::/10"
        );
    }

    #[test]
    fn test_is_private_ip_ipv6_just_outside_link_local_range_is_public() {
        // fe7f:: is one step below fe80::/10 — not link-local and not ULA.
        assert!(
            !is_private_ip("fe7f::1".parse().unwrap()),
            "fe7f::1 is below fe80::/10 and must not be private"
        );
        // fec0:: is one step above febf:: — outside fe80::/10 and outside fc00::/7.
        assert!(
            !is_private_ip("fec0::1".parse().unwrap()),
            "fec0::1 is above fe80::/10 and not ULA — must not be private"
        );
    }

    #[test]
    fn test_is_private_ip_ipv6_ula_still_detected() {
        assert!(is_private_ip("fc00::1".parse().unwrap()), "fc00::/7 is ULA");
        assert!(is_private_ip("fd00::1".parse().unwrap()), "fd00:: is ULA");
        assert!(is_private_ip("fdff::1".parse().unwrap()), "fdff:: is ULA");
    }

    #[test]
    fn test_is_private_ip_ipv6_loopback_still_detected() {
        assert!(is_private_ip("::1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ip_ipv6_global_unicast_is_public() {
        assert!(!is_private_ip("2001:4860:4860::8888".parse().unwrap()));
        assert!(!is_private_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn test_link_local_mask_boundary_exhaustive() {
        // Verify the exact boundary of fe80::/10.
        // The mask 0xffc0 applied to the first segment must equal 0xfe80.
        let cases: &[(&str, bool)] = &[
            ("fe80::1", true),
            ("fe81::1", true),
            ("fea0::1", true),
            ("febf::1", true),  // last /10 prefix
            ("fec0::1", false), // first address outside /10
            ("fe7f::1", false), // just below the range
            ("ff00::1", false), // multicast
        ];
        for &(addr_str, expected) in cases {
            let ip: IpAddr = addr_str.parse().expect(addr_str);
            assert_eq!(
                is_private_ip(ip),
                expected,
                "{addr_str}: expected is_private={expected}"
            );
        }
    }

    // ===== T-5: IPv4-mapped IPv6 address classification =====

    #[test]
    fn test_is_private_ip_ipv4_mapped_private_rfc1918_is_private() {
        // ::ffff:192.168.x.x, ::ffff:10.x.x.x, ::ffff:172.16-31.x.x — RFC 1918
        assert!(is_private_ip("::ffff:192.168.1.1".parse().unwrap()));
        assert!(is_private_ip("::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("::ffff:172.16.0.1".parse().unwrap()));
        assert!(is_private_ip("::ffff:172.31.255.255".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ip_ipv4_mapped_loopback_is_private() {
        assert!(is_private_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_private_ip("::ffff:127.255.255.255".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ip_ipv4_mapped_link_local_is_private() {
        // 169.254.0.0/16 is IPv4 link-local
        assert!(is_private_ip("::ffff:169.254.0.1".parse().unwrap()));
        assert!(is_private_ip("::ffff:169.254.255.254".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ip_ipv4_mapped_public_is_not_private() {
        assert!(!is_private_ip("::ffff:8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip("::ffff:1.1.1.1".parse().unwrap()));
        assert!(!is_private_ip("::ffff:203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ip_ipv4_compatible_not_treated_as_mapped() {
        // ::192.168.1.1 is IPv4-compatible (deprecated, segs[5]=0, not 0xffff).
        // It does NOT match the ::ffff:0:0/96 mapped range and falls through to
        // pure-IPv6 rules, which classify it as public (not ULA, not link-local).
        assert!(!is_private_ip("::192.168.1.1".parse::<IpAddr>().unwrap()));
    }
}