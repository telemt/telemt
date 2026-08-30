//! Runtime DNS overrides for `host:port` targets.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::error::{ProxyError, Result};

type OverrideMap = HashMap<(String, u16), IpAddr>;
const DNS_OVERRIDE_MAX_ENTRIES: usize = 4096;

/// Immutable DNS override snapshot owned by one runtime generation.
#[derive(Debug, Clone, Default)]
pub struct DnsOverrides {
    entries: Arc<OverrideMap>,
}

impl DnsOverrides {
    /// Parses a validated generation-local override snapshot.
    pub fn from_entries(entries: &[String]) -> Result<Self> {
        Ok(Self {
            entries: Arc::new(parse_entries(entries)?),
        })
    }

    /// Resolves a generation-local hostname override.
    pub fn resolve(&self, host: &str, port: u16) -> Option<IpAddr> {
        self.entries
            .get(&(host.to_ascii_lowercase(), port))
            .copied()
    }

    /// Resolves a generation-local override as a socket address.
    pub fn resolve_socket_addr(&self, host: &str, port: u16) -> Option<SocketAddr> {
        self.resolve(host, port).map(|ip| SocketAddr::new(ip, port))
    }
}

/// Atomically published DNS override snapshot owned by one runtime generation.
#[derive(Debug, Default)]
pub struct GenerationDnsResolver {
    snapshot: ArcSwap<DnsOverrides>,
}

impl GenerationDnsResolver {
    /// Creates one resolver from a validated immutable entry set.
    pub fn from_entries(entries: &[String]) -> Result<Self> {
        Ok(Self {
            snapshot: ArcSwap::from_pointee(DnsOverrides::from_entries(entries)?),
        })
    }

    /// Validates and atomically publishes a new generation-local snapshot.
    pub fn apply_entries(&self, entries: &[String]) -> Result<()> {
        let snapshot = DnsOverrides::from_entries(entries)?;
        self.snapshot.store(Arc::new(snapshot));
        Ok(())
    }

    /// Resolves one configured override without consulting system DNS.
    pub fn resolve_socket_addr(&self, host: &str, port: u16) -> Option<SocketAddr> {
        self.snapshot.load().resolve_socket_addr(host, port)
    }
}

fn parse_ip_spec(ip_spec: &str) -> Result<IpAddr> {
    if ip_spec.starts_with('[') && ip_spec.ends_with(']') {
        let inner = &ip_spec[1..ip_spec.len() - 1];
        let ipv6 = inner.parse::<Ipv6Addr>().map_err(|_| {
            ProxyError::Config(format!(
                "network.dns_overrides IPv6 override is invalid: '{ip_spec}'"
            ))
        })?;
        return Ok(IpAddr::V6(ipv6));
    }

    let ip = ip_spec.parse::<IpAddr>().map_err(|_| {
        ProxyError::Config(format!("network.dns_overrides IP is invalid: '{ip_spec}'"))
    })?;
    if matches!(ip, IpAddr::V6(_)) {
        return Err(ProxyError::Config(format!(
            "network.dns_overrides IPv6 must be bracketed: '{ip_spec}'"
        )));
    }
    Ok(ip)
}

fn parse_entry(entry: &str) -> Result<((String, u16), IpAddr)> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return Err(ProxyError::Config(
            "network.dns_overrides entry cannot be empty".to_string(),
        ));
    }

    let first_sep = trimmed.find(':').ok_or_else(|| {
        ProxyError::Config(format!(
            "network.dns_overrides entry must use host:port:ip format: '{trimmed}'"
        ))
    })?;
    let second_sep = trimmed[first_sep + 1..]
        .find(':')
        .map(|idx| first_sep + 1 + idx)
        .ok_or_else(|| {
            ProxyError::Config(format!(
                "network.dns_overrides entry must use host:port:ip format: '{trimmed}'"
            ))
        })?;

    let host = trimmed[..first_sep].trim();
    let port_str = trimmed[first_sep + 1..second_sep].trim();
    let ip_str = trimmed[second_sep + 1..].trim();

    if host.is_empty() {
        return Err(ProxyError::Config(format!(
            "network.dns_overrides host cannot be empty: '{trimmed}'"
        )));
    }
    if host.contains(':') {
        return Err(ProxyError::Config(format!(
            "network.dns_overrides host must be a domain name without ':' in this format: '{trimmed}'"
        )));
    }

    let port = port_str.parse::<u16>().map_err(|_| {
        ProxyError::Config(format!(
            "network.dns_overrides port is invalid: '{trimmed}'"
        ))
    })?;
    let ip = parse_ip_spec(ip_str)?;

    Ok(((host.to_ascii_lowercase(), port), ip))
}

fn parse_entries(entries: &[String]) -> Result<OverrideMap> {
    if entries.len() > DNS_OVERRIDE_MAX_ENTRIES {
        return Err(ProxyError::Config(format!(
            "network.dns_overrides exceeds maximum entry count {DNS_OVERRIDE_MAX_ENTRIES}"
        )));
    }
    let mut parsed = HashMap::new();
    for entry in entries {
        let (key, ip) = parse_entry(entry)?;
        parsed.insert(key, ip);
    }
    Ok(parsed)
}

/// Validate `network.dns_overrides` entries without updating runtime state.
pub fn validate_entries(entries: &[String]) -> Result<()> {
    let _ = parse_entries(entries)?;
    Ok(())
}

/// Parse a runtime endpoint in `host:port` format.
///
/// Supports:
/// - `example.com:443`
/// - `[2001:db8::1]:443`
pub fn split_host_port(endpoint: &str) -> Option<(String, u16)> {
    if endpoint.starts_with('[') {
        let bracket_end = endpoint.find(']')?;
        if endpoint.as_bytes().get(bracket_end + 1) != Some(&b':') {
            return None;
        }
        let host = endpoint[1..bracket_end].trim();
        let port = endpoint[bracket_end + 2..].trim().parse::<u16>().ok()?;
        if host.is_empty() {
            return None;
        }
        return Some((host.to_ascii_lowercase(), port));
    }

    let split_idx = endpoint.rfind(':')?;
    let host = endpoint[..split_idx].trim();
    let port = endpoint[split_idx + 1..].trim().parse::<u16>().ok()?;
    if host.is_empty() || host.contains(':') {
        return None;
    }

    Some((host.to_ascii_lowercase(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_ipv4_and_bracketed_ipv6() {
        let entries = vec![
            "example.com:443:127.0.0.1".to_string(),
            "example.net:8443:[2001:db8::10]".to_string(),
        ];
        assert!(validate_entries(&entries).is_ok());
    }

    #[test]
    fn validate_rejects_unbracketed_ipv6() {
        let entries = vec!["example.net:443:2001:db8::10".to_string()];
        let err = validate_entries(&entries).unwrap_err().to_string();
        assert!(err.contains("must be bracketed"));
    }

    #[test]
    fn generation_resolver_updates_are_case_insensitive_for_host() {
        let entries = vec!["MyPetrovich.ru:8443:127.0.0.1".to_string()];
        let resolver = GenerationDnsResolver::from_entries(&entries).unwrap();

        assert_eq!(
            resolver.resolve_socket_addr("mypetrovich.ru", 8443),
            Some("127.0.0.1:8443".parse().unwrap())
        );
    }

    #[test]
    fn generation_snapshots_do_not_observe_each_other() {
        let first = DnsOverrides::from_entries(&["example.com:443:127.0.0.1".to_string()]).unwrap();
        let second =
            DnsOverrides::from_entries(&["example.com:443:127.0.0.2".to_string()]).unwrap();

        assert_eq!(
            first.resolve("example.com", 443),
            Some("127.0.0.1".parse().unwrap())
        );
        assert_eq!(
            second.resolve("example.com", 443),
            Some("127.0.0.2".parse().unwrap())
        );
    }

    #[test]
    fn split_host_port_parses_supported_shapes() {
        assert_eq!(
            split_host_port("example.com:443"),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(
            split_host_port("[2001:db8::1]:443"),
            Some(("2001:db8::1".to_string(), 443))
        );
        assert_eq!(split_host_port("2001:db8::1:443"), None);
    }
}
