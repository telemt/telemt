//! Runtime DNS overrides for `host:port` targets.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{OnceLock, RwLock};

use crate::error::{ProxyError, Result};

type OverrideMap = HashMap<(String, u16), IpAddr>;

static DNS_OVERRIDES: OnceLock<RwLock<OverrideMap>> = OnceLock::new();

fn overrides_store() -> &'static RwLock<OverrideMap> {
    DNS_OVERRIDES.get_or_init(|| RwLock::new(HashMap::new()))
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
        ProxyError::Config(format!(
            "network.dns_overrides IP is invalid: '{ip_spec}'"
        ))
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

/// Replace runtime DNS overrides with a new validated snapshot.
pub fn install_entries(entries: &[String]) -> Result<()> {
    let parsed = parse_entries(entries)?;
    let mut guard = overrides_store()
        .write()
        .map_err(|_| ProxyError::Config("network.dns_overrides runtime lock is poisoned".to_string()))?;
    *guard = parsed;
    Ok(())
}

/// Resolve a hostname override for `(host, port)` if present.
pub fn resolve(host: &str, port: u16) -> Option<IpAddr> {
    let key = (host.to_ascii_lowercase(), port);
    overrides_store()
        .read()
        .ok()
        .and_then(|guard| guard.get(&key).copied())
}

/// Resolve a hostname override and construct a socket address when present.
pub fn resolve_socket_addr(host: &str, port: u16) -> Option<SocketAddr> {
    resolve(host, port).map(|ip| SocketAddr::new(ip, port))
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
    fn install_and_resolve_are_case_insensitive_for_host() {
        let entries = vec!["MyPetrovich.ru:8443:127.0.0.1".to_string()];
        install_entries(&entries).unwrap();

        let resolved = resolve("mypetrovich.ru", 8443);
        assert_eq!(resolved, Some("127.0.0.1".parse().unwrap()));
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
