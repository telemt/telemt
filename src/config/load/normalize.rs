use crate::error::{ProxyError, Result};
use tracing::warn;

pub(super) fn is_valid_tls_domain_name(domain: &str) -> bool {
    !domain.is_empty()
        && !domain
            .chars()
            .any(|ch| ch.is_whitespace() || matches!(ch, '/' | '\\'))
}

pub(super) fn normalize_domain_to_ascii(domain: &str, field: &str) -> Result<String> {
    let domain = domain.trim();
    if !is_valid_tls_domain_name(domain) {
        return Err(ProxyError::Config(format!(
            "Invalid {field}: '{}'. Must be a valid domain name",
            domain
        )));
    }

    let parsed = url::Url::parse(&format!("https://{domain}/")).map_err(|error| {
        ProxyError::Config(format!(
            "Invalid {field}: '{}'. IDNA conversion failed: {error}",
            domain
        ))
    })?;
    let host = parsed.host_str().ok_or_else(|| {
        ProxyError::Config(format!("Invalid {field}: '{}'. Host is empty", domain))
    })?;
    Ok(host.to_ascii_lowercase())
}

pub(super) fn normalize_mask_host_to_ascii(host: &str, field: &str) -> Result<String> {
    let host = host.trim();
    if host.starts_with('[') && host.ends_with(']') {
        let inner = &host[1..host.len() - 1];
        let ip = inner.parse::<std::net::IpAddr>().map_err(|_| {
            ProxyError::Config(format!(
                "Invalid {field}: '{}'. IPv6 literal is invalid",
                host
            ))
        })?;
        return match ip {
            std::net::IpAddr::V6(v6) => Ok(format!("[{v6}]")),
            std::net::IpAddr::V4(v4) => Ok(v4.to_string()),
        };
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => Ok(v4.to_string()),
            std::net::IpAddr::V6(v6) => Ok(format!("[{v6}]")),
        };
    }

    normalize_domain_to_ascii(host, field)
}

pub(super) fn parse_exclusive_mask_target(target: &str) -> Option<(&str, u16)> {
    let target = target.trim();
    if target.is_empty() {
        return None;
    }

    if target.starts_with('[') {
        let end = target.find(']')?;
        if target.get(end + 1..end + 2)? != ":" {
            return None;
        }
        let host = &target[..=end];
        let port = target[end + 2..].parse::<u16>().ok()?;
        return (port > 0).then_some((host, port));
    }

    let (host, port) = target.rsplit_once(':')?;
    if host.is_empty() || host.contains(':') {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    (port > 0).then_some((host, port))
}

pub(super) fn normalize_exclusive_mask_target(target: &str, field: &str) -> Result<String> {
    let (host, port) = parse_exclusive_mask_target(target).ok_or_else(|| {
        ProxyError::Config(format!(
            "Invalid {field}: '{}'. Expected host:port with port > 0",
            target
        ))
    })?;
    let host = normalize_mask_host_to_ascii(host, field)?;
    Ok(format!("{host}:{port}"))
}

pub(super) fn push_unique_nonempty(target: &mut Vec<String>, value: String) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }
    if !target.iter().any(|existing| existing == trimmed) {
        target.push(trimmed.to_string());
    }
}

pub(super) fn is_valid_ad_tag(tag: &str) -> bool {
    tag.len() == 32 && tag.chars().all(|ch| ch.is_ascii_hexdigit())
}

pub(super) fn sanitize_ad_tag(ad_tag: &mut Option<String>) {
    let Some(tag) = ad_tag.as_ref() else {
        return;
    };

    if !is_valid_ad_tag(tag) {
        warn!("Invalid general.ad_tag value, expected exactly 32 hex chars; ad_tag is disabled");
        *ad_tag = None;
    }
}
