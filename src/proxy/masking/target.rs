use super::*;

/// Detect client type based on initial data.
pub(super) fn detect_client_type(data: &[u8]) -> &'static str {
    // Check for HTTP request
    if is_http_probe(data) {
        return "HTTP";
    }

    // Check for TLS ClientHello (0x16 = handshake, 0x03 0x01-0x03 = TLS version)
    if data.len() > 3 && data[0] == 0x16 && data[1] == 0x03 {
        return "TLS-scanner";
    }

    // Check for SSH
    if data.starts_with(b"SSH-") {
        return "SSH";
    }

    // Port scanner (very short data)
    if data.len() < 10 {
        return "port-scanner";
    }

    "unknown"
}

pub(super) fn parse_mask_host_ip_literal(host: &str) -> Option<IpAddr> {
    if host.starts_with('[') && host.ends_with(']') {
        return host[1..host.len() - 1].parse::<IpAddr>().ok();
    }
    host.parse::<IpAddr>().ok()
}

pub(super) async fn resolve_mask_target_addrs(
    mask_host: &str,
    mask_port: u16,
    upstream_manager: Option<&crate::transport::UpstreamManager>,
) -> std::io::Result<Vec<SocketAddr>> {
    if let Some(ip) = parse_mask_host_ip_literal(mask_host) {
        return Ok(vec![SocketAddr::new(ip, mask_port)]);
    }

    if let Some(upstream_manager) = upstream_manager {
        return upstream_manager
            .resolve_all(mask_host, mask_port)
            .await
            .map_err(|error| IoError::new(ErrorKind::NotFound, error.to_string()));
    }

    let addrs = timeout(MASK_TIMEOUT, lookup_host((mask_host, mask_port)))
        .await
        .map_err(|_| IoError::new(ErrorKind::TimedOut, "mask target DNS lookup timed out"))??;
    let addrs = addrs
        .take(MASK_DNS_RESULT_MAX_ADDRESSES)
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(IoError::new(
            ErrorKind::NotFound,
            "mask target DNS lookup returned no addresses",
        ));
    }

    Ok(addrs)
}

pub(super) fn matching_tls_domain_for_sni<'a>(
    config: &'a ProxyConfig,
    sni: &str,
) -> Option<&'a str> {
    if config.censorship.tls_domain.eq_ignore_ascii_case(sni) {
        return Some(config.censorship.tls_domain.as_str());
    }

    for domain in &config.censorship.tls_domains {
        if domain.eq_ignore_ascii_case(sni) {
            return Some(domain.as_str());
        }
    }

    None
}

pub(super) fn parse_exclusive_mask_target(target: &str) -> Option<MaskTcpTarget<'_>> {
    let target = target.trim();
    if target.is_empty() {
        return None;
    }

    if target.starts_with('[') {
        let end = target.find(']')?;
        if target.get(end + 1..end + 2)? != ":" {
            return None;
        }
        let port = target[end + 2..].parse::<u16>().ok()?;
        return (port > 0).then_some(MaskTcpTarget {
            host: &target[..=end],
            port,
        });
    }

    let (host, port) = target.rsplit_once(':')?;
    if host.is_empty() || host.contains(':') {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    (port > 0).then_some(MaskTcpTarget { host, port })
}

pub(super) fn exclusive_mask_target_for_sni<'a>(
    config: &'a ProxyConfig,
    sni: &str,
) -> Option<MaskTcpTarget<'a>> {
    if let Some(target) = config.censorship.exclusive_mask_targets.get(sni) {
        return Some(MaskTcpTarget {
            host: target.host.as_str(),
            port: target.port,
        });
    }
    if let Some(target) = config.censorship.exclusive_mask.get(sni) {
        return parse_exclusive_mask_target(target);
    }

    if sni.bytes().any(|byte| byte.is_ascii_uppercase()) {
        let normalized_sni = sni.to_ascii_lowercase();
        if let Some(target) = config
            .censorship
            .exclusive_mask_targets
            .get(&normalized_sni)
        {
            return Some(MaskTcpTarget {
                host: target.host.as_str(),
                port: target.port,
            });
        }
        if let Some(target) = config.censorship.exclusive_mask.get(&normalized_sni) {
            return parse_exclusive_mask_target(target);
        }
    }

    None
}

#[cfg(test)]
pub(super) fn mask_host_for_initial_data<'a>(
    config: &'a ProxyConfig,
    initial_data: &[u8],
) -> &'a str {
    mask_tcp_target_for_initial_data(config, initial_data).host
}

#[cfg(test)]
pub(super) fn mask_tcp_target_for_initial_data<'a>(
    config: &'a ProxyConfig,
    initial_data: &[u8],
) -> MaskTcpTarget<'a> {
    let sni = tls::extract_sni_from_client_hello(initial_data);
    if let Some(target) = sni
        .as_deref()
        .and_then(|sni| exclusive_mask_target_for_sni(config, sni))
    {
        return target;
    }

    default_mask_tcp_target_for_initial_data(config, initial_data, sni.as_deref())
}

pub(super) fn default_mask_tcp_target_for_initial_data<'a>(
    config: &'a ProxyConfig,
    initial_data: &[u8],
    sni: Option<&str>,
) -> MaskTcpTarget<'a> {
    let configured_mask_host = config
        .censorship
        .mask_host
        .as_deref()
        .unwrap_or(&config.censorship.tls_domain);

    if config.censorship.mask_host.is_none() && config.censorship.mask_dynamic {
        let extracted_sni = if sni.is_none() {
            tls::extract_sni_from_client_hello(initial_data)
        } else {
            None
        };
        if let Some(host) = sni
            .or(extracted_sni.as_deref())
            .and_then(|sni| matching_tls_domain_for_sni(config, sni))
        {
            return MaskTcpTarget {
                host,
                port: config.censorship.mask_port,
            };
        }
    }

    if let Some(mask_host) = config.censorship.mask_host.as_deref() {
        return MaskTcpTarget {
            host: mask_host,
            port: config.censorship.mask_port,
        };
    }

    MaskTcpTarget {
        host: configured_mask_host,
        port: config.censorship.mask_port,
    }
}
