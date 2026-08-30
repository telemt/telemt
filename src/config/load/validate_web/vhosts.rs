use super::*;

pub(super) fn validate_vhosts(config: &mut ProxyConfig) -> Result<()> {
    let limits = &config.web.limits;
    if config.web.vhosts.len() > limits.max_vhosts {
        return config_error("web.vhosts exceeds web.limits.max_vhosts");
    }
    let mut hosts = HashSet::with_capacity(config.web.vhosts.len());
    let mut profile_count = 0usize;
    for (vhost_idx, vhost) in config.web.vhosts.iter_mut().enumerate() {
        vhost.host = normalize_web_host(&vhost.host, &format!("web.vhosts[{vhost_idx}].host"))?;
        if !hosts.insert(vhost.host.clone()) {
            return config_error(&format!("duplicate WEB vhost host `{}`", vhost.host));
        }
        if vhost.public_addr.port() != 443 || vhost.public_addr.ip().is_unspecified() {
            return config_error(&format!(
                "web.vhosts[{vhost_idx}].public_addr must be a concrete socket address on port 443"
            ));
        }
        if config.web.enabled && vhost.profiles.is_empty() {
            return config_error(&format!(
                "web.vhosts[{vhost_idx}].profiles must be non-empty when web.enabled=true"
            ));
        }
        validate_decoy(vhost_idx, &vhost.decoy)?;
        let mut profiles = HashSet::with_capacity(vhost.profiles.len());
        for (profile_idx, profile) in vhost.profiles.iter().enumerate() {
            if profile.user.is_empty() || profile.user.len() > 64 {
                return config_error(&format!(
                    "web.vhosts[{vhost_idx}].profiles[{profile_idx}].user must contain 1..64 bytes"
                ));
            }
            if !config.access.users.contains_key(&profile.user) {
                return config_error(&format!(
                    "web.vhosts[{vhost_idx}].profiles[{profile_idx}].user references unknown access user `{}`",
                    profile.user
                ));
            }
            if !profiles.insert((profile.user.as_str(), profile.secret_mode)) {
                return config_error(&format!(
                    "duplicate WEB profile for user `{}` in vhost `{}`",
                    profile.user, vhost.host
                ));
            }
            let max_streams = profile.max_streams.unwrap_or(limits.max_streams_global);
            let max_streams_per_session = profile
                .max_streams_per_session
                .unwrap_or(limits.max_streams_per_session);
            if profile.max_sessions == Some(0)
                || profile
                    .max_sessions
                    .is_some_and(|value| value > limits.max_sessions_global)
                || profile.max_streams == Some(0)
                || profile
                    .max_streams
                    .is_some_and(|value| value > limits.max_streams_global)
                || profile.max_streams_per_session == Some(0)
                || profile
                    .max_streams_per_session
                    .is_some_and(|value| value > limits.max_streams_per_session)
                || max_streams_per_session > max_streams
            {
                return config_error(&format!(
                    "web.vhosts[{vhost_idx}].profiles[{profile_idx}] limits must be non-zero and within global WEB limits"
                ));
            }
            profile_count = profile_count.checked_add(1).ok_or_else(|| {
                ProxyError::Config("WEB profile count overflowed usize".to_string())
            })?;
        }
    }
    if profile_count > limits.max_profiles {
        return config_error("WEB profiles exceed web.limits.max_profiles");
    }
    Ok(())
}

pub(super) fn normalize_web_host(value: &str, field: &str) -> Result<String> {
    let input = value.trim();
    if input.is_empty()
        || input.ends_with('.')
        || input
            .chars()
            .any(|character| matches!(character, ':' | '/' | '?' | '#' | '@'))
    {
        return config_error(&format!(
            "{field} must be a hostname without a port, path, credentials, or trailing dot"
        ));
    }
    let host = normalize_domain_to_ascii(input, field)?;
    if host.len() > 253
        || !host.contains('.')
        || host.parse::<IpAddr>().is_ok()
        || web_host_last_label_is_numeric(&host)
    {
        return config_error(&format!(
            "{field} must be a non-IP fully-qualified hostname accepted by Telegram Desktop"
        ));
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return config_error(&format!(
                "{field} contains a hostname label rejected by Telegram Desktop"
            ));
        }
    }
    Ok(host)
}

pub(super) fn web_host_last_label_is_numeric(host: &str) -> bool {
    let label = host.rsplit('.').next().unwrap_or_default();
    let digits = label
        .strip_prefix("0x")
        .or_else(|| label.strip_prefix("0X"));
    if let Some(digits) = digits {
        return digits.bytes().all(|byte| byte.is_ascii_hexdigit());
    }
    label.bytes().all(|byte| byte.is_ascii_digit())
}

pub(super) fn validate_decoy(vhost_idx: usize, decoy: &WebDecoyConfig) -> Result<()> {
    match decoy {
        WebDecoyConfig::HttpUpstream { upstream } => {
            let parsed = url::Url::parse(upstream).map_err(|error| {
                ProxyError::Config(format!(
                    "web.vhosts[{vhost_idx}].decoy.upstream is invalid: {error}"
                ))
            })?;
            if parsed.scheme() != "http"
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.query().is_some()
                || parsed.fragment().is_some()
                || parsed.path() != "/"
                || parsed.port() == Some(0)
            {
                return config_error(&format!(
                    "web.vhosts[{vhost_idx}].decoy.upstream must be an http origin without credentials, path, query, or fragment"
                ));
            }
            let ip = match parsed.host() {
                Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip),
                Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip),
                _ => {
                    return config_error(&format!(
                        "web.vhosts[{vhost_idx}].decoy.upstream host must be a loopback or private IP literal"
                    ));
                }
            };
            let private = match ip {
                IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
                IpAddr::V6(ip) => {
                    ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
                }
            };
            if !private {
                return config_error(&format!(
                    "web.vhosts[{vhost_idx}].decoy.upstream must remain inside loopback or a private network"
                ));
            }
        }
        WebDecoyConfig::StaticDirectory { directory, index } => {
            if !directory.is_absolute() {
                return config_error(&format!(
                    "web.vhosts[{vhost_idx}].decoy.directory must be absolute"
                ));
            }
            if index.is_empty()
                || index.contains('\\')
                || std::path::Path::new(index).components().count() != 1
                || matches!(index.as_str(), "." | "..")
            {
                return config_error(&format!(
                    "web.vhosts[{vhost_idx}].decoy.index must be one safe file name"
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn config_error<T>(message: &str) -> Result<T> {
    Err(ProxyError::Config(message.to_string()))
}
