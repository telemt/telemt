use super::*;

/// Bounds exact bindings and wildcard rules before normalizing hostname selectors.
pub(super) fn validate_vhosts(config: &mut ProxyConfig) -> Result<()> {
    let limits = &config.web.limits;
    let mut host_count = 0usize;
    let mut rule_count = 0usize;
    let mut profile_count = 0usize;
    for (vhost_idx, vhost) in config.web.vhosts.iter().enumerate() {
        match (&vhost.host, &vhost.hosts) {
            (Some(_), None) => {}
            (None, Some(hosts)) if !hosts.is_empty() => {}
            _ => {
                return config_error(&format!(
                    "web.vhosts[{vhost_idx}] requires exactly one of host or non-empty hosts"
                ));
            }
        }
        let selectors = vhost.host.iter().chain(vhost.hosts.iter().flatten());
        let patterns = selectors
            .clone()
            .filter(|host| host.trim().starts_with('*'))
            .count();
        let exact = selectors.count() - patterns;
        rule_count = rule_count.checked_add(patterns).ok_or_else(|| {
            ProxyError::Config("WEB wildcard rule count overflowed usize".to_string())
        })?;
        if patterns > 0
            && (!config.web.allow_wildcard_hosts
                || rule_count > limits.wildcard.max_rules
                || vhost.profiles.len() > limits.wildcard.max_profiles_per_request)
        {
            return config_error(&format!(
                "web.vhosts[{vhost_idx}] wildcard selectors require allow_wildcard_hosts and must fit web.limits.wildcard bounds"
            ));
        }
        host_count = host_count
            .checked_add(exact)
            .ok_or_else(|| ProxyError::Config("WEB hostname count overflowed usize".to_string()))?;
        profile_count = exact
            .checked_add(usize::from(patterns > 0))
            .and_then(|count| count.checked_mul(vhost.profiles.len()))
            .and_then(|expanded| profile_count.checked_add(expanded))
            .ok_or_else(|| ProxyError::Config("WEB profile count overflowed usize".to_string()))?;
        if host_count > limits.max_vhosts {
            return config_error("web.vhosts exceeds web.limits.max_vhosts");
        }
        if profile_count > limits.max_profiles {
            return config_error("WEB profiles exceed web.limits.max_profiles");
        }
    }
    let mut hosts = HashSet::with_capacity(host_count);
    for (vhost_idx, vhost) in config.web.vhosts.iter_mut().enumerate() {
        let single = vhost.host.is_some();
        for (host_idx, host) in vhost
            .host
            .iter_mut()
            .chain(vhost.hosts.iter_mut().flatten())
            .enumerate()
        {
            let field = if single {
                format!("web.vhosts[{vhost_idx}].host")
            } else {
                format!("web.vhosts[{vhost_idx}].hosts[{host_idx}]")
            };
            *host = if config.web.allow_wildcard_hosts && host.trim() == "*" {
                "*".to_string()
            } else if config.web.allow_wildcard_hosts
                && let Some(suffix) = host.trim().strip_prefix("*.")
            {
                let normalized = normalize_web_host(&format!("x.{suffix}"), &field)?;
                format!("*.{}", &normalized[2..])
            } else {
                normalize_web_host(host, &field)?
            };
            if !hosts.insert(host.clone()) {
                return config_error(&format!("duplicate WEB vhost host `{host}` at {field}"));
            }
        }
        validate_web_base_path(
            &vhost.base_path,
            &format!("web.vhosts[{vhost_idx}].base_path"),
        )?;
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
                    "duplicate WEB profile for user `{}` in web.vhosts[{vhost_idx}]",
                    profile.user
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
        }
    }
    Ok(())
}

fn validate_web_base_path(value: &str, field: &str) -> Result<()> {
    let valid = value.len() <= 128
        && !value.starts_with('/')
        && !value.ends_with('/')
        && value.split('/').all(|segment| {
            let mut bytes = segment.bytes();
            bytes
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        });
    if value.is_empty() || valid {
        return Ok(());
    }
    config_error(&format!(
        "{field} must be empty or contain at most 128 ASCII bytes in slash-separated [A-Za-z0-9][A-Za-z0-9_-]* segments"
    ))
}

/// Applies the client-compatible hostname rules only during configuration loading.
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

/// Rejects numeric suffixes that clients may interpret as address literals.
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

/// Validates one group's ordinary-site origin or bounded static snapshot source.
pub(super) fn validate_decoy(vhost_idx: usize, decoy: &WebDecoyConfig) -> Result<()> {
    match decoy {
        WebDecoyConfig::HttpUpstream { upstream, resolve } => {
            decoy_dns::parse_origin(vhost_idx, upstream, *resolve)?;
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
