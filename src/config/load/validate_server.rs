use super::*;

pub(super) fn validate(config: &mut ProxyConfig) -> Result<()> {
    if !(1..=MAX_API_REQUEST_BODY_LIMIT_BYTES).contains(&config.server.api.request_body_limit_bytes)
    {
        return Err(ProxyError::Config(
            "server.api.request_body_limit_bytes must be within [1, 1048576]".to_string(),
        ));
    }

    if config.server.api.minimal_runtime_cache_ttl_ms > 60_000 {
        return Err(ProxyError::Config(
            "server.api.minimal_runtime_cache_ttl_ms must be within [0, 60000]".to_string(),
        ));
    }

    if config.server.api.runtime_edge_cache_ttl_ms > 60_000 {
        return Err(ProxyError::Config(
            "server.api.runtime_edge_cache_ttl_ms must be within [0, 60000]".to_string(),
        ));
    }

    if !(1..=1000).contains(&config.server.api.runtime_edge_top_n) {
        return Err(ProxyError::Config(
            "server.api.runtime_edge_top_n must be within [1, 1000]".to_string(),
        ));
    }

    if !(16..=4096).contains(&config.server.api.runtime_edge_events_capacity) {
        return Err(ProxyError::Config(
            "server.api.runtime_edge_events_capacity must be within [16, 4096]".to_string(),
        ));
    }

    if config.server.api.listen.parse::<SocketAddr>().is_err() {
        return Err(ProxyError::Config(
            "server.api.listen must be in IP:PORT format".to_string(),
        ));
    }

    if config.server.proxy_protocol_header_timeout_ms == 0 {
        return Err(ProxyError::Config(
            "server.proxy_protocol_header_timeout_ms must be > 0".to_string(),
        ));
    }

    if config.server.listen_backlog == 0 || config.server.listen_backlog > i32::MAX as u32 {
        return Err(ProxyError::Config(format!(
            "server.listen_backlog must be within [1, {}]",
            i32::MAX
        )));
    }

    config
        .server
        .client_mss_value()
        .map_err(|error| ProxyError::Config(format!("server.client_mss {error}")))?;
    config
        .server
        .client_mss_bulk_value()
        .map_err(|error| ProxyError::Config(format!("server.client_mss_bulk {error}")))?;
    for (idx, listener) in config.server.listeners.iter().enumerate() {
        if listener.client_mss.is_some() {
            listener
                .effective_client_mss(&config.server)
                .map_err(|error| {
                    ProxyError::Config(format!("server.listeners[{idx}].client_mss {error}"))
                })?;
        }
        if listener.synlimit_seconds == 0 {
            return Err(ProxyError::Config(format!(
                "server.listeners[{idx}].synlimit_seconds must be > 0"
            )));
        }
        if listener.synlimit_hitcount == 0 {
            return Err(ProxyError::Config(format!(
                "server.listeners[{idx}].synlimit_hitcount must be > 0"
            )));
        }
        if listener.synlimit_burst == 0 {
            return Err(ProxyError::Config(format!(
                "server.listeners[{idx}].synlimit_burst must be > 0"
            )));
        }
        if listener.synlimit_ios_seconds == 0 {
            return Err(ProxyError::Config(format!(
                "server.listeners[{idx}].synlimit_ios_seconds must be > 0"
            )));
        }
        if listener.synlimit_ios_hitcount == 0 {
            return Err(ProxyError::Config(format!(
                "server.listeners[{idx}].synlimit_ios_hitcount must be > 0"
            )));
        }
        if listener.synlimit_ios_burst == 0 {
            return Err(ProxyError::Config(format!(
                "server.listeners[{idx}].synlimit_ios_burst must be > 0"
            )));
        }
        if listener.synlimit_hashlimit_expire_ms == 0 {
            return Err(ProxyError::Config(format!(
                "server.listeners[{idx}].synlimit_hashlimit_expire_ms must be > 0"
            )));
        }
        if listener.synlimit_hashlimit_size == 0 {
            return Err(ProxyError::Config(format!(
                "server.listeners[{idx}].synlimit_hashlimit_size must be > 0"
            )));
        }
    }

    if config.server.accept_permit_timeout_ms > 60_000 {
        return Err(ProxyError::Config(
            "server.accept_permit_timeout_ms must be within [0, 60000]".to_string(),
        ));
    }

    if config.server.max_pending_handshakes_per_ip > 65_535 {
        return Err(ProxyError::Config(
            "server.max_pending_handshakes_per_ip must be within [0, 65535]".to_string(),
        ));
    }

    if config.server.conntrack_control.pressure_high_watermark_pct == 0
        || config.server.conntrack_control.pressure_high_watermark_pct > 100
    {
        return Err(ProxyError::Config(
            "server.conntrack_control.pressure_high_watermark_pct must be within [1, 100]"
                .to_string(),
        ));
    }

    if config.server.conntrack_control.pressure_low_watermark_pct
        >= config.server.conntrack_control.pressure_high_watermark_pct
    {
        return Err(ProxyError::Config(
            "server.conntrack_control.pressure_low_watermark_pct must be < pressure_high_watermark_pct"
                .to_string(),
        ));
    }

    if config.server.conntrack_control.delete_budget_per_sec == 0 {
        return Err(ProxyError::Config(
            "server.conntrack_control.delete_budget_per_sec must be > 0".to_string(),
        ));
    }

    if matches!(config.server.conntrack_control.mode, ConntrackMode::Hybrid)
        && config
            .server
            .conntrack_control
            .hybrid_listener_ips
            .is_empty()
    {
        return Err(ProxyError::Config(
            "server.conntrack_control.hybrid_listener_ips must be non-empty in mode=hybrid"
                .to_string(),
        ));
    }

    if config.general.effective_me_pool_force_close_secs() > 0
        && config.general.effective_me_pool_force_close_secs()
            < config.general.me_pool_drain_ttl_secs
    {
        warn!(
            me_pool_drain_ttl_secs = config.general.me_pool_drain_ttl_secs,
            me_reinit_drain_timeout_secs = config.general.effective_me_pool_force_close_secs(),
            "force-close timeout is lower than drain TTL; bumping force-close timeout to TTL"
        );
        config.general.me_reinit_drain_timeout_secs = config.general.me_pool_drain_ttl_secs;
    }

    // Validate secrets.
    for (user, secret) in &config.access.users {
        if !secret.chars().all(|c| c.is_ascii_hexdigit()) || secret.len() != 32 {
            return Err(ProxyError::InvalidSecret {
                user: user.clone(),
                reason: "Must be 32 hex characters".to_string(),
            });
        }
    }

    config.censorship.tls_domain =
        normalize_domain_to_ascii(&config.censorship.tls_domain, "censorship.tls_domain")?;

    // Validate mask_unix_sock.
    if let Some(ref sock_path) = config.censorship.mask_unix_sock {
        if sock_path.is_empty() {
            return Err(ProxyError::Config(
                "mask_unix_sock cannot be empty".to_string(),
            ));
        }
        #[cfg(unix)]
        if sock_path.len() > 107 {
            return Err(ProxyError::Config(format!(
                "mask_unix_sock path too long: {} bytes (max 107)",
                sock_path.len()
            )));
        }
        #[cfg(not(unix))]
        return Err(ProxyError::Config(
            "mask_unix_sock is only supported on Unix platforms".to_string(),
        ));

        if config.censorship.mask_host.is_some() {
            return Err(ProxyError::Config(
                "mask_unix_sock and mask_host are mutually exclusive".to_string(),
            ));
        }
    }

    if let Some(mask_host) = config.censorship.mask_host.as_mut() {
        *mask_host = normalize_mask_host_to_ascii(mask_host, "censorship.mask_host")?;
    }

    for (domain, target) in &config.censorship.exclusive_mask {
        if !is_valid_tls_domain_name(domain) {
            return Err(ProxyError::Config(format!(
                "Invalid censorship.exclusive_mask domain: '{}'. Must be a valid domain name",
                domain
            )));
        }
        if parse_exclusive_mask_target(target).is_none() {
            return Err(ProxyError::Config(format!(
                "Invalid censorship.exclusive_mask target for '{}': '{}'. Expected host:port with port > 0",
                domain, target
            )));
        }
    }
    Ok(())
}
