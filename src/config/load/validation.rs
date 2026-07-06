use shadowsocks::config::ServerConfig as ShadowsocksServerConfig;
use tracing::warn;

use crate::error::{ProxyError, Result};

use super::super::types::{LoggingConfig, LoggingDestination, NetworkConfig, UpstreamType};
use super::ProxyConfig;

pub(super) fn validate_network_cfg(net: &mut NetworkConfig) -> Result<()> {
    if !net.ipv4 && matches!(net.ipv6, Some(false)) {
        return Err(ProxyError::Config(
            "Both ipv4 and ipv6 are disabled in [network]".to_string(),
        ));
    }

    if net.prefer != 4 && net.prefer != 6 {
        return Err(ProxyError::Config(
            "network.prefer must be 4 or 6".to_string(),
        ));
    }

    if !net.ipv4 && net.prefer == 4 {
        warn!("prefer=4 but ipv4=false; forcing prefer=6");
        net.prefer = 6;
    }

    if matches!(net.ipv6, Some(false)) && net.prefer == 6 {
        warn!("prefer=6 but ipv6=false; forcing prefer=4");
        net.prefer = 4;
    }

    Ok(())
}

pub(super) fn validate_logging_config(logging: &LoggingConfig) -> Result<()> {
    if let Some(path) = logging.path.as_ref()
        && path.trim().is_empty()
    {
        return Err(ProxyError::Config(
            "logging.path cannot be empty when provided".to_string(),
        ));
    }

    if matches!(logging.destination, LoggingDestination::File) && logging.path.is_none() {
        return Err(ProxyError::Config(
            "logging.path must be set when logging.destination=\"file\"".to_string(),
        ));
    }

    Ok(())
}

pub(super) fn validate_upstreams(config: &ProxyConfig) -> Result<()> {
    let has_enabled_shadowsocks = config.upstreams.iter().any(|upstream| {
        upstream.enabled && matches!(upstream.upstream_type, UpstreamType::Shadowsocks { .. })
    });

    if has_enabled_shadowsocks && config.general.use_middle_proxy {
        return Err(ProxyError::Config(
            "shadowsocks upstreams require general.use_middle_proxy = false".to_string(),
        ));
    }

    for upstream in &config.upstreams {
        if matches!(upstream.ipv4, Some(false)) && matches!(upstream.ipv6, Some(false)) {
            return Err(ProxyError::Config(
                "upstream.ipv4 and upstream.ipv6 cannot both be false".to_string(),
            ));
        }
        if let Some(prefer) = upstream.prefer
            && prefer != 4
            && prefer != 6
        {
            return Err(ProxyError::Config(
                "upstream.prefer must be 4 or 6".to_string(),
            ));
        }

        if let UpstreamType::Shadowsocks { url, .. } = &upstream.upstream_type {
            let parsed = ShadowsocksServerConfig::from_url(url)
                .map_err(|error| ProxyError::Config(format!("invalid shadowsocks url: {error}")))?;
            if parsed.plugin().is_some() {
                return Err(ProxyError::Config(
                    "shadowsocks plugins are not supported".to_string(),
                ));
            }
        }
    }

    Ok(())
}

pub(super) fn normalize_upstream_family_policy(config: &mut ProxyConfig) {
    for (idx, upstream) in config.upstreams.iter_mut().enumerate() {
        if matches!(upstream.ipv4, Some(false)) && upstream.prefer == Some(4) {
            warn!(
                upstream = idx,
                "upstream.prefer=4 but upstream.ipv4=false; forcing prefer=6"
            );
            upstream.prefer = Some(6);
        }

        if matches!(upstream.ipv6, Some(false)) && upstream.prefer == Some(6) {
            warn!(
                upstream = idx,
                "upstream.prefer=6 but upstream.ipv6=false; forcing prefer=4"
            );
            upstream.prefer = Some(4);
        }
    }
}
