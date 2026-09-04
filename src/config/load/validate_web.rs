use std::collections::HashSet;

use super::*;

// Debug capture validation is independent from restart-only storage limits.
mod debug;
// Memory-envelope arithmetic remains isolated from protocol validation.
mod memory;
// Carrier ordering, cumulative deadlines, and fallback identity are validated together.
mod negotiation;
// Request and lifecycle timeout relationships are validated together.
mod timeouts;
// WebSocket transport policy is validated independently from HTTP body policy.
mod websocket;

const WEB_FRAME_HEADER_BYTES: usize = 8;
const WEB_QUEUE_ITEM_COST: usize = 256;
const WEB_CONTROL_EXTRA_ITEMS: usize = 16;
const WEB_CONTROL_ITEMS_PER_STREAM: usize = 3;
const WEB_INITIAL_STREAM_WINDOW: usize = 4 * 1024 * 1024;
const MAX_WEB_HEADER_BYTES: usize = 64 * 1024;
const MAX_WEB_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_WEB_FRAME_BYTES: usize = 1024 * 1024;
const MAX_WEB_FRAMES_PER_BODY: usize = 4096;
const MAX_WEB_TOMBSTONES_PER_SESSION: usize = 4096;

/// Validates WEB policy and resource bounds before building runtime state.
pub(super) fn validate(config: &mut ProxyConfig) -> Result<()> {
    let web_listener_count = config
        .server
        .listeners
        .iter()
        .filter(|listener| listener.transport == ListenerTransport::Web)
        .count();
    let eligible_web_listener_count = config
        .server
        .listeners
        .iter()
        .filter(|listener| listener.transport == ListenerTransport::Web)
        .filter(|listener| {
            (listener.ip.is_ipv4() && config.network.ipv4)
                || (listener.ip.is_ipv6() && config.network.ipv6 != Some(false))
        })
        .count();

    for (idx, listener) in config.server.listeners.iter().enumerate() {
        match listener.transport {
            ListenerTransport::Mtproxy => {
                if !listener.web_trusted_proxy_cidrs.is_empty() {
                    return Err(ProxyError::Config(format!(
                        "server.listeners[{idx}].web_trusted_proxy_cidrs is only valid for transport=web"
                    )));
                }
            }
            ListenerTransport::Web => validate_web_listener(config, idx, listener)?,
        }
    }

    if config.web.enabled && eligible_web_listener_count == 0 {
        return Err(ProxyError::Config(
            "web.enabled requires at least one network-eligible server.listeners entry with transport=web"
                .to_string(),
        ));
    }
    if web_listener_count > 0 && config.web.vhosts.is_empty() {
        return Err(ProxyError::Config(
            "WEB listeners require at least one [[web.vhosts]] entry".to_string(),
        ));
    }

    validate_limits(&config.web.limits)?;
    debug::validate(&config.web.debug, &config.web.limits)?;
    let carriers = negotiation::validate(&config.web)?;
    if carriers.contains(&WebCarrier::Https) && config.web.limits.max_http_handlers < 2 {
        return config_error("WEB https candidates require web.limits.max_http_handlers >= 2");
    }
    if carriers.contains(&WebCarrier::HttpsLanes) && config.web.limits.max_http_handlers < 4 {
        return config_error(
            "WEB https-lanes candidates require web.limits.max_http_handlers >= 4",
        );
    }
    timeouts::validate(&config.web.timeouts)?;
    websocket::validate(&carriers, &config.web.limits, &config.web.timeouts)?;
    validate_vhosts(config)?;
    Ok(())
}

fn validate_web_listener(
    config: &ProxyConfig,
    idx: usize,
    listener: &ListenerConfig,
) -> Result<()> {
    if listener.web_trusted_proxy_cidrs.is_empty() {
        return Err(ProxyError::Config(format!(
            "server.listeners[{idx}].web_trusted_proxy_cidrs must be non-empty for transport=web"
        )));
    }
    if listener
        .web_trusted_proxy_cidrs
        .iter()
        .any(|network| network.prefix() == 0)
    {
        return Err(ProxyError::Config(format!(
            "server.listeners[{idx}].web_trusted_proxy_cidrs must not contain a /0 network"
        )));
    }
    let proxy_protocol = listener
        .proxy_protocol
        .unwrap_or(config.server.proxy_protocol);
    if proxy_protocol {
        return Err(ProxyError::Config(format!(
            "server.listeners[{idx}].proxy_protocol must be false for transport=web; WEB identity is accepted only from the configured L7 header"
        )));
    }
    if listener.reuse_allow {
        return Err(ProxyError::Config(format!(
            "server.listeners[{idx}].reuse_allow is not supported for transport=web without external session affinity"
        )));
    }
    if listener.client_mss.is_some()
        || listener.synlimit != SynLimitMode::Off
        || listener.announce.is_some()
        || listener.announce_ip.is_some()
    {
        return Err(ProxyError::Config(format!(
            "server.listeners[{idx}] WEB transport does not accept client_mss, synlimit, announce, or announce_ip"
        )));
    }
    Ok(())
}

fn validate_limits(limits: &WebLimitsConfig) -> Result<()> {
    if !(8192..=MAX_WEB_HEADER_BYTES).contains(&limits.max_header_bytes) {
        return config_error("web.limits.max_header_bytes must be within [8192, 65536]");
    }
    if !(WEB_FRAME_HEADER_BYTES..=MAX_WEB_BODY_BYTES).contains(&limits.max_body_bytes) {
        return config_error("web.limits.max_body_bytes must be within [8, 16777216]");
    }
    if !(1..=MAX_WEB_FRAME_BYTES).contains(&limits.max_frame_payload_bytes) {
        return config_error("web.limits.max_frame_payload_bytes must be within [1, 1048576]");
    }
    if !(1..=MAX_WEB_FRAMES_PER_BODY).contains(&limits.max_frames_per_body) {
        return config_error("web.limits.max_frames_per_body must be within [1, 4096]");
    }
    if !(1..=MAX_WEB_TOMBSTONES_PER_SESSION).contains(&limits.max_tombstones_per_session) {
        return config_error("web.limits.max_tombstones_per_session must be within [1, 4096]");
    }
    if limits.pending_bytes_per_lane <= WEB_FRAME_HEADER_BYTES + WEB_QUEUE_ITEM_COST {
        return config_error(
            "web.limits.pending_bytes_per_lane must preserve one non-empty DATA frame",
        );
    }
    if limits.carrier_batch_bytes > limits.max_body_bytes
        || limits.carrier_batch_bytes
            < limits
                .max_frame_payload_bytes
                .saturating_add(WEB_FRAME_HEADER_BYTES)
    {
        return config_error(
            "web.limits.carrier_batch_bytes must fit max_body_bytes and one maximum frame",
        );
    }
    if limits.max_frame_payload_bytes > WEB_INITIAL_STREAM_WINDOW {
        return config_error(
            "web.limits.max_frame_payload_bytes must not exceed the initial stream window",
        );
    }

    let positive = [
        ("max_http_connections", limits.max_http_connections),
        ("max_http_handlers", limits.max_http_handlers),
        (
            "max_lane_open_waits_per_session",
            limits.max_lane_open_waits_per_session,
        ),
        ("pending_bytes_per_lane", limits.pending_bytes_per_lane),
        ("pending_items_per_lane", limits.pending_items_per_lane),
        (
            "max_websocket_evictions_in_flight",
            limits.max_websocket_evictions_in_flight,
        ),
        (
            "max_carrier_learning_entries",
            limits.max_carrier_learning_entries,
        ),
        ("max_body_readers", limits.max_body_readers),
        ("max_body_bytes_global", limits.max_body_bytes_global),
        ("max_sessions_global", limits.max_sessions_global),
        ("max_sessions_per_ip", limits.max_sessions_per_ip),
        ("max_streams_per_session", limits.max_streams_per_session),
        ("max_streams_global", limits.max_streams_global),
        ("max_stream_handshakes", limits.max_stream_handshakes),
        (
            "pending_bytes_per_session",
            limits.pending_bytes_per_session,
        ),
        ("pending_bytes_global", limits.pending_bytes_global),
        (
            "pending_items_per_session",
            limits.pending_items_per_session,
        ),
        ("pending_items_global", limits.pending_items_global),
        (
            "control_bytes_per_session",
            limits.control_bytes_per_session,
        ),
        ("control_bytes_global", limits.control_bytes_global),
        ("max_bootstraps_global", limits.max_bootstraps_global),
        ("max_bootstraps_per_ip", limits.max_bootstraps_per_ip),
        ("max_vhosts", limits.max_vhosts),
        ("max_profiles", limits.max_profiles),
        ("max_static_files", limits.max_static_files),
        ("max_static_file_bytes", limits.max_static_file_bytes),
        ("max_static_bytes", limits.max_static_bytes),
        ("debug_records_capacity", limits.debug_records_capacity),
        ("debug_bytes_global", limits.debug_bytes_global),
        ("memory_envelope_bytes", limits.memory_envelope_bytes),
    ];
    if let Some((field, _)) = positive.into_iter().find(|(_, value)| *value == 0) {
        return config_error(&format!("web.limits.{field} must be > 0"));
    }
    for (field, value) in [
        ("max_http_connections", limits.max_http_connections),
        ("max_http_handlers", limits.max_http_handlers),
        ("max_body_readers", limits.max_body_readers),
        ("max_body_bytes_global", limits.max_body_bytes_global),
        ("max_stream_handshakes", limits.max_stream_handshakes),
    ] {
        if value > tokio::sync::Semaphore::MAX_PERMITS {
            return config_error(&format!(
                "web.limits.{field} exceeds Tokio semaphore capacity"
            ));
        }
    }
    let rates = [
        (
            "new_bootstraps_per_minute",
            limits.new_bootstraps_per_minute,
        ),
        ("new_bootstraps_burst", limits.new_bootstraps_burst),
        ("new_sessions_per_minute", limits.new_sessions_per_minute),
        ("new_sessions_burst", limits.new_sessions_burst),
        ("new_streams_per_minute", limits.new_streams_per_minute),
        ("new_streams_burst", limits.new_streams_burst),
    ];
    if let Some((field, _)) = rates.into_iter().find(|(_, value)| *value == 0) {
        return config_error(&format!("web.limits.{field} must be > 0"));
    }
    if limits.max_streams_per_session > u16::MAX as usize {
        return config_error("web.limits.max_streams_per_session must fit synthetic source ports");
    }
    if limits.max_sessions_per_ip > limits.max_sessions_global
        || limits.max_streams_per_session > limits.max_streams_global
        || limits.max_stream_handshakes > limits.max_streams_global
        || limits.max_bootstraps_per_ip > limits.max_bootstraps_global
        || limits.max_http_handlers > limits.max_http_connections
        || limits.max_body_readers > limits.max_http_handlers
        || limits.max_lane_open_waits_per_session > limits.max_streams_per_session
        || limits.pending_bytes_per_session > limits.pending_bytes_global
        || limits.pending_items_per_session > limits.pending_items_global
        || limits.pending_bytes_per_lane > limits.pending_bytes_per_session
        || limits.pending_items_per_lane > limits.pending_items_per_session
        || limits.control_bytes_per_session > limits.control_bytes_global
        || limits.control_bytes_per_session > limits.pending_bytes_per_session
        || limits.control_bytes_global > limits.pending_bytes_global
        || limits.max_static_file_bytes > limits.max_static_bytes
    {
        return config_error("web.limits per-owner ceilings must not exceed global ceilings");
    }
    let control_items_per_session = WEB_CONTROL_EXTRA_ITEMS
        .checked_add(
            limits
                .max_streams_per_session
                .checked_mul(WEB_CONTROL_ITEMS_PER_STREAM)
                .ok_or_else(|| {
                    ProxyError::Config(
                        "web.limits control item reservation overflowed usize".to_string(),
                    )
                })?,
        )
        .ok_or_else(|| {
            ProxyError::Config("web.limits control item reservation overflowed usize".to_string())
        })?;
    let control_items_global = control_items_per_session
        .checked_mul(limits.max_sessions_global)
        .ok_or_else(|| {
            ProxyError::Config("web.limits global control reservation overflowed usize".to_string())
        })?;
    let control_frame_cost = WEB_FRAME_HEADER_BYTES + 4 + WEB_QUEUE_ITEM_COST;
    let required_control_bytes_per_session = control_items_per_session
        .checked_mul(control_frame_cost)
        .ok_or_else(|| {
            ProxyError::Config("web.limits control byte reservation overflowed usize".to_string())
        })?;
    let required_control_bytes_global = control_items_global
        .checked_mul(control_frame_cost)
        .ok_or_else(|| {
            ProxyError::Config(
                "web.limits global control byte reservation overflowed usize".to_string(),
            )
        })?;
    if control_items_per_session >= limits.pending_items_per_session
        || control_items_global >= limits.pending_items_global
        || required_control_bytes_per_session > limits.control_bytes_per_session
        || required_control_bytes_global > limits.control_bytes_global
    {
        return config_error(
            "web.limits control reserves must cover bounded control frames and leave data capacity",
        );
    }
    let uplink_bytes = limits
        .max_frames_per_body
        .checked_mul(WEB_QUEUE_ITEM_COST)
        .and_then(|value| value.checked_add(limits.max_body_bytes))
        .ok_or_else(|| {
            ProxyError::Config("web.limits uplink reservation overflowed usize".to_string())
        })?;
    let minimum_downlink_frame_bytes = WEB_FRAME_HEADER_BYTES + 1 + WEB_QUEUE_ITEM_COST;
    let session_required_bytes = limits
        .control_bytes_per_session
        .checked_add(uplink_bytes)
        .and_then(|value| value.checked_add(minimum_downlink_frame_bytes))
        .ok_or_else(|| {
            ProxyError::Config("web.limits session reservation overflowed usize".to_string())
        })?;
    let session_required_items = control_items_per_session
        .checked_add(limits.max_frames_per_body)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| {
            ProxyError::Config("web.limits session item reservation overflowed usize".to_string())
        })?;
    let global_required_bytes = limits
        .control_bytes_global
        .checked_add(uplink_bytes)
        .and_then(|value| value.checked_add(minimum_downlink_frame_bytes))
        .ok_or_else(|| {
            ProxyError::Config("web.limits global reservation overflowed usize".to_string())
        })?;
    let global_required_items = control_items_global
        .checked_add(limits.max_frames_per_body)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| {
            ProxyError::Config("web.limits global item reservation overflowed usize".to_string())
        })?;
    if session_required_bytes > limits.pending_bytes_per_session
        || session_required_items > limits.pending_items_per_session
        || global_required_bytes > limits.pending_bytes_global
        || global_required_items > limits.pending_items_global
    {
        return config_error(
            "web.limits pending ceilings must preserve one uplink batch and downlink progress",
        );
    }
    memory::validate(limits)?;
    Ok(())
}

fn validate_vhosts(config: &mut ProxyConfig) -> Result<()> {
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

fn normalize_web_host(value: &str, field: &str) -> Result<String> {
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

fn web_host_last_label_is_numeric(host: &str) -> bool {
    let label = host.rsplit('.').next().unwrap_or_default();
    let digits = label
        .strip_prefix("0x")
        .or_else(|| label.strip_prefix("0X"));
    if let Some(digits) = digits {
        return digits.bytes().all(|byte| byte.is_ascii_hexdigit());
    }
    label.bytes().all(|byte| byte.is_ascii_digit())
}

fn validate_decoy(vhost_idx: usize, decoy: &WebDecoyConfig) -> Result<()> {
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

fn config_error<T>(message: &str) -> Result<T> {
    Err(ProxyError::Config(message.to_string()))
}

#[cfg(test)]
mod tests;
