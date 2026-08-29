use super::*;

/// Validates WEB request, learning, and lifecycle timeouts.
pub(super) fn validate(timeouts: &WebTimeoutsConfig) -> Result<()> {
    if !(1..=60_000).contains(&timeouts.http_overload_timeout_ms) {
        return config_error("web.timeouts.http_overload_timeout_ms must be within [1, 60000]");
    }
    let values = [
        ("header_secs", timeouts.header_secs),
        ("body_secs", timeouts.body_secs),
        ("stream_handshake_secs", timeouts.stream_handshake_secs),
        ("stream_first_byte_secs", timeouts.stream_first_byte_secs),
        ("long_poll_secs", timeouts.long_poll_secs),
        ("lane_open_wait_secs", timeouts.lane_open_wait_secs),
        ("carrier_health_secs", timeouts.carrier_health_secs),
        ("websocket_upgrade_secs", timeouts.websocket_upgrade_secs),
        ("websocket_open_secs", timeouts.websocket_open_secs),
        ("websocket_write_secs", timeouts.websocket_write_secs),
        (
            "websocket_backpressure_secs",
            timeouts.websocket_backpressure_secs,
        ),
        ("websocket_eviction_secs", timeouts.websocket_eviction_secs),
        ("bootstrap_lifetime_secs", timeouts.bootstrap_lifetime_secs),
        ("reconnect_grace_secs", timeouts.reconnect_grace_secs),
        ("http_idle_secs", timeouts.http_idle_secs),
        ("shutdown_secs", timeouts.shutdown_secs),
        ("decoy_header_secs", timeouts.decoy_header_secs),
    ];
    if let Some((field, _)) = values
        .into_iter()
        .find(|(_, value)| !(1..=3600).contains(value))
    {
        return config_error(&format!("web.timeouts.{field} must be within [1, 3600]"));
    }
    if !(2..=86_400).contains(&timeouts.carrier_learning_secs) {
        return config_error("web.timeouts.carrier_learning_secs must be within [2, 86400]");
    }
    if !(1..=60).contains(&timeouts.bridge_request_secs) {
        return config_error("web.timeouts.bridge_request_secs must be within [1, 60]");
    }
    if !(1..=300).contains(&timeouts.bridge_retry_secs) {
        return config_error("web.timeouts.bridge_retry_secs must be within [1, 300]");
    }
    if timeouts.bridge_request_secs > timeouts.bridge_retry_secs {
        return config_error("web.timeouts.bridge_request_secs must not exceed bridge_retry_secs");
    }
    if timeouts.carrier_probe_coalesce_ms > 10 {
        return config_error("web.timeouts.carrier_probe_coalesce_ms must be within [0, 10]");
    }
    if timeouts.stream_first_byte_secs > 300 {
        return config_error("web.timeouts.stream_first_byte_secs must be within [1, 300]");
    }
    if timeouts.websocket_upgrade_secs > 60 {
        return config_error("web.timeouts.websocket_upgrade_secs must be within [1, 60]");
    }
    if timeouts.websocket_open_secs > 300 {
        return config_error("web.timeouts.websocket_open_secs must be within [1, 300]");
    }
    if timeouts.lane_open_wait_secs > timeouts.long_poll_secs {
        return config_error("web.timeouts.lane_open_wait_secs must not exceed long_poll_secs");
    }
    if timeouts.carrier_health_secs > timeouts.reconnect_grace_secs {
        return config_error(
            "web.timeouts.carrier_health_secs must not exceed reconnect_grace_secs",
        );
    }
    let request_deadline = timeouts
        .header_secs
        .max(timeouts.body_secs)
        .max(timeouts.long_poll_secs)
        .max(timeouts.decoy_header_secs);
    if request_deadline >= timeouts.http_idle_secs {
        return config_error("web.timeouts request deadlines must be lower than http_idle_secs");
    }
    Ok(())
}
