use super::*;

const WEB_DEBUG_RENDERERS: usize = 2;
const WEB_DEBUG_STATUS_PAGE_BYTES: usize = 8 * 1024 * 1024;
const WEB_DEBUG_GROUP_SCRATCH_BYTES: usize = 4 * 1024 * 1024;
const WEB_CARRIER_LEARNING_ENTRY_BYTES: usize = 512;
const WEB_LANE_STATE_BYTES: usize = 512;

/// Validates process-wide body, header, queue, static, and debug reservations.
pub(super) fn validate(limits: &WebLimitsConfig) -> Result<()> {
    if limits.max_carrier_learning_entries == 0 {
        return config_error("web.limits.max_carrier_learning_entries must be > 0");
    }
    let body_reservation = limits
        .max_body_readers
        .checked_mul(limits.max_body_bytes)
        .ok_or_else(|| {
            ProxyError::Config("web.limits body reader reservation overflowed usize".to_string())
        })?;
    if body_reservation > limits.max_body_bytes_global
        || limits.max_body_bytes_global > u32::MAX as usize
    {
        return config_error(
            "web.limits max_body_readers * max_body_bytes must fit max_body_bytes_global and u32",
        );
    }
    let http_header_reservation = limits
        .max_http_connections
        .checked_mul(limits.max_header_bytes)
        .ok_or_else(|| {
            ProxyError::Config("web.limits HTTP header reservations overflow usize".to_string())
        })?;
    let debug_ring_index = limits
        .debug_records_capacity
        .checked_mul(std::mem::size_of::<usize>())
        .ok_or_else(|| ProxyError::Config("web.limits debug index overflowed usize".to_string()))?;
    let status_pages = WEB_DEBUG_RENDERERS
        .checked_mul(WEB_DEBUG_STATUS_PAGE_BYTES)
        .ok_or_else(|| ProxyError::Config("web.debug status pages overflowed usize".to_string()))?;
    let debug_reservation = limits
        .debug_bytes_global
        .checked_add(
            debug_ring_index
                .checked_mul(WEB_DEBUG_RENDERERS)
                .ok_or_else(|| {
                    ProxyError::Config("web.debug snapshot indexes overflowed usize".to_string())
                })?,
        )
        .and_then(|value| {
            WEB_DEBUG_RENDERERS
                .checked_mul(WEB_DEBUG_GROUP_SCRATCH_BYTES)
                .and_then(|scratch| value.checked_add(scratch))
        })
        .ok_or_else(|| ProxyError::Config("web.debug reservations overflowed usize".to_string()))?;
    let carrier_learning_reservation = limits
        .max_carrier_learning_entries
        .checked_mul(WEB_CARRIER_LEARNING_ENTRY_BYTES)
        .ok_or_else(|| {
            ProxyError::Config("web.carrier learning reservation overflowed usize".to_string())
        })?;
    let lane_state_reservation = limits
        .max_streams_per_session
        .checked_add(limits.max_tombstones_per_session)
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_mul(limits.max_sessions_global))
        .and_then(|value| value.checked_mul(WEB_LANE_STATE_BYTES))
        .ok_or_else(|| {
            ProxyError::Config("web.limits lane state reservation overflowed usize".to_string())
        })?;
    let reserved = limits
        .pending_bytes_global
        .checked_add(limits.max_body_bytes_global)
        .and_then(|value| value.checked_add(limits.max_static_bytes))
        .and_then(|value| value.checked_add(debug_ring_index))
        .and_then(|value| value.checked_add(status_pages))
        .and_then(|value| value.checked_add(debug_reservation))
        .and_then(|value| value.checked_add(carrier_learning_reservation))
        .and_then(|value| value.checked_add(lane_state_reservation))
        .and_then(|value| value.checked_add(http_header_reservation))
        .ok_or_else(|| ProxyError::Config("web.limits byte ceilings overflow usize".to_string()))?;
    if reserved > limits.memory_envelope_bytes {
        return config_error("web.limits memory reservations must fit memory_envelope_bytes");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn operator_budget_above_four_gib_is_accepted() {
        let limits = WebLimitsConfig {
            pending_bytes_global: 5 * 1024 * 1024 * 1024,
            memory_envelope_bytes: 8 * 1024 * 1024 * 1024,
            ..WebLimitsConfig::default()
        };
        assert!(validate(&limits).is_ok());
    }

    #[test]
    fn configured_envelope_still_rejects_overcommit() {
        let defaults = WebLimitsConfig::default();
        let limits = WebLimitsConfig {
            pending_bytes_global: defaults.memory_envelope_bytes,
            ..defaults
        };
        assert!(matches!(
            validate(&limits),
            Err(ProxyError::Config(message))
                if message == "web.limits memory reservations must fit memory_envelope_bytes"
        ));
    }

    #[test]
    fn configured_envelope_still_rejects_overflow() {
        let limits = WebLimitsConfig {
            pending_bytes_global: usize::MAX,
            memory_envelope_bytes: usize::MAX,
            ..WebLimitsConfig::default()
        };
        assert!(matches!(
            validate(&limits),
            Err(ProxyError::Config(message))
                if message == "web.limits byte ceilings overflow usize"
        ));
    }

    #[test]
    fn default_envelope_includes_bounded_lane_and_learning_metadata() {
        let limits = WebLimitsConfig::default();
        assert!(validate(&limits).is_ok());

        let previous_envelope = WebLimitsConfig {
            memory_envelope_bytes: 768 * 1024 * 1024,
            ..limits
        };
        assert!(validate(&previous_envelope).is_err());
    }
}
