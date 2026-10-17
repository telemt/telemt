use super::*;

const WEB_DEBUG_RENDERERS: usize = 2;
const WEB_DEBUG_STATUS_PAGE_BYTES: usize = 8 * 1024 * 1024;
const WEB_DEBUG_GROUP_SCRATCH_BYTES: usize = 4 * 1024 * 1024;
const WEB_CARRIER_LEARNING_ENTRY_BYTES: usize = 512;
// Includes the lane plus bounded conveyor slots, Notify ownership, and both hash tables.
const WEB_LANE_STATE_BYTES: usize = 1024;
const WEB_OVERLOAD_CONNECTION_BYTES: usize = 4 * 1024;
// Each profile capability is stored in its vhost and in the global containment table.
const WEB_CAPABILITY_INDEX_ENTRY_BYTES: usize = 64;

/// Validates process-wide body, header, queue, static, and debug reservations.
pub(super) fn validate(limits: &WebLimitsConfig, wildcard: bool) -> Result<()> {
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
    let overload_connection_reservation = limits
        .max_http_overload_connections
        .checked_mul(WEB_OVERLOAD_CONNECTION_BYTES)
        .ok_or_else(|| {
            ProxyError::Config("web.limits HTTP overload reservations overflow usize".to_string())
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
    let capability_index_reservation = limits
        .max_profiles
        .checked_mul(WEB_CAPABILITY_INDEX_ENTRY_BYTES)
        .ok_or_else(|| {
            ProxyError::Config("web capability index reservation overflowed usize".to_string())
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
    let wildcard_reservation = if wildcard {
        wildcard_reservation(limits)?
    } else {
        0
    };
    let reserved = limits
        .pending_bytes_global
        .checked_add(wildcard_reservation)
        .and_then(|value| value.checked_add(limits.max_body_bytes_global))
        .and_then(|value| value.checked_add(limits.max_static_bytes))
        .and_then(|value| value.checked_add(debug_ring_index))
        .and_then(|value| value.checked_add(status_pages))
        .and_then(|value| value.checked_add(debug_reservation))
        .and_then(|value| value.checked_add(carrier_learning_reservation))
        .and_then(|value| value.checked_add(capability_index_reservation))
        .and_then(|value| value.checked_add(lane_state_reservation))
        .and_then(|value| value.checked_add(http_header_reservation))
        .and_then(|value| value.checked_add(overload_connection_reservation))
        .ok_or_else(|| ProxyError::Config("web.limits byte ceilings overflow usize".to_string()))?;
    if reserved > limits.memory_envelope_bytes
        || limits.memory_envelope_bytes > MAX_WEB_MEMORY_ENVELOPE_BYTES
    {
        return config_error(
            "web.limits memory reservations must fit memory_envelope_bytes within 4 GiB",
        );
    }
    Ok(())
}

// Cache entries include their digest index and allocator overhead. Detached entry
// leases remain charged until the last borrower releases them. Handler scratch and
// authenticated host bindings have independent existing concurrency ceilings.
fn wildcard_reservation(limits: &WebLimitsConfig) -> Result<usize> {
    let wildcard = &limits.wildcard;
    if wildcard.max_rules == 0
        || wildcard.max_profiles_per_request == 0
        || wildcard.cache_bytes == 0
        || wildcard.cold_hmac_per_minute == 0
        || (wildcard.cold_hmac_burst as usize) < wildcard.max_profiles_per_request
    {
        return config_error(
            "web.limits.wildcard requires positive bounds and a burst covering a complete profile table",
        );
    }
    let rules = wildcard
        .max_rules
        .checked_mul(1024)
        .and_then(|value| {
            limits
                .max_profiles
                .checked_mul(1024)
                .and_then(|profiles| value.checked_add(profiles))
        })
        .ok_or_else(|| {
            ProxyError::Config("WEB wildcard template reservations overflowed usize".to_string())
        })?;
    wildcard
        .max_profiles_per_request
        .checked_mul(32)
        .and_then(|value| value.checked_add(1024))
        .and_then(|value| value.checked_mul(limits.max_http_handlers))
        .and_then(|value| value.checked_add(wildcard.cache_bytes))
        .and_then(|value| value.checked_add(rules))
        .and_then(|value| {
            limits
                .max_bootstraps_global
                .checked_add(limits.max_sessions_global)
                .and_then(|bindings| bindings.checked_mul(1024))
                .and_then(|bindings| value.checked_add(bindings))
        })
        .ok_or_else(|| {
            ProxyError::Config("WEB wildcard memory reservations overflowed usize".to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_envelope_includes_bounded_lane_and_learning_metadata() {
        let limits = WebLimitsConfig::default();
        assert!(validate(&limits, false).is_ok());

        let previous_envelope = WebLimitsConfig {
            memory_envelope_bytes: 768 * 1024 * 1024,
            ..limits
        };
        assert!(validate(&previous_envelope, false).is_err());
    }

    #[test]
    fn capability_index_reservation_rejects_size_overflow() {
        let limits = WebLimitsConfig {
            max_profiles: usize::MAX,
            ..WebLimitsConfig::default()
        };
        let error = validate(&limits, false).unwrap_err().to_string();
        assert!(error.contains("web capability index reservation overflowed usize"));
    }
}
