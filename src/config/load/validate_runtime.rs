use super::*;

pub(super) fn validate(config: &mut ProxyConfig) -> Result<()> {
    config.access.validate_quota_periods()?;
    if config.general.me_writer_cmd_channel_capacity == 0 {
        return Err(ProxyError::Config(
            "general.me_writer_cmd_channel_capacity must be > 0".to_string(),
        ));
    }
    if config.general.me_writer_cmd_channel_capacity > MAX_ME_WRITER_CMD_CHANNEL_CAPACITY {
        return Err(ProxyError::Config(format!(
            "general.me_writer_cmd_channel_capacity must be within [1, {MAX_ME_WRITER_CMD_CHANNEL_CAPACITY}]"
        )));
    }

    if config.general.me_route_channel_capacity == 0 {
        return Err(ProxyError::Config(
            "general.me_route_channel_capacity must be > 0".to_string(),
        ));
    }
    if config.general.me_route_channel_capacity > MAX_ME_ROUTE_CHANNEL_CAPACITY {
        return Err(ProxyError::Config(format!(
            "general.me_route_channel_capacity must be within [1, {MAX_ME_ROUTE_CHANNEL_CAPACITY}]"
        )));
    }

    if config.general.me_c2me_channel_capacity == 0 {
        return Err(ProxyError::Config(
            "general.me_c2me_channel_capacity must be > 0".to_string(),
        ));
    }
    if config.general.me_c2me_channel_capacity > MAX_ME_C2ME_CHANNEL_CAPACITY {
        return Err(ProxyError::Config(format!(
            "general.me_c2me_channel_capacity must be within [1, {MAX_ME_C2ME_CHANNEL_CAPACITY}]"
        )));
    }

    if !(MIN_MAX_CLIENT_FRAME_BYTES..=MAX_MAX_CLIENT_FRAME_BYTES)
        .contains(&config.general.max_client_frame)
    {
        return Err(ProxyError::Config(format!(
            "general.max_client_frame must be within [{MIN_MAX_CLIENT_FRAME_BYTES}, {MAX_MAX_CLIENT_FRAME_BYTES}]"
        )));
    }

    let min_writer_byte_budget =
        minimum_me_writer_byte_budget_bytes(config.general.max_client_frame);
    if config.general.me_writer_byte_budget_bytes % ME_WRITER_BYTE_PERMIT_UNIT_BYTES != 0 {
        return Err(ProxyError::Config(format!(
            "general.me_writer_byte_budget_bytes must be a multiple of {ME_WRITER_BYTE_PERMIT_UNIT_BYTES}"
        )));
    }
    if !(min_writer_byte_budget..=MAX_ME_WRITER_BYTE_BUDGET_BYTES)
        .contains(&config.general.me_writer_byte_budget_bytes)
    {
        return Err(ProxyError::Config(format!(
            "general.me_writer_byte_budget_bytes must be within [{min_writer_byte_budget}, {MAX_ME_WRITER_BYTE_BUDGET_BYTES}] for general.max_client_frame={}",
            config.general.max_client_frame
        )));
    }

    if config.general.me_c2me_send_timeout_ms > 60_000 {
        return Err(ProxyError::Config(
            "general.me_c2me_send_timeout_ms must be within [0, 60000]".to_string(),
        ));
    }

    if config.general.me_reader_route_data_wait_ms > 20 {
        return Err(ProxyError::Config(
            "general.me_reader_route_data_wait_ms must be within [0, 20]".to_string(),
        ));
    }

    if !(1..=512).contains(&config.general.me_d2c_flush_batch_max_frames) {
        return Err(ProxyError::Config(
            "general.me_d2c_flush_batch_max_frames must be within [1, 512]".to_string(),
        ));
    }

    if !(4096..=2 * 1024 * 1024).contains(&config.general.me_d2c_flush_batch_max_bytes) {
        return Err(ProxyError::Config(
            "general.me_d2c_flush_batch_max_bytes must be within [4096, 2097152]".to_string(),
        ));
    }

    if config.general.me_d2c_flush_batch_max_delay_us > 5000 {
        return Err(ProxyError::Config(
            "general.me_d2c_flush_batch_max_delay_us must be within [0, 5000]".to_string(),
        ));
    }

    if config.general.me_quota_soft_overshoot_bytes > 16 * 1024 * 1024 {
        return Err(ProxyError::Config(
            "general.me_quota_soft_overshoot_bytes must be within [0, 16777216]".to_string(),
        ));
    }

    if !(4096..=16 * 1024 * 1024).contains(&config.general.me_d2c_frame_buf_shrink_threshold_bytes)
    {
        return Err(ProxyError::Config(
            "general.me_d2c_frame_buf_shrink_threshold_bytes must be within [4096, 16777216]"
                .to_string(),
        ));
    }

    if !(4096..=1024 * 1024).contains(&config.general.direct_relay_copy_buf_c2s_bytes) {
        return Err(ProxyError::Config(
            "general.direct_relay_copy_buf_c2s_bytes must be within [4096, 1048576]".to_string(),
        ));
    }

    if !(8192..=2 * 1024 * 1024).contains(&config.general.direct_relay_copy_buf_s2c_bytes) {
        return Err(ProxyError::Config(
            "general.direct_relay_copy_buf_s2c_bytes must be within [8192, 2097152]".to_string(),
        ));
    }

    if config.general.direct_relay_buffer_budget_max_bytes != 0 {
        if config.general.direct_relay_buffer_budget_max_bytes
            % DIRECT_RELAY_BUFFER_BUDGET_UNIT_BYTES
            != 0
        {
            return Err(ProxyError::Config(format!(
                "general.direct_relay_buffer_budget_max_bytes must be 0 or a multiple of {DIRECT_RELAY_BUFFER_BUDGET_UNIT_BYTES}"
            )));
        }
        if !(MIN_DIRECT_RELAY_BUFFER_BUDGET_BYTES..=MAX_DIRECT_RELAY_BUFFER_BUDGET_BYTES)
            .contains(&config.general.direct_relay_buffer_budget_max_bytes)
        {
            return Err(ProxyError::Config(format!(
                "general.direct_relay_buffer_budget_max_bytes must be 0 or within [{MIN_DIRECT_RELAY_BUFFER_BUDGET_BYTES}, {MAX_DIRECT_RELAY_BUFFER_BUDGET_BYTES}]"
            )));
        }
    }

    if config.general.me_health_interval_ms_unhealthy == 0 {
        return Err(ProxyError::Config(
            "general.me_health_interval_ms_unhealthy must be > 0".to_string(),
        ));
    }

    if config.general.me_health_interval_ms_healthy == 0 {
        return Err(ProxyError::Config(
            "general.me_health_interval_ms_healthy must be > 0".to_string(),
        ));
    }

    if config.general.me_admission_poll_ms == 0 {
        return Err(ProxyError::Config(
            "general.me_admission_poll_ms must be > 0".to_string(),
        ));
    }

    if config.general.me_warn_rate_limit_ms == 0 {
        return Err(ProxyError::Config(
            "general.me_warn_rate_limit_ms must be > 0".to_string(),
        ));
    }

    if config.general.me_pool_drain_soft_evict_grace_secs > 3600 {
        return Err(ProxyError::Config(
            "general.me_pool_drain_soft_evict_grace_secs must be within [0, 3600]".to_string(),
        ));
    }

    if config.general.me_pool_drain_soft_evict_per_writer == 0
        || config.general.me_pool_drain_soft_evict_per_writer > 16
    {
        return Err(ProxyError::Config(
            "general.me_pool_drain_soft_evict_per_writer must be within [1, 16]".to_string(),
        ));
    }

    if config.general.me_pool_drain_soft_evict_budget_per_core == 0
        || config.general.me_pool_drain_soft_evict_budget_per_core > 64
    {
        return Err(ProxyError::Config(
            "general.me_pool_drain_soft_evict_budget_per_core must be within [1, 64]".to_string(),
        ));
    }

    if config.general.me_pool_drain_soft_evict_cooldown_ms == 0 {
        return Err(ProxyError::Config(
            "general.me_pool_drain_soft_evict_cooldown_ms must be > 0".to_string(),
        ));
    }

    if config.access.user_max_unique_ips_window_secs == 0 {
        return Err(ProxyError::Config(
            "access.user_max_unique_ips_window_secs must be > 0".to_string(),
        ));
    }

    for (user, limit) in &config.access.user_rate_limits {
        if limit.up_bps == 0 && limit.down_bps == 0 {
            return Err(ProxyError::Config(format!(
                "access.user_rate_limits.{user} must set at least one non-zero direction"
            )));
        }
        for (direction, value) in [("up_bps", limit.up_bps), ("down_bps", limit.down_bps)] {
            if value > MAX_RATE_LIMIT_BPS {
                return Err(ProxyError::Config(format!(
                    "access.user_rate_limits.{user}.{direction} must be within [0, {MAX_RATE_LIMIT_BPS}]"
                )));
            }
        }
    }

    for (cidr, limit) in &config.access.cidr_rate_limits {
        if limit.up_bps == 0 && limit.down_bps == 0 {
            return Err(ProxyError::Config(format!(
                "access.cidr_rate_limits.{cidr} must set at least one non-zero direction"
            )));
        }
        for (direction, value) in [("up_bps", limit.up_bps), ("down_bps", limit.down_bps)] {
            if value > MAX_RATE_LIMIT_BPS {
                return Err(ProxyError::Config(format!(
                    "access.cidr_rate_limits.{cidr}.{direction} must be within [0, {MAX_RATE_LIMIT_BPS}]"
                )));
            }
        }
    }
    let mut cidr_auto_templates = HashSet::new();
    for cidr in config.access.cidr_rate_limits.keys() {
        for template in cidr.auto_templates().into_iter().flatten() {
            if !cidr_auto_templates.insert(template) {
                return Err(ProxyError::Config(format!(
                    "access.cidr_rate_limits.{cidr} duplicates normalized auto-template {template}"
                )));
            }
        }
    }

    Ok(())
}
