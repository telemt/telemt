use super::*;

pub(super) fn validate(config: &mut ProxyConfig) -> Result<()> {
    if config.general.me_reinit_every_secs == 0 {
        return Err(ProxyError::Config(
            "general.me_reinit_every_secs must be > 0".to_string(),
        ));
    }

    if config.general.me_single_endpoint_shadow_writers > 32 {
        return Err(ProxyError::Config(
            "general.me_single_endpoint_shadow_writers must be within [0, 32]".to_string(),
        ));
    }

    if config.general.me_adaptive_floor_min_writers_single_endpoint == 0
        || config.general.me_adaptive_floor_min_writers_single_endpoint > 32
    {
        return Err(ProxyError::Config(
            "general.me_adaptive_floor_min_writers_single_endpoint must be within [1, 32]"
                .to_string(),
        ));
    }

    if config.general.me_adaptive_floor_min_writers_multi_endpoint == 0
        || config.general.me_adaptive_floor_min_writers_multi_endpoint > 32
    {
        return Err(ProxyError::Config(
            "general.me_adaptive_floor_min_writers_multi_endpoint must be within [1, 32]"
                .to_string(),
        ));
    }

    if config.general.me_adaptive_floor_writers_per_core_total == 0 {
        return Err(ProxyError::Config(
            "general.me_adaptive_floor_writers_per_core_total must be > 0".to_string(),
        ));
    }

    if config.general.me_adaptive_floor_max_active_writers_per_core == 0 {
        return Err(ProxyError::Config(
            "general.me_adaptive_floor_max_active_writers_per_core must be > 0".to_string(),
        ));
    }

    if config.general.me_adaptive_floor_max_warm_writers_per_core == 0 {
        return Err(ProxyError::Config(
            "general.me_adaptive_floor_max_warm_writers_per_core must be > 0".to_string(),
        ));
    }

    if config.general.me_adaptive_floor_max_active_writers_global == 0 {
        return Err(ProxyError::Config(
            "general.me_adaptive_floor_max_active_writers_global must be > 0".to_string(),
        ));
    }

    if config.general.me_adaptive_floor_max_warm_writers_global == 0 {
        return Err(ProxyError::Config(
            "general.me_adaptive_floor_max_warm_writers_global must be > 0".to_string(),
        ));
    }

    if config.general.me_single_endpoint_outage_backoff_min_ms == 0 {
        return Err(ProxyError::Config(
            "general.me_single_endpoint_outage_backoff_min_ms must be > 0".to_string(),
        ));
    }

    if config.general.me_single_endpoint_outage_backoff_max_ms == 0 {
        return Err(ProxyError::Config(
            "general.me_single_endpoint_outage_backoff_max_ms must be > 0".to_string(),
        ));
    }

    if config.general.me_single_endpoint_outage_backoff_min_ms
        > config.general.me_single_endpoint_outage_backoff_max_ms
    {
        return Err(ProxyError::Config(
            "general.me_single_endpoint_outage_backoff_min_ms must be <= general.me_single_endpoint_outage_backoff_max_ms".to_string(),
        ));
    }

    if config.general.beobachten_minutes == 0 {
        return Err(ProxyError::Config(
            "general.beobachten_minutes must be > 0".to_string(),
        ));
    }

    if config.general.beobachten_flush_secs == 0 {
        return Err(ProxyError::Config(
            "general.beobachten_flush_secs must be > 0".to_string(),
        ));
    }

    if config.general.beobachten_file.trim().is_empty() {
        return Err(ProxyError::Config(
            "general.beobachten_file cannot be empty".to_string(),
        ));
    }

    if config.general.me_hardswap_warmup_delay_max_ms == 0 {
        return Err(ProxyError::Config(
            "general.me_hardswap_warmup_delay_max_ms must be > 0".to_string(),
        ));
    }

    if config.general.me_hardswap_warmup_delay_min_ms
        > config.general.me_hardswap_warmup_delay_max_ms
    {
        return Err(ProxyError::Config(
            "general.me_hardswap_warmup_delay_min_ms must be <= general.me_hardswap_warmup_delay_max_ms".to_string(),
        ));
    }

    if config.general.me_hardswap_warmup_extra_passes > 10 {
        return Err(ProxyError::Config(
            "general.me_hardswap_warmup_extra_passes must be within [0, 10]".to_string(),
        ));
    }

    if config.general.me_hardswap_warmup_pass_backoff_base_ms == 0 {
        return Err(ProxyError::Config(
            "general.me_hardswap_warmup_pass_backoff_base_ms must be > 0".to_string(),
        ));
    }

    if config.general.me_config_stable_snapshots == 0 {
        return Err(ProxyError::Config(
            "general.me_config_stable_snapshots must be > 0".to_string(),
        ));
    }

    if config.general.me_snapshot_min_proxy_for_lines == 0 {
        return Err(ProxyError::Config(
            "general.me_snapshot_min_proxy_for_lines must be > 0".to_string(),
        ));
    }

    if config.general.proxy_secret_stable_snapshots == 0 {
        return Err(ProxyError::Config(
            "general.proxy_secret_stable_snapshots must be > 0".to_string(),
        ));
    }

    if !(1..=8).contains(&config.general.me_reinit_max_concurrency) {
        return Err(ProxyError::Config(
            "general.me_reinit_max_concurrency must be within [1, 8]".to_string(),
        ));
    }

    if !(1..=4096).contains(&config.general.me_reinit_trigger_channel) {
        return Err(ProxyError::Config(
            "general.me_reinit_trigger_channel must be within [1, 4096]".to_string(),
        ));
    }

    if !(32..=4096).contains(&config.general.proxy_secret_len_max) {
        return Err(ProxyError::Config(
            "general.proxy_secret_len_max must be within [32, 4096]".to_string(),
        ));
    }

    if !(0.0..=1.0).contains(&config.general.me_pool_min_fresh_ratio) {
        return Err(ProxyError::Config(
            "general.me_pool_min_fresh_ratio must be within [0.0, 1.0]".to_string(),
        ));
    }

    if config.general.me_route_backpressure_base_timeout_ms == 0 {
        return Err(ProxyError::Config(
            "general.me_route_backpressure_base_timeout_ms must be > 0".to_string(),
        ));
    }
    if config.general.me_route_backpressure_base_timeout_ms > 5000 {
        return Err(ProxyError::Config(
            "general.me_route_backpressure_base_timeout_ms must be within [1, 5000]".to_string(),
        ));
    }

    if config.general.me_route_backpressure_high_timeout_ms
        < config.general.me_route_backpressure_base_timeout_ms
    {
        return Err(ProxyError::Config(
            "general.me_route_backpressure_high_timeout_ms must be >= general.me_route_backpressure_base_timeout_ms".to_string(),
        ));
    }
    if config.general.me_route_backpressure_high_timeout_ms > 5000 {
        return Err(ProxyError::Config(
            "general.me_route_backpressure_high_timeout_ms must be within [1, 5000]".to_string(),
        ));
    }

    if !(1..=100).contains(&config.general.me_route_backpressure_high_watermark_pct) {
        return Err(ProxyError::Config(
            "general.me_route_backpressure_high_watermark_pct must be within [1, 100]".to_string(),
        ));
    }

    if !(10..=5000).contains(&config.general.me_route_no_writer_wait_ms) {
        return Err(ProxyError::Config(
            "general.me_route_no_writer_wait_ms must be within [10, 5000]".to_string(),
        ));
    }

    if !(50..=60_000).contains(&config.general.me_route_hybrid_max_wait_ms) {
        return Err(ProxyError::Config(
            "general.me_route_hybrid_max_wait_ms must be within [50, 60000]".to_string(),
        ));
    }

    if !(1..=5000).contains(&config.general.me_route_blocking_send_timeout_ms) {
        return Err(ProxyError::Config(
            "general.me_route_blocking_send_timeout_ms must be within [1, 5000]".to_string(),
        ));
    }

    if !(2..=4).contains(&config.general.me_writer_pick_sample_size) {
        return Err(ProxyError::Config(
            "general.me_writer_pick_sample_size must be within [2, 4]".to_string(),
        ));
    }

    if config.general.me_route_inline_recovery_attempts == 0 {
        return Err(ProxyError::Config(
            "general.me_route_inline_recovery_attempts must be > 0".to_string(),
        ));
    }

    if !(10..=30000).contains(&config.general.me_route_inline_recovery_wait_ms) {
        return Err(ProxyError::Config(
            "general.me_route_inline_recovery_wait_ms must be within [10, 30000]".to_string(),
        ));
    }
    Ok(())
}
