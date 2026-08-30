use super::*;

/// Fields that are safe to swap without restarting listeners.
#[derive(Debug, Clone, PartialEq)]
pub struct HotFields {
    pub log_level: LogLevel,
    pub ad_tag: Option<String>,
    pub dns_overrides: Vec<String>,
    pub desync_all_full: bool,
    pub update_every_secs: u64,
    pub me_reinit_every_secs: u64,
    pub me_reinit_singleflight: bool,
    pub me_reinit_max_concurrency: usize,
    pub me_reinit_coalesce_window_ms: u64,
    pub hardswap: bool,
    pub me_pool_drain_ttl_secs: u64,
    pub me_instadrain: bool,
    pub me_pool_drain_threshold: u64,
    pub me_pool_min_fresh_ratio: f32,
    pub me_reinit_drain_timeout_secs: u64,
    pub me_hardswap_warmup_delay_min_ms: u64,
    pub me_hardswap_warmup_delay_max_ms: u64,
    pub me_hardswap_warmup_extra_passes: u8,
    pub me_hardswap_warmup_pass_backoff_base_ms: u64,
    pub me_bind_stale_mode: MeBindStaleMode,
    pub me_bind_stale_ttl_secs: u64,
    pub me_secret_atomic_snapshot: bool,
    pub me_deterministic_writer_sort: bool,
    pub me_writer_pick_mode: MeWriterPickMode,
    pub me_writer_pick_sample_size: u8,
    pub me_single_endpoint_shadow_writers: u8,
    pub me_single_endpoint_outage_mode_enabled: bool,
    pub me_single_endpoint_outage_disable_quarantine: bool,
    pub me_single_endpoint_outage_backoff_min_ms: u64,
    pub me_single_endpoint_outage_backoff_max_ms: u64,
    pub me_single_endpoint_shadow_rotate_every_secs: u64,
    pub me_config_stable_snapshots: u8,
    pub me_config_apply_cooldown_secs: u64,
    pub me_snapshot_require_http_2xx: bool,
    pub me_snapshot_reject_empty_map: bool,
    pub me_snapshot_min_proxy_for_lines: u32,
    pub proxy_secret_stable_snapshots: u8,
    pub proxy_secret_rotate_runtime: bool,
    pub proxy_secret_len_max: usize,
    pub telemetry_core_enabled: bool,
    pub telemetry_user_enabled: bool,
    pub telemetry_me_level: MeTelemetryLevel,
    pub me_socks_kdf_policy: MeSocksKdfPolicy,
    pub me_route_backpressure_enabled: bool,
    pub me_route_fairshare_enabled: bool,
    pub me_floor_mode: MeFloorMode,
    pub me_adaptive_floor_idle_secs: u64,
    pub me_adaptive_floor_min_writers_single_endpoint: u8,
    pub me_adaptive_floor_min_writers_multi_endpoint: u8,
    pub me_adaptive_floor_recover_grace_secs: u64,
    pub me_adaptive_floor_writers_per_core_total: u16,
    pub me_adaptive_floor_cpu_cores_override: u16,
    pub me_adaptive_floor_max_extra_writers_single_per_core: u16,
    pub me_adaptive_floor_max_extra_writers_multi_per_core: u16,
    pub me_adaptive_floor_max_active_writers_per_core: u16,
    pub me_adaptive_floor_max_warm_writers_per_core: u16,
    pub me_adaptive_floor_max_active_writers_global: u32,
    pub me_adaptive_floor_max_warm_writers_global: u32,
    pub me_route_backpressure_base_timeout_ms: u64,
    pub me_route_backpressure_high_timeout_ms: u64,
    pub me_route_backpressure_high_watermark_pct: u8,
    pub me_reader_route_data_wait_ms: u64,
    pub me_d2c_flush_batch_max_frames: usize,
    pub me_d2c_flush_batch_max_bytes: usize,
    pub me_d2c_flush_batch_max_delay_us: u64,
    pub me_d2c_ack_flush_immediate: bool,
    pub me_quota_soft_overshoot_bytes: u64,
    pub me_d2c_frame_buf_shrink_threshold_bytes: usize,
    pub direct_relay_copy_buf_c2s_bytes: usize,
    pub direct_relay_copy_buf_s2c_bytes: usize,
    pub me_health_interval_ms_unhealthy: u64,
    pub me_health_interval_ms_healthy: u64,
    pub me_admission_poll_ms: u64,
    pub me_warn_rate_limit_ms: u64,
    pub users: std::collections::HashMap<String, String>,
    pub user_enabled: std::collections::HashMap<String, bool>,
    pub user_ad_tags: std::collections::HashMap<String, String>,
    pub user_max_tcp_conns: std::collections::HashMap<String, usize>,
    pub user_max_tcp_conns_global_each: usize,
    pub user_expirations: std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>,
    pub user_data_quota: std::collections::HashMap<String, u64>,
    pub user_rate_limits: std::collections::HashMap<String, crate::config::RateLimitBps>,
    pub cidr_rate_limits: std::collections::HashMap<CidrRateLimitKey, crate::config::RateLimitBps>,
    pub user_max_unique_ips: std::collections::HashMap<String, usize>,
    pub user_max_unique_ips_global_each: usize,
    pub user_max_unique_ips_mode: crate::config::UserMaxUniqueIpsMode,
    pub user_max_unique_ips_window_secs: u64,
    pub web_debug: WebDebugConfig,
}

impl HotFields {
    pub fn from_config(cfg: &ProxyConfig) -> Self {
        Self {
            log_level: cfg.general.log_level.clone(),
            ad_tag: cfg.general.ad_tag.clone(),
            dns_overrides: cfg.network.dns_overrides.clone(),
            desync_all_full: cfg.general.desync_all_full,
            update_every_secs: cfg.general.effective_update_every_secs(),
            me_reinit_every_secs: cfg.general.me_reinit_every_secs,
            me_reinit_singleflight: cfg.general.me_reinit_singleflight,
            me_reinit_max_concurrency: cfg.general.me_reinit_max_concurrency,
            me_reinit_coalesce_window_ms: cfg.general.me_reinit_coalesce_window_ms,
            hardswap: cfg.general.hardswap,
            me_pool_drain_ttl_secs: cfg.general.me_pool_drain_ttl_secs,
            me_instadrain: cfg.general.me_instadrain,
            me_pool_drain_threshold: cfg.general.me_pool_drain_threshold,
            me_pool_min_fresh_ratio: cfg.general.me_pool_min_fresh_ratio,
            me_reinit_drain_timeout_secs: cfg.general.me_reinit_drain_timeout_secs,
            me_hardswap_warmup_delay_min_ms: cfg.general.me_hardswap_warmup_delay_min_ms,
            me_hardswap_warmup_delay_max_ms: cfg.general.me_hardswap_warmup_delay_max_ms,
            me_hardswap_warmup_extra_passes: cfg.general.me_hardswap_warmup_extra_passes,
            me_hardswap_warmup_pass_backoff_base_ms: cfg
                .general
                .me_hardswap_warmup_pass_backoff_base_ms,
            me_bind_stale_mode: cfg.general.me_bind_stale_mode,
            me_bind_stale_ttl_secs: cfg.general.me_bind_stale_ttl_secs,
            me_secret_atomic_snapshot: cfg.general.me_secret_atomic_snapshot,
            me_deterministic_writer_sort: cfg.general.me_deterministic_writer_sort,
            me_writer_pick_mode: cfg.general.me_writer_pick_mode,
            me_writer_pick_sample_size: cfg.general.me_writer_pick_sample_size,
            me_single_endpoint_shadow_writers: cfg.general.me_single_endpoint_shadow_writers,
            me_single_endpoint_outage_mode_enabled: cfg
                .general
                .me_single_endpoint_outage_mode_enabled,
            me_single_endpoint_outage_disable_quarantine: cfg
                .general
                .me_single_endpoint_outage_disable_quarantine,
            me_single_endpoint_outage_backoff_min_ms: cfg
                .general
                .me_single_endpoint_outage_backoff_min_ms,
            me_single_endpoint_outage_backoff_max_ms: cfg
                .general
                .me_single_endpoint_outage_backoff_max_ms,
            me_single_endpoint_shadow_rotate_every_secs: cfg
                .general
                .me_single_endpoint_shadow_rotate_every_secs,
            me_config_stable_snapshots: cfg.general.me_config_stable_snapshots,
            me_config_apply_cooldown_secs: cfg.general.me_config_apply_cooldown_secs,
            me_snapshot_require_http_2xx: cfg.general.me_snapshot_require_http_2xx,
            me_snapshot_reject_empty_map: cfg.general.me_snapshot_reject_empty_map,
            me_snapshot_min_proxy_for_lines: cfg.general.me_snapshot_min_proxy_for_lines,
            proxy_secret_stable_snapshots: cfg.general.proxy_secret_stable_snapshots,
            proxy_secret_rotate_runtime: cfg.general.proxy_secret_rotate_runtime,
            proxy_secret_len_max: cfg.general.proxy_secret_len_max,
            telemetry_core_enabled: cfg.general.telemetry.core_enabled,
            telemetry_user_enabled: cfg.general.telemetry.user_enabled,
            telemetry_me_level: cfg.general.telemetry.me_level,
            me_socks_kdf_policy: cfg.general.me_socks_kdf_policy,
            me_route_backpressure_enabled: cfg.general.me_route_backpressure_enabled,
            me_route_fairshare_enabled: cfg.general.me_route_fairshare_enabled,
            me_floor_mode: cfg.general.me_floor_mode,
            me_adaptive_floor_idle_secs: cfg.general.me_adaptive_floor_idle_secs,
            me_adaptive_floor_min_writers_single_endpoint: cfg
                .general
                .me_adaptive_floor_min_writers_single_endpoint,
            me_adaptive_floor_min_writers_multi_endpoint: cfg
                .general
                .me_adaptive_floor_min_writers_multi_endpoint,
            me_adaptive_floor_recover_grace_secs: cfg.general.me_adaptive_floor_recover_grace_secs,
            me_adaptive_floor_writers_per_core_total: cfg
                .general
                .me_adaptive_floor_writers_per_core_total,
            me_adaptive_floor_cpu_cores_override: cfg.general.me_adaptive_floor_cpu_cores_override,
            me_adaptive_floor_max_extra_writers_single_per_core: cfg
                .general
                .me_adaptive_floor_max_extra_writers_single_per_core,
            me_adaptive_floor_max_extra_writers_multi_per_core: cfg
                .general
                .me_adaptive_floor_max_extra_writers_multi_per_core,
            me_adaptive_floor_max_active_writers_per_core: cfg
                .general
                .me_adaptive_floor_max_active_writers_per_core,
            me_adaptive_floor_max_warm_writers_per_core: cfg
                .general
                .me_adaptive_floor_max_warm_writers_per_core,
            me_adaptive_floor_max_active_writers_global: cfg
                .general
                .me_adaptive_floor_max_active_writers_global,
            me_adaptive_floor_max_warm_writers_global: cfg
                .general
                .me_adaptive_floor_max_warm_writers_global,
            me_route_backpressure_base_timeout_ms: cfg
                .general
                .me_route_backpressure_base_timeout_ms,
            me_route_backpressure_high_timeout_ms: cfg
                .general
                .me_route_backpressure_high_timeout_ms,
            me_route_backpressure_high_watermark_pct: cfg
                .general
                .me_route_backpressure_high_watermark_pct,
            me_reader_route_data_wait_ms: cfg.general.me_reader_route_data_wait_ms,
            me_d2c_flush_batch_max_frames: cfg.general.me_d2c_flush_batch_max_frames,
            me_d2c_flush_batch_max_bytes: cfg.general.me_d2c_flush_batch_max_bytes,
            me_d2c_flush_batch_max_delay_us: cfg.general.me_d2c_flush_batch_max_delay_us,
            me_d2c_ack_flush_immediate: cfg.general.me_d2c_ack_flush_immediate,
            me_quota_soft_overshoot_bytes: cfg.general.me_quota_soft_overshoot_bytes,
            me_d2c_frame_buf_shrink_threshold_bytes: cfg
                .general
                .me_d2c_frame_buf_shrink_threshold_bytes,
            direct_relay_copy_buf_c2s_bytes: cfg.general.direct_relay_copy_buf_c2s_bytes,
            direct_relay_copy_buf_s2c_bytes: cfg.general.direct_relay_copy_buf_s2c_bytes,
            me_health_interval_ms_unhealthy: cfg.general.me_health_interval_ms_unhealthy,
            me_health_interval_ms_healthy: cfg.general.me_health_interval_ms_healthy,
            me_admission_poll_ms: cfg.general.me_admission_poll_ms,
            me_warn_rate_limit_ms: cfg.general.me_warn_rate_limit_ms,
            users: cfg.access.users.clone(),
            user_enabled: cfg.access.user_enabled.clone(),
            user_ad_tags: cfg.access.user_ad_tags.clone(),
            user_max_tcp_conns: cfg.access.user_max_tcp_conns.clone(),
            user_max_tcp_conns_global_each: cfg.access.user_max_tcp_conns_global_each,
            user_expirations: cfg.access.user_expirations.clone(),
            user_data_quota: cfg.access.user_data_quota.clone(),
            user_rate_limits: cfg.access.user_rate_limits.clone(),
            cidr_rate_limits: cfg.access.cidr_rate_limits.clone(),
            user_max_unique_ips: cfg.access.user_max_unique_ips.clone(),
            user_max_unique_ips_global_each: cfg.access.user_max_unique_ips_global_each,
            user_max_unique_ips_mode: cfg.access.user_max_unique_ips_mode,
            user_max_unique_ips_window_secs: cfg.access.user_max_unique_ips_window_secs,
            web_debug: cfg.web.debug.clone(),
        }
    }
}

pub(super) fn overlay_hot_fields(old: &ProxyConfig, new: &ProxyConfig) -> ProxyConfig {
    let mut cfg = old.clone();

    cfg.general.log_level = new.general.log_level.clone();
    cfg.general.ad_tag = new.general.ad_tag.clone();
    cfg.network.dns_overrides = new.network.dns_overrides.clone();
    cfg.general.desync_all_full = new.general.desync_all_full;
    cfg.general.update_every = new.general.update_every;
    cfg.general.proxy_secret_auto_reload_secs = new.general.proxy_secret_auto_reload_secs;
    cfg.general.proxy_config_auto_reload_secs = new.general.proxy_config_auto_reload_secs;
    cfg.general.me_reinit_every_secs = new.general.me_reinit_every_secs;
    cfg.general.me_reinit_singleflight = new.general.me_reinit_singleflight;
    cfg.general.me_reinit_max_concurrency = new.general.me_reinit_max_concurrency;
    cfg.general.me_reinit_coalesce_window_ms = new.general.me_reinit_coalesce_window_ms;
    cfg.general.hardswap = new.general.hardswap;
    cfg.general.me_pool_drain_ttl_secs = new.general.me_pool_drain_ttl_secs;
    cfg.general.me_instadrain = new.general.me_instadrain;
    cfg.general.me_pool_drain_threshold = new.general.me_pool_drain_threshold;
    cfg.general.me_pool_min_fresh_ratio = new.general.me_pool_min_fresh_ratio;
    cfg.general.me_reinit_drain_timeout_secs = new.general.me_reinit_drain_timeout_secs;
    cfg.general.me_hardswap_warmup_delay_min_ms = new.general.me_hardswap_warmup_delay_min_ms;
    cfg.general.me_hardswap_warmup_delay_max_ms = new.general.me_hardswap_warmup_delay_max_ms;
    cfg.general.me_hardswap_warmup_extra_passes = new.general.me_hardswap_warmup_extra_passes;
    cfg.general.me_hardswap_warmup_pass_backoff_base_ms =
        new.general.me_hardswap_warmup_pass_backoff_base_ms;
    cfg.general.me_bind_stale_mode = new.general.me_bind_stale_mode;
    cfg.general.me_bind_stale_ttl_secs = new.general.me_bind_stale_ttl_secs;
    cfg.general.me_secret_atomic_snapshot = new.general.me_secret_atomic_snapshot;
    cfg.general.me_deterministic_writer_sort = new.general.me_deterministic_writer_sort;
    cfg.general.me_writer_pick_mode = new.general.me_writer_pick_mode;
    cfg.general.me_writer_pick_sample_size = new.general.me_writer_pick_sample_size;
    cfg.general.me_single_endpoint_shadow_writers = new.general.me_single_endpoint_shadow_writers;
    cfg.general.me_single_endpoint_outage_mode_enabled =
        new.general.me_single_endpoint_outage_mode_enabled;
    cfg.general.me_single_endpoint_outage_disable_quarantine =
        new.general.me_single_endpoint_outage_disable_quarantine;
    cfg.general.me_single_endpoint_outage_backoff_min_ms =
        new.general.me_single_endpoint_outage_backoff_min_ms;
    cfg.general.me_single_endpoint_outage_backoff_max_ms =
        new.general.me_single_endpoint_outage_backoff_max_ms;
    cfg.general.me_single_endpoint_shadow_rotate_every_secs =
        new.general.me_single_endpoint_shadow_rotate_every_secs;
    cfg.general.me_config_stable_snapshots = new.general.me_config_stable_snapshots;
    cfg.general.me_config_apply_cooldown_secs = new.general.me_config_apply_cooldown_secs;
    cfg.general.me_snapshot_require_http_2xx = new.general.me_snapshot_require_http_2xx;
    cfg.general.me_snapshot_reject_empty_map = new.general.me_snapshot_reject_empty_map;
    cfg.general.me_snapshot_min_proxy_for_lines = new.general.me_snapshot_min_proxy_for_lines;
    cfg.general.proxy_secret_stable_snapshots = new.general.proxy_secret_stable_snapshots;
    cfg.general.proxy_secret_rotate_runtime = new.general.proxy_secret_rotate_runtime;
    cfg.general.proxy_secret_len_max = new.general.proxy_secret_len_max;
    cfg.general.telemetry = new.general.telemetry.clone();
    cfg.general.me_socks_kdf_policy = new.general.me_socks_kdf_policy;
    cfg.general.me_floor_mode = new.general.me_floor_mode;
    cfg.general.me_adaptive_floor_idle_secs = new.general.me_adaptive_floor_idle_secs;
    cfg.general.me_adaptive_floor_min_writers_single_endpoint =
        new.general.me_adaptive_floor_min_writers_single_endpoint;
    cfg.general.me_adaptive_floor_min_writers_multi_endpoint =
        new.general.me_adaptive_floor_min_writers_multi_endpoint;
    cfg.general.me_adaptive_floor_recover_grace_secs =
        new.general.me_adaptive_floor_recover_grace_secs;
    cfg.general.me_adaptive_floor_writers_per_core_total =
        new.general.me_adaptive_floor_writers_per_core_total;
    cfg.general.me_adaptive_floor_cpu_cores_override =
        new.general.me_adaptive_floor_cpu_cores_override;
    cfg.general
        .me_adaptive_floor_max_extra_writers_single_per_core = new
        .general
        .me_adaptive_floor_max_extra_writers_single_per_core;
    cfg.general
        .me_adaptive_floor_max_extra_writers_multi_per_core = new
        .general
        .me_adaptive_floor_max_extra_writers_multi_per_core;
    cfg.general.me_adaptive_floor_max_active_writers_per_core =
        new.general.me_adaptive_floor_max_active_writers_per_core;
    cfg.general.me_adaptive_floor_max_warm_writers_per_core =
        new.general.me_adaptive_floor_max_warm_writers_per_core;
    cfg.general.me_adaptive_floor_max_active_writers_global =
        new.general.me_adaptive_floor_max_active_writers_global;
    cfg.general.me_adaptive_floor_max_warm_writers_global =
        new.general.me_adaptive_floor_max_warm_writers_global;
    cfg.general.me_route_backpressure_base_timeout_ms =
        new.general.me_route_backpressure_base_timeout_ms;
    cfg.general.me_route_backpressure_high_timeout_ms =
        new.general.me_route_backpressure_high_timeout_ms;
    cfg.general.me_route_backpressure_high_watermark_pct =
        new.general.me_route_backpressure_high_watermark_pct;
    cfg.general.me_route_backpressure_enabled = new.general.me_route_backpressure_enabled;
    cfg.general.me_route_fairshare_enabled = new.general.me_route_fairshare_enabled;
    cfg.general.me_reader_route_data_wait_ms = new.general.me_reader_route_data_wait_ms;
    cfg.general.me_d2c_flush_batch_max_frames = new.general.me_d2c_flush_batch_max_frames;
    cfg.general.me_d2c_flush_batch_max_bytes = new.general.me_d2c_flush_batch_max_bytes;
    cfg.general.me_d2c_flush_batch_max_delay_us = new.general.me_d2c_flush_batch_max_delay_us;
    cfg.general.me_d2c_ack_flush_immediate = new.general.me_d2c_ack_flush_immediate;
    cfg.general.me_quota_soft_overshoot_bytes = new.general.me_quota_soft_overshoot_bytes;
    cfg.general.me_d2c_frame_buf_shrink_threshold_bytes =
        new.general.me_d2c_frame_buf_shrink_threshold_bytes;
    cfg.general.direct_relay_copy_buf_c2s_bytes = new.general.direct_relay_copy_buf_c2s_bytes;
    cfg.general.direct_relay_copy_buf_s2c_bytes = new.general.direct_relay_copy_buf_s2c_bytes;
    cfg.general.me_health_interval_ms_unhealthy = new.general.me_health_interval_ms_unhealthy;
    cfg.general.me_health_interval_ms_healthy = new.general.me_health_interval_ms_healthy;
    cfg.general.me_admission_poll_ms = new.general.me_admission_poll_ms;
    cfg.general.me_warn_rate_limit_ms = new.general.me_warn_rate_limit_ms;

    cfg.access.users = new.access.users.clone();
    cfg.access.user_enabled = new.access.user_enabled.clone();
    cfg.access.user_ad_tags = new.access.user_ad_tags.clone();
    cfg.access.user_max_tcp_conns = new.access.user_max_tcp_conns.clone();
    cfg.access.user_max_tcp_conns_global_each = new.access.user_max_tcp_conns_global_each;
    cfg.access.user_expirations = new.access.user_expirations.clone();
    cfg.access.user_data_quota = new.access.user_data_quota.clone();
    cfg.access.user_rate_limits = new.access.user_rate_limits.clone();
    cfg.access.cidr_rate_limits = new.access.cidr_rate_limits.clone();
    cfg.access.user_max_unique_ips = new.access.user_max_unique_ips.clone();
    cfg.access.user_max_unique_ips_global_each = new.access.user_max_unique_ips_global_each;
    cfg.access.user_max_unique_ips_mode = new.access.user_max_unique_ips_mode;
    cfg.access.user_max_unique_ips_window_secs = new.access.user_max_unique_ips_window_secs;
    let process_limits = cfg.web.limits.clone();
    cfg.web = new.web.clone();
    cfg.web.limits = process_limits;
    if !web_debug_fits_limits(&cfg.web.debug, &cfg.web.limits) {
        cfg.web.debug = old.web.debug.clone();
    }
    if cfg.rebuild_runtime_user_auth().is_err() {
        cfg.runtime_user_auth = None;
    }
    if cfg.rebuild_runtime_web().is_err() {
        cfg.web = old.web.clone();
    }

    cfg
}
