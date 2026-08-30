use super::*;

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            data_path: None,
            quota_state_path: default_quota_state_path(),
            config_strict: false,
            modes: ProxyModes::default(),
            prefer_ipv6: false,
            fast_mode: default_true(),
            use_middle_proxy: default_true(),
            ad_tag: None,
            proxy_secret_path: default_proxy_secret_path(),
            proxy_secret_url: None,
            proxy_config_v4_cache_path: default_proxy_config_v4_cache_path(),
            proxy_config_v4_url: None,
            proxy_config_v6_cache_path: default_proxy_config_v6_cache_path(),
            proxy_config_v6_url: None,
            middle_proxy_nat_ip: None,
            middle_proxy_nat_probe: default_true(),
            middle_proxy_nat_stun: default_middle_proxy_nat_stun(),
            middle_proxy_nat_stun_servers: default_middle_proxy_nat_stun_servers(),
            stun_nat_probe_concurrency: default_stun_nat_probe_concurrency(),
            middle_proxy_pool_size: default_pool_size(),
            middle_proxy_warm_standby: default_middle_proxy_warm_standby(),
            me_init_retry_attempts: default_me_init_retry_attempts(),
            me2dc_fallback: default_me2dc_fallback(),
            me2dc_fast: default_me2dc_fast(),
            me_keepalive_enabled: default_true(),
            me_keepalive_interval_secs: default_keepalive_interval(),
            me_keepalive_jitter_secs: default_keepalive_jitter(),
            me_keepalive_payload_random: default_true(),
            rpc_proxy_req_every: default_rpc_proxy_req_every(),
            me_writer_cmd_channel_capacity: default_me_writer_cmd_channel_capacity(),
            me_writer_byte_budget_bytes: default_me_writer_byte_budget_bytes(),
            me_route_channel_capacity: default_me_route_channel_capacity(),
            me_c2me_channel_capacity: default_me_c2me_channel_capacity(),
            me_c2me_send_timeout_ms: default_me_c2me_send_timeout_ms(),
            me_reader_route_data_wait_ms: default_me_reader_route_data_wait_ms(),
            me_d2c_flush_batch_max_frames: default_me_d2c_flush_batch_max_frames(),
            me_d2c_flush_batch_max_bytes: default_me_d2c_flush_batch_max_bytes(),
            me_d2c_flush_batch_max_delay_us: default_me_d2c_flush_batch_max_delay_us(),
            me_d2c_ack_flush_immediate: default_me_d2c_ack_flush_immediate(),
            me_quota_soft_overshoot_bytes: default_me_quota_soft_overshoot_bytes(),
            me_d2c_frame_buf_shrink_threshold_bytes:
                default_me_d2c_frame_buf_shrink_threshold_bytes(),
            direct_relay_copy_buf_c2s_bytes: default_direct_relay_copy_buf_c2s_bytes(),
            direct_relay_copy_buf_s2c_bytes: default_direct_relay_copy_buf_s2c_bytes(),
            direct_relay_buffer_budget_max_bytes: default_direct_relay_buffer_budget_max_bytes(),
            me_warmup_stagger_enabled: default_true(),
            me_warmup_step_delay_ms: default_warmup_step_delay_ms(),
            me_warmup_step_jitter_ms: default_warmup_step_jitter_ms(),
            me_reconnect_max_concurrent_per_dc: default_me_reconnect_max_concurrent_per_dc(),
            me_reconnect_backoff_base_ms: default_reconnect_backoff_base_ms(),
            me_reconnect_backoff_cap_ms: default_reconnect_backoff_cap_ms(),
            me_reconnect_fast_retry_count: default_me_reconnect_fast_retry_count(),
            me_single_endpoint_shadow_writers: default_me_single_endpoint_shadow_writers(),
            me_single_endpoint_outage_mode_enabled: default_me_single_endpoint_outage_mode_enabled(
            ),
            me_single_endpoint_outage_disable_quarantine:
                default_me_single_endpoint_outage_disable_quarantine(),
            me_single_endpoint_outage_backoff_min_ms:
                default_me_single_endpoint_outage_backoff_min_ms(),
            me_single_endpoint_outage_backoff_max_ms:
                default_me_single_endpoint_outage_backoff_max_ms(),
            me_single_endpoint_shadow_rotate_every_secs:
                default_me_single_endpoint_shadow_rotate_every_secs(),
            me_floor_mode: MeFloorMode::default(),
            me_adaptive_floor_idle_secs: default_me_adaptive_floor_idle_secs(),
            me_adaptive_floor_min_writers_single_endpoint:
                default_me_adaptive_floor_min_writers_single_endpoint(),
            me_adaptive_floor_min_writers_multi_endpoint:
                default_me_adaptive_floor_min_writers_multi_endpoint(),
            me_adaptive_floor_recover_grace_secs: default_me_adaptive_floor_recover_grace_secs(),
            me_adaptive_floor_writers_per_core_total:
                default_me_adaptive_floor_writers_per_core_total(),
            me_adaptive_floor_cpu_cores_override: default_me_adaptive_floor_cpu_cores_override(),
            me_adaptive_floor_max_extra_writers_single_per_core:
                default_me_adaptive_floor_max_extra_writers_single_per_core(),
            me_adaptive_floor_max_extra_writers_multi_per_core:
                default_me_adaptive_floor_max_extra_writers_multi_per_core(),
            me_adaptive_floor_max_active_writers_per_core:
                default_me_adaptive_floor_max_active_writers_per_core(),
            me_adaptive_floor_max_warm_writers_per_core:
                default_me_adaptive_floor_max_warm_writers_per_core(),
            me_adaptive_floor_max_active_writers_global:
                default_me_adaptive_floor_max_active_writers_global(),
            me_adaptive_floor_max_warm_writers_global:
                default_me_adaptive_floor_max_warm_writers_global(),
            upstream_connect_retry_attempts: default_upstream_connect_retry_attempts(),
            upstream_connect_retry_backoff_ms: default_upstream_connect_retry_backoff_ms(),
            upstream_connect_budget_ms: default_upstream_connect_budget_ms(),
            tg_connect: default_connect_timeout(),
            upstream_unhealthy_fail_threshold: default_upstream_unhealthy_fail_threshold(),
            upstream_connect_failfast_hard_errors: default_upstream_connect_failfast_hard_errors(),
            stun_iface_mismatch_ignore: false,
            unknown_dc_log_path: default_unknown_dc_log_path(),
            unknown_dc_file_log_enabled: default_unknown_dc_file_log_enabled(),
            log_level: LogLevel::Normal,
            disable_colors: false,
            telemetry: TelemetryConfig::default(),
            me_socks_kdf_policy: MeSocksKdfPolicy::Strict,
            me_route_backpressure_enabled: default_me_route_backpressure_enabled(),
            me_route_fairshare_enabled: default_me_route_fairshare_enabled(),
            me_route_backpressure_base_timeout_ms: default_me_route_backpressure_base_timeout_ms(),
            me_route_backpressure_high_timeout_ms: default_me_route_backpressure_high_timeout_ms(),
            me_route_backpressure_high_watermark_pct:
                default_me_route_backpressure_high_watermark_pct(),
            me_health_interval_ms_unhealthy: default_me_health_interval_ms_unhealthy(),
            me_health_interval_ms_healthy: default_me_health_interval_ms_healthy(),
            me_admission_poll_ms: default_me_admission_poll_ms(),
            me_warn_rate_limit_ms: default_me_warn_rate_limit_ms(),
            me_route_no_writer_mode: MeRouteNoWriterMode::default(),
            me_route_no_writer_wait_ms: default_me_route_no_writer_wait_ms(),
            me_route_hybrid_max_wait_ms: default_me_route_hybrid_max_wait_ms(),
            me_route_blocking_send_timeout_ms: default_me_route_blocking_send_timeout_ms(),
            me_route_inline_recovery_attempts: default_me_route_inline_recovery_attempts(),
            me_route_inline_recovery_wait_ms: default_me_route_inline_recovery_wait_ms(),
            links: LinksConfig::default(),
            crypto_pending_buffer: default_crypto_pending_buffer(),
            max_client_frame: default_max_client_frame(),
            desync_all_full: default_desync_all_full(),
            beobachten: default_true(),
            beobachten_minutes: default_beobachten_minutes(),
            beobachten_flush_secs: default_beobachten_flush_secs(),
            beobachten_file: default_beobachten_file(),
            hardswap: default_hardswap(),
            fast_mode_min_tls_record: default_fast_mode_min_tls_record(),
            update_every: default_update_every(),
            me_reinit_every_secs: default_me_reinit_every_secs(),
            me_hardswap_warmup_delay_min_ms: default_me_hardswap_warmup_delay_min_ms(),
            me_hardswap_warmup_delay_max_ms: default_me_hardswap_warmup_delay_max_ms(),
            me_hardswap_warmup_extra_passes: default_me_hardswap_warmup_extra_passes(),
            me_hardswap_warmup_pass_backoff_base_ms:
                default_me_hardswap_warmup_pass_backoff_base_ms(),
            me_config_stable_snapshots: default_me_config_stable_snapshots(),
            me_config_apply_cooldown_secs: default_me_config_apply_cooldown_secs(),
            me_snapshot_require_http_2xx: default_me_snapshot_require_http_2xx(),
            me_snapshot_reject_empty_map: default_me_snapshot_reject_empty_map(),
            me_snapshot_min_proxy_for_lines: default_me_snapshot_min_proxy_for_lines(),
            proxy_secret_stable_snapshots: default_proxy_secret_stable_snapshots(),
            proxy_secret_rotate_runtime: default_proxy_secret_rotate_runtime(),
            me_secret_atomic_snapshot: default_me_secret_atomic_snapshot(),
            proxy_secret_len_max: default_proxy_secret_len_max(),
            me_pool_drain_ttl_secs: default_me_pool_drain_ttl_secs(),
            me_instadrain: default_me_instadrain(),
            me_pool_drain_threshold: default_me_pool_drain_threshold(),
            me_pool_drain_soft_evict_enabled: default_me_pool_drain_soft_evict_enabled(),
            me_pool_drain_soft_evict_grace_secs: default_me_pool_drain_soft_evict_grace_secs(),
            me_pool_drain_soft_evict_per_writer: default_me_pool_drain_soft_evict_per_writer(),
            me_pool_drain_soft_evict_budget_per_core:
                default_me_pool_drain_soft_evict_budget_per_core(),
            me_pool_drain_soft_evict_cooldown_ms: default_me_pool_drain_soft_evict_cooldown_ms(),
            me_bind_stale_mode: MeBindStaleMode::default(),
            me_bind_stale_ttl_secs: default_me_bind_stale_ttl_secs(),
            me_pool_min_fresh_ratio: default_me_pool_min_fresh_ratio(),
            me_reinit_drain_timeout_secs: default_me_reinit_drain_timeout_secs(),
            proxy_secret_auto_reload_secs: default_proxy_secret_reload_secs(),
            proxy_config_auto_reload_secs: default_proxy_config_reload_secs(),
            me_reinit_singleflight: default_me_reinit_singleflight(),
            me_reinit_max_concurrency: default_me_reinit_max_concurrency(),
            me_reinit_trigger_channel: default_me_reinit_trigger_channel(),
            me_reinit_coalesce_window_ms: default_me_reinit_coalesce_window_ms(),
            me_deterministic_writer_sort: default_me_deterministic_writer_sort(),
            me_writer_pick_mode: MeWriterPickMode::default(),
            me_writer_pick_sample_size: default_me_writer_pick_sample_size(),
            ntp_check: default_ntp_check(),
            ntp_servers: default_ntp_servers(),
            auto_degradation_enabled: default_true(),
            degradation_min_unavailable_dc_groups: default_degradation_min_unavailable_dc_groups(),
            rst_on_close: RstOnCloseMode::default(),
        }
    }
}

impl GeneralConfig {
    /// Resolve the active updater interval for ME infrastructure refresh tasks.
    /// `update_every` has priority, otherwise legacy proxy_*_auto_reload_secs are used.
    pub fn effective_update_every_secs(&self) -> u64 {
        self.update_every.unwrap_or_else(|| {
            self.proxy_secret_auto_reload_secs
                .min(self.proxy_config_auto_reload_secs)
        })
    }

    /// Resolve periodic zero-downtime reinit interval for ME writers.
    pub fn effective_me_reinit_every_secs(&self) -> u64 {
        self.me_reinit_every_secs
    }

    /// Resolve force-close timeout for stale writers.
    /// `me_reinit_drain_timeout_secs` remains backward-compatible alias.
    /// A configured `0` uses the runtime safety fallback (300s).
    pub fn effective_me_pool_force_close_secs(&self) -> u64 {
        if self.me_reinit_drain_timeout_secs == 0 {
            300
        } else {
            self.me_reinit_drain_timeout_secs
        }
    }
}
