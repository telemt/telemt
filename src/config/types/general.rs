use super::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default)]
    pub data_path: Option<PathBuf>,
    /// JSON state file for runtime per-user quota consumption.
    #[serde(default = "default_quota_state_path")]
    pub quota_state_path: PathBuf,
    /// Reject unknown TOML config keys during load.
    /// Startup fails fast; hot-reload rejects the new snapshot and keeps the current config.
    #[serde(default)]
    pub config_strict: bool,
    #[serde(default)]
    pub modes: ProxyModes,
    #[serde(default)]
    pub prefer_ipv6: bool,
    #[serde(default = "default_true")]
    pub fast_mode: bool,
    #[serde(default = "default_true")]
    pub use_middle_proxy: bool,
    /// Path to proxy-secret binary file (auto-downloaded if absent).
    /// Infrastructure secret from https://core.telegram.org/getProxySecret.
    #[serde(default = "default_proxy_secret_path")]
    pub proxy_secret_path: Option<String>,
    /// Optional custom URL for infrastructure secret (https://core.telegram.org/getProxySecret if absent).
    #[serde(default)]
    pub proxy_secret_url: Option<String>,
    /// Optional path to cache raw getProxyConfig (IPv4) snapshot for startup fallback.
    #[serde(default = "default_proxy_config_v4_cache_path")]
    pub proxy_config_v4_cache_path: Option<String>,
    /// Optional custom URL for getProxyConfig (https://core.telegram.org/getProxyConfig if absent).
    #[serde(default)]
    pub proxy_config_v4_url: Option<String>,
    /// Optional path to cache raw getProxyConfigV6 snapshot for startup fallback.
    #[serde(default = "default_proxy_config_v6_cache_path")]
    pub proxy_config_v6_cache_path: Option<String>,
    /// Optional custom URL for getProxyConfigV6 (https://core.telegram.org/getProxyConfigV6 if absent).
    #[serde(default)]
    pub proxy_config_v6_url: Option<String>,
    /// Global ad_tag (32 hex chars from @MTProxybot). Fallback when user has no per-user tag in access.user_ad_tags.
    #[serde(default)]
    pub ad_tag: Option<String>,
    /// Public IP override for middle-proxy NAT environments.
    /// When set, this IP is used in ME key derivation and local address translation.
    #[serde(default)]
    pub middle_proxy_nat_ip: Option<IpAddr>,
    /// Enable STUN-based NAT probing to discover public IP:port for ME KDF.
    #[serde(default = "default_true")]
    pub middle_proxy_nat_probe: bool,
    /// Deprecated legacy single STUN server for NAT probing.
    /// Use `network.stun_servers` instead.
    #[serde(default = "default_middle_proxy_nat_stun")]
    pub middle_proxy_nat_stun: Option<String>,
    /// Deprecated legacy STUN list for NAT probing fallback.
    /// Use `network.stun_servers` instead.
    #[serde(default = "default_middle_proxy_nat_stun_servers")]
    pub middle_proxy_nat_stun_servers: Vec<String>,
    /// Maximum number of concurrent STUN probes during NAT detection.
    #[serde(default = "default_stun_nat_probe_concurrency")]
    pub stun_nat_probe_concurrency: usize,
    /// Desired size of active Middle-Proxy writer pool.
    #[serde(default = "default_pool_size")]
    pub middle_proxy_pool_size: usize,
    /// Number of warm standby ME connections kept pre-initialized.
    #[serde(default = "default_middle_proxy_warm_standby")]
    pub middle_proxy_warm_standby: usize,
    /// Startup retries for Middle-End pool initialization before ME→Direct fallback.
    /// 0 means unlimited retries.
    #[serde(default = "default_me_init_retry_attempts")]
    pub me_init_retry_attempts: u32,
    /// Allow fallback from Middle-End mode to direct DC when ME startup cannot be initialized.
    #[serde(default = "default_me2dc_fallback")]
    pub me2dc_fallback: bool,
    /// Fast ME->Direct fallback mode for new sessions.
    /// Active only when both `use_middle_proxy=true` and `me2dc_fallback=true`.
    #[serde(default = "default_me2dc_fast")]
    pub me2dc_fast: bool,
    /// Enable ME keepalive padding frames.
    #[serde(default = "default_true")]
    pub me_keepalive_enabled: bool,
    /// Keepalive interval in seconds.
    #[serde(default = "default_keepalive_interval")]
    pub me_keepalive_interval_secs: u64,
    /// Keepalive jitter in seconds.
    #[serde(default = "default_keepalive_jitter")]
    pub me_keepalive_jitter_secs: u64,
    /// Keepalive payload randomized (4 bytes); otherwise zeros.
    #[serde(default = "default_true")]
    pub me_keepalive_payload_random: bool,
    /// Interval in seconds for service RPC_PROXY_REQ activity signals to ME.
    /// 0 disables service activity signals.
    #[serde(default = "default_rpc_proxy_req_every")]
    pub rpc_proxy_req_every: u64,
    /// Capacity of per-ME writer command channel.
    #[serde(default = "default_me_writer_cmd_channel_capacity")]
    pub me_writer_cmd_channel_capacity: usize,
    /// Resident-memory budget in bytes for each ME writer data queue.
    #[serde(default = "default_me_writer_byte_budget_bytes")]
    pub me_writer_byte_budget_bytes: usize,
    /// Capacity of per-connection ME response route channel.
    #[serde(default = "default_me_route_channel_capacity")]
    pub me_route_channel_capacity: usize,
    /// Capacity of per-client command queue from client reader to ME sender task.
    #[serde(default = "default_me_c2me_channel_capacity")]
    pub me_c2me_channel_capacity: usize,
    /// Maximum wait in milliseconds for enqueueing C2ME commands when the queue is full.
    /// `0` keeps legacy unbounded wait behavior.
    #[serde(default = "default_me_c2me_send_timeout_ms")]
    pub me_c2me_send_timeout_ms: u64,
    /// Bounded wait in milliseconds for routing ME DATA to per-connection queue.
    /// `0` keeps non-blocking routing; values >0 enable bounded wait for compatibility.
    #[serde(default = "default_me_reader_route_data_wait_ms")]
    pub me_reader_route_data_wait_ms: u64,
    /// Maximum number of ME->Client responses coalesced before flush.
    #[serde(default = "default_me_d2c_flush_batch_max_frames")]
    pub me_d2c_flush_batch_max_frames: usize,
    /// Maximum total payload bytes coalesced before flush.
    #[serde(default = "default_me_d2c_flush_batch_max_bytes")]
    pub me_d2c_flush_batch_max_bytes: usize,
    /// Maximum wait in microseconds to coalesce additional ME->Client responses.
    /// `0` disables timed coalescing.
    #[serde(default = "default_me_d2c_flush_batch_max_delay_us")]
    pub me_d2c_flush_batch_max_delay_us: u64,
    /// Flush client writer immediately after quick-ack write.
    #[serde(default = "default_me_d2c_ack_flush_immediate")]
    pub me_d2c_ack_flush_immediate: bool,
    /// Additional bytes above strict per-user quota allowed in hot-path soft mode.
    #[serde(default = "default_me_quota_soft_overshoot_bytes")]
    pub me_quota_soft_overshoot_bytes: u64,
    /// Shrink threshold for reusable ME->Client frame assembly buffer.
    #[serde(default = "default_me_d2c_frame_buf_shrink_threshold_bytes")]
    pub me_d2c_frame_buf_shrink_threshold_bytes: usize,
    /// Copy buffer ceiling for client->DC direction in direct relay.
    ///
    /// This is also the upper bound for one amortized upload rate-limit burst:
    /// upload debt is settled before the next relay read instead of blocking
    /// inside the completed read path.
    #[serde(default = "default_direct_relay_copy_buf_c2s_bytes")]
    pub direct_relay_copy_buf_c2s_bytes: usize,
    /// Copy buffer ceiling for DC->client direction in direct relay.
    ///
    /// This bounds one direct download rate-limit grant because writes are
    /// clipped to the currently available shaper budget.
    #[serde(default = "default_direct_relay_copy_buf_s2c_bytes")]
    pub direct_relay_copy_buf_s2c_bytes: usize,
    /// Process-wide hard ceiling for Direct relay copy buffers.
    /// `0` derives the ceiling from host and cgroup memory limits.
    #[serde(default = "default_direct_relay_buffer_budget_max_bytes")]
    pub direct_relay_buffer_budget_max_bytes: usize,
    /// Max pending ciphertext buffer per client writer (bytes).
    /// Controls FakeTLS backpressure vs throughput.
    #[serde(default = "default_crypto_pending_buffer")]
    pub crypto_pending_buffer: usize,
    /// Maximum allowed client MTProto frame size (bytes).
    #[serde(default = "default_max_client_frame")]
    pub max_client_frame: usize,
    /// Emit full crypto-desync forensic logs for every event.
    /// When false, full forensic details are emitted once per key window.
    #[serde(default = "default_desync_all_full")]
    pub desync_all_full: bool,
    /// Enable per-IP forensic observation buckets for scanners and handshake failures.
    #[serde(default = "default_true")]
    pub beobachten: bool,
    /// Observation retention window in minutes for per-IP forensic buckets.
    #[serde(default = "default_beobachten_minutes")]
    pub beobachten_minutes: u64,
    /// Snapshot flush interval in seconds for beob output file.
    #[serde(default = "default_beobachten_flush_secs")]
    pub beobachten_flush_secs: u64,
    /// Snapshot file path for beob output.
    #[serde(default = "default_beobachten_file")]
    pub beobachten_file: String,
    /// Enable C-like hard-swap for ME pool generations.
    /// When true, Telemt prewarms a new generation and switches once full coverage is reached.
    #[serde(default = "default_hardswap")]
    pub hardswap: bool,
    /// Enable staggered warmup of extra ME writers.
    #[serde(default = "default_true")]
    pub me_warmup_stagger_enabled: bool,
    /// Base delay between warmup connections in ms.
    #[serde(default = "default_warmup_step_delay_ms")]
    pub me_warmup_step_delay_ms: u64,
    /// Jitter for warmup delay in ms.
    #[serde(default = "default_warmup_step_jitter_ms")]
    pub me_warmup_step_jitter_ms: u64,
    /// Max concurrent reconnect attempts per DC.
    #[serde(default = "default_me_reconnect_max_concurrent_per_dc")]
    pub me_reconnect_max_concurrent_per_dc: u32,
    /// Base backoff in ms for reconnect.
    #[serde(default = "default_reconnect_backoff_base_ms")]
    pub me_reconnect_backoff_base_ms: u64,
    /// Cap backoff in ms for reconnect.
    #[serde(default = "default_reconnect_backoff_cap_ms")]
    pub me_reconnect_backoff_cap_ms: u64,
    /// Fast retry attempts before backoff.
    #[serde(default = "default_me_reconnect_fast_retry_count")]
    pub me_reconnect_fast_retry_count: u32,
    /// Number of additional reserve writers for DC groups with exactly one endpoint.
    #[serde(default = "default_me_single_endpoint_shadow_writers")]
    pub me_single_endpoint_shadow_writers: u8,
    /// Enable aggressive outage recovery mode for single-endpoint DC groups.
    #[serde(default = "default_me_single_endpoint_outage_mode_enabled")]
    pub me_single_endpoint_outage_mode_enabled: bool,
    /// Ignore endpoint quarantine while in single-endpoint outage mode.
    #[serde(default = "default_me_single_endpoint_outage_disable_quarantine")]
    pub me_single_endpoint_outage_disable_quarantine: bool,
    /// Minimum reconnect backoff in ms for single-endpoint outage mode.
    #[serde(default = "default_me_single_endpoint_outage_backoff_min_ms")]
    pub me_single_endpoint_outage_backoff_min_ms: u64,
    /// Maximum reconnect backoff in ms for single-endpoint outage mode.
    #[serde(default = "default_me_single_endpoint_outage_backoff_max_ms")]
    pub me_single_endpoint_outage_backoff_max_ms: u64,
    /// Periodic shadow writer rotation interval in seconds for single-endpoint DC groups.
    /// Set to 0 to disable periodic shadow rotation.
    #[serde(default = "default_me_single_endpoint_shadow_rotate_every_secs")]
    pub me_single_endpoint_shadow_rotate_every_secs: u64,
    /// Floor policy mode for ME writer targets.
    #[serde(default)]
    pub me_floor_mode: MeFloorMode,
    /// Idle time in seconds before adaptive floor can reduce single-endpoint writer target.
    #[serde(default = "default_me_adaptive_floor_idle_secs")]
    pub me_adaptive_floor_idle_secs: u64,
    /// Minimum writer target for single-endpoint DC groups in adaptive floor mode.
    #[serde(default = "default_me_adaptive_floor_min_writers_single_endpoint")]
    pub me_adaptive_floor_min_writers_single_endpoint: u8,
    /// Minimum writer target for multi-endpoint DC groups in adaptive floor mode.
    #[serde(default = "default_me_adaptive_floor_min_writers_multi_endpoint")]
    pub me_adaptive_floor_min_writers_multi_endpoint: u8,
    /// Grace period in seconds to hold static floor after activity in adaptive mode.
    #[serde(default = "default_me_adaptive_floor_recover_grace_secs")]
    pub me_adaptive_floor_recover_grace_secs: u64,
    /// Global ME writer budget per logical CPU core in adaptive mode.
    #[serde(default = "default_me_adaptive_floor_writers_per_core_total")]
    pub me_adaptive_floor_writers_per_core_total: u16,
    /// Override logical CPU core count for adaptive floor calculations.
    /// Set to 0 to use runtime auto-detection.
    #[serde(default = "default_me_adaptive_floor_cpu_cores_override")]
    pub me_adaptive_floor_cpu_cores_override: u16,
    /// Per-core max extra writers above base required floor for single-endpoint DC groups.
    #[serde(default = "default_me_adaptive_floor_max_extra_writers_single_per_core")]
    pub me_adaptive_floor_max_extra_writers_single_per_core: u16,
    /// Per-core max extra writers above base required floor for multi-endpoint DC groups.
    #[serde(default = "default_me_adaptive_floor_max_extra_writers_multi_per_core")]
    pub me_adaptive_floor_max_extra_writers_multi_per_core: u16,
    /// Hard cap for active ME writers per logical CPU core.
    #[serde(default = "default_me_adaptive_floor_max_active_writers_per_core")]
    pub me_adaptive_floor_max_active_writers_per_core: u16,
    /// Hard cap for warm ME writers per logical CPU core.
    #[serde(default = "default_me_adaptive_floor_max_warm_writers_per_core")]
    pub me_adaptive_floor_max_warm_writers_per_core: u16,
    /// Hard global cap for active ME writers.
    #[serde(default = "default_me_adaptive_floor_max_active_writers_global")]
    pub me_adaptive_floor_max_active_writers_global: u32,
    /// Hard global cap for warm ME writers.
    #[serde(default = "default_me_adaptive_floor_max_warm_writers_global")]
    pub me_adaptive_floor_max_warm_writers_global: u32,
    /// Connect attempts for the selected upstream before returning error/fallback.
    #[serde(default = "default_upstream_connect_retry_attempts")]
    pub upstream_connect_retry_attempts: u32,
    /// Delay in milliseconds between upstream connect attempts.
    #[serde(default = "default_upstream_connect_retry_backoff_ms")]
    pub upstream_connect_retry_backoff_ms: u64,
    /// Total wall-clock budget in milliseconds for one upstream connect request across retries.
    #[serde(default = "default_upstream_connect_budget_ms")]
    pub upstream_connect_budget_ms: u64,
    /// Per-attempt TCP connect timeout to Telegram DC (seconds).
    #[serde(default = "default_connect_timeout")]
    pub tg_connect: u64,
    /// Consecutive failed requests before upstream is marked unhealthy.
    #[serde(default = "default_upstream_unhealthy_fail_threshold")]
    pub upstream_unhealthy_fail_threshold: u32,
    /// Skip additional retries for hard non-transient upstream connect errors.
    #[serde(default = "default_upstream_connect_failfast_hard_errors")]
    pub upstream_connect_failfast_hard_errors: bool,
    /// Ignore STUN/interface IP mismatch (keep using Middle Proxy even if NAT detected).
    #[serde(default)]
    pub stun_iface_mismatch_ignore: bool,
    /// Log unknown (non-standard) DC requests to a file (default: unknown-dc.txt). Set to null to disable.
    #[serde(default = "default_unknown_dc_log_path")]
    pub unknown_dc_log_path: Option<String>,
    /// Enable unknown-DC file logging.
    #[serde(default = "default_unknown_dc_file_log_enabled")]
    pub unknown_dc_file_log_enabled: bool,
    #[serde(default)]
    pub log_level: LogLevel,
    /// Disable colored output in logs (useful for files/systemd).
    #[serde(default)]
    pub disable_colors: bool,
    /// Runtime telemetry controls for counters/metrics in hot paths.
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    /// SOCKS-bound KDF policy for Middle-End handshake.
    #[serde(default)]
    pub me_socks_kdf_policy: MeSocksKdfPolicy,
    /// Enable route-level ME backpressure controls in reader fairness path.
    #[serde(default = "default_me_route_backpressure_enabled")]
    pub me_route_backpressure_enabled: bool,
    /// Enable worker-local fairshare scheduler for ME reader routing.
    #[serde(default = "default_me_route_fairshare_enabled")]
    pub me_route_fairshare_enabled: bool,
    /// Base backpressure timeout in milliseconds for ME route channel send.
    #[serde(default = "default_me_route_backpressure_base_timeout_ms")]
    pub me_route_backpressure_base_timeout_ms: u64,
    /// High backpressure timeout in milliseconds when queue occupancy is above watermark.
    #[serde(default = "default_me_route_backpressure_high_timeout_ms")]
    pub me_route_backpressure_high_timeout_ms: u64,
    /// Queue occupancy percent threshold for high backpressure timeout.
    #[serde(default = "default_me_route_backpressure_high_watermark_pct")]
    pub me_route_backpressure_high_watermark_pct: u8,
    /// Health monitor interval in milliseconds while writer coverage is degraded.
    #[serde(default = "default_me_health_interval_ms_unhealthy")]
    pub me_health_interval_ms_unhealthy: u64,
    /// Health monitor interval in milliseconds while writer coverage is stable.
    #[serde(default = "default_me_health_interval_ms_healthy")]
    pub me_health_interval_ms_healthy: u64,
    /// Poll interval in milliseconds for conditional-admission state checks.
    #[serde(default = "default_me_admission_poll_ms")]
    pub me_admission_poll_ms: u64,
    /// Cooldown for repetitive ME warning logs in milliseconds.
    #[serde(default = "default_me_warn_rate_limit_ms")]
    pub me_warn_rate_limit_ms: u64,
    /// ME route behavior when no writer is immediately available.
    #[serde(default)]
    pub me_route_no_writer_mode: MeRouteNoWriterMode,
    /// Maximum wait time in milliseconds for async-recovery failfast mode.
    #[serde(default = "default_me_route_no_writer_wait_ms")]
    pub me_route_no_writer_wait_ms: u64,
    /// Maximum cumulative wait in milliseconds for hybrid no-writer mode before failfast.
    #[serde(default = "default_me_route_hybrid_max_wait_ms")]
    pub me_route_hybrid_max_wait_ms: u64,
    /// Maximum wait in milliseconds for blocking ME writer channel send fallback.
    /// Must be within [1, 5000].
    #[serde(default = "default_me_route_blocking_send_timeout_ms")]
    pub me_route_blocking_send_timeout_ms: u64,
    /// Number of inline recovery attempts in legacy mode.
    #[serde(default = "default_me_route_inline_recovery_attempts")]
    pub me_route_inline_recovery_attempts: u32,
    /// Maximum wait time in milliseconds for inline recovery in legacy mode.
    #[serde(default = "default_me_route_inline_recovery_wait_ms")]
    pub me_route_inline_recovery_wait_ms: u64,
    /// [general.links] — proxy link generation overrides.
    #[serde(default)]
    pub links: LinksConfig,
    /// Minimum TLS record size when fast_mode coalescing is enabled (0 = disabled).
    #[serde(default = "default_fast_mode_min_tls_record")]
    pub fast_mode_min_tls_record: usize,
    /// Unified ME updater interval in seconds for getProxyConfig/getProxyConfigV6/getProxySecret.
    /// When omitted, effective value falls back to legacy proxy_*_auto_reload_secs fields.
    #[serde(default = "default_update_every")]
    pub update_every: Option<u64>,
    /// Periodic ME pool reinitialization interval in seconds.
    #[serde(default = "default_me_reinit_every_secs")]
    pub me_reinit_every_secs: u64,
    /// Minimum delay in ms between hardswap warmup connect attempts.
    #[serde(default = "default_me_hardswap_warmup_delay_min_ms")]
    pub me_hardswap_warmup_delay_min_ms: u64,
    /// Maximum delay in ms between hardswap warmup connect attempts.
    #[serde(default = "default_me_hardswap_warmup_delay_max_ms")]
    pub me_hardswap_warmup_delay_max_ms: u64,
    /// Additional warmup passes in the same hardswap cycle after the base pass.
    #[serde(default = "default_me_hardswap_warmup_extra_passes")]
    pub me_hardswap_warmup_extra_passes: u8,
    /// Base backoff in ms between hardswap warmup passes when floor is still incomplete.
    #[serde(default = "default_me_hardswap_warmup_pass_backoff_base_ms")]
    pub me_hardswap_warmup_pass_backoff_base_ms: u64,
    /// Number of identical getProxyConfig snapshots required before applying ME map updates.
    #[serde(default = "default_me_config_stable_snapshots")]
    pub me_config_stable_snapshots: u8,
    /// Cooldown in seconds between applied ME map updates.
    #[serde(default = "default_me_config_apply_cooldown_secs")]
    pub me_config_apply_cooldown_secs: u64,
    /// Ensure getProxyConfig snapshots are applied only for 2xx HTTP responses.
    #[serde(default = "default_me_snapshot_require_http_2xx")]
    pub me_snapshot_require_http_2xx: bool,
    /// Reject empty getProxyConfig snapshots instead of marking them applied.
    #[serde(default = "default_me_snapshot_reject_empty_map")]
    pub me_snapshot_reject_empty_map: bool,
    /// Minimum parsed `proxy_for` rows required to accept a snapshot.
    #[serde(default = "default_me_snapshot_min_proxy_for_lines")]
    pub me_snapshot_min_proxy_for_lines: u32,
    /// Number of identical getProxySecret snapshots required before runtime secret rotation.
    #[serde(default = "default_proxy_secret_stable_snapshots")]
    pub proxy_secret_stable_snapshots: u8,
    /// Enable runtime proxy-secret rotation from getProxySecret.
    #[serde(default = "default_proxy_secret_rotate_runtime")]
    pub proxy_secret_rotate_runtime: bool,
    /// Keep key-selector and secret bytes from one snapshot during ME handshake.
    #[serde(default = "default_me_secret_atomic_snapshot")]
    pub me_secret_atomic_snapshot: bool,
    /// Maximum allowed proxy-secret length in bytes for startup and runtime refresh.
    #[serde(default = "default_proxy_secret_len_max")]
    pub proxy_secret_len_max: usize,
    /// Drain-TTL in seconds for stale ME writers after endpoint map changes.
    /// During TTL, stale writers may be used only as fallback for new bindings.
    #[serde(default = "default_me_pool_drain_ttl_secs")]
    pub me_pool_drain_ttl_secs: u64,
    /// Force-remove any draining writer on the next cleanup tick, regardless of age/deadline.
    #[serde(default = "default_me_instadrain")]
    pub me_instadrain: bool,
    /// Maximum allowed number of draining ME writers before oldest ones are force-closed in batches.
    /// Set to 0 to disable threshold-based draining cleanup and keep timeout-only behavior.
    #[serde(default = "default_me_pool_drain_threshold")]
    pub me_pool_drain_threshold: u64,
    /// Enable staged client eviction for draining ME writers that remain non-empty past TTL.
    #[serde(default = "default_me_pool_drain_soft_evict_enabled")]
    pub me_pool_drain_soft_evict_enabled: bool,
    /// Extra grace in seconds after drain TTL before soft-eviction stage starts.
    #[serde(default = "default_me_pool_drain_soft_evict_grace_secs")]
    pub me_pool_drain_soft_evict_grace_secs: u64,
    /// Maximum number of client sessions to evict from one draining writer per health tick.
    #[serde(default = "default_me_pool_drain_soft_evict_per_writer")]
    pub me_pool_drain_soft_evict_per_writer: u8,
    /// Soft-eviction budget per CPU core for one health tick.
    #[serde(default = "default_me_pool_drain_soft_evict_budget_per_core")]
    pub me_pool_drain_soft_evict_budget_per_core: u16,
    /// Cooldown for repetitive soft-eviction on the same writer in milliseconds.
    #[serde(default = "default_me_pool_drain_soft_evict_cooldown_ms")]
    pub me_pool_drain_soft_evict_cooldown_ms: u64,
    /// Policy for new binds on stale draining writers.
    #[serde(default)]
    pub me_bind_stale_mode: MeBindStaleMode,
    /// TTL for stale bind allowance when `me_bind_stale_mode = \"ttl\"`.
    #[serde(default = "default_me_bind_stale_ttl_secs")]
    pub me_bind_stale_ttl_secs: u64,
    /// Minimum desired-DC coverage ratio required before draining stale writers.
    /// Range: 0.0..=1.0.
    #[serde(default = "default_me_pool_min_fresh_ratio")]
    pub me_pool_min_fresh_ratio: f32,
    /// Drain timeout in seconds for stale ME writers after endpoint map changes.
    /// Set to 0 to use the runtime safety fallback timeout.
    #[serde(default = "default_me_reinit_drain_timeout_secs")]
    pub me_reinit_drain_timeout_secs: u64,
    /// Deprecated legacy setting; kept for backward compatibility fallback.
    /// Use `update_every` instead.
    #[serde(default = "default_proxy_secret_reload_secs")]
    pub proxy_secret_auto_reload_secs: u64,
    /// Deprecated legacy setting; kept for backward compatibility fallback.
    /// Use `update_every` instead.
    #[serde(default = "default_proxy_config_reload_secs")]
    pub proxy_config_auto_reload_secs: u64,
    /// Serialize ME reinit cycles across all trigger sources.
    #[serde(default = "default_me_reinit_singleflight")]
    pub me_reinit_singleflight: bool,
    /// Maximum concurrent ME reinit warmups when single-flight mode is disabled.
    #[serde(default = "default_me_reinit_max_concurrency")]
    pub me_reinit_max_concurrency: usize,
    /// Trigger queue capacity for reinit scheduler.
    #[serde(default = "default_me_reinit_trigger_channel")]
    pub me_reinit_trigger_channel: usize,
    /// Trigger coalescing window before starting a reinit cycle.
    #[serde(default = "default_me_reinit_coalesce_window_ms")]
    pub me_reinit_coalesce_window_ms: u64,
    /// Deterministic candidate sort for ME writer binding path.
    #[serde(default = "default_me_deterministic_writer_sort")]
    pub me_deterministic_writer_sort: bool,
    /// Writer selection mode for ME route bind path.
    #[serde(default)]
    pub me_writer_pick_mode: MeWriterPickMode,
    /// Number of candidates sampled by writer picker in `p2c` mode.
    #[serde(default = "default_me_writer_pick_sample_size")]
    pub me_writer_pick_sample_size: u8,
    /// Enable NTP drift check at startup.
    #[serde(default = "default_ntp_check")]
    pub ntp_check: bool,
    /// NTP servers for drift check.
    #[serde(default = "default_ntp_servers")]
    pub ntp_servers: Vec<String>,
    /// Enable auto-degradation from ME to Direct-DC.
    #[serde(default = "default_true")]
    pub auto_degradation_enabled: bool,
    /// Minimum unavailable ME DC groups before degrading.
    #[serde(default = "default_degradation_min_unavailable_dc_groups")]
    pub degradation_min_unavailable_dc_groups: u8,
    /// RST-on-close mode for accepted client sockets.
    /// `off`    — normal FIN on all closes (default).
    /// `errors` — SO_LINGER(0) on accept, cleared after successful auth;
    ///            pre-handshake failures send RST, relayed sessions close gracefully.
    /// `always` — SO_LINGER(0) on accept, never cleared; all closes send RST.
    #[serde(default)]
    pub rst_on_close: RstOnCloseMode,
}
