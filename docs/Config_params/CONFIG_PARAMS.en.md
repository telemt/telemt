# Telemt Config Parameters Reference

This document lists all configuration keys accepted by `config.toml`.

> [!NOTE]
>
> This reference was drafted with the help of AI and cross-checked against the codebase (config schema, defaults, and validation logic).

> [!WARNING]
>
> The configuration parameters detailed in this document are intended for advanced users and fine-tuning purposes. Modifying these settings without a clear understanding of their function may lead to application instability or other unexpected behavior. Please proceed with caution and at your own risk.

# Table of contents
 - [Top-level keys](#top-level-keys)
 - [general](#general)
 - [general.modes](#generalmodes)
 - [general.links](#generallinks)
 - [general.telemetry](#generaltelemetry)
 - [network](#network)
 - [server](#server)
 - [server.conntrack_control](#serverconntrack_control)
 - [server.api](#serverapi)
 - [[server.listeners]](#serverlisteners)
 - [timeouts](#timeouts)
 - [censorship](#censorship)
 - [censorship.tls_fetch](#censorshiptls_fetch)
 - [access](#access)
 - [[upstreams]](#upstreams)

# Top-level keys

| Key | Type | Default |
| --- | ---- | ------- |
| [`include`](#cfg-top-include) | `String` (special directive) | — |
| [`show_link`](#cfg-top-show_link) | `"*"` or `String[]` | `[]` (`ShowLink::None`) |
| [`dc_overrides`](#cfg-top-dc_overrides) | `Map<String, String or String[]>` | `{}` |
| [`default_dc`](#cfg-top-default_dc) | `u8` | — (effective fallback: `2` in ME routing) |

## "cfg-top-include"
- `include`
  - **Constraints / validation**: Must be a single-line directive in the form `include = "path/to/file.toml"`. Includes are expanded before TOML parsing. Maximum include depth is 10.
  - **Description**: Includes another TOML file with `include = "relative/or/absolute/path.toml"`; includes are processed recursively before parsing.
  - **Example**:

    ```toml
    include = "secrets.toml"
    ```
## "cfg-top-show_link"
- `show_link`
  - **Constraints / validation**: Accepts `"*"` or an array of usernames. Empty array means "show none".
  - **Description**: Legacy top-level link visibility selector (`"*"` for all users or explicit usernames list).
  - **Example**:

    ```toml
    # show links for all configured users
    show_link = "*"

    # or: show links only for selected users
    # show_link = ["alice", "bob"]
    ```
## "cfg-top-dc_overrides"
- `dc_overrides`
  - **Constraints / validation**: Key must be a positive integer DC index encoded as string (e.g. `"203"`). Values must parse as `SocketAddr` (`ip:port`). Empty strings are ignored.
  - **Description**: Overrides DC endpoints for non-standard DCs; key is DC index string, value is one or more `ip:port` addresses.
  - **Example**:

    ```toml
    [dc_overrides]
    "201" = "149.154.175.50:443"
    "203" = ["149.154.175.100:443", "91.105.192.100:443"]
    ```
## "cfg-top-default_dc"
- `default_dc`
  - **Constraints / validation**: Intended range is `1..=5`. If set out of range, runtime falls back to DC1 behavior in direct relay; Middle-End routing falls back to `2` when not set.
  - **Description**: Default DC index used for unmapped non-standard DCs.
  - **Example**:

    ```toml
    # When a client requests an unknown/non-standard DC with no override,
    # route it to this default cluster (1..=5).
    default_dc = 2
    ```

# [general]

| Key | Type | Default |
| --- | ---- | ------- |
| [`data_path`](#cfg-general-data_path) | `String` | — |
| [`prefer_ipv6`](#cfg-general-prefer_ipv6) | `bool` | `false` |
| [`fast_mode`](#cfg-general-fast_mode) | `bool` | `true` |
| [`use_middle_proxy`](#cfg-general-use_middle_proxy) | `bool` | `true` |
| [`proxy_secret_path`](#cfg-general-proxy_secret_path) | `String` | `"proxy-secret"` |
| [`proxy_config_v4_cache_path`](#cfg-general-proxy_config_v4_cache_path) | `String` | `"cache/proxy-config-v4.txt"` |
| [`proxy_config_v6_cache_path`](#cfg-general-proxy_config_v6_cache_path) | `String` | `"cache/proxy-config-v6.txt"` |
| [`ad_tag`](#cfg-general-ad_tag) | `String` | — |
| [`middle_proxy_nat_ip`](#cfg-general-middle_proxy_nat_ip) | `IpAddr` | — |
| [`middle_proxy_nat_probe`](#cfg-general-middle_proxy_nat_probe) | `bool` | `true` |
| [`middle_proxy_nat_stun`](#cfg-general-middle_proxy_nat_stun) | `String` | — |
| [`middle_proxy_nat_stun_servers`](#cfg-general-middle_proxy_nat_stun_servers) | `String[]` | `[]` |
| [`stun_nat_probe_concurrency`](#cfg-general-stun_nat_probe_concurrency) | `usize` | `8` |
| [`middle_proxy_pool_size`](#cfg-general-middle_proxy_pool_size) | `usize` | `8` |
| [`middle_proxy_warm_standby`](#cfg-general-middle_proxy_warm_standby) | `usize` | `16` |
| [`me_init_retry_attempts`](#cfg-general-me_init_retry_attempts) | `u32` | `0` |
| [`me2dc_fallback`](#cfg-general-me2dc_fallback) | `bool` | `true` |
| [`me2dc_fast`](#cfg-general-me2dc_fast) | `bool` | `false` |
| [`me_keepalive_enabled`](#cfg-general-me_keepalive_enabled) | `bool` | `true` |
| [`me_keepalive_interval_secs`](#cfg-general-me_keepalive_interval_secs) | `u64` | `8` |
| [`me_keepalive_jitter_secs`](#cfg-general-me_keepalive_jitter_secs) | `u64` | `2` |
| [`me_keepalive_payload_random`](#cfg-general-me_keepalive_payload_random) | `bool` | `true` |
| [`rpc_proxy_req_every`](#cfg-general-rpc_proxy_req_every) | `u64` | `0` |
| [`me_writer_cmd_channel_capacity`](#cfg-general-me_writer_cmd_channel_capacity) | `usize` | `4096` |
| [`me_route_channel_capacity`](#cfg-general-me_route_channel_capacity) | `usize` | `768` |
| [`me_c2me_channel_capacity`](#cfg-general-me_c2me_channel_capacity) | `usize` | `1024` |
| [`me_c2me_send_timeout_ms`](#cfg-general-me_c2me_send_timeout_ms) | `u64` | `4000` |
| [`me_reader_route_data_wait_ms`](#cfg-general-me_reader_route_data_wait_ms) | `u64` | `2` |
| [`me_d2c_flush_batch_max_frames`](#cfg-general-me_d2c_flush_batch_max_frames) | `usize` | `32` |
| [`me_d2c_flush_batch_max_bytes`](#cfg-general-me_d2c_flush_batch_max_bytes) | `usize` | `131072` |
| [`me_d2c_flush_batch_max_delay_us`](#cfg-general-me_d2c_flush_batch_max_delay_us) | `u64` | `500` |
| [`me_d2c_ack_flush_immediate`](#cfg-general-me_d2c_ack_flush_immediate) | `bool` | `true` |
| [`me_quota_soft_overshoot_bytes`](#cfg-general-me_quota_soft_overshoot_bytes) | `u64` | `65536` |
| [`me_d2c_frame_buf_shrink_threshold_bytes`](#cfg-general-me_d2c_frame_buf_shrink_threshold_bytes) | `usize` | `262144` |
| [`direct_relay_copy_buf_c2s_bytes`](#cfg-general-direct_relay_copy_buf_c2s_bytes) | `usize` | `65536` |
| [`direct_relay_copy_buf_s2c_bytes`](#cfg-general-direct_relay_copy_buf_s2c_bytes) | `usize` | `262144` |
| [`crypto_pending_buffer`](#cfg-general-crypto_pending_buffer) | `usize` | `262144` |
| [`max_client_frame`](#cfg-general-max_client_frame) | `usize` | `16777216` |
| [`desync_all_full`](#cfg-general-desync_all_full) | `bool` | `false` |
| [`beobachten`](#cfg-general-beobachten) | `bool` | `true` |
| [`beobachten_minutes`](#cfg-general-beobachten_minutes) | `u64` | `10` |
| [`beobachten_flush_secs`](#cfg-general-beobachten_flush_secs) | `u64` | `15` |
| [`beobachten_file`](#cfg-general-beobachten_file) | `String` | `"cache/beobachten.txt"` |
| [`hardswap`](#cfg-general-hardswap) | `bool` | `true` |
| [`me_warmup_stagger_enabled`](#cfg-general-me_warmup_stagger_enabled) | `bool` | `true` |
| [`me_warmup_step_delay_ms`](#cfg-general-me_warmup_step_delay_ms) | `u64` | `500` |
| [`me_warmup_step_jitter_ms`](#cfg-general-me_warmup_step_jitter_ms) | `u64` | `300` |
| [`me_reconnect_max_concurrent_per_dc`](#cfg-general-me_reconnect_max_concurrent_per_dc) | `u32` | `8` |
| [`me_reconnect_backoff_base_ms`](#cfg-general-me_reconnect_backoff_base_ms) | `u64` | `500` |
| [`me_reconnect_backoff_cap_ms`](#cfg-general-me_reconnect_backoff_cap_ms) | `u64` | `30000` |
| [`me_reconnect_fast_retry_count`](#cfg-general-me_reconnect_fast_retry_count) | `u32` | `16` |
| [`me_single_endpoint_shadow_writers`](#cfg-general-me_single_endpoint_shadow_writers) | `u8` | `2` |
| [`me_single_endpoint_outage_mode_enabled`](#cfg-general-me_single_endpoint_outage_mode_enabled) | `bool` | `true` |
| [`me_single_endpoint_outage_disable_quarantine`](#cfg-general-me_single_endpoint_outage_disable_quarantine) | `bool` | `true` |
| [`me_single_endpoint_outage_backoff_min_ms`](#cfg-general-me_single_endpoint_outage_backoff_min_ms) | `u64` | `250` |
| [`me_single_endpoint_outage_backoff_max_ms`](#cfg-general-me_single_endpoint_outage_backoff_max_ms) | `u64` | `3000` |
| [`me_single_endpoint_shadow_rotate_every_secs`](#cfg-general-me_single_endpoint_shadow_rotate_every_secs) | `u64` | `900` |
| [`me_floor_mode`](#cfg-general-me_floor_mode) | `"static"` or `"adaptive"` | `"adaptive"` |
| [`me_adaptive_floor_idle_secs`](#cfg-general-me_adaptive_floor_idle_secs) | `u64` | `90` |
| [`me_adaptive_floor_min_writers_single_endpoint`](#cfg-general-me_adaptive_floor_min_writers_single_endpoint) | `u8` | `1` |
| [`me_adaptive_floor_min_writers_multi_endpoint`](#cfg-general-me_adaptive_floor_min_writers_multi_endpoint) | `u8` | `1` |
| [`me_adaptive_floor_recover_grace_secs`](#cfg-general-me_adaptive_floor_recover_grace_secs) | `u64` | `180` |
| [`me_adaptive_floor_writers_per_core_total`](#cfg-general-me_adaptive_floor_writers_per_core_total) | `u16` | `48` |
| [`me_adaptive_floor_cpu_cores_override`](#cfg-general-me_adaptive_floor_cpu_cores_override) | `u16` | `0` |
| [`me_adaptive_floor_max_extra_writers_single_per_core`](#cfg-general-me_adaptive_floor_max_extra_writers_single_per_core) | `u16` | `1` |
| [`me_adaptive_floor_max_extra_writers_multi_per_core`](#cfg-general-me_adaptive_floor_max_extra_writers_multi_per_core) | `u16` | `2` |
| [`me_adaptive_floor_max_active_writers_per_core`](#cfg-general-me_adaptive_floor_max_active_writers_per_core) | `u16` | `64` |
| [`me_adaptive_floor_max_warm_writers_per_core`](#cfg-general-me_adaptive_floor_max_warm_writers_per_core) | `u16` | `64` |
| [`me_adaptive_floor_max_active_writers_global`](#cfg-general-me_adaptive_floor_max_active_writers_global) | `u32` | `256` |
| [`me_adaptive_floor_max_warm_writers_global`](#cfg-general-me_adaptive_floor_max_warm_writers_global) | `u32` | `256` |
| [`upstream_connect_retry_attempts`](#cfg-general-upstream_connect_retry_attempts) | `u32` | `2` |
| [`upstream_connect_retry_backoff_ms`](#cfg-general-upstream_connect_retry_backoff_ms) | `u64` | `100` |
| [`upstream_connect_budget_ms`](#cfg-general-upstream_connect_budget_ms) | `u64` | `3000` |
| [`upstream_unhealthy_fail_threshold`](#cfg-general-upstream_unhealthy_fail_threshold) | `u32` | `5` |
| [`upstream_connect_failfast_hard_errors`](#cfg-general-upstream_connect_failfast_hard_errors) | `bool` | `false` |
| [`stun_iface_mismatch_ignore`](#cfg-general-stun_iface_mismatch_ignore) | `bool` | `false` |
| [`unknown_dc_log_path`](#cfg-general-unknown_dc_log_path) | `String` | `"unknown-dc.txt"` |
| [`unknown_dc_file_log_enabled`](#cfg-general-unknown_dc_file_log_enabled) | `bool` | `false` |
| [`log_level`](#cfg-general-log_level) | `"debug"`, `"verbose"`, `"normal"`, or `"silent"` | `"normal"` |
| [`disable_colors`](#cfg-general-disable_colors) | `bool` | `false` |
| [`me_socks_kdf_policy`](#cfg-general-me_socks_kdf_policy) | `"strict"` or `"compat"` | `"strict"` |
| [`me_route_backpressure_base_timeout_ms`](#cfg-general-me_route_backpressure_base_timeout_ms) | `u64` | `25` |
| [`me_route_backpressure_high_timeout_ms`](#cfg-general-me_route_backpressure_high_timeout_ms) | `u64` | `120` |
| [`me_route_backpressure_high_watermark_pct`](#cfg-general-me_route_backpressure_high_watermark_pct) | `u8` | `80` |
| [`me_health_interval_ms_unhealthy`](#cfg-general-me_health_interval_ms_unhealthy) | `u64` | `1000` |
| [`me_health_interval_ms_healthy`](#cfg-general-me_health_interval_ms_healthy) | `u64` | `3000` |
| [`me_admission_poll_ms`](#cfg-general-me_admission_poll_ms) | `u64` | `1000` |
| [`me_warn_rate_limit_ms`](#cfg-general-me_warn_rate_limit_ms) | `u64` | `5000` |
| [`me_route_no_writer_mode`](#cfg-general-me_route_no_writer_mode) | `"async_recovery_failfast"`, `"inline_recovery_legacy"`, or `"hybrid_async_persistent"` | `"hybrid_async_persistent"` |
| [`me_route_no_writer_wait_ms`](#cfg-general-me_route_no_writer_wait_ms) | `u64` | `250` |
| [`me_route_hybrid_max_wait_ms`](#cfg-general-me_route_hybrid_max_wait_ms) | `u64` | `3000` |
| [`me_route_blocking_send_timeout_ms`](#cfg-general-me_route_blocking_send_timeout_ms) | `u64` | `250` |
| [`me_route_inline_recovery_attempts`](#cfg-general-me_route_inline_recovery_attempts) | `u32` | `3` |
| [`me_route_inline_recovery_wait_ms`](#cfg-general-me_route_inline_recovery_wait_ms) | `u64` | `3000` |
| [`fast_mode_min_tls_record`](#cfg-general-fast_mode_min_tls_record) | `usize` | `0` |
| [`update_every`](#cfg-general-update_every) | `u64` | `300` |
| [`me_reinit_every_secs`](#cfg-general-me_reinit_every_secs) | `u64` | `900` |
| [`me_hardswap_warmup_delay_min_ms`](#cfg-general-me_hardswap_warmup_delay_min_ms) | `u64` | `1000` |
| [`me_hardswap_warmup_delay_max_ms`](#cfg-general-me_hardswap_warmup_delay_max_ms) | `u64` | `2000` |
| [`me_hardswap_warmup_extra_passes`](#cfg-general-me_hardswap_warmup_extra_passes) | `u8` | `3` |
| [`me_hardswap_warmup_pass_backoff_base_ms`](#cfg-general-me_hardswap_warmup_pass_backoff_base_ms) | `u64` | `500` |
| [`me_config_stable_snapshots`](#cfg-general-me_config_stable_snapshots) | `u8` | `2` |
| [`me_config_apply_cooldown_secs`](#cfg-general-me_config_apply_cooldown_secs) | `u64` | `300` |
| [`me_snapshot_require_http_2xx`](#cfg-general-me_snapshot_require_http_2xx) | `bool` | `true` |
| [`me_snapshot_reject_empty_map`](#cfg-general-me_snapshot_reject_empty_map) | `bool` | `true` |
| [`me_snapshot_min_proxy_for_lines`](#cfg-general-me_snapshot_min_proxy_for_lines) | `u32` | `1` |
| [`proxy_secret_stable_snapshots`](#cfg-general-proxy_secret_stable_snapshots) | `u8` | `2` |
| [`proxy_secret_rotate_runtime`](#cfg-general-proxy_secret_rotate_runtime) | `bool` | `true` |
| [`me_secret_atomic_snapshot`](#cfg-general-me_secret_atomic_snapshot) | `bool` | `true` |
| [`proxy_secret_len_max`](#cfg-general-proxy_secret_len_max) | `usize` | `256` |
| [`me_pool_drain_ttl_secs`](#cfg-general-me_pool_drain_ttl_secs) | `u64` | `90` |
| [`me_instadrain`](#cfg-general-me_instadrain) | `bool` | `false` |
| [`me_pool_drain_threshold`](#cfg-general-me_pool_drain_threshold) | `u64` | `32` |
| [`me_pool_drain_soft_evict_enabled`](#cfg-general-me_pool_drain_soft_evict_enabled) | `bool` | `true` |
| [`me_pool_drain_soft_evict_grace_secs`](#cfg-general-me_pool_drain_soft_evict_grace_secs) | `u64` | `10` |
| [`me_pool_drain_soft_evict_per_writer`](#cfg-general-me_pool_drain_soft_evict_per_writer) | `u8` | `2` |
| [`me_pool_drain_soft_evict_budget_per_core`](#cfg-general-me_pool_drain_soft_evict_budget_per_core) | `u16` | `16` |
| [`me_pool_drain_soft_evict_cooldown_ms`](#cfg-general-me_pool_drain_soft_evict_cooldown_ms) | `u64` | `1000` |
| [`me_bind_stale_mode`](#cfg-general-me_bind_stale_mode) | `"never"`, `"ttl"`, or `"always"` | `"ttl"` |
| [`me_bind_stale_ttl_secs`](#cfg-general-me_bind_stale_ttl_secs) | `u64` | `90` |
| [`me_pool_min_fresh_ratio`](#cfg-general-me_pool_min_fresh_ratio) | `f32` | `0.8` |
| [`me_reinit_drain_timeout_secs`](#cfg-general-me_reinit_drain_timeout_secs) | `u64` | `90` |
| [`proxy_secret_auto_reload_secs`](#cfg-general-proxy_secret_auto_reload_secs) | `u64` | `3600` |
| [`proxy_config_auto_reload_secs`](#cfg-general-proxy_config_auto_reload_secs) | `u64` | `3600` |
| [`me_reinit_singleflight`](#cfg-general-me_reinit_singleflight) | `bool` | `true` |
| [`me_reinit_trigger_channel`](#cfg-general-me_reinit_trigger_channel) | `usize` | `64` |
| [`me_reinit_coalesce_window_ms`](#cfg-general-me_reinit_coalesce_window_ms) | `u64` | `200` |
| [`me_deterministic_writer_sort`](#cfg-general-me_deterministic_writer_sort) | `bool` | `true` |
| [`me_writer_pick_mode`](#cfg-general-me_writer_pick_mode) | `"sorted_rr"` or `"p2c"` | `"p2c"` |
| [`me_writer_pick_sample_size`](#cfg-general-me_writer_pick_sample_size) | `u8` | `3` |
| [`ntp_check`](#cfg-general-ntp_check) | `bool` | `true` |
| [`ntp_servers`](#cfg-general-ntp_servers) | `String[]` | `["pool.ntp.org"]` |
| [`auto_degradation_enabled`](#cfg-general-auto_degradation_enabled) | `bool` | `true` |
| [`degradation_min_unavailable_dc_groups`](#cfg-general-degradation_min_unavailable_dc_groups) | `u8` | `2` |
| [`rst_on_close`](#cfg-general-rst_on_close) | `"off"`, `"errors"`, or `"always"` | `"off"` |

## "cfg-general-data_path"
- `data_path`
  - **Constraints / validation**: `String` (optional).
  - **Description**: Optional runtime data directory path.
  - **Example**:

    ```toml
    [general]
    data_path = "/var/lib/telemt"
    ```
## "cfg-general-prefer_ipv6"
- `prefer_ipv6`
  - **Constraints / validation**: Deprecated. Use `network.prefer`.
  - **Description**: Deprecated legacy IPv6 preference flag migrated to `network.prefer`.
  - **Example**:

    ```toml
    [network]
    prefer = 6
    ```
## "cfg-general-fast_mode"
- `fast_mode`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables fast-path optimizations for traffic processing.
  - **Example**:

    ```toml
    [general]
    fast_mode = true
    ```
## "cfg-general-use_middle_proxy"
- `use_middle_proxy`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables ME transport mode; if `false`, runtime falls back to direct DC routing.
  - **Example**:

    ```toml
    [general]
    use_middle_proxy = true
    ```
## "cfg-general-proxy_secret_path"
- `proxy_secret_path`
  - **Constraints / validation**: `String`. When omitted, the default path is `"proxy-secret"`. Empty values are accepted by TOML/serde but will likely fail at runtime (invalid file path).
  - **Description**: Path to Telegram infrastructure `proxy-secret` cache file used by ME handshake/RPC auth. Telemt always tries a fresh download from `https://core.telegram.org/getProxySecret` first, caches it to this path on success, and falls back to reading the cached file (any age) on download failure.
  - **Example**:

    ```toml
    [general]
    proxy_secret_path = "proxy-secret"
    ```
## "cfg-general-proxy_config_v4_cache_path"
- `proxy_config_v4_cache_path`
  - **Constraints / validation**: `String`. When set, must not be empty/whitespace-only.
  - **Description**: Optional disk cache path for raw `getProxyConfig` (IPv4) snapshot. At startup Telemt tries to fetch a fresh snapshot first; on fetch failure or empty snapshot it falls back to this cache file when present and non-empty.
  - **Example**:

    ```toml
    [general]
    proxy_config_v4_cache_path = "cache/proxy-config-v4.txt"
    ```
## "cfg-general-proxy_config_v6_cache_path"
- `proxy_config_v6_cache_path`
  - **Constraints / validation**: `String`. When set, must not be empty/whitespace-only.
  - **Description**: Optional disk cache path for raw `getProxyConfigV6` (IPv6) snapshot. At startup Telemt tries to fetch a fresh snapshot first; on fetch failure or empty snapshot it falls back to this cache file when present and non-empty.
  - **Example**:

    ```toml
    [general]
    proxy_config_v6_cache_path = "cache/proxy-config-v6.txt"
    ```
## "cfg-general-ad_tag"
- `ad_tag`
  - **Constraints / validation**: `String` (optional). When set, must be exactly 32 hex characters; invalid values are disabled during config load.
  - **Description**: Global fallback sponsored-channel `ad_tag` (used when user has no override in `access.user_ad_tags`). An all-zero tag is accepted but has no effect (and is warned about) until replaced with a real tag from `@MTProxybot`.
  - **Example**:

    ```toml
    [general]
    ad_tag = "00112233445566778899aabbccddeeff"
    ```
## "cfg-general-middle_proxy_nat_ip"
- `middle_proxy_nat_ip`
  - **Constraints / validation**: `IpAddr` (optional).
  - **Description**: Manual public NAT IP override used as ME address material when set.
  - **Example**:

    ```toml
    [general]
    middle_proxy_nat_ip = "203.0.113.10"
    ```
## "cfg-general-middle_proxy_nat_probe"
- `middle_proxy_nat_probe`
  - **Constraints / validation**: `bool`. Effective probing is gated by `network.stun_use` (when `network.stun_use = false`, STUN probing is disabled even if this flag is `true`).
  - **Description**: Enables STUN-based NAT probing to discover public IP:port used by ME key derivation in NAT environments.
  - **Example**:

    ```toml
    [general]
    middle_proxy_nat_probe = true
    ```
## "cfg-general-middle_proxy_nat_stun"
- `middle_proxy_nat_stun`
  - **Constraints / validation**: Deprecated. Use `network.stun_servers`.
  - **Description**: Deprecated legacy single STUN server for NAT probing. During config load it is merged into `network.stun_servers` unless `network.stun_servers` is explicitly set.
  - **Example**:

    ```toml
    [network]
    stun_servers = ["stun.l.google.com:19302"]
    ```
## "cfg-general-middle_proxy_nat_stun_servers"
- `middle_proxy_nat_stun_servers`
  - **Constraints / validation**: Deprecated. Use `network.stun_servers`.
  - **Description**: Deprecated legacy STUN list for NAT probing fallback. During config load it is merged into `network.stun_servers` unless `network.stun_servers` is explicitly set.
  - **Example**:

    ```toml
    [network]
    stun_servers = ["stun.l.google.com:19302"]
    ```
## "cfg-general-stun_nat_probe_concurrency"
- `stun_nat_probe_concurrency`
  - **Constraints / validation**: Must be `> 0`.
  - **Description**: Maximum number of parallel STUN probes during NAT/public endpoint discovery.
  - **Example**:

    ```toml
    [general]
    stun_nat_probe_concurrency = 8
    ```
## "cfg-general-middle_proxy_pool_size"
- `middle_proxy_pool_size`
  - **Constraints / validation**: `usize`. Effective value is `max(value, 1)` at runtime (so `0` behaves as `1`).
  - **Description**: Target size of active ME writer pool.
  - **Example**:

    ```toml
    [general]
    middle_proxy_pool_size = 8
    ```
## "cfg-general-middle_proxy_warm_standby"
- `middle_proxy_warm_standby`
  - **Constraints / validation**: `usize`.
  - **Description**: Number of warm standby ME connections kept pre-initialized.
  - **Example**:

    ```toml
    [general]
    middle_proxy_warm_standby = 16
    ```
## "cfg-general-me_init_retry_attempts"
- `me_init_retry_attempts`
  - **Constraints / validation**: `0..=1_000_000` (`0` means unlimited retries).
  - **Description**: Startup retries for ME pool initialization.
  - **Example**:

    ```toml
    [general]
    me_init_retry_attempts = 0
    ```
## "cfg-general-me2dc_fallback"
- `me2dc_fallback`
  - **Constraints / validation**: `bool`.
  - **Description**: Allows fallback from ME mode to direct DC when ME startup fails.
  - **Example**:

    ```toml
    [general]
    me2dc_fallback = true
    ```
## "cfg-general-me2dc_fast"
- `me2dc_fast`
  - **Constraints / validation**: `bool`. Active only when `use_middle_proxy = true` and `me2dc_fallback = true`.
  - **Description**: Fast ME->Direct fallback mode for new sessions.
  - **Example**:

    ```toml
    [general]
    use_middle_proxy = true
    me2dc_fallback = true
    me2dc_fast = false
    ```
## "cfg-general-me_keepalive_enabled"
- `me_keepalive_enabled`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables periodic ME keepalive padding frames.
  - **Example**:

    ```toml
    [general]
    me_keepalive_enabled = true
    ```
## "cfg-general-me_keepalive_interval_secs"
- `me_keepalive_interval_secs`
  - **Constraints / validation**: `u64` (seconds).
  - **Description**: Base ME keepalive interval in seconds.
  - **Example**:

    ```toml
    [general]
    me_keepalive_interval_secs = 8
    ```
## "cfg-general-me_keepalive_jitter_secs"
- `me_keepalive_jitter_secs`
  - **Constraints / validation**: `u64` (seconds).
  - **Description**: Keepalive jitter in seconds to reduce synchronized bursts.
  - **Example**:

    ```toml
    [general]
    me_keepalive_jitter_secs = 2
    ```
## "cfg-general-me_keepalive_payload_random"
- `me_keepalive_payload_random`
  - **Constraints / validation**: `bool`.
  - **Description**: Randomizes keepalive payload bytes instead of fixed zero payload.
  - **Example**:

    ```toml
    [general]
    me_keepalive_payload_random = true
    ```
## "cfg-general-rpc_proxy_req_every"
- `rpc_proxy_req_every`
  - **Constraints / validation**: `0` or within `10..=300` (seconds).
  - **Description**: Interval for service `RPC_PROXY_REQ` activity signals to ME (`0` disables).
  - **Example**:

    ```toml
    [general]
    rpc_proxy_req_every = 0
    ```
## "cfg-general-me_writer_cmd_channel_capacity"
- `me_writer_cmd_channel_capacity`
  - **Constraints / validation**: Must be `> 0`.
  - **Description**: Capacity of per-writer command channel.
  - **Example**:

    ```toml
    [general]
    me_writer_cmd_channel_capacity = 4096
    ```
## "cfg-general-me_route_channel_capacity"
- `me_route_channel_capacity`
  - **Constraints / validation**: Must be `> 0`.
  - **Description**: Capacity of per-connection ME response route channel.
  - **Example**:

    ```toml
    [general]
    me_route_channel_capacity = 768
    ```
## "cfg-general-me_c2me_channel_capacity"
- `me_c2me_channel_capacity`
  - **Constraints / validation**: Must be `> 0`.
  - **Description**: Capacity of per-client command queue (client reader -> ME sender).
  - **Example**:

    ```toml
    [general]
    me_c2me_channel_capacity = 1024
    ```
## "cfg-general-me_c2me_send_timeout_ms"
- `me_c2me_send_timeout_ms`
  - **Constraints / validation**: `0..=60000` (milliseconds).
  - **Description**: Maximum wait for enqueueing client->ME commands when the per-client queue is full (`0` keeps legacy unbounded wait).
  - **Example**:

    ```toml
    [general]
    me_c2me_send_timeout_ms = 4000
    ```
## "cfg-general-me_reader_route_data_wait_ms"
- `me_reader_route_data_wait_ms`
  - **Constraints / validation**: `0..=20` (milliseconds).
  - **Description**: Bounded wait for routing ME DATA to per-connection queue (`0` = no wait).
  - **Example**:

    ```toml
    [general]
    me_reader_route_data_wait_ms = 2
    ```
## "cfg-general-me_d2c_flush_batch_max_frames"
- `me_d2c_flush_batch_max_frames`
  - **Constraints / validation**: Must be within `1..=512`.
  - **Description**: Max ME->client frames coalesced before flush.
  - **Example**:

    ```toml
    [general]
    me_d2c_flush_batch_max_frames = 32
    ```
## "cfg-general-me_d2c_flush_batch_max_bytes"
- `me_d2c_flush_batch_max_bytes`
  - **Constraints / validation**: Must be within `4096..=2097152` (bytes).
  - **Description**: Max ME->client payload bytes coalesced before flush.
  - **Example**:

    ```toml
    [general]
    me_d2c_flush_batch_max_bytes = 131072
    ```
## "cfg-general-me_d2c_flush_batch_max_delay_us"
- `me_d2c_flush_batch_max_delay_us`
  - **Constraints / validation**: `0..=5000` (microseconds).
  - **Description**: Max microsecond wait for coalescing more ME->client frames (`0` disables timed coalescing).
  - **Example**:

    ```toml
    [general]
    me_d2c_flush_batch_max_delay_us = 500
    ```
## "cfg-general-me_d2c_ack_flush_immediate"
- `me_d2c_ack_flush_immediate`
  - **Constraints / validation**: `bool`.
  - **Description**: Flushes client writer immediately after quick-ack write.
  - **Example**:

    ```toml
    [general]
    me_d2c_ack_flush_immediate = true
    ```
## "cfg-general-me_quota_soft_overshoot_bytes"
- `me_quota_soft_overshoot_bytes`
  - **Constraints / validation**: `0..=16777216` (bytes).
  - **Description**: Extra per-route quota allowance (bytes) tolerated before writer-side quota enforcement drops route data.
  - **Example**:

    ```toml
    [general]
    me_quota_soft_overshoot_bytes = 65536
    ```
## "cfg-general-me_d2c_frame_buf_shrink_threshold_bytes"
- `me_d2c_frame_buf_shrink_threshold_bytes`
  - **Constraints / validation**: Must be within `4096..=16777216` (bytes).
  - **Description**: Threshold for shrinking oversized ME->client frame-aggregation buffers after flush.
  - **Example**:

    ```toml
    [general]
    me_d2c_frame_buf_shrink_threshold_bytes = 262144
    ```
## "cfg-general-direct_relay_copy_buf_c2s_bytes"
- `direct_relay_copy_buf_c2s_bytes`
  - **Constraints / validation**: Must be within `4096..=1048576` (bytes).
  - **Description**: Copy buffer size for client->DC direction in direct relay.
  - **Example**:

    ```toml
    [general]
    direct_relay_copy_buf_c2s_bytes = 65536
    ```
## "cfg-general-direct_relay_copy_buf_s2c_bytes"
- `direct_relay_copy_buf_s2c_bytes`
  - **Constraints / validation**: Must be within `8192..=2097152` (bytes).
  - **Description**: Copy buffer size for DC->client direction in direct relay.
  - **Example**:

    ```toml
    [general]
    direct_relay_copy_buf_s2c_bytes = 262144
    ```
## "cfg-general-crypto_pending_buffer"
- `crypto_pending_buffer`
  - **Constraints / validation**: `usize` (bytes).
  - **Description**: Max pending ciphertext buffer per client writer (bytes).
  - **Example**:

    ```toml
    [general]
    crypto_pending_buffer = 262144
    ```
## "cfg-general-max_client_frame"
- `max_client_frame`
  - **Constraints / validation**: `usize` (bytes).
  - **Description**: Maximum allowed client MTProto frame size (bytes).
  - **Example**:

    ```toml
    [general]
    max_client_frame = 16777216
    ```
## "cfg-general-desync_all_full"
- `desync_all_full`
  - **Constraints / validation**: `bool`.
  - **Description**: Emits full crypto-desync forensic logs for every event.
  - **Example**:

    ```toml
    [general]
    desync_all_full = false
    ```
## "cfg-general-beobachten"
- `beobachten`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables per-IP forensic observation buckets.
  - **Example**:

    ```toml
    [general]
    beobachten = true
    ```
## "cfg-general-beobachten_minutes"
- `beobachten_minutes`
  - **Constraints / validation**: Must be `> 0` (minutes).
  - **Description**: Retention window (minutes) for per-IP observation buckets.
  - **Example**:

    ```toml
    [general]
    beobachten_minutes = 10
    ```
## "cfg-general-beobachten_flush_secs"
- `beobachten_flush_secs`
  - **Constraints / validation**: Must be `> 0` (seconds).
  - **Description**: Snapshot flush interval (seconds) for observation output file.
  - **Example**:

    ```toml
    [general]
    beobachten_flush_secs = 15
    ```
## "cfg-general-beobachten_file"
- `beobachten_file`
  - **Constraints / validation**: Must not be empty/whitespace-only.
  - **Description**: Observation snapshot output file path.
  - **Example**:

    ```toml
    [general]
    beobachten_file = "cache/beobachten.txt"
    ```
## "cfg-general-hardswap"
- `hardswap`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables generation-based ME hardswap strategy.
  - **Example**:

    ```toml
    [general]
    hardswap = true
    ```
## "cfg-general-me_warmup_stagger_enabled"
- `me_warmup_stagger_enabled`
  - **Constraints / validation**: `bool`.
  - **Description**: Staggers extra ME warmup dials to avoid connection spikes.
  - **Example**:

    ```toml
    [general]
    me_warmup_stagger_enabled = true
    ```
## "cfg-general-me_warmup_step_delay_ms"
- `me_warmup_step_delay_ms`
  - **Constraints / validation**: `u64` (milliseconds).
  - **Description**: Base delay in milliseconds between warmup dial steps.
  - **Example**:

    ```toml
    [general]
    me_warmup_step_delay_ms = 500
    ```
## "cfg-general-me_warmup_step_jitter_ms"
- `me_warmup_step_jitter_ms`
  - **Constraints / validation**: `u64` (milliseconds).
  - **Description**: Additional random delay in milliseconds for warmup steps.
  - **Example**:

    ```toml
    [general]
    me_warmup_step_jitter_ms = 300
    ```
## "cfg-general-me_reconnect_max_concurrent_per_dc"
- `me_reconnect_max_concurrent_per_dc`
  - **Constraints / validation**: `u32`. Effective value is `max(value, 1)` at runtime (so `0` behaves as `1`).
  - **Description**: Limits concurrent reconnect workers per DC during health recovery.
  - **Example**:

    ```toml
    [general]
    me_reconnect_max_concurrent_per_dc = 8
    ```
## "cfg-general-me_reconnect_backoff_base_ms"
- `me_reconnect_backoff_base_ms`
  - **Constraints / validation**: `u64` (milliseconds).
  - **Description**: Initial reconnect backoff in milliseconds.
  - **Example**:

    ```toml
    [general]
    me_reconnect_backoff_base_ms = 500
    ```
## "cfg-general-me_reconnect_backoff_cap_ms"
- `me_reconnect_backoff_cap_ms`
  - **Constraints / validation**: `u64` (milliseconds).
  - **Description**: Maximum reconnect backoff cap in milliseconds.
  - **Example**:

    ```toml
    [general]
    me_reconnect_backoff_cap_ms = 30000
    ```
## "cfg-general-me_reconnect_fast_retry_count"
- `me_reconnect_fast_retry_count`
  - **Constraints / validation**: `u32`. Effective value is `max(value, 1)` at runtime (so `0` behaves as `1`).
  - **Description**: Immediate retry budget before long backoff behavior applies.
  - **Example**:

    ```toml
    [general]
    me_reconnect_fast_retry_count = 16
    ```
## "cfg-general-me_single_endpoint_shadow_writers"
- `me_single_endpoint_shadow_writers`
  - **Constraints / validation**: Must be within `0..=32`.
  - **Description**: Additional reserve writers for DC groups with exactly one endpoint.
  - **Example**:

    ```toml
    [general]
    me_single_endpoint_shadow_writers = 2
    ```
## "cfg-general-me_single_endpoint_outage_mode_enabled"
- `me_single_endpoint_outage_mode_enabled`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables aggressive outage recovery mode for DC groups with exactly one endpoint.
  - **Example**:

    ```toml
    [general]
    me_single_endpoint_outage_mode_enabled = true
    ```
## "cfg-general-me_single_endpoint_outage_disable_quarantine"
- `me_single_endpoint_outage_disable_quarantine`
  - **Constraints / validation**: `bool`.
  - **Description**: Ignores endpoint quarantine while in single-endpoint outage mode.
  - **Example**:

    ```toml
    [general]
    me_single_endpoint_outage_disable_quarantine = true
    ```
## "cfg-general-me_single_endpoint_outage_backoff_min_ms"
- `me_single_endpoint_outage_backoff_min_ms`
  - **Constraints / validation**: Must be `> 0` (milliseconds) and `<= me_single_endpoint_outage_backoff_max_ms`.
  - **Description**: Minimum reconnect backoff in single-endpoint outage mode.
  - **Example**:

    ```toml
    [general]
    me_single_endpoint_outage_backoff_min_ms = 250
    ```
## "cfg-general-me_single_endpoint_outage_backoff_max_ms"
- `me_single_endpoint_outage_backoff_max_ms`
  - **Constraints / validation**: Must be `> 0` (milliseconds) and `>= me_single_endpoint_outage_backoff_min_ms`.
  - **Description**: Maximum reconnect backoff in single-endpoint outage mode.
  - **Example**:

    ```toml
    [general]
    me_single_endpoint_outage_backoff_max_ms = 3000
    ```
## "cfg-general-me_single_endpoint_shadow_rotate_every_secs"
- `me_single_endpoint_shadow_rotate_every_secs`
  - **Constraints / validation**: `u64` (seconds). `0` disables periodic shadow rotation.
  - **Description**: Periodic shadow writer rotation interval for single-endpoint DC groups.
  - **Example**:

    ```toml
    [general]
    me_single_endpoint_shadow_rotate_every_secs = 900
    ```
## "cfg-general-me_floor_mode"
- `me_floor_mode`
  - **Constraints / validation**: `"static"` or `"adaptive"`.
  - **Description**: Floor policy mode for ME writer targets.
  - **Example**:

    ```toml
    [general]
    me_floor_mode = "adaptive"
    ```
## "cfg-general-me_adaptive_floor_idle_secs"
- `me_adaptive_floor_idle_secs`
  - **Constraints / validation**: `u64` (seconds).
  - **Description**: Idle time before adaptive floor may reduce the single-endpoint writer target.
  - **Example**:

    ```toml
    [general]
    me_adaptive_floor_idle_secs = 90
    ```
## "cfg-general-me_adaptive_floor_min_writers_single_endpoint"
- `me_adaptive_floor_min_writers_single_endpoint`
  - **Constraints / validation**: Must be within `1..=32`.
  - **Description**: Minimum writer target for single-endpoint DC groups in adaptive floor mode.
  - **Example**:

    ```toml
    [general]
    me_adaptive_floor_min_writers_single_endpoint = 1
    ```
## "cfg-general-me_adaptive_floor_min_writers_multi_endpoint"
- `me_adaptive_floor_min_writers_multi_endpoint`
  - **Constraints / validation**: Must be within `1..=32`.
  - **Description**: Minimum writer target for multi-endpoint DC groups in adaptive floor mode.
  - **Example**:

    ```toml
    [general]
    me_adaptive_floor_min_writers_multi_endpoint = 1
    ```
## "cfg-general-me_adaptive_floor_recover_grace_secs"
- `me_adaptive_floor_recover_grace_secs`
  - **Constraints / validation**: `u64` (seconds).
  - **Description**: Grace period to hold static floor after activity in adaptive mode.
  - **Example**:

    ```toml
    [general]
    me_adaptive_floor_recover_grace_secs = 180
    ```
## "cfg-general-me_adaptive_floor_writers_per_core_total"
- `me_adaptive_floor_writers_per_core_total`
  - **Constraints / validation**: Must be `> 0`.
  - **Description**: Global ME writer budget per logical CPU core in adaptive mode.
  - **Example**:

    ```toml
    [general]
    me_adaptive_floor_writers_per_core_total = 48
    ```
## "cfg-general-me_adaptive_floor_cpu_cores_override"
- `me_adaptive_floor_cpu_cores_override`
  - **Constraints / validation**: `u16`. `0` uses runtime auto-detection.
  - **Description**: Override logical CPU core count used for adaptive floor calculations.
  - **Example**:

    ```toml
    [general]
    me_adaptive_floor_cpu_cores_override = 0
    ```
## "cfg-general-me_adaptive_floor_max_extra_writers_single_per_core"
- `me_adaptive_floor_max_extra_writers_single_per_core`
  - **Constraints / validation**: `u16`.
  - **Description**: Per-core max extra writers above base required floor for single-endpoint DC groups.
  - **Example**:

    ```toml
    [general]
    me_adaptive_floor_max_extra_writers_single_per_core = 1
    ```
## "cfg-general-me_adaptive_floor_max_extra_writers_multi_per_core"
- `me_adaptive_floor_max_extra_writers_multi_per_core`
  - **Constraints / validation**: `u16`.
  - **Description**: Per-core max extra writers above base required floor for multi-endpoint DC groups.
  - **Example**:

    ```toml
    [general]
    me_adaptive_floor_max_extra_writers_multi_per_core = 2
    ```
## "cfg-general-me_adaptive_floor_max_active_writers_per_core"
- `me_adaptive_floor_max_active_writers_per_core`
  - **Constraints / validation**: Must be `> 0`.
  - **Description**: Hard cap for active ME writers per logical CPU core.
  - **Example**:

    ```toml
    [general]
    me_adaptive_floor_max_active_writers_per_core = 64
    ```
## "cfg-general-me_adaptive_floor_max_warm_writers_per_core"
- `me_adaptive_floor_max_warm_writers_per_core`
  - **Constraints / validation**: Must be `> 0`.
  - **Description**: Hard cap for warm ME writers per logical CPU core.
  - **Example**:

    ```toml
    [general]
    me_adaptive_floor_max_warm_writers_per_core = 64
    ```
## "cfg-general-me_adaptive_floor_max_active_writers_global"
- `me_adaptive_floor_max_active_writers_global`
  - **Constraints / validation**: Must be `> 0`.
  - **Description**: Hard global cap for active ME writers.
  - **Example**:

    ```toml
    [general]
    me_adaptive_floor_max_active_writers_global = 256
    ```
## "cfg-general-me_adaptive_floor_max_warm_writers_global"
- `me_adaptive_floor_max_warm_writers_global`
  - **Constraints / validation**: Must be `> 0`.
  - **Description**: Hard global cap for warm ME writers.
  - **Example**:

    ```toml
    [general]
    me_adaptive_floor_max_warm_writers_global = 256
    ```
## "cfg-general-upstream_connect_retry_attempts"
- `upstream_connect_retry_attempts`
  - **Constraints / validation**: Must be `> 0`.
  - **Description**: Connect attempts for the selected upstream before returning error/fallback.
  - **Example**:

    ```toml
    [general]
    upstream_connect_retry_attempts = 2
    ```
## "cfg-general-upstream_connect_retry_backoff_ms"
- `upstream_connect_retry_backoff_ms`
  - **Constraints / validation**: `u64` (milliseconds). `0` disables backoff delay (retries become immediate).
  - **Description**: Delay in milliseconds between upstream connect attempts.
  - **Example**:

    ```toml
    [general]
    upstream_connect_retry_backoff_ms = 100
    ```
## "cfg-general-upstream_connect_budget_ms"
- `upstream_connect_budget_ms`
  - **Constraints / validation**: Must be `> 0` (milliseconds).
  - **Description**: Total wall-clock budget in milliseconds for one upstream connect request across retries.
  - **Example**:

    ```toml
    [general]
    upstream_connect_budget_ms = 3000
    ```
## "cfg-general-upstream_unhealthy_fail_threshold"
- `upstream_unhealthy_fail_threshold`
  - **Constraints / validation**: Must be `> 0`.
  - **Description**: Consecutive failed requests before upstream is marked unhealthy.
  - **Example**:

    ```toml
    [general]
    upstream_unhealthy_fail_threshold = 5
    ```
## "cfg-general-upstream_connect_failfast_hard_errors"
- `upstream_connect_failfast_hard_errors`
  - **Constraints / validation**: `bool`.
  - **Description**: When true, skips additional retries for hard non-transient upstream connect errors.
  - **Example**:

    ```toml
    [general]
    upstream_connect_failfast_hard_errors = false
    ```
## "cfg-general-stun_iface_mismatch_ignore"
- `stun_iface_mismatch_ignore`
  - **Constraints / validation**: `bool`.
  - **Description**: Compatibility flag reserved for future use. Currently this key is parsed but not used by the runtime.
  - **Example**:

    ```toml
    [general]
    stun_iface_mismatch_ignore = false
    ```
## "cfg-general-unknown_dc_log_path"
- `unknown_dc_log_path`
  - **Constraints / validation**: `String` (optional). Must be a safe path (no `..` components, parent directory must exist); unsafe paths are rejected at runtime.
  - **Description**: Log file path for unknown (non-standard) DC requests when `unknown_dc_file_log_enabled = true`. Omit this key to disable file logging.
  - **Example**:

    ```toml
    [general]
    unknown_dc_log_path = "unknown-dc.txt"
    ```
## "cfg-general-unknown_dc_file_log_enabled"
- `unknown_dc_file_log_enabled`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables unknown-DC file logging (writes `dc_idx=<N>` lines). Requires `unknown_dc_log_path` to be set and, on non-Unix platforms, may be unsupported. Logging is deduplicated and capped (only the first ~1024 distinct unknown DC indices are recorded).
  - **Example**:

    ```toml
    [general]
    unknown_dc_file_log_enabled = false
    ```
## "cfg-general-log_level"
- `log_level`
  - **Constraints / validation**: `"debug"`, `"verbose"`, `"normal"`, or `"silent"`.
  - **Description**: Runtime logging verbosity level (used when `RUST_LOG` is not set). If `RUST_LOG` is set in the environment, it takes precedence over this setting.
  - **Example**:

    ```toml
    [general]
    log_level = "normal"
    ```
## "cfg-general-disable_colors"
- `disable_colors`
  - **Constraints / validation**: `bool`.
  - **Description**: Disables ANSI colors in logs (useful for files/systemd). This affects log formatting only and does not change the log level/filtering.
  - **Example**:

    ```toml
    [general]
    disable_colors = false
    ```
## "cfg-general-me_socks_kdf_policy"
- `me_socks_kdf_policy`
  - **Constraints / validation**: `"strict"` or `"compat"`.
  - **Description**: SOCKS-bound KDF fallback policy for Middle-End handshake.
  - **Example**:

    ```toml
    [general]
    me_socks_kdf_policy = "strict"
    ```
## "cfg-general-me_route_backpressure_base_timeout_ms"
- `me_route_backpressure_base_timeout_ms`
  - **Constraints / validation**: Must be within `1..=5000` (milliseconds).
  - **Description**: Base backpressure timeout in milliseconds for ME route-channel send.
  - **Example**:

    ```toml
    [general]
    me_route_backpressure_base_timeout_ms = 25
    ```
## "cfg-general-me_route_backpressure_high_timeout_ms"
- `me_route_backpressure_high_timeout_ms`
  - **Constraints / validation**: Must be within `1..=5000` (milliseconds) and `>= me_route_backpressure_base_timeout_ms`.
  - **Description**: High backpressure timeout in milliseconds when queue occupancy is above watermark.
  - **Example**:

    ```toml
    [general]
    me_route_backpressure_high_timeout_ms = 120
    ```
## "cfg-general-me_route_backpressure_high_watermark_pct"
- `me_route_backpressure_high_watermark_pct`
  - **Constraints / validation**: Must be within `1..=100` (percent).
  - **Description**: Queue occupancy percent threshold for switching to high backpressure timeout.
  - **Example**:

    ```toml
    [general]
    me_route_backpressure_high_watermark_pct = 80
    ```
## "cfg-general-me_health_interval_ms_unhealthy"
- `me_health_interval_ms_unhealthy`
  - **Constraints / validation**: Must be `> 0` (milliseconds).
  - **Description**: Health monitor interval while ME writer coverage is degraded.
  - **Example**:

    ```toml
    [general]
    me_health_interval_ms_unhealthy = 1000
    ```
## "cfg-general-me_health_interval_ms_healthy"
- `me_health_interval_ms_healthy`
  - **Constraints / validation**: Must be `> 0` (milliseconds).
  - **Description**: Health monitor interval while ME writer coverage is stable/healthy.
  - **Example**:

    ```toml
    [general]
    me_health_interval_ms_healthy = 3000
    ```
## "cfg-general-me_admission_poll_ms"
- `me_admission_poll_ms`
  - **Constraints / validation**: Must be `> 0` (milliseconds).
  - **Description**: Poll interval for conditional-admission state checks.
  - **Example**:

    ```toml
    [general]
    me_admission_poll_ms = 1000
    ```
## "cfg-general-me_warn_rate_limit_ms"
- `me_warn_rate_limit_ms`
  - **Constraints / validation**: Must be `> 0` (milliseconds).
  - **Description**: Cooldown for repetitive ME warning logs.
  - **Example**:

    ```toml
    [general]
    me_warn_rate_limit_ms = 5000
    ```
## "cfg-general-me_route_no_writer_mode"
- `me_route_no_writer_mode`
  - **Constraints / validation**: `"async_recovery_failfast"`, `"inline_recovery_legacy"`, or `"hybrid_async_persistent"`.
  - **Description**: ME route behavior when no writer is immediately available.
  - **Example**:

    ```toml
    [general]
    me_route_no_writer_mode = "hybrid_async_persistent"
    ```
## "cfg-general-me_route_no_writer_wait_ms"
- `me_route_no_writer_wait_ms`
  - **Constraints / validation**: Must be within `10..=5000` (milliseconds).
  - **Description**: Max wait time used by async-recovery failfast mode before falling back.
  - **Example**:

    ```toml
    [general]
    me_route_no_writer_wait_ms = 250
    ```
## "cfg-general-me_route_hybrid_max_wait_ms"
- `me_route_hybrid_max_wait_ms`
  - **Constraints / validation**: Must be within `50..=60000` (milliseconds).
  - **Description**: Maximum cumulative wait in hybrid no-writer mode before failfast fallback.
  - **Example**:

    ```toml
    [general]
    me_route_hybrid_max_wait_ms = 3000
    ```
## "cfg-general-me_route_blocking_send_timeout_ms"
- `me_route_blocking_send_timeout_ms`
  - **Constraints / validation**: Must be within `0..=5000` (milliseconds). `0` keeps legacy unbounded wait behavior.
  - **Description**: Maximum wait for blocking route-channel send fallback.
  - **Example**:

    ```toml
    [general]
    me_route_blocking_send_timeout_ms = 250
    ```
## "cfg-general-me_route_inline_recovery_attempts"
- `me_route_inline_recovery_attempts`
  - **Constraints / validation**: Must be `> 0`.
  - **Description**: Number of inline recovery attempts in legacy mode.
  - **Example**:

    ```toml
    [general]
    me_route_inline_recovery_attempts = 3
    ```
## "cfg-general-me_route_inline_recovery_wait_ms"
- `me_route_inline_recovery_wait_ms`
  - **Constraints / validation**: Must be within `10..=30000` (milliseconds).
  - **Description**: Max inline recovery wait in legacy mode.
  - **Example**:

    ```toml
    [general]
    me_route_inline_recovery_wait_ms = 3000
    ```
## "cfg-general-fast_mode_min_tls_record"
- `fast_mode_min_tls_record`
  - **Constraints / validation**: `usize` (bytes). `0` disables the limit.
  - **Description**: Minimum TLS record size when fast-mode coalescing is enabled.
  - **Example**:

    ```toml
    [general]
    fast_mode_min_tls_record = 0
    ```
## "cfg-general-update_every"
- `update_every`
  - **Constraints / validation**: `u64` (seconds). If set, must be `> 0`. If this key is not explicitly set, legacy `proxy_secret_auto_reload_secs` and `proxy_config_auto_reload_secs` may be used (their effective minimum must be `> 0`).
  - **Description**: Unified refresh interval for ME updater tasks (`getProxyConfig`, `getProxyConfigV6`, `getProxySecret`). When set, it overrides legacy proxy reload intervals.
  - **Example**:

    ```toml
    [general]
    update_every = 300
    ```
## "cfg-general-me_reinit_every_secs"
- `me_reinit_every_secs`
  - **Constraints / validation**: Must be `> 0` (seconds).
  - **Description**: Periodic interval for zero-downtime ME reinit cycle.
  - **Example**:

    ```toml
    [general]
    me_reinit_every_secs = 900
    ```
## "cfg-general-me_hardswap_warmup_delay_min_ms"
- `me_hardswap_warmup_delay_min_ms`
  - **Constraints / validation**: `u64` (milliseconds). Must be `<= me_hardswap_warmup_delay_max_ms`.
  - **Description**: Lower bound for hardswap warmup dial spacing.
  - **Example**:

    ```toml
    [general]
    me_hardswap_warmup_delay_min_ms = 1000
    ```
## "cfg-general-me_hardswap_warmup_delay_max_ms"
- `me_hardswap_warmup_delay_max_ms`
  - **Constraints / validation**: Must be `> 0` (milliseconds).
  - **Description**: Upper bound for hardswap warmup dial spacing.
  - **Example**:

    ```toml
    [general]
    me_hardswap_warmup_delay_max_ms = 2000
    ```
## "cfg-general-me_hardswap_warmup_extra_passes"
- `me_hardswap_warmup_extra_passes`
  - **Constraints / validation**: Must be within `[0, 10]`.
  - **Description**: Additional warmup passes after the base pass in one hardswap cycle.
  - **Example**:

    ```toml
    [general]
    # default: 3 (allowed range: 0..=10)
    me_hardswap_warmup_extra_passes = 3
    ```
## "cfg-general-me_hardswap_warmup_pass_backoff_base_ms"
- `me_hardswap_warmup_pass_backoff_base_ms`
  - **Constraints / validation**: `u64` (milliseconds). Must be `> 0`.
  - **Description**: Base backoff between extra hardswap warmup passes when the floor is still incomplete.
  - **Example**:

    ```toml
    [general]
    # default: 500
    me_hardswap_warmup_pass_backoff_base_ms = 500
    ```
## "cfg-general-me_config_stable_snapshots"
- `me_config_stable_snapshots`
  - **Constraints / validation**: Must be `> 0`.
  - **Description**: Number of identical ME config snapshots required before apply.
  - **Example**:

    ```toml
    [general]
    # require 3 identical snapshots before applying ME endpoint map updates
    me_config_stable_snapshots = 3
    ```
## "cfg-general-me_config_apply_cooldown_secs"
- `me_config_apply_cooldown_secs`
  - **Constraints / validation**: `u64`.
  - **Description**: Cooldown between applied ME endpoint-map updates. `0` disables the cooldown.
  - **Example**:

    ```toml
    [general]
    # allow applying stable snapshots immediately (no cooldown)
    me_config_apply_cooldown_secs = 0
    ```
## "cfg-general-me_snapshot_require_http_2xx"
- `me_snapshot_require_http_2xx`
  - **Constraints / validation**: `bool`.
  - **Description**: Requires 2xx HTTP responses for applying ME config snapshots. When `false`, non-2xx responses may still be parsed/considered by the updater.
  - **Example**:

    ```toml
    [general]
    # allow applying snapshots even when the HTTP status is non-2xx
    me_snapshot_require_http_2xx = false
    ```
## "cfg-general-me_snapshot_reject_empty_map"
- `me_snapshot_reject_empty_map`
  - **Constraints / validation**: `bool`.
  - **Description**: Rejects empty ME config snapshots (no endpoints). When `false`, an empty snapshot can be applied (subject to other gates), which may temporarily reduce/clear the ME map.
  - **Example**:

    ```toml
    [general]
    # allow applying empty snapshots (use with care)
    me_snapshot_reject_empty_map = false
    ```
## "cfg-general-me_snapshot_min_proxy_for_lines"
- `me_snapshot_min_proxy_for_lines`
  - **Constraints / validation**: Must be `> 0`.
  - **Description**: Minimum parsed `proxy_for` rows required to accept snapshot.
  - **Example**:

    ```toml
    [general]
    # require at least 10 proxy_for rows before accepting a snapshot
    me_snapshot_min_proxy_for_lines = 10
    ```
## "cfg-general-proxy_secret_stable_snapshots"
- `proxy_secret_stable_snapshots`
  - **Constraints / validation**: Must be `> 0`.
  - **Description**: Number of identical proxy-secret snapshots required before rotation.
  - **Example**:

    ```toml
    [general]
    # require 2 identical getProxySecret snapshots before rotating at runtime
    proxy_secret_stable_snapshots = 2
    ```
## "cfg-general-proxy_secret_rotate_runtime"
- `proxy_secret_rotate_runtime`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables runtime proxy-secret rotation from updater snapshots.
  - **Example**:

    ```toml
    [general]
    # disable runtime proxy-secret rotation (startup still uses proxy_secret_path/proxy_secret_len_max)
    proxy_secret_rotate_runtime = false
    ```
## "cfg-general-me_secret_atomic_snapshot"
- `me_secret_atomic_snapshot`
  - **Constraints / validation**: `bool`.
  - **Description**: Keeps selector and secret bytes from the same snapshot atomically. When `general.use_middle_proxy = true`, this is auto-enabled during config load to keep ME KDF material coherent.
  - **Example**:

    ```toml
    [general]
    # NOTE: when use_middle_proxy=true, Telemt will auto-enable this during load
    me_secret_atomic_snapshot = false
    ```
## "cfg-general-proxy_secret_len_max"
- `proxy_secret_len_max`
  - **Constraints / validation**: Must be within `[32, 4096]`.
  - **Description**: Upper length limit (bytes) for accepted proxy-secret during startup and runtime refresh.
  - **Example**:

    ```toml
    [general]
    # default: 256 (bytes)
    proxy_secret_len_max = 256
    ```
## "cfg-general-me_pool_drain_ttl_secs"
- `me_pool_drain_ttl_secs`
  - **Constraints / validation**: `u64` (seconds). `0` disables the drain-TTL window (and suppresses drain-TTL warnings for non-empty draining writers).
  - **Description**: Drain-TTL time window for stale ME writers after endpoint map changes. During the TTL, stale writers may be used only as fallback for new bindings (depending on bind policy).
  - **Example**:

    ```toml
    [general]
    # disable drain TTL (draining writers won't emit "past drain TTL" warnings)
    me_pool_drain_ttl_secs = 0
    ```
## "cfg-general-me_instadrain"
- `me_instadrain`
  - **Constraints / validation**: `bool`.
  - **Description**: Forces draining stale writers to be removed on the next cleanup tick, bypassing TTL/deadline waiting.
  - **Example**:

    ```toml
    [general]
    # default: false
    me_instadrain = false
    ```
## "cfg-general-me_pool_drain_threshold"
- `me_pool_drain_threshold`
  - **Constraints / validation**: `u64`. Set to `0` to disable threshold-based cleanup.
  - **Description**: Maximum number of draining stale writers before oldest ones are force-closed in batches.
  - **Example**:

    ```toml
    [general]
    # default: 32
    me_pool_drain_threshold = 32
    ```
## "cfg-general-me_pool_drain_soft_evict_enabled"
- `me_pool_drain_soft_evict_enabled`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables gradual soft-eviction of stale writers during drain/reinit instead of immediate hard close.
  - **Example**:

    ```toml
    [general]
    # default: true
    me_pool_drain_soft_evict_enabled = true
    ```
## "cfg-general-me_pool_drain_soft_evict_grace_secs"
- `me_pool_drain_soft_evict_grace_secs`
  - **Constraints / validation**: `u64` (seconds). Must be within `[0, 3600]`.
  - **Description**: Extra grace (after drain TTL) before soft-eviction stage starts.
  - **Example**:

    ```toml
    [general]
    # default: 10
    me_pool_drain_soft_evict_grace_secs = 10
    ```
## "cfg-general-me_pool_drain_soft_evict_per_writer"
- `me_pool_drain_soft_evict_per_writer`
  - **Constraints / validation**: `1..=16`.
  - **Description**: Maximum stale routes soft-evicted per writer in one eviction pass.
  - **Example**:

    ```toml
    [general]
    # default: 2
    me_pool_drain_soft_evict_per_writer = 2
    ```
## "cfg-general-me_pool_drain_soft_evict_budget_per_core"
- `me_pool_drain_soft_evict_budget_per_core`
  - **Constraints / validation**: `1..=64`.
  - **Description**: Per-core budget limiting aggregate soft-eviction work per pass.
  - **Example**:

    ```toml
    [general]
    # default: 16
    me_pool_drain_soft_evict_budget_per_core = 16
    ```
## "cfg-general-me_pool_drain_soft_evict_cooldown_ms"
- `me_pool_drain_soft_evict_cooldown_ms`
  - **Constraints / validation**: `u64` (milliseconds). Must be `> 0`.
  - **Description**: Cooldown between repetitive soft-eviction on the same writer.
  - **Example**:

    ```toml
    [general]
    # default: 1000
    me_pool_drain_soft_evict_cooldown_ms = 1000
    ```
## "cfg-general-me_bind_stale_mode"
- `me_bind_stale_mode`
  - **Constraints / validation**: `"never"`, `"ttl"`, or `"always"`.
  - **Description**: Policy for new binds on stale draining writers.
  - **Example**:

    ```toml
    [general]
    # allow stale binds only for a limited time window
    me_bind_stale_mode = "ttl"
    ```
## "cfg-general-me_bind_stale_ttl_secs"
- `me_bind_stale_ttl_secs`
  - **Constraints / validation**: `u64`.
  - **Description**: TTL for stale bind allowance when stale mode is `ttl`.
  - **Example**:

    ```toml
    [general]
    me_bind_stale_mode = "ttl"
    me_bind_stale_ttl_secs = 90
    ```
## "cfg-general-me_pool_min_fresh_ratio"
- `me_pool_min_fresh_ratio`
  - **Constraints / validation**: Must be within `[0.0, 1.0]`.
  - **Description**: Minimum fresh desired-DC coverage ratio before stale writers are drained.
  - **Example**:

    ```toml
    [general]
    # require >=90% desired-DC coverage before draining stale writers
    me_pool_min_fresh_ratio = 0.9
    ```
## "cfg-general-me_reinit_drain_timeout_secs"
- `me_reinit_drain_timeout_secs`
  - **Constraints / validation**: `u64`. `0` uses the runtime safety fallback force-close timeout. If `> 0` and `< me_pool_drain_ttl_secs`, runtime bumps it to TTL.
  - **Description**: Force-close timeout for draining stale writers. When set to `0`, the effective timeout is the runtime safety fallback (300 seconds).
  - **Example**:

    ```toml
    [general]
    # use runtime safety fallback force-close timeout (300s)
    me_reinit_drain_timeout_secs = 0
    ```
## "cfg-general-proxy_secret_auto_reload_secs"
- `proxy_secret_auto_reload_secs`
  - **Constraints / validation**: Deprecated. Use `general.update_every`. When `general.update_every` is not explicitly set, the effective legacy refresh interval is `min(proxy_secret_auto_reload_secs, proxy_config_auto_reload_secs)` and must be `> 0`.
  - **Description**: Deprecated legacy proxy-secret refresh interval. Used only when `general.update_every` is not set.
  - **Example**:

    ```toml
    [general]
    # legacy mode: omit update_every to use proxy_*_auto_reload_secs
    proxy_secret_auto_reload_secs = 600
    proxy_config_auto_reload_secs = 120
    # effective updater interval = min(600, 120) = 120 seconds
    ```
## "cfg-general-proxy_config_auto_reload_secs"
- `proxy_config_auto_reload_secs`
  - **Constraints / validation**: Deprecated. Use `general.update_every`. When `general.update_every` is not explicitly set, the effective legacy refresh interval is `min(proxy_secret_auto_reload_secs, proxy_config_auto_reload_secs)` and must be `> 0`.
  - **Description**: Deprecated legacy ME config refresh interval. Used only when `general.update_every` is not set.
  - **Example**:

    ```toml
    [general]
    # legacy mode: omit update_every to use proxy_*_auto_reload_secs
    proxy_secret_auto_reload_secs = 600
    proxy_config_auto_reload_secs = 120
    # effective updater interval = min(600, 120) = 120 seconds
    ```
## "cfg-general-me_reinit_singleflight"
- `me_reinit_singleflight`
  - **Constraints / validation**: `bool`.
  - **Description**: Serializes ME reinit cycles across trigger sources.
  - **Example**:

    ```toml
    [general]
    me_reinit_singleflight = true
    ```
## "cfg-general-me_reinit_trigger_channel"
- `me_reinit_trigger_channel`
  - **Constraints / validation**: Must be `> 0`.
  - **Description**: Trigger queue capacity for reinit scheduler.
  - **Example**:

    ```toml
    [general]
    me_reinit_trigger_channel = 64
    ```
## "cfg-general-me_reinit_coalesce_window_ms"
- `me_reinit_coalesce_window_ms`
  - **Constraints / validation**: `u64`.
  - **Description**: Trigger coalescing window before starting reinit (ms).
  - **Example**:

    ```toml
    [general]
    me_reinit_coalesce_window_ms = 200
    ```
## "cfg-general-me_deterministic_writer_sort"
- `me_deterministic_writer_sort`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables deterministic candidate sort for writer binding path.
  - **Example**:

    ```toml
    [general]
    me_deterministic_writer_sort = true
    ```
## "cfg-general-me_writer_pick_mode"
- `me_writer_pick_mode`
  - **Constraints / validation**: `"sorted_rr"` or `"p2c"`.
  - **Description**: Writer selection mode for route bind path.
  - **Example**:

    ```toml
    [general]
    me_writer_pick_mode = "p2c"
    ```
## "cfg-general-me_writer_pick_sample_size"
- `me_writer_pick_sample_size`
  - **Constraints / validation**: `2..=4`.
  - **Description**: Number of candidates sampled by picker in `p2c` mode.
  - **Example**:

    ```toml
    [general]
    me_writer_pick_mode = "p2c"
    me_writer_pick_sample_size = 3
    ```
## "cfg-general-ntp_check"
- `ntp_check`
  - **Constraints / validation**: `bool`.
  - **Description**: Reserved for future use. Currently this key is parsed but not used by the runtime.
  - **Example**:

    ```toml
    [general]
    ntp_check = true
    ```
## "cfg-general-ntp_servers"
- `ntp_servers`
  - **Constraints / validation**: `String[]`.
  - **Description**: Reserved for future use. Currently this key is parsed but not used by the runtime.
  - **Example**:

    ```toml
    [general]
    ntp_servers = ["pool.ntp.org"]
    ```
## "cfg-general-auto_degradation_enabled"
- `auto_degradation_enabled`
  - **Constraints / validation**: `bool`.
  - **Description**: Reserved for future use. Currently this key is parsed but not used by the runtime.
  - **Example**:

    ```toml
    [general]
    auto_degradation_enabled = true
    ```
## "cfg-general-degradation_min_unavailable_dc_groups"
- `degradation_min_unavailable_dc_groups`
  - **Constraints / validation**: `u8`.
  - **Description**: Reserved for future use. Currently this key is parsed but not used by the runtime.
  - **Example**:

    ```toml
    [general]
    degradation_min_unavailable_dc_groups = 2
    ```
## "cfg-general-rst_on_close"
- `rst_on_close`
  - **Constraints / validation**: one of `"off"`, `"errors"`, `"always"`.
  - **Description**: Controls `SO_LINGER(0)` behaviour on accepted client TCP sockets.
    High-traffic proxy servers accumulate `FIN-WAIT-1` and orphaned sockets from connections that never complete the Telegram handshake (scanners, DPI probes, bots).
    This option allows sending an immediate `RST` instead of a graceful `FIN` for such connections, freeing kernel resources instantly.
    - `"off"` — default. Normal `FIN` on all closes; no behaviour change.
    - `"errors"` — `SO_LINGER(0)` is set on `accept()`. If the client successfully completes authentication, linger is cleared and the relay session closes gracefully with `FIN`. Connections closed before handshake completion (timeouts, bad crypto, scanners) send `RST`.
    - `"always"` — `SO_LINGER(0)` is set on `accept()` and never cleared. All closes send `RST` regardless of handshake outcome.
  - **Example**:

    ```toml
    [general]
    rst_on_close = "errors"
    ```

# [general.modes]


| Key | Type | Default |
| --- | ---- | ------- |
| [`classic`](#cfg-general-modes-classic) | `bool` | `false` |
| [`secure`](#cfg-general-modes-secure) | `bool` | `false` |
| [`tls`](#cfg-general-modes-tls) | `bool` | `true` |

## "cfg-general-modes-classic"
- `classic`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables classic MTProxy mode.
  - **Example**:

    ```toml
    [general.modes]
    classic = true
    ```
## "cfg-general-modes-secure"
- `secure`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables secure mode.
  - **Example**:

    ```toml
    [general.modes]
    secure = true
    ```
## "cfg-general-modes-tls"
- `tls`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables TLS mode.
  - **Example**:

    ```toml
    [general.modes]
    tls = true
    ```


# [general.links]


| Key | Type | Default |
| --- | ---- | ------- |
| [`show`](#cfg-general-links-show) | `"*"` or `String[]` | `"*"` |
| [`public_host`](#cfg-general-links-public_host) | `String` | — |
| [`public_port`](#cfg-general-links-public_port) | `u16` | — |

## "cfg-general-links-show"
- `show`
  - **Constraints / validation**: `"*"` or `String[]`. An empty array means "show none".
  - **Description**: Selects users whose `tg://` proxy links are shown at startup.
  - **Example**:

    ```toml
    [general.links]
    show = "*"
    # or:
    # show = ["alice", "bob"]
    ```
## "cfg-general-links-public_host"
- `public_host`
  - **Constraints / validation**: `String` (optional).
  - **Description**: Public hostname/IP override used for generated `tg://` links (overrides detected IP).
  - **Example**:

    ```toml
    [general.links]
    public_host = "proxy.example.com"
    ```
## "cfg-general-links-public_port"
- `public_port`
  - **Constraints / validation**: `u16` (optional).
  - **Description**: Public port override used for generated `tg://` links (overrides `server.port`).
  - **Example**:

    ```toml
    [general.links]
    public_port = 443
    ```


# [general.telemetry]


| Key | Type | Default |
| --- | ---- | ------- |
| [`core_enabled`](#cfg-general-telemetry-core_enabled) | `bool` | `true` |
| [`user_enabled`](#cfg-general-telemetry-user_enabled) | `bool` | `true` |
| [`me_level`](#cfg-general-telemetry-me_level) | `"silent"`, `"normal"`, or `"debug"` | `"normal"` |

## "cfg-general-telemetry-core_enabled"
- `core_enabled`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables core hot-path telemetry counters.
  - **Example**:

    ```toml
    [general.telemetry]
    core_enabled = true
    ```
## "cfg-general-telemetry-user_enabled"
- `user_enabled`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables per-user telemetry counters.
  - **Example**:

    ```toml
    [general.telemetry]
    user_enabled = true
    ```
## "cfg-general-telemetry-me_level"
- `me_level`
  - **Constraints / validation**: `"silent"`, `"normal"`, or `"debug"`.
  - **Description**: Middle-End telemetry verbosity level.
  - **Example**:

    ```toml
    [general.telemetry]
    me_level = "normal"
    ```


# [network]


| Key | Type | Default |
| --- | ---- | ------- |
| [`ipv4`](#cfg-network-ipv4) | `bool` | `true` |
| [`ipv6`](#cfg-network-ipv6) | `bool` | `false` |
| [`prefer`](#cfg-network-prefer) | `u8` | `4` |
| [`multipath`](#cfg-network-multipath) | `bool` | `false` |
| [`stun_use`](#cfg-network-stun_use) | `bool` | `true` |
| [`stun_servers`](#cfg-network-stun_servers) | `String[]` | Built-in STUN list (13 hosts) |
| [`stun_tcp_fallback`](#cfg-network-stun_tcp_fallback) | `bool` | `true` |
| [`http_ip_detect_urls`](#cfg-network-http_ip_detect_urls) | `String[]` | `["https://ifconfig.me/ip", "https://api.ipify.org"]` |
| [`cache_public_ip_path`](#cfg-network-cache_public_ip_path) | `String` | `"cache/public_ip.txt"` |
| [`dns_overrides`](#cfg-network-dns_overrides) | `String[]` | `[]` |

## "cfg-network-ipv4"
- `ipv4`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables IPv4 networking.
  - **Example**:

    ```toml
    [network]
    ipv4 = true
    ```
## "cfg-network-ipv6"
- `ipv6`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables/disables IPv6 networking. When omitted, defaults to `false`.
  - **Example**:

    ```toml
    [network]
    # enable IPv6 explicitly
    ipv6 = true

    # or: disable IPv6 explicitly
    # ipv6 = false
    ```
## "cfg-network-prefer"
- `prefer`
  - **Constraints / validation**: Must be `4` or `6`. If `prefer = 4` while `ipv4 = false`, Telemt forces `prefer = 6`. If `prefer = 6` while `ipv6 = false`, Telemt forces `prefer = 4`.
  - **Description**: Preferred IP family for selection when both families are available.
  - **Example**:

    ```toml
    [network]
    prefer = 6
    ```
## "cfg-network-multipath"
- `multipath`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables multipath behavior where supported by the platform and runtime.
  - **Example**:

    ```toml
    [network]
    multipath = true
    ```
## "cfg-network-stun_use"
- `stun_use`
  - **Constraints / validation**: `bool`.
  - **Description**: Global STUN switch; when `false`, STUN probing is disabled and only non-STUN detection remains.
  - **Example**:

    ```toml
    [network]
    stun_use = false
    ```
## "cfg-network-stun_servers"
- `stun_servers`
  - **Constraints / validation**: `String[]`. Values are trimmed; empty values are removed; list is deduplicated. If this key is **not** explicitly set, Telemt keeps the built-in default STUN list.
  - **Description**: STUN servers list for public IP discovery.
  - **Example**:

    ```toml
    [network]
    stun_servers = [
      "stun.l.google.com:19302",
      "stun.stunprotocol.org:3478",
    ]
    ```
## "cfg-network-stun_tcp_fallback"
- `stun_tcp_fallback`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables TCP fallback for STUN when the UDP path is blocked/unavailable.
  - **Example**:

    ```toml
    [network]
    stun_tcp_fallback = true
    ```
## "cfg-network-http_ip_detect_urls"
- `http_ip_detect_urls`
  - **Constraints / validation**: `String[]`.
  - **Description**: HTTP endpoints used for public IP detection (fallback after STUN).
  - **Example**:

    ```toml
    [network]
    http_ip_detect_urls = ["https://ifconfig.me/ip", "https://api.ipify.org"]
    ```
## "cfg-network-cache_public_ip_path"
- `cache_public_ip_path`
  - **Constraints / validation**: `String`.
  - **Description**: File path used to cache the detected public IP.
  - **Example**:

    ```toml
    [network]
    cache_public_ip_path = "cache/public_ip.txt"
    ```
## "cfg-network-dns_overrides"
- `dns_overrides`
  - **Constraints / validation**: `String[]`. Each entry must use `host:port:ip` format.
    - `host`: domain name (must be non-empty and must not contain `:`)
    - `port`: `u16`
    - `ip`: IPv4 (`1.2.3.4`) or bracketed IPv6 (`[2001:db8::1]`). **Unbracketed IPv6 is rejected**.
  - **Description**: Runtime DNS overrides for `host:port` targets. Useful for forcing specific IPs for given upstream domains without touching system DNS.
  - **Example**:

    ```toml
    [network]
    dns_overrides = [
      "example.com:443:127.0.0.1",
      "example.net:8443:[2001:db8::10]",
    ]
    ```


# [server]


| Key | Type | Default |
| --- | ---- | ------- |
| [`port`](#cfg-server-port) | `u16` | `443` |
| [`listen_addr_ipv4`](#cfg-server-listen_addr_ipv4) | `String` | `"0.0.0.0"` |
| [`listen_addr_ipv6`](#cfg-server-listen_addr_ipv6) | `String` | `"::"` |
| [`listen_unix_sock`](#cfg-server-listen_unix_sock) | `String` | — |
| [`listen_unix_sock_perm`](#cfg-server-listen_unix_sock_perm) | `String` | — |
| [`listen_tcp`](#cfg-server-listen_tcp) | `bool` | — (auto) |
| [`proxy_protocol`](#cfg-server-proxy_protocol) | `bool` | `false` |
| [`proxy_protocol_header_timeout_ms`](#cfg-server-proxy_protocol_header_timeout_ms) | `u64` | `500` |
| [`proxy_protocol_trusted_cidrs`](#cfg-server-proxy_protocol_trusted_cidrs) | `IpNetwork[]` | `[]` |
| [`metrics_port`](#cfg-server-metrics_port) | `u16` | — |
| [`metrics_listen`](#cfg-server-metrics_listen) | `String` | — |
| [`metrics_whitelist`](#cfg-server-metrics_whitelist) | `IpNetwork[]` | `["127.0.0.1/32", "::1/128"]` |
| [`max_connections`](#cfg-server-max_connections) | `u32` | `10000` |
| [`accept_permit_timeout_ms`](#cfg-server-accept_permit_timeout_ms) | `u64` | `250` |

## "cfg-server-port"
- `port`
  - **Constraints / validation**: `u16`.
  - **Description**: Main proxy listen port (TCP).
  - **Example**:

    ```toml
    [server]
    port = 443
    ```
## "cfg-server-listen_addr_ipv4"
- `listen_addr_ipv4`
  - **Constraints / validation**: `String` (optional). When set, must be a valid IPv4 address string.
  - **Description**: IPv4 bind address for TCP listener (omit this key to disable IPv4 bind).
  - **Example**:

    ```toml
    [server]
    listen_addr_ipv4 = "0.0.0.0"
    ```
## "cfg-server-listen_addr_ipv6"
- `listen_addr_ipv6`
  - **Constraints / validation**: `String` (optional). When set, must be a valid IPv6 address string.
  - **Description**: IPv6 bind address for TCP listener (omit this key to disable IPv6 bind).
  - **Example**:

    ```toml
    [server]
    listen_addr_ipv6 = "::"
    ```
## "cfg-server-listen_unix_sock"
- `listen_unix_sock`
  - **Constraints / validation**: `String` (optional). Must not be empty when set. Unix only.
  - **Description**: Unix socket path for listener. When set, `server.listen_tcp` defaults to `false` (unless explicitly overridden).
  - **Example**:

    ```toml
    [server]
    listen_unix_sock = "/run/telemt.sock"
    ```
## "cfg-server-listen_unix_sock_perm"
- `listen_unix_sock_perm`
  - **Constraints / validation**: `String` (optional). When set, should be an octal permission string like `"0666"` or `"0777"`.
  - **Description**: Optional Unix socket file permissions applied after bind (chmod). When omitted, permissions are not changed (inherits umask).
  - **Example**:

    ```toml
    [server]
    listen_unix_sock = "/run/telemt.sock"
    listen_unix_sock_perm = "0666"
    ```
## "cfg-server-listen_tcp"
- `listen_tcp`
  - **Constraints / validation**: `bool` (optional). When omitted, Telemt auto-detects:
    - `true` when `listen_unix_sock` is not set
    - `false` when `listen_unix_sock` is set
  - **Description**: Explicit TCP listener enable/disable override.
  - **Example**:

    ```toml
    [server]
    # force-enable TCP even when also binding a unix socket
    listen_unix_sock = "/run/telemt.sock"
    listen_tcp = true
    ```
## "cfg-server-proxy_protocol"
- `proxy_protocol`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables HAProxy PROXY protocol parsing on incoming connections (PROXY v1/v2). When enabled, client source address is taken from the PROXY header.
  - **Example**:

    ```toml
    [server]
    proxy_protocol = true
    ```
## "cfg-server-proxy_protocol_header_timeout_ms"
- `proxy_protocol_header_timeout_ms`
  - **Constraints / validation**: Must be `> 0` (milliseconds).
  - **Description**: Timeout for reading and parsing PROXY protocol headers (ms).
  - **Example**:

    ```toml
    [server]
    proxy_protocol = true
    proxy_protocol_header_timeout_ms = 500
    ```
## "cfg-server-proxy_protocol_trusted_cidrs"
- `proxy_protocol_trusted_cidrs`
  - **Constraints / validation**: `IpNetwork[]`.
    - If omitted, defaults to trust-all CIDRs (`0.0.0.0/0` and `::/0`).
    - If explicitly set to an empty array, all PROXY headers are rejected.
  - **Description**: Trusted source CIDRs allowed to provide PROXY protocol headers (security control).
  - **Example**:

    ```toml
    [server]
    proxy_protocol = true
    proxy_protocol_trusted_cidrs = ["127.0.0.1/32", "10.0.0.0/8"]
    ```
## "cfg-server-metrics_port"
- `metrics_port`
  - **Constraints / validation**: `u16` (optional).
  - **Description**: Prometheus-compatible metrics endpoint port. When set, enables the metrics listener (bind behavior can be overridden by `metrics_listen`).
  - **Example**:

    ```toml
    [server]
    metrics_port = 9090
    ```
## "cfg-server-metrics_listen"
- `metrics_listen`
  - **Constraints / validation**: `String` (optional). When set, must be in `IP:PORT` format.
  - **Description**: Full metrics bind address (`IP:PORT`), overrides `metrics_port` and binds on the specified address only.
  - **Example**:

    ```toml
    [server]
    metrics_listen = "127.0.0.1:9090"
    ```
## "cfg-server-metrics_whitelist"
- `metrics_whitelist`
  - **Constraints / validation**: `IpNetwork[]`.
  - **Description**: CIDR whitelist for metrics endpoint access.
  - **Example**:

    ```toml
    [server]
    metrics_port = 9090
    metrics_whitelist = ["127.0.0.1/32", "::1/128"]
    ```
## "cfg-server-max_connections"
- `max_connections`
  - **Constraints / validation**: `u32`. `0` means unlimited.
  - **Description**: Maximum number of concurrent client connections.
  - **Example**:

    ```toml
    [server]
    max_connections = 10000
    ```
## "cfg-server-accept_permit_timeout_ms"
- `accept_permit_timeout_ms`
  - **Constraints / validation**: `0..=60000` (milliseconds). `0` keeps legacy unbounded wait behavior.
  - **Description**: Maximum wait for acquiring a connection-slot permit before the accepted connection is dropped.
  - **Example**:

    ```toml
    [server]
    accept_permit_timeout_ms = 250
    ```


Note: When `server.proxy_protocol` is enabled, incoming PROXY protocol headers are parsed from the first bytes of the connection and the client source address is replaced with `src_addr` from the header. For security, the peer source IP (the direct connection address) is verified against `server.proxy_protocol_trusted_cidrs`; if this list is empty, PROXY headers are rejected and the connection is considered untrusted.

# [server.conntrack_control]

Note: The conntrack-control worker runs **only on Linux**. On other operating systems it is not started; if `inline_conntrack_control` is `true`, a warning is logged. Effective operation also requires **CAP_NET_ADMIN** and a usable backend (`nft` or `iptables` / `ip6tables` on `PATH`). The `conntrack` utility is used for optional table entry deletes under pressure.


| Key | Type | Default |
| --- | ---- | ------- |
| [`inline_conntrack_control`](#cfg-server-conntrack_control-inline_conntrack_control) | `bool` | `true` |
| [`mode`](#cfg-server-conntrack_control-mode) | `String` | `"tracked"` |
| [`backend`](#cfg-server-conntrack_control-backend) | `String` | `"auto"` |
| [`profile`](#cfg-server-conntrack_control-profile) | `String` | `"balanced"` |
| [`hybrid_listener_ips`](#cfg-server-conntrack_control-hybrid_listener_ips) | `IpAddr[]` | `[]` |
| [`pressure_high_watermark_pct`](#cfg-server-conntrack_control-pressure_high_watermark_pct) | `u8` | `85` |
| [`pressure_low_watermark_pct`](#cfg-server-conntrack_control-pressure_low_watermark_pct) | `u8` | `70` |
| [`delete_budget_per_sec`](#cfg-server-conntrack_control-delete_budget_per_sec) | `u64` | `4096` |

## "cfg-server-conntrack_control-inline_conntrack_control"
- `inline_conntrack_control`
  - **Constraints / validation**: `bool`.
  - **Description**: Master switch for the runtime conntrack-control task: reconciles **raw/notrack** netfilter rules for listener ingress (see `mode`), samples load every second, and may run **`conntrack -D`** deletes for qualifying close events while **pressure mode** is active (see `delete_budget_per_sec`). When `false`, notrack rules are cleared and pressure-driven deletes are disabled.
  - **Example**:

    ```toml
    [server.conntrack_control]
    inline_conntrack_control = true
    ```
## "cfg-server-conntrack_control-mode"
- `mode`
  - **Constraints / validation**: One of `tracked`, `notrack`, `hybrid` (case-insensitive; serialized lowercase).
  - **Description**: **`tracked`**: do not install telemt notrack rules (connections stay in conntrack). **`notrack`**: mark matching ingress TCP to `server.port` as notrack — targets are derived from `[[server.listeners]]` if any, otherwise from `server.listen_addr_ipv4` / `server.listen_addr_ipv6` (unspecified addresses mean “any” for that family). **`hybrid`**: notrack only for addresses listed in `hybrid_listener_ips` (must be non-empty; validated at load).
  - **Example**:

    ```toml
    [server.conntrack_control]
    mode = "notrack"
    ```
## "cfg-server-conntrack_control-backend"
- `backend`
  - **Constraints / validation**: One of `auto`, `nftables`, `iptables` (case-insensitive; serialized lowercase).
  - **Description**: Which command set applies notrack rules. **`auto`**: use `nft` if present on `PATH`, else `iptables`/`ip6tables` if present. **`nftables`** / **`iptables`**: force that backend; missing binary means rules cannot be applied. The nft path uses table `inet telemt_conntrack` and a prerouting raw hook; iptables uses chain `TELEMT_NOTRACK` in the `raw` table.
  - **Example**:

    ```toml
    [server.conntrack_control]
    backend = "auto"
    ```
## "cfg-server-conntrack_control-profile"
- `profile`
  - **Constraints / validation**: One of `conservative`, `balanced`, `aggressive` (case-insensitive; serialized lowercase).
  - **Description**: When **conntrack pressure mode** is active (`pressure_*` watermarks), caps idle and activity timeouts to reduce conntrack churn: e.g. **client first-byte idle** (`client.rs`), **direct relay activity timeout** (`direct_relay.rs`), and **middle-relay idle policy** caps (`middle_relay.rs` via `ConntrackPressureProfile::*_cap_secs` / `direct_activity_timeout_secs`). More aggressive profiles use shorter caps.
  - **Example**:

    ```toml
    [server.conntrack_control]
    profile = "balanced"
    ```
## "cfg-server-conntrack_control-hybrid_listener_ips"
- `hybrid_listener_ips`
  - **Constraints / validation**: `IpAddr[]`. Required to be **non-empty** when `mode = "hybrid"`. Ignored for `tracked` / `notrack`.
  - **Description**: Explicit listener addresses that receive notrack rules in hybrid mode (split into IPv4 vs IPv6 rules by the implementation).
  - **Example**:

    ```toml
    [server.conntrack_control]
    mode = "hybrid"
    hybrid_listener_ips = ["203.0.113.10", "2001:db8::1"]
    ```
## "cfg-server-conntrack_control-pressure_high_watermark_pct"
- `pressure_high_watermark_pct`
  - **Constraints / validation**: Must be within `[1, 100]`.
  - **Description**: Pressure mode **enters** when any of: connection fill vs `server.max_connections` (percentage, if `max_connections > 0`), **file-descriptor** usage vs process soft `RLIMIT_NOFILE`, **non-zero** `accept_permit_timeout` events in the last sample window, or **ME c2me send-full** counter delta. Entry compares relevant percentages against this high watermark (see `update_pressure_state` in `conntrack_control.rs`).
  - **Example**:

    ```toml
    [server.conntrack_control]
    pressure_high_watermark_pct = 85
    ```
## "cfg-server-conntrack_control-pressure_low_watermark_pct"
- `pressure_low_watermark_pct`
  - **Constraints / validation**: Must be **strictly less than** `pressure_high_watermark_pct`.
  - **Description**: Pressure mode **clears** only after **three** consecutive one-second samples where all signals are at or below this low watermark and the accept-timeout / ME-queue deltas are zero (hysteresis).
  - **Example**:

    ```toml
    [server.conntrack_control]
    pressure_low_watermark_pct = 70
    ```
## "cfg-server-conntrack_control-delete_budget_per_sec"
- `delete_budget_per_sec`
  - **Constraints / validation**: Must be `> 0`.
  - **Description**: Maximum number of **`conntrack -D`** attempts **per second** while pressure mode is active (token bucket refilled each second). Deletes run only for close events with reasons **timeout**, **pressure**, or **reset**; each attempt consumes a token regardless of outcome.
  - **Example**:

    ```toml
    [server.conntrack_control]
    delete_budget_per_sec = 4096
    ```


# [server.api]

Note: This section also accepts the legacy alias `[server.admin_api]` (same schema as `[server.api]`).


| Key | Type | Default |
| --- | ---- | ------- |
| [`enabled`](#cfg-server-api-enabled) | `bool` | `true` |
| [`listen`](#cfg-server-api-listen) | `String` | `"0.0.0.0:9091"` |
| [`whitelist`](#cfg-server-api-whitelist) | `IpNetwork[]` | `["127.0.0.0/8"]` |
| [`auth_header`](#cfg-server-api-auth_header) | `String` | `""` |
| [`request_body_limit_bytes`](#cfg-server-api-request_body_limit_bytes) | `usize` | `65536` |
| [`minimal_runtime_enabled`](#cfg-server-api-minimal_runtime_enabled) | `bool` | `true` |
| [`minimal_runtime_cache_ttl_ms`](#cfg-server-api-minimal_runtime_cache_ttl_ms) | `u64` | `1000` |
| [`runtime_edge_enabled`](#cfg-server-api-runtime_edge_enabled) | `bool` | `false` |
| [`runtime_edge_cache_ttl_ms`](#cfg-server-api-runtime_edge_cache_ttl_ms) | `u64` | `1000` |
| [`runtime_edge_top_n`](#cfg-server-api-runtime_edge_top_n) | `usize` | `10` |
| [`runtime_edge_events_capacity`](#cfg-server-api-runtime_edge_events_capacity) | `usize` | `256` |
| [`read_only`](#cfg-server-api-read_only) | `bool` | `false` |

## "cfg-server-api-enabled"
- `enabled`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables control-plane REST API.
  - **Example**:

    ```toml
    [server.api]
    enabled = true
    ```
## "cfg-server-api-listen"
- `listen`
  - **Constraints / validation**: `String`. Must be in `IP:PORT` format.
  - **Description**: API bind address in `IP:PORT` format.
  - **Example**:

    ```toml
    [server.api]
    listen = "0.0.0.0:9091"
    ```
## "cfg-server-api-whitelist"
- `whitelist`
  - **Constraints / validation**: `IpNetwork[]`.
  - **Description**: CIDR whitelist allowed to access API.
  - **Example**:

    ```toml
    [server.api]
    whitelist = ["127.0.0.0/8"]
    ```
## "cfg-server-api-auth_header"
- `auth_header`
  - **Constraints / validation**: `String`. Empty string disables auth-header validation.
  - **Description**: Exact expected `Authorization` header value (static shared secret).
  - **Example**:

    ```toml
    [server.api]
    auth_header = "Bearer MY_TOKEN"
    ```
## "cfg-server-api-request_body_limit_bytes"
- `request_body_limit_bytes`
  - **Constraints / validation**: Must be `> 0` (bytes).
  - **Description**: Maximum accepted HTTP request body size (bytes).
  - **Example**:

    ```toml
    [server.api]
    request_body_limit_bytes = 65536
    ```
## "cfg-server-api-minimal_runtime_enabled"
- `minimal_runtime_enabled`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables minimal runtime snapshots endpoint logic.
  - **Example**:

    ```toml
    [server.api]
    minimal_runtime_enabled = true
    ```
## "cfg-server-api-minimal_runtime_cache_ttl_ms"
- `minimal_runtime_cache_ttl_ms`
  - **Constraints / validation**: `0..=60000` (milliseconds). `0` disables cache.
  - **Description**: Cache TTL for minimal runtime snapshots (ms).
  - **Example**:

    ```toml
    [server.api]
    minimal_runtime_cache_ttl_ms = 1000
    ```
## "cfg-server-api-runtime_edge_enabled"
- `runtime_edge_enabled`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables runtime edge endpoints.
  - **Example**:

    ```toml
    [server.api]
    runtime_edge_enabled = false
    ```
## "cfg-server-api-runtime_edge_cache_ttl_ms"
- `runtime_edge_cache_ttl_ms`
  - **Constraints / validation**: `0..=60000` (milliseconds).
  - **Description**: Cache TTL for runtime edge aggregation payloads (ms).
  - **Example**:

    ```toml
    [server.api]
    runtime_edge_cache_ttl_ms = 1000
    ```
## "cfg-server-api-runtime_edge_top_n"
- `runtime_edge_top_n`
  - **Constraints / validation**: `1..=1000`.
  - **Description**: Top-N size for edge connection leaderboard.
  - **Example**:

    ```toml
    [server.api]
    runtime_edge_top_n = 10
    ```
## "cfg-server-api-runtime_edge_events_capacity"
- `runtime_edge_events_capacity`
  - **Constraints / validation**: `16..=4096`.
  - **Description**: Ring-buffer capacity for runtime edge events.
  - **Example**:

    ```toml
    [server.api]
    runtime_edge_events_capacity = 256
    ```
## "cfg-server-api-read_only"
- `read_only`
  - **Constraints / validation**: `bool`.
  - **Description**: Rejects mutating API endpoints when enabled.
  - **Example**:

    ```toml
    [server.api]
    read_only = false
    ```


# [[server.listeners]]


| Key | Type | Default |
| --- | ---- | ------- |
| [`ip`](#cfg-server-listeners-ip) | `IpAddr` | — |
| [`announce`](#cfg-server-listeners-announce) | `String` | — |
| [`announce_ip`](#cfg-server-listeners-announce_ip) | `IpAddr` | — |
| [`proxy_protocol`](#cfg-server-listeners-proxy_protocol) | `bool` | — |
| [`reuse_allow`](#cfg-server-listeners-reuse_allow) | `bool` | `false` |

## "cfg-server-listeners-ip"
- `ip`
  - **Constraints / validation**: Required field. Must be an `IpAddr`.
  - **Description**: Listener bind IP.
  - **Example**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    ```
## "cfg-server-listeners-announce"
- `announce`
  - **Constraints / validation**: `String` (optional). Must not be empty when set.
  - **Description**: Public IP/domain announced in proxy links for this listener. Takes precedence over `announce_ip`.
  - **Example**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    announce = "proxy.example.com"
    ```
## "cfg-server-listeners-announce_ip"
- `announce_ip`
  - **Constraints / validation**: `IpAddr` (optional). Deprecated. Use `announce`.
  - **Description**: Deprecated legacy announce IP. During config load it is migrated to `announce` when `announce` is not set.
  - **Example**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    announce_ip = "203.0.113.10"
    ```
## "cfg-server-listeners-proxy_protocol"
- `proxy_protocol`
  - **Constraints / validation**: `bool` (optional). When set, overrides `server.proxy_protocol` for this listener.
  - **Description**: Per-listener PROXY protocol override.
  - **Example**:

    ```toml
    [server]
    proxy_protocol = false

    [[server.listeners]]
    ip = "0.0.0.0"
    proxy_protocol = true
    ```
## "cfg-server-listeners-reuse_allow"
- `reuse_allow`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables `SO_REUSEPORT` for multi-instance bind sharing (allows multiple telemt instances to listen on the same `ip:port`).
  - **Example**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    reuse_allow = false
    ```


# [timeouts]


| Key | Type | Default |
| --- | ---- | ------- |
| [`client_handshake`](#cfg-timeouts-client_handshake) | `u64` | `30` |
| [`relay_idle_policy_v2_enabled`](#cfg-timeouts-relay_idle_policy_v2_enabled) | `bool` | `true` |
| [`relay_client_idle_soft_secs`](#cfg-timeouts-relay_client_idle_soft_secs) | `u64` | `120` |
| [`relay_client_idle_hard_secs`](#cfg-timeouts-relay_client_idle_hard_secs) | `u64` | `360` |
| [`relay_idle_grace_after_downstream_activity_secs`](#cfg-timeouts-relay_idle_grace_after_downstream_activity_secs) | `u64` | `30` |
| [`tg_connect`](#cfg-timeouts-tg_connect) | `u64` | `10` |
| [`client_keepalive`](#cfg-timeouts-client_keepalive) | `u64` | `15` |
| [`client_ack`](#cfg-timeouts-client_ack) | `u64` | `90` |
| [`me_one_retry`](#cfg-timeouts-me_one_retry) | `u8` | `12` |
| [`me_one_timeout_ms`](#cfg-timeouts-me_one_timeout_ms) | `u64` | `1200` |

## "cfg-timeouts-client_handshake"
- `client_handshake`
  - **Constraints / validation**: Must be `> 0`. Value is in seconds. Also used as an upper bound for some TLS emulation delays (see `censorship.server_hello_delay_max_ms`).
  - **Description**: Client handshake timeout (seconds).
  - **Example**:

    ```toml
    [timeouts]
    client_handshake = 30
    ```
## "cfg-timeouts-relay_idle_policy_v2_enabled"
- `relay_idle_policy_v2_enabled`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables soft/hard middle-relay client idle policy.
  - **Example**:

    ```toml
    [timeouts]
    relay_idle_policy_v2_enabled = true
    ```
## "cfg-timeouts-relay_client_idle_soft_secs"
- `relay_client_idle_soft_secs`
  - **Constraints / validation**: Must be `> 0`; must be `<= relay_client_idle_hard_secs`.
  - **Description**: Soft idle threshold (seconds) for middle-relay client uplink inactivity. Hitting this threshold marks the session as an idle-candidate (it may be eligible for cleanup depending on policy).
  - **Example**:

    ```toml
    [timeouts]
    relay_client_idle_soft_secs = 120
    ```
## "cfg-timeouts-relay_client_idle_hard_secs"
- `relay_client_idle_hard_secs`
  - **Constraints / validation**: Must be `> 0`; must be `>= relay_client_idle_soft_secs`.
  - **Description**: Hard idle threshold (seconds) for middle-relay client uplink inactivity. Hitting this threshold closes the session.
  - **Example**:

    ```toml
    [timeouts]
    relay_client_idle_hard_secs = 360
    ```
## "cfg-timeouts-relay_idle_grace_after_downstream_activity_secs"
- `relay_idle_grace_after_downstream_activity_secs`
  - **Constraints / validation**: Must be `<= relay_client_idle_hard_secs`.
  - **Description**: Extra hard-idle grace period (seconds) added after recent downstream activity.
  - **Example**:

    ```toml
    [timeouts]
    relay_idle_grace_after_downstream_activity_secs = 30
    ```
## "cfg-timeouts-tg_connect"
- `tg_connect`
  - **Constraints / validation**: `u64`. Value is in seconds.
  - **Description**: Upstream Telegram connect timeout (seconds).
  - **Example**:

    ```toml
    [timeouts]
    tg_connect = 10
    ```
## "cfg-timeouts-client_keepalive"
- `client_keepalive`
  - **Constraints / validation**: `u64`. Value is in seconds.
  - **Description**: Client keepalive timeout (seconds).
  - **Example**:

    ```toml
    [timeouts]
    client_keepalive = 15
    ```
## "cfg-timeouts-client_ack"
- `client_ack`
  - **Constraints / validation**: `u64`. Value is in seconds.
  - **Description**: Client ACK timeout (seconds).
  - **Example**:

    ```toml
    [timeouts]
    client_ack = 90
    ```
## "cfg-timeouts-me_one_retry"
- `me_one_retry`
  - **Constraints / validation**: `u8`.
  - **Description**: Fast reconnect attempts budget for single-endpoint DC scenarios.
  - **Example**:

    ```toml
    [timeouts]
    me_one_retry = 12
    ```
## "cfg-timeouts-me_one_timeout_ms"
- `me_one_timeout_ms`
  - **Constraints / validation**: `u64`. Value is in milliseconds.
  - **Description**: Timeout per quick attempt (ms) for single-endpoint DC reconnect logic.
  - **Example**:

    ```toml
    [timeouts]
    me_one_timeout_ms = 1200
    ```


# [censorship]


| Key | Type | Default |
| --- | ---- | ------- |
| [`tls_domain`](#cfg-censorship-tls_domain) | `String` | `"petrovich.ru"` |
| [`tls_domains`](#cfg-censorship-tls_domains) | `String[]` | `[]` |
| [`unknown_sni_action`](#cfg-censorship-unknown_sni_action) | `"drop"`, `"mask"`, `"accept"` | `"drop"` |
| [`tls_fetch_scope`](#cfg-censorship-tls_fetch_scope) | `String` | `""` |
| [`tls_fetch`](#cfg-censorship-tls_fetch) | `Table` | built-in defaults |
| [`mask`](#cfg-censorship-mask) | `bool` | `true` |
| [`mask_host`](#cfg-censorship-mask_host) | `String` | — |
| [`mask_port`](#cfg-censorship-mask_port) | `u16` | `443` |
| [`mask_unix_sock`](#cfg-censorship-mask_unix_sock) | `String` | — |
| [`fake_cert_len`](#cfg-censorship-fake_cert_len) | `usize` | `2048` |
| [`tls_emulation`](#cfg-censorship-tls_emulation) | `bool` | `true` |
| [`tls_front_dir`](#cfg-censorship-tls_front_dir) | `String` | `"tlsfront"` |
| [`server_hello_delay_min_ms`](#cfg-censorship-server_hello_delay_min_ms) | `u64` | `0` |
| [`server_hello_delay_max_ms`](#cfg-censorship-server_hello_delay_max_ms) | `u64` | `0` |
| [`tls_new_session_tickets`](#cfg-censorship-tls_new_session_tickets) | `u8` | `0` |
| [`tls_full_cert_ttl_secs`](#cfg-censorship-tls_full_cert_ttl_secs) | `u64` | `90` |
| [`alpn_enforce`](#cfg-censorship-alpn_enforce) | `bool` | `true` |
| [`mask_proxy_protocol`](#cfg-censorship-mask_proxy_protocol) | `u8` | `0` |
| [`mask_shape_hardening`](#cfg-censorship-mask_shape_hardening) | `bool` | `true` |
| [`mask_shape_hardening_aggressive_mode`](#cfg-censorship-mask_shape_hardening_aggressive_mode) | `bool` | `false` |
| [`mask_shape_bucket_floor_bytes`](#cfg-censorship-mask_shape_bucket_floor_bytes) | `usize` | `512` |
| [`mask_shape_bucket_cap_bytes`](#cfg-censorship-mask_shape_bucket_cap_bytes) | `usize` | `4096` |
| [`mask_shape_above_cap_blur`](#cfg-censorship-mask_shape_above_cap_blur) | `bool` | `false` |
| [`mask_shape_above_cap_blur_max_bytes`](#cfg-censorship-mask_shape_above_cap_blur_max_bytes) | `usize` | `512` |
| [`mask_relay_max_bytes`](#cfg-censorship-mask_relay_max_bytes) | `usize` | `5242880` |
| [`mask_classifier_prefetch_timeout_ms`](#cfg-censorship-mask_classifier_prefetch_timeout_ms) | `u64` | `5` |
| [`mask_timing_normalization_enabled`](#cfg-censorship-mask_timing_normalization_enabled) | `bool` | `false` |
| [`mask_timing_normalization_floor_ms`](#cfg-censorship-mask_timing_normalization_floor_ms) | `u64` | `0` |
| [`mask_timing_normalization_ceiling_ms`](#cfg-censorship-mask_timing_normalization_ceiling_ms) | `u64` | `0` |

## "cfg-censorship-tls_domain"
- `tls_domain`
  - **Constraints / validation**: Must be a non-empty domain name. Must not contain spaces or `/`.
  - **Description**: Primary TLS domain used in FakeTLS handshake profile and as the default SNI domain.
  - **Example**:

    ```toml
    [censorship]
    tls_domain = "example.com"
    ```
## "cfg-censorship-tls_domains"
- `tls_domains`
  - **Constraints / validation**: `String[]`. When set, values are merged with `tls_domain` and deduplicated (primary `tls_domain` always stays first).
  - **Description**: Additional TLS domains for generating multiple proxy links.
  - **Example**:

    ```toml
    [censorship]
    tls_domain = "example.com"
    tls_domains = ["example.net", "example.org"]
    ```
## "cfg-censorship-unknown_sni_action"
- `unknown_sni_action`
  - **Constraints / validation**: `"drop"`, `"mask"` or `"accept"`.
  - **Description**: Action for TLS ClientHello with unknown / non-configured SNI.
  - **Example**:

    ```toml
    [censorship]
    unknown_sni_action = "drop"
    ```
## "cfg-censorship-tls_fetch_scope"
- `tls_fetch_scope`
  - **Constraints / validation**: `String`. Value is trimmed during load; whitespace-only becomes empty.
  - **Description**: Upstream scope tag used for TLS-front metadata fetches. Empty value keeps default upstream routing behavior.
  - **Example**:

    ```toml
    [censorship]
    tls_fetch_scope = "fetch"
    ```
## "cfg-censorship-tls_fetch"
- `tls_fetch`
  - **Constraints / validation**: Table. See `[censorship.tls_fetch]` section below.
  - **Description**: TLS-front metadata fetch strategy settings (bootstrap + refresh behavior for TLS emulation data).
  - **Example**:

    ```toml
    [censorship.tls_fetch]
    strict_route = true
    attempt_timeout_ms = 5000
    total_budget_ms = 15000
    ```
## "cfg-censorship-mask"
- `mask`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables masking / fronting relay mode.
  - **Example**:

    ```toml
    [censorship]
    mask = true
    ```
## "cfg-censorship-mask_host"
- `mask_host`
  - **Constraints / validation**: `String` (optional).
    - If `mask_unix_sock` is set, `mask_host` must be omitted (mutually exclusive).
    - If `mask_host` is not set and `mask_unix_sock` is not set, Telemt defaults `mask_host` to `tls_domain`.
  - **Description**: Upstream mask host for TLS fronting relay.
  - **Example**:

    ```toml
    [censorship]
    mask_host = "www.cloudflare.com"
    ```
## "cfg-censorship-mask_port"
- `mask_port`
  - **Constraints / validation**: `u16`.
  - **Description**: Upstream mask port for TLS fronting relay.
  - **Example**:

    ```toml
    [censorship]
    mask_port = 443
    ```
## "cfg-censorship-mask_unix_sock"
- `mask_unix_sock`
  - **Constraints / validation**: `String` (optional).
    - Must not be empty when set.
    - Unix only; rejected on non-Unix platforms.
    - On Unix, must be \(\le 107\) bytes (path length limit).
    - Mutually exclusive with `mask_host`.
  - **Description**: Unix socket path for mask backend instead of TCP `mask_host`/`mask_port`.
  - **Example**:

    ```toml
    [censorship]
    mask_unix_sock = "/run/telemt/mask.sock"
    ```
## "cfg-censorship-fake_cert_len"
- `fake_cert_len`
  - **Constraints / validation**: `usize`. When `tls_emulation = false` and the default value is in use, Telemt may randomize this at startup for variability.
  - **Description**: Length of synthetic certificate payload when emulation data is unavailable.
  - **Example**:

    ```toml
    [censorship]
    fake_cert_len = 2048
    ```
## "cfg-censorship-tls_emulation"
- `tls_emulation`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables certificate/TLS behavior emulation from cached real fronts.
  - **Example**:

    ```toml
    [censorship]
    tls_emulation = true
    ```
## "cfg-censorship-tls_front_dir"
- `tls_front_dir`
  - **Constraints / validation**: `String`.
  - **Description**: Directory path for TLS front cache storage.
  - **Example**:

    ```toml
    [censorship]
    tls_front_dir = "tlsfront"
    ```
## "cfg-censorship-server_hello_delay_min_ms"
- `server_hello_delay_min_ms`
  - **Constraints / validation**: `u64` (milliseconds).
  - **Description**: Minimum `server_hello` delay for anti-fingerprint behavior (ms).
  - **Example**:

    ```toml
    [censorship]
    server_hello_delay_min_ms = 0
    ```
## "cfg-censorship-server_hello_delay_max_ms"
- `server_hello_delay_max_ms`
  - **Constraints / validation**: `u64` (milliseconds). Must be \(<\) `timeouts.client_handshake * 1000`.
  - **Description**: Maximum `server_hello` delay for anti-fingerprint behavior (ms).
  - **Example**:

    ```toml
    [timeouts]
    client_handshake = 30

    [censorship]
    server_hello_delay_max_ms = 0
    ```
## "cfg-censorship-tls_new_session_tickets"
- `tls_new_session_tickets`
  - **Constraints / validation**: `u8`.
  - **Description**: Number of `NewSessionTicket` messages to emit after handshake.
  - **Example**:

    ```toml
    [censorship]
    tls_new_session_tickets = 0
    ```
## "cfg-censorship-tls_full_cert_ttl_secs"
- `tls_full_cert_ttl_secs`
  - **Constraints / validation**: `u64` (seconds).
  - **Description**: TTL for sending full cert payload per (domain, client IP) tuple.
  - **Example**:

    ```toml
    [censorship]
    tls_full_cert_ttl_secs = 90
    ```
## "cfg-censorship-alpn_enforce"
- `alpn_enforce`
  - **Constraints / validation**: `bool`.
  - **Description**: Enforces ALPN echo behavior based on client preference.
  - **Example**:

    ```toml
    [censorship]
    alpn_enforce = true
    ```
## "cfg-censorship-mask_proxy_protocol"
- `mask_proxy_protocol`
  - **Constraints / validation**: `u8`. `0` = disabled, `1` = v1 (text), `2` = v2 (binary).
  - **Description**: Sends PROXY protocol header when connecting to mask backend, allowing the backend to see the real client IP.
  - **Example**:

    ```toml
    [censorship]
    mask_proxy_protocol = 0
    ```
## "cfg-censorship-mask_shape_hardening"
- `mask_shape_hardening`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables client->mask shape-channel hardening by applying controlled tail padding to bucket boundaries on mask relay shutdown.
  - **Example**:

    ```toml
    [censorship]
    mask_shape_hardening = true
    ```
## "cfg-censorship-mask_shape_hardening_aggressive_mode"
- `mask_shape_hardening_aggressive_mode`
  - **Constraints / validation**: Requires `mask_shape_hardening = true`.
  - **Description**: Opt-in aggressive shaping profile (stronger anti-classifier behavior with different shaping semantics).
  - **Example**:

    ```toml
    [censorship]
    mask_shape_hardening = true
    mask_shape_hardening_aggressive_mode = false
    ```
## "cfg-censorship-mask_shape_bucket_floor_bytes"
- `mask_shape_bucket_floor_bytes`
  - **Constraints / validation**: Must be `> 0`; must be `<= mask_shape_bucket_cap_bytes`.
  - **Description**: Minimum bucket size used by shape-channel hardening.
  - **Example**:

    ```toml
    [censorship]
    mask_shape_bucket_floor_bytes = 512
    ```
## "cfg-censorship-mask_shape_bucket_cap_bytes"
- `mask_shape_bucket_cap_bytes`
  - **Constraints / validation**: Must be `>= mask_shape_bucket_floor_bytes`.
  - **Description**: Maximum bucket size used by shape-channel hardening; traffic above cap is not bucket-padded further.
  - **Example**:

    ```toml
    [censorship]
    mask_shape_bucket_cap_bytes = 4096
    ```
## "cfg-censorship-mask_shape_above_cap_blur"
- `mask_shape_above_cap_blur`
  - **Constraints / validation**: Requires `mask_shape_hardening = true`.
  - **Description**: Adds bounded randomized tail bytes even when forwarded size already exceeds cap.
  - **Example**:

    ```toml
    [censorship]
    mask_shape_hardening = true
    mask_shape_above_cap_blur = false
    ```
## "cfg-censorship-mask_shape_above_cap_blur_max_bytes"
- `mask_shape_above_cap_blur_max_bytes`
  - **Constraints / validation**: Must be `<= 1048576`. Must be `> 0` when `mask_shape_above_cap_blur = true`.
  - **Description**: Maximum randomized extra bytes appended above cap when above-cap blur is enabled.
  - **Example**:

    ```toml
    [censorship]
    mask_shape_above_cap_blur = true
    mask_shape_above_cap_blur_max_bytes = 64
    ```
## "cfg-censorship-mask_relay_max_bytes"
- `mask_relay_max_bytes`
  - **Constraints / validation**: Must be `> 0`; must be `<= 67108864`.
  - **Description**: Maximum relayed bytes per direction on unauthenticated masking fallback path.
  - **Example**:

    ```toml
    [censorship]
    mask_relay_max_bytes = 5242880
    ```
## "cfg-censorship-mask_classifier_prefetch_timeout_ms"
- `mask_classifier_prefetch_timeout_ms`
  - **Constraints / validation**: Must be within `[5, 50]` (milliseconds).
  - **Description**: Timeout budget (ms) for extending fragmented initial classifier window on masking fallback.
  - **Example**:

    ```toml
    [censorship]
    mask_classifier_prefetch_timeout_ms = 5
    ```
## "cfg-censorship-mask_timing_normalization_enabled"
- `mask_timing_normalization_enabled`
  - **Constraints / validation**: When `true`, requires `mask_timing_normalization_floor_ms > 0` and `mask_timing_normalization_ceiling_ms >= mask_timing_normalization_floor_ms`. Ceiling must be `<= 60000`.
  - **Description**: Enables timing envelope normalization on masking outcomes.
  - **Example**:

    ```toml
    [censorship]
    mask_timing_normalization_enabled = false
    ```
## "cfg-censorship-mask_timing_normalization_floor_ms"
- `mask_timing_normalization_floor_ms`
  - **Constraints / validation**: Must be `> 0` when timing normalization is enabled; must be `<= mask_timing_normalization_ceiling_ms`.
  - **Description**: Lower bound (ms) for masking outcome normalization target.
  - **Example**:

    ```toml
    [censorship]
    mask_timing_normalization_floor_ms = 0
    ```
## "cfg-censorship-mask_timing_normalization_ceiling_ms"
- `mask_timing_normalization_ceiling_ms`
  - **Constraints / validation**: Must be `>= mask_timing_normalization_floor_ms`; must be `<= 60000`.
  - **Description**: Upper bound (ms) for masking outcome normalization target.
  - **Example**:

    ```toml
    [censorship]
    mask_timing_normalization_ceiling_ms = 0
    ```

## Shape-channel hardening notes (`[censorship]`)

These parameters are designed to reduce one specific fingerprint source during masking: the exact number of bytes sent from proxy to `mask_host` for invalid or probing traffic.

Without hardening, a censor can often correlate probe input length with backend-observed length very precisely (for example: `5 + body_sent` on early TLS reject paths). That creates a length-based classifier signal.

When `mask_shape_hardening = true`, Telemt pads the **client->mask** stream tail to a bucket boundary at relay shutdown:

- Total bytes sent to mask are first measured.
- A bucket is selected using powers of two starting from `mask_shape_bucket_floor_bytes`.
- Padding is added only if total bytes are below `mask_shape_bucket_cap_bytes`.
- If bytes already exceed cap, no extra padding is added.

This means multiple nearby probe sizes collapse into the same backend-observed size class, making active classification harder.

What each parameter changes in practice:

- `mask_shape_hardening`
  Enables or disables this entire length-shaping stage on the fallback path.
  When `false`, backend-observed length stays close to the real forwarded probe length.
  When `true`, clean relay shutdown can append random padding bytes to move the total into a bucket.
- `mask_shape_bucket_floor_bytes`
  Sets the first bucket boundary used for small probes.
  Example: with floor `512`, a malformed probe that would otherwise forward `37` bytes can be expanded to `512` bytes on clean EOF.
  Larger floor values hide very small probes better, but increase egress cost.
- `mask_shape_bucket_cap_bytes`
  Sets the largest bucket Telemt will pad up to with bucket logic.
  Example: with cap `4096`, a forwarded total of `1800` bytes may be padded to `2048` or `4096` depending on the bucket ladder, but a total already above `4096` will not be bucket-padded further.
  Larger cap values increase the range over which size classes are collapsed, but also increase worst-case overhead.
- Clean EOF matters in conservative mode
  In the default profile, shape padding is intentionally conservative: it is applied on clean relay shutdown, not on every timeout/drip path.
  This avoids introducing new timeout-tail artifacts that some backends or tests interpret as a separate fingerprint.

Practical trade-offs:

- Better anti-fingerprinting on size/shape channel.
- Slightly higher egress overhead for small probes due to padding.
- Behavior is intentionally conservative and enabled by default.

Recommended starting profile:

- `mask_shape_hardening = true` (default)
- `mask_shape_bucket_floor_bytes = 512`
- `mask_shape_bucket_cap_bytes = 4096`

## Aggressive mode notes (`[censorship]`)

`mask_shape_hardening_aggressive_mode` is an opt-in profile for higher anti-classifier pressure.

- Default is `false` to preserve conservative timeout/no-tail behavior.
- Requires `mask_shape_hardening = true`.
- When enabled, backend-silent non-EOF masking paths may be shaped.
- When enabled together with above-cap blur, the random extra tail uses `[1, max]` instead of `[0, max]`.

What changes when aggressive mode is enabled:

- Backend-silent timeout paths can be shaped
  In default mode, a client that keeps the socket half-open and times out will usually not receive shape padding on that path.
  In aggressive mode, Telemt may still shape that backend-silent session if no backend bytes were returned.
  This is specifically aimed at active probes that try to avoid EOF in order to preserve an exact backend-observed length.
- Above-cap blur always adds at least one byte
  In default mode, above-cap blur may choose `0`, so some oversized probes still land on their exact base forwarded length.
  In aggressive mode, that exact-base sample is removed by construction.
- Tradeoff
  Aggressive mode improves resistance to active length classifiers, but it is more opinionated and less conservative.
  If your deployment prioritizes strict compatibility with timeout/no-tail semantics, leave it disabled.
  If your threat model includes repeated active probing by a censor, this mode is the stronger profile.

Use this mode only when your threat model prioritizes classifier resistance over strict compatibility with conservative masking semantics.

## Above-cap blur notes (`[censorship]`)

`mask_shape_above_cap_blur` adds a second-stage blur for very large probes that are already above `mask_shape_bucket_cap_bytes`.

- A random tail in `[0, mask_shape_above_cap_blur_max_bytes]` is appended in default mode.
- In aggressive mode, the random tail becomes strictly positive: `[1, mask_shape_above_cap_blur_max_bytes]`.
- This reduces exact-size leakage above cap at bounded overhead.
- Keep `mask_shape_above_cap_blur_max_bytes` conservative to avoid unnecessary egress growth.

Operational meaning:

- Without above-cap blur
  A probe that forwards `5005` bytes will still look like `5005` bytes to the backend if it is already above cap.
- With above-cap blur enabled
  That same probe may look like any value in a bounded window above its base length.
  Example with `mask_shape_above_cap_blur_max_bytes = 64`:
  backend-observed size becomes `5005..5069` in default mode, or `5006..5069` in aggressive mode.
- Choosing `mask_shape_above_cap_blur_max_bytes`
  Small values reduce cost but preserve more separability between far-apart oversized classes.
  Larger values blur oversized classes more aggressively, but add more egress overhead and more output variance.

## Timing normalization envelope notes (`[censorship]`)

`mask_timing_normalization_enabled` smooths timing differences between masking outcomes by applying a target duration envelope.

- A random target is selected in `[mask_timing_normalization_floor_ms, mask_timing_normalization_ceiling_ms]`.
- Fast paths are delayed up to the selected target.
- Slow paths are not forced to finish by the ceiling (the envelope is best-effort shaping, not truncation).

Recommended starting profile for timing shaping:

- `mask_timing_normalization_enabled = true`
- `mask_timing_normalization_floor_ms = 180`
- `mask_timing_normalization_ceiling_ms = 320`

If your backend or network is very bandwidth-constrained, reduce cap first. If probes are still too distinguishable in your environment, increase floor gradually.


# [censorship.tls_fetch]


| Key | Type | Default |
| --- | ---- | ------- |
| [`profiles`](#cfg-censorship-tls_fetch-profiles) | `String[]` | `["modern_chrome_like", "modern_firefox_like", "compat_tls12", "legacy_minimal"]` |
| [`strict_route`](#cfg-censorship-tls_fetch-strict_route) | `bool` | `true` |
| [`attempt_timeout_ms`](#cfg-censorship-tls_fetch-attempt_timeout_ms) | `u64` | `5000` |
| [`total_budget_ms`](#cfg-censorship-tls_fetch-total_budget_ms) | `u64` | `15000` |
| [`grease_enabled`](#cfg-censorship-tls_fetch-grease_enabled) | `bool` | `false` |
| [`deterministic`](#cfg-censorship-tls_fetch-deterministic) | `bool` | `false` |
| [`profile_cache_ttl_secs`](#cfg-censorship-tls_fetch-profile_cache_ttl_secs) | `u64` | `600` |

## "cfg-censorship-tls_fetch-profiles"
- `profiles`
  - **Constraints / validation**: `String[]`. Empty list falls back to defaults; values are deduplicated preserving order.
  - **Description**: Ordered ClientHello profile fallback chain for TLS-front metadata fetch.
  - **Example**:

    ```toml
    [censorship.tls_fetch]
    profiles = ["modern_chrome_like", "compat_tls12"]
    ```
## "cfg-censorship-tls_fetch-strict_route"
- `strict_route`
  - **Constraints / validation**: `bool`.
  - **Description**: When `true` and an upstream route is configured, TLS fetch fails closed on upstream connect errors instead of falling back to direct TCP.
  - **Example**:

    ```toml
    [censorship.tls_fetch]
    strict_route = true
    ```
## "cfg-censorship-tls_fetch-attempt_timeout_ms"
- `attempt_timeout_ms`
  - **Constraints / validation**: Must be `> 0` (milliseconds).
  - **Description**: Timeout budget per one TLS-fetch profile attempt (ms).
  - **Example**:

    ```toml
    [censorship.tls_fetch]
    attempt_timeout_ms = 5000
    ```
## "cfg-censorship-tls_fetch-total_budget_ms"
- `total_budget_ms`
  - **Constraints / validation**: Must be `> 0` (milliseconds).
  - **Description**: Total wall-clock budget across all TLS-fetch attempts (ms).
  - **Example**:

    ```toml
    [censorship.tls_fetch]
    total_budget_ms = 15000
    ```
## "cfg-censorship-tls_fetch-grease_enabled"
- `grease_enabled`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables GREASE-style random values in selected ClientHello extensions for fetch traffic.
  - **Example**:

    ```toml
    [censorship.tls_fetch]
    grease_enabled = false
    ```
## "cfg-censorship-tls_fetch-deterministic"
- `deterministic`
  - **Constraints / validation**: `bool`.
  - **Description**: Enables deterministic ClientHello randomness for debugging/tests.
  - **Example**:

    ```toml
    [censorship.tls_fetch]
    deterministic = false
    ```
## "cfg-censorship-tls_fetch-profile_cache_ttl_secs"
- `profile_cache_ttl_secs`
  - **Constraints / validation**: `u64` (seconds). `0` disables cache.
  - **Description**: TTL for winner-profile cache entries used by TLS fetch path.
  - **Example**:

    ```toml
    [censorship.tls_fetch]
    profile_cache_ttl_secs = 600
    ```

# [access]


| Key | Type | Default |
| --- | ---- | ------- |
| [`users`](#cfg-access-users) | `Map<String, String>` | `{"default": "000…000"}` |
| [`user_ad_tags`](#cfg-access-user_ad_tags) | `Map<String, String>` | `{}` |
| [`user_max_tcp_conns`](#cfg-access-user_max_tcp_conns) | `Map<String, usize>` | `{}` |
| [`user_max_tcp_conns_global_each`](#cfg-access-user_max_tcp_conns_global_each) | `usize` | `0` |
| [`user_expirations`](#cfg-access-user_expirations) | `Map<String, DateTime<Utc>>` | `{}` |
| [`user_data_quota`](#cfg-access-user_data_quota) | `Map<String, u64>` | `{}` |
| [`user_max_unique_ips`](#cfg-access-user_max_unique_ips) | `Map<String, usize>` | `{}` |
| [`user_max_unique_ips_global_each`](#cfg-access-user_max_unique_ips_global_each) | `usize` | `0` |
| [`user_max_unique_ips_mode`](#cfg-access-user_max_unique_ips_mode) | `"active_window"`, `"time_window"`, or `"combined"` | `"active_window"` |
| [`user_max_unique_ips_window_secs`](#cfg-access-user_max_unique_ips_window_secs) | `u64` | `30` |
| [`replay_check_len`](#cfg-access-replay_check_len) | `usize` | `65536` |
| [`replay_window_secs`](#cfg-access-replay_window_secs) | `u64` | `120` |
| [`ignore_time_skew`](#cfg-access-ignore_time_skew) | `bool` | `false` |

## "cfg-access-users"
- `users`
  - **Constraints / validation**: Must not be empty (at least one user must exist). Each value must be **exactly 32 hex characters**.
  - **Description**: User credentials map used for client authentication. Keys are user names; values are MTProxy secrets.
  - **Example**:

    ```toml
    [access.users]
    alice = "00112233445566778899aabbccddeeff"
    bob   = "0123456789abcdef0123456789abcdef"
    ```
## "cfg-access-user_ad_tags"
- `user_ad_tags`
  - **Constraints / validation**: Each value must be **exactly 32 hex characters** (same format as `general.ad_tag`). An all-zero tag is allowed but logs a warning.
  - **Description**: Per-user sponsored-channel ad tag override. When a user has an entry here, it takes precedence over `general.ad_tag`.
  - **Example**:

    ```toml
    [general]
    ad_tag = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    [access.user_ad_tags]
    alice = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ```
## "cfg-access-user_max_tcp_conns"
- `user_max_tcp_conns`
  - **Constraints / validation**: `Map<String, usize>`.
  - **Description**: Per-user maximum concurrent TCP connections.
  - **Example**:

    ```toml
    [access.user_max_tcp_conns]
    alice = 500
    ```
## "cfg-access-user_max_tcp_conns_global_each"
- `user_max_tcp_conns_global_each`
  - **Constraints / validation**: `usize`. `0` disables the inherited limit.
  - **Description**: Global per-user maximum concurrent TCP connections, applied when a user has **no positive** entry in `[access.user_max_tcp_conns]` (a missing key, or a value of `0`, both fall through to this setting). Per-user limits greater than `0` in `user_max_tcp_conns` take precedence.
  - **Example**:

    ```toml
    [access]
    user_max_tcp_conns_global_each = 200

    [access.user_max_tcp_conns]
    alice = 500   # uses 500, not the global cap
    # bob has no entry → uses 200
    ```
## "cfg-access-user_expirations"
- `user_expirations`
  - **Constraints / validation**: `Map<String, DateTime<Utc>>`. Each value must be a valid RFC3339 / ISO-8601 datetime.
  - **Description**: Per-user account expiration timestamps (UTC).
  - **Example**:

    ```toml
    [access.user_expirations]
    alice = "2026-12-31T23:59:59Z"
    ```
## "cfg-access-user_data_quota"
- `user_data_quota`
  - **Constraints / validation**: `Map<String, u64>`.
  - **Description**: Per-user traffic quota in bytes.
  - **Example**:

    ```toml
    [access.user_data_quota]
    alice = 1073741824 # 1 GiB
    ```
## "cfg-access-user_max_unique_ips"
- `user_max_unique_ips`
  - **Constraints / validation**: `Map<String, usize>`.
  - **Description**: Per-user unique source IP limits.
  - **Example**:

    ```toml
    [access.user_max_unique_ips]
    alice = 16
    ```
## "cfg-access-user_max_unique_ips_global_each"
- `user_max_unique_ips_global_each`
  - **Constraints / validation**: `usize`. `0` disables the inherited limit.
  - **Description**: Global per-user unique IP limit applied when a user has no individual override in `[access.user_max_unique_ips]`.
  - **Example**:

    ```toml
    [access]
    user_max_unique_ips_global_each = 8
    ```
## "cfg-access-user_max_unique_ips_mode"
- `user_max_unique_ips_mode`
  - **Constraints / validation**: Must be one of `"active_window"`, `"time_window"`, `"combined"`.
  - **Description**: Unique source IP limit accounting mode.
  - **Example**:

    ```toml
    [access]
    user_max_unique_ips_mode = "active_window"
    ```
## "cfg-access-user_max_unique_ips_window_secs"
- `user_max_unique_ips_window_secs`
  - **Constraints / validation**: Must be `> 0`.
  - **Description**: Window size (seconds) used by unique-IP accounting modes that include a time window (`"time_window"` and `"combined"`).
  - **Example**:

    ```toml
    [access]
    user_max_unique_ips_window_secs = 30
    ```
## "cfg-access-replay_check_len"
- `replay_check_len`
  - **Constraints / validation**: `usize`.
  - **Description**: Replay-protection storage length (number of entries tracked for duplicate detection).
  - **Example**:

    ```toml
    [access]
    replay_check_len = 65536
    ```
## "cfg-access-replay_window_secs"
- `replay_window_secs`
  - **Constraints / validation**: `u64`.
  - **Description**: Replay-protection time window in seconds.
  - **Example**:

    ```toml
    [access]
    replay_window_secs = 120
    ```
## "cfg-access-ignore_time_skew"
- `ignore_time_skew`
  - **Constraints / validation**: `bool`.
  - **Description**: Disables client/server timestamp skew checks in replay validation when enabled.
  - **Example**:

    ```toml
    [access]
    ignore_time_skew = false
    ```


# [[upstreams]]


| Key | Type | Default |
| --- | ---- | ------- |
| [`type`](#cfg-upstreams-type) | `"direct"`, `"socks4"`, `"socks5"`, or `"shadowsocks"` | — |
| [`weight`](#cfg-upstreams-weight) | `u16` | `1` |
| [`enabled`](#cfg-upstreams-enabled) | `bool` | `true` |
| [`scopes`](#cfg-upstreams-scopes) | `String` | `""` |
| [`interface`](#cfg-upstreams-interface) | `String` | — |
| [`bind_addresses`](#cfg-upstreams-bind_addresses) | `String[]` | — |
| [`url`](#cfg-upstreams-url) | `String` | — |
| [`address`](#cfg-upstreams-address) | `String` | — |
| [`user_id`](#cfg-upstreams-user_id) | `String` | — |
| [`username`](#cfg-upstreams-username) | `String` | — |
| [`password`](#cfg-upstreams-password) | `String` | — |

## "cfg-upstreams-type"
- `type`
  - **Constraints / validation**: Required field. Must be one of: `"direct"`, `"socks4"`, `"socks5"`, `"shadowsocks"`.
  - **Description**: Selects the upstream transport implementation for this `[[upstreams]]` entry.
  - **Example**:

    ```toml
    [[upstreams]]
    type = "direct"

    [[upstreams]]
    type = "socks5"
    address = "127.0.0.1:9050"

    [[upstreams]]
    type = "shadowsocks"
    url = "ss://2022-blake3-aes-256-gcm:BASE64PASSWORD@127.0.0.1:8388"
    ```
## "cfg-upstreams-weight"
- `weight`
  - **Constraints / validation**: `u16` (0..=65535).
  - **Description**: Base weight used by weighted-random upstream selection (higher = chosen more often).
  - **Example**:

    ```toml
    [[upstreams]]
    type = "direct"
    weight = 10
    ```
## "cfg-upstreams-enabled"
- `enabled`
  - **Constraints / validation**: `bool`.
  - **Description**: When `false`, this entry is ignored and not used for any upstream selection.
  - **Example**:

    ```toml
    [[upstreams]]
    type = "socks5"
    address = "127.0.0.1:9050"
    enabled = false
    ```
## "cfg-upstreams-scopes"
- `scopes`
  - **Constraints / validation**: `String`. Comma-separated list; whitespace is trimmed during matching.
  - **Description**: Scope tags used for request-level upstream filtering. If a request specifies a scope, only upstreams whose `scopes` contains that tag can be selected. If a request does not specify a scope, only upstreams with empty `scopes` are eligible.
  - **Example**:

    ```toml
    [[upstreams]]
    type = "socks4"
    address = "10.0.0.10:1080"
    scopes = "me, fetch, dc2"
    ```
## "cfg-upstreams-interface"
- `interface`
  - **Constraints / validation**: `String` (optional).
    - For `"direct"`: may be an IP address (used as explicit local bind) or an OS interface name (resolved to an IP at runtime; Unix only).
    - For `"socks4"`/`"socks5"`: supported only when `address` is an `IP:port` literal; when `address` is a hostname, interface binding is ignored.
    - For `"shadowsocks"`: passed to the shadowsocks connector as an optional outbound bind hint.
  - **Description**: Optional outbound interface / local bind hint for the upstream connect socket.
  - **Example**:

    ```toml
    [[upstreams]]
    type = "direct"
    interface = "eth0"

    [[upstreams]]
    type = "socks5"
    address = "203.0.113.10:1080"
    interface = "192.0.2.10" # explicit local bind IP
    ```
## "cfg-upstreams-bind_addresses"
- `bind_addresses`
  - **Constraints / validation**: `String[]` (optional). Applies only to `type = "direct"`.
    - Each entry should be an IP address string.
    - At runtime, Telemt selects an address that matches the target family (IPv4 vs IPv6). If `bind_addresses` is set and none match the target family, the connect attempt fails.
  - **Description**: Explicit local source addresses for outgoing direct TCP connects. When multiple addresses are provided, selection is round-robin.
  - **Example**:

    ```toml
    [[upstreams]]
    type = "direct"
    bind_addresses = ["192.0.2.10", "192.0.2.11"]
    ```
## "cfg-upstreams-url"
- `url`
  - **Constraints / validation**: Applies only to `type = "shadowsocks"`.
    - Must be a valid Shadowsocks URL accepted by the `shadowsocks` crate.
    - Shadowsocks plugins are not supported.
    - Requires `general.use_middle_proxy = false` (shadowsocks upstreams are rejected in ME mode).
  - **Description**: Shadowsocks server URL used for connecting to Telegram via a Shadowsocks relay.
  - **Example**:

    ```toml
    [general]
    use_middle_proxy = false

    [[upstreams]]
    type = "shadowsocks"
    url = "ss://2022-blake3-aes-256-gcm:BASE64PASSWORD@127.0.0.1:8388"
    ```
## "cfg-upstreams-address"
- `address`
  - **Constraints / validation**: Required for `type = "socks4"` and `type = "socks5"`. Must be `host:port` or `ip:port`.
  - **Description**: SOCKS proxy server endpoint used for upstream connects.
  - **Example**:

    ```toml
    [[upstreams]]
    type = "socks5"
    address = "127.0.0.1:9050"
    ```
## "cfg-upstreams-user_id"
- `user_id`
  - **Constraints / validation**: `String` (optional). Only for `type = "socks4"`.
  - **Description**: SOCKS4 CONNECT user ID. Note: when a request scope is selected, Telemt may override this with the selected scope value.
  - **Example**:

    ```toml
    [[upstreams]]
    type = "socks4"
    address = "127.0.0.1:1080"
    user_id = "telemt"
    ```
## "cfg-upstreams-username"
- `username`
  - **Constraints / validation**: `String` (optional). Only for `type = "socks5"`.
  - **Description**: SOCKS5 username (for username/password authentication). Note: when a request scope is selected, Telemt may override this with the selected scope value.
  - **Example**:

    ```toml
    [[upstreams]]
    type = "socks5"
    address = "127.0.0.1:9050"
    username = "alice"
    ```
## "cfg-upstreams-password"
- `password`
  - **Constraints / validation**: `String` (optional). Only for `type = "socks5"`.
  - **Description**: SOCKS5 password (for username/password authentication). Note: when a request scope is selected, Telemt may override this with the selected scope value.
  - **Example**:

    ```toml
    [[upstreams]]
    type = "socks5"
    address = "127.0.0.1:9050"
    username = "alice"
    password = "secret"
    ```


