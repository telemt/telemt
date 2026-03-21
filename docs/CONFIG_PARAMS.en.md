# Telemt Config Parameters Reference

This document lists all configuration keys accepted by `config.toml`.

> [!WARNING]
> 
> The configuration parameters detailed in this document are intended for advanced users and fine-tuning purposes. Modifying these settings without a clear understanding of their function may lead to application instability or other unexpected behavior. Please proceed with caution and at your own risk.

## Top-level keys

| Parameter | Type | Default | Constraints / validation | Description |
|---|---|---|---|---|
| include | `String` (special directive) | `null` | — | Includes another TOML file with `include = "relative/or/absolute/path.toml"`; includes are processed recursively before parsing. |
| show_link | `"*" \| String[]` | `[]` (`ShowLink::None`) | — | Legacy top-level link visibility selector (`"*"` for all users or explicit usernames list). |
| dc_overrides | `Map<String, String[]>` | `{}` | — | Overrides DC endpoints for non-standard DCs; key is DC id string, value is `ip:port` list. |
| default_dc | `u8 \| null` | `null` (effective fallback: `2` in ME routing) | — | Default DC index used for unmapped non-standard DCs. |

## [general]

| Parameter | Type | Default | Constraints / validation | Description |
|---|---|---|---|---|
| data_path | `String \| null` | `null` | — | Optional runtime data directory path. |
| prefer_ipv6 | `bool` | `false` | — | Prefer IPv6 where applicable in runtime logic. |
| fast_mode | `bool` | `true` | — | Enables fast-path optimizations for traffic processing. |
| use_middle_proxy | `bool` | `true` | none | Enables ME transport mode; if `false`, runtime falls back to direct DC routing. |
| proxy_secret_path | `String \| null` | `"proxy-secret"` | Path may be `null`. | Path to Telegram infrastructure proxy-secret file used by ME handshake logic. |
| proxy_config_v4_cache_path | `String \| null` | `"cache/proxy-config-v4.txt"` | — | Optional cache path for raw `getProxyConfig` (IPv4) snapshot. |
| proxy_config_v6_cache_path | `String \| null` | `"cache/proxy-config-v6.txt"` | — | Optional cache path for raw `getProxyConfigV6` (IPv6) snapshot. |
| ad_tag | `String \| null` | `null` | — | Global fallback ad tag (32 hex characters). |
| middle_proxy_nat_ip | `IpAddr \| null` | `null` | Must be a valid IP when set. | Manual public NAT IP override used as ME address material when set. |
| middle_proxy_nat_probe | `bool` | `true` | Auto-forced to `true` when `use_middle_proxy = true`. | Enables ME NAT probing; runtime may force it on when ME mode is active. |
| middle_proxy_nat_stun | `String \| null` | `null` | Deprecated. Use `network.stun_servers`. | Deprecated legacy single STUN server for NAT probing. |
| middle_proxy_nat_stun_servers | `String[]` | `[]` | Deprecated. Use `network.stun_servers`. | Deprecated legacy STUN list for NAT probing fallback. |
| stun_nat_probe_concurrency | `usize` | `8` | Must be `> 0`. | Maximum number of parallel STUN probes during NAT/public endpoint discovery. |
| middle_proxy_pool_size | `usize` | `8` | none | Target size of active ME writer pool. |
| middle_proxy_warm_standby | `usize` | `16` | none | Reserved compatibility field in current runtime revision. |
| me_init_retry_attempts | `u32` | `0` | `0..=1_000_000`. | Startup retries for ME pool initialization (`0` means unlimited). |
| me2dc_fallback | `bool` | `true` | — | Allows fallback from ME mode to direct DC when ME startup fails. |
| me_keepalive_enabled | `bool` | `true` | none | Enables periodic ME keepalive/ping traffic. |
| me_keepalive_interval_secs | `u64` | `8` | none | Base ME keepalive interval in seconds. |
| me_keepalive_jitter_secs | `u64` | `2` | none | Keepalive jitter in seconds to reduce synchronized bursts. |
| me_keepalive_payload_random | `bool` | `true` | none | Randomizes keepalive payload bytes instead of fixed zero payload. |
| rpc_proxy_req_every | `u64` | `0` | `0` or `10..=300`. | Interval for service `RPC_PROXY_REQ` activity signals (`0` disables). |
| me_writer_cmd_channel_capacity | `usize` | `4096` | Must be `> 0`. | Capacity of per-writer command channel. |
| me_route_channel_capacity | `usize` | `768` | Must be `> 0`. | Capacity of per-connection ME response route channel. |
| me_c2me_channel_capacity | `usize` | `1024` | Must be `> 0`. | Capacity of per-client command queue (client reader -> ME sender). |
| me_reader_route_data_wait_ms | `u64` | `2` | `0..=20`. | Bounded wait for routing ME DATA to per-connection queue (`0` = no wait). |
| me_d2c_flush_batch_max_frames | `usize` | `32` | `1..=512`. | Max ME->client frames coalesced before flush. |
| me_d2c_flush_batch_max_bytes | `usize` | `131072` | `4096..=2_097_152`. | Max ME->client payload bytes coalesced before flush. |
| me_d2c_flush_batch_max_delay_us | `u64` | `500` | `0..=5000`. | Max microsecond wait for coalescing more ME->client frames (`0` disables timed coalescing). |
| me_d2c_ack_flush_immediate | `bool` | `true` | — | Flushes client writer immediately after quick-ack write. |
| direct_relay_copy_buf_c2s_bytes | `usize` | `65536` | `4096..=1_048_576`. | Copy buffer size for client->DC direction in direct relay. |
| direct_relay_copy_buf_s2c_bytes | `usize` | `262144` | `8192..=2_097_152`. | Copy buffer size for DC->client direction in direct relay. |
| crypto_pending_buffer | `usize` | `262144` | — | Max pending ciphertext buffer per client writer (bytes). |
| max_client_frame | `usize` | `16777216` | — | Maximum allowed client MTProto frame size (bytes). |
| desync_all_full | `bool` | `false` | — | Emits full crypto-desync forensic logs for every event. |
| beobachten | `bool` | `true` | — | Enables per-IP forensic observation buckets. |
| beobachten_minutes | `u64` | `10` | Must be `> 0`. | Retention window (minutes) for per-IP observation buckets. |
| beobachten_flush_secs | `u64` | `15` | Must be `> 0`. | Snapshot flush interval (seconds) for observation output file. |
| beobachten_file | `String` | `"cache/beobachten.txt"` | — | Observation snapshot output file path. |
| hardswap | `bool` | `true` | none | Enables generation-based ME hardswap strategy. |
| me_warmup_stagger_enabled | `bool` | `true` | none | Staggers extra ME warmup dials to avoid connection spikes. |
| me_warmup_step_delay_ms | `u64` | `500` | none | Base delay in milliseconds between warmup dial steps. |
| me_warmup_step_jitter_ms | `u64` | `300` | none | Additional random delay in milliseconds for warmup steps. |
| me_reconnect_max_concurrent_per_dc | `u32` | `8` | none | Limits concurrent reconnect workers per DC during health recovery. |
| me_reconnect_backoff_base_ms | `u64` | `500` | none | Initial reconnect backoff in milliseconds. |
| me_reconnect_backoff_cap_ms | `u64` | `30000` | none | Maximum reconnect backoff cap in milliseconds. |
| me_reconnect_fast_retry_count | `u32` | `16` | none | Immediate retry budget before long backoff behavior applies. |
| me_single_endpoint_shadow_writers | `u8` | `2` | `0..=32`. | Additional reserve writers for one-endpoint DC groups. |
| me_single_endpoint_outage_mode_enabled | `bool` | `true` | — | Enables aggressive outage recovery for one-endpoint DC groups. |
| me_single_endpoint_outage_disable_quarantine | `bool` | `true` | — | Ignores endpoint quarantine in one-endpoint outage mode. |
| me_single_endpoint_outage_backoff_min_ms | `u64` | `250` | Must be `> 0`; also `<= me_single_endpoint_outage_backoff_max_ms`. | Minimum reconnect backoff in outage mode (ms). |
| me_single_endpoint_outage_backoff_max_ms | `u64` | `3000` | Must be `> 0`; also `>= me_single_endpoint_outage_backoff_min_ms`. | Maximum reconnect backoff in outage mode (ms). |
| me_single_endpoint_shadow_rotate_every_secs | `u64` | `900` | — | Periodic shadow writer rotation interval (`0` disables). |
| me_floor_mode | `"static" \| "adaptive"` | `"adaptive"` | — | Writer floor policy mode. |
| me_adaptive_floor_idle_secs | `u64` | `90` | — | Idle time before adaptive floor may reduce one-endpoint target. |
| me_adaptive_floor_min_writers_single_endpoint | `u8` | `1` | `1..=32`. | Minimum adaptive writer target for one-endpoint DC groups. |
| me_adaptive_floor_min_writers_multi_endpoint | `u8` | `1` | `1..=32`. | Minimum adaptive writer target for multi-endpoint DC groups. |
| me_adaptive_floor_recover_grace_secs | `u64` | `180` | — | Grace period to hold static floor after activity. |
| me_adaptive_floor_writers_per_core_total | `u16` | `48` | Must be `> 0`. | Global writer budget per logical CPU core in adaptive mode. |
| me_adaptive_floor_cpu_cores_override | `u16` | `0` | — | Manual CPU core count override (`0` uses auto-detection). |
| me_adaptive_floor_max_extra_writers_single_per_core | `u16` | `1` | — | Per-core max extra writers above base floor for one-endpoint DCs. |
| me_adaptive_floor_max_extra_writers_multi_per_core | `u16` | `2` | — | Per-core max extra writers above base floor for multi-endpoint DCs. |
| me_adaptive_floor_max_active_writers_per_core | `u16` | `64` | Must be `> 0`. | Hard cap for active ME writers per logical CPU core. |
| me_adaptive_floor_max_warm_writers_per_core | `u16` | `64` | Must be `> 0`. | Hard cap for warm ME writers per logical CPU core. |
| me_adaptive_floor_max_active_writers_global | `u32` | `256` | Must be `> 0`. | Hard global cap for active ME writers. |
| me_adaptive_floor_max_warm_writers_global | `u32` | `256` | Must be `> 0`. | Hard global cap for warm ME writers. |
| upstream_connect_retry_attempts | `u32` | `2` | Must be `> 0`. | Connect attempts for selected upstream before error/fallback. |
| upstream_connect_retry_backoff_ms | `u64` | `100` | — | Delay between upstream connect attempts (ms). |
| upstream_connect_budget_ms | `u64` | `3000` | Must be `> 0`. | Total wall-clock budget for one upstream connect request (ms). |
| upstream_unhealthy_fail_threshold | `u32` | `5` | Must be `> 0`. | Consecutive failed requests before upstream is marked unhealthy. |
| upstream_connect_failfast_hard_errors | `bool` | `false` | — | Skips additional retries for hard non-transient connect errors. |
| stun_iface_mismatch_ignore | `bool` | `false` | none | Reserved compatibility flag in current runtime revision. |
| unknown_dc_log_path | `String \| null` | `"unknown-dc.txt"` | — | File path for unknown-DC request logging (`null` disables file path). |
| unknown_dc_file_log_enabled | `bool` | `false` | — | Enables unknown-DC file logging. |
| log_level | `"debug" \| "verbose" \| "normal" \| "silent"` | `"normal"` | — | Runtime logging verbosity. |
| disable_colors | `bool` | `false` | — | Disables ANSI colors in logs. |
| me_socks_kdf_policy | `"strict" \| "compat"` | `"strict"` | — | SOCKS-bound KDF fallback policy for ME handshake. |
| me_route_backpressure_base_timeout_ms | `u64` | `25` | Must be `> 0`. | Base backpressure timeout for route-channel send (ms). |
| me_route_backpressure_high_timeout_ms | `u64` | `120` | Must be `>= me_route_backpressure_base_timeout_ms`. | High backpressure timeout when queue occupancy exceeds watermark (ms). |
| me_route_backpressure_high_watermark_pct | `u8` | `80` | `1..=100`. | Queue occupancy threshold (%) for high timeout mode. |
| me_health_interval_ms_unhealthy | `u64` | `1000` | Must be `> 0`. | Health monitor interval while writer coverage is degraded (ms). |
| me_health_interval_ms_healthy | `u64` | `3000` | Must be `> 0`. | Health monitor interval while writer coverage is healthy (ms). |
| me_admission_poll_ms | `u64` | `1000` | Must be `> 0`. | Poll interval for conditional-admission checks (ms). |
| me_warn_rate_limit_ms | `u64` | `5000` | Must be `> 0`. | Cooldown for repetitive ME warning logs (ms). |
| me_route_no_writer_mode | `"async_recovery_failfast" \| "inline_recovery_legacy" \| "hybrid_async_persistent"` | `"hybrid_async_persistent"` | — | Route behavior when no writer is immediately available. |
| me_route_no_writer_wait_ms | `u64` | `250` | `10..=5000`. | Max wait in async-recovery failfast mode (ms). |
| me_route_inline_recovery_attempts | `u32` | `3` | Must be `> 0`. | Inline recovery attempts in legacy mode. |
| me_route_inline_recovery_wait_ms | `u64` | `3000` | `10..=30000`. | Max inline recovery wait in legacy mode (ms). |
| fast_mode_min_tls_record | `usize` | `0` | — | Minimum TLS record size when fast-mode coalescing is enabled (`0` disables). |
| update_every | `u64 \| null` | `300` | If set: must be `> 0`; if `null`: legacy fallback path is used. | Unified refresh interval for ME config and proxy-secret updater tasks. |
| me_reinit_every_secs | `u64` | `900` | Must be `> 0`. | Periodic interval for zero-downtime ME reinit cycle. |
| me_hardswap_warmup_delay_min_ms | `u64` | `1000` | Must be `<= me_hardswap_warmup_delay_max_ms`. | Lower bound for hardswap warmup dial spacing. |
| me_hardswap_warmup_delay_max_ms | `u64` | `2000` | Must be `> 0`. | Upper bound for hardswap warmup dial spacing. |
| me_hardswap_warmup_extra_passes | `u8` | `3` | Must be within `[0, 10]`. | Additional warmup passes after the base pass in one hardswap cycle. |
| me_hardswap_warmup_pass_backoff_base_ms | `u64` | `500` | Must be `> 0`. | Base backoff between extra hardswap warmup passes. |
| me_config_stable_snapshots | `u8` | `2` | Must be `> 0`. | Number of identical ME config snapshots required before apply. |
| me_config_apply_cooldown_secs | `u64` | `300` | none | Cooldown between applied ME endpoint-map updates. |
| me_snapshot_require_http_2xx | `bool` | `true` | — | Requires 2xx HTTP responses for applying config snapshots. |
| me_snapshot_reject_empty_map | `bool` | `true` | — | Rejects empty config snapshots. |
| me_snapshot_min_proxy_for_lines | `u32` | `1` | Must be `> 0`. | Minimum parsed `proxy_for` rows required to accept snapshot. |
| proxy_secret_stable_snapshots | `u8` | `2` | Must be `> 0`. | Number of identical proxy-secret snapshots required before rotation. |
| proxy_secret_rotate_runtime | `bool` | `true` | none | Enables runtime proxy-secret rotation from updater snapshots. |
| me_secret_atomic_snapshot | `bool` | `true` | — | Keeps selector and secret bytes from the same snapshot atomically. |
| proxy_secret_len_max | `usize` | `256` | Must be within `[32, 4096]`. | Upper length limit for accepted proxy-secret bytes. |
| me_pool_drain_ttl_secs | `u64` | `90` | none | Time window where stale writers remain fallback-eligible after map change. |
| me_pool_drain_threshold | `u64` | `128` | — | Max draining stale writers before batch force-close (`0` disables threshold cleanup). |
| me_pool_drain_soft_evict_enabled | `bool` | `true` | — | Enables gradual soft-eviction of stale writers during drain/reinit instead of immediate hard close. |
| me_pool_drain_soft_evict_grace_secs | `u64` | `30` | `0..=3600`. | Grace period before stale writers become soft-evict candidates. |
| me_pool_drain_soft_evict_per_writer | `u8` | `1` | `1..=16`. | Maximum stale routes soft-evicted per writer in one eviction pass. |
| me_pool_drain_soft_evict_budget_per_core | `u16` | `8` | `1..=64`. | Per-core budget limiting aggregate soft-eviction work per pass. |
| me_pool_drain_soft_evict_cooldown_ms | `u64` | `5000` | Must be `> 0`. | Cooldown between consecutive soft-eviction passes (ms). |
| me_bind_stale_mode | `"never" \| "ttl" \| "always"` | `"ttl"` | — | Policy for new binds on stale draining writers. |
| me_bind_stale_ttl_secs | `u64` | `90` | — | TTL for stale bind allowance when stale mode is `ttl`. |
| me_pool_min_fresh_ratio | `f32` | `0.8` | Must be within `[0.0, 1.0]`. | Minimum fresh desired-DC coverage ratio before stale writers are drained. |
| me_reinit_drain_timeout_secs | `u64` | `120` | `0` disables force-close; if `> 0` and `< me_pool_drain_ttl_secs`, runtime bumps it to TTL. | Force-close timeout for draining stale writers (`0` keeps indefinite draining). |
| proxy_secret_auto_reload_secs | `u64` | `3600` | Deprecated. Use `general.update_every`. | Deprecated legacy secret reload interval (fallback when `update_every` is not set). |
| proxy_config_auto_reload_secs | `u64` | `3600` | Deprecated. Use `general.update_every`. | Deprecated legacy config reload interval (fallback when `update_every` is not set). |
| me_reinit_singleflight | `bool` | `true` | — | Serializes ME reinit cycles across trigger sources. |
| me_reinit_trigger_channel | `usize` | `64` | Must be `> 0`. | Trigger queue capacity for reinit scheduler. |
| me_reinit_coalesce_window_ms | `u64` | `200` | — | Trigger coalescing window before starting reinit (ms). |
| me_deterministic_writer_sort | `bool` | `true` | — | Enables deterministic candidate sort for writer binding path. |
| me_writer_pick_mode | `"sorted_rr" \| "p2c"` | `"p2c"` | — | Writer selection mode for route bind path. |
| me_writer_pick_sample_size | `u8` | `3` | `2..=4`. | Number of candidates sampled by picker in `p2c` mode. |
| ntp_check | `bool` | `true` | — | Enables NTP drift check at startup. |
| ntp_servers | `String[]` | `["pool.ntp.org"]` | — | NTP servers used for drift check. |
| auto_degradation_enabled | `bool` | `true` | none | Reserved compatibility flag in current runtime revision. |
| degradation_min_unavailable_dc_groups | `u8` | `2` | none | Reserved compatibility threshold in current runtime revision. |

## [general.modes]

| Parameter | Type | Default | Constraints / validation | Description |
|---|---|---|---|---|
| classic | `bool` | `false` | — | Enables classic MTProxy mode. |
| secure | `bool` | `false` | — | Enables secure mode. |
| tls | `bool` | `true` | — | Enables TLS mode. |

## [general.links]

| Parameter | Type | Default | Constraints / validation | Description |
|---|---|---|---|---|
| show | `"*" \| String[]` | `"*"` | — | Selects users whose tg:// links are shown at startup. |
| public_host | `String \| null` | `null` | — | Public hostname/IP override for generated tg:// links. |
| public_port | `u16 \| null` | `null` | — | Public port override for generated tg:// links. |

## [general.telemetry]

| Parameter | Type | Default | Constraints / validation | Description |
|---|---|---|---|---|
| core_enabled | `bool` | `true` | — | Enables core hot-path telemetry counters. |
| user_enabled | `bool` | `true` | — | Enables per-user telemetry counters. |
| me_level | `"silent" \| "normal" \| "debug"` | `"normal"` | — | Middle-End telemetry verbosity level. |

## [network]

| Parameter | Type | Default | Constraints / validation | Description |
|---|---|---|---|---|
| ipv4 | `bool` | `true` | — | Enables IPv4 networking. |
| ipv6 | `bool` | `false` | — | Enables/disables IPv6 when set |
| prefer | `u8` | `4` | Must be `4` or `6`. | Preferred IP family for selection (`4` or `6`). |
| multipath | `bool` | `false` | — | Enables multipath behavior where supported. |
| stun_use | `bool` | `true` | none | Global STUN switch; when `false`, STUN probing path is disabled. |
| stun_servers | `String[]` | Built-in STUN list (13 hosts) | Deduplicated; empty values are removed. | Primary STUN server list for NAT/public endpoint discovery. |
| stun_tcp_fallback | `bool` | `true` | none | Enables TCP fallback for STUN when UDP path is blocked. |
| http_ip_detect_urls | `String[]` | `["https://ifconfig.me/ip", "https://api.ipify.org"]` | none | HTTP fallback endpoints for public IP detection when STUN is unavailable. |
| cache_public_ip_path | `String` | `"cache/public_ip.txt"` | — | File path for caching detected public IP. |
| dns_overrides | `String[]` | `[]` | Must match `host:port:ip`; IPv6 must be bracketed. | Runtime DNS overrides in `host:port:ip` format. |

## [server]

| Parameter | Type | Default | Constraints / validation | Description |
|---|---|---|---|---|
| port | `u16` | `443` | — | Main proxy listen port. |
| listen_addr_ipv4 | `String \| null` | `"0.0.0.0"` | — | IPv4 bind address for TCP listener. |
| listen_addr_ipv6 | `String \| null` | `"::"` | — | IPv6 bind address for TCP listener. |
| listen_unix_sock | `String \| null` | `null` | — | Unix socket path for listener. |
| listen_unix_sock_perm | `String \| null` | `null` | — | Unix socket permissions in octal string (e.g., `"0666"`). |
| listen_tcp | `bool \| null` | `null` (auto) | — | Explicit TCP listener enable/disable override. |
| proxy_protocol | `bool` | `false` | — | Enables HAProxy PROXY protocol parsing on incoming client connections. |
| proxy_protocol_header_timeout_ms | `u64` | `500` | Must be `> 0`. | Timeout for PROXY protocol header read/parse (ms). |
| metrics_port | `u16 \| null` | `null` | — | Metrics endpoint port (enables metrics listener). |
| metrics_listen | `String \| null` | `null` | — | Full metrics bind address (`IP:PORT`), overrides `metrics_port`. |
| metrics_whitelist | `IpNetwork[]` | `["127.0.0.1/32", "::1/128"]` | — | CIDR whitelist for metrics endpoint access. |
| max_connections | `u32` | `10000` | — | Max concurrent client connections (`0` = unlimited). |

## [server.api]

| Parameter | Type | Default | Constraints / validation | Description |
|---|---|---|---|---|
| enabled | `bool` | `true` | — | Enables control-plane REST API. |
| listen | `String` | `"0.0.0.0:9091"` | Must be valid `IP:PORT`. | API bind address in `IP:PORT` format. |
| whitelist | `IpNetwork[]` | `["127.0.0.0/8"]` | — | CIDR whitelist allowed to access API. |
| auth_header | `String` | `""` | — | Exact expected `Authorization` header value (empty = disabled). |
| request_body_limit_bytes | `usize` | `65536` | Must be `> 0`. | Maximum accepted HTTP request body size. |
| minimal_runtime_enabled | `bool` | `true` | — | Enables minimal runtime snapshots endpoint logic. |
| minimal_runtime_cache_ttl_ms | `u64` | `1000` | `0..=60000`. | Cache TTL for minimal runtime snapshots (ms; `0` disables cache). |
| runtime_edge_enabled | `bool` | `false` | — | Enables runtime edge endpoints. |
| runtime_edge_cache_ttl_ms | `u64` | `1000` | `0..=60000`. | Cache TTL for runtime edge aggregation payloads (ms). |
| runtime_edge_top_n | `usize` | `10` | `1..=1000`. | Top-N size for edge connection leaderboard. |
| runtime_edge_events_capacity | `usize` | `256` | `16..=4096`. | Ring-buffer capacity for runtime edge events. |
| read_only | `bool` | `false` | — | Rejects mutating API endpoints when enabled. |

## [[server.listeners]]

| Parameter | Type | Default | Constraints / validation | Description |
|---|---|---|---|---|
| ip | `IpAddr` | — | — | Listener bind IP. |
| announce | `String \| null` | — | — | Public IP/domain announced in proxy links (priority over `announce_ip`). |
| announce_ip | `IpAddr \| null` | — | — | Deprecated legacy announce IP (migrated to `announce` if needed). |
| proxy_protocol | `bool \| null` | `null` | — | Per-listener override for PROXY protocol enable flag. |
| reuse_allow | `bool` | `false` | — | Enables `SO_REUSEPORT` for multi-instance bind sharing. |

## [timeouts]

| Parameter | Type | Default | Constraints / validation | Description |
|---|---|---|---|---|
| client_handshake | `u64` | `30` | — | Client handshake timeout. |
| tg_connect | `u64` | `10` | — | Upstream Telegram connect timeout. |
| client_keepalive | `u64` | `15` | — | Client keepalive timeout. |
| client_ack | `u64` | `90` | — | Client ACK timeout. |
| me_one_retry | `u8` | `12` | none | Fast reconnect attempts budget for single-endpoint DC scenarios. |
| me_one_timeout_ms | `u64` | `1200` | none | Timeout in milliseconds for each quick single-endpoint reconnect attempt. |

## [censorship]

| Parameter | Type | Default | Constraints / validation | Description |
|---|---|---|---|---|
| tls_domain | `String` | `"petrovich.ru"` | — | Primary TLS domain used in fake TLS handshake profile. |
| tls_domains | `String[]` | `[]` | — | Additional TLS domains for generating multiple links. |
| mask | `bool` | `true` | — | Enables masking/fronting relay mode. |
| mask_host | `String \| null` | `null` | — | Upstream mask host for TLS fronting relay. |
| mask_port | `u16` | `443` | — | Upstream mask port for TLS fronting relay. |
| mask_unix_sock | `String \| null` | `null` | — | Unix socket path for mask backend instead of TCP host/port. |
| fake_cert_len | `usize` | `2048` | — | Length of synthetic certificate payload when emulation data is unavailable. |
| tls_emulation | `bool` | `true` | — | Enables certificate/TLS behavior emulation from cached real fronts. |
| tls_front_dir | `String` | `"tlsfront"` | — | Directory path for TLS front cache storage. |
| server_hello_delay_min_ms | `u64` | `0` | — | Minimum server_hello delay for anti-fingerprint behavior (ms). |
| server_hello_delay_max_ms | `u64` | `0` | — | Maximum server_hello delay for anti-fingerprint behavior (ms). |
| tls_new_session_tickets | `u8` | `0` | — | Number of `NewSessionTicket` messages to emit after handshake. |
| tls_full_cert_ttl_secs | `u64` | `90` | — | TTL for sending full cert payload per (domain, client IP) tuple. |
| alpn_enforce | `bool` | `true` | — | Enforces ALPN echo behavior based on client preference. |
| mask_proxy_protocol | `u8` | `0` | — | PROXY protocol mode for mask backend (`0` disabled, `1` v1, `2` v2). |
| mask_shape_hardening | `bool` | `true` | — | Enables client->mask shape-channel hardening by applying controlled tail padding to bucket boundaries on mask relay shutdown. |
| mask_shape_bucket_floor_bytes | `usize` | `512` | Must be `> 0`; should be `<= mask_shape_bucket_cap_bytes`. | Minimum bucket size used by shape-channel hardening. |
| mask_shape_bucket_cap_bytes | `usize` | `4096` | Must be `>= mask_shape_bucket_floor_bytes`. | Maximum bucket size used by shape-channel hardening; traffic above cap is not padded further. |
| mask_shape_above_cap_blur | `bool` | `false` | Requires `mask_shape_hardening = true`; requires `mask_shape_above_cap_blur_max_bytes > 0`. | Adds bounded randomized tail bytes even when forwarded size already exceeds cap. |
| mask_shape_above_cap_blur_max_bytes | `usize` | `512` | Must be `<= 1048576`; must be `> 0` when `mask_shape_above_cap_blur = true`. | Maximum randomized extra bytes appended above cap. |
| mask_timing_normalization_enabled | `bool` | `false` | Requires `mask_timing_normalization_floor_ms > 0`; requires `ceiling >= floor`. | Enables timing envelope normalization on masking outcomes. |
| mask_timing_normalization_floor_ms | `u64` | `0` | Must be `> 0` when timing normalization is enabled; must be `<= ceiling`. | Lower bound (ms) for masking outcome normalization target. |
| mask_timing_normalization_ceiling_ms | `u64` | `0` | Must be `>= floor`; must be `<= 60000`. | Upper bound (ms) for masking outcome normalization target. |

### Shape-channel hardening notes (`[censorship]`)

These parameters are designed to reduce one specific fingerprint source during masking: the exact number of bytes sent from proxy to `mask_host` for invalid or probing traffic.

Without hardening, a censor can often correlate probe input length with backend-observed length very precisely (for example: `5 + body_sent` on early TLS reject paths). That creates a length-based classifier signal.

When `mask_shape_hardening = true`, Telemt pads the **client->mask** stream tail to a bucket boundary at relay shutdown:

- Total bytes sent to mask are first measured.
- A bucket is selected using powers of two starting from `mask_shape_bucket_floor_bytes`.
- Padding is added only if total bytes are below `mask_shape_bucket_cap_bytes`.
- If bytes already exceed cap, no extra padding is added.

This means multiple nearby probe sizes collapse into the same backend-observed size class, making active classification harder.

Practical trade-offs:

- Better anti-fingerprinting on size/shape channel.
- Slightly higher egress overhead for small probes due to padding.
- Behavior is intentionally conservative and enabled by default.

Recommended starting profile:

- `mask_shape_hardening = true` (default)
- `mask_shape_bucket_floor_bytes = 512`
- `mask_shape_bucket_cap_bytes = 4096`

### Above-cap blur notes (`[censorship]`)

`mask_shape_above_cap_blur` adds a second-stage blur for very large probes that are already above `mask_shape_bucket_cap_bytes`.

- A random tail in `[0, mask_shape_above_cap_blur_max_bytes]` is appended.
- This reduces exact-size leakage above cap at bounded overhead.
- Keep `mask_shape_above_cap_blur_max_bytes` conservative to avoid unnecessary egress growth.

### Timing normalization envelope notes (`[censorship]`)

`mask_timing_normalization_enabled` smooths timing differences between masking outcomes by applying a target duration envelope.

- A random target is selected in `[mask_timing_normalization_floor_ms, mask_timing_normalization_ceiling_ms]`.
- Fast paths are delayed up to the selected target.
- Slow paths are not forced to finish by the ceiling (the envelope is best-effort shaping, not truncation).

Recommended starting profile for timing shaping:

- `mask_timing_normalization_enabled = true`
- `mask_timing_normalization_floor_ms = 180`
- `mask_timing_normalization_ceiling_ms = 320`

If your backend or network is very bandwidth-constrained, reduce cap first. If probes are still too distinguishable in your environment, increase floor gradually.

## [access]

| Parameter | Type | Default | Constraints / validation | TOML shape example | Description |
|---|---|---|---|---|---|
| users | `Map<String, String>` | `{"default": "000…000"}` | Secret must be 32 hex characters. | `[access.users]`<br>`user = "32-hex secret"`<br>`user2 = "32-hex secret"` | User credentials map used for client authentication. |
| user_ad_tags | `Map<String, String>` | `{}` | Every value must be exactly 32 hex characters. | `[access.user_ad_tags]`<br>`user = "32-hex ad_tag"` | Per-user ad tags used as override over `general.ad_tag`. |
| user_max_tcp_conns | `Map<String, usize>` | `{}` | — | `[access.user_max_tcp_conns]`<br>`user = 500` | Per-user maximum concurrent TCP connections. |
| user_expirations | `Map<String, DateTime<Utc>>` | `{}` | Timestamp must be valid RFC3339/ISO-8601 datetime. | `[access.user_expirations]`<br>`user = "2026-12-31T23:59:59Z"` | Per-user account expiration timestamps. |
| user_data_quota | `Map<String, u64>` | `{}` | — | `[access.user_data_quota]`<br>`user = 1073741824` | Per-user traffic quota in bytes. |
| user_max_unique_ips | `Map<String, usize>` | `{}` | — | `[access.user_max_unique_ips]`<br>`user = 16` | Per-user unique source IP limits. |
| user_max_unique_ips_global_each | `usize` | `0` | — | `user_max_unique_ips_global_each = 0` | Global fallback used when `[access.user_max_unique_ips]` has no per-user override. |
| user_max_unique_ips_mode | `"active_window" \| "time_window" \| "combined"` | `"active_window"` | — | `user_max_unique_ips_mode = "active_window"` | Unique source IP limit accounting mode. |
| user_max_unique_ips_window_secs | `u64` | `30` | Must be `> 0`. | `user_max_unique_ips_window_secs = 30` | Window size (seconds) used by unique-IP accounting modes that use time windows. |
| replay_check_len | `usize` | `65536` | — | `replay_check_len = 65536` | Replay-protection storage length. |
| replay_window_secs | `u64` | `1800` | — | `replay_window_secs = 1800` | Replay-protection window in seconds. |
| ignore_time_skew | `bool` | `false` | — | `ignore_time_skew = false` | Disables client/server timestamp skew checks in replay validation when enabled. |

## [[upstreams]]

| Parameter | Type | Default | Constraints / validation | Description |
|---|---|---|---|---|
| type | `"direct" \| "socks4" \| "socks5"` | — | Required field. | Upstream transport type selector. |
| weight | `u16` | `1` | none | Base weight used by weighted-random upstream selection. |
| enabled | `bool` | `true` | none | Disabled entries are excluded from upstream selection at runtime. |
| scopes | `String` | `""` | none | Comma-separated scope tags used for request-level upstream filtering. |
| interface | `String \| null` | `null` | Optional; type-specific runtime rules apply. | Optional outbound interface/local bind hint (supported with type-specific rules). |
| bind_addresses | `String[] \| null` | `null` | Applies to `type = "direct"`. | Optional explicit local source bind addresses for `type = "direct"`. |
| address | `String` | — | Required for `type = "socks4"` and `type = "socks5"`. | SOCKS server endpoint (`host:port` or `ip:port`) for SOCKS upstream types. |
| user_id | `String \| null` | `null` | Only for `type = "socks4"`. | SOCKS4 CONNECT user ID (`type = "socks4"` only). |
| username | `String \| null` | `null` | Only for `type = "socks5"`. | SOCKS5 username (`type = "socks5"` only). |
| password | `String \| null` | `null` | Only for `type = "socks5"`. | SOCKS5 password (`type = "socks5"` only). |
