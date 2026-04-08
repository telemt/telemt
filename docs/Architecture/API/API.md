# Telemt Control API

## Purpose
Control-plane HTTP API for runtime visibility and user/config management.
Data-plane MTProto traffic is out of scope.

## Runtime Configuration
API runtime is configured in `[server.api]`.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | `bool` | `true` | Enables REST API listener. |
| `listen` | `string` (`IP:PORT`) | `0.0.0.0:9091` | API bind address. |
| `whitelist` | `CIDR[]` | `127.0.0.0/8` | Source IP allowlist. Empty list means allow all. |
| `auth_header` | `string` | `""` | Exact value for `Authorization` header. Empty disables header auth. |
| `request_body_limit_bytes` | `usize` | `65536` | Maximum request body size. Must be `> 0`. |
| `minimal_runtime_enabled` | `bool` | `true` | Enables runtime snapshot endpoints requiring ME pool read-lock aggregation. |
| `minimal_runtime_cache_ttl_ms` | `u64` | `1000` | Cache TTL for minimal snapshots. `0` disables cache; valid range is `[0, 60000]`. |
| `runtime_edge_enabled` | `bool` | `false` | Enables runtime edge endpoints with cached aggregation payloads. |
| `runtime_edge_cache_ttl_ms` | `u64` | `1000` | Cache TTL for runtime edge summary payloads. `0` disables cache. |
| `runtime_edge_top_n` | `usize` | `10` | Top-N rows for runtime edge leaderboard payloads. |
| `runtime_edge_events_capacity` | `usize` | `256` | Ring-buffer size for `/v1/runtime/events/recent`. |
| `read_only` | `bool` | `false` | Disables mutating endpoints. |

`server.admin_api` is accepted as an alias for backward compatibility.

Runtime validation for API config:
- `server.api.listen` must be a valid `IP:PORT`.
- `server.api.request_body_limit_bytes` must be `> 0`.
- `server.api.minimal_runtime_cache_ttl_ms` must be within `[0, 60000]`.
- `server.api.runtime_edge_cache_ttl_ms` must be within `[0, 60000]`.
- `server.api.runtime_edge_top_n` must be within `[1, 1000]`.
- `server.api.runtime_edge_events_capacity` must be within `[16, 4096]`.

## Protocol Contract

| Item | Value |
| --- | --- |
| Transport | HTTP/1.1 |
| Content type | `application/json; charset=utf-8` |
| Prefix | `/v1` |
| Optimistic concurrency | `If-Match: <revision>` on mutating requests (optional) |
| Revision format | SHA-256 hex of current `config.toml` content |

### Success Envelope
```json
{
  "ok": true,
  "data": {},
  "revision": "sha256-hex"
}
```

### Error Envelope
```json
{
  "ok": false,
  "error": {
    "code": "machine_code",
    "message": "human-readable"
  },
  "request_id": 1
}
```

## Request Processing Order

Requests are processed in this order:
1. `api_enabled` gate (`503 api_disabled` if disabled).
2. Source IP whitelist gate (`403 forbidden`).
3. `Authorization` header gate when configured (`401 unauthorized`).
4. Route and method matching (`404 not_found` or `405 method_not_allowed`).
5. `read_only` gate for mutating routes (`403 read_only`).
6. Request body read/limit/JSON decode (`413 payload_too_large`, `400 bad_request`).
7. Business validation and config write path.

Notes:
- Whitelist is evaluated against the direct TCP peer IP (`SocketAddr::ip`), without `X-Forwarded-For` support.
- `Authorization` check is exact string equality against configured `auth_header`.

## Endpoint Matrix

| Method | Path | Body | Success | `data` contract |
| --- | --- | --- | --- | --- |
| `GET` | `/v1/health` | none | `200` | `HealthData` |
| `GET` | `/v1/system/info` | none | `200` | `SystemInfoData` |
| `GET` | `/v1/runtime/gates` | none | `200` | `RuntimeGatesData` |
| `GET` | `/v1/runtime/initialization` | none | `200` | `RuntimeInitializationData` |
| `GET` | `/v1/limits/effective` | none | `200` | `EffectiveLimitsData` |
| `GET` | `/v1/security/posture` | none | `200` | `SecurityPostureData` |
| `GET` | `/v1/security/whitelist` | none | `200` | `SecurityWhitelistData` |
| `GET` | `/v1/stats/summary` | none | `200` | `SummaryData` |
| `GET` | `/v1/stats/zero/all` | none | `200` | `ZeroAllData` |
| `GET` | `/v1/stats/upstreams` | none | `200` | `UpstreamsData` |
| `GET` | `/v1/stats/minimal/all` | none | `200` | `MinimalAllData` |
| `GET` | `/v1/stats/me-writers` | none | `200` | `MeWritersData` |
| `GET` | `/v1/stats/dcs` | none | `200` | `DcStatusData` |
| `GET` | `/v1/runtime/me_pool_state` | none | `200` | `RuntimeMePoolStateData` |
| `GET` | `/v1/runtime/me_quality` | none | `200` | `RuntimeMeQualityData` |
| `GET` | `/v1/runtime/upstream_quality` | none | `200` | `RuntimeUpstreamQualityData` |
| `GET` | `/v1/runtime/nat_stun` | none | `200` | `RuntimeNatStunData` |
| `GET` | `/v1/runtime/me-selftest` | none | `200` | `RuntimeMeSelftestData` |
| `GET` | `/v1/runtime/connections/summary` | none | `200` | `RuntimeEdgeConnectionsSummaryData` |
| `GET` | `/v1/runtime/events/recent` | none | `200` | `RuntimeEdgeEventsData` |
| `GET` | `/v1/stats/users` | none | `200` | `UserInfo[]` |
| `GET` | `/v1/users` | none | `200` | `UserInfo[]` |
| `POST` | `/v1/users` | `CreateUserRequest` | `201` | `CreateUserResponse` |
| `GET` | `/v1/users/{username}` | none | `200` | `UserInfo` |
| `PATCH` | `/v1/users/{username}` | `PatchUserRequest` | `200` | `UserInfo` |
| `DELETE` | `/v1/users/{username}` | none | `200` | `string` (deleted username) |
| `POST` | `/v1/users/{username}/rotate-secret` | `RotateSecretRequest` or empty body | `404` | `ErrorResponse` (`not_found`, current runtime behavior) |

## Common Error Codes

| HTTP | `error.code` | Trigger |
| --- | --- | --- |
| `400` | `bad_request` | Invalid JSON, validation failures, malformed request body. |
| `401` | `unauthorized` | Missing/invalid `Authorization` when `auth_header` is configured. |
| `403` | `forbidden` | Source IP is not allowed by whitelist. |
| `403` | `read_only` | Mutating endpoint called while `read_only=true`. |
| `404` | `not_found` | Unknown route, unknown user, or unsupported sub-route (including current `rotate-secret` route). |
| `405` | `method_not_allowed` | Unsupported method for `/v1/users/{username}` route shape. |
| `409` | `revision_conflict` | `If-Match` revision mismatch. |
| `409` | `user_exists` | User already exists on create. |
| `409` | `last_user_forbidden` | Attempt to delete last configured user. |
| `413` | `payload_too_large` | Body exceeds `request_body_limit_bytes`. |
| `500` | `internal_error` | Internal error (I/O, serialization, config load/save). |
| `503` | `api_disabled` | API disabled in config. |

## Routing and Method Edge Cases

| Case | Behavior |
| --- | --- |
| Path matching | Exact match on `req.uri().path()`. Query string does not affect route matching. |
| Trailing slash | Not normalized. Example: `/v1/users/` is `404`. |
| Username route with extra slash | `/v1/users/{username}/...` is not treated as user route and returns `404`. |
| `PUT /v1/users/{username}` | `405 method_not_allowed`. |
| `POST /v1/users/{username}` | `404 not_found`. |
| `POST /v1/users/{username}/rotate-secret` | `404 not_found` in current release due route matcher limitation. |

## Body and JSON Semantics

- Request body is read only for mutating routes that define a body contract.
- Body size limit is enforced during streaming read (`413 payload_too_large`).
- Invalid transport body frame returns `400 bad_request` (`Invalid request body`).
- Invalid JSON returns `400 bad_request` (`Invalid JSON body`).
- `Content-Type` is not required for JSON parsing.
- Unknown JSON fields are ignored by deserialization.
- `PATCH` updates only provided fields and does not support explicit clearing of optional fields.
- `If-Match` supports both quoted and unquoted values; surrounding whitespace is trimmed.

## Query Parameters

| Endpoint | Query | Behavior |
| --- | --- | --- |
| `GET /v1/runtime/events/recent` | `limit=<usize>` | Optional. Invalid/missing value falls back to default `50`. Effective value is clamped to `[1, 1000]` and additionally bounded by ring-buffer capacity. |

## Request Contracts

### `CreateUserRequest`
| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `username` | `string` | yes | `[A-Za-z0-9_.-]`, length `1..64`. |
| `secret` | `string` | no | Exactly 32 hex chars. If missing, generated automatically. |
| `user_ad_tag` | `string` | no | Exactly 32 hex chars. |
| `max_tcp_conns` | `usize` | no | Per-user concurrent TCP limit. |
| `expiration_rfc3339` | `string` | no | RFC3339 expiration timestamp. |
| `data_quota_bytes` | `u64` | no | Per-user traffic quota. |
| `max_unique_ips` | `usize` | no | Per-user unique source IP limit. |

### `PatchUserRequest`
| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `secret` | `string` | no | Exactly 32 hex chars. |
| `user_ad_tag` | `string` | no | Exactly 32 hex chars. |
| `max_tcp_conns` | `usize` | no | Per-user concurrent TCP limit. |
| `expiration_rfc3339` | `string` | no | RFC3339 expiration timestamp. |
| `data_quota_bytes` | `u64` | no | Per-user traffic quota. |
| `max_unique_ips` | `usize` | no | Per-user unique source IP limit. |

### `RotateSecretRequest`
| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `secret` | `string` | no | Exactly 32 hex chars. If missing, generated automatically. |

Note: the request contract is defined, but the corresponding route currently returns `404` (see routing edge cases).

## Response Data Contracts

### `HealthData`
| Field | Type | Description |
| --- | --- | --- |
| `status` | `string` | Always `"ok"`. |
| `read_only` | `bool` | Mirrors current API `read_only` mode. |

### `SummaryData`
| Field | Type | Description |
| --- | --- | --- |
| `uptime_seconds` | `f64` | Process uptime in seconds. |
| `connections_total` | `u64` | Total accepted client connections. |
| `connections_bad_total` | `u64` | Failed/invalid client connections. |
| `handshake_timeouts_total` | `u64` | Handshake timeout count. |
| `configured_users` | `usize` | Number of configured users in config. |

### `SystemInfoData`
| Field | Type | Description |
| --- | --- | --- |
| `version` | `string` | Binary version (`CARGO_PKG_VERSION`). |
| `target_arch` | `string` | Target architecture (`std::env::consts::ARCH`). |
| `target_os` | `string` | Target OS (`std::env::consts::OS`). |
| `build_profile` | `string` | Build profile (`PROFILE` env when available). |
| `git_commit` | `string?` | Optional commit hash from build env metadata. |
| `build_time_utc` | `string?` | Optional build timestamp from build env metadata. |
| `rustc_version` | `string?` | Optional compiler version from build env metadata. |
| `process_started_at_epoch_secs` | `u64` | Process start time as Unix epoch seconds. |
| `uptime_seconds` | `f64` | Process uptime in seconds. |
| `config_path` | `string` | Active config file path used by runtime. |
| `config_hash` | `string` | SHA-256 hash of current config content (same value as envelope `revision`). |
| `config_reload_count` | `u64` | Number of successfully observed config updates since process start. |
| `last_config_reload_epoch_secs` | `u64?` | Unix epoch seconds of the latest observed config reload; null/absent before first reload. |

### `RuntimeGatesData`
| Field | Type | Description |
| --- | --- | --- |
| `accepting_new_connections` | `bool` | Current admission-gate state for new listener accepts. |
| `conditional_cast_enabled` | `bool` | Whether conditional ME admission logic is enabled (`general.use_middle_proxy`). |
| `me_runtime_ready` | `bool` | Current ME runtime readiness status used for conditional gate decisions. |
| `me2dc_fallback_enabled` | `bool` | Whether ME -> direct fallback is enabled. |
| `use_middle_proxy` | `bool` | Current transport mode preference. |
| `startup_status` | `string` | Startup status (`pending`, `initializing`, `ready`, `failed`, `skipped`). |
| `startup_stage` | `string` | Current startup stage identifier. |
| `startup_progress_pct` | `f64` | Startup progress percentage (`0..100`). |

### `RuntimeInitializationData`
| Field | Type | Description |
| --- | --- | --- |
| `status` | `string` | Startup status (`pending`, `initializing`, `ready`, `failed`, `skipped`). |
| `degraded` | `bool` | Whether runtime is currently in degraded mode. |
| `current_stage` | `string` | Current startup stage identifier. |
| `progress_pct` | `f64` | Overall startup progress percentage (`0..100`). |
| `started_at_epoch_secs` | `u64` | Process start timestamp (Unix seconds). |
| `ready_at_epoch_secs` | `u64?` | Timestamp when startup reached ready state; absent until ready. |
| `total_elapsed_ms` | `u64` | Elapsed startup duration in milliseconds. |
| `transport_mode` | `string` | Startup transport mode (`middle_proxy` or `direct`). |
| `me` | `RuntimeInitializationMeData` | ME startup substate snapshot. |
| `components` | `RuntimeInitializationComponentData[]` | Per-component startup timeline and status. |

#### `RuntimeInitializationMeData`
| Field | Type | Description |
| --- | --- | --- |
| `status` | `string` | ME startup status (`pending`, `initializing`, `ready`, `failed`, `skipped`). |
| `current_stage` | `string` | Current ME startup stage identifier. |
| `progress_pct` | `f64` | ME startup progress percentage (`0..100`). |
| `init_attempt` | `u32` | Current ME init attempt counter. |
| `retry_limit` | `string` | Retry limit (`"unlimited"` or numeric string). |
| `last_error` | `string?` | Last ME initialization error text when present. |

#### `RuntimeInitializationComponentData`
| Field | Type | Description |
| --- | --- | --- |
| `id` | `string` | Startup component identifier. |
| `title` | `string` | Human-readable component title. |
| `status` | `string` | Component status (`pending`, `running`, `ready`, `failed`, `skipped`). |
| `started_at_epoch_ms` | `u64?` | Component start timestamp in Unix milliseconds. |
| `finished_at_epoch_ms` | `u64?` | Component finish timestamp in Unix milliseconds. |
| `duration_ms` | `u64?` | Component duration in milliseconds. |
| `attempts` | `u32` | Attempt counter for this component. |
| `details` | `string?` | Optional short status details text. |

### `EffectiveLimitsData`
| Field | Type | Description |
| --- | --- | --- |
| `update_every_secs` | `u64` | Effective unified updater interval. |
| `me_reinit_every_secs` | `u64` | Effective ME periodic reinit interval. |
| `me_pool_force_close_secs` | `u64` | Effective stale-writer force-close timeout. |
| `timeouts` | `EffectiveTimeoutLimits` | Effective timeout policy snapshot. |
| `upstream` | `EffectiveUpstreamLimits` | Effective upstream connect/retry limits. |
| `middle_proxy` | `EffectiveMiddleProxyLimits` | Effective ME pool/floor/reconnect limits. |
| `user_ip_policy` | `EffectiveUserIpPolicyLimits` | Effective unique-IP policy mode/window. |

#### `EffectiveTimeoutLimits`
| Field | Type | Description |
| --- | --- | --- |
| `client_handshake_secs` | `u64` | Client handshake timeout. |
| `tg_connect_secs` | `u64` | Upstream Telegram connect timeout. |
| `client_keepalive_secs` | `u64` | Client keepalive interval. |
| `client_ack_secs` | `u64` | ACK timeout. |
| `me_one_retry` | `u8` | Fast retry count for single-endpoint ME DC. |
| `me_one_timeout_ms` | `u64` | Fast retry timeout per attempt for single-endpoint ME DC. |

#### `EffectiveUpstreamLimits`
| Field | Type | Description |
| --- | --- | --- |
| `connect_retry_attempts` | `u32` | Upstream connect retry attempts. |
| `connect_retry_backoff_ms` | `u64` | Upstream retry backoff delay. |
| `connect_budget_ms` | `u64` | Total connect wall-clock budget across retries. |
| `unhealthy_fail_threshold` | `u32` | Consecutive fail threshold for unhealthy marking. |
| `connect_failfast_hard_errors` | `bool` | Whether hard errors skip additional retries. |

#### `EffectiveMiddleProxyLimits`
| Field | Type | Description |
| --- | --- | --- |
| `floor_mode` | `string` | Effective floor mode (`static` or `adaptive`). |
| `adaptive_floor_idle_secs` | `u64` | Adaptive floor idle threshold. |
| `adaptive_floor_min_writers_single_endpoint` | `u8` | Adaptive floor minimum for single-endpoint DCs. |
| `adaptive_floor_min_writers_multi_endpoint` | `u8` | Adaptive floor minimum for multi-endpoint DCs. |
| `adaptive_floor_recover_grace_secs` | `u64` | Adaptive floor recovery grace period. |
| `adaptive_floor_writers_per_core_total` | `u16` | Target total writers-per-core budget in adaptive mode. |
| `adaptive_floor_cpu_cores_override` | `u16` | Manual CPU core override (`0` means auto-detect). |
| `adaptive_floor_max_extra_writers_single_per_core` | `u16` | Extra per-core adaptive headroom for single-endpoint DCs. |
| `adaptive_floor_max_extra_writers_multi_per_core` | `u16` | Extra per-core adaptive headroom for multi-endpoint DCs. |
| `adaptive_floor_max_active_writers_per_core` | `u16` | Active writer cap per CPU core. |
| `adaptive_floor_max_warm_writers_per_core` | `u16` | Warm writer cap per CPU core. |
| `adaptive_floor_max_active_writers_global` | `u32` | Global active writer cap. |
| `adaptive_floor_max_warm_writers_global` | `u32` | Global warm writer cap. |
| `reconnect_max_concurrent_per_dc` | `u32` | Max concurrent reconnects per DC. |
| `reconnect_backoff_base_ms` | `u64` | Reconnect base backoff. |
| `reconnect_backoff_cap_ms` | `u64` | Reconnect backoff cap. |
| `reconnect_fast_retry_count` | `u32` | Number of fast retries before standard backoff strategy. |
| `writer_pick_mode` | `string` | Writer picker mode (`sorted_rr`, `p2c`). |
| `writer_pick_sample_size` | `u8` | Candidate sample size for `p2c` picker mode. |
| `me2dc_fallback` | `bool` | Effective ME -> direct fallback flag. |

#### `EffectiveUserIpPolicyLimits`
| Field | Type | Description |
| --- | --- | --- |
| `mode` | `string` | Unique-IP policy mode (`active_window`, `time_window`, `combined`). |
| `window_secs` | `u64` | Time window length used by unique-IP policy. |

### `SecurityPostureData`
| Field | Type | Description |
| --- | --- | --- |
| `api_read_only` | `bool` | Current API read-only state. |
| `api_whitelist_enabled` | `bool` | Whether whitelist filtering is active. |
| `api_whitelist_entries` | `usize` | Number of configured whitelist CIDRs. |
| `api_auth_header_enabled` | `bool` | Whether `Authorization` header validation is active. |
| `proxy_protocol_enabled` | `bool` | Global PROXY protocol accept setting. |
| `log_level` | `string` | Effective log level (`debug`, `verbose`, `normal`, `silent`). |
| `telemetry_core_enabled` | `bool` | Core telemetry toggle. |
| `telemetry_user_enabled` | `bool` | Per-user telemetry toggle. |
| `telemetry_me_level` | `string` | ME telemetry level (`silent`, `normal`, `debug`). |

### `SecurityWhitelistData`
| Field | Type | Description |
| --- | --- | --- |
| `generated_at_epoch_secs` | `u64` | Snapshot generation timestamp. |
| `enabled` | `bool` | `true` when whitelist has at least one CIDR entry. |
| `entries_total` | `usize` | Number of whitelist CIDR entries. |
| `entries` | `string[]` | Whitelist CIDR entries as strings. |

### `RuntimeMePoolStateData`
| Field | Type | Description |
| --- | --- | --- |
| `enabled` | `bool` | Runtime payload availability. |
| `reason` | `string?` | `source_unavailable` when ME pool snapshot is unavailable. |
| `generated_at_epoch_secs` | `u64` | Snapshot generation timestamp. |
| `data` | `RuntimeMePoolStatePayload?` | Null when unavailable. |

#### `RuntimeMePoolStatePayload`
| Field | Type | Description |
| --- | --- | --- |
| `generations` | `RuntimeMePoolStateGenerationData` | Active/warm/pending/draining generation snapshot. |
| `hardswap` | `RuntimeMePoolStateHardswapData` | Hardswap state flags. |
| `writers` | `RuntimeMePoolStateWriterData` | Writer total/contour/health counters. |
| `refill` | `RuntimeMePoolStateRefillData` | In-flight refill counters by DC/family. |

#### `RuntimeMePoolStateGenerationData`
| Field | Type | Description |
| --- | --- | --- |
| `active_generation` | `u64` | Active pool generation id. |
| `warm_generation` | `u64` | Warm pool generation id. |
| `pending_hardswap_generation` | `u64` | Pending hardswap generation id (`0` when none). |
| `pending_hardswap_age_secs` | `u64?` | Age of pending hardswap generation in seconds. |
| `draining_generations` | `u64[]` | Distinct generation ids currently draining. |

#### `RuntimeMePoolStateHardswapData`
| Field | Type | Description |
| --- | --- | --- |
| `enabled` | `bool` | Hardswap feature toggle. |
| `pending` | `bool` | `true` when pending generation is non-zero. |

#### `RuntimeMePoolStateWriterData`
| Field | Type | Description |
| --- | --- | --- |
| `total` | `usize` | Total writer rows in snapshot. |
| `alive_non_draining` | `usize` | Alive writers excluding draining ones. |
| `draining` | `usize` | Writers marked draining. |
| `degraded` | `usize` | Non-draining degraded writers. |
| `contour` | `RuntimeMePoolStateWriterContourData` | Counts by contour state. |
| `health` | `RuntimeMePoolStateWriterHealthData` | Counts by health bucket. |

#### `RuntimeMePoolStateWriterContourData`
| Field | Type | Description |
| --- | --- | --- |
| `warm` | `usize` | Writers in warm contour. |
| `active` | `usize` | Writers in active contour. |
| `draining` | `usize` | Writers in draining contour. |

#### `RuntimeMePoolStateWriterHealthData`
| Field | Type | Description |
| --- | --- | --- |
| `healthy` | `usize` | Non-draining non-degraded writers. |
| `degraded` | `usize` | Non-draining degraded writers. |
| `draining` | `usize` | Draining writers. |

#### `RuntimeMePoolStateRefillData`
| Field | Type | Description |
| --- | --- | --- |
| `inflight_endpoints_total` | `usize` | Total in-flight endpoint refill operations. |
| `inflight_dc_total` | `usize` | Number of distinct DC+family keys with refill in flight. |
| `by_dc` | `RuntimeMePoolStateRefillDcData[]` | Per-DC refill rows. |

#### `RuntimeMePoolStateRefillDcData`
| Field | Type | Description |
| --- | --- | --- |
| `dc` | `i16` | Telegram DC id. |
| `family` | `string` | Address family label (`V4`, `V6`). |
| `inflight` | `usize` | In-flight refill operations for this row. |

### `RuntimeMeQualityData`
| Field | Type | Description |
| --- | --- | --- |
| `enabled` | `bool` | Runtime payload availability. |
| `reason` | `string?` | `source_unavailable` when ME pool snapshot is unavailable. |
| `generated_at_epoch_secs` | `u64` | Snapshot generation timestamp. |
| `data` | `RuntimeMeQualityPayload?` | Null when unavailable. |

#### `RuntimeMeQualityPayload`
| Field | Type | Description |
| --- | --- | --- |
| `counters` | `RuntimeMeQualityCountersData` | Key ME lifecycle/error counters. |
| `route_drops` | `RuntimeMeQualityRouteDropData` | Route drop counters by reason. |
| `dc_rtt` | `RuntimeMeQualityDcRttData[]` | Per-DC RTT and writer coverage rows. |

#### `RuntimeMeQualityCountersData`
| Field | Type | Description |
| --- | --- | --- |
| `idle_close_by_peer_total` | `u64` | Peer-initiated idle closes. |
| `reader_eof_total` | `u64` | Reader EOF events. |
| `kdf_drift_total` | `u64` | KDF drift detections. |
| `kdf_port_only_drift_total` | `u64` | KDF port-only drift detections. |
| `reconnect_attempt_total` | `u64` | Reconnect attempts. |
| `reconnect_success_total` | `u64` | Successful reconnects. |

#### `RuntimeMeQualityRouteDropData`
| Field | Type | Description |
| --- | --- | --- |
| `no_conn_total` | `u64` | Route drops with no connection mapping. |
| `channel_closed_total` | `u64` | Route drops because destination channel is closed. |
| `queue_full_total` | `u64` | Route drops due queue backpressure (aggregate). |
| `queue_full_base_total` | `u64` | Route drops in base-queue path. |
| `queue_full_high_total` | `u64` | Route drops in high-priority queue path. |

#### `RuntimeMeQualityDcRttData`
| Field | Type | Description |
| --- | --- | --- |
| `dc` | `i16` | Telegram DC id. |
| `rtt_ema_ms` | `f64?` | RTT EMA for this DC. |
| `alive_writers` | `usize` | Alive writers currently mapped to this DC. |
| `required_writers` | `usize` | Target writer floor for this DC. |
| `coverage_pct` | `f64` | `alive_writers / required_writers * 100`. |

### `RuntimeUpstreamQualityData`
| Field | Type | Description |
| --- | --- | --- |
| `enabled` | `bool` | Runtime payload availability. |
| `reason` | `string?` | `source_unavailable` when upstream runtime snapshot is unavailable. |
| `generated_at_epoch_secs` | `u64` | Snapshot generation timestamp. |
| `policy` | `RuntimeUpstreamQualityPolicyData` | Effective upstream policy values. |
| `counters` | `RuntimeUpstreamQualityCountersData` | Upstream connect counters. |
| `summary` | `RuntimeUpstreamQualitySummaryData?` | Aggregate runtime health summary. |
| `upstreams` | `RuntimeUpstreamQualityUpstreamData[]?` | Per-upstream runtime rows. |

#### `RuntimeUpstreamQualityPolicyData`
| Field | Type | Description |
| --- | --- | --- |
| `connect_retry_attempts` | `u32` | Upstream connect retry attempts. |
| `connect_retry_backoff_ms` | `u64` | Upstream retry backoff delay. |
| `connect_budget_ms` | `u64` | Total connect wall-clock budget. |
| `unhealthy_fail_threshold` | `u32` | Consecutive fail threshold for unhealthy marking. |
| `connect_failfast_hard_errors` | `bool` | Whether hard errors skip retries. |

#### `RuntimeUpstreamQualityCountersData`
| Field | Type | Description |
| --- | --- | --- |
| `connect_attempt_total` | `u64` | Total connect attempts. |
| `connect_success_total` | `u64` | Successful connects. |
| `connect_fail_total` | `u64` | Failed connects. |
| `connect_failfast_hard_error_total` | `u64` | Fail-fast hard errors. |

#### `RuntimeUpstreamQualitySummaryData`
| Field | Type | Description |
| --- | --- | --- |
| `configured_total` | `usize` | Total configured upstream entries. |
| `healthy_total` | `usize` | Upstreams currently healthy. |
| `unhealthy_total` | `usize` | Upstreams currently unhealthy. |
| `direct_total` | `usize` | Direct-route upstream entries. |
| `socks4_total` | `usize` | SOCKS4 upstream entries. |
| `socks5_total` | `usize` | SOCKS5 upstream entries. |
| `shadowsocks_total` | `usize` | Shadowsocks upstream entries. |

#### `RuntimeUpstreamQualityUpstreamData`
| Field | Type | Description |
| --- | --- | --- |
| `upstream_id` | `usize` | Runtime upstream index. |
| `route_kind` | `string` | `direct`, `socks4`, `socks5`, `shadowsocks`. |
| `address` | `string` | Upstream address (`direct` literal for direct route kind, `host:port` only for proxied upstreams). |
| `weight` | `u16` | Selection weight. |
| `scopes` | `string` | Configured scope selector. |
| `healthy` | `bool` | Current health flag. |
| `fails` | `u32` | Consecutive fail counter. |
| `last_check_age_secs` | `u64` | Seconds since last health update. |
| `effective_latency_ms` | `f64?` | Effective latency score used by selector. |
| `dc` | `RuntimeUpstreamQualityDcData[]` | Per-DC runtime rows. |

#### `RuntimeUpstreamQualityDcData`
| Field | Type | Description |
| --- | --- | --- |
| `dc` | `i16` | Telegram DC id. |
| `latency_ema_ms` | `f64?` | Per-DC latency EMA. |
| `ip_preference` | `string` | `unknown`, `prefer_v4`, `prefer_v6`, `both_work`, `unavailable`. |

### `RuntimeNatStunData`
| Field | Type | Description |
| --- | --- | --- |
| `enabled` | `bool` | Runtime payload availability. |
| `reason` | `string?` | `source_unavailable` when shared STUN state is unavailable. |
| `generated_at_epoch_secs` | `u64` | Snapshot generation timestamp. |
| `data` | `RuntimeNatStunPayload?` | Null when unavailable. |

#### `RuntimeNatStunPayload`
| Field | Type | Description |
| --- | --- | --- |
| `flags` | `RuntimeNatStunFlagsData` | NAT probe runtime flags. |
| `servers` | `RuntimeNatStunServersData` | Configured/live STUN server lists. |
| `reflection` | `RuntimeNatStunReflectionBlockData` | Reflection cache data for v4/v6. |
| `stun_backoff_remaining_ms` | `u64?` | Remaining retry backoff (milliseconds). |

#### `RuntimeNatStunFlagsData`
| Field | Type | Description |
| --- | --- | --- |
| `nat_probe_enabled` | `bool` | Current NAT probe enable state. |
| `nat_probe_disabled_runtime` | `bool` | Runtime disable flag due failures/conditions. |
| `nat_probe_attempts` | `u8` | Configured NAT probe attempt count. |

#### `RuntimeNatStunServersData`
| Field | Type | Description |
| --- | --- | --- |
| `configured` | `string[]` | Configured STUN server entries. |
| `live` | `string[]` | Runtime live STUN server entries. |
| `live_total` | `usize` | Number of live STUN entries. |

#### `RuntimeNatStunReflectionBlockData`
| Field | Type | Description |
| --- | --- | --- |
| `v4` | `RuntimeNatStunReflectionData?` | IPv4 reflection data. |
| `v6` | `RuntimeNatStunReflectionData?` | IPv6 reflection data. |

#### `RuntimeNatStunReflectionData`
| Field | Type | Description |
| --- | --- | --- |
| `addr` | `string` | Reflected public endpoint (`ip:port`). |
| `age_secs` | `u64` | Reflection value age in seconds. |

### `RuntimeMeSelftestData`
| Field | Type | Description |
| --- | --- | --- |
| `enabled` | `bool` | Runtime payload availability. |
| `reason` | `string?` | `source_unavailable` when ME pool is unavailable. |
| `generated_at_epoch_secs` | `u64` | Snapshot generation timestamp. |
| `data` | `RuntimeMeSelftestPayload?` | Null when unavailable. |

#### `RuntimeMeSelftestPayload`
| Field | Type | Description |
| --- | --- | --- |
| `kdf` | `RuntimeMeSelftestKdfData` | KDF EWMA health state. |
| `timeskew` | `RuntimeMeSelftestTimeskewData` | Date-header skew health state. |
| `ip` | `RuntimeMeSelftestIpData` | Interface IP family classification. |
| `pid` | `RuntimeMeSelftestPidData` | Process PID marker (`one|non-one`). |
| `bnd` | `RuntimeMeSelftestBndData` | SOCKS BND.ADDR/BND.PORT health state. |

#### `RuntimeMeSelftestKdfData`
| Field | Type | Description |
| --- | --- | --- |
| `state` | `string` | `ok` or `error` based on EWMA threshold. |
| `ewma_errors_per_min` | `f64` | EWMA KDF error rate per minute. |
| `threshold_errors_per_min` | `f64` | Threshold used for `error` decision. |
| `errors_total` | `u64` | Total source errors (`kdf_drift + socks_kdf_strict_reject`). |

#### `RuntimeMeSelftestTimeskewData`
| Field | Type | Description |
| --- | --- | --- |
| `state` | `string` | `ok` or `error` (`max_skew_secs_15m > 60` => `error`). |
| `max_skew_secs_15m` | `u64?` | Maximum observed skew in the last 15 minutes. |
| `samples_15m` | `usize` | Number of skew samples in the last 15 minutes. |
| `last_skew_secs` | `u64?` | Latest observed skew value. |
| `last_source` | `string?` | Latest skew source marker. |
| `last_seen_age_secs` | `u64?` | Age of the latest skew sample. |

#### `RuntimeMeSelftestIpData`
| Field | Type | Description |
| --- | --- | --- |
| `v4` | `RuntimeMeSelftestIpFamilyData?` | IPv4 interface probe result; absent when unknown. |
| `v6` | `RuntimeMeSelftestIpFamilyData?` | IPv6 interface probe result; absent when unknown. |

#### `RuntimeMeSelftestIpFamilyData`
| Field | Type | Description |
| --- | --- | --- |
| `addr` | `string` | Detected interface IP. |
| `state` | `string` | `good`, `bogon`, or `loopback`. |

#### `RuntimeMeSelftestPidData`
| Field | Type | Description |
| --- | --- | --- |
| `pid` | `u32` | Current process PID. |
| `state` | `string` | `one` when PID=1, otherwise `non-one`. |

#### `RuntimeMeSelftestBndData`
| Field | Type | Description |
| --- | --- | --- |
| `addr_state` | `string` | `ok`, `bogon`, or `error`. |
| `port_state` | `string` | `ok`, `zero`, or `error`. |
| `last_addr` | `string?` | Latest observed SOCKS BND address. |
| `last_seen_age_secs` | `u64?` | Age of latest BND sample. |

### `RuntimeEdgeConnectionsSummaryData`
| Field | Type | Description |
| --- | --- | --- |
| `enabled` | `bool` | Endpoint availability under `runtime_edge_enabled`. |
| `reason` | `string?` | `feature_disabled` or `source_unavailable`. |
| `generated_at_epoch_secs` | `u64` | Snapshot generation timestamp. |
| `data` | `RuntimeEdgeConnectionsSummaryPayload?` | Null when unavailable. |

#### `RuntimeEdgeConnectionsSummaryPayload`
| Field | Type | Description |
| --- | --- | --- |
| `cache` | `RuntimeEdgeConnectionCacheData` | Runtime edge cache metadata. |
| `totals` | `RuntimeEdgeConnectionTotalsData` | Connection totals block. |
| `top` | `RuntimeEdgeConnectionTopData` | Top-N leaderboard blocks. |
| `telemetry` | `RuntimeEdgeConnectionTelemetryData` | Telemetry-policy flags for counters. |

#### `RuntimeEdgeConnectionCacheData`
| Field | Type | Description |
| --- | --- | --- |
| `ttl_ms` | `u64` | Configured cache TTL in milliseconds. |
| `served_from_cache` | `bool` | `true` when payload is served from cache. |
| `stale_cache_used` | `bool` | `true` when stale cache is used because recompute is busy. |

#### `RuntimeEdgeConnectionTotalsData`
| Field | Type | Description |
| --- | --- | --- |
| `current_connections` | `u64` | Current global live connections. |
| `current_connections_me` | `u64` | Current live connections routed through ME. |
| `current_connections_direct` | `u64` | Current live connections routed through direct path. |
| `active_users` | `usize` | Users with `current_connections > 0`. |

#### `RuntimeEdgeConnectionTopData`
| Field | Type | Description |
| --- | --- | --- |
| `limit` | `usize` | Effective Top-N row count. |
| `by_connections` | `RuntimeEdgeConnectionUserData[]` | Users sorted by current connections. |
| `by_throughput` | `RuntimeEdgeConnectionUserData[]` | Users sorted by cumulative octets. |

#### `RuntimeEdgeConnectionUserData`
| Field | Type | Description |
| --- | --- | --- |
| `username` | `string` | Username. |
| `current_connections` | `u64` | Current live connections for user. |
| `total_octets` | `u64` | Cumulative (`client->proxy + proxy->client`) octets. |

#### `RuntimeEdgeConnectionTelemetryData`
| Field | Type | Description |
| --- | --- | --- |
| `user_enabled` | `bool` | Per-user telemetry enable flag. |
| `throughput_is_cumulative` | `bool` | Always `true` in current implementation. |

### `RuntimeEdgeEventsData`
| Field | Type | Description |
| --- | --- | --- |
| `enabled` | `bool` | Endpoint availability under `runtime_edge_enabled`. |
| `reason` | `string?` | `feature_disabled` when endpoint is disabled. |
| `generated_at_epoch_secs` | `u64` | Snapshot generation timestamp. |
| `data` | `RuntimeEdgeEventsPayload?` | Null when unavailable. |

#### `RuntimeEdgeEventsPayload`
| Field | Type | Description |
| --- | --- | --- |
| `capacity` | `usize` | Effective ring-buffer capacity. |
| `dropped_total` | `u64` | Count of dropped oldest events due capacity pressure. |
| `events` | `ApiEventRecord[]` | Recent events in chronological order. |

#### `ApiEventRecord`
| Field | Type | Description |
| --- | --- | --- |
| `seq` | `u64` | Monotonic sequence number. |
| `ts_epoch_secs` | `u64` | Event timestamp (Unix seconds). |
| `event_type` | `string` | Event kind identifier. |
| `context` | `string` | Context text (truncated to implementation-defined max length). |

### `ZeroAllData`
| Field | Type | Description |
| --- | --- | --- |
| `generated_at_epoch_secs` | `u64` | Snapshot time (Unix epoch seconds). |
| `core` | `ZeroCoreData` | Core counters and telemetry policy snapshot. |
| `upstream` | `ZeroUpstreamData` | Upstream connect counters/histogram buckets. |
| `middle_proxy` | `ZeroMiddleProxyData` | ME protocol/health counters. |
| `pool` | `ZeroPoolData` | ME pool lifecycle counters. |
| `desync` | `ZeroDesyncData` | Frame desync counters. |

#### `ZeroCoreData`
| Field | Type | Description |
| --- | --- | --- |
| `uptime_seconds` | `f64` | Process uptime. |
| `connections_total` | `u64` | Total accepted connections. |
| `connections_bad_total` | `u64` | Failed/invalid connections. |
| `handshake_timeouts_total` | `u64` | Handshake timeouts. |
| `configured_users` | `usize` | Configured user count. |
| `telemetry_core_enabled` | `bool` | Core telemetry toggle. |
| `telemetry_user_enabled` | `bool` | User telemetry toggle. |
| `telemetry_me_level` | `string` | ME telemetry level (`off|normal|verbose`). |

#### `ZeroUpstreamData`
| Field | Type | Description |
| --- | --- | --- |
| `connect_attempt_total` | `u64` | Total upstream connect attempts. |
| `connect_success_total` | `u64` | Successful upstream connects. |
| `connect_fail_total` | `u64` | Failed upstream connects. |
| `connect_failfast_hard_error_total` | `u64` | Fail-fast hard errors. |
| `connect_attempts_bucket_1` | `u64` | Connect attempts resolved in 1 try. |
| `connect_attempts_bucket_2` | `u64` | Connect attempts resolved in 2 tries. |
| `connect_attempts_bucket_3_4` | `u64` | Connect attempts resolved in 3-4 tries. |
| `connect_attempts_bucket_gt_4` | `u64` | Connect attempts requiring more than 4 tries. |
| `connect_duration_success_bucket_le_100ms` | `u64` | Successful connects <=100 ms. |
| `connect_duration_success_bucket_101_500ms` | `u64` | Successful connects 101-500 ms. |
| `connect_duration_success_bucket_501_1000ms` | `u64` | Successful connects 501-1000 ms. |
| `connect_duration_success_bucket_gt_1000ms` | `u64` | Successful connects >1000 ms. |
| `connect_duration_fail_bucket_le_100ms` | `u64` | Failed connects <=100 ms. |
| `connect_duration_fail_bucket_101_500ms` | `u64` | Failed connects 101-500 ms. |
| `connect_duration_fail_bucket_501_1000ms` | `u64` | Failed connects 501-1000 ms. |
| `connect_duration_fail_bucket_gt_1000ms` | `u64` | Failed connects >1000 ms. |

### `UpstreamsData`
| Field | Type | Description |
| --- | --- | --- |
| `enabled` | `bool` | Runtime upstream snapshot availability according to API config. |
| `reason` | `string?` | `feature_disabled` or `source_unavailable` when runtime snapshot is unavailable. |
| `generated_at_epoch_secs` | `u64` | Snapshot generation time. |
| `zero` | `ZeroUpstreamData` | Always available zero-cost upstream counters block. |
| `summary` | `UpstreamSummaryData?` | Runtime upstream aggregate view, null when unavailable. |
| `upstreams` | `UpstreamStatus[]?` | Per-upstream runtime status rows, null when unavailable. |

#### `UpstreamSummaryData`
| Field | Type | Description |
| --- | --- | --- |
| `configured_total` | `usize` | Total configured upstream entries. |
| `healthy_total` | `usize` | Upstreams currently marked healthy. |
| `unhealthy_total` | `usize` | Upstreams currently marked unhealthy. |
| `direct_total` | `usize` | Number of direct upstream entries. |
| `socks4_total` | `usize` | Number of SOCKS4 upstream entries. |
| `socks5_total` | `usize` | Number of SOCKS5 upstream entries. |
| `shadowsocks_total` | `usize` | Number of Shadowsocks upstream entries. |

#### `UpstreamStatus`
| Field | Type | Description |
| --- | --- | --- |
| `upstream_id` | `usize` | Runtime upstream index. |
| `route_kind` | `string` | Upstream route kind: `direct`, `socks4`, `socks5`, `shadowsocks`. |
| `address` | `string` | Upstream address (`direct` for direct route kind, `host:port` for Shadowsocks). Authentication fields are intentionally omitted. |
| `weight` | `u16` | Selection weight. |
| `scopes` | `string` | Configured scope selector string. |
| `healthy` | `bool` | Current health flag. |
| `fails` | `u32` | Consecutive fail counter. |
| `last_check_age_secs` | `u64` | Seconds since the last health-check update. |
| `effective_latency_ms` | `f64?` | Effective upstream latency used by selector. |
| `dc` | `UpstreamDcStatus[]` | Per-DC latency/IP preference snapshot. |

#### `UpstreamDcStatus`
| Field | Type | Description |
| --- | --- | --- |
| `dc` | `i16` | Telegram DC id. |
| `latency_ema_ms` | `f64?` | Per-DC latency EMA value. |
| `ip_preference` | `string` | Per-DC IP family preference: `unknown`, `prefer_v4`, `prefer_v6`, `both_work`, `unavailable`. |

#### `ZeroMiddleProxyData`
| Field | Type | Description |
| --- | --- | --- |
| `keepalive_sent_total` | `u64` | ME keepalive packets sent. |
| `keepalive_failed_total` | `u64` | ME keepalive send failures. |
| `keepalive_pong_total` | `u64` | Keepalive pong responses received. |
| `keepalive_timeout_total` | `u64` | Keepalive timeout events. |
| `rpc_proxy_req_signal_sent_total` | `u64` | RPC proxy activity signals sent. |
| `rpc_proxy_req_signal_failed_total` | `u64` | RPC proxy activity signal failures. |
| `rpc_proxy_req_signal_skipped_no_meta_total` | `u64` | Signals skipped due to missing metadata. |
| `rpc_proxy_req_signal_response_total` | `u64` | RPC proxy signal responses received. |
| `rpc_proxy_req_signal_close_sent_total` | `u64` | RPC proxy close signals sent. |
| `reconnect_attempt_total` | `u64` | ME reconnect attempts. |
| `reconnect_success_total` | `u64` | Successful reconnects. |
| `handshake_reject_total` | `u64` | ME handshake rejects. |
| `handshake_error_codes` | `ZeroCodeCount[]` | Handshake rejects grouped by code. |
| `reader_eof_total` | `u64` | ME reader EOF events. |
| `idle_close_by_peer_total` | `u64` | Idle closes initiated by peer. |
| `route_drop_no_conn_total` | `u64` | Route drops due to missing bound connection. |
| `route_drop_channel_closed_total` | `u64` | Route drops due to closed channel. |
| `route_drop_queue_full_total` | `u64` | Route drops due to full queue (total). |
| `route_drop_queue_full_base_total` | `u64` | Route drops in base queue mode. |
| `route_drop_queue_full_high_total` | `u64` | Route drops in high queue mode. |
| `socks_kdf_strict_reject_total` | `u64` | SOCKS KDF strict rejects. |
| `socks_kdf_compat_fallback_total` | `u64` | SOCKS KDF compat fallbacks. |
| `endpoint_quarantine_total` | `u64` | Endpoint quarantine activations. |
| `kdf_drift_total` | `u64` | KDF drift detections. |
| `kdf_port_only_drift_total` | `u64` | KDF port-only drift detections. |
| `hardswap_pending_reuse_total` | `u64` | Pending hardswap reused events. |
| `hardswap_pending_ttl_expired_total` | `u64` | Pending hardswap TTL expiry events. |
| `single_endpoint_outage_enter_total` | `u64` | Entered single-endpoint outage mode. |
| `single_endpoint_outage_exit_total` | `u64` | Exited single-endpoint outage mode. |
| `single_endpoint_outage_reconnect_attempt_total` | `u64` | Reconnect attempts in outage mode. |
| `single_endpoint_outage_reconnect_success_total` | `u64` | Reconnect successes in outage mode. |
| `single_endpoint_quarantine_bypass_total` | `u64` | Quarantine bypasses in outage mode. |
| `single_endpoint_shadow_rotate_total` | `u64` | Shadow writer rotations. |
| `single_endpoint_shadow_rotate_skipped_quarantine_total` | `u64` | Shadow rotations skipped because of quarantine. |
| `floor_mode_switch_total` | `u64` | Total floor mode switches. |
| `floor_mode_switch_static_to_adaptive_total` | `u64` | Static -> adaptive switches. |
| `floor_mode_switch_adaptive_to_static_total` | `u64` | Adaptive -> static switches. |

#### `ZeroCodeCount`
| Field | Type | Description |
| --- | --- | --- |
| `code` | `i32` | Handshake error code. |
| `total` | `u64` | Events with this code. |

#### `ZeroPoolData`
| Field | Type | Description |
| --- | --- | --- |
| `pool_swap_total` | `u64` | Pool swap count. |
| `pool_drain_active` | `u64` | Current active draining pools. |
| `pool_force_close_total` | `u64` | Forced pool closes by timeout. |
| `pool_stale_pick_total` | `u64` | Stale writer picks for binding. |
| `writer_removed_total` | `u64` | Writer removals total. |
| `writer_removed_unexpected_total` | `u64` | Unexpected writer removals. |
| `refill_triggered_total` | `u64` | Refill triggers. |
| `refill_skipped_inflight_total` | `u64` | Refill skipped because refill already in-flight. |
| `refill_failed_total` | `u64` | Refill failures. |
| `writer_restored_same_endpoint_total` | `u64` | Restores on same endpoint. |
| `writer_restored_fallback_total` | `u64` | Restores on fallback endpoint. |

#### `ZeroDesyncData`
| Field | Type | Description |
| --- | --- | --- |
| `secure_padding_invalid_total` | `u64` | Invalid secure padding events. |
| `desync_total` | `u64` | Desync events total. |
| `desync_full_logged_total` | `u64` | Fully logged desync events. |
| `desync_suppressed_total` | `u64` | Suppressed desync logs. |
| `desync_frames_bucket_0` | `u64` | Desync frames bucket 0. |
| `desync_frames_bucket_1_2` | `u64` | Desync frames bucket 1-2. |
| `desync_frames_bucket_3_10` | `u64` | Desync frames bucket 3-10. |
| `desync_frames_bucket_gt_10` | `u64` | Desync frames bucket >10. |

### `MinimalAllData`
| Field | Type | Description |
| --- | --- | --- |
| `enabled` | `bool` | Whether minimal runtime snapshots are enabled by config. |
| `reason` | `string?` | `feature_disabled` or `source_unavailable` when applicable. |
| `generated_at_epoch_secs` | `u64` | Snapshot generation time. |
| `data` | `MinimalAllPayload?` | Null when disabled; fallback payload when source unavailable. |

#### `MinimalAllPayload`
| Field | Type | Description |
| --- | --- | --- |
| `me_writers` | `MeWritersData` | ME writer status block. |
| `dcs` | `DcStatusData` | DC aggregate status block. |
| `me_runtime` | `MinimalMeRuntimeData?` | Runtime ME control snapshot. |
| `network_path` | `MinimalDcPathData[]` | Active IP path selection per DC. |

#### `MinimalMeRuntimeData`
| Field | Type | Description |
| --- | --- | --- |
| `active_generation` | `u64` | Active pool generation. |
| `warm_generation` | `u64` | Warm pool generation. |
| `pending_hardswap_generation` | `u64` | Pending hardswap generation. |
| `pending_hardswap_age_secs` | `u64?` | Pending hardswap age in seconds. |
| `hardswap_enabled` | `bool` | Hardswap mode toggle. |
| `floor_mode` | `string` | Writer floor mode. |
| `adaptive_floor_idle_secs` | `u64` | Idle threshold for adaptive floor. |
| `adaptive_floor_min_writers_single_endpoint` | `u8` | Minimum writers for single-endpoint DC in adaptive mode. |
| `adaptive_floor_min_writers_multi_endpoint` | `u8` | Minimum writers for multi-endpoint DC in adaptive mode. |
| `adaptive_floor_recover_grace_secs` | `u64` | Grace period for floor recovery. |
| `adaptive_floor_writers_per_core_total` | `u16` | Target total writers-per-core budget in adaptive mode. |
| `adaptive_floor_cpu_cores_override` | `u16` | CPU core override (`0` means auto-detect). |
| `adaptive_floor_max_extra_writers_single_per_core` | `u16` | Extra single-endpoint writers budget per core. |
| `adaptive_floor_max_extra_writers_multi_per_core` | `u16` | Extra multi-endpoint writers budget per core. |
| `adaptive_floor_max_active_writers_per_core` | `u16` | Active writer cap per core. |
| `adaptive_floor_max_warm_writers_per_core` | `u16` | Warm writer cap per core. |
| `adaptive_floor_max_active_writers_global` | `u32` | Global active writer cap. |
| `adaptive_floor_max_warm_writers_global` | `u32` | Global warm writer cap. |
| `adaptive_floor_cpu_cores_detected` | `u32` | Runtime-detected CPU cores. |
| `adaptive_floor_cpu_cores_effective` | `u32` | Effective core count used for adaptive caps. |
| `adaptive_floor_global_cap_raw` | `u64` | Raw global cap before clamping. |
| `adaptive_floor_global_cap_effective` | `u64` | Effective global cap after clamping. |
| `adaptive_floor_target_writers_total` | `u64` | Current adaptive total writer target. |
| `adaptive_floor_active_cap_configured` | `u64` | Configured global active cap. |
| `adaptive_floor_active_cap_effective` | `u64` | Effective global active cap. |
| `adaptive_floor_warm_cap_configured` | `u64` | Configured global warm cap. |
| `adaptive_floor_warm_cap_effective` | `u64` | Effective global warm cap. |
| `adaptive_floor_active_writers_current` | `u64` | Current active writers count. |
| `adaptive_floor_warm_writers_current` | `u64` | Current warm writers count. |
| `me_keepalive_enabled` | `bool` | ME keepalive toggle. |
| `me_keepalive_interval_secs` | `u64` | Keepalive period. |
| `me_keepalive_jitter_secs` | `u64` | Keepalive jitter. |
| `me_keepalive_payload_random` | `bool` | Randomized keepalive payload toggle. |
| `rpc_proxy_req_every_secs` | `u64` | Period for RPC proxy request signal. |
| `me_reconnect_max_concurrent_per_dc` | `u32` | Reconnect concurrency per DC. |
| `me_reconnect_backoff_base_ms` | `u64` | Base reconnect backoff. |
| `me_reconnect_backoff_cap_ms` | `u64` | Max reconnect backoff. |
| `me_reconnect_fast_retry_count` | `u32` | Fast retry attempts before normal backoff. |
| `me_pool_drain_ttl_secs` | `u64` | Pool drain TTL. |
| `me_pool_force_close_secs` | `u64` | Hard close timeout for draining writers. |
| `me_pool_min_fresh_ratio` | `f32` | Minimum fresh ratio before swap. |
| `me_bind_stale_mode` | `string` | Stale writer bind policy. |
| `me_bind_stale_ttl_secs` | `u64` | Stale writer TTL. |
| `me_single_endpoint_shadow_writers` | `u8` | Shadow writers for single-endpoint DCs. |
| `me_single_endpoint_outage_mode_enabled` | `bool` | Outage mode toggle for single-endpoint DCs. |
| `me_single_endpoint_outage_disable_quarantine` | `bool` | Quarantine behavior in outage mode. |
| `me_single_endpoint_outage_backoff_min_ms` | `u64` | Outage mode min reconnect backoff. |
| `me_single_endpoint_outage_backoff_max_ms` | `u64` | Outage mode max reconnect backoff. |
| `me_single_endpoint_shadow_rotate_every_secs` | `u64` | Shadow rotation interval. |
| `me_deterministic_writer_sort` | `bool` | Deterministic writer ordering toggle. |
| `me_writer_pick_mode` | `string` | Writer picker mode (`sorted_rr`, `p2c`). |
| `me_writer_pick_sample_size` | `u8` | Candidate sample size for `p2c` picker mode. |
| `me_socks_kdf_policy` | `string` | Current SOCKS KDF policy mode. |
| `quarantined_endpoints_total` | `usize` | Total quarantined endpoints. |
| `quarantined_endpoints` | `MinimalQuarantineData[]` | Quarantine details. |

#### `MinimalQuarantineData`
| Field | Type | Description |
| --- | --- | --- |
| `endpoint` | `string` | Endpoint (`ip:port`). |
| `remaining_ms` | `u64` | Remaining quarantine duration. |

#### `MinimalDcPathData`
| Field | Type | Description |
| --- | --- | --- |
| `dc` | `i16` | Telegram DC identifier. |
| `ip_preference` | `string?` | Runtime IP family preference. |
| `selected_addr_v4` | `string?` | Selected IPv4 endpoint for this DC. |
| `selected_addr_v6` | `string?` | Selected IPv6 endpoint for this DC. |

### `MeWritersData`
| Field | Type | Description |
| --- | --- | --- |
| `middle_proxy_enabled` | `bool` | `false` when minimal runtime is disabled or source unavailable. |
| `reason` | `string?` | `feature_disabled` or `source_unavailable` when not fully available. |
| `generated_at_epoch_secs` | `u64` | Snapshot generation time. |
| `summary` | `MeWritersSummary` | Coverage/availability summary. |
| `writers` | `MeWriterStatus[]` | Per-writer statuses. |

#### `MeWritersSummary`
| Field | Type | Description |
| --- | --- | --- |
| `configured_dc_groups` | `usize` | Number of configured DC groups. |
| `configured_endpoints` | `usize` | Total configured ME endpoints. |
| `available_endpoints` | `usize` | Endpoints currently available. |
| `available_pct` | `f64` | `available_endpoints / configured_endpoints * 100`. |
| `required_writers` | `usize` | Required writers based on current floor policy. |
| `alive_writers` | `usize` | Writers currently alive. |
| `coverage_pct` | `f64` | `alive_writers / required_writers * 100`. |

#### `MeWriterStatus`
| Field | Type | Description |
| --- | --- | --- |
| `writer_id` | `u64` | Runtime writer identifier. |
| `dc` | `i16?` | DC id if mapped. |
| `endpoint` | `string` | Endpoint (`ip:port`). |
| `generation` | `u64` | Pool generation owning this writer. |
| `state` | `string` | Writer state (`warm`, `active`, `draining`). |
| `draining` | `bool` | Draining flag. |
| `degraded` | `bool` | Degraded flag. |
| `bound_clients` | `usize` | Number of currently bound clients. |
| `idle_for_secs` | `u64?` | Idle age in seconds if idle. |
| `rtt_ema_ms` | `f64?` | RTT exponential moving average. |

### `DcStatusData`
| Field | Type | Description |
| --- | --- | --- |
| `middle_proxy_enabled` | `bool` | `false` when minimal runtime is disabled or source unavailable. |
| `reason` | `string?` | `feature_disabled` or `source_unavailable` when not fully available. |
| `generated_at_epoch_secs` | `u64` | Snapshot generation time. |
| `dcs` | `DcStatus[]` | Per-DC status rows. |

#### `DcStatus`
| Field | Type | Description |
| --- | --- | --- |
| `dc` | `i16` | Telegram DC id. |
| `endpoints` | `string[]` | Endpoints in this DC (`ip:port`). |
| `endpoint_writers` | `DcEndpointWriters[]` | Active writer counts grouped by endpoint. |
| `available_endpoints` | `usize` | Endpoints currently available in this DC. |
| `available_pct` | `f64` | `available_endpoints / endpoints_total * 100`. |
| `required_writers` | `usize` | Required writer count for this DC. |
| `floor_min` | `usize` | Floor lower bound for this DC. |
| `floor_target` | `usize` | Floor target writer count for this DC. |
| `floor_max` | `usize` | Floor upper bound for this DC. |
| `floor_capped` | `bool` | `true` when computed floor target was capped by active limits. |
| `alive_writers` | `usize` | Alive writers in this DC. |
| `coverage_pct` | `f64` | `alive_writers / required_writers * 100`. |
| `rtt_ms` | `f64?` | Aggregated RTT for DC. |
| `load` | `usize` | Active client sessions bound to this DC. |

#### `DcEndpointWriters`
| Field | Type | Description |
| --- | --- | --- |
| `endpoint` | `string` | Endpoint (`ip:port`). |
| `active_writers` | `usize` | Active writers currently mapped to endpoint. |

### `UserInfo`
| Field | Type | Description |
| --- | --- | --- |
| `username` | `string` | Username. |
| `user_ad_tag` | `string?` | Optional ad tag (32 hex chars). |
| `max_tcp_conns` | `usize?` | Optional max concurrent TCP limit. |
| `expiration_rfc3339` | `string?` | Optional expiration timestamp. |
| `data_quota_bytes` | `u64?` | Optional data quota. |
| `max_unique_ips` | `usize?` | Optional unique IP limit. |
| `current_connections` | `u64` | Current live connections. |
| `active_unique_ips` | `usize` | Current active unique source IPs. |
| `active_unique_ips_list` | `ip[]` | Current active unique source IP list. |
| `recent_unique_ips` | `usize` | Unique source IP count inside the configured recent window. |
| `recent_unique_ips_list` | `ip[]` | Recent-window unique source IP list. |
| `total_octets` | `u64` | Total traffic octets for this user. |
| `links` | `UserLinks` | Active connection links derived from current config. |

#### `UserLinks`
| Field | Type | Description |
| --- | --- | --- |
| `classic` | `string[]` | Active `tg://proxy` links for classic mode. |
| `secure` | `string[]` | Active `tg://proxy` links for secure/DD mode. |
| `tls` | `string[]` | Active `tg://proxy` links for EE-TLS mode (for each host+TLS domain). |

Link generation uses active config and enabled modes:
- Link port is `general.links.public_port` when configured; otherwise `server.port`.
- If `general.links.public_host` is non-empty, it is used as the single link host override.
- If `public_host` is not set, hosts are resolved from `server.listeners` in order:
  `announce` -> `announce_ip` -> listener bind `ip`.
- For wildcard listener IPs (`0.0.0.0` / `::`), startup-detected external IP of the same family is used when available.
- Listener-derived hosts are de-duplicated while preserving first-seen order.
- If multiple hosts are resolved, API returns links for all resolved hosts in every enabled mode.
- If no host can be resolved from listeners, fallback is startup-detected `IPv4 -> IPv6`.
- Final compatibility fallback uses `listen_addr_ipv4`/`listen_addr_ipv6` when routable, otherwise `"UNKNOWN"`.
- User rows are sorted by `username` in ascending lexical order.

### `CreateUserResponse`
| Field | Type | Description |
| --- | --- | --- |
| `user` | `UserInfo` | Created or updated user view. |
| `secret` | `string` | Effective user secret. |

## Mutation Semantics

| Endpoint | Notes |
| --- | --- |
| `POST /v1/users` | Creates user, validates config, then atomically updates only affected `access.*` TOML tables (`access.users` always, plus optional per-user tables present in request). |
| `PATCH /v1/users/{username}` | Partial update of provided fields only. Missing fields remain unchanged. Current implementation persists full config document on success. |
| `POST /v1/users/{username}/rotate-secret` | Currently returns `404` in runtime route matcher; request schema is reserved for intended behavior. |
| `DELETE /v1/users/{username}` | Deletes only specified user, removes this user from related optional `access.user_*` maps, blocks last-user deletion, and atomically updates only related `access.*` TOML tables. |

All mutating endpoints:
- Respect `read_only` mode.
- Accept optional `If-Match` for optimistic concurrency.
- Return new `revision` after successful write.
- Use process-local mutation lock + atomic write (`tmp + rename`) for config persistence.

Delete path cleanup guarantees:
- Config cleanup removes only the requested username keys.
- Runtime unique-IP cleanup removes only this user's limiter and tracked IP state.

## Runtime State Matrix

| Endpoint | `minimal_runtime_enabled=false` | `minimal_runtime_enabled=true` + source unavailable | `minimal_runtime_enabled=true` + source available |
| --- | --- | --- | --- |
| `/v1/stats/minimal/all` | `enabled=false`, `reason=feature_disabled`, `data=null` | `enabled=true`, `reason=source_unavailable`, fallback `data` with disabled ME blocks | `enabled=true`, `reason` omitted, full payload |
| `/v1/stats/me-writers` | `middle_proxy_enabled=false`, `reason=feature_disabled` | `middle_proxy_enabled=false`, `reason=source_unavailable` | `middle_proxy_enabled=true`, runtime snapshot |
| `/v1/stats/dcs` | `middle_proxy_enabled=false`, `reason=feature_disabled` | `middle_proxy_enabled=false`, `reason=source_unavailable` | `middle_proxy_enabled=true`, runtime snapshot |
| `/v1/stats/upstreams` | `enabled=false`, `reason=feature_disabled`, `summary/upstreams` omitted, `zero` still present | `enabled=true`, `reason=source_unavailable`, `summary/upstreams` omitted, `zero` present | `enabled=true`, `reason` omitted, `summary/upstreams` present, `zero` present |

`source_unavailable` conditions:
- ME endpoints: ME pool is absent (for example direct-only mode or failed ME initialization).
- Upstreams endpoint: non-blocking upstream snapshot lock is unavailable at request time.

Additional runtime endpoint behavior:

| Endpoint | Disabled by feature flag | `source_unavailable` condition | Normal mode |
| --- | --- | --- | --- |
| `/v1/runtime/me_pool_state` | No | ME pool snapshot unavailable | `enabled=true`, full payload |
| `/v1/runtime/me_quality` | No | ME pool snapshot unavailable | `enabled=true`, full payload |
| `/v1/runtime/upstream_quality` | No | Upstream runtime snapshot unavailable | `enabled=true`, full payload |
| `/v1/runtime/nat_stun` | No | STUN shared state unavailable | `enabled=true`, full payload |
| `/v1/runtime/me-selftest` | No | ME pool unavailable => `enabled=false`, `reason=source_unavailable` | `enabled=true`, full payload |
| `/v1/runtime/connections/summary` | `runtime_edge_enabled=false` => `enabled=false`, `reason=feature_disabled` | Recompute lock contention with no cache entry => `enabled=true`, `reason=source_unavailable` | `enabled=true`, full payload |
| `/v1/runtime/events/recent` | `runtime_edge_enabled=false` => `enabled=false`, `reason=feature_disabled` | Not used in current implementation | `enabled=true`, full payload |

## ME Fallback Behavior Exposed Via API

When `general.use_middle_proxy=true` and `general.me2dc_fallback=true`:
- Startup does not block on full ME pool readiness; initialization can continue in background.
- Runtime initialization payload can expose ME stage `background_init` until pool becomes ready.
- Admission/routing decision uses two readiness grace windows for "ME not ready" periods:
  `80s` before first-ever readiness is observed (startup grace),
  `6s` after readiness has been observed at least once (runtime failover timeout).
- While in fallback window breach, new sessions are routed via Direct-DC; when ME becomes ready, routing returns to Middle mode for new sessions.

## Serialization Rules

- Success responses always include `revision`.
- Error responses never include `revision`; they include `request_id`.
- Optional fields with `skip_serializing_if` are omitted when absent.
- Nullable payload fields may still be `null` where contract uses `?` (for example `UserInfo` option fields).
- For `/v1/stats/upstreams`, authentication details of SOCKS upstreams are intentionally omitted.
- `ip[]` fields are serialized as JSON string arrays (for example `"1.2.3.4"`, `"2001:db8::1"`).

## Operational Notes

| Topic | Details |
| --- | --- |
| API startup | API listener is spawned only when `[server.api].enabled=true`. |
| `listen` port `0` | API spawn is skipped when parsed listen port is `0` (treated as disabled bind target). |
| Bind failure | Failed API bind logs warning and API task exits (no auto-retry loop). |
| ME runtime status endpoints | `/v1/stats/me-writers`, `/v1/stats/dcs`, `/v1/stats/minimal/all` require `[server.api].minimal_runtime_enabled=true`; otherwise they return disabled payload with `reason=feature_disabled`. |
| Upstream runtime endpoint | `/v1/stats/upstreams` always returns `zero`, but runtime fields (`summary`, `upstreams`) require `[server.api].minimal_runtime_enabled=true`. |
| Restart requirements | `server.api` changes are restart-required for predictable behavior. |
| Hot-reload nuance | A pure `server.api`-only config change may not propagate through watcher broadcast; a mixed change (with hot fields) may propagate API flags while still warning that restart is required. |
| Runtime apply path | Successful writes are picked up by existing config watcher/hot-reload path. |
| Exposure | Built-in TLS/mTLS is not provided. Use loopback bind + reverse proxy if needed. |
| Pagination | User list currently has no pagination/filtering. |
| Serialization side effect | Updated TOML table bodies are re-serialized on write. Endpoints that persist full config can still rewrite broader formatting/comments. |

## Known Limitations (Current Release)

- `POST /v1/users/{username}/rotate-secret` is currently unreachable in route matcher and returns `404`.
- API runtime controls under `server.api` are documented as restart-required; hot-reload behavior for these fields is not strictly uniform in all change combinations.
