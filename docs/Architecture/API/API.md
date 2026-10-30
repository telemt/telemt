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
| `request_body_limit_bytes` | `usize` | `65536` | Maximum request body size. Must be within `[1, 1048576]`. |
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
- `server.api.request_body_limit_bytes` must be within `[1, 1048576]`.
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
| Revision format | SHA-256 hex of the canonical recursive source manifest: normalized source paths plus each source's raw bytes. Formatting, comments, and path changes therefore change the revision. |

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
- `Authorization` check is exact constant-time byte equality against configured `auth_header`.

## Endpoint Matrix

| Method | Path | Body | Success | `data` contract |
| --- | --- | --- | --- | --- |
| `GET` | `/v1/health` | none | `200` | `HealthData` |
| `GET` | `/v1/health/ready` | none | `200` or `503` | `HealthReadyData` |
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
| `GET` | `/v1/runtime/tls-fingerprints` | optional `limit=1..1000` | `200` | `RuntimeEdgeTlsFingerprintsData` |
| `GET` | `/v1/runtime/web/status` | none | `200` | `WebStatusData` |
| `GET` | `/v1/runtime/web/sessions` | bounded query | `200` | `SessionPage` |
| `GET` | `/v1/runtime/web/sessions/{session_ref}` | none | `200` or `410` | `SessionRow` or closed tombstone |
| `POST` | `/v1/runtime/web/sessions/close` | `CloseRequest` | `202` | `ControlOperationStatus` |
| `GET` | `/v1/runtime/web/operations/{operation_id}` | none | `200` | `ControlOperationStatus` |
| `POST` | `/v1/runtime/web/debug/clear` | `RuntimeInstanceRequest` | `200` | `DebugClearData` |
| `POST` | `/v1/runtime/web/carrier-learning/reset` | `RuntimeInstanceRequest` | `200` | `LearningResetData` |
| `POST` | `/v1/runtime/web/lifecycle/pause` | `RuntimeInstanceRequest` | `200` | `OperatorLifecycleStatus` |
| `POST` | `/v1/runtime/web/lifecycle/drain` | `DrainRequest` | `202` | `OperatorLifecycleStatus` |
| `POST` | `/v1/runtime/web/lifecycle/resume` | `RuntimeInstanceRequest` | `200` | `OperatorLifecycleStatus` |
| `GET` | `/v1/stats/users/active-ips` | none | `200` | `UserActiveIps[]` |
| `GET` | `/v1/stats/users` | none | `200` | `UserInfo[]` |
| `GET` | `/v1/stats/users/quota` | none | `200` | User quota counters and recurring schedule status in `data.users`. |
| `GET` | `/v1/config` | none | `200` | `ConfigData` |
| `PATCH` | `/v1/config` | sparse JSON object; optional reload query | `200` or `202` | `PatchConfigResponse` |
| `POST` | `/v1/system/reload` | `ReloadRequest` or empty body | `202` | `ReloadAccepted` |
| `GET` | `/v1/system/reload/{id}` | none | `200` | `ReloadStatus` |
| `GET` | `/v1/users` | none | `200` | `UserInfo[]` |
| `POST` | `/v1/users` | `CreateUserRequest` | `201` or `202` | `CreateUserResponse` |
| `GET` | `/v1/users/{username}` | none | `200` | `UserInfo` |
| `PATCH` | `/v1/users/{username}` | `PatchUserRequest` | `200` or `202` | `UserInfo` |
| `DELETE` | `/v1/users/{username}` | none | `200` or `202` | `DeleteUserResponse` |
| `POST` | `/v1/users/{username}/rotate-secret` | `RotateSecretRequest` or empty body | `200` or `202` | `CreateUserResponse` |
| `POST` | `/v1/users/{username}/enable` | empty body | `200` or `202` | `UserInfo` |
| `POST` | `/v1/users/{username}/disable` | empty body | `200` or `202` | `UserInfo` |
| `POST` | `/v1/users/{username}/reset-quota` | empty body | `200` | `ResetUserQuotaResponse` |

## Endpoint Behavior

| Endpoint | Function |
| --- | --- |
| `GET /v1/health` | Returns basic API liveness and current `read_only` flag. |
| `GET /v1/health/ready` | Returns readiness based on admission state and upstream health; returns `503` when not ready. |
| `GET /v1/system/info` | Returns binary/build metadata, process uptime, config path/hash, and reload counters. |
| `GET /v1/runtime/gates` | Returns admission, ME readiness, fallback/reroute, and startup gate state. |
| `GET /v1/runtime/initialization` | Returns startup progress, ME initialization status, and per-component timeline. |
| `GET /v1/limits/effective` | Returns effective timeout, upstream, ME, unique-IP, and TCP policy values after config defaults/resolution. |
| `GET /v1/security/posture` | Returns current API/security/telemetry posture flags. |
| `GET /v1/security/whitelist` | Returns configured API whitelist CIDRs. |
| `GET /v1/stats/summary` | Returns compact core counters and classed failure counters. |
| `GET /v1/stats/zero/all` | Returns zero-cost core, upstream, ME, pool, and desync counters. |
| `GET /v1/stats/upstreams` | Returns upstream zero counters and, when enabled/available, runtime upstream health rows. |
| `GET /v1/stats/minimal/all` | Returns cached minimal ME writer/DC/runtime/network-path snapshot. |
| `GET /v1/stats/me-writers` | Returns cached ME writer coverage and per-writer status rows. |
| `GET /v1/stats/dcs` | Returns cached per-DC endpoint/writer/load status rows. |
| `GET /v1/runtime/me_pool_state` | Returns active/warm/pending/draining generation state, writer contour/health, and refill state. |
| `GET /v1/runtime/me_quality` | Returns ME lifecycle counters, route-drop counters, family states, drain gate, and per-DC RTT/coverage. |
| `GET /v1/runtime/upstream_quality` | Returns upstream policy/counters plus runtime upstream health rows when available. |
| `GET /v1/runtime/nat_stun` | Returns NAT/STUN runtime flags, configured/live STUN servers, reflection cache, and backoff. |
| `GET /v1/runtime/me-selftest` | Returns ME self-test state for KDF, time skew, IP family, PID, and SOCKS BND observations. |
| `GET /v1/runtime/connections/summary` | Returns runtime-edge connection totals and top-N users by connections/throughput. |
| `GET /v1/runtime/events/recent` | Returns recent API/runtime event records with optional `limit` query. |
| `GET /v1/runtime/web/status` | Returns WEB listener lifecycle and a non-blocking, plane-local snapshot of the process-owned WEB runtime when available. |
| `GET /v1/runtime/web/sessions` | Returns a bounded ordered page of live WEB sessions with strict filters and opaque process-fenced references. |
| `GET /v1/runtime/web/sessions/{session_ref}` | Returns one exact live-session snapshot or a retained closed-session tombstone. |
| `POST /v1/runtime/web/sessions/close` | Accepts one bounded asynchronous point-in-time close operation. |
| `GET /v1/runtime/web/operations/{operation_id}` | Returns one of the 32 most recently retained WEB close-operation states. |
| `POST /v1/runtime/web/debug/clear` | Clears the bounded WEB debug ring under an epoch fence. |
| `POST /v1/runtime/web/carrier-learning/reset` | Clears process-local carrier-learning evidence without changing live attempt chains. |
| `POST /v1/runtime/web/lifecycle/pause` | Ephemerally closes new WEB work admission without closing existing sessions or streams. |
| `POST /v1/runtime/web/lifecycle/drain` | Starts one asynchronous graceful WEB drain under a bounded monotonic deadline. |
| `POST /v1/runtime/web/lifecycle/resume` | Cancels an active drain, if any, and reopens only the operator-owned admission fence. |
| `GET /v1/stats/users/active-ips` | Returns users that currently have non-empty active source-IP lists. |
| `GET /v1/stats/users` | Alias of `GET /v1/users`; returns disk-first user views with runtime lag flag. |
| `GET /v1/config` | Returns the current editable config sections as JSON (no `access.*`) plus the revision. |
| `PATCH /v1/config` | Applies a sparse patch and optionally submits an in-process runtime reload to Maestro. |
| `POST /v1/system/reload` | Loads and validates the current on-disk config, then asks Maestro to prepare and activate a new runtime generation. |
| `GET /v1/system/reload/{id}` | Returns one retained reload status; the coordinator retains the most recent 32 operations. |
| `GET /v1/users` | Returns disk-first user views sorted by username. |
| `POST /v1/users` | Creates a user and returns the effective user view plus secret. |
| `GET /v1/users/{username}` | Returns one disk-first user view or `404` when absent. |
| `PATCH /v1/users/{username}` | Updates selected per-user fields with JSON Merge Patch semantics. |
| `DELETE /v1/users/{username}` | Deletes one user and related API-managed per-user access-map entries. It does not modify `access.user_source_deny`. |
| `POST /v1/users/{username}/rotate-secret` | Rotates one user's secret and returns the effective secret. |
| `POST /v1/users/{username}/enable` | Enables one user, removing any disabled override from config. |
| `POST /v1/users/{username}/disable` | Disables one user and closes active runtime sessions for that user. |
| `POST /v1/users/{username}/reset-quota` | Persists the quota checkpoint before resetting one user's live accounting. |

## Common Error Codes

| HTTP | `error.code` | Trigger |
| --- | --- | --- |
| `400` | `bad_request` | Invalid JSON, validation failures, malformed request body. |
| `400` | `access_not_editable` | `PATCH /v1/config` body contains an `access` key (managed via users API). |
| `400` | `section_not_editable` | `PATCH /v1/config` body contains `network` or an unknown top-level key. |
| `400` | `field_not_editable` | `PATCH /v1/config` body contains a forbidden nested field under a partially editable section (e.g. `server.api`, `server.port`). |
| `401` | `unauthorized` | Missing/invalid `Authorization` when `auth_header` is configured. |
| `403` | `forbidden` | Source IP is not allowed by whitelist. |
| `403` | `read_only` | Mutating endpoint called while `read_only=true`. |
| `404` | `not_found` | Unknown route, unknown user, or unsupported sub-route. |
| `405` | `method_not_allowed` | Unsupported method for `/v1/users/{username}` route shape. |
| `409` | `revision_conflict` | `If-Match` mismatch, or the source graph/owner changed during a fenced write. |
| `409` | `reload_in_progress` | Another reload operation is non-terminal. |
| `409` | `web_runtime_mismatch` | A runtime instance, session reference, or operation reference belongs to another WEB process instance. |
| `409` | `web_issuance_enabled` | A WEB close-all operation was requested while effective issuance remained enabled. |
| `409` | `web_operation_in_progress` | Another bounded WEB close operation is active. |
| `409` | `web_lifecycle_in_progress` | Another WEB drain operation is active. |
| `409` | `user_exists` | User already exists on create. |
| `409` | `last_user_forbidden` | Attempt to delete last configured user. |
| `413` | `payload_too_large` | Body exceeds `request_body_limit_bytes`. |
| `415` | `unsupported_media_type` | A WEB runtime POST does not carry exactly one `Content-Type: application/json` header. |
| `410` | success envelope | A valid WEB session reference resolves to a retained closed-session tombstone. |
| `500` | `internal_error` | Internal error (I/O, serialization, config load/save). |
| `503` | `api_disabled` | API disabled in config. |
| `503` | `maestro_unavailable` | Maestro's reload command channel is unavailable. |
| `503` | `web_runtime_unavailable` | The WEB runtime is not running or has left the readable lifecycle. |
| `503` | `web_snapshot_busy` | An exact non-blocking WEB session snapshot encountered lock contention. |

## Routing and Method Edge Cases

| Case | Behavior |
| --- | --- |
| Path matching | Exact match on `req.uri().path()`. Query string does not affect route matching. |
| Trailing slash | Trimmed for route matching when path length is greater than 1. Example: `/v1/users/` matches `/v1/users`. |
| Username route with extra slash | `/v1/users/{username}/...` is not treated as user route and returns `404`. |
| `DELETE /v1/config` (or any method not in `GET`, `PATCH`) | `405 method_not_allowed` with `Allow: GET, PATCH`. |
| `PUT /v1/users/{username}` | `405 method_not_allowed`. |
| `POST /v1/users/{username}` | `404 not_found`. |
| `POST /v1/users/{username}/rotate-secret/` | Trailing slash is trimmed and the route matches `rotate-secret`. |
| `POST /v1/users/{username}/enable/` | Trailing slash is trimmed and the route matches `enable`. |
| `POST /v1/users/{username}/disable/` | Trailing slash is trimmed and the route matches `disable`. |
| `POST /v1/users/{username}/reset-quota/` | Trailing slash is trimmed and the route matches `reset-quota`. |

## Body and JSON Semantics

- Request body is read only for mutating routes that define a body contract.
- Body size limit is enforced during streaming read (`413 payload_too_large`).
- Invalid transport body frame returns `400 bad_request` (`Invalid request body`).
- Invalid JSON returns `400 bad_request` (`Invalid JSON body`).
- `Content-Type` is not required for existing config/user/reload JSON parsing. Every WEB runtime POST requires exactly one header with the exact value `application/json`.
- Existing request DTOs retain their documented unknown-field behavior. WEB runtime POST DTOs reject unknown JSON fields.
- `PATCH` uses JSON Merge Patch semantics for optional per-user fields: omitted means unchanged, explicit `null` removes the config entry, and a non-null value sets it.
- `If-Match` supports both quoted and unquoted values; surrounding whitespace is trimmed.

## Query Parameters

| Endpoint | Query | Behavior |
| --- | --- | --- |
| `GET /v1/runtime/events/recent` | `limit=<usize>` | Optional. Invalid/missing value falls back to default `50`. Effective value is clamped to `[1, 1000]` and additionally bounded by ring-buffer capacity. |
| `GET /v1/runtime/web/sessions` | `limit`, `cursor`, `session_ref`, `ip`, `host`, `user`, `user_agent_id`, `key_id`, `carrier`, `state` | `limit` defaults to 50 and is bounded to `1..=200`; the ordered candidate scan stops at 1000. Duplicate and unknown fields are rejected. `session_ref` selects an exact logical session and cannot be combined with `cursor` or `limit`. |

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
| `quota_period` | `string` or `null` | no | `daily`, `weekly`, or `monthly`; requires a positive quota. Missing/null means no recurring reset. |
| `rate_limit_up_bps` | `u64` | no | Per-user upload rate limit in bits per second. |
| `rate_limit_down_bps` | `u64` | no | Per-user download rate limit in bits per second. |
| `max_unique_ips` | `usize` | no | Per-user unique source IP limit. |
| `enabled` | `bool` | no | User enable flag. Missing means enabled. `false` persists a disabled override. |

### `PatchUserRequest`
| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `secret` | `string` | no | Exactly 32 hex chars. |
| `user_ad_tag` | `string` or `null` | no | Exactly 32 hex chars; `null` removes the per-user ad tag. |
| `max_tcp_conns` | `usize` or `null` | no | Per-user concurrent TCP limit; `null` removes the per-user override. |
| `expiration_rfc3339` | `string` or `null` | no | RFC3339 expiration timestamp; `null` removes the expiration. |
| `data_quota_bytes` | `u64` or `null` | no | Per-user traffic quota; `null` removes the per-user quota. Remove `quota_period` in the same request if one is configured. |
| `quota_period` | `string` or `null` | no | `daily`, `weekly`, or `monthly`. Omitted preserves the setting; `null` removes it. Requires a positive resulting quota. |
| `rate_limit_up_bps` | `u64` or `null` | no | Per-user upload rate limit in bits per second; `null` removes the upload direction limit. |
| `rate_limit_down_bps` | `u64` or `null` | no | Per-user download rate limit in bits per second; `null` removes the download direction limit. |
| `max_unique_ips` | `usize` or `null` | no | Per-user unique source IP limit; `null` removes the per-user override. |
| `enabled` | `bool` or `null` | no | `false` disables the user. `true` or `null` removes the disabled override, so the user is enabled. |

### `access.user_source_deny` via API
- In current API surface, per-user deny-list is **not** exposed as a dedicated field in `CreateUserRequest` / `PatchUserRequest`.
- Configure it in `config.toml` under `[access.user_source_deny]` and apply via normal config reload path.
- Runtime behavior after apply:
  - auth succeeds for username/secret
  - source IP is checked against `access.user_source_deny[username]`
  - on match, handshake is rejected with the same fail-closed outcome as invalid auth

Example config:
```toml
[access.user_source_deny]
alice = ["203.0.113.0/24", "2001:db8:abcd::/48"]
bob = ["198.51.100.42/32"]
```

### `PatchConfigRequest`

A sparse JSON object containing only the top-level config sections to modify. Each key must be one of the editable sections (`general`, `timeouts`, `censorship`, `upstreams`, `dc_overrides`, `web`) or the partially editable `server` object (only `listeners` is allowed under `server`; see below). Tables within a section are deep-merged field-by-field into the existing config; arrays and scalar values replace the existing value wholesale. Untouched table bodies and other source files remain byte-identical; a touched TOML table body is reserialized, so comments and formatting inside it can change.

**Rejected keys:**
- `access` → `400 access_not_editable` (users/secrets are managed via `POST/PATCH /v1/users`).
- `network` or any unknown top-level key → `400 section_not_editable`.
- `server` with any key other than `listeners` (e.g. `port`, `api`, `admin_api`) → `400 field_not_editable`.
- An object with no editable keys → `400 bad_request` (empty patch).

Example — patch only the SNI domain:
```json
{"censorship": {"tls_domain": "front.example.com"}}
```

Example — replace `[[server.listeners]]` (other `[server]` fields including `[server.api]` are preserved):
```json
{"server": {"listeners": [{"ip": "0.0.0.0", "port": 443, "client_mss": "92"}]}}
```

### `RotateSecretRequest`
| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `secret` | `string` | no | Exactly 32 hex chars. If missing, generated automatically. |

An empty request body is accepted and generates a new secret automatically.

## Response Data Contracts

### `ConfigData`

Returned by `GET /v1/config` as the envelope `data`. The fields are exactly the editable TOML sections. The current revision is returned in the envelope `revision` field (same value as `config_hash` in `SystemInfoData`), **not** inside `data`.

| Field | Type | Description |
| --- | --- | --- |
| `general` | `object` | Complete normalized `[general]` section, including defaults. |
| `timeouts` | `object` | Complete normalized `[timeouts]` section, including defaults. |
| `censorship` | `object` | Complete normalized `[censorship]` section, including defaults. |
| `upstreams` | `object[]` | Complete normalized upstream array. When no upstream is authored, the loader inserts one enabled direct upstream. |
| `dc_overrides` | `object` | Complete normalized DC override map, including the synthesized DC 203 endpoint when it is not authored. |
| `web` | `object` | Complete normalized `[web]` section, including defaults. Each `web.vhosts[]` item preserves either `host` or `hosts` and includes `base_path` (empty string when omitted in TOML); hostname lists remain grouped. The derived runtime-only `web.runtime` field is excluded. |
| `server` | `object?` | Partial `[server]` view when editable nested fields are present. Currently only `listeners` may appear; `api`/`admin_api`, `port`, unix sockets, and other bind-identity fields are never returned. |

The editable typed sections are serialized from the fully defaulted configuration, even when omitted from the source files. Only the editable sections above are returned; `access` (users/secrets) and `network` (per-node addresses) are always excluded. Under `server`, only the nested field-level allowlist (`listeners`) is exposed, and an empty listener array is omitted. Changes to `web.allow_wildcard_hosts` and `[web.limits]` remain process-deferred; the patch response reports them in `deferred_process_fields` until restart. Wildcard patterns require the flag to be enabled in the active process; staging the flag does not authorize patterns before restart.

### WEB runtime identity and lifecycle

The WEB control plane is process-fenced. `runtime_instance` is a random 128-bit lowercase hexadecimal value created with the process-owned WEB runtime. Session references use `ws1.<runtime_instance>.<16-lowercase-hex-id>`, close-operation references use `wo1.<runtime_instance>.<16-lowercase-hex-id>`, and drain references use `wd1.<runtime_instance>.<16-lowercase-hex-id>`. Treat all references as opaque. A reference from another process instance returns `409 web_runtime_mismatch`, preventing an old controller from targeting reused counters after restart.

`GET /v1/config` is the desired on-disk configuration view. `GET /v1/runtime/web/status` is the effective process view. Its envelope `revision` still identifies the current source graph and can therefore be newer than the active runtime generation while a reload is pending.

`WebStatusData` contains:

| Field | Type | Description |
| --- | --- | --- |
| `lifecycle` | `string` | `starting`, `no_web_listener`, `running`, `draining`, `drained`, or `deadline_exceeded`. |
| `lifecycle_epoch` | `u64` | Monotonic publication epoch. |
| `lifecycle_age_ms` | `u64` | Monotonic age of the current lifecycle publication. |
| `available` | `bool` | Backward-compatible readable-runtime flag; it is not public TLS or private acceptor readiness. |
| `reason` | `string?` | Stable unavailability reason when `available=false`. |
| `listeners` | `string[]` | Effective bound WEB listener addresses. |
| `effective_config_enabled` | `bool` | `web.enabled` in the API request's active runtime generation. |
| `ingress` | `WebIngressStatus` | Process-owned listener/acceptor liveness and TCP accept counters. |
| `capacity` | `WebCapacityStatus` | Effective accepted-socket policy, fixed global resources, and typed rejection counters. |
| `decoy_upstream` | `WebDecoyUpstreamStatus` | Passive outcomes for Telemt's internal plain-HTTP decoy origin hop. |
| `decoy_fasttrack` | `WebDecoyFastTrackStatus` | Effective restart-frozen capability policy and fixed process-lifetime routing counters. |
| `carrier_negotiation` | `WebCarrierNegotiationStatus` | Fixed process-lifetime selection, reported-failure, and health/learning outcome counters. |
| `lifecycle_counters` | `WebLifecycleCountersStatus` | Fixed close-reason, post-gap observation, and bridge-recovery counters plus the effective recovery deadline. |
| `operator_lifecycle` | `OperatorLifecycleStatus?` | Process-local reversible admission and active/latest drain status while a runtime is published. |
| `runtime` | `WebRuntimeStatus?` | Present while the weak process-runtime publication can be upgraded. |

`WebIngressStatus` contains `configured_listeners`, `live_acceptors`, `accepting_connections`, optional `reason`, `tcp_accept_total`, and `tcp_accept_error_total`. Accepting requires lifecycle `running`, a readable runtime, at least one effective WEB listener, and one live accept loop per listener. Stable non-accepting reasons are `starting`, `no_web_listener`, `ingress_draining`, `ingress_drained`, `deadline_exceeded`, `runtime_released`, and `acceptor_unavailable`. Accept errors are `accept(2)` failures observed by Telemt; they are not kernel backlog drops or failed connection attempts that never reached the process.

`WebCapacityStatus` contains `http_connection_capacity_action`, `max_http_overload_connections`, `http_overload_timeout_ms`, fixed `resources`, `saturated_resources`, `partial`, `rejections`, and `http_connection_overload_outcomes`. Each resource has a closed-set `resource`, `unit`, `used`, `available`, `limit`, and terminal `closed` flag. Saturation is an instantaneous plane-local observation and never changes `available` or ingress readiness. Rejections are monotonic admission decisions indexed only by a closed reason enum; an internally retried queue or byte-budget decision may later make progress. Accepted-socket outcomes are `dropped`, `wait_admitted`, `wait_timeout_503`, `responded_503`, `overflow_capacity_drop`, `response_error_drop`, and `shutdown_drop`; `wait_admitted` is not a rejection.

`WebDecoyUpstreamStatus` contains the complete fixed outcome set plus optional `last_outcome` and `last_outcome_age_ms`. Outcomes distinguish `success`, `deadline_exhausted`, `connect_refused`, `connect_timeout`, `connect_error`, `http_handshake_timeout`, `http_handshake_error`, `response_head_timeout`, and `request_error`. This describes only Telemt to the configured decoy origin. A public client to NGINX refusal, or an NGINX to Telemt refusal before `accept(2)`, is outside this counter plane.

`WebDecoyFastTrackStatus` contains effective `mode` and the complete fixed `requests` disposition array. Dispositions are `shadow_would_fasttrack`, `shadow_candidate_full_scan`, `enforce_fasttrack`, and `enforce_candidate_full_scan`. `off` performs no fast-track counter writes. The complete set remains visible and retains its process-lifetime totals after runtime release because telemetry is process-owned.

`WebCarrierNegotiationStatus` remains present when the process runtime is unavailable because its counters belong to the WEB publication. `selections` is the complete carrier x disposition matrix (`profile_disabled`, `policy_disabled`, `policy_pending`, `epoch_exhausted`, `cold`, `applied`). `reported_failures` is the complete carrier x phase x canonical reason matrix, where phase is `provisional` or `committed` and reason is `timeout`, `network`, `upgrade`, `http`, or `protocol`. `learning_outcomes` distinguishes `recorded`, `not_eligible`, `policy_disabled`, `stale_epoch`, `capacity_rejected`, `sequence_exhausted`, `missing_chain`, `phase_mismatch`, `session_mismatch`, `owner_not_live`, and `closed_before_health`. Reported failures and rejection outcomes are diagnostic only and never create negative ranking evidence.

`WebLifecycleCountersStatus` always contains `bridge_recovery_secs`, the complete carrier x close-reason matrix, the complete carrier x lifecycle-observation matrix, and all recovery milestones. Close reasons are `client_delete`, `bridge_recovery`, `peer_idle`, `negotiation_timeout`, `carrier_superseded`, `protocol`, `backpressure`, `websocket_ended`, `api_close`, `operator_force`, and `runtime_shutdown`. Observations are `http_activity_after_gap`, `websocket_activity_after_gap`, and `request_after_close`. Recovery events are `bootstrap_issued`, `session_created`, `committed`, `expired_unused`, and `closed_before_commit`. All counters are process-owned, monotonic, fixed-cardinality, and remain present at zero while the runtime is unavailable.

`WebRuntimeStatus` includes `runtime_instance`, `generation_id`, immutable effective `limits`, manager/stream/budget/WebSocket/learning/debug planes, permit usage, task/counter totals, and `partial`. Plane locks are read with `try_lock`; a contended plane is omitted and named in `partial`. Status collection performs no cleanup, waits, or data-plane mutation, so fields are plane-local observations rather than one globally atomic snapshot. `runtime.manager.issuance_enabled` is the authority to check before close-all.

`OperatorLifecycleStatus` is a lock-free process snapshot with `state`, monotonic `epoch`, `age_ms`, `admission_open`, `effective_new_work_admission`, and the active or latest `drain`. States are `running`, `paused`, `draining`, `force_closing`, and `drained`. Drain status contains its opaque id, phase/outcome, frozen timeout, wall-clock correlation timestamps, latest session/stream/WebSocket remainder, and `force_close_signalled`. The response envelope `revision` remains a config source-graph revision and is not a lifecycle version.

The Prometheus endpoint exports the same process-owned observations through fixed-cardinality `telemt_web_*` families: ingress/operator lifecycle states, independent ingress flags, listener and TCP accept counts, resource usage/closure/saturation, typed rejection totals, accepted-socket overload outcomes, internal decoy-origin outcomes, and session/stream/carrier aggregate totals. Decoy routing adds `telemt_web_decoy_fasttrack_mode{mode}` and `telemt_web_decoy_fasttrack_requests_total{disposition}`. Carrier negotiation adds `telemt_web_carrier_selections_total{carrier,disposition}`, `telemt_web_carrier_reported_failures_total{carrier,phase,reason}`, `telemt_web_carrier_learning_outcomes_total{carrier,outcome}`, one-hot `telemt_web_carrier_learning_state{state}`, `telemt_web_carrier_learning_entries{kind}`, and one-hot `telemt_web_carrier_learning_policy{aggressiveness}`. Lifecycle recovery adds `telemt_web_session_closures_total{carrier,reason}`, `telemt_web_session_lifecycle_observations_total{carrier,observation}`, `telemt_web_bridge_recovery_events_total{event}`, and `telemt_web_bridge_recovery_seconds`. The learning states are `unavailable`, `partial`, `pending`, `exhausted`, `disabled`, and `enabled`; `pending` explicitly exposes a generation/policy publication mismatch instead of silently treating it as cold evidence. WEB labels never contain a host, user, client IP, listener address, token, session reference, profile key, runtime instance, or generation ID. Telemt does not claim health for the externally owned NGINX or HAProxy TLS endpoint; that boundary requires terminator telemetry and an external TCP/TLS probe.

### WEB session enumeration

`GET /v1/runtime/web/sessions` defaults to `limit=50`, permits `1..=200`, and scans at most 1000 ordered candidates. `next_cursor` continues after the last scanned opaque session reference. `scan_truncated` reports the scan bound, `partial_sessions` counts contended per-session snapshots, and `partial` names an unavailable manager plane. The complete serialized page remains below the API response envelope because every string and row count is bounded.

Filters are exact unless stated otherwise:

| Query field | Contract |
| --- | --- |
| `cursor`, `session_ref` | Canonical opaque reference for the current `runtime_instance`; `session_ref` forces one-row lookup semantics and is mutually exclusive with `cursor` and `limit`. |
| `ip` | Canonically formatted IPv4 or IPv6 address. |
| `host` | Non-empty, at most 253 bytes. |
| `user` | Non-empty, at most 64 bytes. |
| `user_agent_id` | Exactly 32 lowercase hexadecimal characters. |
| `key_id` | Exactly 16 lowercase hexadecimal characters; this is a non-secret domain-separated fingerprint. |
| `carrier` | `https`, `https-lanes`, `websocket`, or `websocket-lanes`. |
| `state` | `provisional`, `replacing`, `committed`, `healthy`, `closing`, `superseded`, or transient live-index `closed`. |

Each `SessionRow` contains `session_ref`, optional bounded `user_agent` and `user_agent_id`, plus client IP, host, user, key fingerprint, carrier/attempt/class/state, health publication, stream/task/lane/WebSocket counts, pending/control usage, progress idle time, authenticated peer idle time, frozen reconnect grace, remaining peer deadline, and optional negotiation time remaining. Server-only progress and empty long polls do not extend the authenticated peer deadline. No bootstrap token, session bearer, raw capability, configured secret/hash, or synthetic source/KDF port is returned. `GET /v1/runtime/web/sessions/{session_ref}` returns `200` for a live row, `410` with `state`, `attempt`, `carrier`, `reason`, and `closed_age_ms` for a bounded retained tombstone, `404` if unknown, or `503 web_snapshot_busy` on lock contention.

### WEB runtime mutations

Every WEB runtime POST requires the currently published `runtime_instance`, exactly one `Content-Type: application/json` header, no query parameters, and a JSON object with no unknown fields. All mutations inherit API authentication, direct-peer whitelist, body limit, audit recording, and `read_only` enforcement.

Operator lifecycle requests are:

```json
{"runtime_instance":"0123456789abcdef0123456789abcdef"}
```

for `POST /v1/runtime/web/lifecycle/pause` and `/resume`, and:

```json
{"runtime_instance":"0123456789abcdef0123456789abcdef","timeout_secs":30}
```

for `POST /v1/runtime/web/lifecycle/drain`, where `timeout_secs` is bounded to `1..=3600`. Pause and resume return `200`; drain freezes one monotonic absolute deadline and returns `202` without waiting for completion. A second drain while one is `draining` or `force_closing` returns `409 web_lifecycle_in_progress` and cannot alter the first deadline. Repeated pause/resume requests already satisfied by the current state are idempotent and do not advance the lifecycle epoch. Pause during an active drain leaves that drain running. Resume cancels an active drain and opens admission; if the deadline already committed its forced-close snapshot, those old session close signals remain effective.

Pause and drain block bootstrap issuance, initial/replacement session creation, and logical-stream admission. Exact session-creation replay, existing DATA/WINDOW/CLOSE, carrier polling/WebSocket exchanges, and explicit session DELETE remain available. Rejection does not consume bootstrap/session/stream rate or quota state: authenticated session creation returns retryable `503` with `Retry-After: 1`, while bridge issuance preserves the decoy route and a rejected logical `OPEN` receives a stream-local close.

Drain remains graceful until either all live sessions, logical-stream ownership, and session-owned WebSockets reach zero or its deadline fires. The deadline is the latest time to commit close signals, not a claim that cooperative task teardown is already complete. At the deadline every remaining live session receives an idempotent close signal outside manager locks, status becomes `force_closing`, and only confirmed zero publishes `drained` with outcome `forced`. Natural zero publishes outcome `graceful`. Both outcomes keep operator admission closed until explicit resume.

This lifecycle is ephemeral: it survives in-process generation reload because its authority is process-owned, is not written to configuration, and starts as `running` after process restart. Resume never overrides `web.enabled=false`, disabled-user policy, generation health admission, or terminal process shutdown. The global health/readiness and native TCP/Unix admission contracts are unchanged.

`POST /v1/runtime/web/sessions/close` accepts:

```json
{
  "runtime_instance": "0123456789abcdef0123456789abcdef",
  "selector": {
    "kind": "refs",
    "session_refs": ["ws1.0123456789abcdef0123456789abcdef.0000000000000001"]
  }
}
```

The selector is exactly one of:

- `refs`: `1..=200` unique current-instance session references.
- `filter`: at least one session filter using the same fields and bounds as enumeration.
- `all`: every session at or below the operation's submission high-water mark; rejected with `409 web_issuance_enabled` until effective issuance is disabled.

Only one close operation runs at a time. Work is chunked into at most 128 registry candidates between cancellation points, never awaits while holding a manager/session lock, and never targets sessions created above its high-water mark. `202` returns `ControlOperationStatus`; poll its `operation_id` through `GET /v1/runtime/web/operations/{operation_id}`. The process retains 32 statuses. Fields include `state` (`queued`, `running`, `completed`, `cancelled`, or `failed`), the high-water reference, requested/scanned/matched/signalled/conflicted counters, timestamps, and an optional sanitized failure token.

`POST /v1/runtime/web/debug/clear` and `POST /v1/runtime/web/carrier-learning/reset` both accept:

```json
{"runtime_instance":"0123456789abcdef0123456789abcdef"}
```

Debug clear swaps the retained ring under a new epoch and reports `records_cleared`, still-leased snapshot bytes, and `epoch`; old in-flight commits cannot restore removed data. Learning reset swaps bounded evidence under a new epoch and reports `entries_cleared` and `epoch`; live sessions and already frozen negotiation chains are unaffected.

Deterministic close-all sequence:

1. `PATCH /v1/config?reload=drain` with `{"web":{"enabled":false}}`.
2. Poll the accepted reload, then `GET /v1/runtime/web/status` until `runtime.manager.issuance_enabled=false`.
3. Submit the `all` close selector with the same status `runtime_instance`.
4. Poll the returned operation to a terminal state.

`web.enabled=false` only stops new bridge/bootstrap/session issuance. It never implicitly closes active WEB sessions.

### `PatchConfigResponse`

Returned by `PATCH /v1/config` on success (`200`, or `202` when a reload was accepted).

| Field | Type | Description |
| --- | --- | --- |
| `revision` | `string` | SHA-256 hex of the canonical recursive source manifest after the patch was written. |
| `restart_required` | `bool` | Legacy classifier result: `true` when the old file watcher alone cannot apply every changed field. Use `runtime_reload_required` and `process_restart_required` for new integrations. |
| `runtime_reload_required` | `bool` | `true` when effective runtime-owned state differs and must be activated. With a reload query an operation is enqueued; without one, supported hot fields may be applied by the file watcher. |
| `process_restart_required` | `bool` | `true` when a process-owned field changed and remains deferred after an in-process reload. |
| `deferred_process_fields` | `string[]` | Process-owned sockets, paths, capacities, or policies retained by the active process. |
| `changed` | `string[]` | Top-level section names that differed between the old and new config (e.g. `["censorship"]`). |
| `reload` | `ReloadAccepted?` | Present only when the patch included a valid reload query and Maestro accepted the operation. |

### `HealthData`
| Field | Type | Description |
| --- | --- | --- |
| `status` | `string` | Always `"ok"`. |
| `read_only` | `bool` | Mirrors current API `read_only` mode. |

### `HealthReadyData`
| Field | Type | Description |
| --- | --- | --- |
| `ready` | `bool` | `true` when admission is open and at least one upstream is healthy. |
| `status` | `string` | `"ready"` or `"not_ready"`. |
| `reason` | `string?` | `admission_closed` or `no_healthy_upstreams` when not ready. |
| `admission_open` | `bool` | Current admission-gate state. |
| `healthy_upstreams` | `usize` | Number of healthy upstream entries. |
| `total_upstreams` | `usize` | Number of configured upstream entries. |

### `SummaryData`
| Field | Type | Description |
| --- | --- | --- |
| `uptime_seconds` | `f64` | Process uptime in seconds. |
| `connections_total` | `u64` | Total accepted client connections. |
| `connections_bad_total` | `u64` | Failed/invalid client connections. |
| `connections_bad_by_class` | `ClassCount[]` | Failed/invalid connections grouped by class. |
| `handshake_failures_by_class` | `ClassCount[]` | Handshake failures grouped by class. |
| `handshake_timeouts_total` | `u64` | Handshake timeout count. |
| `configured_users` | `usize` | Number of configured users in config. |

#### `ClassCount`
| Field | Type | Description |
| --- | --- | --- |
| `class` | `string` | Failure class label. |
| `total` | `u64` | Counter value for this class. |

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
| `config_hash` | `string` | SHA-256 hash of the canonical recursive configuration source manifest (same value as envelope `revision`). |
| `config_reload_count` | `u64` | Number of successfully observed config updates since process start. |
| `last_config_reload_epoch_secs` | `u64?` | Unix epoch seconds of the latest observed config reload; null/absent before first reload. |

### `RuntimeGatesData`
| Field | Type | Description |
| --- | --- | --- |
| `accepting_new_connections` | `bool` | Current admission-gate state for new listener accepts. |
| `conditional_cast_enabled` | `bool` | Whether conditional ME admission logic is enabled (`general.use_middle_proxy`). |
| `me_runtime_ready` | `bool` | Current ME runtime readiness status used for conditional gate decisions. |
| `me2dc_fallback_enabled` | `bool` | Whether ME -> direct fallback is enabled. |
| `me2dc_fast_enabled` | `bool` | Whether fast ME -> direct fallback is enabled. |
| `use_middle_proxy` | `bool` | Current transport mode preference. |
| `route_mode` | `string` | Current route mode label from route runtime controller. |
| `reroute_active` | `bool` | `true` when ME fallback currently routes new sessions to Direct-DC. |
| `reroute_to_direct_at_epoch_secs` | `u64?` | Unix timestamp when current direct reroute began. |
| `reroute_reason` | `string?` | `startup_direct_fallback`, `fast_not_ready_fallback`, or `strict_grace_fallback` while reroute is active. |
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
| `user_tcp_policy` | `EffectiveUserTcpPolicyLimits` | Effective per-user TCP connection policy. |

#### `EffectiveTimeoutLimits`
| Field | Type | Description |
| --- | --- | --- |
| `client_handshake_secs` | `u64` | Client handshake timeout. |
| `client_first_byte_idle_secs` | `u64` | First-byte idle timeout before protocol classification. |
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
| `me2dc_fast` | `bool` | Effective fast fallback flag. |

#### `EffectiveUserIpPolicyLimits`
| Field | Type | Description |
| --- | --- | --- |
| `global_each` | `usize` | Global per-user unique-IP limit applied when no per-user override exists. |
| `mode` | `string` | Unique-IP policy mode (`active_window`, `time_window`, `combined`). |
| `window_secs` | `u64` | Time window length used by unique-IP policy. |

#### `EffectiveUserTcpPolicyLimits`
| Field | Type | Description |
| --- | --- | --- |
| `global_each` | `usize` | Global per-user concurrent TCP limit applied when no per-user override exists. |

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
| `warm_generations` | `u64[]` | All concurrently warming generation ids in ascending order. |
| `pending_hardswap_generation` | `u64` | Pending hardswap generation id (`0` when none). |
| `pending_hardswap_age_secs` | `u64?` | Age of pending hardswap generation in seconds. |
| `reinit_inflight` | `usize` | Generation warmups currently in flight. |
| `reinit_max_concurrency_effective` | `usize` | Effective bounded warmup concurrency. |
| `draining_generations` | `u64[]` | Distinct generation ids currently draining. |

#### `RuntimeMePoolStateHardswapData`
| Field | Type | Description |
| --- | --- | --- |
| `enabled` | `bool` | Hardswap feature toggle. |
| `pending` | `bool` | `true` when pending generation is non-zero. |
| `pending_writers_current` | `usize` | Authoritative warm writers owned by the pending generation. |
| `pending_writer_deficit` | `usize` | Writers still required to satisfy the pending generation floor. |
| `pending_missing_dc_groups` | `usize` | Desired DC-family groups below the pending generation floor. |
| `pending_map_current` | `bool?` | Whether the pending generation targets the current endpoint map; serialized as `null` when no comparison is available. |
| `orphan_warm_writers_current` | `usize` | Warm writers not owned by the pending generation. |
| `replacement_preparing_current` | `usize` | Writer replacements preparing a successor. |
| `replacement_retiring_current` | `usize` | Writer replacements retiring a predecessor. |

With no pending generation, `pending_map_current` is `null`. When it is `false`, the pending writer, deficit, and missing-group coverage fields are intentionally zero rather than computed against stale ownership. `orphan_warm_writers_current` counts non-draining Warm writers not owned by a current-map pending generation, so every Warm writer is orphaned when pending ownership is absent or stale. Replacement counts are independent of pending state.

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
| `running_dc_total` | `usize` | DC+family refill workers currently running. |
| `pending_dc_total` | `usize` | Running DC+family workers with one coalesced pending endpoint. |
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
| `family_states` | `RuntimeMeQualityFamilyStateData[]` | Per-family ME route/recovery state rows. |
| `drain_gate` | `RuntimeMeQualityDrainGateData` | Current ME drain-gate decision state. |
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

#### `RuntimeMeQualityFamilyStateData`
| Field | Type | Description |
| --- | --- | --- |
| `family` | `string` | Address family label. |
| `state` | `string` | Current family state label. |
| `state_since_epoch_secs` | `u64` | Unix timestamp when current state began. |
| `suppressed_until_epoch_secs` | `u64?` | Unix timestamp until suppression remains active. |
| `fail_streak` | `u32` | Consecutive failure count. |
| `recover_success_streak` | `u32` | Consecutive recovery success count. |

#### `RuntimeMeQualityDrainGateData`
| Field | Type | Description |
| --- | --- | --- |
| `route_quorum_ok` | `bool` | Whether route quorum condition allows drain. |
| `redundancy_ok` | `bool` | Whether redundancy condition allows drain. |
| `block_reason` | `string` | Current drain block reason label. |
| `updated_at_epoch_secs` | `u64` | Unix timestamp of the latest gate update. |

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
| `pid` | `RuntimeMeSelftestPidData` | Process PID marker (`one` or `non-one`). |
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
| `current_connections` | `u64` | Authoritative process-scoped live connections for the user across runtime generations. |
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

### `RuntimeEdgeTlsFingerprintsData`
| Field | Type | Description |
| --- | --- | --- |
| `enabled` | `bool` | Endpoint availability under `runtime_edge_enabled`. |
| `reason` | `string?` | `feature_disabled` when endpoint is disabled. |
| `generated_at_epoch_secs` | `u64` | Snapshot generation timestamp. |
| `data` | `RuntimeEdgeTlsFingerprintsPayload?` | Null when unavailable. |

#### `RuntimeEdgeTlsFingerprintsPayload`
| Field | Type | Description |
| --- | --- | --- |
| `limit` | `usize` | Effective Top-N row count. |
| `retention_secs` | `u64` | In-memory retention window, derived from `general.beobachten_minutes`. |
| `capacity` | `usize` | Maximum retained fingerprint buckets. |
| `dropped_total` | `u64` | Buckets dropped because the collector was full. |
| `parse_error_total` | `u64` | Complete ClientHello records that could not be fingerprinted. |
| `by_fingerprint` | `RuntimeEdgeTlsFingerprintRow[]` | Global JA3/JA4 leaderboard. |
| `by_ip` | `RuntimeEdgeTlsFingerprintRow[]` | Source-IP scoped leaderboard. |
| `by_cidr` | `RuntimeEdgeTlsFingerprintRow[]` | Source CIDR scoped leaderboard (`/24` for IPv4, `/56` for IPv6). |
| `by_user` | `RuntimeEdgeTlsFingerprintRow[]` | Authenticated user scoped leaderboard. |

#### `RuntimeEdgeTlsFingerprintRow`
| Field | Type | Description |
| --- | --- | --- |
| `scope` | `string?` | IP, CIDR, or username; absent in `by_fingerprint`. |
| `ja3` | `string` | JA3 MD5 hash. |
| `ja3_raw` | `string` | Raw JA3 field string. |
| `ja4` | `string` | JA4 TLS client fingerprint. |
| `ja4_raw` | `string` | Raw JA4 material used for the hashed parts. |
| `total` | `u64` | Complete ClientHello observations for this bucket. |
| `auth_success` | `u64` | TLS-authenticated observations for this bucket. |
| `bad_or_probe` | `u64` | Complete ClientHello observations later classified as bad/probe. |
| `first_seen_epoch_secs` | `u64` | First observation timestamp. |
| `last_seen_epoch_secs` | `u64` | Last observation timestamp. |

JA3 follows the Salesforce ClientHello field order. JA4 follows the FoxIO TLS-client `a_b_c` format; GREASE values are excluded and no high-cardinality Prometheus labels are emitted for fingerprints.

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
| `connections_bad_by_class` | `ClassCount[]` | Failed/invalid connections grouped by class. |
| `handshake_failures_by_class` | `ClassCount[]` | Handshake failures grouped by class. |
| `handshake_timeouts_total` | `u64` | Handshake timeouts. |
| `accept_permit_timeout_total` | `u64` | Listener admission permit acquisition timeouts. |
| `configured_users` | `usize` | Configured user count. |
| `telemetry_core_enabled` | `bool` | Core telemetry toggle. |
| `telemetry_user_enabled` | `bool` | User telemetry toggle. |
| `telemetry_me_level` | `string` | ME telemetry level (`silent`, `normal`, or `debug`). |
| `conntrack_control_enabled` | `bool` | Whether conntrack control is enabled by policy. |
| `conntrack_control_available` | `bool` | Whether conntrack control backend is currently available. |
| `conntrack_pressure_active` | `bool` | Current conntrack pressure flag. |
| `conntrack_event_queue_depth` | `u64` | Current conntrack close-event queue depth. |
| `conntrack_rule_apply_ok` | `bool` | Last conntrack rule application state. |
| `conntrack_rule_reconcile_success_total` | `u64` | Successful process-owned firewall reconciliations. |
| `conntrack_rule_reconcile_error_total` | `u64` | Failed process-owned firewall reconciliations. |
| `conntrack_rule_rollback_success_total` | `u64` | Successful rollback attempts after partial firewall application. |
| `conntrack_rule_rollback_error_total` | `u64` | Failed rollback attempts after partial firewall application. |
| `conntrack_delete_attempt_total` | `u64` | Conntrack delete attempts. |
| `conntrack_delete_success_total` | `u64` | Successful conntrack deletes. |
| `conntrack_delete_not_found_total` | `u64` | Conntrack delete misses. |
| `conntrack_delete_error_total` | `u64` | Conntrack delete errors. |
| `conntrack_close_event_drop_total` | `u64` | Dropped conntrack close events. |

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
| `handshake_error_code_overflow_total` | `u64` | Handshake rejects whose new error code exceeded the bounded 64-code breakdown. |
| `reader_eof_total` | `u64` | ME reader EOF events. |
| `idle_close_by_peer_total` | `u64` | Idle closes initiated by peer. |
| `route_drop_no_conn_total` | `u64` | Route drops due to missing bound connection. |
| `route_drop_channel_closed_total` | `u64` | Route drops due to closed channel. |
| `route_drop_queue_full_total` | `u64` | Route drops due to full queue (total). |
| `route_drop_queue_full_base_total` | `u64` | Route drops in base queue mode. |
| `route_drop_queue_full_high_total` | `u64` | Route drops in high queue mode. |
| `d2c_batches_total` | `u64` | ME D->C batch flushes. |
| `d2c_batch_frames_total` | `u64` | ME D->C frames included in batches. |
| `d2c_batch_bytes_total` | `u64` | ME D->C payload bytes included in batches. |
| `d2c_flush_reason_queue_drain_total` | `u64` | Flushes caused by queue drain. |
| `d2c_flush_reason_batch_frames_total` | `u64` | Flushes caused by frame-count batch limit. |
| `d2c_flush_reason_batch_bytes_total` | `u64` | Flushes caused by byte-count batch limit. |
| `d2c_flush_reason_max_delay_total` | `u64` | Flushes caused by max-delay budget. |
| `d2c_flush_reason_ack_immediate_total` | `u64` | Flushes caused by immediate ACK policy. |
| `d2c_flush_reason_close_total` | `u64` | Flushes caused by close path. |
| `d2c_data_frames_total` | `u64` | ME D->C data frames. |
| `d2c_ack_frames_total` | `u64` | ME D->C ACK frames. |
| `d2c_payload_bytes_total` | `u64` | ME D->C payload bytes. |
| `d2c_write_mode_coalesced_total` | `u64` | Coalesced D->C writes. |
| `d2c_write_mode_split_total` | `u64` | Split D->C writes. |
| `d2c_quota_reject_pre_write_total` | `u64` | D->C quota rejects before write. |
| `d2c_quota_reject_post_write_total` | `u64` | D->C quota rejects after write. |
| `d2c_frame_buf_shrink_total` | `u64` | D->C frame-buffer shrink operations. |
| `d2c_frame_buf_shrink_bytes_total` | `u64` | Bytes released by D->C frame-buffer shrink operations. |
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
| `warm_generations` | `u64[]` | All concurrently warming generation ids in ascending order. |
| `pending_hardswap_generation` | `u64` | Pending hardswap generation. |
| `pending_hardswap_age_secs` | `u64?` | Pending hardswap age in seconds. |
| `reinit_inflight` | `usize` | Generation warmups currently in flight. |
| `reinit_max_concurrency_effective` | `usize` | Effective bounded warmup concurrency. |
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
| `fresh_alive_writers` | `usize` | Alive writers that match freshness requirements. |
| `fresh_coverage_pct` | `f64` | `fresh_alive_writers / required_writers * 100`. |

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
| `matches_active_generation` | `bool` | Whether this writer belongs to the active pool generation. |
| `in_desired_map` | `bool` | Whether this writer's endpoint remains in desired topology. |
| `allow_drain_fallback` | `bool` | Whether drain fallback is allowed for this writer. |
| `drain_started_at_epoch_secs` | `u64?` | Unix timestamp when drain started. |
| `drain_deadline_epoch_secs` | `u64?` | Unix timestamp of drain deadline. |
| `drain_over_ttl` | `bool` | Whether drain has exceeded its TTL. |

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
| `fresh_alive_writers` | `usize` | Fresh alive writers in this DC. |
| `fresh_coverage_pct` | `f64` | `fresh_alive_writers / required_writers * 100`. |
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
| `enabled` | `bool` | Effective user enable flag. Missing config entry is reported as `true`. |
| `in_runtime` | `bool` | Whether current runtime config already contains this user. |
| `user_ad_tag` | `string?` | Optional ad tag (32 hex chars). |
| `max_tcp_conns` | `usize?` | Optional max concurrent TCP limit. |
| `expiration_rfc3339` | `string?` | Optional expiration timestamp. |
| `data_quota_bytes` | `u64?` | Optional data quota. |
| `quota_period` | `string?` | Desired recurring period from configuration; effective calendar state is available in the quota endpoint. |
| `rate_limit_up_bps` | `u64?` | Optional upload rate limit in bits per second. |
| `rate_limit_down_bps` | `u64?` | Optional download rate limit in bits per second. |
| `max_unique_ips` | `usize?` | Optional unique IP limit. |
| `current_connections` | `u64` | Authoritative process-scoped live connections for this user across runtime generations; independent of optional per-user telemetry. |
| `active_unique_ips` | `usize` | Current active unique source IPs. |
| `active_unique_ips_list` | `ip[]` | Current active unique source IP list. |
| `recent_unique_ips` | `usize` | Unique source IP count inside the configured recent window. |
| `recent_unique_ips_list` | `ip[]` | Recent-window unique source IP list. |
| `total_octets` | `u64` | Total traffic octets for this user. |
| `links` | `UserLinks` | Active connection links derived from current config. |

### `UserActiveIps`
| Field | Type | Description |
| --- | --- | --- |
| `username` | `string` | Username with at least one active tracked source IP. |
| `active_ips` | `ip[]` | Active source IPs for this user. |

#### `UserLinks`

`UserLinks` contains only native MTProxy links. It never contains a WEB `tg://webproxy` link; WEB links use a separate startup-only derivation contract based on every configured exact hostname selected by `web.vhosts[].host` or `hosts` (never a wildcard pattern), `base_path`, and profile secret mode.

| Field | Type | Description |
| --- | --- | --- |
| `classic` | `string[]` | Active `tg://proxy` links for classic mode. |
| `secure` | `string[]` | Active `tg://proxy` links for secure/DD mode. |
| `tls` | `string[]` | Active `tg://proxy` links for EE-TLS mode (for each host+TLS domain). |
| `tls_domains` | `TlsDomainLink[]` | Extra TLS-domain links as explicit domain/link pairs for `censorship.tls_domains`. |

#### `TlsDomainLink`
| Field | Type | Description |
| --- | --- | --- |
| `domain` | `string` | TLS domain represented by the link. |
| `link` | `string` | `tg://proxy` link for this domain. |

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

### `DeleteUserResponse`
| Field | Type | Description |
| --- | --- | --- |
| `username` | `string` | Deleted username. |
| `in_runtime` | `bool` | `true` when runtime config still contains the user and hot-reload has not applied deletion yet. |

### `ResetUserQuotaResponse`
| Field | Type | Description |
| --- | --- | --- |
| `username` | `string` | User whose runtime quota counter was reset. |
| `used_bytes` | `u64` | Current used bytes after reset; always `0` on success. |
| `last_reset_epoch_secs` | `u64` | Unix timestamp of the reset operation. |

### Recurring quota periods

`quota_period` is persisted in `[access.user_quota_periods]` through the existing
user create/PATCH routes and include-owner write rules. Generic `PATCH /v1/config`
continues to reject `access`. Invalid periods, missing/nonpositive quota amounts,
and inventories above 65,536 users with any period configured are rejected before
writing. A metadata-only change does not cancel sessions or rotate secrets.

`GET /v1/stats/users/quota` returns configured users with a positive quota only,
sorted by username. Its `data.users` entries contain the existing `username`,
`data_quota_bytes`, `used_bytes`, and `last_reset_epoch_secs`, plus:

| Field | Type | Meaning |
| --- | --- | --- |
| `quota_period` | `string?` | Desired `daily`, `weekly`, or `monthly` policy from configuration. |
| `active_quota_period` | `string?` | Effective durable calendar; null while runtime policy reconciliation awaits its checkpoint. |
| `quota_period_start_epoch_secs` | `u64?` | UTC boundary containing the effective monotonic calendar cursor. |
| `quota_next_reset_epoch_secs` | `u64?` | First boundary strictly after that cursor; may be in the past while overdue. |
| `quota_schedule_state` | `string` | `disabled`, `pending`, `active`, `overdue`, or `error`. |

`pending` covers unapplied desired configuration and accepted policies awaiting
durable publication. Before the runtime accepts a desired change, the old active
period can still be returned with `pending`. After acceptance, its active period
and boundary fields are null until the new metadata is durable. `error` means a
calendar/checkpoint attempt failed; consumption is not reset and cursors do not
advance, while ongoing traffic continues to accrue. `overdue` means the
next boundary has arrived and the durable reset has not completed. Status reads
share the quota mutation gate, so an in-flight commit can delay the response.

All periods use UTC: daily midnight, Monday midnight, or the first day of the
month. Enabling/changing a period preserves current usage. Removing a period
retains its watermark to prevent repeated resets after clock rollback. A manual
`POST /v1/users/{username}/reset-quota` advances the watermark through the accepted
reset time without changing cadence. Secret rotation preserves it; deletion and
recreation start fresh. Disabled or expired users still rotate quotas but are not
reenabled by a reset.

Before CREATE persists any new username, including one without a recurring quota, it durably removes any retired quota row
for that name. An unreadable checkpoint or failed durable write returns HTTP 500
without creating the user in configuration or live admission; retry after fixing
storage. The existing quota gate spans this cleanup and config publication. Other
users' persisted consumption and calendar metadata are preserved. An existing
checkpoint is rewritten even when that username has no row, confirming durability
after a possibly ambiguous earlier rename/sync failure. A missing checkpoint
needs no cleanup write.

One process worker checkpoints due users as a batch before resetting live
accounting generations. Existing reservations stay in their original generation;
late refunds cannot subtract new-period usage. No TLS, MTProto, KDF, relay limit,
or lifetime telemetry semantics change. I/O failures do not reset consumption or
advance cursors; traffic continues to accrue. Retries run at 1, 2, 4, 8, 16, 32,
then 60 seconds. After downtime, only the latest due period is
applied. The worker finishes accepted writes cooperatively before final shutdown
persistence. Config and quota-state files remain separate durable writes, not a
cross-file transaction.

With recurring policies, invalid existing quota state fails startup. Missing state
initializes fresh counters; legacy state migrates without resetting consumption.
Startup also requires successful durable publication of the initial state, even
when the checkpoint was valid or missing.
The existing 16 MiB checkpoint limit remains. There is no traffic write-ahead log,
so consumption since the previous checkpoint can still be lost on a crash.

## Config Endpoints

### `GET /v1/config`

Returns the current editable config sections as TOML-shaped JSON, plus the current revision. The `access` section (users and secrets) is always stripped and never appears in the response.

**Auth:** requires `Authorization` header when `auth_header` is configured (same as all other endpoints).

**Abridged success `200` response body:**
```json
{
  "ok": true,
  "data": {
    "censorship": {"tls_domain": "front.example.com"},
    "general": {"log_level": "normal"}
  },
  "revision": "<sha256-hex>"
}
```

The real `data` object contains every fully defaulted editable section; the example omits most fields for readability. The response is built from the validated, include-expanded configuration and may therefore contain normalized defaults or synthesized listeners that are absent from the root file. Only `GET` and `PATCH` are accepted; any other method returns `405 Method Not Allowed` with `Allow: GET, PATCH`.

---

### `PATCH /v1/config`

Applies a sparse patch to the editable config sections. The merged config is fully validated before writing; if validation fails the file is not modified.

**Auth:** requires `Authorization` header when `auth_header` is configured.

**Headers:**

| Header | Required | Description |
| --- | --- | --- |
| `Authorization` | when configured | Same token as all other endpoints. |
| `Content-Type: application/json` | recommended | Not enforced, but body must be valid JSON. |
| `If-Match: <revision>` | no | Optimistic concurrency. `<revision>` is the `revision` value from `GET /v1/config` or `config_hash` from `GET /v1/system/info`. It covers the complete recursive include graph. If supplied and it does not match the current source manifest, returns `409 revision_conflict`. Omitting it removes the caller precondition, but the internal graph/owner race fence can still return the same conflict. |

**Editable sections:** `general`, `timeouts`, `censorship`, `upstreams`, `dc_overrides`, `web`, plus partially editable `server` (only nested `listeners`).

**Rejected keys and their error codes:**

| Key | HTTP | `error.code` |
| --- | --- | --- |
| `access` | `400` | `access_not_editable` |
| `network` or any unknown top-level key | `400` | `section_not_editable` |
| `server` with keys other than `listeners` | `400` | `field_not_editable` |
| Object with no editable key | `400` | `bad_request` |

**Merge semantics:** tables are deep-merged field-by-field; arrays and scalar values replace the existing value wholesale. In particular, `web.vhosts` is an array: changing one vhost `base_path` requires sending the complete vhost array, including every retained vhost and each required hostname selector (`host` or non-empty `hosts`), `public_addr`, `decoy`, and profile field. A mutation is written to the single source file that owns every touched semantic section. Untouched table bodies, the root file when it is not the owner, and all other include files remain byte-identical; touched TOML table bodies are reserialized and may lose their internal formatting or comments. A target split across sources, a patch spanning multiple owners, or an include directive nested inside a TOML table returns `409 config_patch_not_atomic` without writing any file.

**Validation:** the merged config is deserialized into the full `ProxyConfig` type and validated before writing. Failures return `400` with a descriptive message; the file is not modified. WEB host selectors are mutually exclusive; duplicate normalized names are rejected across all groups. The effective configuration must fit active process limits: `max_vhosts` counts exact hostname entries and `max_profiles` counts exact host/profile pairs plus one shared profile set per wildcard source group. Wildcard selectors count toward `web.limits.wildcard.max_rules`. Raising desired restart-only limits in the same patch cannot bypass the active ceilings.

**Read-only mode:** returns `403 read_only` when the API runs with `read_only = true`.

**Optional in-process reload query:**

| Query | Required | Description |
| --- | --- | --- |
| `reload=instant` | no | Activates a new generation and cancels sessions owned by the previous generation. |
| `reload=drain` | no | Activates a new generation and lets old sessions finish until `timeout_secs`. |
| `timeout_secs=1..3600` | for `reload=drain` | Bounded old-generation drain interval. Invalid with `reload=instant`. |
| `failure_policy=keep_new\|rollback` | no | Defaults to `keep_new`. `rollback` applies only through the activation barrier, before old-generation teardown. |

Without a `reload` query parameter, the endpoint writes the patch and the file watcher applies only supported hot fields. With a reload query, coordinator capacity and status are reserved before the source file is replaced. Runtime-owned changes enqueue the validated immutable snapshot after the atomic write. A process-only patch is persisted with `200`, reports its deferred fields, and does not create a reload operation.

**Success `200` or `202` response body** (`data` field of the standard envelope):
```json
{
  "revision": "<new-sha256-hex>",
  "restart_required": true,
  "runtime_reload_required": true,
  "process_restart_required": false,
  "deferred_process_fields": [],
  "changed": ["censorship"],
  "reload": {
    "reload_id": 7,
    "target_generation": 2,
    "config_revision": "<new-sha256-hex>",
    "state": "accepted",
    "mode": "instant",
    "failure_policy": "keep_new"
  }
}
```

- `revision` — SHA-256 hex of the canonical source manifest after the write, including every recursive include path and its raw bytes.
- `restart_required` — legacy file-watcher classification retained for compatibility.
- `runtime_reload_required` — reports that effective runtime-owned state differs and needs activation. With an explicit reload query Telemt enqueues the immutable snapshot; otherwise the watcher may apply supported hot fields.
- `process_restart_required` and `deferred_process_fields` — report process-owned sockets, paths, capacities, or policies that remain unchanged by an in-process reload, including `web.decoy_fasttrack_mode`. A native-listener endpoint-only move is reloadable only when the complete WEB listener plan remains identical, every retained endpoint keeps identical bind policy, and neither the active nor desired listener set uses SYN limiting; same-address MSS, PROXY protocol, backlog, reuse, or SYN-limit changes remain deferred.
- `changed` — list of top-level section names that differed.
- `reload` — accepted operation metadata; omitted without a reload query and for process-only patches that cannot change the active generation.

Example — replace the complete vhost array while changing one `base_path`:

```json
{
  "web": {
    "vhosts": [{
      "host": "proxy.example.com",
      "base_path": "telegram/web",
      "public_addr": "203.0.113.10:443",
      "decoy": {"mode": "http_upstream", "upstream": "http://127.0.0.1:18081"},
      "profiles": [{"user": "web-user", "secret_mode": "dd"}]
    }]
  }
}
```

A valid base-path-only change reports `restart_required=false`, `runtime_reload_required=true`, `process_restart_required=false`, `deferred_process_fields=[]`, and `changed=["web"]`. An invalid path returns `400 bad_request`; no source file or active runtime state changes.

**Status codes:**

| HTTP | `error.code` | Condition |
| --- | --- | --- |
| `200` | — | Patch applied successfully. |
| `202` | — | Patch applied and runtime reload accepted. |
| `400` | `bad_request` | Invalid JSON, empty patch, or config validation/deserialization failure. |
| `400` | `access_not_editable` | Patch contains an `access` key. |
| `400` | `section_not_editable` | Patch contains `network` or an unknown top-level key. |
| `400` | `field_not_editable` | Patch contains a forbidden nested `server.*` field (anything other than `listeners`). |
| `401` | `unauthorized` | Missing or invalid `Authorization` header. |
| `403` | `read_only` | API is in read-only mode. |
| `405` | `method_not_allowed` | Method other than `GET` or `PATCH` used on `/v1/config`. |
| `409` | `revision_conflict` | `If-Match` does not match, or the source graph/owner changes during the fenced write. |
| `409` | `reload_in_progress` | Another runtime reload is active; the patch is not written. |
| `409` | `config_patch_not_atomic` | Touched semantic sections have multiple source owners or cannot be mutated as one source-file transaction. |
| `500` | `internal_error` | I/O or serialization failure. |

**curl example:**
```bash
# get current revision
curl -s -H "Authorization: <token>" http://127.0.0.1:<api>/v1/system/info | jq -r .config_hash

# patch the SNI domain with optimistic concurrency
curl -s -X PATCH -H "Authorization: <token>" -H "If-Match: <revision>" \
  -H "Content-Type: application/json" \
  -d '{"censorship":{"tls_domain":"front.example.com"}}' \
  'http://127.0.0.1:<api>/v1/config?reload=instant'
```

## Runtime Reload Endpoints

Prepared or delayed configuration snapshots cannot restore an older quota period
after a newer API user mutation, including period-only changes that preserve
credentials. Admission changes made after preparation remain authoritative during
activation.

### `POST /v1/system/reload`

Loads the current on-disk config under the API mutation lock and submits an immutable config snapshot to Maestro. `If-Match` is optional and uses the same revision contract as `PATCH /v1/config`. An empty body defaults to `{"mode":"instant","failure_policy":"keep_new"}`.

```json
{
  "mode": "drain",
  "timeout_secs": 30,
  "failure_policy": "rollback"
}
```

The endpoint returns `202` with `ReloadAccepted`. A concurrent non-terminal reload returns `409 reload_in_progress`. Config parsing or validation failure is reported before a command is submitted.

### `GET /v1/system/reload/{id}`

Returns `ReloadStatus` with `state` equal to `accepted`, `preparing`, `activating`, `draining`, `succeeded`, `rolled_back`, or `failed`. Terminal statuses include `finished_at_epoch_secs`; failures include `error`. Successful activation may include `warnings` for old-generation cleanup failures and `deferred_process_fields` for process-owned settings.

Runtime generation activation rebuilds statistics, upstream routing, replay and buffer state, TLS-front cache, IP tracking, admission/route state, and Middle-End orchestration. Per-user quota accounting is process-scoped and remains continuous across generations. A process-owned listener manager can prepare new endpoint sockets without calling `listen(2)`, stop removed acceptors before the runtime swap, and start new acceptors only after the swap. Inbound listener planning depends on normalized config and explicit IPv4/IPv6 policy, never transient outbound connectivity-probe results. Retained endpoints are not rebound, and unsupported same-address policy changes are overlaid with active values and reported as deferred. API, metrics, Unix listeners, PID ownership, and logging remain process-scoped. Maestro does not invoke systemd, containerd, or another process supervisor.

Reload preparation requires every configured TLS-front domain to have a non-default cached profile and requires a ready Middle-End pool when direct fallback is disabled. A candidate that does not satisfy either readiness condition fails without replacing the active generation.

The revision is verified again after preparation. With `failure_policy=rollback`, a changed revision or revision read failure rolls the candidate back; with `failure_policy=keep_new`, the condition is reported in `warnings` and activation continues.

## WEB Proxy Management

The API exposes WEB desired configuration through the common config resource, process state through `/v1/runtime/web`, and bounded read-only HTML diagnostics at `GET /web-status`. There is no separate `/v1/web` configuration resource.

| Operation | Current contract |
| --- | --- |
| Read or patch `[web]`, vhosts, profiles, decoys, timeouts, or limits | Supported through `GET` and `PATCH /v1/config`; `web.runtime` is derived and excluded. Tables deep-merge, arrays replace wholesale; changing one `web.vhosts[].base_path` therefore requires the complete vhost array. `web.allow_wildcard_hosts`, `web.limits`, and `web.decoy_fasttrack_mode` remain process-deferred. Patterns require wildcard mode to be active before the update. |
| Persist `server.listeners` | Supported through `PATCH /v1/config`; arrays replace wholesale. A native endpoint-only change may rebind in-process under the constraints above. Any WEB listener-plan change and unsupported native policy change remain deferred until process restart. |
| Apply an externally edited WEB config | Update the owning TOML source, call `POST /v1/system/reload`, then poll `GET /v1/system/reload/{id}`. |
| Inspect restart requirements | Read `deferred_process_fields` from reload status. Unsupported `server.listeners` changes, `web.allow_wildcard_hosts`, `web.limits`, and `web.decoy_fasttrack_mode` require process restart. |
| Inspect WEB lifecycle, capacity, sessions, operations, learning, and debug state | Use the authenticated `GET /v1/runtime/web/*` routes documented above. |
| Pause, drain, or resume new WEB work | Use `POST /v1/runtime/web/lifecycle/pause`, `/drain`, or `/resume` with the current `runtime_instance`. |
| Close selected or all point-in-time sessions | Use `POST /v1/runtime/web/sessions/close`; close-all first requires effective issuance to be disabled. |
| Clear debug records or reset carrier learning | Use `POST /v1/runtime/web/debug/clear` or `/carrier-learning/reset` with the current `runtime_instance`. |
| Manage access users | Use `/v1/users`. Creating a user does not add it to `web.vhosts.profiles`; add profile membership through the `web` config patch. |
| Disable one user | `POST /v1/users/{username}/disable` updates admission immediately and cancels the user's active sessions. |
| Rotate a profiled user's secret | Use `/v1/users/{username}/rotate-secret`; the durable credential identity is staged immediately and active owners for the old identity are cancelled. The config watcher rebuilds WEB capabilities from the new access snapshot. The API returns the raw secret, not a `tg://webproxy` link. |
| Read WEB-specific runtime diagnostics | Use authenticated `GET /web-status`; filters cover client IP, process session ID, User-Agent, and non-secret key fingerprint, with optional grouping, expandable HTTP request-to-response details, and WebSocket handshake/message/frame rows. |

`web.enabled`, `web.carrier`, `web.debug`, `web.timeouts`, vhosts, profiles, and decoy snapshots are runtime-generation fields. A changed carrier applies only to newly issued bridge sessions; existing sessions and issued bootstrap chains retain their issuance-time policy. `web.enabled=false` stops new issuance but never closes live sessions implicitly. WEB listener inventory and trust policy, plus `web.allow_wildcard_hosts` and all `[web.limits]`, are process-owned. A successful reload can therefore activate the runtime-owned subset while reporting the process-owned subset as deferred.

`base_path` scopes only the WEB data listener. It never prefixes Control API `/v1/*`, `/web-status`, or `/metrics`. `GET /v1/config` shows the desired path but does not prove runtime activation because WEB status intentionally exposes no host, path, or capability. Confirm a terminal reload, the expected `runtime.generation_id`, and external probes of the new and old exact routes. Paths and base paths are never Prometheus labels.

Before deleting a user referenced by a WEB profile, remove and apply the profile first. User mutations validate the complete resulting configuration, so a dangling WEB profile is rejected rather than persisted.

The API whitelist is evaluated against the direct TCP peer and does not use the WEB listener's `X-Forwarded-For` policy. `/web-status` inherits API enablement, whitelist, gray action, and exact authorization-header checks; it accepts only `GET`, normalizes a trailing slash, sets `no-store` and restrictive browser security headers, caps each page at 8 MiB, and permits at most two concurrent renderers. Keep the API on a separate loopback or private bind, use a narrow whitelist and a non-empty exact `auth_header`, and do not expose it through the public WEB vhost.

`window_secs` defaults to `[web.debug].default_window_secs = 180` and cannot exceed `max_window_secs`. The page can group by any combination of `ip`, `session`, `user_agent`, and `key`. Detail views retain policy-bounded HTTP method, sanitized headers, body, timing, and inner frames from request through response. For `websocket` and `websocket-lanes`, they additionally show the sanitized `GET` to `101` handshake and bounded per-message direction, type, payload/body capture, processing timing, connection/lane identifiers, and parsed inner frames. Raw query credentials, authorization values, WebSocket subprotocols, and session tokens are never retained.

Deployment, TLS-terminator examples, links, and WEB-specific verification are documented in the [WEB proxy guide](../../WEB/WEB_PROXY.en.md).

## Mutation Semantics

| Endpoint | Notes |
| --- | --- |
| `PATCH /v1/config` | Deep-merges and validates the patch, writes touched sections via atomic `tmp + rename`, and optionally submits the exact written revision for an in-process Maestro reload. |
| `POST /v1/users` | Before saving any new user, including one without a recurring quota, reads existing quota state and durably clears any retired row; read/write failure returns `500` without creating the user. Creates and validates a user, atomically updates only affected `access.*` TOML tables, then stages the credential and enabled state in process-wide admission after the durable write. |
| `PATCH /v1/users/{username}` | Partial update of provided fields only. Missing fields remain unchanged; explicit `null` removes optional entries. Admission is staged when `secret` or `enabled` is explicitly supplied, even if unchanged; an identity change or disable cancels current owners, while a metadata-only patch does not. Every accepted patch also fences quota policy freshness, including metadata-only or no-op patches. |
| `POST /v1/users/{username}/rotate-secret` | Replaces the user's secret with a provided valid 32-hex value or a generated value, stages the new process-wide admission identity, cancels owners of the old identity, then returns the effective secret in `CreateUserResponse`. |
| `POST /v1/users/{username}/enable` | Enables the user idempotently by removing the `access.user_enabled[username]` override and updating the runtime admission state immediately. |
| `POST /v1/users/{username}/disable` | Disables the user idempotently by writing `access.user_enabled[username] = false`, updating runtime admission immediately, and cancelling active sessions for that username. |
| `POST /v1/users/{username}/reset-quota` | Persists the quota checkpoint to `general.quota_state_path` before resetting live accounting for the route username; does not modify user config. |
| `DELETE /v1/users/{username}` | Deletes only the specified user, removes it from API-managed optional `access.user_*` maps, blocks last-user deletion, stages a deletion tombstone that cancels active owners, and atomically updates only related API-managed `access.*` TOML tables. It leaves `access.user_source_deny` untouched; manage that table manually in TOML. |

All accepted durable config, user, and quota mutations:
- Respect `read_only` mode.
- Accept optional `If-Match` for optimistic concurrency.
- Return new `revision` after successful write.
- Continue to completion after the server has accepted the mutation even if the requesting client disconnects or cancels the HTTP request.
- Serialize through one process-local async mutation lock.
- Publish mandatory process-wide admission state only after the durable write; a stale runtime generation cannot overwrite a newer user mutation.
- Keep the mutation admission override authoritative until the matching active config-source value arrives; publications from older or non-active generations are rejected.

For Unix config and user source writes, Telemt additionally takes an advisory `flock` on the root source's sibling `.lock` file, rechecks the complete source-graph revision and owner contents, and replaces the owning source through a same-directory atomic rename. Every source involved must be a non-symlink regular file with one directory entry, at most 8 MiB, and unchanged while read. The replacement preserves the existing UID, GID, and mode, syncs the temporary file before rename, and attempts to sync the parent directory afterward. Rename is the commit boundary; a later directory-sync failure is logged as a durability warning and does not roll back the already committed mutation. External writers coordinate only if they honor the same sidecar lock. Quota-state persistence does not use this config-source rename path.

Docker deployment note:
- Mutating endpoints require `config.toml` to live inside a writable mounted directory.
- Do not mount `config.toml` as a single bind-mounted file when API mutations are enabled; atomic `tmp + rename` writes can fail with `Device or resource busy`.
- Mount the config directory instead, for example `./config:/etc/telemt:rw`, and start Telemt with `/etc/telemt/config.toml`.
- A read-only single-file mount remains valid only for read-only deployments or when `[server.api].read_only=true`.

Delete path cleanup guarantees:
- DELETE commits config and admission removal even if quota-checkpoint cleanup fails; the failure is logged. Recreating the username through CREATE still requires successful durable cleanup before saving the new account.
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
| `/v1/runtime/tls-fingerprints` | `runtime_edge_enabled=false` => `enabled=false`, `reason=feature_disabled` | Not used in current implementation | `enabled=true`, full payload |

## ME Fallback Behavior Exposed Via API

When `general.use_middle_proxy=true` and `general.me2dc_fallback=true`:
- Startup opens Direct-DC routing first, then initializes ME in background and switches new sessions to Middle mode after ME readiness is observed.
- Runtime initialization payload can expose ME stage `background_init` until pool becomes ready.
- Admission/routing decision uses two readiness grace windows for "ME not ready" periods:
  direct startup fallback before first-ever readiness is observed,
  `6s` after readiness has been observed at least once (runtime failover timeout).
- While fallback is active, new sessions are routed via Direct-DC; when ME becomes ready, routing returns to Middle mode. Direct sessions affected by the cutover are closed with the existing staggered delay so clients reconnect through the current route.

## Additional Runtime Metrics

The current runtime exports these additional bounded-cardinality families. All use closed labels except the explicitly capped per-user family described below:

- `telemt_me_hardswap_pending`, `telemt_me_hardswap_pending_age_seconds`, `telemt_me_hardswap_pending_writers_current`, `telemt_me_hardswap_pending_writer_deficit`, `telemt_me_hardswap_pending_missing_dc_groups`, `telemt_me_hardswap_pending_map_current`, and `telemt_me_hardswap_orphan_warm_writers_current` describe the authoritative pending generation. They render zero when ME telemetry is `silent` or the active ME snapshot is unavailable. Prometheus `pending_map_current=0` represents both no pending generation and a stale pending map, so pair it with `telemt_me_hardswap_pending`; the API distinguishes no pending generation with `null`.
- `telemt_me_hardswap_pending_reuse_total` is emitted at debug ME telemetry and counts reuse of matching pending ownership; `telemt_me_hardswap_pending_ttl_expired_total` is emitted at normal telemetry and counts 1800-second pending expiry.
- `telemt_me_writer_replacement_current{state="preparing"|"retiring"}` describes transactional writer replacement phases.
- `telemt_conntrack_rule_reconcile_total{result="success"|"error"}` and `telemt_conntrack_rule_rollback_total{result="success"|"error"}` describe process-owned firewall reconcile and best-effort rollback attempts.
- The conntrack reconcile/rollback counters and rate-limiter CAS samples render zero while core telemetry is disabled; conntrack control-state gauges continue to report their effective state.
- `telemt_rate_limiter_cas_retry_exhausted_total{scope,direction,operation}` uses the closed labels `scope=user|cidr`, `direction=up|down`, and `operation=reserve|refund`. Reserve exhaustion returns a zero grant without classifying it as configured throttling; refund exhaustion retains the charge. Neither outcome is a connection-drop counter.
- `telemt_user_connections_current{user}` uses the same authoritative process-scoped admission count as API `current_connections`; it does not reset at a runtime generation boundary. Its Prometheus samples are emitted only when user telemetry is enabled and remain bounded to 4096 tracked telemetry users; `/v1/users` rows and their process-scoped counts are independent of that optional telemetry.

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

- API runtime controls under `server.api` are documented as restart-required; hot-reload behavior for these fields is not strictly uniform in all change combinations.
