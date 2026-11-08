# Telemt Tuning Guide: Middle-End and Upstreams

This document describes the current runtime behavior for Middle-End (ME) and upstream routing based on:
- `src/config/types.rs`
- `src/config/defaults.rs`
- `src/config/load.rs`
- `src/transport/upstream.rs`

Defaults below are code defaults (used when a key is omitted), not necessarily values from `config.full.toml` examples.

## Middle-End Parameters

### 1) Core ME mode, NAT, and STUN

| Parameter | Type | Default | Constraints / validation | Runtime effect | Example |
|---|---|---:|---|---|---|
| `general.use_middle_proxy` | `bool` | `true` | none | Enables ME transport mode. If `false`, Direct mode is used. | `use_middle_proxy = true` |
| `general.proxy_secret_path` | `Option<String>` | `"proxy-secret"` | path may be `null` | Path to Telegram infrastructure proxy-secret file. | `proxy_secret_path = "proxy-secret"` |
| `general.middle_proxy_nat_ip` | `Option<IpAddr>` | `null` | valid IP when set | Manual public NAT IP override for ME address material. | `middle_proxy_nat_ip = "203.0.113.10"` |
| `general.middle_proxy_nat_probe` | `bool` | `true` | none | Enables ME NAT probing when ME mode and `network.stun_use` are both enabled. | `middle_proxy_nat_probe = true` |
| `general.stun_nat_probe_concurrency` | `usize` | `8` | must be `> 0` | Max parallel STUN probes during NAT discovery. | `stun_nat_probe_concurrency = 16` |
| `network.stun_use` | `bool` | `true` | none | Global STUN switch. If `false`, STUN probing is disabled. | `stun_use = true` |
| `network.stun_servers` | `Vec<String>` | built-in public pool | deduplicated + empty values removed | Primary STUN server list for NAT/public endpoint discovery. | `stun_servers = ["stun1.l.google.com:19302"]` |
| `network.stun_tcp_fallback` | `bool` | `true` | none | Enables TCP fallback path when UDP STUN is blocked. | `stun_tcp_fallback = true` |
| `network.http_ip_detect_urls` | `Vec<String>` | `ifconfig.me` + `api.ipify.org` | none | HTTP fallback for public IPv4 detection if STUN is unavailable. | `http_ip_detect_urls = ["https://api.ipify.org"]` |
| `general.stun_iface_mismatch_ignore` | `bool` | `false` | none | Reserved flag in current revision (not consumed by runtime path). | `stun_iface_mismatch_ignore = false` |
| `timeouts.me_one_retry` | `u8` | `12` | none | Fast reconnect attempts for single-endpoint DC cases. | `me_one_retry = 6` |
| `timeouts.me_one_timeout_ms` | `u64` | `1200` | none | Timeout per quick single-endpoint attempt (ms). | `me_one_timeout_ms = 1500` |

### 2) Pool size, keepalive, and reconnect policy

| Parameter | Type | Default | Constraints / validation | Runtime effect | Example |
|---|---|---:|---|---|---|
| `general.middle_proxy_pool_size` | `usize` | `8` | none | Non-enforcing compatibility/startup-log input; active writer targets come from the DC-family floor policy. | `middle_proxy_pool_size = 12` |
| `general.middle_proxy_warm_standby` | `usize` | `16` | none | Reserved compatibility field in current revision (no active runtime consumer). | `middle_proxy_warm_standby = 16` |
| `general.me_keepalive_enabled` | `bool` | `true` | none | Enables periodic ME keepalive/ping traffic. | `me_keepalive_enabled = true` |
| `general.me_keepalive_interval_secs` | `u64` | `8` | none | Base keepalive interval (seconds). | `me_keepalive_interval_secs = 20` |
| `general.me_keepalive_jitter_secs` | `u64` | `2` | none | Keepalive jitter to avoid synchronization bursts. | `me_keepalive_jitter_secs = 3` |
| `general.me_keepalive_payload_random` | `bool` | `true` | none | Randomizes keepalive payload bytes. | `me_keepalive_payload_random = true` |
| `general.me_warmup_stagger_enabled` | `bool` | `true` | none | Staggers extra ME warmup dials to avoid spikes. | `me_warmup_stagger_enabled = true` |
| `general.me_warmup_step_delay_ms` | `u64` | `500` | none | Base delay between warmup dial steps (ms). | `me_warmup_step_delay_ms = 300` |
| `general.me_warmup_step_jitter_ms` | `u64` | `300` | none | Additional random delay for warmup steps (ms). | `me_warmup_step_jitter_ms = 200` |
| `general.me_reconnect_max_concurrent_per_dc` | `u32` | `8` | none | Limits concurrent reconnect workers per DC in health recovery. | `me_reconnect_max_concurrent_per_dc = 12` |
| `general.me_reconnect_backoff_base_ms` | `u64` | `500` | none | Initial reconnect backoff (ms). | `me_reconnect_backoff_base_ms = 250` |
| `general.me_reconnect_backoff_cap_ms` | `u64` | `30000` | none | Maximum reconnect backoff (ms). | `me_reconnect_backoff_cap_ms = 10000` |
| `general.me_reconnect_fast_retry_count` | `u32` | `16` | none | Immediate retry budget before long backoff behavior. | `me_reconnect_fast_retry_count = 8` |
| `general.me_writer_byte_budget_bytes` | `usize` | `33570816` | multiple of `16384`; dynamic minimum for `max_client_frame`; maximum `268435456` | Bounded byte permits assigned to each ME writer's outbound staging queue. | `me_writer_byte_budget_bytes = 33570816` |

### 3) Reinit/hardswap, secret rotation, and degradation

| Parameter | Type | Default | Constraints / validation | Runtime effect | Example |
|---|---|---:|---|---|---|
| `general.hardswap` | `bool` | `true` | none | Enables generation-based ME hardswap strategy. | `hardswap = true` |
| `general.me_reinit_every_secs` | `u64` | `900` | must be `> 0` | Periodic ME reinit interval. | `me_reinit_every_secs = 600` |
| `general.me_reinit_singleflight` | `bool` | `true` | none | Serializes reinit cycles from all trigger sources. | `me_reinit_singleflight = true` |
| `general.me_reinit_max_concurrency` | `usize` | `2` | must be within `[1,8]`; effective value is `1` with singleflight | Bounds concurrent generation warmups; excess triggers coalesce into one rerun. | `me_reinit_max_concurrency = 2` |
| `general.me_reinit_trigger_channel` | `usize` | `64` | must be within `[1,4096]` | Bounds queued reinit trigger notifications in each runtime generation. | `me_reinit_trigger_channel = 64` |
| `general.me_reinit_coalesce_window_ms` | `u64` | `200` | none | Coalesces trigger bursts before one reinit cycle. | `me_reinit_coalesce_window_ms = 200` |
| `general.me_hardswap_warmup_delay_min_ms` | `u64` | `1000` | must be `<= me_hardswap_warmup_delay_max_ms` | Lower bound for hardswap warmup dial spacing. | `me_hardswap_warmup_delay_min_ms = 500` |
| `general.me_hardswap_warmup_delay_max_ms` | `u64` | `2000` | must be `> 0` | Upper bound for hardswap warmup dial spacing. | `me_hardswap_warmup_delay_max_ms = 1200` |
| `general.me_hardswap_warmup_extra_passes` | `u8` | `3` | must be within `[0,10]` | Additional warmup passes after base pass. | `me_hardswap_warmup_extra_passes = 2` |
| `general.me_hardswap_warmup_pass_backoff_base_ms` | `u64` | `500` | must be `> 0` | Base backoff between extra warmup passes. | `me_hardswap_warmup_pass_backoff_base_ms = 400` |
| `general.me_config_stable_snapshots` | `u8` | `2` | must be `> 0` | Number of identical ME config snapshots required before apply. | `me_config_stable_snapshots = 3` |
| `general.me_config_apply_cooldown_secs` | `u64` | `300` | none | Cooldown between applied ME map updates. | `me_config_apply_cooldown_secs = 120` |
| `general.proxy_secret_stable_snapshots` | `u8` | `2` | must be `> 0` | Number of identical proxy-secret snapshots required before rotation. | `proxy_secret_stable_snapshots = 3` |
| `general.proxy_secret_rotate_runtime` | `bool` | `true` | none | Enables runtime proxy-secret rotation. | `proxy_secret_rotate_runtime = true` |
| `general.proxy_secret_len_max` | `usize` | `256` | must be within `[32,4096]` | Upper limit for accepted proxy-secret length. | `proxy_secret_len_max = 512` |
| `general.update_every` | `Option<u64>` | `300` | if set: must be `> 0`; if `null`: legacy min fallback | Unified refresh interval for ME config + secret updater. | `update_every = 300` |
| `general.me_pool_drain_ttl_secs` | `u64` | `90` | none | Age threshold for prolonged-drain warnings and the lower-bound normalization of force-close timeout; it does not grant stale binds. | `me_pool_drain_ttl_secs = 120` |
| `general.me_bind_stale_mode` | `"never"`, `"ttl"`, or `"always"` | `"never"` | none | Controls whether new bindings may use draining stale writers for uncovered DC-family groups. | `me_bind_stale_mode = "never"` |
| `general.me_bind_stale_ttl_secs` | `u64` | `90` | none | Stale-bind eligibility window used only when `me_bind_stale_mode = "ttl"`; `0` disables TTL expiry for eligible draining writers. | `me_bind_stale_ttl_secs = 90` |
| `general.me_pool_min_fresh_ratio` | `f32` | `0.8` | must be within `[0.0,1.0]` | Minimum fresh DC-family coverage ratio required at commit. | `me_pool_min_fresh_ratio = 0.9` |
| `general.me_reinit_drain_timeout_secs` | `u64` | `90` | `0` uses the 300-second safety fallback; an effective value below the drain TTL is bumped to the TTL | Force-close timeout for draining stale writers. | `me_reinit_drain_timeout_secs = 0` |
| `general.auto_degradation_enabled` | `bool` | `true` | none | Reserved compatibility flag in current revision (no active runtime consumer). | `auto_degradation_enabled = true` |
| `general.degradation_min_unavailable_dc_groups` | `u8` | `2` | none | Reserved compatibility threshold in current revision (no active runtime consumer). | `degradation_min_unavailable_dc_groups = 2` |

A hardswap candidate is authoritative only for the same desired-map hash and endpoint revision. Repeated attempts reuse that pending generation for at most 1800 seconds; after the pending TTL a fresh generation is allocated. Commit revalidates authority and requires fresh DC-family coverage of at least `me_pool_min_fresh_ratio`. Missing groups block commit when `me_bind_stale_mode = "never"`; `ttl` or `always` may commit with policy-bounded stale fallback for those groups. Covered old writers may retire immediately, so hardswap is an atomic policy transition rather than a universal zero-drop guarantee.

Writer replacement uses a separate cancellation-safe `Open -> Preparing -> Retiring` state. `Preparing` prevents duplicate replacement work but still allows new binds. Under the registry binding guard, commit revalidates the victim, moves it to `Retiring` to block new binds, installs and publishes the successor, and starts draining the predecessor before releasing the guard. Dropping a reservation before that commit boundary restores `Open`.

Operators can observe pending age, writer count and deficit, missing DC groups, map currency, orphan warm writers, and replacement `preparing`/`retiring` phases through `/v1/runtime/me_pool_state`. The corresponding `telemt_me_hardswap_*` and `telemt_me_writer_replacement_current` gauges render zero when ME telemetry is `silent` or the active ME snapshot is unavailable. In Prometheus, pair `telemt_me_hardswap_pending_map_current` with `telemt_me_hardswap_pending`: zero map currency also represents no pending generation, while the API uses `null` for that case. Alert on a pending age approaching 1800 seconds, a persistent writer deficit or missing group count, a stale map, orphan warm writers, or replacement phases that do not converge.

## Deprecated / Legacy Parameters

| Parameter | Status | Replacement | Current behavior | Migration recommendation |
|---|---|---|---|---|
| `general.middle_proxy_nat_stun` | Deprecated | `network.stun_servers` | Merged into `network.stun_servers` only when `network.stun_servers` is not explicitly set. | Move value into `network.stun_servers` and remove legacy key. |
| `general.middle_proxy_nat_stun_servers` | Deprecated | `network.stun_servers` | Merged into `network.stun_servers` only when `network.stun_servers` is not explicitly set. | Move values into `network.stun_servers` and remove legacy key. |
| `general.proxy_secret_auto_reload_secs` | Deprecated | `general.update_every` | Used only when `update_every = null` (legacy fallback path). | Set `general.update_every` explicitly and remove legacy key. |
| `general.proxy_config_auto_reload_secs` | Deprecated | `general.update_every` | Used only when `update_every = null` (legacy fallback path). | Set `general.update_every` explicitly and remove legacy key. |

## How Upstreams Are Configured

### Upstream schema

| Field | Applies to | Type | Required | Default | Meaning |
|---|---|---|---|---|---|
| `[[upstreams]].type` | all upstreams | `"direct" \| "socks4" \| "socks5" \| "shadowsocks"` | yes | n/a | Upstream transport type. |
| `[[upstreams]].weight` | all upstreams | `u16` | no | `1` | Base weight for weighted-random selection. |
| `[[upstreams]].enabled` | all upstreams | `bool` | no | `true` | Disabled entries are ignored at startup. |
| `[[upstreams]].scopes` | all upstreams | `String` | no | `""` | Comma-separated scope tags for request-level routing. |
| `[[upstreams]].ipv4` | all upstreams | `Option<bool>` | no | `auto` | Allow IPv4 DC targets for this upstream. |
| `[[upstreams]].ipv6` | all upstreams | `Option<bool>` | no | `auto` | Allow IPv6 DC targets for this upstream, including proxy egress independent of host IPv6. |
| `[[upstreams]].prefer` | all upstreams | `Option<4 \| 6>` | no | effective `[network].prefer` | Per-upstream DC target family preference. |
| `interface` | `direct` | `Option<String>` | no | `null` | Interface name (e.g. `eth0`) or literal local IP for bind selection. |
| `bind_addresses` | `direct` | `Option<Vec<IpAddr>>` | no | `null` | Explicit local source IP candidates (strict priority over `interface`). |
| `address` | `socks4` | `String` | yes | n/a | SOCKS4 server endpoint (`ip:port` or `host:port`). |
| `interface` | `socks4` | `Option<String>` | no | `null` | Used only for SOCKS server `ip:port` dial path. |
| `user_id` | `socks4` | `Option<String>` | no | `null` | SOCKS4 user ID for CONNECT request. |
| `address` | `socks5` | `String` | yes | n/a | SOCKS5 server endpoint (`ip:port` or `host:port`). |
| `interface` | `socks5` | `Option<String>` | no | `null` | Used only for SOCKS server `ip:port` dial path. |
| `username` | `socks5` | `Option<String>` | no | `null` | SOCKS5 username auth. |
| `password` | `socks5` | `Option<String>` | no | `null` | SOCKS5 password auth. |
| `url` | `shadowsocks` | `String` | yes | n/a | Shadowsocks SIP002 URL (`ss://...`). Only `host:port` is exposed in runtime APIs. |
| `interface` | `shadowsocks` | `Option<String>` | no | `null` | Optional outgoing bind interface or literal local IP. |

### Runtime rules (important)

1. If `[[upstreams]]` is omitted, loader injects one default `direct` upstream.
2. Scope filtering is exact-token based:
- when request scope is set -> only entries whose `scopes` contains that exact token;
- when request scope is not set -> only entries with empty `scopes`.
3. Healthy upstreams are selected by weighted random using: `weight * latency_factor`.
4. If no healthy upstream exists in filtered set, random selection is used among filtered entries.
5. `direct` bind resolution order:
- `bind_addresses` candidates (same IP family as target) first;
- if `interface` is an interface name and `bind_addresses` is set, each candidate IP is validated against addresses currently assigned to that interface;
- invalid candidates are dropped with `WARN`;
- if a non-empty `bind_addresses` list leaves no valid same-family candidate, the connection fails closed with a configuration error;
- only when `bind_addresses` is absent or empty, `interface` is used (literal IP or resolved interface primary IP); if that yields no address, direct connect remains unbound.
6. For `socks4/socks5` with `address` as hostname, interface binding is not supported and is ignored with warning.
7. Runtime DNS overrides are used for upstream hostname resolution.
8. In ME mode, the selected upstream is also used for ME TCP dial path.
9. In ME mode for `direct` upstream with bind/interface, STUN reflection logic is bind-aware for KDF source material.
10. In ME mode for SOCKS upstream, a valid public `BND.ADDR/BND.PORT` with a nonzero port supplies the full KDF source tuple. Its address family must match the logical ME destination, independently of the TCP family used to reach SOCKS. IPv4-mapped destinations require a native IPv4 BND tuple; IPv4-compatible IPv6 remains IPv6.
11. `shadowsocks` upstreams require `general.use_middle_proxy = false`. Config load fails fast if ME mode is enabled.

## Upstream Configuration Examples

### Example 1: Minimal direct upstream

```toml
[[upstreams]]
type = "direct"
weight = 1
enabled = true
```

### Example 2: Direct with interface + explicit bind addresses

```toml
[[upstreams]]
type = "direct"
interface = "eth0"
bind_addresses = ["192.168.1.100", "192.168.1.101"]
weight = 3
enabled = true
```

### Example 3: SOCKS5 upstream with authentication

```toml
[[upstreams]]
type = "socks5"
address = "198.51.100.30:1080"
username = "proxy-user"
password = "proxy-pass"
weight = 2
enabled = true
```

### Example 4: Shadowsocks upstream

```toml
[general]
use_middle_proxy = false

[[upstreams]]
type = "shadowsocks"
url = "ss://2022-blake3-aes-256-gcm:BASE64_KEY@198.51.100.50:8388"
weight = 2
enabled = true
```

### Example 5: Mixed upstreams with scopes

```toml
[[upstreams]]
type = "direct"
weight = 5
enabled = true
scopes = ""

[[upstreams]]
type = "socks5"
address = "203.0.113.40:1080"
username = "edge"
password = "edgepass"
weight = 3
enabled = true
scopes = "premium,me"
```

### Example 5: ME-focused tuning profile

```toml
[general]
use_middle_proxy = true
proxy_secret_path = "proxy-secret"
middle_proxy_nat_probe = true
stun_nat_probe_concurrency = 16
me_keepalive_enabled = true
me_keepalive_interval_secs = 20
me_keepalive_jitter_secs = 4
me_reconnect_max_concurrent_per_dc = 12
me_reconnect_backoff_base_ms = 300
me_reconnect_backoff_cap_ms = 10000
me_reconnect_fast_retry_count = 10
hardswap = true
me_reinit_every_secs = 600
me_reinit_singleflight = true
me_reinit_max_concurrency = 2
me_reinit_trigger_channel = 64
me_reinit_coalesce_window_ms = 200
me_hardswap_warmup_delay_min_ms = 500
me_hardswap_warmup_delay_max_ms = 1200
me_hardswap_warmup_extra_passes = 2
me_hardswap_warmup_pass_backoff_base_ms = 400
me_config_stable_snapshots = 3
me_config_apply_cooldown_secs = 120
proxy_secret_stable_snapshots = 3
proxy_secret_rotate_runtime = true
proxy_secret_len_max = 512
update_every = 300
me_pool_drain_ttl_secs = 120
me_bind_stale_mode = "never"
me_bind_stale_ttl_secs = 90
me_pool_min_fresh_ratio = 0.9
me_reinit_drain_timeout_secs = 180

[timeouts]
me_one_retry = 8
me_one_timeout_ms = 1200

[network]
stun_use = true
stun_tcp_fallback = true
stun_servers = [
  "stun1.l.google.com:19302",
  "stun2.l.google.com:19302"
]
http_ip_detect_urls = [
  "https://api.ipify.org",
  "https://ifconfig.me/ip"
]
```
