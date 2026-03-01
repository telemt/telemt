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
| `general.middle_proxy_nat_probe` | `bool` | `true` | auto-forced to `true` when `use_middle_proxy=true` | Enables ME NAT probing. | `middle_proxy_nat_probe = true` |
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
| `general.middle_proxy_pool_size` | `usize` | `8` | none | Target active ME writer pool size. | `middle_proxy_pool_size = 12` |
| `general.middle_proxy_warm_standby` | `usize` | `16` | none | Reserved compatibility field in current revision (no active runtime consumer). | `middle_proxy_warm_standby = 16` |
| `general.me_keepalive_enabled` | `bool` | `true` | none | Enables periodic ME keepalive/ping traffic. | `me_keepalive_enabled = true` |
| `general.me_keepalive_interval_secs` | `u64` | `25` | none | Base keepalive interval (seconds). | `me_keepalive_interval_secs = 20` |
| `general.me_keepalive_jitter_secs` | `u64` | `5` | none | Keepalive jitter to avoid synchronization bursts. | `me_keepalive_jitter_secs = 3` |
| `general.me_keepalive_payload_random` | `bool` | `true` | none | Randomizes keepalive payload bytes. | `me_keepalive_payload_random = true` |
| `general.me_warmup_stagger_enabled` | `bool` | `true` | none | Staggers extra ME warmup dials to avoid spikes. | `me_warmup_stagger_enabled = true` |
| `general.me_warmup_step_delay_ms` | `u64` | `500` | none | Base delay between warmup dial steps (ms). | `me_warmup_step_delay_ms = 300` |
| `general.me_warmup_step_jitter_ms` | `u64` | `300` | none | Additional random delay for warmup steps (ms). | `me_warmup_step_jitter_ms = 200` |
| `general.me_reconnect_max_concurrent_per_dc` | `u32` | `8` | none | Limits concurrent reconnect workers per DC in health recovery. | `me_reconnect_max_concurrent_per_dc = 12` |
| `general.me_reconnect_backoff_base_ms` | `u64` | `500` | none | Initial reconnect backoff (ms). | `me_reconnect_backoff_base_ms = 250` |
| `general.me_reconnect_backoff_cap_ms` | `u64` | `30000` | none | Maximum reconnect backoff (ms). | `me_reconnect_backoff_cap_ms = 10000` |
| `general.me_reconnect_fast_retry_count` | `u32` | `16` | none | Immediate retry budget before long backoff behavior. | `me_reconnect_fast_retry_count = 8` |

### 3) Reinit/hardswap, secret rotation, and degradation

| Parameter | Type | Default | Constraints / validation | Runtime effect | Example |
|---|---|---:|---|---|---|
| `general.hardswap` | `bool` | `true` | none | Enables generation-based ME hardswap strategy. | `hardswap = true` |
| `general.me_reinit_every_secs` | `u64` | `900` | must be `> 0` | Periodic ME reinit interval. | `me_reinit_every_secs = 600` |
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
| `general.me_pool_drain_ttl_secs` | `u64` | `90` | none | Time window where stale writers remain fallback-eligible. | `me_pool_drain_ttl_secs = 120` |
| `general.me_pool_min_fresh_ratio` | `f32` | `0.8` | must be within `[0.0,1.0]` | Coverage threshold before stale generation can be drained. | `me_pool_min_fresh_ratio = 0.9` |
| `general.me_reinit_drain_timeout_secs` | `u64` | `120` | `0` means no force-close; if `>0 && < TTL` it is bumped to TTL | Force-close timeout for draining stale writers. | `me_reinit_drain_timeout_secs = 0` |
| `general.auto_degradation_enabled` | `bool` | `true` | none | Reserved compatibility flag in current revision (no active runtime consumer). | `auto_degradation_enabled = true` |
| `general.degradation_min_unavailable_dc_groups` | `u8` | `2` | none | Reserved compatibility threshold in current revision (no active runtime consumer). | `degradation_min_unavailable_dc_groups = 2` |

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
| `[[upstreams]].type` | all upstreams | `"direct" \| "socks4" \| "socks5"` | yes | n/a | Upstream transport type. |
| `[[upstreams]].weight` | all upstreams | `u16` | no | `1` | Base weight for weighted-random selection. |
| `[[upstreams]].enabled` | all upstreams | `bool` | no | `true` | Disabled entries are ignored at startup. |
| `[[upstreams]].scopes` | all upstreams | `String` | no | `""` | Comma-separated scope tags for request-level routing. |
| `interface` | `direct` | `Option<String>` | no | `null` | Interface name (e.g. `eth0`) or literal local IP for bind selection. |
| `bind_addresses` | `direct` | `Option<Vec<IpAddr>>` | no | `null` | Explicit local source IP candidates (strict priority over `interface`). |
| `address` | `socks4` | `String` | yes | n/a | SOCKS4 server endpoint (`ip:port` or `host:port`). |
| `interface` | `socks4` | `Option<String>` | no | `null` | Used only for SOCKS server `ip:port` dial path. |
| `user_id` | `socks4` | `Option<String>` | no | `null` | SOCKS4 user ID for CONNECT request. |
| `address` | `socks5` | `String` | yes | n/a | SOCKS5 server endpoint (`ip:port` or `host:port`). |
| `interface` | `socks5` | `Option<String>` | no | `null` | Used only for SOCKS server `ip:port` dial path. |
| `username` | `socks5` | `Option<String>` | no | `null` | SOCKS5 username auth. |
| `password` | `socks5` | `Option<String>` | no | `null` | SOCKS5 password auth. |

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
- if no valid candidate remains, connection falls back to unbound direct connect (`bind_ip=None`);
- if no `bind_addresses` candidate, `interface` is used (literal IP or resolved interface primary IP).
6. For `socks4/socks5` with `address` as hostname, interface binding is not supported and is ignored with warning.
7. Runtime DNS overrides are used for upstream hostname resolution.
8. In ME mode, the selected upstream is also used for ME TCP dial path.
9. In ME mode for `direct` upstream with bind/interface, STUN reflection logic is bind-aware for KDF source material.
10. In ME mode for SOCKS upstream, SOCKS `BND.ADDR/BND.PORT` is used for KDF when it is valid/public for the same family.

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

### Example 4: Mixed upstreams with scopes

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
middle_proxy_pool_size = 12
me_keepalive_enabled = true
me_keepalive_interval_secs = 20
me_keepalive_jitter_secs = 4
me_reconnect_max_concurrent_per_dc = 12
me_reconnect_backoff_base_ms = 300
me_reconnect_backoff_cap_ms = 10000
me_reconnect_fast_retry_count = 10
hardswap = true
me_reinit_every_secs = 600
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
