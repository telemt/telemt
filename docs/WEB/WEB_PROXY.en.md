# WEB proxy mode

[English](WEB_PROXY.en.md) | [Русский](WEB_PROXY.ru.md) | [Deutsch](WEB_PROXY.de.md)

WEB mode carries ordinary MTProxy streams through bounded HTTPS or WebSocket carriers compatible with Telegram Desktop's `WEB` proxy type. Telemt does not terminate TLS: NGINX or HAProxy owns the public certificate and forwards plain HTTP/1.1 to a private Telemt listener.

> [!IMPORTANT]
>
> WEB mode is implemented and configurable in the current source tree. The first deployment requires a binary built from a revision containing this implementation and a Telemt process restart. Published packages can be used only after verifying that they contain the same revision. End-to-end validation with the intended Telegram Desktop build and the real public TLS endpoint remains an operator acceptance step.

## Traffic path

```text
Telegram Desktop
    | HTTPS or WSS :443
    v
NGINX or HAProxy (TLS termination, canonical Host and one X-Forwarded-For address)
    | plain HTTP/1.1 on a private network
    v
Telemt WEB listener
    |-- authenticated carrier --> bounded logical MTProxy relays --> Telegram
    `-- ordinary or invalid request --> configured decoy site
```

Route the complete public vhost to Telemt. Splitting only recognized carrier paths at the TLS terminator would make ordinary and authenticated behavior observably different and would bypass Telemt's decoy policy.

## Supported client contract

- The public endpoint is always `https://HOST:443`.
- `plain` and `dd` 16-byte MTProxy secrets are supported. `ee` FakeTLS secrets are not supported by WEB mode.
- `web.carrier` selects the sole carrier when auto-negotiation is disabled and the final fallback when it is enabled. `https` uses serialized HTTPS uplink and long polling. `https-lanes` uses independent HTTPS sequencing and polling per logical stream. `websocket` uses one ordered WebSocket for all streams. `websocket-lanes` uses one independently owned WebSocket per non-zero logical stream.
- Missing `web.carriers` or `web.carriers = false` disables auto-negotiation and learning. A non-empty array enables startup-only sequential negotiation; it never migrates an already committed session.
- Native clients without canonical carrier-negotiation headers use the configured fixed `carrier`, even when `carriers` enables negotiation for capable clients. Current Telegram iOS supports only `https`, so an operator serving metadata-free iOS clients must set `web.carrier = "https"`; it does not support `https-lanes`. User-Agent values, including CFNetwork or Darwin, never infer capabilities. When a native iOS request does send explicit negotiation metadata, Telemt intersects it with the server-authoritative `{https}` ceiling and rejects an empty result; other explicit clients use their advertised capability set.
- Capability, bootstrap, and session credentials are separate bounded-lifetime values. Carrier credentials must be treated as secrets and must not appear in access logs.
- A bootstrap is a bearer credential, not a source-address-bound token. The client address and IP family may change between bridge loading and session creation. The issuing address retains unused-bootstrap accounting, while the address on the first valid creation request owns the session.
- Inner MTProxy authentication is restricted to the user and secret mode selected by the vhost profile. Invalid inner handshakes close only their logical stream and never enter the TCP masking path.

Telegram Desktop WEB links omit a port because the client requires port 443:

```text
tg://webproxy?server=proxy.example.com&secret=0123456789abcdef0123456789abcdef
tg://webproxy?server=proxy.example.com&secret=dd0123456789abcdef0123456789abcdef
```

Telemt prints links for WEB profiles selected by `[general.links].show` through the existing `telemt::links` log target.

## Prerequisites

- A dedicated public FQDN and valid TLS certificate on NGINX or HAProxy.
- A stable public IP for that hostname. `public_addr` must be that concrete IP on port 443 because it participates in the inner relay destination tuple.
- A private or loopback HTTP path from the TLS terminator to Telemt.
- A normal decoy site, either a private HTTP origin or an immutable local directory snapshot.
- A compatible Telegram Desktop build with the `WEB` proxy type.

The forwarded client address may differ in family from `public_addr` and may change while a bootstrap is live. `public_addr` must still identify the exact public endpoint used by the inner MTProxy route.

## Minimal Telemt configuration

The example keeps the WEB listener on loopback and uses a private HTTP decoy origin:

```toml
[general.links]
show = ["web-user"]

[access.users]
web-user = "0123456789abcdef0123456789abcdef"

[[server.listeners]]
ip = "127.0.0.1"
port = 18080
transport = "web"
proxy_protocol = false
web_client_ip_source = "x_forwarded_for"
web_trusted_proxy_cidrs = ["127.0.0.1/32"]

[web]
enabled = true
carrier = "https-lanes"
http_connection_capacity_action = "drop"

[[web.vhosts]]
host = "proxy.example.com"
public_addr = "203.0.113.10:443"

[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://127.0.0.1:18081"

[[web.vhosts.profiles]]
user = "web-user"
secret_mode = "dd"
max_sessions = 8
max_streams = 512
max_streams_per_session = 64
```

Accepted-socket overload handling is independently configurable. `drop` preserves the legacy close after `accept(2)`. `respond` writes an empty retryable `503` without parsing a request. `wait` waits outside the accept loop for ordinary connection capacity and then enters normal HTTP handling; timeout writes the same `503`. Both waiting and response writing use `web.timeouts.http_overload_timeout_ms` per phase. `web.limits.max_http_overload_connections` bounds sockets outside ordinary capacity and requires a process restart when changed; the action and timeout are hot-reloadable.

## Server-side carrier negotiation

Auto-negotiation is optional and disabled unless `carriers` is an explicit non-empty array. The configured `carrier` remains the final fallback and is appended exactly once, even when it also appears in the array:

```toml
[web]
enabled = true
carrier = "https"
carriers = ["websocket-lanes", "websocket", "https-lanes"]
carrier_learning = true
carrier_negotiation_aggressiveness = "conservative"

[web.timeouts]
carrier_negotiation_deadlines_secs = [3, 5, 8, 12]
carrier_health_secs = 30
carrier_learning_secs = 600
bridge_request_secs = 10
bridge_retry_secs = 90
carrier_probe_coalesce_ms = 0
```

The generated bridge sends canonical `X-Carrier-Capabilities`, `X-Carrier-Attempt`, and, after the first attempt, `X-Carrier-Failure` headers on `/session`. Every successful automatic response returns `X-Carrier-Mode`, `X-Carrier-Attempt`, `X-Carrier-Candidate-Count`, `X-Carrier-Deadline`, and `X-Carrier-State`. The bridge starts its local cumulative clock immediately before the first `/session` request; the server freezes its separate absolute chain deadline when it accepts the first automatic attempt. Both use the configured offsets, and neither resets across replacement attempts. For one through four effective candidates, the attempt checkpoints are respectively `[d3]`, `[d0, d3]`, `[d0, d1, d3]`, and `[d0, d1, d2, d3]`; the final candidate always owns `d3`. A successor remains admissible until its own checkpoint. The states are `provisional`, `committed`, and `healthy`.

Attempts are strictly sequential. Accepted `OPEN` or `DATA` progress commits the chosen carrier immediately and permanently closes the replacement boundary. A `409` for an authenticated committed chain echoes the committed metadata and is terminal; it is not permission to advance. Exact `/session` replay is used only while that response is ambiguous. Once an authenticated response has selected a provisional carrier, a transport failure requests the next attempt directly; if the previous probe actually committed, the server answers with the terminal `409` instead of permitting an unsafe replacement. The server's final absolute deadline also bounds a successor response that the client never received. Post-commit dynamic switching is deliberately unsupported: reconnect with a new session instead.

Each bridge HTTP operation has an absolute `bridge_retry_secs` budget and at most nine attempts. `bridge_request_secs` covers both the Fetch response head and complete response body; a downlink attempt additionally receives the configured long-poll interval. Network failures and `408`, `429`, `502`, `503`, or `504` responses use bounded exponential backoff, while `Retry-After` cannot extend the absolute budget. `carrier_probe_coalesce_ms = 0` sends the first ordered `OPEN` probe immediately. A value up to 10 ms may include matching `DATA` that arrives in that window; multiplexed carriers preserve the complete preceding frame order, while lane carriers claim only the selected lane. No HTTP downlink starts before the probe acknowledgement. Multiplexed WebSocket Upgrade may begin as soon as `/session` selects it and then absorbs queued probe data; a lane WebSocket waits until its stream ID is known.

Automatic WebSockets use `tproxy-auto-v1.<session-token>` or `tproxy-auto-lane-v1.<session-token>.<stream-id>`. The first accepted binary message containing real `OPEN` or `DATA` progress commits the carrier; the server then writes an empty binary commit acknowledgement to that exact connection. Ping/Pong does not commit a carrier and does not count as learning evidence.

A committed attempt becomes healthy only after transport-specific bidirectional evidence remains valid for `carrier_health_secs`. HTTPS requires accepted `DATA`, an acknowledged non-empty post-commit downlink batch, and authenticated activity at or after the health deadline. WebSocket requires the exact commit acknowledgement to be written, subsequent accepted `OPEN` or `DATA` from the same owner, and that owner to remain live through the interval. Closing earlier is neutral and records no learning result.

Learning is process-local, in-memory, positive-only, and bounded by `max_carrier_learning_entries`. It ranks only client-supported configured candidates, keeps the configured fallback last, and uses configured order for equal scores. User-Agent and profile evidence have primary weight; an eligible IP is only a tie-breaker. IP evidence requires exactly one explicit, globally routable `X-Forwarded-For` address; private, loopback, link-local, carrier-grade NAT, documentation, multicast, and IPv4-mapped equivalents are excluded. Client-reported failure categories and request latency are diagnostics, not negative or ranking evidence. `conservative` requires 3 User-Agent outcomes or 8 profile outcomes across 4 cohorts and disables IP evidence; `balanced` uses 2, 6 across 3, and 3 eligible-IP outcomes; `aggressive` uses 1, 4 across 2, and 1 eligible-IP outcome. Disabling learning or changing its policy on reload clears incompatible evidence without changing in-flight sessions.

`https` remains the default and preserves the original serialized behavior. `https-lanes` assigns lane zero to session control and one lane to every non-zero logical stream. Each lane has its own uplink sequence, retry digest, downlink cursor, unacknowledged replay batch, queue, and newest-poll-wins lifecycle. A slow stream therefore does not block another stream at the WEB protocol layer.

This removes application-level serialization between WEB streams. Public HTTP/2 still runs over one or more TCP connections, so packet loss can cause transport-level head-of-line blocking; `https-lanes` is not an HTTP/3 or QUIC carrier.

All lane queues and resident response bodies remain inside the existing per-session and process-wide byte/item budgets. Telemt additionally limits each lane to `pending_bytes_per_lane` and `pending_items_per_lane`; the generated bridge caps its corresponding queues at 8 MiB and 1024 items. Telemt permits lane long polls to occupy at most half of `web.limits.max_http_handlers`, preserving handler capacity for session creation, uplink, DELETE, and other control work. `https` requires `max_http_handlers >= 2`, and `https-lanes` requires `max_http_handlers >= 4`.

The `/api/v1/up` and `/api/v1/down` paths do not change. In `https-lanes`, every request on those paths carries one canonical decimal `X-Lane-ID`. Uplink sequence starts at `1` and downlink cursor at `0` independently for each lane. Lane zero accepts only session `PONG`; every frame in a non-zero lane must have the same stream ID, and a new lane must begin with `OPEN`. A canonical cursor-zero downlink that reaches Telemt just before its lane `OPEN` waits up to `lane_open_wait_secs` without creating lane state; per-session and process auxiliary permits bound these waits. Expiry returns an empty `204`, while a missing lane with an advanced cursor remains a protocol failure routed through the decoy. After a closed lane's queued and unacknowledged downlink data is drained, Telemt returns an empty response with `X-Lane-Closed: 1`, and the bridge stops polling it. Retries remain byte-identical and replay the original acknowledgement or downlink batch.

Both WebSocket carriers still create and delete the parent session over HTTPS. They then use a strict bodyless `GET /api/v1/ws` Upgrade request. `websocket` offers exactly `tproxy-v1.<session-token>` in `Sec-WebSocket-Protocol`; binary messages are ordered carrier batches, and a protocol, deadline, or connection failure closes the complete parent session. `websocket-lanes` offers exactly `tproxy-lane-v1.<session-token>.<stream-id>`, where the stream ID is canonical decimal in `1..=16777215`. Its first binary message must begin with `OPEN`, every frame must use that stream ID, and failure after upgrade closes only that lane. There is no lane-zero WebSocket: HTTPS carries `HELLO` and `WELCOME`, while RFC 6455 Ping/Pong supplies connection liveness.

Before HTTP `101`, a WebSocket-lane reservation binds to the exact process connection and lane incarnation; an accepted `OPEN` transfers ownership to the exact stream incarnation before its backend task can run. A late poll, close, or reservation drop from an older socket cannot acknowledge, close, or release a replacement that reused the same numeric lane ID.

WebSocket codec buffers and in-flight read/write messages share the process-owned `pending_bytes_global` budget with carrier queues and are additionally bounded by `websocket_bytes_global`. Admission leaves `websocket_http_connection_reserve` accepted connections for ordinary HTTP and decoys. Admission replacement selects dead active connections globally first, then uses same-session, same-profile-owner, and same-client-IP locality. An unrelated healthy victim is eligible only when the requester is below its fair byte share and the victim owner is above it. Within one locality, claimed or upgraded connections precede active lanes, active lanes precede active multiplexed sessions, and least-recent progress, creation order, and connection ID provide deterministic tie breaking. Memory-pressure cleanup uses the same dead-first and lifecycle ordering, preferring over-share owners without stalling when every owner is at or below its share. `max_websocket_evictions_in_flight` bounds concurrent exact eviction claims. Upgrade, first-message, write, backpressure, and eviction deadlines are frozen from the parent session. A transport Ping is sent after `long_poll_secs` without peer activity, including during continuous downlink traffic; missing peer activity for twice that creation-time interval makes an active connection eligible for cleanup.

Every pre-Upgrade authentication, shape, lane-reservation, or capacity failure follows the sanitized decoy path instead of exposing a WebSocket-specific status. The exact subprotocol contains the session bearer and must not be logged.

The WEB listener must use `proxy_protocol = false` and `reuse_allow = false`. It cannot use `client_mss`, `synlimit`, `announce`, or `announce_ip`. `web_trusted_proxy_cidrs` must be non-empty and must contain only the immediate NGINX or HAProxy peers; `/0` networks are rejected.

The HTTP decoy origin must be a loopback, link-local, or private IP literal. Telemt preserves ordinary request method, path, query, headers, streamed body, response status, headers, and body while removing hop-by-hop headers. Malformed carrier requests have carrier credentials and bodies removed before falling back to the decoy. A literal decoy endpoint that exactly matches an effective WEB listener, or is covered by its same-family wildcard address on the same port, is rejected. Indirect loops through DNS, NGINX, HAProxy, or another forwarding layer cannot be proven from Telemt configuration and must be excluded operationally.

An immutable static-site snapshot can be used instead:

```toml
[web.vhosts.decoy]
mode = "static_directory"
directory = "/var/lib/telemt/public"
index = "index.html"
```

Static files are read at startup and successful configuration reload. Entry count, per-file size, and total snapshot size are bounded by `[web.limits]`. Symlinks and paths escaping the configured directory are rejected. Do not mutate the directory concurrently while Telemt builds a snapshot.

All WEB keys and defaults are listed in the [configuration reference](../Config_params/CONFIG_PARAMS.en.md#web).

## NGINX TLS termination

```nginx
map $http_upgrade $telemt_connection_upgrade {
    default upgrade;
    ''      '';
}

upstream telemt_web {
    server 127.0.0.1:18080;
    keepalive 64;
}

server {
    listen 443 ssl;
    http2 on;
    server_name proxy.example.com;
    access_log off;

    ssl_certificate     /etc/letsencrypt/live/proxy.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/proxy.example.com/privkey.pem;

    client_max_body_size 2m;

    location / {
        proxy_pass http://telemt_web;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $telemt_connection_upgrade;

        proxy_connect_timeout 5s;
        proxy_send_timeout 65s;
        proxy_read_timeout 65s;
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_next_upstream off;
    }
}
```

Place the `map` in NGINX's `http` context. `client_max_body_size` must be at least `web.limits.max_body_bytes`. Read, send, and client timeouts must exceed both the 25-second default long poll and twice the configured WebSocket liveness interval; 65 seconds covers the defaults. Overwrite, rather than append to, `X-Forwarded-For`. Telemt accepts one parseable IP address; if a trusted terminator omits the header, Telemt falls back to the direct peer address, but per-client limits and source policy then see the terminator rather than the real client. Do not enable upstream retries: the bridge performs byte-identical HTTPS retries, while an established WebSocket is never transparently replayed.

Public HTTP/2 is mandatory for `https-lanes`; use the equivalent HTTP/2 directive supported by the installed NGINX release. WebSocket Upgrade requires HTTP/1.1, so the public endpoint must also permit HTTP/1.1 and the private NGINX-to-Telemt hop remains HTTP/1.1. Preserve `Connection`, `Upgrade`, and `Sec-WebSocket-*` exactly as shown. Ensure the upstream connection capacity can sustain the expected simultaneous lane polls or WebSocket lanes; `keepalive` controls the idle pool and is not a concurrency limit.

### Distinguishing refusal from WEB capacity

`connect() failed (111: Connection refused) while connecting to upstream` is a TCP-connect failure before Telemt accepts a socket. Check that the Telemt process is running, the effective WEB listener address and port match the NGINX upstream, both processes share the expected network namespace and address family, and no local firewall actively rejects the connection. Startup bind failure, terminal listener removal, or switching NGINX to a desired port before a restart-only listener change becomes effective can produce this symptom. Kernel listen-backlog pressure is separate and normally requires host `ListenOverflows`/`ListenDrops` telemetry.

WEB capacity is enforced after successful `accept(2)`. Exhausting `max_http_connections` therefore produces the configured `drop`, `wait`, or `respond` outcome; it does not produce an upstream connect refusal. Handler, body, lane, stream, queue, and WebSocket limits have their own HTTP, decoy, or stream-local failure boundaries. Operator pause and drain also leave the WEB listener bound, so they cannot by themselves cause a refusal.

Use `GET /v1/runtime/web/status` to correlate only Telemt-owned state. `ingress.accepting_connections` requires a running publication, a readable runtime, and one live acceptor for every effective WEB listener. `capacity.saturated_resources`, typed rejection totals, and overload outcomes identify failures after acceptance. `decoy_upstream` describes only Telemt's outgoing plain-HTTP decoy hop. None of these fields claims that the public NGINX TLS endpoint is reachable; use an external TCP/TLS probe and NGINX or HAProxy telemetry for that boundary.

## HAProxy TLS termination

```haproxy
frontend public_https
    mode http
    no log
    bind :443 ssl crt /etc/haproxy/certs/proxy.example.com.pem alpn h2,http/1.1
    acl telemt_web_host hdr(host) -i proxy.example.com proxy.example.com:443
    use_backend telemt_web if telemt_web_host

backend telemt_web
    mode http
    option http-keep-alive
    retries 0
    timeout connect 5s
    timeout server 65s
    http-request set-header Host proxy.example.com
    http-request del-header X-Forwarded-For
    http-request set-header X-Forwarded-For %[src]
    server telemt_web_1 127.0.0.1:18080 check
```

The frontend or `defaults` section must also set `timeout client 65s` or longer for the default WebSocket liveness interval. HAProxy's public ALPN must include `h2` for `https-lanes` and `http/1.1` for WebSocket Upgrade. Preserve `Connection`, `Upgrade`, and `Sec-WebSocket-*`; do not rewrite the path, raw query, body, or the `Authorization`, `Content-Type`, `X-Up-Seq`, `X-Down-Cursor`, and `X-Lane-ID` carrier headers.

## Lifecycle and reload behavior

| Configuration | Runtime behavior |
| --- | --- |
| WEB listener inventory, bind address, and trust policy | Process-owned; restart Telemt. |
| Any `[web.limits]` value | Process-owned memory/resource contract; restart Telemt. |
| `web.enabled`, carrier/negotiation policy, `web.debug`, timeouts, vhosts, profiles, and decoys | Applied by the config watcher or a runtime generation reload. |
| Operator pause/drain state | Process-owned and ephemeral; survives generation reload, never writes config, and resets to `running` after process restart. |
| Existing HTTP connections and WEB sessions | Keep their acquisition-time HTTP idle limit, carrier candidates, limits, body timeout, closed-token replay lifetime, and absolute session/negotiation deadlines; each issued bridge embeds its request, retry, and probe-coalescing values. WebSocket upgrade, open, write, backpressure, and eviction operations use the parent session's frozen deadlines. Newly issued bridges use the active policy, while new logical streams use the active relay generation. |
| Process shutdown | Captures the latest reloaded `web.timeouts.shutdown_secs` once and shares that single absolute deadline across listener acceptors and connections plus WEB sessions and auxiliary tasks. The waits do not receive sequential per-component budgets. |

Each logical stream keeps its session's creation-time client IP and owns a process-unique, non-zero synthetic source port for the complete relay lifetime. This preserves one stable, non-colliding source/destination tuple for Direct and Middle-End KDF routing.

HTTP idle accounting protects only explicitly bounded request-body, long-poll, decoy connect/response-head, and pending-Upgrade phases. The operation's own deadline remains exact; if its lease is still present at that instant, the connection watchdog allows at most one connection-idle interval for the scheduled task to publish its timeout/result before forcing closure. Between exchanges, and after a response head is ready, progress resets the idle clock while a stalled response body remains idle-bounded. Completion of an older phase cannot release the deadline protection owned by a newer phase.

An `OPEN` reserves the bounded logical-stream and tuple ownership but does not consume the relay generation's `max_connections` permit. Telemt acquires that permit only after the first inner byte arrives; the frozen first-byte deadline and stream limits bound silent opens, and capacity exhaustion then closes only the affected stream.

## API management

WEB configuration, runtime status, and bounded runtime controls share the authenticated API listener. `/web-status` remains a read-only HTML diagnostic view; state-changing operations exist only under `/v1/runtime/web`.

| Operation | API support |
| --- | --- |
| Read or patch `[web]`, vhosts, profiles, decoys, timeouts, or limits | Yes, through `GET` or `PATCH /v1/config`. The derived `web.runtime` snapshot is never returned or writable. Nested tables merge field-by-field; arrays replace the previous array wholesale. Every `[web.limits]` change is accepted as desired configuration but reported as deferred until process restart. |
| Persist `server.listeners` | Yes, through `PATCH /v1/config`, but a changed WEB listener remains deferred until process restart. |
| Apply an externally edited WEB configuration | Yes, through `POST /v1/system/reload`, then inspect the operation status. |
| Inspect bounded server-side WEB request and lifecycle details | Yes, through authenticated `GET /web-status`. |
| Inspect lifecycle, capacity planes, learning/debug state, and live sessions | Yes, through `GET /v1/runtime/web/status` and `/v1/runtime/web/sessions`. |
| Close selected live WEB sessions | Yes, through the asynchronous `POST /v1/runtime/web/sessions/close` operation. |
| Pause, deadline-drain, or resume new WEB work | Yes, through `/v1/runtime/web/lifecycle/{pause,drain,resume}`. |
| Clear debug records or reset carrier learning | Yes, through the corresponding runtime POST endpoints. |
| Manage `[access.users]` | Yes, through `/v1/users`. User creation does not create a WEB profile. |
| Revoke one user | Yes. `/v1/users/{username}/disable` updates admission immediately and cancels that user's active sessions. |

Bind the API to loopback, keep its direct-peer whitelist narrow, configure an exact authorization header, and leave `read_only = false` only when mutation is required:

```toml
[server.api]
enabled = true
listen = "127.0.0.1:9091"
whitelist = ["127.0.0.0/8"]
auth_header = "Bearer replace-with-a-random-control-token"
read_only = false
```

The API whitelist checks the direct TCP peer and does not trust `X-Forwarded-For`. Changes to `[server.api]` itself require a process restart.

### Runtime status and control

`GET /v1/runtime/web/status` always returns the published ingress lifecycle (`starting`, `no_web_listener`, `running`, `draining`, `drained`, or `deadline_exceeded`), its epoch and age, effective listener addresses, and backward-compatible runtime availability. `ingress` independently reports configured listeners, live acceptors, accepting state, accept totals, and a stable reason. `capacity` reports effective accepted-socket overload policy, fixed resource usage, instantaneous saturation, partial planes, typed rejection decisions, and overload outcomes. `decoy_upstream` reports fixed outcomes and the age of the latest internal origin result. When the process-owned WEB runtime is alive, `operator_lifecycle` independently exposes `running`, `paused`, `draining`, `force_closing`, or `drained`, its own epoch/admission flags, and the active or latest drain. `runtime` adds the random 128-bit `runtime_instance`, active generation, immutable limits, plane-local capacity counters, carrier-learning/debug epochs, and totals. Runtime plane collection uses non-blocking reads: a contended plane is omitted and named in `partial`; the endpoint never waits for, cleans up, or mutates the data plane.

Prometheus exports the same process-owned planes as fixed-cardinality `telemt_web_*` families: ingress and operator one-hot states, listener/accept counters, capacity usage and saturation, typed terminal rejections, accepted-socket overload outcomes, internal decoy-origin outcomes, and existing session/stream/carrier totals. Labels are closed enums or fixed resource names; user, host, client IP, token, profile key, runtime instance, listener address, and generation ID are never labels. A successful `wait` outcome does not increment a rejection counter.

`GET /v1/runtime/web/sessions` returns at most 50 sessions by default and at most 200 when `limit` is supplied. Its ordered scan is capped at 1000 candidates. `cursor` and `session_ref` use the opaque canonical form `ws1.<runtime-instance>.<lowercase-hex-id>`; exact `session_ref` is mutually exclusive with `cursor` and `limit`. Filters are `ip`, `host`, `user`, `user_agent_id`, `key_id`, `carrier`, and `state`; duplicate or unknown query fields are rejected. The detail route is `GET /v1/runtime/web/sessions/{session_ref}`. A retained closed-session tombstone returns `410`; a contended exact snapshot returns `503 web_snapshot_busy`. Responses expose bounded non-secret metadata and never expose bootstrap/session bearers, capabilities, secret hashes, or synthetic/KDF ports.

Every runtime POST requires `Content-Type: application/json` exactly, rejects unknown JSON fields, obeys API authentication, whitelist, and `read_only`, and carries the current `runtime_instance` as an ABA fence. Available controls are:

- `POST /v1/runtime/web/lifecycle/pause` with `{"runtime_instance":"..."}`. It blocks new bootstrap, session incarnation, replacement, and logical-stream admission after a linearizable fence. Existing carrier exchanges and streams continue, exact session replay remains available, and bridge rejection stays on the decoy route.
- `POST /v1/runtime/web/lifecycle/drain` with `{"runtime_instance":"...","timeout_secs":30}`. It returns `202`, keeps the same admission fence closed, and waits asynchronously for sessions, streams, and session-owned WebSockets. At the monotonic deadline it signals close to every remaining live session and reports `force_closing` until zero is confirmed. Natural and forced completion both remain closed until resume. A concurrent second drain returns `409 web_lifecycle_in_progress`.
- `POST /v1/runtime/web/lifecycle/resume` with `{"runtime_instance":"..."}`. It cancels an active drain and reopens only operator admission. If forced close already committed, old session cancellation cannot be undone. Config, user, generation, and terminal shutdown gates still dominate.
- `POST /v1/runtime/web/sessions/close` with one selector: `{"kind":"refs","session_refs":[...]}`, `{"kind":"filter",...}`, or `{"kind":"all"}`. Exact refs are limited to 200, a filter must be non-empty, only one close operation may run, and `all` is rejected while effective issuance remains enabled. The `202` response returns `operation_id`; poll `GET /v1/runtime/web/operations/{operation_id}`. The operation scans only sessions at or below its submission high-water mark in chunks of 128.
- `POST /v1/runtime/web/debug/clear` with `{"runtime_instance":"..."}`. The response reports cleared records, bytes still leased by already rendered snapshots, and the new epoch. In-flight writers from the old epoch cannot repopulate the ring.
- `POST /v1/runtime/web/carrier-learning/reset` with the same body shape. It clears retained process-local evidence and advances the learning epoch; already frozen attempt chains and live sessions are unchanged.

For a deterministic close-all, patch `{"web":{"enabled":false}}` with runtime reload enabled, wait until `runtime.manager.issuance_enabled` is `false`, submit the `all` selector using that same `runtime_instance`, and poll the operation to a terminal state. Disabling WEB stops new bootstrap/session issuance but never implicitly closes existing sessions.

Operator lifecycle is WEB-only and does not change global readiness, liveness, native TCP/Unix listeners, TLS-fronting, or fallback behavior. A pre-pause WebSocket lane reservation is already admitted logical work: it may finish opening and remains included in drain accounting. Lifecycle rejection consumes no rate/quota tokens and adds no hot-path relay lock.

### Server-side WEB debug view

Enable bounded collection in the owned configuration file:

```toml
[web.debug]
enabled = true
capture_lifecycle = true
capture_headers = true
capture_timings = true
capture_frames = true
body_capture = "metadata"
body_prefix_bytes = 4096
decoy_body_prefix_bytes = 4096
default_window_secs = 180
max_window_secs = 3600
```

Open `http://127.0.0.1:9091/web-status` with the same direct-peer whitelist and exact `Authorization` header used by the API. A trailing slash is accepted. Only `GET` is allowed. The page supports `window_secs`, canonical `ip`, numeric `session`, case-insensitive `user_agent`, and `key` filters. Repeat `group_by=ip`, `group_by=session`, `group_by=user_agent`, or `group_by=key` to build grouped summaries; `limit` is restricted to `1..=1000`. HTTP rows expand from request through response with method, path, sanitized headers, body metadata or bytes, timing points, parsed frames, and typed lifecycle events, including carrier attempt, commit, healthy, and reported-failure transitions. WebSocket operation adds the sanitized `GET` to `101` handshake plus bounded per-message direction, message type, payload/body capture, processing time, connection/lane identifiers, and parsed inner frames. Raw subprotocols and session tokens are never retained.

The process-owned ring survives runtime generation replacement. Capture-policy changes clear incompatible retained records; window-only changes do not. The ring defaults to 65536 records and 64 MiB retained plus in-flight bytes, the HTML response is capped at 8 MiB, grouping is capped at 1024 groups, and no more than two response bodies retain page permits concurrently. Change `web.limits.debug_records_capacity` or `web.limits.debug_bytes_global` only with a process restart. A hot prefix that fits only a simultaneously increased restart-only capacity is deferred until that restart.

`body_capture = "off"` omits bodies, `metadata` retains lengths and terminal states, `prefix` retains configured prefixes, and `full` retains recognized carrier bodies up to `web.limits.max_body_bytes`. Ordinary decoy bodies remain limited by `decoy_body_prefix_bytes` even in `full` mode. Queries and raw capabilities are never stored; credential header values are omitted; known WEB capabilities and bearer tokens are scrubbed from captured bodies; the displayed key is a non-secret domain-separated fingerprint. Timing ends at Hyper body polling and does not claim kernel flush or TCP acknowledgment.

After an administrator or configuration system atomically updates the TOML file, set `TELEMT_API_AUTH` to the exact value configured in `auth_header` and submit an observable generation reload:

```bash
curl -sS -X POST http://127.0.0.1:9091/v1/system/reload \
  -H "Authorization: ${TELEMT_API_AUTH}" \
  -H 'Content-Type: application/json' \
  -d '{"mode":"drain","timeout_secs":30,"failure_policy":"rollback"}'

# Use data.reload_id from the response.
curl -sS http://127.0.0.1:9091/v1/system/reload/RELOAD_ID \
  -H "Authorization: ${TELEMT_API_AUTH}"
```

A terminal `succeeded` status confirms runtime activation. Changed carrier, candidate, deadline, or learning policy is used by newly issued bridge sessions; existing sessions and in-flight attempt chains are not migrated. If `deferred_process_fields` contains `server.listeners` or `web.limits`, the file is valid and persisted but those settings still require a Telemt restart.

Access-user operations use the existing endpoints, for example:

```bash
curl -sS -X POST http://127.0.0.1:9091/v1/users/web-user/disable \
  -H "Authorization: ${TELEMT_API_AUTH}"

curl -sS -X POST http://127.0.0.1:9091/v1/users/web-user/rotate-secret \
  -H "Authorization: ${TELEMT_API_AUTH}" \
  -H 'Content-Type: application/json' \
  -d '{}'
```

The config watcher rebuilds WEB capabilities after a secret rotation. The users API returns the secret, not a `tg://webproxy` URL; construct the link with the configured hostname and the profile's `plain` or `dd` representation. Before deleting a user referenced by a WEB profile, remove and apply that profile first so the resulting configuration remains valid.

See the complete [Control API contract](../Architecture/API/API.md) for request envelopes, revisions, failure modes, and all user endpoints.

## Deployment invariants

- Never expose the plain HTTP WEB listener to an untrusted network. Enforce the restriction with host firewall rules even when it binds to loopback.
- Disable request-target and authorization logging at the TLS terminator, or use a verified redacted format. Raw queries contain bridge capabilities and `Authorization` contains bootstrap or session bearer credentials.
- Keep one stable public address per vhost. If DNS returns several ingress addresses, each deployment must use the address matching its external path.
- Bootstrap and session registries are process-local. A multi-process or multi-host upstream pool requires affinity for the complete vhost: bridge GET, session creation, uplink, downlink, and DELETE. A single Telemt process needs no extra affinity.
- An unused bootstrap survives a configuration reload only when the exact profile identity remains active: host, `public_addr`, user, secret mode, carrier candidates, negotiation deadlines, and capability. Existing created sessions retain their immutable carrier and profile identity and remain lifecycle-bounded.
- The decoy is part of the anti-probing contract. Verify its ordinary 404 behavior and response timing through the public TLS endpoint before distributing links.

## Initial verification

1. Start the rebuilt Telemt binary with the WEB configuration and confirm that the private listener is bound.
2. Confirm through the public TLS endpoint that `GET /`, an unknown path, and an invalid `bridge` query return the configured decoy site.
3. Confirm that Telemt receives one parseable `X-Forwarded-For` address and `Host: proxy.example.com` or `Host: proxy.example.com:443`.
4. Import the printed `tg://webproxy` link in the intended Telegram Desktop build and establish a proxy connection.
5. For `https-lanes`, confirm that the public connection negotiated HTTP/2 and exercise at least two simultaneous logical streams; the private Telemt hop remains HTTP/1.1.
6. For `websocket`, confirm one `101` response, binary relay traffic, and RFC 6455 Ping/Pong beyond 25 seconds. For `websocket-lanes`, exercise at least two simultaneous stream sockets and verify that closing or corrupting one lane does not close its sibling or parent session.
7. Exercise reconnect and at least one long poll beyond 25 seconds to prove the frontend timeouts do not truncate the carrier.
8. Verify user and logical MTProxy connection limits using logical-stream counters, not the number of HTTP connections.
9. When auto-negotiation is enabled, verify the configured sequence, exact-attempt replay after an intentionally lost response, terminal behavior after commit, and `carrier_committed`/`carrier_healthy` lifecycle rows in `/web-status`. Verify that a metadata-free native client uses the fixed `carrier` without automatic response headers and that explicit capabilities remain unchanged.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| WEB configuration is valid on disk but listener behavior did not change | Inspect reload `deferred_process_fields`; listener and `[web.limits]` changes require restart. |
| Carrier requests reach the decoy | Verify exact vhost, link secret mode, direct proxy CIDR, and one parseable `X-Forwarded-For` value. |
| A racing `https-lanes` downlink reaches the decoy with `404` | Confirm it starts at `X-Down-Cursor: 0`, preserve `X-Lane-ID`, and set `lane_open_wait_secs` above the observed down-before-`OPEN` skew. Advanced cursors for missing lanes intentionally fail closed. |
| Auto-negotiation advances after traffic was already accepted | This is not valid behavior. Inspect the authenticated `X-Carrier-State` replay and the carrier commit lifecycle row; a committed or healthy response is terminal and requires a new session. |
| Long polls disconnect near a fixed interval | Raise NGINX/HAProxy client, server, send, and read timeouts above `web.timeouts.long_poll_secs`. |
| WebSocket Upgrade reaches the decoy instead of returning `101` | Preserve HTTP/1.1 `Connection: Upgrade`, `Upgrade: websocket`, the single exact `Sec-WebSocket-Protocol`, and the canonical bodyless `/api/v1/ws` request. Also check carrier/session compatibility and the process connection reserve. |
| One `websocket-lanes` stream closes while siblings stay connected | This is the intended failure boundary. Inspect that lane's message/frame rows in `/web-status`; malformed, cross-lane, write-timeout, and backend-close paths terminate only the affected lane. |
| `/web-status` is empty | Confirm `[web.debug].enabled = true`, apply the configuration, select a window within `max_window_secs`, and generate new WEB traffic after the policy change. |
| `https-lanes` works but streams still block each other | Confirm public HTTP/2 negotiation, preserve `X-Lane-ID`, and provide enough TLS-terminator upstream connections for concurrent private HTTP/1.1 polls. |
| Telegram Desktop rejects the link | Omit the port, use a valid FQDN, port 443 externally, and only `plain` or `dd` secret mode. |
| One node works but a load-balanced pool is intermittent | Add complete-vhost affinity; WEB credential registries are process-local. |
