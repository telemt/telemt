# High-Load Configuration & Tuning Guide

[English](HIGH_LOAD.en.md) · [Русский](HIGH_LOAD.ru.md) · [Deutsch](HIGH_LOAD.de.md)

Use this guide when measured load exposes a specific resource limit. The values below are example capacities, not a tested guarantee of a particular connection count. Record the kernel version, active configuration, connection rate, memory use and latency before changing a setting. Save the previous values and change one group at a time so you can compare and revert it.

For terminology, see the [shared glossary](../TERMINOLOGY.md).

---
## 1. System Limits & File Descriptors

Also size [`server.max_connections`](../Config_params/CONFIG_PARAMS.en.md#max_connections) for the intended client load, including ME traffic. `0` removes this configured client ceiling and does not impose a 128-client ME limit. OS descriptors, per-user limits, queues, memory budgets, and writer policies still apply. Changing this setting requires a process restart.

Every TCP connection requires a file descriptor. At 100k connections, standard Linux limits (often 1024 or 65535) will be exhausted immediately.
### System-Wide Limits (`sysctl`)
Increase the global file descriptor limit in `/etc/sysctl.conf`:
```ini
fs.file-max = 2097152
fs.nr_open = 2097152
```
### User-Level Limits (`limits.conf`)
Edit `/etc/security/limits.conf` to allow the telemt (or proxy) user to allocate them:
```conf
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
```
### Systemd / Docker Overrides
If using **Systemd**, add to your `telemt.service`:
```ini
[Service]
LimitNOFILE=1048576
LimitNPROC=65535
TasksMax=infinity
```
If using **Docker**, configure `ulimits` in `docker-compose.yaml`:
```yaml
services:
  telemt:
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
```

---
## 2. Kernel Network Stack Tuning (`sysctl`)
Create a dedicated file `/etc/sysctl.d/99-telemt-highload.conf` and apply it via `sysctl -p /etc/sysctl.d/99-telemt-highload.conf`.
### 2.1 Connection Queues & SYN Flood Protection
Increase the size of accept queues to absorb sudden connection spikes (bursts) and mitigate SYN floods:
```ini
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_syncookies = 1
```
### 2.2 Port Exhaustion & TIME-WAIT Sockets
First distinguish failed outbound connects caused by exhausted source ports from a large but harmless TIME-WAIT population. Inspect the failing error, destination tuples and `ss -s`. Expanding the ephemeral range can help when this is the limiting resource; account for ports reserved by other services:

```ini
net.ipv4.ip_local_port_range = 10000 65535
```

`tcp_tw_reuse` controls reuse of TIME-WAIT sockets when the protocol permits it. In the referenced kernel documentation, `0` disables it, `1` enables it globally and `2` limits it to loopback; inspect your running kernel's current value before changing it. `tcp_max_tw_buckets` limits retained TIME-WAIT entries, not the duration of TIME-WAIT.

`tcp_fin_timeout` applies to orphaned connections in `FIN_WAIT_2`; reducing it does not shorten `TIME_WAIT`. Keep these mechanisms separate when investigating port exhaustion. See the [Linux IP sysctl reference](https://docs.kernel.org/networking/ip-sysctl.html).

### 2.3 TCP Keepalive
These sysctls are defaults for sockets with TCP keepalive enabled that do not override the corresponding options. They start probing after five idle minutes and exhaust the subsequent probe budget after roughly 7–8 minutes of total inactivity:

```ini
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
```

Telemt overrides keepalive time and interval on client sockets using `timeouts.client_keepalive` (default 15 seconds). On Linux its ME sockets use 30 seconds idle, a 10-second interval and 3 probes. These are TCP socket settings; ME RPC Ping/Pong, `timeouts.client_ack` and relay idle policies impose separate checks. The sysctl example therefore does not define the lifetime of every Telemt connection. Verify the relevant socket and configured application timeout.

### 2.4 TCP Buffers & Congestion Control
Measure memory pressure, throughput and p95/p99 latency with the same workload before and after changing buffers. The maximum below is a ceiling for an eligible socket, not a fixed allocation for every connection. Telemt also sets socket buffer sizes explicitly, so kernel defaults alone do not describe its effective buffers.

```ini
# Example buffer ceilings: size them for the available memory and workload.
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
```

Check available congestion-control algorithms with `sysctl net.ipv4.tcp_available_congestion_control`. If BBR is supported, evaluate it against the current algorithm under representative RTT, loss and load; this guide does not establish that it always improves latency. An example BBR configuration is:

```ini
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
```


---
## 3. Conntrack (Netfilter) Tuning
Stateful firewall and NAT rules can use `nf_conntrack` to track connections. Check whether tracking is active on the relevant route, especially with NOTRACK rules. Exhausting the conntrack table can cause new packets to be dropped.
Check your current limit and usage:
```bash
sysctl net.netfilter.nf_conntrack_max
sysctl net.netfilter.nf_conntrack_count
```
If measured occupancy approaches the limit and memory permits, evaluate a larger table. Shorter tracking timeouts can remove idle NAT/firewall state needed by long-lived connections, so validate them separately. These are example values, not a universal profile:
```ini
# In /etc/sysctl.d/99-telemt-highload.conf
net.netfilter.nf_conntrack_max = 2097152
# Reduce timeout from default 5 days to 1 hour
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 12
```
*Note: Depending on your OS, you may need to run `modprobe nf_conntrack` before setting these parameters.*

When `server.conntrack_control.inline_conntrack_control = true` and `[server.conntrack_control]` uses `notrack` or `hybrid`, one generation-fenced authority owns only the conntrack-control rules created by Telemt. It applies IPv4 and IPv6 changes, ignores stale or conflicting publications, and retries failed reconciliation after 1, 2, 4, 8, 16, then capped 30-second delays. A partial multi-command failure triggers best-effort restoration; failed rollback leaves the applied firewall state unknown until a later successful reconcile. `telemt_conntrack_control_state{flag="rule_apply_ok"}` reports whether the desired rule set is effective. With core telemetry enabled, reconcile and rollback attempts use `telemt_conntrack_rule_reconcile_total{result="success"|"error"}` and `telemt_conntrack_rule_rollback_total{result="success"|"error"}`. Shutdown performs a bounded 30-second best-effort cleanup of owned rules. Conntrack-control configuration remains restart-only.

---
## 4. Multi-Tier Architecture: HAProxy Setup

### 4.1 Native MTProxy and TLS-front L4 deployment

For massive native MTProxy or TLS-front traffic, an L4 HAProxy can absorb connection spikes before handing TCP streams to Telemt. The following example is **not valid for a WEB listener**.

#### HAProxy High-Load `haproxy.cfg`
```haproxy
global
    # Disable detailed connection logs under load
    log stdout format raw local0 err
    maxconn 250000
    # Tune buffers and socket acceptance
    tune.bufsize 16384
    tune.maxaccept 64
defaults
    log     global
    mode    tcp
    option  clitcpka
    option  srvtcpka
    timeout connect 5s
    timeout client  1h
    timeout server  1h
    # Purge dead peers quickly
    timeout client-fin 10s
    timeout server-fin 10s
frontend proxy_in
    bind *:443
    maxconn 250000
    option tcp-smart-accept
    default_backend telemt_backend
backend telemt_backend
    option tcp-smart-connect
    # Preserve the client IP for Telemt through PROXY v2
    server telemt_core 10.10.10.1:443 maxconn 250000 send-proxy-v2 check inter 5s
```
**Important**: configure the explicit Telemt listener for PROXY protocol and set `server.proxy_protocol_trusted_cidrs` to the immediate HAProxy addresses. Check its bind address and host firewall. The [two-hop example](../Setup_examples/VPS_DOUBLE_HOP.en.md#step-2-installing-telemt-on-server-b-conditionally-netherlands) shows the complete listener setup.

### 4.2 WEB deployment

WEB mode requires an L7 TLS terminator and a private plain HTTP/1.1 Telemt listener with `proxy_protocol = false`; do not reuse the L4 `send-proxy-v2` backend above. Follow the complete [WEB proxy guide](../WEB/WEB_PROXY.en.md) and preserve `Host`, the exact path and query, WebSocket Upgrade headers, and a single overwritten `X-Forwarded-For` value from explicitly trusted terminator CIDRs. Public ALPN must offer `h2` for `https-lanes` and `http/1.1` for WebSocket Upgrade.

Set the WEB listener to `web_client_ip_source = "x_forwarded_for"` and list only the immediate HAProxy addresses in `web_trusted_proxy_cidrs`. Never trust a client-reachable subnet and never enable PROXY protocol on this listener.

Route the complete vhost to one Telemt process. For prefix cohosting, preserve the configured `base_path` without rewrite; while migrating it, route both old and new subtrees to Telemt until old process-issued credentials can no longer be used. Multi-process backends require whole-vhost affinity for the bridge root, session creation, recovery, uplink, downlink, DELETE, diagnostics, and WebSocket Upgrade.

For example, this HAProxy fragment routes only one exact host and slash-terminated WEB subtree without changing the request target:

```haproxy
frontend https_in
    mode http
    bind *:443 ssl crt /etc/haproxy/certs/proxy.pem alpn h2,http/1.1
    timeout client 65s
    acl telemt_web_host hdr(host) -i proxy.example.com proxy.example.com:443
    acl telemt_web_path path_beg /telegram/web/
    use_backend telemt_web if telemt_web_host telemt_web_path

backend telemt_web
    mode http
    retries 0
    timeout connect 5s
    timeout server 65s
    http-request set-header Host proxy.example.com
    http-request set-header X-Forwarded-For %[src]
    server telemt_web_1 127.0.0.1:18080 check
```

Handle the no-slash `/telegram/web` path outside this backend so the frontend cannot synthesize a redirect alias into the authenticated subtree. Do not add `set-path`, `replace-path`, or a path component to the backend server URL. The 65-second values are examples for the defaults; configure client and server timeouts above `web.timeouts.long_poll_secs` and twice the effective WebSocket liveness interval.

Capacity planning must include both public TLS sockets and private terminator-to-Telemt sockets. Size file descriptors, terminator upstream capacity, `web.limits.max_http_connections`, handler capacity, concurrent long polls, and WebSocket lanes together; an upstream keepalive pool is not a concurrency limit.

---
## 5. Diagnostics & Monitoring
When operating under load, these commands are useful for diagnostics:

- **Listen queue drops**: inspect `ListenOverflows` and `ListenDrops` in `/proc/net/netstat` or `nstat`.
- **Conntrack pressure**: inspect `nf_conntrack_count`, kernel logs, and `telemt_conntrack_control_state{flag="rule_apply_ok"}`; with core telemetry enabled, also inspect the reconcile/rollback counters above.
- **File descriptor usage**: `cat /proc/sys/fs/file-nr` and the Telemt process limits under `/proc/<pid>/limits`.
- **Connection states**: `ss -s`; avoid full `netstat` scans on a busy host.
- **Rate limiter contention**: with core telemetry enabled, alert on a positive counter increase or rate, for example `increase(telemt_rate_limiter_cas_retry_exhausted_total[5m]) > 0`, grouped by `scope`, `direction`, and `operation`. Reserve exhaustion returns a zero grant without classifying it as a configured throttle; refund exhaustion retains the charge. This metric is neither a connection-drop counter nor a policy-throttle counter.
- **WEB**: combine terminator telemetry and an external TLS probe with `/v1/runtime/web/status`, `telemt_web_tcp_accept_total{result="accepted"|"error"}`, and the other `telemt_web_*` metrics. Request paths and `base_path` are intentionally not metric labels.
