# High-Load Configuration & Tuning Guide
When deploying Telemt under high-traffic load (tens or hundreds of thousands of concurrent connections), the standard OS network stack limits can lead to packet drops, high CPU context switching, and connection failures. This guide covers Linux kernel tuning, hardware configuration, and architecture optimizations required to prepare the server for high-load scenarios.

---
## 1. System Limits & File Descriptors
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
High churn rates lead to ephemeral port exhaustion. Expand the range and rapidly recycle closed sockets:
```ini
net.ipv4.ip_local_port_range = 10000 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 2000000
```
### 2.3 TCP Keepalive (Aggressive Dead Connection Culling)
By default, Linux keeps silent, dropped connections open for over 2 hours. This consumes memory at scale. Configure the system to detect and drop them in < 5 minutes:
```ini
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
```
### 2.4 TCP Buffers & Congestion Control
Optimize memory usage per socket and switch to BBR (Bottleneck Bandwidth and Round-trip propagation time) to improve latency on lossy networks:
```ini
# Core buffer sizes
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
# TCP specific buffers (min, default, max)
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
# Enable BBR
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
```

---
## 3. Conntrack (Netfilter) Tuning
If your server uses `iptables`, `ufw`, or `firewalld`, the Linux kernel tracks every connection state in a table (`nf_conntrack`). When this table fills up, Linux drops new packets.
Check your current limit and usage:
```bash
sysctl net.netfilter.nf_conntrack_max
sysctl net.netfilter.nf_conntrack_count
```
If it gets close to the limit, tune it up, and reduce the time established connections linger in the tracker:
```ini
# In /etc/sysctl.d/99-telemt-highload.conf
net.netfilter.nf_conntrack_max = 2097152
# Reduce timeout from default 5 days to 1 hour
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 12
```
*Note: Depending on your OS, you may need to run `modprobe nf_conntrack` before setting these parameters.*

---
## 4. Multi-Tier Architecture: HAProxy Setup
For massive traffic loads, buffering Telemt behind a reverse proxy like HAProxy can help absorb connection spikes and handle basic TCP connections before handing them off.
### HAProxy High-Load `haproxy.cfg`
```haproxy
global
    # Disable detailed logging under load
    log stdout format raw local0 err
    # maxconn 250000
    
    # Buffer tuning
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
    # Quick purge for dead peers
    timeout client-fin 10s
    timeout server-fin 10s
frontend proxy_in
    bind *:443
    maxconn 250000
    option tcp-smart-accept
    default_backend telemt_backend
backend telemt_backend
    option tcp-smart-connect
    # Send-Proxy-V2 to preserve Client IP for Telemt's internal logic
    server telemt_core 10.10.10.1:443 maxconn 250000 send-proxy-v2 check inter 5s
```
**Important**: Telemt must be configured to process the `PROXY` protocol on port `443` for this chain to work and preserve client IPs.

---
## 5. Diagnostics & Monitoring
When operating under load, these commands are useful for diagnostics:
* **Checking dropped connections (Queues full)**: `netstat -s | grep "times the listen queue of a socket overflowed"`
* **Checking Conntrack drops**: `dmesg | grep conntrack`
* **Checking File Descriptor usage**: `cat /proc/sys/fs/file-nr`
* **Real-time connection states**: `ss -s` (Avoid using `netstat` on heavy loads).
