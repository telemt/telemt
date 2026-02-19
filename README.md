# Telemt - MTProxy on Rust + Tokio

**Telemt** is a fast, secure, and feature-rich server written in Rust: it fully implements the official Telegram proxy algo and adds many production-ready improvements such as connection pooling, replay protection, detailed statistics, masking from "prying" eyes

## NEWS and EMERGENCY
### ✈️ Telemt 3 is released!
<table>
<tr>
<td width="50%" valign="top">

### 🇷🇺 RU

18 февраля мы опубликовали `telemt 3.0.3`, он имеет:

- улучшенный механизм Middle-End Health Check
- высокоскоростное восстановление инициализации Middle-End
- меньше задержек на hot-path
- более корректную работу в Dualstack, а именно - IPv6 Middle-End
- аккуратное переподключение клиента без дрифта сессий между Middle-End
- автоматическая деградация на Direct-DC при массовой (>2 ME-DC-групп) недоступности Middle-End
- автодетект IP за NAT, при возможности - будет выполнен хендшейк с ME, при неудаче - автодеградация
- единственный известный специальный DC=203 уже добавлен в код: медиа загружаются с CDN в Direct-DC режиме

[Здесь вы можете найти релиз](https://github.com/telemt/telemt/releases/tag/3.0.3)

Если у вас есть компетенции в асинхронных сетевых приложениях, анализе трафика, реверс-инжиниринге или сетевых расследованиях - мы открыты к идеям и pull requests!

</td>
<td width="50%" valign="top">

### 🇬🇧 EN

On February 18, we released `telemt 3.0.3`. This version introduces:

- improved Middle-End Health Check method  
- high-speed recovery of Middle-End init
- reduced latency on the hot path  
- correct Dualstack support: proper handling of IPv6 Middle-End  
- *clean* client reconnection without session "drift" between Middle-End
- automatic degradation to Direct-DC mode in case of large-scale (>2 ME-DC groups) Middle-End unavailability  
- automatic public IP detection behind NAT; first - Middle-End handshake is performed, otherwise automatic degradation is applied  
- known special DC=203 is now handled natively: media is delivered from the CDN via Direct-DC mode  

[Release is available here](https://github.com/telemt/telemt/releases/tag/3.0.3)

If you have expertise in asynchronous network applications, traffic analysis, reverse engineering, or network forensics - we welcome ideas and pull requests!

</td>
</tr>
</table>

# Features
💥 The configuration structure has changed since version 1.1.0.0. change it in your environment!

⚓ Our implementation of **TLS-fronting** is one of the most deeply debugged, focused, advanced and *almost* **"behaviorally consistent to real"**:  we are confident we have it right - [see evidence on our validation and traces](#recognizability-for-dpi-and-crawler)

⚓ Our ***Middle-End Pool*** is fastest by design in standard scenarios, compared to other implementations of connecting to the Middle-End Proxy: non dramatically, but usual

# GOTO
- [Features](#features)
- [Quick Start Guide](#quick-start-guide)
- [How to use?](#how-to-use)
  - [Systemd Method](#telemt-via-systemd)
- [Configuration](#configuration)
  - [Minimal Configuration](#minimal-configuration-for-first-start)
  - [Advanced](#advanced)
    - [Adtag](#adtag)
    - [Listening and Announce IPs](#listening-and-announce-ips)
    - [Upstream Manager](#upstream-manager)
      - [IP](#bind-on-ip)
      - [SOCKS](#socks45-as-upstream)
- [FAQ](#faq)
  - [Recognizability for DPI + crawler](#recognizability-for-dpi-and-crawler)
  - [Telegram Calls](#telegram-calls-via-mtproxy)
  - [DPI](#how-does-dpi-see-mtproxy-tls)
  - [Whitelist on Network Level](#whitelist-on-ip)
  - [Too many open files](#too-many-open-files)
- [Build](#build)
- [Docker](#docker)
- [Why Rust?](#why-rust)

## Features

- Full support for all official MTProto proxy modes:
  - Classic
  - Secure - with `dd` prefix
  - Fake TLS - with `ee` prefix + SNI fronting
- Replay attack protection
- Optional traffic masking: forward unrecognized connections to a real web server, e.g. GitHub 🤪
- Configurable keepalives + timeouts + IPv6 and "Fast Mode"
- Graceful shutdown on Ctrl+C
- Extensive logging via `trace` and `debug` with `RUST_LOG` method

## Quick Start Guide
**This software is designed for Debian-based OS: in addition to Debian, these are Ubuntu, Mint, Kali, MX and many other Linux**
1. Download release
```bash
wget https://github.com/telemt/telemt/releases/latest/download/telemt
```
2. Move to Bin Folder
```bash
mv telemt /bin
```
4. Make Executable
```bash
chmod +x /bin/telemt
```
5. Go to [How to use?](#how-to-use) section for for further steps

## How to use?
### Telemt via Systemd
**This instruction "assume" that you:**
- logged in as root or executed `su -` / `sudo su`
- you already have an assembled and executable `telemt` in /bin folder as a result of the [Quick Start Guide](#quick-start-guide) or [Build](#build)

**0. Check port and generate secrets**

The port you have selected for use should be MISSING from the list, when:
```bash
netstat -lnp
```

Generate 16 bytes/32 characters HEX with OpenSSL or another way:
```bash
openssl rand -hex 16
```
OR
```bash
xxd -l 16 -p /dev/urandom
```
OR
```bash
python3 -c 'import os; print(os.urandom(16).hex())'
```

**1. Place your config to /etc/telemt.toml**

Open nano
```bash
nano /etc/telemt.toml
```
paste your config from [Configuration](#configuration) section

then Ctrl+X -> Y -> Enter to save

**2. Create service on /etc/systemd/system/telemt.service**

Open nano
```bash
nano /etc/systemd/system/telemt.service
```
paste this Systemd Module
```bash
[Unit]
Description=Telemt
After=network.target

[Service]
Type=simple
WorkingDirectory=/bin
ExecStart=/bin/telemt /etc/telemt.toml
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```
then Ctrl+X -> Y -> Enter to save

**3.**  In Shell type `systemctl start telemt` - it must start with zero exit-code

**4.** In Shell type `systemctl status telemt` - there you can reach info about current MTProxy status

**5.** In Shell type `systemctl enable telemt` - then telemt will start with system startup, after the network is up

## Configuration
### Minimal Configuration for First Start
```toml
# === General Settings ===
[general]
# prefer_ipv6 is deprecated; use [network].prefer
prefer_ipv6 = false
fast_mode = true
use_middle_proxy = false
# ad_tag = "..."
# disable_colors = false  # Disable colored output in logs (useful for files/systemd)

[network]
ipv4 = true
ipv6 = true   # set false to disable, omit for auto
prefer = 4    # 4 or 6
multipath = false

[general.modes]
classic = false
secure = false
tls = true

# === Server Binding ===
[server]
port = 443
listen_addr_ipv4 = "0.0.0.0"
listen_addr_ipv6 = "::"
# metrics_port = 9090
# metrics_whitelist = ["127.0.0.1", "::1"]

# Listen on multiple interfaces/IPs (overrides listen_addr_*)
[[server.listeners]]
ip = "0.0.0.0"
# announce = "my.hostname.tld" # Optional: hostname for tg:// links
# OR
# announce = "1.2.3.4" # Optional: Public IP for tg:// links

[[server.listeners]]
ip = "::"

# Users to show in the startup log (tg:// links)
[general.links]
show = ["hello"]          # Only show links for user "hello"
# show = ["alice", "bob"] # Only show links for alice and bob
# show = "*"              # Show links for all users
# public_host = "proxy.example.com"  # Host (IP or domain) for tg:// links
# public_port = 443                  # Port for tg:// links (default: server.port)

# === Timeouts (in seconds) ===
[timeouts]
client_handshake = 15
tg_connect = 10
client_keepalive = 60
client_ack = 300

# === Anti-Censorship & Masking ===
[censorship]
tls_domain = "petrovich.ru"
mask = true
mask_port = 443
# mask_host = "petrovich.ru" # Defaults to tls_domain if not set
# mask_unix_sock = "/var/run/nginx.sock" # Unix socket (mutually exclusive with mask_host)
fake_cert_len = 2048

# === Access Control & Users ===
# username "hello" is used for example
[access]
replay_check_len = 65536
ignore_time_skew = false

[access.users]
# format: "username" = "32_hex_chars_secret"
hello = "00000000000000000000000000000000"

# [access.user_max_tcp_conns]
# hello = 50

# [access.user_data_quota]
# hello = 1073741824 # 1 GB

# === Upstreams & Routing ===
# By default, direct connection is used, but you can add SOCKS proxy

# Direct - Default
[[upstreams]]
type = "direct"
enabled = true
weight = 10

# SOCKS5
# [[upstreams]]
# type = "socks5"
# address = "127.0.0.1:9050"
# enabled = false
# weight = 1

# === DC Address Overrides ===
# [dc_overrides]
# "203" = "91.105.192.100:443"
```
### Advanced
#### Adtag
To use channel advertising and usage statistics from Telegram, get Adtag from [@mtproxybot](https://t.me/mtproxybot), add this parameter to section `[General]`
```toml
ad_tag = "00000000000000000000000000000000" # Replace zeros to your adtag from @mtproxybot
```
#### Listening and Announce IPs
To specify listening address and/or address in links, add to section `[[server.listeners]]` of config.toml:
```toml
[[server.listeners]]
ip = "0.0.0.0"          # 0.0.0.0 = all IPs; your IP = specific listening
announce_ip = "1.2.3.4" # IP in links; comment with # if not used
```
#### Upstream Manager
To specify upstream, add to section `[[upstreams]]` of config.toml:
##### Bind on IP
```toml
[[upstreams]]
type = "direct"
weight = 1
enabled = true
interface = "192.168.1.100" # Change to your outgoing IP
```
##### SOCKS4/5 as Upstream
- Without Auth:
```toml
[[upstreams]]
type = "socks5"            # Specify SOCKS4 or SOCKS5
address = "1.2.3.4:1234"   # SOCKS-server Address
weight = 1                 # Set Weight for Scenarios
enabled = true
```

- With Auth:
```toml
[[upstreams]]
type = "socks5"            # Specify SOCKS4 or SOCKS5
address = "1.2.3.4:1234"   # SOCKS-server Address
username = "user"          # Username for Auth on SOCKS-server
password = "pass"          # Password for Auth on SOCKS-server
weight = 1                 # Set Weight for Scenarios
enabled = true
```

## FAQ
### Recognizability for DPI and crawler
Since version 1.1.0.0, we have debugged masking perfectly: for all clients without "presenting" a key, 
we transparently direct traffic to the target host!

- We consider this a breakthrough aspect, which has no stable analogues today
- Based on this: if `telemt` configured correctly, **TLS mode is completely identical to real-life handshake + communication** with a specified host
- Here is our evidence:
    - 212.220.88.77 - "dummy" host, running `telemt`
    - `petrovich.ru` - `tls` + `masking` host, in HEX: `706574726f766963682e7275`
    - **No MITM + No Fake Certificates/Crypto** = pure transparent *TCP Splice* to "best" upstream: MTProxy or tls/mask-host:
      - DPI see legitimate HTTPS to `tls_host`, including *valid chain-of-trust* and entropy
      - Crawlers completely satisfied receiving responses from `mask_host`
  #### Client WITH secret-key accesses the MTProxy resource:
  
  <img width="360" height="439" alt="telemt" src="https://github.com/user-attachments/assets/39352afb-4a11-4ecc-9d91-9e8cfb20607d" />
  
  #### Client WITHOUT secret-key gets transparent access to the specified resource:
    - with trusted certificate
    - with original handshake
    - with full request-response way
    - with low-latency overhead
```bash
root@debian:~/telemt# curl -v -I --resolve petrovich.ru:443:212.220.88.77 https://petrovich.ru/
* Added petrovich.ru:443:212.220.88.77 to DNS cache
* Hostname petrovich.ru was found in DNS cache
*   Trying 212.220.88.77:443...
* Connected to petrovich.ru (212.220.88.77) port 443 (#0)
* ALPN: offers h2,http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
*  CAfile: /etc/ssl/certs/ca-certificates.crt
*  CApath: /etc/ssl/certs
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* ALPN: server did not agree on a protocol. Uses default.
* Server certificate:
*  subject: C=RU; ST=Saint Petersburg; L=Saint Petersburg; O=STD Petrovich; CN=*.petrovich.ru
*  start date: Jan 28 11:21:01 2025 GMT
*  expire date: Mar  1 11:21:00 2026 GMT
*  subjectAltName: host "petrovich.ru" matched cert's "petrovich.ru"
*  issuer: C=BE; O=GlobalSign nv-sa; CN=GlobalSign RSA OV SSL CA 2018
*  SSL certificate verify ok.
* using HTTP/1.x
> HEAD / HTTP/1.1
> Host: petrovich.ru
> User-Agent: curl/7.88.1
> Accept: */*
> 
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* old SSL session ID is stale, removing
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
< Server: Variti/0.9.3a
Server: Variti/0.9.3a
< Date: Thu, 01 Jan 2026 00:0000 GMT
Date: Thu, 01 Jan 2026 00:0000 GMT
< Access-Control-Allow-Origin: *
Access-Control-Allow-Origin: *
< Content-Type: text/html
Content-Type: text/html
< Cache-Control: no-store
Cache-Control: no-store
< Expires: Thu, 01 Jan 2026 00:0000 GMT
Expires: Thu, 01 Jan 2026 00:0000 GMT
< Pragma: no-cache
Pragma: no-cache
< Set-Cookie: ipp_uid=XXXXX/XXXXX/XXXXX==; Expires=Tue, 31 Dec 2040 23:59:59 GMT; Domain=.petrovich.ru; Path=/
Set-Cookie: ipp_uid=XXXXX/XXXXX/XXXXX==; Expires=Tue, 31 Dec 2040 23:59:59 GMT; Domain=.petrovich.ru; Path=/
< Content-Type: text/html
Content-Type: text/html
< Content-Length: 31253
Content-Length: 31253
< Connection: keep-alive
Connection: keep-alive
< Keep-Alive: timeout=60
Keep-Alive: timeout=60

< 
* Connection #0 to host petrovich.ru left intact

```
- We challenged ourselves, we kept trying and we didn't only *beat the air*: now, we have something to show you
  - Do not just take our word for it? - This is great and we respect that: you can build your own `telemt` or download a build and check it right now
### Telegram Calls via MTProxy
- Telegram architecture **does NOT allow calls via MTProxy**, but only via SOCKS5, which cannot be obfuscated
### How does DPI see MTProxy TLS?
- DPI sees MTProxy in Fake TLS (ee) mode as TLS 1.3
- the SNI you specify sends both the client and the server;
- ALPN is similar to HTTP 1.1/2;
- high entropy, which is normal for AES-encrypted traffic;
### Whitelist on IP
- MTProxy cannot work when there is: 
  - no IP connectivity to the target host: Russian Whitelist on Mobile Networks - "Белый список"
  - OR all TCP traffic is blocked
  - OR high entropy/encrypted traffic is blocked: content filters at universities and critical infrastructure
  - OR all TLS traffic is blocked
  - OR specified port is blocked: use 443 to make it "like real"
  - OR provided SNI is blocked: use "officially approved"/innocuous name
- like most protocols on the Internet; 
- these situations are observed:
  - in China behind the Great Firewall
  - in Russia on mobile networks, less in wired networks
  - in Iran during "activity"
### Too many open files
- On a fresh Linux install the default open file limit is low; under load `telemt` may fail with `Accept error: Too many open files`
- **Systemd**: add `LimitNOFILE=65536` to the `[Service]` section (already included in the example above)
- **Docker**: add `--ulimit nofile=65536:65536` to your `docker run` command, or in `docker-compose.yml`:
```yaml
ulimits:
  nofile:
    soft: 65536
    hard: 65536
```
- **System-wide** (optional): add to `/etc/security/limits.conf`:
```
*       soft    nofile  1048576
*       hard    nofile  1048576
root    soft    nofile  1048576
root    hard    nofile  1048576
```


## Build
```bash
# Cloning repo
git clone https://github.com/telemt/telemt 
# Changing Directory to telemt
cd telemt
# Starting Release Build
cargo build --release
# Move to /bin
mv ./target/release/telemt /bin
# Make executable
chmod +x /bin/telemt
# Lets go!
telemt config.toml
```

## Docker
**Quick start (Docker Compose)**

1. Edit `config.toml` in repo root (at least: port, users secrets, tls_domain)
2. Start container:
```bash
docker compose up -d --build
```
3. Check logs:
```bash
docker compose logs -f telemt
```
4. Stop:
```bash
docker compose down
```

**Notes**
- `docker-compose.yml` maps `./config.toml` to `/app/config.toml` (read-only)
- By default it publishes `443:443` and runs with dropped capabilities (only `NET_BIND_SERVICE` is added)
- If you really need host networking (usually only for some IPv6 setups) uncomment `network_mode: host`

**Run without Compose**
```bash
docker build -t telemt:local .
docker run --name telemt --restart unless-stopped \
  -p 443:443 \
  -e RUST_LOG=info \
  -v "$PWD/config.toml:/app/config.toml:ro" \
  --read-only \
  --cap-drop ALL --cap-add NET_BIND_SERVICE \
  --ulimit nofile=65536:65536 \
  telemt:local
```

## Why Rust?
- Long-running reliability and idempotent behavior
- Rust's deterministic resource management - RAII 
- No garbage collector
- Memory safety and reduced attack surface
- Tokio's asynchronous architecture

## Issues
- ✅ [SOCKS5 as Upstream](https://github.com/telemt/telemt/issues/1) -> added Upstream Management
- ✅ [iOS - Media Upload Hanging-in-Loop](https://github.com/telemt/telemt/issues/2)

## Roadmap
- Public IP in links
- Config Reload-on-fly
- Bind to device or IP for outbound/inbound connections
- Adtag Support per SNI / Secret
- Fail-fast on start + Fail-soft on runtime (only WARN/ERROR)
- Zero-copy, minimal allocs on hotpath
- DC Healthchecks + global fallback
- No global mutable state
- Client isolation + Fair Bandwidth
- Backpressure-aware IO
- "Secret Policy" - SNI / Secret Routing :D
- Multi-upstream Balancer and Failover
- Strict FSM per handshake
- Session-based Antireplay with Sliding window, non-broking reconnects
- Web Control: statistic, state of health, latency, client experience...
