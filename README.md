# Telemt - MTProxy on Rust + Tokio

**Telemt** is a fast, secure, and feature-rich server written in Rust: it fully implements the official Telegram proxy algo and adds many production-ready improvements such as connection pooling, replay protection, detailed statistics, masking from "prying" eyes

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
  - [Telegram Calls](#telegram-calls-via-mtproxy)
  - [DPI](#how-does-dpi-see-mtproxy-tls)
  - [Whitelist on Network Level](#whitelist-on-ip)
- [Build](#build)
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
port = 443                              # Listening port
show_link = ["tele", "hello"]          # Specify users, for whom will be displayed the links

tls_domain = "petrovich.ru"             # Domain for ee-secret and masking
mask = true                             # Enable masking of bad traffic
mask_host = "petrovich.ru"              # Optional override for mask destination
mask_port = 443                         # Port for masking

prefer_ipv6 = false                     # Try IPv6 DCs first if true
fast_mode = true                        # Use "fast" obfuscation variant

client_keepalive = 600                  # Seconds
client_ack_timeout = 300                # Seconds

[modes]
classic = true                          # Plain obfuscated mode
secure = true                           # dd-prefix mode
tls = true                              # Fake TLS (ee-prefix)

[users]
hello = "00000000000000000000000000000000" # Replace the secret with one generated before
tele = "00000000000000000000000000000000" # Replace the secret with one generated before
```
### Advanced
#### Adtag
To use channel advertising and usage statistics from Telegram, get Adtag from [@mtproxybot](https://t.me/mtproxybot), add this parameter to the end of config.toml and specify it
```toml
ad_tag = "00000000000000000000000000000000" # Replace zeros to your adtag from @mtproxybot
```
#### Listening and Announce IPs
To specify listening address and/or address in links, add to the end of config.toml:
```toml
[[listeners]]
ip = "0.0.0.0"          # 0.0.0.0 = all IPs; your IP = specific listening
announce_ip = "1.2.3.4" # IP in links; comment with # if not used
```
#### Upstream Manager
To specify upstream, add to the end of config.toml:
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

## Why Rust?
- Long-running reliability and idempotent behavior
- Rust’s deterministic resource management - RAII 
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
