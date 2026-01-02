# Telemt - MTProxy on Rust + Tokio

**Telemt** is a fast, secure, and feature-rich server written in Rust: it fully implements the official Telegram proxy algo and adds many production-ready improvements such as connection pooling, replay protection, detailed statistics, masking from "prying" eyes

# GOTO
- [Features](#features)
- [Quick Start Guide](#quick-start-guide)
  - [Build](#build)
- [How to use?](#how-to-use)
  - [Systemd Method](#telemt-via-systemd)
- [FAQ](#faq)
  - [Telegram Calls](#telegram-calls-via-mtproxy)
  - [DPI](#how-does-dpi-see-mtproxy-tls)
  - [Whitelist on Network Level](#whitelist-on-ip)
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

### Build
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

## How to use?
### Telemt via Systemd
**0. Check port and generate secrets**

The port you have selected for use should be MISSING from the list, when:
```bash
netstat -lnp
```

Generate 16 bytes/32 characters HEX with OpenSSL or another way:
```bash
openssl rand -hex 16
```

**1. Place your config to /etc/telemt.toml**
```bash
port = 443                              # Listening port

[users]
hello = "00000000000000000000000000000000" # Replace the secret with one generated before

[modes]
classic = false                         # Plain obfuscated mode
secure = false                          # dd-prefix mode
tls = true                              # Fake TLS - ee-prefix

tls_domain = "petrovich.ru"             # Domain for ee-secret and masking
mask = true                             # Enable masking of bad traffic
mask_host = "petrovich.ru"              # Optional override for mask destination
mask_port = 443                         # Port for masking

prefer_ipv6 = false                     # Try IPv6 DCs first if true
fast_mode = true                        # Use "fast" obfuscation variant

client_keepalive = 600                  # Seconds
client_ack_timeout = 300                # Seconds
```
**2. Create service on /etc/systemd/system/telemt.service**
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
**3.**  In Shell type `systemctl start telemt` - it must start with zero exit-code

**4.** In Shell type `systemctl status telemt` - there you can reach info about current MTProxy status

**5.** In Shell type `systemctl enable telemt` - then telemt will start with system startup, after the network is up

## FAQ
### Telegram Calls via MTProxy
- Telegram architecture does **NOT allow calls via MTProxy**, but only via SOCKS5, which cannot be obfuscated
### How does DPI see MTProxy TLS?
- DPI sees MTProxy in Fake TLS (ee) mode as TLS 1.3
- the SNI you specify sends both the client and the server;
- ALPN is similar to HTTP 1.1/2;
- high entropy, which is normal for AES-encrypted traffic;
### Whitelist on IP
- MTProxy cannot work when there is: 
  - no IP connectivity to the target host
  - OR all TCP traffic is blocked
  - OR all TLS traffic is blocked,
- like most protocols on the Internet; 
- this situation is observed in China behind the Great Chinese Firewall and in Russia on mobile networks

## Why Rust?
- Long-running reliability and idempotent behavior
- Rust’s deterministic resource management - RAII 
- No garbage collector
- Memory safety and reduced attack surface
- Tokio's asynchronous architecture

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
