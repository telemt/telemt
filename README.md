# Telemt - MTProxy on Rust + Tokio

***Löst Probleme, bevor andere überhaupt wissen, dass sie existieren*** / ***It solves problems before others even realize they exist***

**Telemt** is a fast, secure, and feature-rich server written in Rust: it fully implements the official Telegram proxy algo and adds many production-ready improvements such as:
- [ME Pool + Reader/Writer + Registry + Refill + Adaptive Floor + Trio-State + Generation Lifecycle](https://github.com/telemt/telemt/blob/main/docs/model/MODEL.en.md)
- [Full-covered API w/ management](https://github.com/telemt/telemt/blob/main/docs/API.md)
- Anti-Replay on Sliding Window
- Prometheus-format Metrics
- TLS-Fronting and TCP-Splicing for masking from "prying" eyes

[**Telemt Chat in Telegram**](https://t.me/telemtrs)

## NEWS and EMERGENCY
### ✈️ Telemt 3 is released!
<table>
<tr>
<td width="50%" valign="top">

### 🇷🇺 RU

#### О релизах

[3.3.27](https://github.com/telemt/telemt/releases/tag/3.3.27) даёт баланс стабильности и передового функционала, а так же последние исправления по безопасности и багам

Будем рады вашему фидбеку и предложениям по улучшению — особенно в части **API**, **статистики**, **UX**

---

Если у вас есть компетенции в:

- Асинхронных сетевых приложениях  
- Анализе трафика  
- Реверс-инжиниринге  
- Сетевых расследованиях  

Мы открыты к архитектурным предложениям, идеям и pull requests
</td>
<td width="50%" valign="top">

### 🇬🇧 EN

#### About releases

[3.3.27](https://github.com/telemt/telemt/releases/tag/3.3.27) provides a balance of stability and advanced functionality, as well as the latest security and bug fixes

We are looking forward to your feedback and improvement proposals — especially regarding **API**, **statistics**, **UX**

---

If you have expertise in:

- Asynchronous network applications  
- Traffic analysis  
- Reverse engineering  
- Network forensics  

We welcome ideas, architectural feedback, and pull requests.
</td>
</tr>
</table>

# Features
💥 The configuration structure has changed since version 1.1.0.0. change it in your environment!

⚓ Our implementation of **TLS-fronting** is one of the most deeply debugged, focused, advanced and *almost* **"behaviorally consistent to real"**:  we are confident we have it right - [see evidence on our validation and traces](#recognizability-for-dpi-and-crawler)

⚓ Our ***Middle-End Pool*** is fastest by design in standard scenarios, compared to other implementations of connecting to the Middle-End Proxy: non dramatically, but usual

- Full support for all official MTProto proxy modes:
  - Classic
  - Secure - with `dd` prefix
  - Fake TLS - with `ee` prefix + SNI fronting
- Replay attack protection
- Optional traffic masking: forward unrecognized connections to a real web server, e.g. GitHub 🤪
- Configurable keepalives + timeouts + IPv6 and "Fast Mode"
- Graceful shutdown on Ctrl+C
- Extensive logging via `trace` and `debug` with `RUST_LOG` method

# GOTO
- [Quick Start Guide](#quick-start-guide)
- [FAQ](#faq)
  - [Recognizability for DPI and crawler](#recognizability-for-dpi-and-crawler)
    - [Client WITH secret-key accesses the MTProxy resource:](#client-with-secret-key-accesses-the-mtproxy-resource)
    - [Client WITHOUT secret-key gets transparent access to the specified resource:](#client-without-secret-key-gets-transparent-access-to-the-specified-resource)
  - [Telegram Calls via MTProxy](#telegram-calls-via-mtproxy)
  - [How does DPI see MTProxy TLS?](#how-does-dpi-see-mtproxy-tls)
  - [Whitelist on IP](#whitelist-on-ip)
  - [Too many open files](#too-many-open-files)
- [Build](#build)
- [Why Rust?](#why-rust)
- [Issues](#issues)
- [Roadmap](#roadmap)


## Quick Start Guide
- [Quick Start Guide RU](docs/QUICK_START_GUIDE.ru.md)
- [Quick Start Guide EN](docs/QUICK_START_GUIDE.en.md)

## FAQ

- [FAQ RU](docs/FAQ.ru.md)
- [FAQ EN](docs/FAQ.en.md)

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

# Low-RAM devices (1 GB, e.g. NanoPi Neo3 / Raspberry Pi Zero 2):
# release profile uses lto = "thin" to reduce peak linker memory.
# If your custom toolchain overrides profiles, avoid enabling fat LTO.

# Move to /bin
mv ./target/release/telemt /bin
# Make executable
chmod +x /bin/telemt
# Lets go!
telemt config.toml
```

### OpenBSD
- Build and service setup guide: [OpenBSD Guide (EN)](docs/OPENBSD.en.md)
- Example rc.d script: [contrib/openbsd/telemt.rcd](contrib/openbsd/telemt.rcd)
- Status: OpenBSD sandbox hardening with `pledge(2)` and `unveil(2)` is not implemented yet.


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
