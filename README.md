# Telemt - MTProxy on Rust + Tokio

***Löst Probleme, bevor andere überhaupt wissen, dass sie existieren*** / ***It solves problems before others even realize they exist***

> [!NOTE]
>
> Fixed TLS ClientHello is now available in **Telegram Desktop** starting from version **6.7.2**: to work with EE-MTProxy, please update your client;
> 
> Fixed TLS ClientHello for Telegram Android Client is available in [our chat](https://t.me/telemtrs/30234/36441); **official releases for Android and iOS are "work in progress"**;

<p align="center">
  <a href="https://t.me/telemtrs">
    <img src="docs/assets/telegram_button.png" alt="Join us in Telegram" />
  </a>
</p>

**Telemt** is a fast, secure, and feature-rich server written in Rust: it fully implements the official Telegram proxy algo and adds many production-ready improvements such as:
- [ME Pool + Reader/Writer + Registry + Refill + Adaptive Floor + Trio-State + Generation Lifecycle](https://github.com/telemt/telemt/blob/main/docs/model/MODEL.en.md);
- [Full-covered API w/ management](https://github.com/telemt/telemt/blob/main/docs/API.md);
- Anti-Replay on Sliding Window;
- Prometheus-format Metrics;
- TLS-Fronting and TCP-Splicing for masking from "prying" eyes.

![telemt_scheme](docs/assets/telemt.png)

⚓ Our implementation of **TLS-fronting** is one of the most deeply debugged, focused, advanced and *almost* **"behaviorally consistent to real"**:  we are confident we have it right - [see evidence on our validation and traces](#recognizability-for-dpi-and-crawler)

⚓ Our ***Middle-End Pool*** is fastest by design in standard scenarios, compared to other implementations of connecting to the Middle-End Proxy: non dramatically, but usual

- Full support for all official MTProto proxy modes:
  - Classic;
  - Secure - with `dd` prefix;
  - Fake TLS - with `ee` prefix + SNI fronting;
- Replay attack protection;
- Optional traffic masking: forward unrecognized connections to a real web server, e.g. GitHub 🤪;
- Configurable keepalives + timeouts + IPv6 and "Fast Mode";
- Graceful shutdown on Ctrl+C;
- Extensive logging via `trace` and `debug` with `RUST_LOG` method.

# GOTO
- [FAQ](#faq)
- [Architecture](docs/Architecture)
- [Quick Start Guide](#quick-start-guide)
- [Config parameters](docs/Config_params)
- [Build](#build)
- [Why Rust?](#why-rust)
- [Issues](#issues)
- [Roadmap](#roadmap)

## Quick Start Guide
- [Quick Start Guide RU](docs/Quick_start/QUICK_START_GUIDE.ru.md)
- [Quick Start Guide EN](docs/Quick_start/QUICK_START_GUIDE.en.md)

## FAQ

- [FAQ RU](docs/FAQ.ru.md)
- [FAQ EN](docs/FAQ.en.md)

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
- Build and service setup guide: [OpenBSD Guide (EN)](docs/Quick_start/OPENBSD_QUICK_START_GUIDE.en.md)
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
