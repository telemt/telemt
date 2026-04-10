# Telemt - MTProxy on Rust + Tokio

![Latest Release](https://img.shields.io/github/v/release/telemt/telemt?color=neon) ![Stars](https://img.shields.io/github/stars/telemt/telemt?style=social) ![Forks](https://img.shields.io/github/forks/telemt/telemt?style=social) [![Telegram](https://img.shields.io/badge/Telegram-Chat-24a1de?logo=telegram&logoColor=24a1de)](https://t.me/telemtrs)

***Löst Probleme, bevor andere überhaupt wissen, dass sie existieren*** / ***It solves problems before others even realize they exist***

> [!NOTE]
>
> Fixed TLS ClientHello is now available in official clients for Desktop / Android / iOS
>
> To work with EE-MTProxy, please update your client!

<p align="center">
  <a href="https://t.me/telemtrs">
    <img src="/docs/assets/telegram_button.svg" width="150"/>
  </a>
</p>

**Telemt** is a fast, secure, and feature-rich server written in Rust: it fully implements the official Telegram proxy algo and adds many production-ready improvements

### One-command Install and Update
```bash
curl -fsSL https://raw.githubusercontent.com/telemt/telemt/main/install.sh | sh
```
- [Quick Start Guide](docs/Quick_start/QUICK_START_GUIDE.en.md)
- [Инструкция по быстрому запуску](docs/Quick_start/QUICK_START_GUIDE.ru.md)

## Features
Our implementation of **TLS-fronting** is one of the most deeply debugged, focused, advanced and *almost* **"behaviorally consistent to real"**:  we are confident we have it right - [see evidence on our validation and traces](docs/FAQ.en.md#recognizability-for-dpi-and-crawler)

Our ***Middle-End Pool*** is fastest by design in standard scenarios, compared to other implementations of connecting to the Middle-End Proxy: non dramatically, but usual

- Full support for all official MTProto proxy modes:
  - Classic;
  - Secure - with `dd` prefix;
  - Fake TLS - with `ee` prefix + SNI fronting;
- Replay attack protection;
- Optional traffic masking: forward unrecognized connections to a real web server, e.g. GitHub 🤪;
- Configurable keepalives + timeouts + IPv6 and "Fast Mode";
- Graceful shutdown on Ctrl+C;
- Extensive logging via `trace` and `debug` with `RUST_LOG` method.

## FAQ
- [FAQ RU](docs/FAQ.ru.md)
- [FAQ EN](docs/FAQ.en.md)

# Learn more about Telemt
- [Our Architecture](docs/Architecture)
- [All Config Options](docs/Config_params)
- [How to build your own Telemt?](#build)
- [Running on BSD](docs/Quick_start/OPENBSD_QUICK_START_GUIDE.en.md)
- [Why Rust?](#why-rust)

## Build
```bash
# Cloning repo
git clone https://github.com/telemt/telemt 
# Changing Directory to telemt
cd telemt
# Starting Release Build
cargo build --release

# Current release profile uses lto = "fat" for maximum optimization (see Cargo.toml).
# On low-RAM systems (~1 GB) you can override it to "thin".

# Move to /bin
mv ./target/release/telemt /bin
# Make executable
chmod +x /bin/telemt
# Lets go!
telemt config.toml
```

## Why Rust?
- Long-running reliability and idempotent behavior
- Rust's deterministic resource management - RAII 
- No garbage collector
- Memory safety and reduced attack surface
- Tokio's asynchronous architecture

## Support Telemt

Telemt is free, open-source, and built in personal time.
If it helps you — consider supporting continued development.

Any cryptocurrency (BTC, ETH, USDT, 350+ coins):

<p align="center">
  <a href="https://nowpayments.io/donation?api_key=2bf1afd2-abc2-49f9-a012-f1e715b37223" target="_blank" rel="noreferrer noopener">
    <img src="https://nowpayments.io/images/embeds/donation-button-white.svg" alt="Cryptocurrency & Bitcoin donation button by NOWPayments" height="80">
  </a>
</p>

Monero (XMR) directly:

```
8Bk4tZEYPQWSypeD2hrUXG2rKbAKF16GqEN942ZdAP5cFdSqW6h4DwkP5cJMAdszzuPeHeHZPTyjWWFwzeFdjuci3ktfMoB
```

All donations go toward infrastructure, development, and research.


![telemt_scheme](docs/assets/telemt.png)
