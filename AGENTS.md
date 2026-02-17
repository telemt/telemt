# AGENTS.md

** Use general system promt from AGENTS_SYSTEM_PROMT.md **
** Additional techiques and architectury details are here **

This file provides guidance to agents when working with code in this repository.

## Build & Test Commands
```bash
cargo build --release          # Production build
cargo test                     # Run all tests
cargo test --lib error         # Run tests for specific module (error module)
cargo bench --bench crypto_bench  # Run crypto benchmarks
cargo clippy -- -D warnings    # Lint with clippy
```

## Project-Specific Conventions

### Rust Edition
- Uses **Rust edition 2024** (not 2021) - specified in Cargo.toml

### Error Handling Pattern
- Custom [`Recoverable`](src/error.rs:110) trait distinguishes recoverable vs fatal errors
- [`HandshakeResult<T,R,W>`](src/error.rs:292) returns streams on bad client for masking - do not drop them
- Always use [`ProxyError`](src/error.rs:168) from [`src/error.rs`](src/error.rs) for proxy operations

### Configuration Auto-Migration
- [`ProxyConfig::load()`](src/config/mod.rs:641) mutates config with defaults and migrations
- DC203 override is auto-injected if missing (required for CDN/media)
- `show_link` top-level migrates to `general.links.show`

### Middle-End Proxy Requirements
- Requires public IP on interface OR 1:1 NAT with STUN probing
- Falls back to direct mode on STUN/interface mismatch unless `stun_iface_mismatch_ignore=true`
- Proxy-secret from Telegram is separate from user secrets

### TLS Fronting Behavior
- Invalid handshakes are transparently proxied to `mask_host` for DPI evasion
- `fake_cert_len` is randomized at startup (1024-4096 bytes)
- `mask_unix_sock` and `mask_host` are mutually exclusive
