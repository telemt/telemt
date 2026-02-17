# Debug Mode Rules for Telemt

## Logging
- `RUST_LOG` environment variable takes absolute priority over all config log levels
- Log levels: `trace`, `debug`, `info`, `warn`, `error`
- Use `RUST_LOG=debug cargo run` for detailed operational logs
- Use `RUST_LOG=trace cargo run` for full protocol-level debugging

## Middle-End Proxy Debugging
- Set `ME_DIAG=1` environment variable for high-precision cryptography diagnostics
- STUN probe results are logged at startup - check for mismatch between local and reflected IP
- If Middle-End fails, check `proxy_secret_path` points to valid file from https://core.telegram.org/getProxySecret

## Connection Issues
- DC connectivity is logged at startup with RTT measurements
- If DC ping fails, check `dc_overrides` for custom addresses
- Use `prefer_ipv6=false` in config if IPv6 is unreliable

## TLS Fronting Issues
- Invalid handshakes are proxied to `mask_host` - check this host is reachable
- `mask_unix_sock` and `mask_host` are mutually exclusive - only one can be set
- If `mask_unix_sock` is set, socket must exist before connections arrive

## Common Errors
- `ReplayAttack` - client replayed a handshake nonce, potential attack
- `TimeSkew` - client clock is off, can disable with `ignore_time_skew=true`
- `TgHandshakeTimeout` - upstream DC connection failed, check network
