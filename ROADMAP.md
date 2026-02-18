### 3.0.0 Anschluss
- **Middle Proxy now is stable**, confirmed on canary-deploy over ~20 users
- Ad-tag now is working
- DC=203/CDN now is working over ME
- `getProxyConfig` and `ProxySecret` are automated
- Version order is now in format `3.0.0` - without Windows-style "microfixes"

### 3.0.1 Kabelsammler
- Handshake timeouts fixed
- Connectivity logging refactored
- Docker: tmpfs for ProxyConfig and ProxySecret
- Public Host and Port in config
- ME Relays Head-of-Line Blocking fixed
- ME Ping

### 3.0.2 Microtrencher
- New [network] section
- ME Fixes
- Small bugs coverage

### 3.0.3 Ausrutscher
- ME as stateful, no conn-id migration
- No `flush()` on datapath after RpcWriter
- Hightech parser for IPv6 without regexp
- `nat_probe = true` by default
- Timeout for `recv()` in STUN-client
- ConnRegistry review
- Dualstack emergency reconnect

### 3.0.4 Schneeflecken
- Only WARN and Links in Normal log
- Consistent IP-family detection
- Includes for config
- `nonce_frame_hex` in log only with `DEBUG`
