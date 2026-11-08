# Middle-End Proxy

## KDF Addressing — Implementation FAQ

### Does the C-implementation require both external IP address and port for the KDF?

**Yes!**

In the C reference implementation, **both IP address and port are included in the KDF input** from both sides of the connection.

Inside `aes_create_keys()`, the KDF input explicitly contains:

- `server_ip + client_port`
- `client_ip + server_port`
- followed by shared secret / nonces

For IPv6:

- IPv4 fields are zeroed
- IPv6 addresses are inserted

However, **client_port and server_port remain part of the KDF regardless of IP version**.

> If externally observed IP or port (e.g. due to NAT, SOCKS, or proxy traversal) differs from what the peer expects, the derived keys will not match and the handshake will fail.

---

### Can port be excluded from KDF (e.g. by using port = 0)?

**No!**

The C-implementation provides **no mechanism to ignore the port**:

- `client_port` and `server_port` are explicitly included in the KDF input
- Real socket ports are always passed:
  - `c->our_port`
  - `c->remote_port`

If a port is `0`, it is still incorporated into the KDF as `0`.

There is **no conditional logic to exclude ports**

### How does Telemt select a SOCKS KDF source?

A valid public SOCKS `BND.ADDR/BND.PORT` with a nonzero port supplies the complete KDF source tuple, ahead of configured/discovered NAT information. Its family must match the logical ME destination, independently of the TCP family used to reach SOCKS. IPv4-mapped IPv6 destinations count as IPv4 and require a native IPv4 BND tuple; IPv4-compatible destinations remain IPv6. `strict` rejects unavailable/invalid BND; `compat` retains the existing fallback. This does not change KDF fields, ports, SOCKS CONNECT destination encoding, public-address checks, or STUN behavior.
