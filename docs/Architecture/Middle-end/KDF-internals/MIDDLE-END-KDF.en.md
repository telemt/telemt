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
