<img src="https://gist.githubusercontent.com/avbor/1f8a128e628f47249aae6e058a57610b/raw/19013276c035e91058e0a9799ab145f8e70e3ff5/scheme.svg">

## Concept
- **Server A** (_e.g., RU_):\
  Entry point, accepts Telegram proxy user traffic via **Xray** (port `443\tcp`)\
  and sends it through the tunnel to Server **B**.\
  Public port for Telegram clients — `443\tcp`
- **Server B** (_e.g., NL_):\
  Exit point, runs the **Xray server** (to terminate the tunnel entry point) and **telemt**.\
  The server must have unrestricted access to Telegram Data Centers.\
  Public port for VLESS/REALITY (incoming) — `443\tcp`\
  Internal telemt port (where decrypted Xray traffic ends up) — `8443\tcp`

The tunnel works over the `VLESS-XTLS-Reality` (or `VLESS/xhttp/reality`) protocol. The original client IP address is preserved thanks to the PROXYv2 protocol, which Xray on Server A dynamically injects via a local loopback before wrapping the traffic into Reality, transparently delivering the real IPs to telemt on Server B.

---

## Step 1. Setup Xray Tunnel (A <-> B)

You must install **Xray-core** (version 1.8.4 or newer recommended) on both servers.
Official installation script (run on both servers):
```bash
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
```

### Key and Parameter Generation (Run Once)
For configuration, you need a unique UUID and Xray Reality keys. Run on any server with Xray installed:
1. **Client UUID:**
```bash
xray uuid
# Save the output (e.g.: 12345678-abcd-1234-abcd-1234567890ab) — this is <XRAY_UUID>
```
2. **X25519 Keypair (Private & Public) for Reality:**
```bash
xray x25519
# Save the Private key (<SERVER_B_PRIVATE_KEY>) and Public key (<SERVER_B_PUBLIC_KEY>)
```
3. **Short ID (Reality identifier):**
```bash
openssl rand -hex 8
# Save the output (e.g.: abc123def456) — this is <SHORT_ID>
```
4. **Random Path (for xhttp):**
```bash
openssl rand -hex 16
# Save the output (e.g., 0123456789abcdef0123456789abcdef) to replace <YOUR_RANDOM_PATH> in configs
```

---

### Configuration for Server B (_EU_):

Create or edit the file `/usr/local/etc/xray/config.json`.
This Xray instance will listen on the public `443` port and proxy valid Reality traffic, while routing "disguised" traffic (e.g., direct web browser scans) to `yahoo.com`.

```bash
nano /usr/local/etc/xray/config.json
```

File content:
```json
{
  "log": {
    "loglevel": "error",
    "access": "none"
  },
  "inbounds": [
    {
      "tag": "vless-in",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "<XRAY_UUID>"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "reality",
        "realitySettings": {
          "dest": "yahoo.com:443",
          "serverNames": [
            "yahoo.com"
          ],
          "privateKey": "<SERVER_B_PRIVATE_KEY>",
          "shortIds": [
            "<SHORT_ID>"
          ]
        },
        "xhttpSettings": {
          "path": "/<YOUR_RANDOM_PATH>",
          "mode": "auto"
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "tunnel-to-telemt",
      "protocol": "freedom",
      "settings": {
        "destination": "127.0.0.1:8443"
      }
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "inboundTag": [
          "vless-in"
        ],
        "outboundTag": "tunnel-to-telemt"
      }
    ]
  }
}
```

Open the firewall port (if enabled):
```bash
sudo ufw allow 443/tcp
```
Restart and setup Xray to run at boot:
```bash
sudo systemctl restart xray
sudo systemctl enable xray
```

---

### Configuration for Server A (_RU_):

Similarly, edit `/usr/local/etc/xray/config.json`.
Here Xray acts as the public entry point: it listens on `443\tcp`, uses a local loopback (via internal port `10444`) to prepend the `PROXYv2` header, and encapsulates the payload via Reality to Server B, instructing Server B to deliver it to its *local* `127.0.0.1:8443` port (where telemt will listen).

```bash
nano /usr/local/etc/xray/config.json
```

File content:
```json
{
  "log": {
    "loglevel": "error",
    "access": "none"
  },
  "inbounds": [
    {
      "tag": "public-in",
      "port": 443,
      "listen": "0.0.0.0",
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 10444,
        "network": "tcp"
      }
    },
    {
      "tag": "tunnel-in",
      "port": 10444,
      "listen": "127.0.0.1",
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 8443,
        "network": "tcp"
      }
    }
  ],
  "outbounds": [
    {
      "tag": "local-injector",
      "protocol": "freedom",
      "settings": {
        "proxyProtocol": 2
      }
    },
    {
      "tag": "vless-out",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "<PUBLIC_IP_SERVER_B>",
            "port": 443,
            "users": [
              {
                "id": "<XRAY_UUID>",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "reality",
        "realitySettings": {
          "serverName": "yahoo.com",
          "publicKey": "<SERVER_B_PUBLIC_KEY>",
          "shortId": "<SHORT_ID>",
          "spiderX": "/",
          "fingerprint": "chrome"
        },
        "xhttpSettings": {
          "path": "/<YOUR_RANDOM_PATH>"
        }
      }
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "inboundTag": ["public-in"],
        "outboundTag": "local-injector"
      },
      {
        "type": "field",
        "inboundTag": ["tunnel-in"],
        "outboundTag": "vless-out"
      }
    ]
  }
}
```
*Replace `<PUBLIC_IP_SERVER_B>` with the public IP address of Server B.*

Open the firewall port for clients (if enabled):
```bash
sudo ufw allow 443/tcp
```

Restart and setup Xray to run at boot:
```bash
sudo systemctl restart xray
sudo systemctl enable xray
```

---

## Step 2. Install telemt on Server B (_EU_)

telemt installation is heavily covered in the [Quick Start Guide](../Quick_start/QUICK_START_GUIDE.en.md).
By contrast to standard setups, telemt must listen strictly _locally_ (since Xray occupies the public `443` interface) and must expect `PROXYv2` packets.

Edit the configuration file (`config.toml`) on Server B accordingly:

```toml
[server]
port = 8443
listen_addr_ipv4 = "127.0.0.1"
proxy_protocol = true

[general.links]
show = "*"
public_host = "<FQDN_OR_IP_SERVER_A>"
public_port = 443
```

- Address `127.0.0.1` and `port = 8443` instructs the core proxy router to process connections unpacked locally via Xray-server.
- `proxy_protocol = true` commands telemt to parse the injected PROXY header (from Server A's Xray local loopback) and log genuine end-user IPs.
- Under `public_host`, place Server A's public IP address or FQDN to ensure working links are generated for Telegram users.

Restart `telemt`. Your server is now robust against DPI scanners, passing traffic optimally.

