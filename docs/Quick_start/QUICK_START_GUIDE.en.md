# Very quick start

### One-command installation / update on re-run
```bash
curl -fsSL https://raw.githubusercontent.com/telemt/telemt/main/install.sh | sh
```
### Installing a specific version
```bash
curl -fsSL https://raw.githubusercontent.com/telemt/telemt/main/install.sh | sh -s -- 3.3.39
```

### Uninstall with full cleanup
```bash
curl -fsSL https://raw.githubusercontent.com/telemt/telemt/main/install.sh | sh -s -- purge
```

# Telemt via Systemd

## Installation

This software is designed for Debian-based OS: in addition to Debian, these are Ubuntu, Mint, Kali, MX and many other Linux

**1. Download**
```bash
wget -qO- "https://github.com/telemt/telemt/releases/latest/download/telemt-$(uname -m)-linux-$(ldd --version 2>&1 | grep -iq musl && echo musl || echo gnu).tar.gz" | tar -xz
```
**2. Move to the Bin folder**
```bash
mv telemt /bin
```
**3. Make the file executable**
```bash
chmod +x /bin/telemt
```

## How to use?

**This guide "assumes" that you:**
- logged in as root or executed `su -` / `sudo su`
- Already have the "telemt" executable file in the /bin folder. Read the **[Installation](#Installation)** section.

---

**0. Check port and generate secrets**

The port you have selected for use should not be in the list:
```bash
netstat -lnp
```

Generate 16 bytes/32 characters in HEX format with OpenSSL or another way:
```bash
openssl rand -hex 16
```
OR
```bash
xxd -l 16 -p /dev/urandom
```
OR
```bash
python3 -c 'import os; print(os.urandom(16).hex())'
```
Save the obtained result somewhere. You will need it later!

---

**1. Place your config to /etc/telemt/telemt.toml**

Create the config directory:
```bash
mkdir /etc/telemt
```

Open nano
```bash
nano /etc/telemt/telemt.toml
```
Insert your configuration:

```toml
### Telemt Based Config.toml
# We believe that these settings are sufficient for most scenarios 
# where cutting-egde methods and parameters or special solutions are not needed

# === General Settings ===
[general]
use_middle_proxy = true
# Global ad_tag fallback when user has no per-user tag in [access.user_ad_tags]
# ad_tag = "00000000000000000000000000000000"
# Per-user ad_tag in [access.user_ad_tags] (32 hex from @MTProxybot)

# === Log Level ===
# Log level: debug | verbose | normal | silent
# Can be overridden with --silent or --log-level CLI flags
# RUST_LOG env var takes absolute priority over all of these
log_level = "normal"

[general.modes]
classic = false
secure = false
tls = true

[general.links]
show = "*"
# show = ["alice", "bob"] # Only show links for alice and bob
# show = "*"              # Show links for all users
# public_host = "proxy.example.com"  # Host (IP or domain) for tg:// links
# public_port = 443                  # Port for tg:// links (default: server.port)

# === Server Binding ===
[server]
port = 443
# proxy_protocol = false           # Enable if behind HAProxy/nginx with PROXY protocol
# metrics_port = 9090
# metrics_listen = "0.0.0.0:9090"  # Listen address for metrics (overrides metrics_port)
# metrics_whitelist = ["127.0.0.1", "::1", "0.0.0.0/0"]

[server.api]
enabled = true
listen = "0.0.0.0:9091"
whitelist = ["127.0.0.0/8"]
minimal_runtime_enabled = false
minimal_runtime_cache_ttl_ms = 1000

# Listen on multiple interfaces/IPs - IPv4
[[server.listeners]]
ip = "0.0.0.0"

# === Anti-Censorship & Masking ===
[censorship]
tls_domain = "petrovich.ru"
mask = true
tls_emulation = true        # Fetch real cert lengths and emulate TLS records
tls_front_dir = "tlsfront"   # Cache directory for TLS emulation

[access.users]
# format: "username" = "32_hex_chars_secret"
hello = "00000000000000000000000000000000"
```

then Ctrl+S -> Ctrl+X to save

> [!WARNING]
> Replace the value of the hello parameter with the value you obtained in step 0.  
> Additionally, change the value of the tls_domain parameter to a different website.
> Changing the tls_domain parameter will break all links that use the old domain!

---

**2. Create telemt user**

```bash
useradd -d /opt/telemt -m -r -U telemt
chown -R telemt:telemt /etc/telemt
```

**3. Create service in /etc/systemd/system/telemt.service**

Open nano
```bash
nano /etc/systemd/system/telemt.service
```

Insert this Systemd module:
```bash
[Unit]
Description=Telemt
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=telemt
Group=telemt
WorkingDirectory=/opt/telemt
ExecStart=/bin/telemt /etc/telemt/telemt.toml
Restart=on-failure
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```
then Ctrl+S -> Ctrl+X to save

reload systemd units
```bash
systemctl daemon-reload
```

**4.** To start it, enter the command `systemctl start telemt`

**5.** To get status information, enter `systemctl status telemt`

**6.** For automatic startup at system boot, enter `systemctl enable telemt`

**7.** To get the link(s), enter:
```bash
curl -s http://127.0.0.1:9091/v1/users | jq -r '.data[] | "[\(.username)]", (.links.classic[]? | "classic: \(.)"), (.links.secure[]? | "secure: \(.)"), (.links.tls[]? | "tls: \(.)"), ""'
```

> Any number of people can use one link.

> [!WARNING]
> Only the command from step 7 can provide a working link. Do not try to create it yourself or copy it from anywhere if you are not sure what you are doing!

---

# Telemt via Docker Compose

**1. Edit `config.toml` in repo root (at least: port, users secrets, tls_domain)**  
**2. Start container:**
```bash
docker compose up -d --build
```
**3. Check logs:**
```bash
docker compose logs -f telemt
```
**4. Stop:**
```bash
docker compose down
```
> [!NOTE]
> - `docker-compose.yml` maps `./config.toml` to `/app/config.toml` (read-only)
> - By default it publishes `443:443` and runs with dropped capabilities (only `NET_BIND_SERVICE` is added)
> - If you really need host networking (usually only for some IPv6 setups) uncomment `network_mode: host`

**Run without Compose**
```bash
docker build -t telemt:local .
docker run --name telemt --restart unless-stopped \
  -p 443:443 \
  -p 9090:9090 \
  -p 9091:9091 \
  -e RUST_LOG=info \
  -v "$PWD/config.toml:/app/config.toml:ro" \
  --read-only \
  --cap-drop ALL --cap-add NET_BIND_SERVICE \
  --ulimit nofile=65536:65536 \
  telemt:local
```
