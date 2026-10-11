# Installation Options 
There are three options for installing Telemt:
 - [Automated installation using a script](#very-quick-start).
 - [Manual installation of Telemt as a service](#telemt-via-systemd).
 - [Installation using Docker Compose](#telemt-via-docker-compose).

# Very quick start

### One-command installation / update on re-run
```bash
curl -fsSL https://raw.githubusercontent.com/telemt/telemt/main/install.sh | sh
```

After starting, the script will prompt for:
 - Your language (1 - English, 2 - Russian);
 - Your server port (press Enter for 443);
 - Your TLS domain (press Enter for petrovich.ru).

The script checks if the port (default **443**) is free. If the port is already in use, installation will fail. You need to free up the port or use the **-p** flag with a different port to retry the installation.

To modify the script’s startup parameters, you can use the following flags:
 - **-d, --domain** - TLS domain;
 - **-p, --port** - server port (1–65535);
 - **-s, --secret** - 32 hex secret;
 - **-a, --ad-tag** - ad_tag;
 - **-l, --lang** - language (1/en or 2/ru);

Providing all options skips interactive prompts.

After completion, the script will provide a link for client connections:
```bash
tg://proxy?server=IP&port=PORT&secret=SECRET
```

### Installing a specific version
```bash
TELEMT_VERSION=3.5.7
curl -fsSL https://raw.githubusercontent.com/telemt/telemt/main/install.sh | sh -s -- "$TELEMT_VERSION"
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
- Already have the "telemt" executable file in the /bin folder. Read the **[Installation](#installation)** section.

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
# Minimal Telemt configuration
# These settings are sufficient for most deployments that do not require
# advanced methods, parameters, or specialized solutions.

# General settings
[general]
use_middle_proxy = true
# Global ad_tag fallback when user has no per-user tag in [access.user_ad_tags]
# ad_tag = "00000000000000000000000000000000"
# Per-user ad_tag in [access.user_ad_tags] (32 hex from @MTProxybot)

# Logging
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
# Only show links for alice and bob
# show = ["alice", "bob"]
# Show links for all users
# show = "*"
# Host (IP or domain) for tg:// links
# public_host = "proxy.example.com"
# Port for tg:// links; defaults to server.port
# public_port = 443

# Server binding
[server]
port = 443
# Enable behind HAProxy/nginx with PROXY protocol
# proxy_protocol = false
# metrics_port = 9090
# Listen address for metrics; overrides metrics_port
# metrics_listen = "127.0.0.1:9090"
# metrics_whitelist = ["127.0.0.1/32", "::1/128"]

[server.api]
enabled = true
listen = "127.0.0.1:9091"
whitelist = ["127.0.0.1/32", "::1/128"]
minimal_runtime_enabled = false
minimal_runtime_cache_ttl_ms = 1000

# Listen on multiple interfaces/IPs - IPv4
[[server.listeners]]
ip = "0.0.0.0"

# Anti-censorship and masking
[censorship]
# Fake-TLS/SNI masking domain used in generated ee links.
tls_domain = "petrovich.ru"
mask = true
# Fetch real certificate lengths and emulate TLS records.
tls_emulation = true
# Cache directory for TLS emulation.
tls_front_dir = "tlsfront"

[access.users]
# format: "username" = "32_hex_chars_secret"
hello = "00000000000000000000000000000000"
```

then Ctrl+S -> Ctrl+X to save

> [!WARNING]
> Replace the value of the `hello` parameter with the value you obtained in step 0.  
> Additionally, change the value of the `tls_domain` parameter to a different website.
> Changing the `tls_domain` parameter will break all links that use the old domain!

---

**2. Create telemt user**

```bash
useradd -d /opt/telemt -m -r -U -s "$(command -v nologin)" telemt
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

**1. Create `config/` in the repository root and place the edited `config.toml` there (at least: port, user secrets, and `tls_domain`):**
```bash
mkdir -p config
mv config.toml config/
```
**2. Start the container:**
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
> - `docker-compose.yml` mounts `./config/` at `/etc/telemt/` read-write and starts Telemt with `/etc/telemt/config.toml`.
> - The directory mount is required for mutating Control API endpoints: Telemt persists the complete configuration source graph with same-directory temporary files and atomic renames. Do not replace it with a single-file bind mount.
> - The host `./config/` directory and its source files must be writable by the container user (UID/GID `65532` in the production image) when configuration mutations are enabled.
> - `/run/telemt` is a small writable `tmpfs`; the rest of the container filesystem remains read-only.
> - By default only `443:443` is public. The published Metrics and Control API ports are restricted to host loopback, and all capabilities except `NET_BIND_SERVICE` are dropped.
> - Port publishing does not enable a service or make a container-loopback listener reachable. The bundled `config.toml` leaves Metrics disabled and binds the Control API to `127.0.0.1` inside the container. To use either host mapping, explicitly bind that service to a container-reachable address and whitelist only the immediate Docker peer/network; keep the host-side mapping on loopback.

**Run without Compose**
```bash
docker build -t telemt:local .
docker run --name telemt --restart unless-stopped \
  -p 443:443 \
  -p 127.0.0.1:9090:9090 \
  -p 127.0.0.1:9091:9091 \
  -e RUST_LOG=info \
  -v "$PWD/config:/etc/telemt:rw" \
  --tmpfs /run/telemt:rw,mode=1777,size=4m \
  -w /run/telemt \
  --read-only \
  --cap-drop ALL --cap-add NET_BIND_SERVICE \
  --ulimit nofile=65536:65536 \
  telemt:local /etc/telemt/config.toml
```
