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

The port you have selected for use should be MISSING from the list, when:
```bash
netstat -lnp
```

Generate 16 bytes/32 characters HEX with OpenSSL or another way:
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

**1. Place your config to /etc/telemt.toml**

Open nano
```bash
nano /etc/telemt.toml
```
paste your config

```toml
# === General Settings ===
[general]
# ad_tag = "00000000000000000000000000000000"

[general.modes]
classic = false
secure = false
tls = true

# === Anti-Censorship & Masking ===
[censorship]
tls_domain = "petrovich.ru"

[access.users]
# format: "username" = "32_hex_chars_secret"
hello = "00000000000000000000000000000000"
```
then Ctrl+S -> Ctrl+X to save

> [!WARNING]
> Replace the value of the hello parameter with the value you obtained in step 0. 
> Replace the value of the tls_domain parameter with another website.

---

**2. Create service on /etc/systemd/system/telemt.service**

Open nano
```bash
nano /etc/systemd/system/telemt.service
```

paste this Systemd Module
```bash
[Unit]
Description=Telemt
After=network.target

[Service]
Type=simple
WorkingDirectory=/bin
ExecStart=/bin/telemt /etc/telemt.toml
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```
then Ctrl+S -> Ctrl+X to save


**3.** To start it, enter the command `systemctl start telemt`

**4.** To get status information, enter `systemctl status telemt`

**5.** For automatic startup at system boot, enter `systemctl enable telemt`

**6.** To get the links, enter `journalctl -u telemt -n -g "links" --no-pager -o cat | tac`

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
  -e RUST_LOG=info \
  -v "$PWD/config.toml:/app/config.toml:ro" \
  --read-only \
  --cap-drop ALL --cap-add NET_BIND_SERVICE \
  --ulimit nofile=65536:65536 \
  telemt:local
```
