<img src="https://gist.githubusercontent.com/avbor/1f8a128e628f47249aae6e058a57610b/raw/19013276c035e91058e0a9799ab145f8e70e3ff5/scheme.svg">

## Concept
- **Server A** (__conditionally Russian Federation_):\
  Entry point, receives Telegram proxy user traffic via **HAProxy** (port `443`)\
  and sends it to the tunnel to Server **B**.\
  Internal IP in the tunnel — `10.10.10.2`\
  Port for HAProxy clients — `443\tcp`
- **Server B** (_conditionally Netherlands_):\
  Exit point, runs **telemt** and accepts client connections through Server **A**.\
  The server must have unrestricted access to Telegram servers.\
  Internal IP in the tunnel — `10.10.10.1`\
  AmneziaWG port — `8443\udp`\
  Port for telemt clients — `443\tcp`

---

## Step 1. Setting up the AmneziaWG tunnel (A <-> B)
[AmneziaWG](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module) must be installed on all servers.\
All following commands are given for **Ubuntu 24.04**.\
For RHEL-based distributions, installation instructions are available at the link above.

### Installing AmneziaWG (Servers A and B)
The following steps must be performed on each server:

#### 1. Adding the AmneziaWG repository and installing required packages:
```bash
sudo apt install -y software-properties-common python3-launchpadlib gnupg2 linux-headers-$(uname -r) && \
sudo add-apt-repository ppa:amnezia/ppa && \
sudo apt-get install -y amneziawg
```

#### 2. Generating a unique key pair:
```bash
cd /etc/amnezia/amneziawg && \
awg genkey | tee private.key | awg pubkey > public.key
```

As a result, you will get two files in the `/etc/amnezia/amneziawg` folder:\
`private.key` - private, and\
`public.key` - public server keys

#### 3. Configuring network interfaces:
Obfuscation parameters `S1`, `S2`, `H1`, `H2`, `H3`, `H4` must be strictly identical on both servers.\
Parameters `Jc`, `Jmin` and `Jmax` can differ.\
Parameters `I1-I5` ([Custom Protocol Signature](https://docs.amnezia.org/documentation/amnezia-wg/)) must be specified on the client side (Server **A**).

Recommendations for choosing values:

```text
Jc — 1 ≤ Jc ≤ 128; from 4 to 12 inclusive
Jmin — Jmax > Jmin < 1280*; recommended 8
Jmax — Jmin < Jmax ≤ 1280*; recommended 80
S1 — S1 ≤ 1132* (1280* - 148 = 1132); S1 + 56 ≠ S2;
recommended range from 15 to 150 inclusive
S2 — S2 ≤ 1188* (1280* - 92 = 1188);
recommended range from 15 to 150 inclusive
H1/H2/H3/H4 — must be unique and differ from each other;
recommended range from 5 to 2147483647 inclusive

* It is assumed that the Internet connection has an MTU of 1280.
```

> [!IMPORTANT]
> It is recommended to use your own, unique values.\
> You can use the [generator](https://htmlpreview.github.io/?https://gist.githubusercontent.com/avbor/955782b5c37b06240b243aa375baeac5/raw/13f5517ca473b47c412b9a99407066de973732bd/awg-gen.html) to select parameters.

#### Server B Configuration (Netherlands):

Create the interface configuration file (`awg0`)
```bash
nano /etc/amnezia/amneziawg/awg0.conf
```

File content
```ini
[Interface]
Address = 10.10.10.1/24
ListenPort = 8443
PrivateKey = <PRIVATE_KEY_SERVER_B>
SaveConfig = true
Jc = 4
Jmin = 8
Jmax = 80
S1 = 29
S2 = 15
S3 = 18
S4 = 0
H1 = 2087563914
H2 = 188817757
H3 = 101784570
H4 = 432174303

[Peer]
PublicKey = <PUBLIC_KEY_SERVER_A>
AllowedIPs = 10.10.10.2/32
```
`ListenPort` - the port on which the server will wait for connections, you can choose any free one.\
`<PRIVATE_KEY_SERVER_B>` - the content of the `private.key` file from Server **B**.\
`<PUBLIC_KEY_SERVER_A>` - the content of the `public.key` file from Server **A**.

Open the port on the firewall (if enabled):
```bash
sudo ufw allow from <PUBLIC_IP_SERVER_A> to any port 8443 proto udp
```

`<PUBLIC_IP_SERVER_A>` - the external IP address of Server **A**.

#### Server A Configuration (Russian Federation):
Create the interface configuration file (awg0)

```bash
nano /etc/amnezia/amneziawg/awg0.conf
```

File content
```ini
[Interface]
Address = 10.10.10.2/24
PrivateKey = <PRIVATE_KEY_SERVER_A>
Jc = 4
Jmin = 8
Jmax = 80
S1 = 29
S2 = 15
S3 = 18
S4 = 0
H1 = 2087563914
H2 = 188817757
H3 = 101784570
H4 = 432174303
I1 = <b 0xc10000000108981eba846e21f74e00>
I2 = <b 0xc20000000108981eba846e21f74e00>
I3 = <b 0xc30000000108981eba846e21f74e00>
I4 = <b 0x43981eba846e21f74e>
I5 = <b 0x43981eba846e21f74e>

[Peer]
PublicKey = <PUBLIC_KEY_SERVER_B>
Endpoint = <PUBLIC_IP_SERVER_B>:8443
AllowedIPs = 10.10.10.1/32
PersistentKeepalive = 25
```

`<PRIVATE_KEY_SERVER_A>` - the content of the `private.key` file from Server **A**.\
`<PUBLIC_KEY_SERVER_B>` - the content of the `public.key` file from Server **B**.\
`<PUBLIC_IP_SERVER_B>` - the public IP address of Server **B**.

Enable the tunnel on both servers:
```bash
sudo systemctl enable --now awg-quick@awg0
```

Make sure Server B is accessible from Server A through the tunnel.
```bash
ping 10.10.10.1
PING 10.10.10.1 (10.10.10.1) 56(84) bytes of data.
64 bytes from 10.10.10.1: icmp_seq=1 ttl=64 time=35.1 ms
64 bytes from 10.10.10.1: icmp_seq=2 ttl=64 time=35.0 ms
64 bytes from 10.10.10.1: icmp_seq=3 ttl=64 time=35.1 ms
^C
```
---

## Step 2. Installing telemt on Server B (conditionally Netherlands)
Installation and configuration are described [here](https://github.com/telemt/telemt/blob/main/docs/Quick_start/QUICK_START_GUIDE.en.md) or [here](https://gitlab.com/An0nX/telemt-docker#-quick-start-docker-compose).\
It is assumed that telemt expects connections on port `443\tcp`.

In the telemt config, you must enable the `Proxy` protocol and restrict connections to it only through the tunnel.
```toml
[server]
port = 443
listen_addr_ipv4 = "10.10.10.1"
proxy_protocol = true
```

Also, for correct link generation, specify the FQDN or IP address and port of Server `A`
```toml
[general.links]
show = "*"
public_host = "<FQDN_OR_IP_SERVER_A>"
public_port = 443
```

Open the port on the firewall (if enabled):
```bash
sudo ufw allow from 10.10.10.2 to any port 443 proto tcp
```

---

## Step 3. Configuring HAProxy on Server A (Russian Federation)
Since the version in the standard Ubuntu repository is relatively old, it makes sense to use the official Docker image.\
[Instructions](https://docs.docker.com/engine/install/ubuntu/) for installing Docker on Ubuntu.

> [!WARNING]
> By default, regular users do not have rights to use ports < 1024.
> Attempts to run HAProxy on port 443 can lead to errors:
> ```
> [ALERT] (8) : Binding [/usr/local/etc/haproxy/haproxy.cfg:17] for frontend tcp_in_443: 
> protocol tcpv4: cannot bind socket (Permission denied) for [0.0.0.0:443].
> ```
> There are two simple ways to bypass this restriction, choose one:
> 1. At the OS level, change the net.ipv4.ip_unprivileged_port_start setting to allow users to use all ports:
> ```
> echo "net.ipv4.ip_unprivileged_port_start = 0" | sudo tee -a /etc/sysctl.conf && sudo sysctl -p
> ```
> or
> 
> 2. Run HAProxy as root:
> Uncomment the `user: "root"` parameter in docker-compose.yaml.

#### Create a folder for HAProxy:
```bash
mkdir -p /opt/docker-compose/haproxy && cd $_
```

#### Create the docker-compose.yaml file
`nano docker-compose.yaml`

File content
```yaml
services:
  haproxy:
    image: haproxy:latest
    container_name: haproxy
    restart: unless-stopped
    # user: "root"
    network_mode: "host"
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "1"
```

#### Create the haproxy.cfg config file
Accept connections on port 443\tcp and send them through the tunnel to Server `B` 10.10.10.1:443

`nano haproxy.cfg`

File content

```haproxy
global
    log stdout format raw local0
    maxconn 10000

defaults
    log     global
    mode    tcp
    option  tcplog
    option  clitcpka
    option  srvtcpka
    timeout connect 5s
    timeout client  2h
    timeout server  2h
    timeout check   5s

frontend tcp_in_443
    bind *:443
    maxconn 8000
    option tcp-smart-accept
    default_backend telemt_nodes

backend telemt_nodes
    option tcp-smart-connect
    server server_a 10.10.10.1:443 check inter 5s rise 2 fall 3 send-proxy-v2


```
> [!WARNING]
> **The file must end with an empty line, otherwise HAProxy will not start!**

#### Allow port 443\tcp in the firewall (if enabled)
```bash
sudo ufw allow 443/tcp
```

#### Start the HAProxy container
```bash
docker compose up -d
```

If everything is configured correctly, you can now try connecting Telegram clients using links from the telemt log\api.
