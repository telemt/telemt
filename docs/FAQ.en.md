## How to set up a "proxy sponsor" channel and statistics via the @MTProxybot
1. Go to the @MTProxybot.
2. Enter the `/newproxy` command.
3. Send your server's IP address and port. For example: `1.2.3.4:443`.
4. Open the configuration file: `nano /etc/telemt/telemt.toml`.
5. Copy and send the user secret from the `[access.users]` section to the bot.
6. Copy the tag provided by the bot. For example: `1234567890abcdef1234567890abcdef`.
> [!WARNING]
> The link provided by the bot will not work. Do not copy or use it!
7. Uncomment the `ad_tag` parameter and enter the tag received from the bot.
8. Uncomment or add the `use_middle_proxy = true` parameter.

Configuration example:
```toml
[general]
ad_tag = "1234567890abcdef1234567890abcdef"
use_middle_proxy = true
```
9. Save the changes (in nano: Ctrl+S -> Ctrl+X).
10. Restart the telemt service: `systemctl restart telemt`.
11. Send the `/myproxies` command to the bot and select the added server.
12. Click the "Set promotion" button.
13. Send a **public link** to the channel. Private channels cannot be added!
14. Wait for about 1 hour for the information to update on Telegram servers.
> [!WARNING]
> The sponsored channel will not be displayed to you if you are already subscribed to it.

**You can also configure different sponsored channels for different users:**
```toml
[access.user_ad_tags]
hello = "ad_tag"
hello2 = "ad_tag2"
```
## Recognizability for DPI and crawler

On April 1, 2026, we became aware of a method for detecting MTProxy Fake-TLS, 
based on the ECH extension and the ordering of cipher suites, 
as well as an overall unique JA3/JA4 fingerprint 
that does not occur in modern browsers.

> [!IMPORTANT]
> TLS fingerprint has been fixed in latest version of clients for Desktop / Android / iOS.  
> Please update your client for MTProxy Fake-TLS to work correctly.

- We consider this a breakthrough aspect, which has no stable analogues today
- Based on this: if `telemt` configured correctly, **TLS mode is completely identical to real-life handshake + communication** with a specified host
- Here is our evidence:
    - 212.220.88.77 - "dummy" host, running `telemt`
    - `petrovich.ru` - `tls` + `masking` host, in HEX: `706574726f766963682e7275`
    - **No MITM + No Fake Certificates/Crypto** = pure transparent *TCP Splice* to "best" upstream: MTProxy or tls/mask-host:
      - DPI see legitimate HTTPS to `tls_host`, including *valid chain-of-trust* and entropy
      - Crawlers completely satisfied receiving responses from `mask_host`
  ### Client WITH secret-key accesses the MTProxy resource:
  
  <img width="360" height="439" alt="telemt" src="https://github.com/user-attachments/assets/39352afb-4a11-4ecc-9d91-9e8cfb20607d" />
  
  ### Client WITHOUT secret-key gets transparent access to the specified resource:
    - with trusted certificate
    - with original handshake
    - with full request-response way
    - with low-latency overhead
```bash
root@debian:~/telemt# curl -v -I --resolve petrovich.ru:443:212.220.88.77 https://petrovich.ru/
* Added petrovich.ru:443:212.220.88.77 to DNS cache
* Hostname petrovich.ru was found in DNS cache
*   Trying 212.220.88.77:443...
* Connected to petrovich.ru (212.220.88.77) port 443 (#0)
* ALPN: offers h2,http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
*  CAfile: /etc/ssl/certs/ca-certificates.crt
*  CApath: /etc/ssl/certs
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* ALPN: server did not agree on a protocol. Uses default.
* Server certificate:
*  subject: C=RU; ST=Saint Petersburg; L=Saint Petersburg; O=STD Petrovich; CN=*.petrovich.ru
*  start date: Jan 28 11:21:01 2025 GMT
*  expire date: Mar  1 11:21:00 2026 GMT
*  subjectAltName: host "petrovich.ru" matched cert's "petrovich.ru"
*  issuer: C=BE; O=GlobalSign nv-sa; CN=GlobalSign RSA OV SSL CA 2018
*  SSL certificate verify ok.
* using HTTP/1.x
> HEAD / HTTP/1.1
> Host: petrovich.ru
> User-Agent: curl/7.88.1
> Accept: */*
> 
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* old SSL session ID is stale, removing
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
< Server: Variti/0.9.3a
Server: Variti/0.9.3a
< Date: Thu, 01 Jan 2026 00:0000 GMT
Date: Thu, 01 Jan 2026 00:0000 GMT
< Access-Control-Allow-Origin: *
Access-Control-Allow-Origin: *
< Content-Type: text/html
Content-Type: text/html
< Cache-Control: no-store
Cache-Control: no-store
< Expires: Thu, 01 Jan 2026 00:0000 GMT
Expires: Thu, 01 Jan 2026 00:0000 GMT
< Pragma: no-cache
Pragma: no-cache
< Set-Cookie: ipp_uid=XXXXX/XXXXX/XXXXX==; Expires=Tue, 31 Dec 2040 23:59:59 GMT; Domain=.petrovich.ru; Path=/
Set-Cookie: ipp_uid=XXXXX/XXXXX/XXXXX==; Expires=Tue, 31 Dec 2040 23:59:59 GMT; Domain=.petrovich.ru; Path=/
< Content-Type: text/html
Content-Type: text/html
< Content-Length: 31253
Content-Length: 31253
< Connection: keep-alive
Connection: keep-alive
< Keep-Alive: timeout=60
Keep-Alive: timeout=60

< 
* Connection #0 to host petrovich.ru left intact

```
- We challenged ourselves, we kept trying and we didn't only *beat the air*: now, we have something to show you
  - Do not just take our word for it? - This is great and we respect that: you can build your own `telemt` or download a build and check it right now


## F.A.Q.

### Telegram Calls via MTProxy
- Telegram architecture **does NOT allow calls via MTProxy**, but only via SOCKS5, which cannot be obfuscated

### How does DPI see MTProxy TLS?
- DPI sees MTProxy in Fake TLS (ee) mode as TLS 1.3
- the SNI you specify sends both the client and the server;
- ALPN is similar to HTTP 1.1/2;
- high entropy, which is normal for AES-encrypted traffic;

### Whitelist on IP
- MTProxy cannot work when there is: 
  - no IP connectivity to the target host: Russian Whitelist on Mobile Networks - "Белый список"
  - OR all TCP traffic is blocked
  - OR high entropy/encrypted traffic is blocked: content filters at universities and critical infrastructure
  - OR all TLS traffic is blocked
  - OR specified port is blocked: use 443 to make it "like real"
  - OR provided SNI is blocked: use "officially approved"/innocuous name
- like most protocols on the Internet; 
- these situations are observed:
  - in China behind the Great Firewall
  - in Russia on mobile networks, less in wired networks
  - in Iran during "activity"

### Why do you need a middle proxy (ME)
https://github.com/telemt/telemt/discussions/167

## How clients interact with Telegram DCs
When you register a Telegram account, it gets permanently bound to one of Telegram's data centers (DCs).  
It is deciced beforehand by Telegram based on the phone number's region.  
This DC becomes your **home DC**: all content you upload (photos, videos, files, messages) is stored there.  
Your client authenticates on it with every connection.  

For example, if your account is registered on **DC2**, your client will always connect to DC2 first.  
When you open a chat with another user whose home DC is **DC5**, your client opens an additional connection to DC5 to download their media.  
Those cross-DC requests are normal and happen constantly.  

> [!WARNING]
> Because every session is anchored to your home DC, an outage there causes other DCs to be unavaliable.  
> If your home DC is DC2 and DC2 goes down, you **cannot** reach DC5 even though DC5 itself is perfectly healthy.  
> The client has no valid session to route the request through.  

This is also why an MTProxy only needs to reach Telegram's DC infrastructure as a whole.  
The proxy itself doesn't care which DC your account lives on. The client negotiates the correct DC through the proxy after connecting.

### How many people can use one link
By default, an unlimited number of people can use a single link.  
However, you can limit the number of unique IP addresses for each user:
```toml
[access.user_max_unique_ips]
hello = 1
```
This parameter sets the maximum number of unique IP addresses from which a single link can be used simultaneously. If the first user disconnects, a second one can connect.
At the same time, multiple users can connect from a single IP address simultaneously (for example, devices on the same Wi-Fi network).

### How to create multiple different links
1. Generate the required number of secrets using the command: `openssl rand -hex 16`.
2. Open the configuration file: `nano /etc/telemt/telemt.toml`.
3. Add new users to the `[access.users]` section:
```toml
[access.users]
user1 = "00000000000000000000000000000001"
user2 = "00000000000000000000000000000002"
user3 = "00000000000000000000000000000003"
```
4. Save the configuration (Ctrl+S -> Ctrl+X). There is no need to restart the telemt service.
5. Get the ready-to-use links using the command:
```bash
curl -s http://127.0.0.1:9091/v1/users | jq
```

### "Unknown TLS SNI" error
Usually, this error occurs if you have changed the `tls_domain` parameter, but users continue to connect using old links with the previous domain.

If you need to allow connections with any domains (ignoring SNI mismatches), add the following parameters:
```toml
[censorship]
unknown_sni_action = "mask"
```

Alternatively, if you want telemt to behave like a vanilla nginx with `ssl_reject_handshake on;` on unknown SNI (emit a TLS `unrecognized_name` alert and close the connection), use:
```toml
[censorship]
unknown_sni_action = "reject_handshake"
```
This does not recover stale clients, but it makes port 443 wire-indistinguishable from a stock web server that simply does not host the requested vhost.

### How to view metrics

1. Open the configuration file: `nano /etc/telemt/telemt.toml`.
2. Add the following parameters:
```toml
[server]
metrics_port = 9090
metrics_whitelist = ["127.0.0.1/32", "::1/128", "0.0.0.0/0"]
```
3. Save the changes (Ctrl+S -> Ctrl+X).
4. After that, metrics will be available at: `SERVER_IP:9090/metrics`. 
> [!WARNING]
> The value `"0.0.0.0/0"` in `metrics_whitelist` opens access to metrics from any IP address. It is recommended to replace it with your personal IP, for example: `"1.2.3.4/32"`.

### Too many open files
- On a fresh Linux install the default open file limit is low; under load `telemt` may fail with `Accept error: Too many open files`
- **Systemd**: add `LimitNOFILE=65536` to the `[Service]` section (already included in the example above)
- **Docker**: add `--ulimit nofile=65536:65536` to your `docker run` command, or in `docker-compose.yml`:
```yaml
ulimits:
  nofile:
    soft: 65536
    hard: 65536
```
- **System-wide** (optional): add to `/etc/security/limits.conf`:
```
*       soft    nofile  1048576
*       hard    nofile  1048576
root    soft    nofile  1048576
root    hard    nofile  1048576
```


## Additional parameters

### Domain in the link instead of IP
To display a domain instead of an IP address in the connection links, add the following lines to the configuration file:
```toml
[general.links]
public_host = "proxy.example.com"
```

### Total server connection limit
This parameter limits the total number of active connections to the server:
```toml
[server]
max_connections = 10000    # 0 - unlimited, 10000 - default
```

### Upstream Manager
To configure outbound connections (upstreams), add the corresponding parameters to the `[[upstreams]]` section of the configuration file:

#### Binding to an outbound IP address
```toml
[[upstreams]]
type = "direct"
weight = 1
enabled = true
interface = "192.168.1.100" # Replace with your outbound IP
```

#### Using SOCKS4/5 as an Upstream
- Without authorization:
```toml
[[upstreams]]
type = "socks5"            # Specify SOCKS4 or SOCKS5
address = "1.2.3.4:1234"   # SOCKS-server Address
weight = 1                 # Set Weight for Scenarios
enabled = true
```

- With authorization:
```toml
[[upstreams]]
type = "socks5"            # Specify SOCKS4 or SOCKS5
address = "1.2.3.4:1234"   # SOCKS-server Address
username = "user"          # Username for Auth on SOCKS-server
password = "pass"          # Password for Auth on SOCKS-server
weight = 1                 # Set Weight for Scenarios
enabled = true
```

#### Using Shadowsocks as an Upstream
For this method to work, the `use_middle_proxy = false` parameter must be set.

```toml
[general]
use_middle_proxy = false

[[upstreams]]
type = "shadowsocks"
url = "ss://2022-blake3-aes-256-gcm:BASE64_KEY@1.2.3.4:8388"
weight = 1
enabled = true
```
