## How to set up "proxy sponsor" channel and statistics via @MTProxybot bot

1. Go to @MTProxybot bot.
2. Enter the command `/newproxy`
3. Send the server IP and port. For example: 1.2.3.4:443
4. Open the config `nano /etc/telemt/telemt.toml`.
5. Copy and send the user secret from the [access.users] section to the bot.
6. Copy the tag received from the bot. For example 1234567890abcdef1234567890abcdef.
> [!WARNING]
> The link provided by the bot will not work. Do not copy or use it!
7. Uncomment the ad_tag parameter and enter the tag received from the bot.
8. Uncomment/add the parameter `use_middle_proxy = true`.

Config example:
```toml
[general]
ad_tag = "1234567890abcdef1234567890abcdef"
use_middle_proxy = true
```
9. Save the config. Ctrl+S -> Ctrl+X.
10. Restart telemt `systemctl restart telemt`.
11. In the bot, send the command /myproxies and select the added server.
12. Click the "Set promotion" button.
13. Send a **public link** to the channel. Private channels cannot be added!
14. Wait approximately 1 hour for the information to update on Telegram servers.
> [!WARNING]
> You will not see the "proxy sponsor" if you are already subscribed to the channel.

**You can also set up different channels for different users.**
```toml
[access.user_ad_tags]
hello = "ad_tag"
hello2 = "ad_tag2"
```

## Why is middle proxy (ME) needed
https://github.com/telemt/telemt/discussions/167

## How many people can use 1 link

By default, 1 link can be used by any number of people.  
You can limit the number of IPs using the proxy.
```toml
[access.user_max_unique_ips]
hello = 1
```
This parameter limits how many unique IPs can use 1 link simultaneously. If one user disconnects, a second user can connect. Also, multiple users can sit behind the same IP.

## How to create multiple different links

1. Generate the required number of secrets `openssl rand -hex 16`
2. Open the config `nano /etc/telemt.toml`
3. Add new users.
```toml
[access.users]
user1 = "00000000000000000000000000000001"
user2 = "00000000000000000000000000000002"
user3 = "00000000000000000000000000000003"
```
4. Save the config. Ctrl+S -> Ctrl+X. You don't need to restart telemt.
5. Get the links via
```bash
curl -s http://127.0.0.1:9091/v1/users | jq
```

## "Unknown TLS SNI" Error
You probably updated tls_domain, but users are still connecting via old links with the previous domain.

## How to view metrics

1. Open the config `nano /etc/telemt/telemt.toml`
2. Add the following parameters
```toml
[server]
metrics_port = 9090
metrics_whitelist = ["127.0.0.1/32", "::1/128", "0.0.0.0/0"]
```
3. Save the config. Ctrl+S -> Ctrl+X.
4. Metrics are available at SERVER_IP:9090/metrics.
> [!WARNING]
> "0.0.0.0/0" in metrics_whitelist opens access from any IP. Replace with your own IP. For example "1.2.3.4"

## Additional parameters

### Domain in link instead of IP
To specify a domain in the links, add to the `[general.links]` section of the config file.
```toml
[general.links]
public_host = "proxy.example.com"
```

### Server connection limit
Limits the total number of open connections to the server:
```toml
[server]
max_connections = 10000    # 0 - unlimited, 10000 - default
```

### Upstream Manager
To specify an upstream, add to the `[[upstreams]]` section of the config.toml file:
#### Binding to IP
```toml
[[upstreams]]
type = "direct"
weight = 1
enabled = true
interface = "192.168.1.100" # Change to your outgoing IP
```
#### SOCKS4/5 as Upstream
- Without authentication:
```toml
[[upstreams]]
type = "socks5"            # Specify SOCKS4 or SOCKS5
address = "1.2.3.4:1234"   # SOCKS-server Address
weight = 1                 # Set Weight for Scenarios
enabled = true
```

- With authentication:
```toml
[[upstreams]]
type = "socks5"            # Specify SOCKS4 or SOCKS5
address = "1.2.3.4:1234"   # SOCKS-server Address
username = "user"          # Username for Auth on SOCKS-server
password = "pass"          # Password for Auth on SOCKS-server
weight = 1                 # Set Weight for Scenarios
enabled = true
```

#### Shadowsocks as Upstream
Requires `use_middle_proxy = false`.

```toml
[general]
use_middle_proxy = false

[[upstreams]]
type = "shadowsocks"
url = "ss://2022-blake3-aes-256-gcm:BASE64_KEY@1.2.3.4:8388"
weight = 1
enabled = true
```
