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

## Why do you need a middle proxy (ME)
https://github.com/telemt/telemt/discussions/167


## How many people can use one link

By default, an unlimited number of people can use a single link.  
However, you can limit the number of unique IP addresses for each user:
```toml
[access.user_max_unique_ips]
hello = 1
```
This parameter sets the maximum number of unique IP addresses from which a single link can be used simultaneously. If the first user disconnects, a second one can connect. At the same time, multiple users can connect from a single IP address simultaneously (for example, devices on the same Wi-Fi network).

## How to create multiple different links

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

## "Unknown TLS SNI" error
Usually, this error occurs if you have changed the `tls_domain` parameter, but users continue to connect using old links with the previous domain.

If you need to allow connections with any domains (ignoring SNI mismatches), add the following parameters:
```toml
[censorship]
unknown_sni_action = "mask"
```

## How to view metrics

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
