<img src="https://gist.githubusercontent.com/avbor/1f8a128e628f47249aae6e058a57610b/raw/19013276c035e91058e0a9799ab145f8e70e3ff5/scheme.svg">

## Концепция
- **Сервер A** (_РФ_):\
  Точка входа, принимает трафик пользователей Telegram-прокси напрямую через **Xray** (порт `443\tcp`)\
  и отправляет его в туннель на Сервер **B**.\
  Порт для клиентов Telegram — `443\tcp`
- **Сервер B** (_условно Нидерланды_):\
  Точка выхода, на нем работает **Xray-сервер** (принимает подключения точки входа) и **telemt**.\
  На сервере должен быть неограниченный доступ до серверов Telegram.\
  Порт для VLESS/REALITY (вход) — `443\tcp`\
  Внутренний порт telemt (куда пробрасывается трафик) — `8443\tcp`

Туннель работает по протоколу VLESS-XTLS-Reality (или VLESS/xhttp/reality). Оригинальный IP-адрес клиента сохраняется благодаря протоколу PROXYv2, который Xray на Сервере А добавляет через локальный loopback перед упаковкой в туннель, благодаря чему прозрачно доходит до telemt.

---

## Шаг 1. Настройка туннеля Xray (A <-> B)

На обоих серверах необходимо установить **Xray-core** (рекомендуется версия 1.8.4 или новее).
Официальный скрипт установки (выполнить на обоих серверах):
```bash
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
```

### Генерация ключей и параметров (выполнить один раз)
Для конфигурации потребуются уникальные ID и ключи Xray Reality. Выполните на любом сервере с установленным Xray:
1. **UUID клиента:**
```bash
xray uuid
# Сохраните вывод (например: 12345678-abcd-1234-abcd-1234567890ab) — это <XRAY_UUID>
```
2. **Пара ключей X25519 (Private & Public) для Reality:**
```bash
xray x25519
# Сохраните Private key (<SERVER_B_PRIVATE_KEY>) и Public key (<SERVER_B_PUBLIC_KEY>)
```
3. **Short ID (идентификатор Reality):**
```bash
openssl rand -hex 16
# Сохраните вывод (например: 0123456789abcdef0123456789abcdef) — это <SHORT_ID>
```
4. **Random Path (путь для xhttp):**
```bash
openssl rand -hex 8
# Сохраните вывод (например, abc123def456), чтобы заменить <YOUR_RANDOM_PATH> в конфигах
```

---

### Конфигурация Сервера B (_Нидерланды_):

Создаем или редактируем файл `/usr/local/etc/xray/config.json`.
Этот Xray-сервер будет слушать порт `443` и прозрачно пропускать валидный Reality трафик дальше, а "замаскированный" трафик (например, если кто-то стучится в лоб веб-браузером) пойдет на `yahoo.com`.

```bash
nano /usr/local/etc/xray/config.json
```

Содержимое файла:
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

Открываем порт на фаерволе (если включен):
```bash
sudo ufw allow 443/tcp
```
Перезапускаем Xray:
```bash
sudo systemctl restart xray
sudo systemctl enable xray
```

---

### Конфигурация Сервера A (_РФ_):

Аналогично, редактируем `/usr/local/etc/xray/config.json`.
Здесь Xray выступает публичной точкой: он принимает трафик на внешний порт `443\tcp`, пропускает через локальный loopback (порт `10444`) для добавления PROXYv2-заголовка, и упаковывает в Reality до Сервера B, прося тот доставить данные на *свой локальный* порт `127.0.0.1:8443` (именно там будет слушать telemt).

```bash
nano /usr/local/etc/xray/config.json
```

Содержимое файла:
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
*Замените `<PUBLIC_IP_SERVER_B>` на внешний IP-адрес Сервера B.*

Открываем порт на фаерволе для клиентов:
```bash
sudo ufw allow 443/tcp
```

Перезапускаем Xray:
```bash
sudo systemctl restart xray
sudo systemctl enable xray
```

---

## Шаг 2. Установка и настройка telemt на Сервере B (_Нидерланды_)

Установка telemt описана [в основной инструкции](../Quick_start/QUICK_START_GUIDE.ru.md).
Отличие в том, что telemt должен слушать *внутренний* порт (так как 443 занят Xray-сервером), а также ожидать `PROXY` протокол из Xray туннеля.

В конфиге `config.toml` прокси (на Сервере B) укажите:
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

- `port = 8443` и `listen_addr_ipv4 = "127.0.0.1"` означают, что telemt принимает подключения только изнутри (приходящие от локального Xray-процесса).
- `proxy_protocol = true` заставляет telemt парсить PROXYv2-заголовок (который добавил Xray на Сервере A через loopback), восстанавливая IP-адрес конечного пользователя (РФ).
- В `public_host` укажите публичный IP-адрес или домен Сервера A, чтобы ссылки на подключение генерировались корректно.

Перезапустите `telemt`, и клиенты смогут подключаться по выданным ссылкам.

