# Варианты установки
Имеется три варианта установки Telemt:
 - [Автоматизированная установка с помощью скрипта](#очень-быстрый-старт).
 - [Ручная установка Telemt в качестве службы](#telemt-через-systemd-вручную).
 - [Установка через Docker Compose](#telemt-через-docker-compose).

# Очень быстрый старт

### Установка одной командой / обновление при повторном запуске
```bash
curl -fsSL https://raw.githubusercontent.com/telemt/telemt/main/install.sh | sh
```
После запуска скрипт запросит:
 - ваш язык (1 - English, 2 - Русский);
 - порт сервера (нажмите Enter для 443);
 - ваш TLS-домен (нажмите Enter для petrovich.ru).

Во время установки скрипт проверяет, свободен ли порт (по умолчанию **443**). Если порт занят другим процессом - установка завершится с ошибкой. Для повторной установки необходимо освободить порт или указать другой через флаг **-p**.

Для изменения параметров запуска скрипта можно использовать следующие флаги:
 - **-d, --domain** - TLS-домен;
 - **-p, --port** - порт (1–65535);
 - **-s, --secret** - секрет (32 hex символа);
 - **-a, --ad-tag** - ad_tag;
 - **-l, --lang** - язык (1/en или 2/ru).

Если заданы все параметры, интерактивных вопросов не будет.

После завершения установки скрипт выдаст ссылку для подключения клиентов:
```bash
tg://proxy?server=IP&port=PORT&secret=SECRET
```

### Установка нужной версии
```bash
TELEMT_VERSION=3.5.7
curl -fsSL https://raw.githubusercontent.com/telemt/telemt/main/install.sh | sh -s -- "$TELEMT_VERSION"
```

### Удаление с полной очисткой
```bash
curl -fsSL https://raw.githubusercontent.com/telemt/telemt/main/install.sh | sh -s -- purge
```

# Telemt через Systemd вручную

## Установка

Это программное обеспечение разработано для ОС на базе Debian: помимо Debian, это Ubuntu, Mint, Kali, MX и многие другие Linux

**1. Скачать**
```bash
wget -qO- "https://github.com/telemt/telemt/releases/latest/download/telemt-$(uname -m)-linux-$(ldd --version 2>&1 | grep -iq musl && echo musl || echo gnu).tar.gz" | tar -xz
```
**2. Переместить в папку Bin**
```bash
mv telemt /bin
```
**3. Сделать файл исполняемым**
```bash
chmod +x /bin/telemt
```

## Как правильно использовать?

**Эта инструкция "предполагает", что вы:**
- Авторизовались как пользователь root или выполнил `su -` / `sudo su`
- У вас уже есть исполняемый файл "telemt" в папке /bin. Читайте раздел **[Установка](#установка)**

---

**0. Проверьте порт и сгенерируйте секреты**

Порт, который вы выбрали для использования, должен отсутствовать в списке:
```bash
netstat -lnp
```

Сгенерируйте 16 bytes/32 символа в шестнадцатеричном формате с помощью OpenSSL или другим способом:
```bash
openssl rand -hex 16
```
ИЛИ
```bash
xxd -l 16 -p /dev/urandom
```
ИЛИ
```bash
python3 -c 'import os; print(os.urandom(16).hex())'
```
Полученный результат сохраняем где-нибудь. Он понадобиться вам дальше!

---

**1. Поместите свою конфигурацию в файл /etc/telemt/telemt.toml**

Создаём директорию для конфига:
```bash
mkdir /etc/telemt
```

Открываем nano
```bash
nano /etc/telemt/telemt.toml
```
Вставьте свою конфигурацию

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

Затем нажмите Ctrl+O -> Ctrl+X, чтобы сохранить

> [!WARNING]
> Замените значение параметра `hello` на значение, которое вы получили в пункте 0.  
> Так же замените значение параметра `tls_domain` на другой сайт.
> Изменение параметра `tls_domain` сделает нерабочими все ссылки, использующие старый домен!

---

**2. Создайте пользователя для telemt**

```bash
useradd -d /opt/telemt -m -r -U -s "$(command -v nologin)" telemt
chown -R telemt:telemt /etc/telemt
```

**3. Создайте службу в /etc/systemd/system/telemt.service**

Открываем nano
```bash
nano /etc/systemd/system/telemt.service
```

Вставьте этот модуль Systemd
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
Затем нажмите Ctrl+S -> Ctrl+X, чтобы сохранить

перезагрузите конфигурацию systemd
```bash
systemctl daemon-reload
```

**4.** Для запуска введите команду `systemctl start telemt`

**5.** Для получения информации о статусе введите `systemctl status telemt`

**6.** Для автоматического запуска при запуске системы в введите `systemctl enable telemt`

**7.** Для получения ссылки/ссылок введите 
```bash
curl -s http://127.0.0.1:9091/v1/users | jq -r '.data[] | "[\(.username)]", (.links.classic[]? | "classic: \(.)"), (.links.secure[]? | "secure: \(.)"), (.links.tls[]? | "tls: \(.)"), ""'
```
> Одной ссылкой может пользоваться сколько угодно человек.

> [!WARNING]
> Рабочую ссылку может выдать только команда из 7 пункта. Не пытайтесь делать ее самостоятельно или копировать откуда-либо если вы не уверены в том, что делаете!

---

# Telemt через Docker Compose

**1. Создайте директорию `config/` и поместите в неё отредактированный `config.toml` (указав как минимум порт, пользовательские секреты и `tls_domain`):**
```bash
mkdir -p config
mv config.toml config/
```
**2. Запустите контейнер:**
```bash
docker compose up -d --build
```
**3. Проверьте логи:**
```bash
docker compose logs -f telemt
```
**4. Остановите контейнер:**
```bash
docker compose down
```
> [!NOTE]
> - `docker-compose.yml` монтирует `./config/` в `/etc/telemt/` с правом записи и запускает Telemt с `/etc/telemt/config.toml`.
> - Монтирование директории необходимо для изменяющих Control API endpoints: Telemt сохраняет полный граф источников конфигурации через временные файлы в тех же директориях и атомарные rename. Не заменяйте его bind mount одного файла.
> - Host-директория `./config/` и файлы источников должны быть доступны для записи пользователю контейнера (UID/GID `65532` в production image), если включены изменения конфигурации.
> - `/run/telemt` предоставляется как небольшой записываемый `tmpfs`; остальная файловая система контейнера остаётся read-only.
> - По умолчанию публично доступен только `443:443`. Опубликованные порты Metrics и Control API ограничены loopback хоста, а из capabilities оставлена только `NET_BIND_SERVICE`.
> - Публикация порта не включает сервис и не делает доступным listener, привязанный к loopback контейнера. В поставляемом `config.toml` Metrics выключены, а Control API привязан к `127.0.0.1` внутри контейнера. Чтобы использовать любой из host mappings, явно привяжите сервис к адресу, доступному из контейнерной сети, и добавьте в whitelist только непосредственный Docker peer/network; host-side mapping оставьте на loopback.

**Запуск без Docker Compose**
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
