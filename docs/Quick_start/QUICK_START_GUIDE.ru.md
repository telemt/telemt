# Очень быстрый старт

### Установка одной командой / обновление при повторном запуске
```bash
curl -fsSL https://raw.githubusercontent.com/telemt/telemt/main/install.sh | sh
```
### Установка нужной версии
```bash
curl -fsSL https://raw.githubusercontent.com/telemt/telemt/main/install.sh | sh -s -- 3.3.39
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
### Конфигурационный файл на основе Telemt
# Мы полагаем, что этих настроек достаточно для большинства сценариев, 
# где не требуются передовые методы, параметры или специальные решения

# === Общие настройки ===
[general]
use_middle_proxy = true
# Глобальный ad_tag, если у пользователя нет индивидуального тега в [access.user_ad_tags]
# ad_tag = "00000000000000000000000000000000"
# Индивидуальный ad_tag в [access.user_ad_tags] (32 шестнадцатеричных символа от @MTProxybot)

# === Уровень логирования ===
# Уровень логирования: debug | verbose | normal | silent
# Можно переопределить с помощью флагов командной строки --silent или --log-level
# Переменная окружения RUST_LOG имеет абсолютный приоритет над всеми этими настройками
log_level = "normal"

[general.modes]
classic = false
secure = false
tls = true

[general.links]
show = "*"
# show = ["alice", "bob"] # Показывать ссылки только для alice и bob
# show = "*"              # Показывать ссылки для всех пользователей
# public_host = "proxy.example.com"  # Хост (IP-адрес или домен) для ссылок tg://
# public_port = 443                  # Порт для ссылок tg:// (по умолчанию: server.port)

# === Привязка сервера ===
[server]
port = 443
# proxy_protocol = false           # Включите, если сервер находится за HAProxy/nginx с протоколом PROXY
# metrics_port = 9090
# metrics_listen = "127.0.0.1:9090"  # Адрес прослушивания для метрик (переопределяет metrics_port)
# metrics_whitelist = ["127.0.0.1/32", "::1/128"]

[server.api]
enabled = true
listen = "127.0.0.1:9091"
whitelist = ["127.0.0.1/32", "::1/128"]
minimal_runtime_enabled = false
minimal_runtime_cache_ttl_ms = 1000

# Прослушивание на нескольких интерфейсах/IP-адресах - IPv4
[[server.listeners]]
ip = "0.0.0.0"

# === Обход блокировок и маскировка ===
[censorship]
tls_domain = "petrovich.ru"  # Домен Fake-TLS / SNI, который будет использоваться в сгенерированных ee-ссылках
mask = true
tls_emulation = true         # Получить реальную длину сертификата и эмулировать запись TLS
tls_front_dir = "tlsfront"   # Директория кэша для эмуляции TLS

[access.users]
# формат: "имя_пользователя" = "секрет_из_32_шестнадцатеричных_символов"
hello = "00000000000000000000000000000000"
```

Затем нажмите Ctrl+S -> Ctrl+X, чтобы сохранить

> [!WARNING]
> Замените значение параметра `hello` на значение, которое вы получили в пункте 0.  
> Так же замените значение параметра `tls_domain` на другой сайт.
> Изменение параметра `tls_domain` сделает нерабочими все ссылки, использующие старый домен!

---

**2. Создайте пользователя для telemt**

```bash
useradd -d /opt/telemt -m -r -U telemt
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

**1. Отредактируйте `config.toml` в корневом каталоге репозитория (как минимум: порт, пользовательские секреты, tls_domain)**  
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
> - В `docker-compose.yml` файл `./config.toml` монтируется в `/app/config.toml` (доступно только для чтения)  
> - По умолчанию публикуются порты 443:443, а контейнер запускается со сброшенными привилегиями (добавлена только `NET_BIND_SERVICE`)  
> - Если вам действительно нужна сеть хоста (обычно это требуется только для некоторых конфигураций IPv6), раскомментируйте `network_mode: host`

**Запуск без Docker Compose**
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
