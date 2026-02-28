# Telemt через Systemd

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

**1. Поместите свою конфигурацию в файл /etc/telemt.toml**

Открываем nano
```bash
nano /etc/telemt.toml
```
Вставьте свою конфигурацию

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
Затем нажмите Ctrl+X -> Y -> Enter, чтобы сохранить

> [!WARNING]
> Замените значение параметра hello на значение, которое вы получили в пункте 0.  
> Так же замените значение параметра tls_domain на другой сайт.

---

**2. Создайте службу в /etc/systemd/system/telemt.service**

Открываем nano
```bash
nano /etc/systemd/system/telemt.service
```

Вставьте этот модуль Systemd
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
Затем нажмите Ctrl+X -> Y -> Enter, чтобы сохранить


**3.** Для запуска введите команду `systemctl start telemt`

**4.** Для получения информации о статусе введите `systemctl status telemt`

**5.** Для автоматического запуска при запуске системы в введите `systemctl enable telemt`

**6.** Для получите ссылки введите `journalctl -u telemt -n -g "links" --no-pager -o cat | tac`

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

**Запуск в Docker Compose**
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
