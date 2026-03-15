## Как настроить канал "спонсор прокси" и статистику через бота @MTProxybot

1. Зайти в бота @MTProxybot.
2. Ввести команду `/newproxy`
3. Отправить IP и порт сервера. Например: 1.2.3.4:443
4. Открыть конфиг `nano /etc/telemt.toml`.
5. Скопировать и отправить боту секрет пользователя из раздела [access.users].
6. Скопировать полученный tag у бота. Например 1234567890abcdef1234567890abcdef.
> [!WARNING]
> Ссылка, которую выдает бот, не будет работать. Не копируйте и не используйте её!
7. Раскомментировать параметр ad_tag и вписать tag, полученный у бота.
8. Раскомментировать/добавить параметр use_middle_proxy = true.

Пример конфига:
```toml
[general]
ad_tag = "1234567890abcdef1234567890abcdef"
use_middle_proxy = true
```
9.  Сохранить конфиг. Ctrl+S -> Ctrl+X.
10. Перезапустить telemt `systemctl restart telemt`.
11. В боте отправить команду /myproxies и выбрать добавленный сервер.
12. Нажать кнопку "Set promotion".
13. Отправить **публичную ссылку** на канал. Приватный канал добавить нельзя!
14. Подождать примерно 1 час, пока информация обновится на серверах Telegram.
> [!WARNING]
> У вас не будет отображаться "спонсор прокси" если вы уже подписаны на канал.

**Также вы можете настроить разные каналы для разных пользователей.**
```toml
[access.user_ad_tags]
hello = "ad_tag"
hello2 = "ad_tag2"
```

## Сколько человек может пользоваться 1 ссылкой

По умолчанию 1 ссылкой может пользоваться сколько угодно человек.  
Вы можете ограничить число IP, использующих прокси.
```toml
[access.user_max_unique_ips]
hello = 1
```
Этот параметр ограничивает, сколько уникальных IP может использовать 1 ссылку одновременно. Если один пользователь отключится, второй сможет подключиться. Также с одного IP может сидеть несколько пользователей.

## Как сделать несколько разных ссылок

1. Сгенерируйте нужное число секретов `openssl rand -hex 16`
2. Открыть конфиг `nano /etc/telemt.toml`
3. Добавить новых пользователей.
```toml
[access.users]
user1 = "00000000000000000000000000000001"
user2 = "00000000000000000000000000000002"
user3 = "00000000000000000000000000000003"
```
4. Сохранить конфиг. Ctrl+S -> Ctrl+X. Перезапускать telemt не нужно.
5. Получить ссылки через
```bash
curl -s http://127.0.0.1:9091/v1/users | jq
```

## Как посмотреть метрики

1. Открыть конфиг `nano /etc/telemt.toml`
2. Добавить следующие параметры
```toml
[server]
metrics_port = 9090
metrics_whitelist = ["127.0.0.1/32", "::1/128", "0.0.0.0/0"]
```
3. Сохранить конфиг. Ctrl+S -> Ctrl+X.
4. Метрики доступны по адресу SERVER_IP:9090/metrics. 
> [!WARNING]
> "0.0.0.0/0" в metrics_whitelist открывает доступ с любого IP. Замените на свой ip. Например "1.2.3.4"

## Дополнительные параметры

### Домен в ссылке вместо IP
Чтобы указать домен в ссылках, добавьте в секцию `[general.links]` файла config.
```toml
[general.links]
public_host = "proxy.example.com"
```

### Upstream Manager
Чтобы указать апстрим, добавьте в секцию `[[upstreams]]` файла config.toml:
#### Привязка к IP
```toml
[[upstreams]]
type = "direct"
weight = 1
enabled = true
interface = "192.168.1.100" # Change to your outgoing IP
```
#### SOCKS4/5 как Upstream
- Без авторизации:
```toml
[[upstreams]]
type = "socks5"            # Specify SOCKS4 or SOCKS5
address = "1.2.3.4:1234"   # SOCKS-server Address
weight = 1                 # Set Weight for Scenarios
enabled = true
```

- С авторизацией:
```toml
[[upstreams]]
type = "socks5"            # Specify SOCKS4 or SOCKS5
address = "1.2.3.4:1234"   # SOCKS-server Address
username = "user"          # Username for Auth on SOCKS-server
password = "pass"          # Password for Auth on SOCKS-server
weight = 1                 # Set Weight for Scenarios
enabled = true
```
