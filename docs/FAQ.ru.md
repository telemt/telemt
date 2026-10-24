## Как настроить канал "спонсор прокси" и статистику через бота @MTProxybot

1. Зайдите в бота @MTProxybot.
2. Введите команду `/newproxy`.
3. Отправьте IP-адрес и порт сервера. Например: `1.2.3.4:443`.
4. Откройте файл конфигурации: `nano /etc/telemt/telemt.toml`.
5. Скопируйте и отправьте боту секрет пользователя из раздела `[access.users]`.
6. Скопируйте тег (tag), который выдаст бот. Например: `1234567890abcdef1234567890abcdef`.
> [!WARNING]
> Ссылка, которую выдает бот, работать не будет. Не копируйте и не используйте её!
7. Раскомментируйте параметр `ad_tag` и впишите тег, полученный от бота.
8. Раскомментируйте или добавьте параметр `use_middle_proxy = true`.

Пример конфигурации:
```toml
[general]
ad_tag = "1234567890abcdef1234567890abcdef"
use_middle_proxy = true
```
9. Сохраните изменения (в nano: Ctrl+S -> Ctrl+X).
10. Перезапустите службу telemt: `systemctl restart telemt`.
11. В боте отправьте команду `/myproxies` и выберите добавленный сервер.
12. Нажмите кнопку «Set promotion».
13. Отправьте **публичную ссылку** на канал. Приватные каналы добавлять нельзя!
14. Подождите примерно 1 час, пока информация обновится на серверах Telegram.
> [!WARNING]
> Спонсорский канал не будет у вас отображаться, если вы уже на него подписаны.

**Вы также можете настроить разные спонсорские каналы для разных пользователей:**
```toml
[access.user_ad_tags]
hello = "ad_tag"
hello2 = "ad_tag2"
```
## Распознаваемость для DPI и сканеров
1 апреля 2026 года нам стало известно о методе обнаружения MTProxy Fake-TLS, основанном на расширении ECH и порядке набора шифров,
а также об общем уникальном отпечатке JA3/JA4, который не встречается в современных браузерах.

> [!IMPORTANT]
> Проблема с TLS отпечатком исправлена в последних версиях клиентов Telegram для Desktop / Android / iOS.  
> Обновите свой клиент для корректной работы с MTProxy Fake-TLS!

- Для расследования блокировок на базе JA4 ClientHello используйте отдельную инструкцию: [`JA3 и JA4 анализ в Telemt`](Architecture/Fronting-splitting/TLS_JA3_JA4_ANALYSIS.ru.md).

- При корректной настройке TLS fronting неаутентифицированный трафик проходит через реальный upstream TLS handshake и получает его ответы. Устойчивость fingerprint по-прежнему зависит от версии клиента, выбранного host, сетевого пути и внешней проверки;
- Вот наши доказательства:
    - 212.220.88.77 — «фиктивный» хост, на котором запущен `telemt`;
    - `petrovich.ru` — хост с `tls` + `masking`, в HEX: `706574726f766963682e7275`;
    - **Без MITM + без поддельных сертификатов/шифрования** = чистое прозрачное *TCP Splice* к «лучшему» исходному серверу: MTProxy или tls/mask-host:
      - DPI видит легитимный HTTPS к `tls_host`, включая *достоверную цепочку доверия* и энтропию;
      - Краулеры полностью удовлетворены получением ответов от `mask_host`.
 
  ### Клиент С секретным ключом получает доступ к ресурсу MTProxy:
  
  <img width="360" height="439" alt="telemt" src="https://github.com/user-attachments/assets/39352afb-4a11-4ecc-9d91-9e8cfb20607d" />
  
  ### Клиент БЕЗ секретного ключа получает прозрачный доступ к указанному ресурсу:
    - с доверенным сертификатом;
    - с исходным «рукопожатием»;
    - с полным циклом запрос-ответ;
    - с низкой задержкой.

> [!NOTE]
> Ниже приведён исторический capture от 1 января 2026 года, а не проверка текущей доступности. Показанный сертификат истёк 1 марта 2026 года; актуальные endpoint и сертификат необходимо проверять отдельно.

```text
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
- Мы поставили перед собой задачу, не сдавались и не просто «бились в пустоту»: теперь у нас есть что вам показать.
- Не верите нам на слово? — Это прекрасно, и мы уважаем ваше решение: вы можете собрать свой собственный `telemt` или скачать готовую сборку и проверить её прямо сейчас.

## ЧаВо

### Звонки в Telegram через MTProxy
- Архитектура Telegram **НЕ поддерживает звонки через MTProxy**, а только через SOCKS5, который невозможно замаскировать

### Как DPI распознает TLS-соединение MTProxy?
- DPI распознает MTProxy в режиме Fake TLS (ee) как TLS 1.3
- указанный вами SNI отправляется как клиентом, так и сервером;
- ALPN аналогичен HTTP 1.1/2;
- высокая энтропия, что нормально для трафика, зашифрованного AES;

### Белый список по IP
- MTProxy не может работать, если: 
  - отсутствует IP-связь с целевым хостом: российский белый список в мобильных сетях — «Белый список»;
  - ИЛИ весь TCP-трафик заблокирован;
  - ИЛИ трафик с высокой энтропией/зашифрованный трафик заблокирован: контент-фильтры в университетах и критически важной инфраструктуре;
  - ИЛИ весь TLS-трафик заблокирован;
  - ИЛИ заблокирован указанный порт: используйте 443, чтобы сделать его «как настоящий»;
  - ИЛИ заблокирован предоставленный SNI: используйте «официально одобренное»/безобидное имя;
- как и большинство протоколов в Интернете; 
- такие ситуации наблюдаются:
  - в Китае за Великим файрволом;
  - в России в мобильных сетях, реже в проводных сетях;
  - в Иране во время «активности».


### Зачем нужен middle proxy (ME)
https://github.com/telemt/telemt/discussions/167

## Как клиенты взаимодействуют с дата-центрами Telegram
При регистрации аккаунта Telegram он навсегда привязывается к одному из дата-центров (DC).  
Telegram заранее определяет к какому DC привязать аккаунт исходя из региона, к которому относится номер телефона.  
Этот DC становится вашим **домашним**: именно там хранится весь контент, который вы загружаете (фото, видео, файлы, сообщения).  
И именно на нем клиент авторизуется при каждом подключении.  

Например, если ваш аккаунт зарегистрирован на **DC2**, клиент всегда будет подключаться в первую очередь к DC2.  
Когда вы открываете переписку с пользователем, чей домашний DC — **DC5**, клиент устанавливает доп. соединение с DC5, чтобы загрузить его контент.  
Такие кросс-запросы к DC — это нормальная часть работы Telegram.  

> [!WARNING]
> Поскольку аккаунт всегда привязан к домашнему DC, при его падении контент с других DC будет недоступен.  
> Если ваш домашний DC — DC2, и DC2 лежит, вы **не сможете** достучаться  и до DC5, даже если сам DC5 полностью исправен.  
> У клиента просто нет валидной сессии, через которую можно было бы направить запрос.  

По той же причине MTProxy необходимо иметь доступ к инфраструктуре Telegram целиком, а не частично.  
Cамому MTProxy всё равно, на каком DC живёт ваш аккаунт. Клиент cам договаривается о нужном DC через прокси уже после подключения.  

### Что такое `dd` и `ee` в контексте MTProxy?

Это разные режимы прокси, обозначаемые в начале закодированного секрета. `dd` включает защищённый обфусцированный транспорт. `ee` включает Fake TLS и добавляет к секрету настроенный SNI-домен. Выбирайте режим по поддержке клиентом, условиям цензуры и настроенному пути fronting/masking. Используйте `ee`, только когда требуется TLS-shaped traffic, и проверяйте его через реальный публичный endpoint; WEB-режим поддерживает `plain` и `dd`, но не `ee`.

### Где эти режимы настраиваются?

```toml
[general.modes]
# Classic MTProxy mode.
classic = false
# dd mode.
secure = false
# ee Fake TLS mode.
tls = true
```

### Сколько человек может пользоваться одной ссылкой

По умолчанию одной ссылкой может пользоваться неограниченное число людей.  
Однако вы можете ограничить количество уникальных IP-адресов для каждого пользователя:
```toml
[access.user_max_unique_ips]
hello = 1
```
Этот параметр задает максимальное количество уникальных IP-адресов, с которых можно одновременно использовать одну ссылку. Если первый пользователь отключится, второй сможет подключиться. При этом с одного IP-адреса могут подключаться несколько пользователей одновременно (например, устройства в одной Wi-Fi сети).

### Как создать несколько разных ссылок

1. Сгенерируйте необходимое количество секретов с помощью команды: `openssl rand -hex 16`.
2. Откройте файл конфигурации: `nano /etc/telemt/telemt.toml`.
3. Добавьте новых пользователей в секцию `[access.users]`:
```toml
[access.users]
user1 = "00000000000000000000000000000001"
user2 = "00000000000000000000000000000002"
user3 = "00000000000000000000000000000003"
```
4. Сохраните конфигурацию (Ctrl+S -> Ctrl+X). Перезапускать службу telemt не нужно.
5. Получите готовые ссылки с помощью команды:
```bash
curl -s http://127.0.0.1:9091/v1/users | jq
```

### Ошибка "Unknown TLS SNI"
Обычно эта ошибка возникает, если вы изменили параметр `tls_domain`, но пользователи продолжают подключаться по старым ссылкам с прежним доменом.

Если необходимо разрешить подключение с любыми доменами (игнорируя несовпадения SNI), добавьте следующие параметры:
```toml
[censorship]
unknown_sni_action = "mask"
```

Альтернатива: если вы хотите, чтобы telemt на неизвестный SNI вёл себя как обычный nginx с `ssl_reject_handshake on;` (отдавал TLS-alert `unrecognized_name` и закрывал соединение), используйте:
```toml
[censorship]
unknown_sni_action = "reject_handshake"
```
Это не пропускает старых клиентов, но делает поведение на 443-м порту неотличимым от стокового веб-сервера, у которого просто нет такого виртуального хоста.

### Как посмотреть метрики

1. Откройте файл конфигурации: `nano /etc/telemt/telemt.toml`.
2. Добавьте следующие параметры:
```toml
[server]
metrics_listen = "127.0.0.1:9090"
metrics_whitelist = ["127.0.0.1/32", "::1/128"]
```
3. Сохраните изменения (Ctrl+S -> Ctrl+X).
4. Метрики будут доступны локально по адресу `http://127.0.0.1:9090/metrics`.
> [!WARNING]
> Оставляйте metrics на loopback, если удалённый сборщик не требуется. Для удалённого сбора привяжите явный приватный адрес, разрешите только CIDR сборщика и закрепите ту же границу в host firewall. Не используйте whitelist `/0`.

Счётчики нагрузки и проверки операционной системы описаны в [руководстве по High-Load](Advanced_settings/HIGH_LOAD.ru.md#5-диагностика-и-мониторинг).

### Слишком много открытых файлов

- На свежей Linux-системе лимит открытых файлов обычно мал; под нагрузкой Telemt может завершать accept с ошибкой `Too many open files`.
- Для systemd добавьте `LimitNOFILE=65536` в секцию `[Service]`.
- Для Docker добавьте `--ulimit nofile=65536:65536` в `docker run` либо настройте Compose:

```yaml
ulimits:
  nofile:
    soft: 65536
    hard: 65536
```

- При необходимости задайте системные пределы в `/etc/security/limits.conf`:

```conf
*       soft    nofile  1048576
*       hard    nofile  1048576
root    soft    nofile  1048576
root    hard    nofile  1048576
```

## Дополнительные параметры

### Домен в ссылке вместо IP
Чтобы в native-ссылках `tg://proxy` отображался домен вместо IP-адреса, добавьте следующие строки в файл конфигурации:
```toml
[general.links]
public_host = "proxy.example.com"
```

Эта настройка вместе с `public_port` влияет только на native-ссылки. WEB-ссылки `tg://webproxy` всегда используют `[[web.vhosts]].host` и внешний порт `443`.

### Общий лимит подключений к серверу
Этот параметр ограничивает общее количество активных подключений к серверу:
```toml
[server]
# Zero disables the limit; 10000 is the default.
max_connections = 10000
```

Лимит распространяется и на клиентские сессии, работающие через ME. При
`max_connections = 0` отдельного ограничения числа сессий ME нет; ограничения
ресурсов ОС и остальные настроенные лимиты продолжают действовать. Этот параметр
не задаёт количество исходящих TCP-соединений пула ME. Для изменения нужен
перезапуск процесса: перечитывания конфигурации недостаточно. Подробнее — в
[справочнике параметров](Config_params/CONFIG_PARAMS.ru.md#max_connections).

### Upstream Manager
Для настройки исходящих подключений (Upstreams) добавьте соответствующие параметры в секцию `[[upstreams]]` файла конфигурации:

#### Привязка к исходящему IP-адресу
```toml
[[upstreams]]
type = "direct"
weight = 1
enabled = true
# Replace this value with your outbound IP.
interface = "192.168.1.100"
```

#### Использование SOCKS4/5 в качестве Upstream
- Без авторизации:
```toml
[[upstreams]]
# Specify SOCKS4 or SOCKS5.
type = "socks5"
# SOCKS server address.
address = "1.2.3.4:1234"
# Selection weight.
weight = 1
enabled = true
```

- С авторизацией:
```toml
[[upstreams]]
# Specify SOCKS4 or SOCKS5.
type = "socks5"
# SOCKS server address.
address = "1.2.3.4:1234"
# SOCKS username.
username = "user"
# SOCKS password.
password = "pass"
# Selection weight.
weight = 1
enabled = true
```

#### Использование Shadowsocks в качестве Upstream
Для работы этого метода требуется установить параметр `use_middle_proxy = false`.

```toml
[general]
use_middle_proxy = false

[[upstreams]]
type = "shadowsocks"
url = "ss://2022-blake3-aes-256-gcm:BASE64_KEY@1.2.3.4:8388"
weight = 1
enabled = true
```
