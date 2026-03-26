<img src="https://gist.githubusercontent.com/avbor/1f8a128e628f47249aae6e058a57610b/raw/19013276c035e91058e0a9799ab145f8e70e3ff5/scheme.svg">

## Концепция
- **Сервер A** (_РФ_):\
  Точка входа, принимает трафик пользователей Telegram-прокси через **HAProxy** (порт `443`)\
  и отправляет в туннель на Сервер **B**.\
  Внутренний IP в туннеле — `10.10.10.2`\
  Порт для клиентов HAProxy — `443\tcp`
- **Сервер B** (_условно Нидерланды_):\
  Точка выхода, на нем работает **telemt** и принимает подключения клиентов через Сервер **A**.\
  На сервере должен быть неограниченный доступ до серверов Telegram.\
  Внутренний IP в туннеле — `10.10.10.1`\
  Порт AmneziaWG — `8443\udp`\
  Порт для клиентов telemt — `443\tcp`

---

## Шаг 1. Настройка туннеля AmneziaWG (A <-> B)

На всех серверах необходимо установить [amneziawg](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module).\
Далее все команды даны для **Ununtu 24.04**.\
Для RHEL-based дистрибутивов инструкция по установке есть по ссылке выше.

### Установка AmneziaWG (Сервера A и B)
На каждом из серверов необходимо выполнить следующие шаги:

#### 1. Добавление репозитория AmneziaWG и установка необходимых пакетов:
```bash
sudo apt install -y software-properties-common python3-launchpadlib gnupg2 linux-headers-$(uname -r) && \
sudo add-apt-repository ppa:amnezia/ppa && \
sudo apt-get install -y amneziawg
```
 
#### 2. Генерация уникальной пары ключей:
```bash
cd /etc/amnezia/amneziawg && \
awg genkey | tee private.key | awg pubkey > public.key
```
В результате вы получите в папке `/etc/amnezia/amneziawg` два файла:\
`private.key` - приватный и\
`public.key` - публичный ключи сервера

#### 3. Настройка сетевых интерфейсов:

Параметры обфускации `S1`, `S2`, `H1`, `H2`, `H3`, `H4` должны быть строго идентичными на обоих серверах.\
Параметры `Jc`, `Jmin` и `Jmax` могут отличатся.\
Параметры `I1-I5` ([Custom Protocol Signature](https://docs.amnezia.org/documentation/amnezia-wg/)) нужно указывать на стороне _клиента_ (Сервер **А**).

Рекомендации по выбору значений:
```text
Jc — 1 ≤ Jc ≤ 128; от 4 до 12 включительно
Jmin — Jmax > Jmin < 1280*; рекомендовано 8
Jmax — Jmin < Jmax ≤ 1280*; рекомендовано 80
S1 — S1 ≤ 1132* (1280* - 148 = 1132); S1 + 56 ≠ S2;
рекомендованный диапазон от 15 до 150 включительно
S2 — S2 ≤ 1188* (1280* - 92 = 1188);
рекомендованный диапазон от 15 до 150 включительно
H1/H2/H3/H4 — должны быть уникальны и отличаться друг от друга;
рекомендованный диапазон от 5 до 2147483647 включительно

* Предполагается, что подключение к Интернету имеет MTU 1280.
```
> [!IMPORTANT]
> Рекомендуется использовать собственные, уникальные значения.\
> Для выбора параметров можете воспользоваться [генератором](https://htmlpreview.github.io/?https://gist.githubusercontent.com/avbor/955782b5c37b06240b243aa375baeac5/raw/13f5517ca473b47c412b9a99407066de973732bd/awg-gen.html).

#### Конфигурация Сервера B (_Нидерланды_):

Создаем файл конфигурации интерфейса (`awg0`)
```bash
nano /etc/amnezia/amneziawg/awg0.conf
```

Содержимое файла
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

`ListenPort` - порт, на котором сервер будет ждать подключения, можете выбрать любой свободный.\
`<PRIVATE_KEY_SERVER_B>` - содержимое файла `private.key` с сервера **B**.\
`<PUBLIC_KEY_SERVER_A>` - содержимое файла `public.key` с сервера **A**.

Открываем порт на фаерволе (если включен):
```bash
sudo ufw allow from <PUBLIC_IP_SERVER_A> to any port 8443 proto udp
```

`<PUBLIC_IP_SERVER_A>` - внешний IP адрес Сервера **A**.

#### Конфигурация Сервера A (_РФ_):

Создаем файл конфигурации интерфейса (`awg0`)
```bash
nano /etc/amnezia/amneziawg/awg0.conf
```

Содержимое файла
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

`<PRIVATE_KEY_SERVER_A>` - содержимое файла `private.key` с сервера **A**.\
`<PUBLIC_KEY_SERVER_B>` - содержимое файла `public.key` с сервера **B**.\
`<PUBLIC_IP_SERVER_B>` - публичный IP адресс сервера **B**.

#### Включаем туннель на обоих серверах:
```bash
sudo systemctl enable --now awg-quick@awg0 
```

Убедитесь, что с Сервера `A` доступен Сервер `B` через туннель.
```bash
ping 10.10.10.1
PING 10.10.10.1 (10.10.10.1) 56(84) bytes of data.
64 bytes from 10.10.10.1: icmp_seq=1 ttl=64 time=35.1 ms
64 bytes from 10.10.10.1: icmp_seq=2 ttl=64 time=35.0 ms
64 bytes from 10.10.10.1: icmp_seq=3 ttl=64 time=35.1 ms
^C

```

---

## Шаг 2. Установка telemt на Сервере B (_условно Нидерланды_)

Установка и настройка описаны [здесь](https://github.com/telemt/telemt/blob/main/docs/QUICK_START_GUIDE.ru.md) или [здесь](https://gitlab.com/An0nX/telemt-docker#-quick-start-docker-compose).\
Подразумевается что telemt ожидает подключения на порту `443\tcp`.

В конфиге telemt необходимо включить протокол `Proxy` и ограничить подключения к нему только через туннель.

```toml
[server]
port = 443
listen_addr_ipv4 = "10.10.10.1"
proxy_protocol = true
```

А также, для правильной генерации ссылок, указать FQDN или IP адрес и порт Сервера `A` 

```toml
[general.links]
show = "*"
public_host = "<FQDN_OR_IP_SERVER_A>"
public_port = 443
```

Открываем порт на фаерволе (если включен):
```bash
sudo ufw allow from 10.10.10.2 to any port 443 proto tcp
```

---

### Шаг 3. Настройка HAProxy на Сервере A (_РФ_)

Т.к. в стандартном репозитории Ubuntu версия относительно старая, имеет смысл воспользоваться официальным образом Docker.\
[Инструкция](https://docs.docker.com/engine/install/ubuntu/) по установке Docker на Ubuntu.

> [!WARNING]
> По умолчанию у обычных пользователей нет прав на использование портов < 1024.\
> Попытки запустить HAProxy на 443 порту могут приводить к ошибкам:
> ```
> [ALERT] (8) : Binding [/usr/local/etc/haproxy/haproxy.cfg:17] for frontend tcp_in_443: 
> protocol tcpv4: cannot bind socket (Permission denied) for [0.0.0.0:443].
> ```
> Есть два простых способа обойти это ограничение, выберите что-то одно:
> 1. На уровне ОС изменить настройку net.ipv4.ip_unprivileged_port_start, разрешив пользователям использовать все порты:
> ```
> echo "net.ipv4.ip_unprivileged_port_start = 0" | sudo tee -a /etc/sysctl.conf && sudo sysctl -p
> ```
> или
> 
> 2. Запустить HAProxy под root:\
> Раскомментируйте в docker-compose.yaml параметр `user: "root"`.

#### Создаем папку для HAProxy:
```bash
mkdir -p /opt/docker-compose/haproxy && cd $_
```
#### Создаем файл docker-compose.yaml

`nano docker-compose.yaml`

Содержимое файла
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
#### Создаем файл конфига haproxy.cfg
Принимаем подключения на порту 443\tcp и отправляем их через туннель на Сервер `B` 10.10.10.1:443

`nano haproxy.cfg`

Содержимое файла
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
>[!WARNING]
>**Файл должен заканчиваться пустой строкой, иначе HAProxy не запустится!**

#### Разрешаем порт 443\tcp в фаерволе (если включен)
```bash
sudo ufw allow 443/tcp
```

#### Запускаем контейнер HAProxy
```bash
docker compose up -d
```

Если все настроено верно, то теперь можно пробовать подключить клиентов Telegram с использованием ссылок из лога\api telemt.
