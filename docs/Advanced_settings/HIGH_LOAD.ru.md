# Настройка Telemt для высокой нагрузки

[English](HIGH_LOAD.en.md) · [Русский](HIGH_LOAD.ru.md) · [Deutsch](HIGH_LOAD.de.md)

Используйте это руководство, когда измерения показывают конкретное ограничение ресурсов. Значения ниже — примеры настройки, а не подтверждённая гарантия определённого числа соединений. Перед изменениями запишите версию ядра, действующую конфигурацию, частоту подключений, расход памяти и задержку. Сохраните прежние значения и меняйте одну группу настроек за раз, чтобы сравнить результат и при необходимости откатить изменение.

Термины объяснены в [общем словаре](../TERMINOLOGY.md).

---
## 1. Системные лимиты и файловые дескрипторы

Также учитывайте [`server.max_connections`](../Config_params/CONFIG_PARAMS.ru.md#max_connections) при расчёте клиентской нагрузки, в том числе через ME. `0` снимает этот общий клиентский лимит и не ограничивает ME 128 клиентами. Ограничения дескрипторов ОС, пользовательские лимиты, очереди, бюджеты памяти и политики ME Writer продолжают действовать. Для изменения параметра нужен перезапуск процесса.

Каждое TCP-соединение требует файлового дескриптора. При 100 тысячах соединений стандартные лимиты Linux (зачастую 1024 или 65535) будут исчерпаны немедленно.
### Общесистемные лимиты (`sysctl`)
Увеличьте глобальный лимит файловых дескрипторов в `/etc/sysctl.conf`:
```ini
fs.file-max = 2097152
fs.nr_open = 2097152
```
### На уровне пользователя (`limits.conf`)
Отредактируйте `/etc/security/limits.conf`, чтобы разрешить пользователю (от которого запущен telemt) резервировать дескрипторы:
```conf
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
```
### Переопределения для Systemd / Docker
Если используется **Systemd**, добавьте в ваш `telemt.service`:
```ini
[Service]
LimitNOFILE=1048576
LimitNPROC=65535
TasksMax=infinity
```
Если используется **Docker**, задайте `ulimits` в `docker-compose.yaml`:
```yaml
services:
  telemt:
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
```

---
## 2. Тонкая настройка сетевого стека ядра (`sysctl`)
Создайте выделенный файл `/etc/sysctl.d/99-telemt-highload.conf` и примените его через `sysctl -p /etc/sysctl.d/99-telemt-highload.conf`.
### 2.1 Очереди соединений и защита от SYN-флуда
Увеличьте размеры очередей, чтобы поглощать внезапные всплески соединений и смягчить атаки типа SYN flood:
```ini
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_syncookies = 1
```
### 2.2 Исчерпание портов и TIME-WAIT сокеты
Сначала отличите ошибки исходящих подключений из-за нехватки портов от большого, но безвредного числа записей TIME-WAIT. Проверьте ошибку подключения, адреса и порты назначения и вывод `ss -s`. Если ограничение действительно связано с исходными портами, диапазон можно расширить с учётом портов, зарезервированных другими службами:

```ini
net.ipv4.ip_local_port_range = 10000 65535
```

`tcp_tw_reuse` управляет повторным использованием TIME-WAIT-сокетов, когда это допускает протокол. В указанной документации ядра `0` отключает повторное использование, `1` включает его глобально, `2` — только для loopback. Перед изменением проверьте значение в работающем ядре. `tcp_max_tw_buckets` ограничивает число сохраняемых записей, а не продолжительность TIME-WAIT.

`tcp_fin_timeout` действует на осиротевшие соединения в `FIN_WAIT_2`: его уменьшение не сокращает `TIME_WAIT`. При диагностике исчерпания портов различайте эти механизмы. См. [справочник IP sysctl ядра Linux](https://docs.kernel.org/networking/ip-sysctl.html).

### 2.3 TCP Keepalive
Эти sysctl задают значения по умолчанию для сокетов с включённым TCP keepalive, если приложение не переопределило соответствующие параметры. Проверки начинаются после пяти минут простоя; с учётом последующих проб общий срок составляет примерно 7–8 минут:

```ini
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
```

Для клиентских сокетов Telemt задаёт время ожидания и интервал через `timeouts.client_keepalive` — по умолчанию 15 секунд. Для ME-сокетов на Linux используются 30 секунд простоя, интервал 10 секунд и 3 пробы. Это параметры TCP; ME RPC Ping/Pong, `timeouts.client_ack` и политики простоя при передаче данных выполняют отдельные проверки. Поэтому пример sysctl не определяет срок жизни каждого соединения Telemt. Проверяйте нужный сокет и настроенный прикладной таймаут.

### 2.4 Буферы TCP и управление перегрузкой
До и после изменения буферов сравните расход памяти, пропускную способность и задержки p95/p99 при одинаковой нагрузке. Максимум ниже задаёт верхнюю границу для подходящего сокета, а не постоянное выделение такого объёма каждому соединению. Telemt также явно устанавливает размеры буферов сокетов, поэтому одних системных значений по умолчанию недостаточно для оценки.

```ini
# Example buffer ceilings: size them for the available memory and workload.
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
```

Проверьте доступные алгоритмы командой `sysctl net.ipv4.tcp_available_congestion_control`. Если BBR поддерживается, сравните его с действующим алгоритмом при характерных RTT, потерях и нагрузке. Это руководство не подтверждает универсального снижения задержки. Пример настройки BBR:

```ini
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
```


---
## 3. Тюнинг Conntrack (Netfilter)
Правила межсетевого экрана с отслеживанием состояния и NAT могут использовать `nf_conntrack`. Проверьте, включён ли учёт на нужном маршруте, особенно при наличии правил NOTRACK. Переполнение таблицы может приводить к отбрасыванию новых пакетов.
Проверьте текущие лимиты и использование:
```bash
sysctl net.netfilter.nf_conntrack_max
sysctl net.netfilter.nf_conntrack_count
```
Если измеренное заполнение приближается к пределу и памяти достаточно, оцените увеличение таблицы. Короткие таймауты могут удалить состояние NAT или межсетевого экрана, нужное долгоживущим соединениям; проверяйте их отдельно. Ниже приведены примеры значений:
```ini
# In /etc/sysctl.d/99-telemt-highload.conf
net.netfilter.nf_conntrack_max = 2097152
# Reduce timeout from default 5 days to 1 hour
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 12
```
*Внимание: в зависимости от ОС, вам может потребоваться выполнить `modprobe nf_conntrack` перед установкой этих параметров.*

При `server.conntrack_control.inline_conntrack_control = true` и режиме `notrack` или `hybrid` правилами, созданными Telemt, управляет один владелец. Он учитывает поколения конфигурации, применяет изменения IPv4 и IPv6 и отклоняет устаревшие или конфликтующие публикации. После ошибки повторяет согласование правил через 1, 2, 4, 8, 16 секунд, затем с паузой не более 30 секунд. При частичном сбое пытается восстановить прежние правила; если откат не удался, действующее состояние считается неизвестным до успешного согласования. `telemt_conntrack_control_state{flag="rule_apply_ok"}` показывает, применён ли требуемый набор. При включённой основной телеметрии попытки учитываются в `telemt_conntrack_rule_reconcile_total{result="success"|"error"}` и `telemt_conntrack_rule_rollback_total{result="success"|"error"}`. При завершении работы Telemt пытается удалить собственные правила в пределах 30 секунд. Изменение настроек conntrack требует перезапуска процесса.

---
## 4. Архитектура: развёртывание за HAProxy

### 4.1 L4-развёртывание native MTProxy и TLS-front

Для массового native MTProxy- или TLS-front-трафика L4 HAProxy может поглощать всплески соединений перед передачей TCP-потоков в Telemt. Следующий пример **не подходит для WEB-listener**.

#### Пример `haproxy.cfg` для высокой нагрузки
```haproxy
global
    # Disable detailed connection logs under load
    log stdout format raw local0 err
    maxconn 250000
    # Tune buffers and socket acceptance
    tune.bufsize 16384
    tune.maxaccept 64
defaults
    log     global
    mode    tcp
    option  clitcpka
    option  srvtcpka
    timeout connect 5s
    timeout client  1h
    timeout server  1h
    # Purge dead peers quickly
    timeout client-fin 10s
    timeout server-fin 10s
frontend proxy_in
    bind *:443
    maxconn 250000
    option tcp-smart-accept
    default_backend telemt_backend
backend telemt_backend
    option tcp-smart-connect
    # Preserve the client IP for Telemt through PROXY v2
    server telemt_core 10.10.10.1:443 maxconn 250000 send-proxy-v2 check inter 5s
```
**Важно**: включите PROXY protocol на явном listener Telemt и задайте в `server.proxy_protocol_trusted_cidrs` адреса непосредственного HAProxy. Проверьте адрес прослушивания и правила межсетевого экрана. Полная настройка listener показана в [примере двойного перехода](../Setup_examples/VPS_DOUBLE_HOP.ru.md#шаг-2-установка-telemt-на-сервере-b-условно-нидерланды).

### 4.2 WEB-развёртывание

WEB-режиму нужны TLS-терминатор уровня L7 и приватный HTTP/1.1 listener Telemt без шифрования, с `proxy_protocol = false`. Предыдущий пример L4 с `send-proxy-v2` для этого не подходит. Следуйте [руководству WEB](../WEB/WEB_PROXY.ru.md): сохраняйте `Host`, точный путь и строку запроса, а также заголовки WebSocket Upgrade. Передавайте один заново сформированный `X-Forwarded-For` только от явно доверенных CIDR терминатора. На публичном TLS-входе ALPN должен предлагать `h2` для `https-lanes` и `http/1.1` для WebSocket Upgrade.

Для WEB-listener задайте `web_client_ip_source = "x_forwarded_for"`; в `web_trusted_proxy_cidrs` укажите только адреса непосредственного HAProxy. Не доверяйте доступной клиентам подсети и не включайте PROXY protocol на этом listener.

Направляйте весь виртуальный хост в один процесс Telemt. При размещении в подкаталоге сохраняйте `base_path` без переписывания. Во время миграции направляйте в Telemt и старое, и новое поддеревья, пока ещё могут использоваться ранее выпущенные процессом токены. Если процессов несколько, закрепляйте за одним процессом весь виртуальный хост: страницу моста, создание и восстановление сессий, передачу в обе стороны, DELETE, диагностику и WebSocket Upgrade.

Например, этот фрагмент HAProxy направляет в Telemt только указанный хост и WEB-поддерево с завершающим слешем, сохраняя исходный адрес запроса:

```haproxy
frontend https_in
    mode http
    bind *:443 ssl crt /etc/haproxy/certs/proxy.pem alpn h2,http/1.1
    timeout client 65s
    acl telemt_web_host hdr(host) -i proxy.example.com proxy.example.com:443
    acl telemt_web_path path_beg /telegram/web/
    use_backend telemt_web if telemt_web_host telemt_web_path

backend telemt_web
    mode http
    retries 0
    timeout connect 5s
    timeout server 65s
    http-request set-header Host proxy.example.com
    http-request set-header X-Forwarded-For %[src]
    server telemt_web_1 127.0.0.1:18080 check
```

Обрабатывайте путь без завершающего слеша `/telegram/web` вне этого backend, чтобы не создавать перенаправление в аутентифицированное поддерево. Не добавляйте `set-path`, `replace-path` или путь к адресу сервера backend. Таймаут 65 секунд подходит для настроек по умолчанию. Таймауты клиента и сервера должны превышать `web.timeouts.long_poll_secs` и удвоенный действующий интервал проверки активности WebSocket.

При расчёте ёмкости учитывайте и публичные TLS-сокеты, и приватные соединения между терминатором и Telemt. Согласуйте лимиты файловых дескрипторов, исходящих соединений терминатора, `web.limits.max_http_connections`, обработчиков, параллельных долгих опросов и каналов WebSocket. Пул простаивающих keepalive-соединений не ограничивает число одновременных запросов.

---
## 5. Диагностика и мониторинг

- **Переполнение очередей входящих соединений**: проверяйте `ListenOverflows` и `ListenDrops` в `/proc/net/netstat` либо через `nstat`.
- **Заполнение conntrack**: проверяйте `nf_conntrack_count`, журнал ядра и `telemt_conntrack_control_state{flag="rule_apply_ok"}`; при включённой основной телеметрии — также указанные выше счётчики согласования и отката правил.
- **Файловые дескрипторы**: `cat /proc/sys/fs/file-nr` и лимиты процесса Telemt в `/proc/<pid>/limits`.
- **Состояния соединений**: `ss -s`; избегайте полного сканирования через `netstat` на нагруженном сервере.
- **Конкуренция за ограничитель скорости**: при включённой основной телеметрии отслеживайте рост счётчика, например `increase(telemt_rate_limiter_cas_retry_exhausted_total[5m]) > 0`, с группировкой по `scope`, `direction` и `operation`. Исчерпание попыток резервирования возвращает нулевое разрешение на передачу и не считается срабатыванием настроенного лимита. Исчерпание попыток возврата сохраняет списанный объём. Метрика не считает разорванные соединения или ограничения, предусмотренные политикой.
- **WEB**: сопоставляйте телеметрию терминатора и внешнюю проверку TLS с `/v1/runtime/web/status`, `telemt_web_tcp_accept_total{result="accepted"|"error"}` и остальными метриками `telemt_web_*`. Путь запроса и `base_path` намеренно не используются как метки метрик.
