# Руководство по High-Load конфигурации и тюнингу
При развертывании Telemt под высокой нагрузкой (десятки и сотни тысяч одновременных подключений), стандартные ограничения сетевого стека ОС могут приводить к потерям пакетов, переключениям контекста CPU и отказам в соединениях. В данном руководстве описана настройка ядра Linux, системных лимитов и аппаратной конфигурации для работы в подобных сценариях.

---
## 1. Системные лимиты и файловые дескрипторы

Также учитывайте [`server.max_connections`](../Config_params/CONFIG_PARAMS.ru.md#max_connections) при расчёте клиентской нагрузки, в том числе через ME. `0` снимает этот общий клиентский лимит и не ограничивает ME 128 клиентами. Ограничения дескрипторов ОС, пользовательские лимиты, очереди, бюджеты памяти и политики writer-ов продолжают действовать. Для изменения параметра нужен перезапуск процесса.

Каждое TCP-сосоединение требует файлового дескриптора. При 100 тысячах соединений стандартные лимиты Linux (зачастую 1024 или 65535) будут исчерпаны немедленно.
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
Высокая текучесть приводит к нехватке временных (ephemeral) портов. Расширьте диапазон портов и позвольте ядру быстро переиспользовать закрытые сокеты:
```ini
net.ipv4.ip_local_port_range = 10000 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 2000000
```
### 2.3 TCP Keepalive (Агрессивная очистка мертвых соединений)
По умолчанию Linux держит "оборванные" TCP-сессии более 2 часов. Значения ниже начинают probes после пяти минут простоя и закрывают не отвечающий peer после последующего probe budget — примерно через 7–8 минут общего простоя:
```ini
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
```
### 2.4 Буферы TCP и управление перегрузками (Congestion Control)
Оптимизируйте использование памяти на сокет и переключитесь на алгоритм BBR (Bottleneck Bandwidth and Round-trip propagation time) для улучшения задержки на плохих сетях:
```ini
# Core buffer sizes
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
# TCP-specific buffers (min, default, max)
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
# Enable BBR
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
```

---
## 3. Тюнинг Conntrack (Netfilter)
Если ваш сервер использует `iptables`, `ufw` или `firewalld`, ядро вынуждено отслеживать каждое соединение в таблице состояний (`nf_conntrack`). Когда эта таблица переполняется, Linux отбрасывает новые пакеты без уведомления приложения.
Проверьте текущие лимиты и использование:
```bash
sysctl net.netfilter.nf_conntrack_max
sysctl net.netfilter.nf_conntrack_count
```
Если вы близки к пределу, увеличьте таблицу и заставьте ядро быстрее удалять установленные соединения. Добавьте в `/etc/sysctl.d/99-telemt-highload.conf`:
```ini
# In /etc/sysctl.d/99-telemt-highload.conf
net.netfilter.nf_conntrack_max = 2097152
# Reduce timeout from default 5 days to 1 hour
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 12
```
*Внимание: в зависимости от ОС, вам может потребоваться выполнить `modprobe nf_conntrack` перед установкой этих параметров.*

Когда `server.conntrack_control.inline_conntrack_control = true` и `[server.conntrack_control]` использует `notrack` или `hybrid`, один generation-fenced authority владеет только правилами conntrack control, созданными Telemt. Он применяет изменения IPv4 и IPv6, игнорирует устаревшие или конфликтующие публикации и повторяет неудачный reconcile через 1, 2, 4, 8, 16 и далее не более чем 30 секунд. Частичный многошаговый сбой запускает best-effort восстановление; неудачный rollback оставляет applied firewall state неизвестным до следующего успешного reconcile. `telemt_conntrack_control_state{flag="rule_apply_ok"}` показывает, действует ли требуемый набор правил. При включённой core telemetry попытки используют `telemt_conntrack_rule_reconcile_total{result="success"|"error"}` и `telemt_conntrack_rule_rollback_total{result="success"|"error"}`. При shutdown выполняется ограниченный 30 секундами best-effort cleanup собственных правил. Настройки conntrack control требуют перезапуска.

---
## 4. Архитектура: развёртывание за HAProxy

### 4.1 L4-развёртывание native MTProxy и TLS-front

Для массового native MTProxy- или TLS-front-трафика L4 HAProxy может поглощать всплески соединений перед передачей TCP streams в Telemt. Следующий пример **не подходит для WEB-listener**.

#### Оптимизация `haproxy.cfg` для High-Load
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
**Важно**: Telemt должен быть настроен на обработку протокола `PROXY` на порту `443`, чтобы получать оригинальные IP-адреса клиентов.

### 4.2 WEB-развёртывание

WEB-режиму требуется L7 TLS-терминатор и приватный plain HTTP/1.1 listener Telemt с `proxy_protocol = false`; не используйте для него L4 backend с `send-proxy-v2` из предыдущего примера. Следуйте полному [руководству по WEB-прокси](../WEB/WEB_PROXY.ru.md), сохраняйте `Host`, точные path и query, WebSocket Upgrade headers и передавайте один перезаписанный `X-Forwarded-For` только от явно доверенных CIDR терминатора. Public ALPN должен предлагать `h2` для `https-lanes` и `http/1.1` для WebSocket Upgrade.

Для WEB-listener задайте `web_client_ip_source = "x_forwarded_for"` и укажите в `web_trusted_proxy_cidrs` только адреса непосредственного HAProxy. Не доверяйте доступной клиентам подсети и не включайте PROXY protocol на этом listener.

Направляйте весь vhost в один процесс Telemt. При совместном размещении по prefix сохраняйте настроенный `base_path` без rewrite; во время миграции направляйте в Telemt старое и новое поддеревья, пока ранее выпущенные процессом credentials ещё могут использоваться. Multi-process backend требует affinity всего vhost для bridge root, создания и восстановления session, uplink, downlink, DELETE, diagnostics и WebSocket Upgrade.

Например, следующий фрагмент HAProxy направляет только точный host и WEB-поддерево с завершающим слешем, не изменяя request target:

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

Обрабатывайте путь без завершающего слеша `/telegram/web` вне этого backend, чтобы frontend не создавал redirect alias в аутентифицированное поддерево. Не добавляйте `set-path`, `replace-path` или path-компонент к адресу backend server. Значения 65 секунд — пример для defaults; client и server timeouts должны быть больше `web.timeouts.long_poll_secs` и удвоенного effective WebSocket liveness interval.

При расчёте capacity учитывайте одновременно публичные TLS sockets и приватные sockets между терминатором и Telemt. Совместно рассчитывайте file descriptors, upstream capacity терминатора, `web.limits.max_http_connections`, handler capacity, параллельные long polls и WebSocket lanes; upstream keepalive pool не является лимитом concurrency.

---
## 5. Диагностика и мониторинг

- **Переполнение listen queues**: проверяйте `ListenOverflows` и `ListenDrops` в `/proc/net/netstat` либо через `nstat`.
- **Conntrack pressure**: проверяйте `nf_conntrack_count`, kernel logs и `telemt_conntrack_control_state{flag="rule_apply_ok"}`; при включённой core telemetry также проверяйте счётчики reconcile/rollback выше.
- **File descriptors**: `cat /proc/sys/fs/file-nr` и лимиты процесса Telemt в `/proc/<pid>/limits`.
- **Состояния соединений**: `ss -s`; избегайте полного сканирования через `netstat` на нагруженном сервере.
- **Rate limiter contention**: при включённой core telemetry настройте alert на положительный прирост или rate counter, например `increase(telemt_rate_limiter_cas_retry_exhausted_total[5m]) > 0`, с группировкой по `scope`, `direction` и `operation`. Reserve exhaustion возвращает нулевой grant без классификации как настроенный throttle; refund exhaustion сохраняет списание. Эта метрика не является ни счётчиком dropped connections, ни счётчиком policy throttling.
- **WEB**: объединяйте telemetry терминатора и внешний TLS probe с `/v1/runtime/web/status`, `telemt_web_tcp_accept_total{result="accepted"|"error"}` и остальными `telemt_web_*` metrics. Request path и `base_path` намеренно не используются как metric labels.
