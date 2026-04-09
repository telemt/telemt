# Руководство по High-Load конфигурации и тюнингу
При развертывании Telemt под высокой нагрузкой (десятки и сотни тысяч одновременных подключений), стандартные ограничения сетевого стека ОС могут приводить к потерям пакетов, переключениям контекста CPU и отказам в соединениях. В данном руководстве описана настройка ядра Linux, системных лимитов и аппаратной конфигурации для работы в подобных сценариях.

---
## 1. Системные лимиты и файловые дескрипторы
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
По умолчанию Linux держит "оборванные" TCP-сессии более 2 часов. Задайте параметры для обнаружения и сброса мертвых соединений за менее чем 5 минут:
```ini
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
```
### 2.4 Буферы TCP и управление перегрузками (Congestion Control)
Оптимизируйте использование памяти на сокет и переключитесь на алгоритм BBR (Bottleneck Bandwidth and Round-trip propagation time) для улучшения задержки на плохих сетях:
```ini
# Размеры буферов ядра (по умолчанию и макс)
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
# Специфичные TCP буферы (min, default, max)
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
# Включение BBR
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
net.netfilter.nf_conntrack_max = 2097152
# Снижаем таймаут с дефолтных 5 дней до 1 часа
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 12
```
*Внимание: в зависимости от ОС, вам может потребоваться выполнить `modprobe nf_conntrack` перед установкой этих параметров.*

---
## 4. Архитектура: Развертывание за HAProxy
Для максимальных нагрузок выставление Telemt напрямую в интернет менее эффективно, чем использование оптимизированного L4-балансировщика. HAProxy эффективен в поглощении TCP атак, обработке рукопожатий и сглаживании всплесков подключений.
### Оптимизация `haproxy.cfg` для High-Load
```haproxy
global
    # Отключить детальные логи соединений под нагрузкой
    log stdout format raw local0 err
    maxconn 250000
    # Тюнинг буферов и приема сокетов
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
    # Быстрая очистка мертвых пиров
    timeout client-fin 10s
    timeout server-fin 10s
frontend proxy_in
    bind *:443
    maxconn 250000
    option tcp-smart-accept
    default_backend telemt_backend
backend telemt_backend
    option tcp-smart-connect
    # Send-Proxy-V2 обязателен для сохранения IP клиента внутри внутренней логики Telemt
    server telemt_core 10.10.10.1:443 maxconn 250000 send-proxy-v2 check inter 5s
```
**Важно**: Telemt должен быть настроен на обработку протокола `PROXY` на порту `443`, чтобы получать оригинальные IP-адреса клиентов.

---
## 5. Диагностика
Команды для выявления узких мест:
* **Проверка дропов TCP (переполнение очередей)**: `netstat -s | grep "times the listen queue of a socket overflowed"`
* **Контроль отбрасывания пакетов Conntrack**: `dmesg | grep conntrack`
* **Проверка использования файловых дескрипторов**: `cat /proc/sys/fs/file-nr`
* **Отображение состояния сокетов**: `ss -s` (Избегайте использования `netstat` под высокой нагрузкой).
