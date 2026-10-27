# Руководство по тюнингу Telemt: Middle-End и Upstreams

Документ описывает актуальное поведение Middle-End (ME) и маршрутизации через upstream на основе:
- `src/config/types.rs`
- `src/config/defaults.rs`
- `src/config/load.rs`
- `src/transport/upstream.rs`

Значения `Default` ниже — это значения из кода при отсутствии ключа в конфиге, а не обязательно значения из примеров `config.full.toml`.

## Параметры Middle-End

### 1) Базовый режим ME, NAT и STUN

| Параметр | Тип | Default | Ограничения / валидация | Влияние на runtime | Пример |
|---|---|---:|---|---|---|
| `general.use_middle_proxy` | `bool` | `true` | нет | Включает транспорт ME. При `false` используется Direct-режим. | `use_middle_proxy = true` |
| `general.proxy_secret_path` | `Option<String>` | `"proxy-secret"` | путь может быть `null` | Путь к инфраструктурному proxy-secret Telegram. | `proxy_secret_path = "proxy-secret"` |
| `general.middle_proxy_nat_ip` | `Option<IpAddr>` | `null` | валидный IP при задании | Ручной override публичного NAT IP для адресного материала ME. | `middle_proxy_nat_ip = "203.0.113.10"` |
| `general.middle_proxy_nat_probe` | `bool` | `true` | нет | Включает NAT probing, когда одновременно включены ME-режим и `network.stun_use`. | `middle_proxy_nat_probe = true` |
| `general.stun_nat_probe_concurrency` | `usize` | `8` | должно быть `> 0` | Максимум параллельных STUN-проб при NAT-детекте. | `stun_nat_probe_concurrency = 16` |
| `network.stun_use` | `bool` | `true` | нет | Глобальный переключатель STUN. При `false` STUN отключен. | `stun_use = true` |
| `network.stun_servers` | `Vec<String>` | встроенный публичный пул | удаляются дубликаты и пустые значения | Основной список STUN-серверов для NAT/public endpoint discovery. | `stun_servers = ["stun1.l.google.com:19302"]` |
| `network.stun_tcp_fallback` | `bool` | `true` | нет | Включает TCP fallback, если UDP STUN недоступен. | `stun_tcp_fallback = true` |
| `network.http_ip_detect_urls` | `Vec<String>` | `ifconfig.me` + `api.ipify.org` | нет | HTTP fallback для определения публичного IPv4 при недоступности STUN. | `http_ip_detect_urls = ["https://api.ipify.org"]` |
| `general.stun_iface_mismatch_ignore` | `bool` | `false` | нет | Зарезервированный флаг в текущей ревизии (runtime его не использует). | `stun_iface_mismatch_ignore = false` |
| `timeouts.me_one_retry` | `u8` | `12` | нет | Количество быстрых reconnect-попыток для DC с одним endpoint. | `me_one_retry = 6` |
| `timeouts.me_one_timeout_ms` | `u64` | `1200` | нет | Таймаут одной быстрой попытки (мс). | `me_one_timeout_ms = 1500` |

### 2) Размер пула, keepalive и reconnect-политика

| Параметр | Тип | Default | Ограничения / валидация | Влияние на runtime | Пример |
|---|---|---:|---|---|---|
| `general.middle_proxy_pool_size` | `usize` | `8` | нет | Не влияющий на enforcement compatibility/startup-log input; active writer targets определяет DC-family floor policy. | `middle_proxy_pool_size = 12` |
| `general.middle_proxy_warm_standby` | `usize` | `16` | нет | Зарезервированное поле совместимости в текущей ревизии (активного runtime-consumer нет). | `middle_proxy_warm_standby = 16` |
| `general.me_keepalive_enabled` | `bool` | `true` | нет | Включает периодические keepalive/ping кадры ME. | `me_keepalive_enabled = true` |
| `general.me_keepalive_interval_secs` | `u64` | `8` | нет | Базовый интервал keepalive (сек). | `me_keepalive_interval_secs = 20` |
| `general.me_keepalive_jitter_secs` | `u64` | `2` | нет | Джиттер keepalive для предотвращения синхронных всплесков. | `me_keepalive_jitter_secs = 3` |
| `general.me_keepalive_payload_random` | `bool` | `true` | нет | Рандомизирует payload keepalive-кадров. | `me_keepalive_payload_random = true` |
| `general.me_warmup_stagger_enabled` | `bool` | `true` | нет | Включает staggered warmup дополнительных ME-коннектов. | `me_warmup_stagger_enabled = true` |
| `general.me_warmup_step_delay_ms` | `u64` | `500` | нет | Базовая задержка между шагами warmup (мс). | `me_warmup_step_delay_ms = 300` |
| `general.me_warmup_step_jitter_ms` | `u64` | `300` | нет | Дополнительный случайный warmup-джиттер (мс). | `me_warmup_step_jitter_ms = 200` |
| `general.me_reconnect_max_concurrent_per_dc` | `u32` | `8` | нет | Ограничивает параллельные reconnect worker'ы на один DC. | `me_reconnect_max_concurrent_per_dc = 12` |
| `general.me_reconnect_backoff_base_ms` | `u64` | `500` | нет | Начальный backoff reconnect (мс). | `me_reconnect_backoff_base_ms = 250` |
| `general.me_reconnect_backoff_cap_ms` | `u64` | `30000` | нет | Верхняя граница backoff reconnect (мс). | `me_reconnect_backoff_cap_ms = 10000` |
| `general.me_reconnect_fast_retry_count` | `u32` | `16` | нет | Бюджет быстрых retry до длинного backoff. | `me_reconnect_fast_retry_count = 8` |
| `general.me_writer_byte_budget_bytes` | `usize` | `33570816` | кратно `16384`; динамический минимум для `max_client_frame`; максимум `268435456` | Ограниченные byte permits для исходящей staging queue каждого ME writer. | `me_writer_byte_budget_bytes = 33570816` |

### 3) Reinit/hardswap, ротация секрета и деградация

| Параметр | Тип | Default | Ограничения / валидация | Влияние на runtime | Пример |
|---|---|---:|---|---|---|
| `general.hardswap` | `bool` | `true` | нет | Включает generation-based стратегию hardswap для ME-пула. | `hardswap = true` |
| `general.me_reinit_every_secs` | `u64` | `900` | должно быть `> 0` | Интервал периодического reinit ME-пула. | `me_reinit_every_secs = 600` |
| `general.me_reinit_singleflight` | `bool` | `true` | нет | Сериализует reinit cycles из всех trigger sources. | `me_reinit_singleflight = true` |
| `general.me_reinit_max_concurrency` | `usize` | `2` | диапазон `[1,8]`; эффективное значение `1` при singleflight | Ограничивает параллельные generation warmup; дополнительные triggers объединяются в один rerun. | `me_reinit_max_concurrency = 2` |
| `general.me_reinit_trigger_channel` | `usize` | `64` | диапазон `[1,4096]` | Ограничивает очередь reinit triggers в каждом runtime generation. | `me_reinit_trigger_channel = 64` |
| `general.me_reinit_coalesce_window_ms` | `u64` | `200` | нет | Объединяет burst triggers перед одним reinit cycle. | `me_reinit_coalesce_window_ms = 200` |
| `general.me_hardswap_warmup_delay_min_ms` | `u64` | `1000` | должно быть `<= me_hardswap_warmup_delay_max_ms` | Нижняя граница пауз между warmup dial попытками. | `me_hardswap_warmup_delay_min_ms = 500` |
| `general.me_hardswap_warmup_delay_max_ms` | `u64` | `2000` | должно быть `> 0` | Верхняя граница пауз между warmup dial попытками. | `me_hardswap_warmup_delay_max_ms = 1200` |
| `general.me_hardswap_warmup_extra_passes` | `u8` | `3` | диапазон `[0,10]` | Дополнительные warmup-проходы после базового. | `me_hardswap_warmup_extra_passes = 2` |
| `general.me_hardswap_warmup_pass_backoff_base_ms` | `u64` | `500` | должно быть `> 0` | Базовый backoff между extra-pass в warmup. | `me_hardswap_warmup_pass_backoff_base_ms = 400` |
| `general.me_config_stable_snapshots` | `u8` | `2` | должно быть `> 0` | Количество одинаковых snapshot перед применением ME map update. | `me_config_stable_snapshots = 3` |
| `general.me_config_apply_cooldown_secs` | `u64` | `300` | нет | Cooldown между применёнными обновлениями ME map. | `me_config_apply_cooldown_secs = 120` |
| `general.proxy_secret_stable_snapshots` | `u8` | `2` | должно быть `> 0` | Количество одинаковых snapshot перед runtime-rotation proxy-secret. | `proxy_secret_stable_snapshots = 3` |
| `general.proxy_secret_rotate_runtime` | `bool` | `true` | нет | Включает runtime-ротацию proxy-secret. | `proxy_secret_rotate_runtime = true` |
| `general.proxy_secret_len_max` | `usize` | `256` | диапазон `[32,4096]` | Верхний лимит длины принимаемого proxy-secret. | `proxy_secret_len_max = 512` |
| `general.update_every` | `Option<u64>` | `300` | если задано: `> 0`; если `null`: fallback на legacy минимум | Единый интервал refresh для ME config + secret updater. | `update_every = 300` |
| `general.me_pool_drain_ttl_secs` | `u64` | `90` | нет | Возрастной порог предупреждений о долгом drain и нижняя граница нормализации force-close timeout; stale binds он не разрешает. | `me_pool_drain_ttl_secs = 120` |
| `general.me_bind_stale_mode` | `"never"`, `"ttl"` или `"always"` | `"never"` | нет | Управляет новыми bindings на draining stale writers для непокрытых DC-family groups. | `me_bind_stale_mode = "never"` |
| `general.me_bind_stale_ttl_secs` | `u64` | `90` | нет | Окно stale-bind только для `me_bind_stale_mode = "ttl"`; `0` отключает TTL expiry для разрешённых draining writers. | `me_bind_stale_ttl_secs = 90` |
| `general.me_pool_min_fresh_ratio` | `f32` | `0.8` | диапазон `[0.0,1.0]` | Минимальная доля fresh DC-family coverage при commit. | `me_pool_min_fresh_ratio = 0.9` |
| `general.me_reinit_drain_timeout_secs` | `u64` | `90` | `0` использует safety fallback 300 секунд; effective value ниже drain TTL повышается до TTL | Таймаут force-close для draining stale writer. | `me_reinit_drain_timeout_secs = 0` |
| `general.auto_degradation_enabled` | `bool` | `true` | нет | Зарезервированный флаг совместимости в текущей ревизии (активного runtime-consumer нет). | `auto_degradation_enabled = true` |
| `general.degradation_min_unavailable_dc_groups` | `u8` | `2` | нет | Зарезервированный порог совместимости в текущей ревизии (активного runtime-consumer нет). | `degradation_min_unavailable_dc_groups = 2` |

Candidate generation hardswap авторитетна только для того же desired-map hash и endpoint revision. Повторные попытки переиспользуют pending generation не более 1800 секунд; после TTL создаётся новая generation. Commit повторно проверяет authority и требует fresh DC-family coverage не ниже `me_pool_min_fresh_ratio`. Отсутствующие groups блокируют commit при `me_bind_stale_mode = "never"`; `ttl` или `always` позволяют commit с ограниченным policy stale fallback для этих groups. Покрытые старые writers могут сразу перейти в retirement, поэтому hardswap является атомарной сменой policy, а не универсальной zero-drop гарантией.

Writer replacement использует отдельное cancellation-safe состояние `Open -> Preparing -> Retiring`. `Preparing` запрещает дублирующую replacement work, но разрешает новые binds. Под registry binding guard commit повторно проверяет victim, переводит его в `Retiring`, чтобы запретить новые binds, устанавливает и публикует successor и начинает drain predecessor до освобождения guard. Отмена reservation до этой commit boundary возвращает `Open`.

Возраст pending generation, число и дефицит writers, отсутствующие DC groups, актуальность map, orphan warm writers и фазы `preparing`/`retiring` доступны через `/v1/runtime/me_pool_state`. Соответствующие gauges `telemt_me_hardswap_*` и `telemt_me_writer_replacement_current` равны нулю, когда ME telemetry имеет уровень `silent` или активный ME snapshot недоступен. В Prometheus `telemt_me_hardswap_pending_map_current` следует проверять вместе с `telemt_me_hardswap_pending`: нулевая map currency также означает отсутствие pending generation, тогда как API возвращает `null`. Настройте alerts на pending age около 1800 секунд, устойчивый deficit или missing groups, stale map, orphan warm writers и не сходящиеся replacement phases.

## Устаревшие / legacy параметры

| Параметр | Статус | Замена | Текущее поведение | Рекомендация миграции |
|---|---|---|---|---|
| `general.middle_proxy_nat_stun` | Deprecated | `network.stun_servers` | Добавляется в `network.stun_servers`, только если `network.stun_servers` не задан явно. | Перенести значение в `network.stun_servers`, legacy-ключ удалить. |
| `general.middle_proxy_nat_stun_servers` | Deprecated | `network.stun_servers` | Добавляется в `network.stun_servers`, только если `network.stun_servers` не задан явно. | Перенести значения в `network.stun_servers`, legacy-ключ удалить. |
| `general.proxy_secret_auto_reload_secs` | Deprecated | `general.update_every` | Используется только если `update_every = null` (legacy fallback). | Явно задать `general.update_every`, legacy-ключ удалить. |
| `general.proxy_config_auto_reload_secs` | Deprecated | `general.update_every` | Используется только если `update_every = null` (legacy fallback). | Явно задать `general.update_every`, legacy-ключ удалить. |

## Как конфигурируются Upstreams

### Схема upstream

| Поле | Применимость | Тип | Обязательно | Default | Назначение |
|---|---|---|---|---|---|
| `[[upstreams]].type` | все upstream | `"direct" \| "socks4" \| "socks5" \| "shadowsocks"` | да | n/a | Тип upstream транспорта. |
| `[[upstreams]].weight` | все upstream | `u16` | нет | `1` | Базовый вес в weighted-random выборе. |
| `[[upstreams]].enabled` | все upstream | `bool` | нет | `true` | Выключенные записи игнорируются на старте. |
| `[[upstreams]].scopes` | все upstream | `String` | нет | `""` | Список scope-токенов через запятую для маршрутизации. |
| `[[upstreams]].ipv4` | все upstream | `Option<bool>` | нет | `auto` | Разрешает IPv4 DC-targets для этого upstream. |
| `[[upstreams]].ipv6` | все upstream | `Option<bool>` | нет | `auto` | Разрешает IPv6 DC-targets для этого upstream, включая proxy egress независимо от IPv6 на хосте. |
| `[[upstreams]].prefer` | все upstream | `Option<4 \| 6>` | нет | эффективный `[network].prefer` | Предпочтительное семейство DC-target для конкретного upstream. |
| `interface` | `direct` | `Option<String>` | нет | `null` | Имя интерфейса (например `eth0`) или literal локальный IP. |
| `bind_addresses` | `direct` | `Option<Vec<IpAddr>>` | нет | `null` | Явные кандидаты source IP (имеют приоритет над `interface`). |
| `address` | `socks4` | `String` | да | n/a | Адрес SOCKS4 сервера (`ip:port` или `host:port`). |
| `interface` | `socks4` | `Option<String>` | нет | `null` | Используется только если `address` задан как `ip:port`. |
| `user_id` | `socks4` | `Option<String>` | нет | `null` | SOCKS4 user ID в CONNECT-запросе. |
| `address` | `socks5` | `String` | да | n/a | Адрес SOCKS5 сервера (`ip:port` или `host:port`). |
| `interface` | `socks5` | `Option<String>` | нет | `null` | Используется только если `address` задан как `ip:port`. |
| `username` | `socks5` | `Option<String>` | нет | `null` | Логин SOCKS5 auth. |
| `password` | `socks5` | `Option<String>` | нет | `null` | Пароль SOCKS5 auth. |
| `url` | `shadowsocks` | `String` | да | n/a | Shadowsocks SIP002 URL (`ss://...`). В runtime API раскрывается только `host:port`. |
| `interface` | `shadowsocks` | `Option<String>` | нет | `null` | Необязательный исходящий bind-интерфейс или literal локальный IP. |

### Runtime-правила

1. Если `[[upstreams]]` отсутствует, loader добавляет один upstream `direct` по умолчанию.
2. Scope-фильтрация — по точному совпадению токена:
- если scope запроса задан -> используются только записи, где `scopes` содержит такой же токен;
- если scope запроса не задан -> используются только записи с пустым `scopes`.
3. Среди healthy upstream используется weighted-random выбор: `weight * latency_factor`.
4. Если в отфильтрованном наборе нет healthy upstream, выбирается случайный из отфильтрованных.
5. Порядок выбора bind для `direct`:
- сначала `bind_addresses` (только IP нужного семейства);
- если одновременно заданы `interface` (имя) и `bind_addresses`, каждый IP проверяется на принадлежность интерфейсу;
- несовпадающие IP отбрасываются с `WARN`;
- если непустой список `bind_addresses` не оставляет валидного candidate нужного семейства, connection завершается fail-closed с configuration error;
- только при отсутствующем или пустом `bind_addresses` применяется `interface` (literal IP или адрес интерфейса); если он также не даёт адрес, direct connect остаётся unbound.
6. Для `socks4/socks5` с `address` в виде hostname интерфейсный bind не поддерживается и игнорируется с предупреждением.
7. Runtime DNS overrides применяются к резолвингу hostname в upstream-подключениях.
8. В ME-режиме выбранный upstream также используется для ME TCP dial path.
9. В ME-режиме для `direct` upstream с bind/interface STUN-рефлексия выполняется bind-aware для KDF материала.
10. В ME-режиме через SOCKS корректные публичные `BND.ADDR/BND.PORT` с ненулевым портом задают полный исходный кортеж KDF. Семейство адреса должно совпадать с логическим ME-назначением независимо от семейства TCP-соединения к SOCKS. Для IPv4-mapped назначения нужен обычный IPv4 BND; IPv4-compatible IPv6 остаётся IPv6.
11. `shadowsocks` upstream требует `general.use_middle_proxy = false`. При включенном ME-режиме конфиг отклоняется при загрузке.

## Примеры конфигурации Upstreams

### Пример 1: минимальный direct upstream

```toml
[[upstreams]]
type = "direct"
weight = 1
enabled = true
```

### Пример 2: direct с interface + явными bind IP

```toml
[[upstreams]]
type = "direct"
interface = "eth0"
bind_addresses = ["192.168.1.100", "192.168.1.101"]
weight = 3
enabled = true
```

### Пример 3: SOCKS5 upstream с аутентификацией

```toml
[[upstreams]]
type = "socks5"
address = "198.51.100.30:1080"
username = "proxy-user"
password = "proxy-pass"
weight = 2
enabled = true
```

### Пример 4: Shadowsocks upstream

```toml
[general]
use_middle_proxy = false

[[upstreams]]
type = "shadowsocks"
url = "ss://2022-blake3-aes-256-gcm:BASE64_KEY@198.51.100.50:8388"
weight = 2
enabled = true
```

### Пример 5: смешанные upstream с scopes

```toml
[[upstreams]]
type = "direct"
weight = 5
enabled = true
scopes = ""

[[upstreams]]
type = "socks5"
address = "203.0.113.40:1080"
username = "edge"
password = "edgepass"
weight = 3
enabled = true
scopes = "premium,me"
```

### Пример 5: профиль тюнинга под ME

```toml
[general]
use_middle_proxy = true
proxy_secret_path = "proxy-secret"
middle_proxy_nat_probe = true
stun_nat_probe_concurrency = 16
me_keepalive_enabled = true
me_keepalive_interval_secs = 20
me_keepalive_jitter_secs = 4
me_reconnect_max_concurrent_per_dc = 12
me_reconnect_backoff_base_ms = 300
me_reconnect_backoff_cap_ms = 10000
me_reconnect_fast_retry_count = 10
hardswap = true
me_reinit_every_secs = 600
me_reinit_singleflight = true
me_reinit_max_concurrency = 2
me_reinit_trigger_channel = 64
me_reinit_coalesce_window_ms = 200
me_hardswap_warmup_delay_min_ms = 500
me_hardswap_warmup_delay_max_ms = 1200
me_hardswap_warmup_extra_passes = 2
me_hardswap_warmup_pass_backoff_base_ms = 400
me_config_stable_snapshots = 3
me_config_apply_cooldown_secs = 120
proxy_secret_stable_snapshots = 3
proxy_secret_rotate_runtime = true
proxy_secret_len_max = 512
update_every = 300
me_pool_drain_ttl_secs = 120
me_bind_stale_mode = "never"
me_bind_stale_ttl_secs = 90
me_pool_min_fresh_ratio = 0.9
me_reinit_drain_timeout_secs = 180

[timeouts]
me_one_retry = 8
me_one_timeout_ms = 1200

[network]
stun_use = true
stun_tcp_fallback = true
stun_servers = [
  "stun1.l.google.com:19302",
  "stun2.l.google.com:19302"
]
http_ip_detect_urls = [
  "https://api.ipify.org",
  "https://ifconfig.me/ip"
]
```
