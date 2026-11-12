# Руководство по тюнингу Telemt: Middle-End и Upstreams

[English](TUNING.en.md) · [Русский](TUNING.ru.md) · [Deutsch](TUNING.de.md) · [EN / RU / DE terminology](../TERMINOLOGY.md)

Документ описывает актуальное поведение Middle-End (ME) и маршрутизации через upstream на основе:
- `src/config/types.rs`
- `src/config/defaults.rs`
- `src/config/load.rs`
- `src/transport/upstream.rs`

Значения `По умолчанию` ниже — это значения из кода при отсутствии ключа в конфиге, а не обязательно значения из примеров `config.full.toml`.

`Option<T>` и `null` в столбцах типов и значений по умолчанию обозначают необязательные внутренние значения. В TOML нет литерала `null`. Для старых интервалов обновления не задавайте `general.update_every` и явно укажите старые ключи; в остальных случаях общий интервал по умолчанию равен 300 секундам. Значения null в полях объекта PATCH конфигурации игнорируются и не удаляют настройки.

## Параметры Middle-End

### 1) Базовый режим ME, NAT и STUN

| Параметр | Тип | По умолчанию | Ограничения / валидация | Влияние на работу | Пример |
|---|---|---:|---|---|---|
| `general.use_middle_proxy` | `bool` | `true` | нет | Включает транспорт ME. При `false` используется Direct-режим. | `use_middle_proxy = true` |
| `general.proxy_secret_path` | `Option<String>` | `"proxy-secret"` | необязательный путь; в TOML нет `null` | Путь к инфраструктурному proxy-secret Telegram. | `proxy_secret_path = "proxy-secret"` |
| `general.middle_proxy_nat_ip` | `Option<IpAddr>` | `null` | валидный IP при задании | Явный публичный IP за NAT для вычисления адресной части ключей ME. | `middle_proxy_nat_ip = "203.0.113.10"` |
| `general.middle_proxy_nat_probe` | `bool` | `true` | нет | Проверяет внешний адрес за NAT, если включены ME и `network.stun_use`. | `middle_proxy_nat_probe = true` |
| `general.stun_nat_probe_concurrency` | `usize` | `8` | должно быть `> 0` | Максимум параллельных STUN-проб при NAT-детекте. | `stun_nat_probe_concurrency = 16` |
| `network.stun_use` | `bool` | `true` | нет | Глобальный переключатель STUN. При `false` STUN отключен. | `stun_use = true` |
| `network.stun_servers` | `Vec<String>` | встроенный публичный пул | удаляются дубликаты и пустые значения | Основной список STUN-серверов для определения внешнего адреса и порта за NAT. | `stun_servers = ["stun1.l.google.com:19302"]` |
| `network.stun_tcp_fallback` | `bool` | `true` | нет | Разрешает резервную проверку по TCP, когда STUN по UDP недоступен. | `stun_tcp_fallback = true` |
| `network.http_ip_detect_urls` | `Vec<String>` | `ifconfig.me` + `api.ipify.org` | нет | Резервные HTTP-сервисы для определения публичного IPv4 при недоступности STUN. | `http_ip_detect_urls = ["https://api.ipify.org"]` |
| `general.stun_iface_mismatch_ignore` | `bool` | `false` | нет | Зарезервированный флаг; в текущей ревизии не влияет на работу. | `stun_iface_mismatch_ignore = false` |
| `timeouts.me_one_retry` | `u8` | `12` | нет | Число быстрых повторных подключений для DC с одним адресом подключения. | `me_one_retry = 6` |
| `timeouts.me_one_timeout_ms` | `u64` | `1200` | нет | Таймаут одной быстрой попытки (мс). | `me_one_timeout_ms = 1500` |

### 2) Размер пула, keepalive и reconnect-политика

| Параметр | Тип | По умолчанию | Ограничения / валидация | Влияние на работу | Пример |
|---|---|---:|---|---|---|
| `general.middle_proxy_pool_size` | `usize` | `8` | нет | Поле совместимости и стартового журнала. Целевое число активных ME Writer задаёт политика минимального покрытия групп «DC + семейство IP». | `middle_proxy_pool_size = 12` |
| `general.middle_proxy_warm_standby` | `usize` | `16` | нет | Поле совместимости; в текущей ревизии не влияет на работу. | `middle_proxy_warm_standby = 16` |
| `general.me_keepalive_enabled` | `bool` | `true` | нет | Включает периодические keepalive/ping кадры ME. | `me_keepalive_enabled = true` |
| `general.me_keepalive_interval_secs` | `u64` | `8` | нет | Базовый интервал keepalive (сек). | `me_keepalive_interval_secs = 20` |
| `general.me_keepalive_jitter_secs` | `u64` | `2` | нет | Джиттер keepalive для предотвращения синхронных всплесков. | `me_keepalive_jitter_secs = 3` |
| `general.me_keepalive_payload_random` | `bool` | `true` | нет | Добавляет случайные данные в полезную нагрузку кадров keepalive. | `me_keepalive_payload_random = true` |
| `general.me_warmup_stagger_enabled` | `bool` | `true` | нет | Готовит дополнительные ME-соединения постепенно. | `me_warmup_stagger_enabled = true` |
| `general.me_warmup_step_delay_ms` | `u64` | `500` | нет | Базовая задержка между шагами подготовки соединений, мс. | `me_warmup_step_delay_ms = 300` |
| `general.me_warmup_step_jitter_ms` | `u64` | `300` | нет | Дополнительный случайный разброс задержки при подготовке соединений, мс. | `me_warmup_step_jitter_ms = 200` |
| `general.me_reconnect_max_concurrent_per_dc` | `u32` | `8` | нет | Ограничивает число параллельных задач повторного подключения для одного DC. | `me_reconnect_max_concurrent_per_dc = 12` |
| `general.me_reconnect_backoff_base_ms` | `u64` | `500` | нет | Начальная задержка перед повторным подключением, мс. | `me_reconnect_backoff_base_ms = 250` |
| `general.me_reconnect_backoff_cap_ms` | `u64` | `30000` | нет | Верхняя граница задержки перед повторным подключением, мс. | `me_reconnect_backoff_cap_ms = 10000` |
| `general.me_reconnect_fast_retry_count` | `u32` | `16` | нет | Число быстрых повторных попыток до перехода к увеличенным задержкам. | `me_reconnect_fast_retry_count = 8` |
| `general.me_writer_byte_budget_bytes` | `usize` | `33570816` | кратно `16384`; динамический минимум для `max_client_frame`; максимум `268435456` | Лимит байтов, зарезервированных для исходящей очереди каждого ME Writer. | `me_writer_byte_budget_bytes = 33570816` |

### 3) Reinit/hardswap, ротация секрета и деградация

| Параметр | Тип | По умолчанию | Ограничения / валидация | Влияние на работу | Пример |
|---|---|---:|---|---|---|
| `general.hardswap` | `bool` | `true` | нет | Включает смену поколений пула ME по стратегии hardswap. | `hardswap = true` |
| `general.me_reinit_every_secs` | `u64` | `900` | должно быть `> 0` | Интервал периодической переинициализации пула ME. | `me_reinit_every_secs = 600` |
| `general.me_reinit_singleflight` | `bool` | `true` | нет | Выполняет переинициализации последовательно независимо от источника запроса. | `me_reinit_singleflight = true` |
| `general.me_reinit_max_concurrency` | `usize` | `2` | диапазон `[1,8]`; эффективное значение `1` при singleflight | Ограничивает параллельную подготовку поколений; дополнительные запросы объединяются в один повторный запуск. | `me_reinit_max_concurrency = 2` |
| `general.me_reinit_trigger_channel` | `usize` | `64` | диапазон `[1,4096]` | Ограничивает очередь запросов переинициализации в каждом поколении. | `me_reinit_trigger_channel = 64` |
| `general.me_reinit_coalesce_window_ms` | `u64` | `200` | нет | Объединяет всплеск запросов в один цикл переинициализации. | `me_reinit_coalesce_window_ms = 200` |
| `general.me_hardswap_warmup_delay_min_ms` | `u64` | `1000` | должно быть `<= me_hardswap_warmup_delay_max_ms` | Нижняя граница паузы между попытками подключения при подготовке поколения. | `me_hardswap_warmup_delay_min_ms = 500` |
| `general.me_hardswap_warmup_delay_max_ms` | `u64` | `2000` | должно быть `> 0` | Верхняя граница паузы между попытками подключения при подготовке поколения. | `me_hardswap_warmup_delay_max_ms = 1200` |
| `general.me_hardswap_warmup_extra_passes` | `u8` | `3` | диапазон `[0,10]` | Число дополнительных проходов подготовки после основного. | `me_hardswap_warmup_extra_passes = 2` |
| `general.me_hardswap_warmup_pass_backoff_base_ms` | `u64` | `500` | должно быть `> 0` | Базовая задержка между дополнительными проходами подготовки. | `me_hardswap_warmup_pass_backoff_base_ms = 400` |
| `general.me_config_stable_snapshots` | `u8` | `2` | должно быть `> 0` | Число одинаковых снимков карты ME, необходимых перед её обновлением. | `me_config_stable_snapshots = 3` |
| `general.me_config_apply_cooldown_secs` | `u64` | `300` | нет | Минимальная пауза между применёнными обновлениями карты ME. | `me_config_apply_cooldown_secs = 120` |
| `general.proxy_secret_stable_snapshots` | `u8` | `2` | должно быть `> 0` | Число одинаковых снимков секрета перед его заменой во время работы. | `proxy_secret_stable_snapshots = 3` |
| `general.proxy_secret_rotate_runtime` | `bool` | `true` | нет | Разрешает замену инфраструктурного секрета без перезапуска процесса. | `proxy_secret_rotate_runtime = true` |
| `general.proxy_secret_len_max` | `usize` | `256` | диапазон `[32,4096]` | Верхний лимит длины принимаемого proxy-secret. | `proxy_secret_len_max = 512` |
| `general.update_every` | `Option<u64>` | `300` | если задано: `> 0`; при отсутствии с явно заданными старыми ключами — их минимум | Общий интервал обновления карты ME и инфраструктурного секрета. | `update_every = 300` |
| `general.me_pool_drain_ttl_secs` | `u64` | `90` | нет | Порог предупреждения о долгом завершении обслуживания и нижняя граница таймаута принудительного закрытия. Не разрешает новые привязки к старым соединениям. | `me_pool_drain_ttl_secs = 120` |
| `general.me_bind_stale_mode` | `"never"`, `"ttl"` или `"always"` | `"never"` | нет | Разрешает или запрещает новые привязки к старым ME Writer для групп «DC + семейство IP», не обеспеченных новым поколением. | `me_bind_stale_mode = "never"` |
| `general.me_bind_stale_ttl_secs` | `u64` | `90` | нет | Срок допуска старых соединений только для режима `ttl`; `0` отключает истечение этого срока для разрешённых ME Writer. | `me_bind_stale_ttl_secs = 90` |
| `general.me_pool_min_fresh_ratio` | `f32` | `0.8` | диапазон `[0.0,1.0]` | Минимальная доля групп «DC + семейство IP», обеспеченных новым поколением перед переходом. | `me_pool_min_fresh_ratio = 0.9` |
| `general.me_reinit_drain_timeout_secs` | `u64` | `90` | `0` означает резервный срок 300 секунд; значение ниже срока drain повышается до него | Срок до принудительного закрытия старых ME Writer, завершающих обслуживание. | `me_reinit_drain_timeout_secs = 0` |
| `general.auto_degradation_enabled` | `bool` | `true` | нет | Флаг совместимости; в текущей ревизии не влияет на работу. | `auto_degradation_enabled = true` |
| `general.degradation_min_unavailable_dc_groups` | `u8` | `2` | нет | Порог совместимости; в текущей ревизии не влияет на работу. | `degradation_min_unavailable_dc_groups = 2` |

Подготовленное для hardswap поколение можно применить только при неизменных хеше требуемой карты ME и ревизии адресов подключения. При повторных попытках оно используется не дольше 1800 секунд, после чего создаётся новое. Перед фиксацией перехода Telemt заново проверяет эти условия и долю групп «DC + семейство IP», обеспеченных новыми соединениями: она должна быть не ниже `me_pool_min_fresh_ratio`. При `me_bind_stale_mode = "never"` отсутствие любой группы блокирует переход. Режимы `ttl` и `always` допускают для таких групп резервное использование старых соединений в пределах выбранной политики. Старые ME Writer для уже обеспеченных групп могут сразу выводиться из обслуживания. Поэтому атомарность смены политики не означает, что hardswap гарантированно сохранит все соединения.

Замена отдельного ME Writer использует состояния `Open -> Preparing -> Retiring` и корректно обрабатывает отмену операции. В `Preparing` нельзя запустить вторую замену того же компонента, но можно привязывать к нему новые потоки. При фиксации замены Telemt под блокировкой реестра привязок заново проверяет заменяемый ME Writer, переводит его в `Retiring`, запрещая новые привязки, устанавливает и публикует замену и начинает завершение обслуживания прежнего компонента. Только после этого блокировка снимается. Отмена резервирования до этой границы возвращает состояние `Open`.

Эндпоинт `/v1/runtime/me_pool_state` показывает возраст ожидающего поколения, число и дефицит ME Writer, отсутствующие группы DC, актуальность карты, подготовленные соединения без владельца и фазы `preparing`/`retiring`. Метрики `telemt_me_hardswap_*` и `telemt_me_writer_replacement_current` равны нулю при уровне ME-телеметрии `silent` или отсутствии активного снимка состояния. Проверяйте `telemt_me_hardswap_pending_map_current` вместе с `telemt_me_hardswap_pending`: ноль может означать отсутствие ожидающего поколения, а не устаревшую карту. В таком случае API возвращает `null`. Настройте оповещения при возрасте ожидающего поколения около 1800 секунд, устойчивом дефиците соединений или групп, устаревшей карте, подготовленных соединениях без владельца и затянувшихся фазах замены.

## Устаревшие параметры

| Параметр | Статус | Замена | Текущее поведение | Рекомендация миграции |
|---|---|---|---|---|
| `general.middle_proxy_nat_stun` | Устарел | `network.stun_servers` | Добавляется в `network.stun_servers`, только если `network.stun_servers` не задан явно. | Перенести значение в `network.stun_servers`, старый ключ удалить. |
| `general.middle_proxy_nat_stun_servers` | Устарел | `network.stun_servers` | Добавляется в `network.stun_servers`, только если `network.stun_servers` не задан явно. | Перенести значения в `network.stun_servers`, старый ключ удалить. |
| `general.proxy_secret_auto_reload_secs` | Устарел | `general.update_every` | Используется, если `update_every` отсутствует, а старые интервалы заданы явно. | Явно задать `general.update_every`, старый ключ удалить. |
| `general.proxy_config_auto_reload_secs` | Устарел | `general.update_every` | Используется, если `update_every` отсутствует, а старые интервалы заданы явно. | Явно задать `general.update_every`, старый ключ удалить. |

## Как конфигурируются Upstreams

### Схема upstream

| Поле | Применимость | Тип | Обязательно | По умолчанию | Назначение |
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

### Правила выбора соединения

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

## Примеры настройки апстримов

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

### Выбор апстрима по имени пользователя

В Direct-режиме пользователь `scope_premium` выбирает точный scope `premium`. Часть имени после `scope_` должна содержать 1–64 латинские буквы ASCII, цифры или дефисы. Пустой или некорректный суффикс включает обычный выбор без scope. Если корректный scope задан, но подходящего апстрима нет, соединение завершается ошибкой; перехода на маршрут без scope не происходит. Метки scope не создают пользователей и не заменяют аутентификацию.

При выборе scope его строка подставляется вместо `user_id` SOCKS4 и вместо имени и пароля SOCKS5. В этом примере SOCKS5-сервер должен принимать `premium` и как имя, и как пароль. Обычные пользователи выбирают прямой маршрут без scope. Перед использованием замените секрет и адрес SOCKS-сервера.

```toml
[general]
use_middle_proxy = false

[access.users]
scope_premium = "0123456789abcdef0123456789abcdef"

[[upstreams]]
type = "direct"
scopes = ""

[[upstreams]]
type = "socks5"
address = "203.0.113.40:1080"
username = "premium"
password = "premium"
scopes = "premium"
```

Этот механизм выбора по пользователю действует в Direct-режиме. При подключении ME пользовательский scope сейчас не передаётся: метка `me` сама по себе не выбирает апстрим ME. Для получения TLS-профилей применяется отдельная настройка `censorship.tls_fetch_scope`. См. [правила фильтрации](../Config_params/CONFIG_PARAMS.ru.md#scopes).


### Пример 6: профиль настройки ME

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
