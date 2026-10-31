# WEB-режим прокси

[English](WEB_PROXY.en.md) | [Русский](WEB_PROXY.ru.md) | [Deutsch](WEB_PROXY.de.md)

[Ping в списке прокси, RPC Ping/Pong и задержки WEB](PROXY_PING.ru.md)

WEB-режим переносит обычные MTProxy-потоки через bounded HTTPS или WebSocket carriers, совместимые с типом прокси `WEB` в Telegram Desktop. Telemt не терминирует TLS: публичный сертификат обслуживает NGINX, HAProxy или Caddy, который передаёт обычный HTTP/1.1 на приватный listener Telemt.

> [!IMPORTANT]
>
> WEB-режим реализован и настраивается в текущем дереве исходного кода. Для первого развёртывания нужен бинарный файл, собранный из ревизии с этой реализацией, и перезапуск процесса Telemt. Готовый пакет можно использовать только после проверки, что он содержит эту ревизию. Сквозная проверка с целевой сборкой Telegram Desktop и реальным публичным TLS endpoint остаётся обязательным приёмочным шагом оператора.

## Путь трафика

```text
Telegram Desktop
    | HTTPS или WSS :443
    v
NGINX, HAProxy или Caddy (TLS termination, канонический Host и один адрес X-Forwarded-For)
    | обычный HTTP/1.1 в приватной сети
    v
WEB-listener Telemt
    |-- аутентифицированный carrier --> bounded logical MTProxy relays --> Telegram
    `-- обычный или некорректный запрос --> настроенный decoy site
```

Направляйте в Telemt всю настроенную WEB-область. При пустом `base_path` по умолчанию это весь публичный vhost, а при непустом — точное поддерево с завершающим слешем. Если TLS-терминатор будет выделять внутри этой области только известные carrier endpoints, поведение обычных и аутентифицированных запросов станет наблюдаемо различным, а decoy policy Telemt будет обойдена.

Обозначим через `BASE` значение `/` при пустом `base_path` или `/<base_path>/` в остальных случаях. Публичные WEB-маршруты задаются относительно этого точного base:

| Метод | Путь | Назначение |
| --- | --- | --- |
| `GET` | `BASE?bridge=<capability>` | Исходный bridge document или recovery representation при наличии recovery-заголовка `Accept` и необязательного bearer. |
| `POST`, `DELETE` | `BASEapi/v1/session` | Создание или закрытие parent session. |
| `POST` | `BASEapi/v1/up` | Uplink HTTPS carrier. |
| `POST` | `BASEapi/v1/down` | Downlink HTTPS carrier. |
| `GET` | `BASEapi/v1/ws` | WebSocket Upgrade. |

`POST BASEapi/v1/diagnostic` — внутренний sideband-маршрут сгенерированного bridge, а не публичный client API. Сопоставление путей регистрозависимо и побайтно точно: нет aliases, вариантов с лишним или percent-encoded слешем и query parameters у carrier endpoints. Запрос неправильной формы с capability или bearer, аутентифицированным текущим процессом, получает локальный не кэшируемый `404`; несовпавший запрос без подлинного carrier material следует в настроенный decoy. `base_path` меняет только эти маршруты WEB-listener. Он не добавляется к Control API, `/web-status` или Prometheus metrics.

## Поддерживаемый контракт клиента

- При пустом `base_path` публичный endpoint имеет вид `https://HOST:443/`, иначе — `https://HOST:443/BASE/`. Base path регистрозависим и проверяется точно; Telemt не перенаправляет, не нормализует и не удаляет его перед отправкой в decoy.
- Поддерживаются 16-байтовые MTProxy-секреты `plain` и `dd`. FakeTLS-секреты `ee` в WEB-режиме не поддерживаются.
- `web.carrier` выбирает единственный carrier при выключенном auto-negotiation и последний fallback при включённом. `https` использует общую последовательность HTTPS uplink и long polling. `https-lanes` использует независимые HTTPS sequencing и polling для каждого logical stream. `websocket` использует один упорядоченный WebSocket для всех streams. `websocket-lanes` использует отдельный WebSocket с независимым ownership для каждого ненулевого logical stream.
- Отсутствующий `web.carriers` или `web.carriers = false` отключает auto-negotiation и обучение. Непустой массив включает только стартовый последовательный перебор; уже committed session никогда не мигрирует.
- Нативные клиенты без канонических headers carrier negotiation используют настроенный фиксированный `carrier`, даже когда `carriers` включает negotiation для поддерживающих его клиентов. Текущий Telegram iOS поддерживает только `https`, поэтому для metadata-free iOS оператор должен задать `web.carrier = "https"`; `https-lanes` этим клиентом не поддерживается. User-Agent, включая CFNetwork или Darwin, никогда не выводит capabilities неявно. Если нативный iOS всё же отправляет явные negotiation metadata, Telemt пересекает их с server-authoritative ceiling `{https}` и отклоняет пустой результат; остальные явные клиенты используют заявленный capability set.
- Capability, bootstrap и session credentials — отдельные значения с ограниченным сроком жизни. Carrier credentials считаются секретами и не должны попадать в access logs.
- Bootstrap является bearer credential, а не token с привязкой к source address. Адрес клиента и его IP-семейство могут измениться между загрузкой bridge и созданием session. Адрес выдачи продолжает учитываться в лимите неиспользованных bootstrap, а владельцем session становится адрес первого корректного запроса создания.
- Внутренняя MTProxy-аутентификация ограничена пользователем и режимом секрета, выбранными профилем vhost. Некорректный внутренний handshake закрывает только свой logical stream и никогда не попадает в TCP masking path.

В WEB-ссылках Telegram Desktop нет порта, потому что клиент требует порт 443:

```text
tg://webproxy?server=proxy.example.com&secret=0123456789abcdef0123456789abcdef
tg://webproxy?server=proxy.example.com&secret=dd0123456789abcdef0123456789abcdef
tg://webproxy?server=proxy.example.com%2Ftelegram%2Fweb&secret=cAABAgMEBQYHCAkKCwwNDg8
```

При запуске процесса Telemt печатает ссылки для WEB-профилей, выбранных в `[general.links].show`, через существующий log target `telemt::links`. Root-ссылки сохраняют прежний шестнадцатеричный secret. В path-ссылке `HOST/BASE` в параметре `server` percent-encoded, а secret равен base64url без padding от `0x70 || client_secret`, где `client_secret` — исходный 16-байтовый secret для режима `plain` либо `0xdd || secret` для режима `dd`. Users API возвращает только исходный секрет, а не WEB-ссылку. `[general.links].public_host` и `public_port` влияют только на нативные ссылки и не переопределяют ссылки WEB-vhost.

## Предварительные требования

- Отдельный публичный FQDN и действующий TLS-сертификат на NGINX или HAProxy.
- Стабильный публичный IP этого hostname. В `public_addr` должен быть указан именно этот конкретный IP с портом 443, поскольку адрес участвует во внутреннем destination tuple relay.
- Приватный или loopback HTTP-путь от TLS-терминатора до Telemt.
- Обычный decoy site: приватный HTTP origin либо immutable snapshot локального каталога.
- Совместимая сборка Telegram Desktop с типом прокси `WEB`.

Forwarded client address может принадлежать другому IP-семейству, чем `public_addr`, и изменяться в течение срока жизни bootstrap. При этом `public_addr` должен по-прежнему указывать точный публичный endpoint внутреннего MTProxy route.

## Минимальная конфигурация Telemt

В примере WEB-listener остаётся на loopback, а decoy использует приватный HTTP origin:

```toml
[general.links]
show = ["web-user"]

[access.users]
web-user = "0123456789abcdef0123456789abcdef"

[[server.listeners]]
ip = "127.0.0.1"
port = 18080
transport = "web"
proxy_protocol = false
web_client_ip_source = "x_forwarded_for"
web_trusted_proxy_cidrs = ["127.0.0.1/32"]

[web]
enabled = true
carrier = "https-lanes"
decoy_fasttrack_mode = "off"
http_connection_capacity_action = "drop"

[[web.vhosts]]
host = "proxy.example.com"
base_path = "telegram/web"
public_addr = "203.0.113.10:443"

[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://127.0.0.1:18081"

[[web.vhosts.profiles]]
user = "web-user"
secret_mode = "dd"
max_sessions = 8
max_streams = 512
max_streams_per_session = 64
```

Обработка перегрузки уже принятых sockets настраивается отдельно. `drop` сохраняет прежнее закрытие после `accept(2)`. `respond` без разбора запроса записывает пустой retryable-ответ `503`. `wait` вне accept loop ожидает обычную connection capacity, а затем переходит к стандартной HTTP-обработке; timeout записывает тот же `503`. Ожидание и запись используют `web.timeouts.http_overload_timeout_ms` для каждой фазы. `web.limits.max_http_overload_connections` ограничивает sockets вне обычной capacity и требует перезапуска процесса при изменении; action и timeout поддерживают hot reload.

`base_path` по умолчанию пуст. Непустое значение содержит не более 128 ASCII-байт и состоит из разделённых слешами сегментов `[A-Za-z0-9][A-Za-z0-9_-]*` без начального и завершающего слеша. Root-vhost сохраняет derivation capability v1. Path-vhost использует контекст v2 с точными каноническими host и base path, поэтому изменение регистра или любого сегмента меняет и маршрут, и capability.

`decoy_fasttrack_mode` управляет только capability processing для `GET/HEAD` на настроенном base root. Значение `off` по умолчанию сохраняет полный прежний scan без fast-track counters. `shadow` учитывает, какие структурно невозможные запросы могли бы обойти scan, но всё равно выполняет его полностью. `enforce` обходит capability work только для `HEAD` либо отсутствующего или неканонического query `bridge`. Каждый точный канонический bridge GET на base root выполняет полный scan всех профилей выбранного vhost и при совпадении, и при промахе. Настройка требует перезапуска процесса: reload сохраняет желаемое значение, но сообщает `web.decoy_fasttrack_mode` как deferred. Fast-track не защищает от злонамеренной CPU-нагрузки, потому что scanner всегда может отправлять канонические candidates; кроме того, `enforce` может создать публично наблюдаемый timing class формы запроса, особенно при статическом decoy. Не включайте этот режим без внешних timing measurements через production TLS-терминатор.

## Общие профили для нескольких доменов

Замените селектор `host` непустым списком `hosts`, чтобы несколько доменов
использовали общие определения профилей и один снимок decoy:

```toml
[[web.vhosts]]
hosts = ["proxy.example.com", "backup.example.com"]
base_path = "telegram/web"
public_addr = "203.0.113.10:443"

[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://127.0.0.1:18081"

[[web.vhosts.profiles]]
user = "web-user"
secret_mode = "dd"
max_sessions = 8
max_streams = 512
max_streams_per_session = 64
```

Этот фрагмент дополняет пользователя доступа и WEB listener из предыдущего
примера. Укажите ровно один селектор: `host` или `hosts`. При загрузке имена
нормализуются; совпадающие после нормализации имена запрещены. Шаблоны wildcard
и `*` требуют явного включения режима, описанного ниже. У всех доменов группы
общие `base_path`, `public_addr`, профили и decoy. Если эти настройки различаются,
создайте отдельные группы. TLS-терминатор должен обслуживать каждый домен из
списка и передавать исходный канонический `Host`.

У каждого домена свои capability, bootstrap/session credentials и квота профиля.
В примере профиль допускает до восьми сессий на каждом домене с учётом общих
ограничений процесса, IP и пользователя доступа. При запуске ссылки формируются
отдельно для каждого выбранного пользователя/профиля и конкретного домена.
Группировка не перенаправляет клиентов и не позволяет переносить credentials
между доменами.

В режиме точных имён `max_vhosts` учитывает каждый домен, а `max_profiles` —
каждую пару домен/профиль. Для восьми доменов со 100 профилями нужны пределы
не менее восьми vhosts и 800 profiles. Статические файлы и байты снимка одной
группы учитываются один раз; у отдельных групп снимки отдельные. Настроенные
максимумы сессий не резервируют сессии заранее. Общая неизменяемая политика
уменьшает дублирование, но индексы capability растут с числом пар домен/профиль.

Сначала установите новую сборку с прежней конфигурацией одиночных `host`, затем
объедините одинаково настроенные записи через reload. Группировка и перестановка
доменов сохраняют совместимые bootstrap credentials, идентичность квот и данные
обучения профиля. Удаление домена запрещает новые запросы к нему, не вводя новых
правил завершения существующих соединений. Увеличение лимитов требует перезапуска
и должно вступить в силу до добавления записей сверх действующих пределов.
Перед откатом на сборку без поддержки `hosts` разверните группы в одиночные
записи `host` и повторно проверьте бюджет статических снимков.

## Wildcard-хосты

По умолчанию используются точные `host` / `hosts`. Для произвольных поддоменов
установите `web.allow_wildcard_hosts = true` и перезапустите Telemt. После этого
селекторы также принимают `*.example.com` и `*`; точные имена и шаблоны можно
смешивать в одном списке:

```toml
[web]
enabled = true
allow_wildcard_hosts = true

[web.limits]
# Additional wildcard reservations must fit the declared envelope.
memory_envelope_bytes = 1610612736

[web.limits.wildcard]
max_rules = 32
max_profiles_per_request = 256
cache_hosts = 256
cache_bytes = 8388608
cold_hmac_per_minute = 1000000
cold_hmac_burst = 65536

[[web.vhosts]]
hosts = ["proxy.example.com", "*.example.com"]
base_path = "relay"
public_addr = "203.0.113.10:443"

[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://127.0.0.1:8080"

[[web.vhosts.profiles]]
user = "web-user"
secret_mode = "dd"
```

Этот пример дополняет ранее показанные listener и пользователя доступа. Запрос
выбирает одну группу: сначала точное имя, затем самый длинный подходящий суффикс,
затем `*`. Суффикс охватывает потомков любой глубины, включая `a.b.example.com`,
но не сам `example.com`. Неуспешная аутентификация не переключает запрос на
другое правило. Встроенные wildcard и регулярные выражения запрещены, как и
дубли селекторов после нормализации между группами. Выбранная группа сохраняет
свои фиксированные `public_addr`, базовый путь, профили и decoy. Заголовок Host
не выбирает адрес upstream.

В этом режиме HTTP Host нормализуется без учёта регистра ASCII; удаляется только
необязательный буквальный порт `:443`. Повторные Host, IP-адреса вместо домена,
некорректные DNS/ACE-метки, завершающая точка и другие порты запрещены.
`X-Forwarded-Host` не используется. Capability вычисляется по фактическому
каноническому имени с существующим клиентским алгоритмом; менять клиентов не
нужно. Квоты сессий/потоков/профиля остаются привязаны к конкретной тройке
`(host, user, secret_mode)`. Ограничения процесса, IP и пользователя доступа
продолжают действовать. Ссылки при запуске выводятся только для точных имён.

Frontend **обязан ограничивать допустимые Host**, а незашифрованный WEB backend
должен оставаться в закрытой сети. Сертификаты TLS должны покрывать каждое
фактическое имя клиента. Это явная граница безопасности: capability неизвестного
или вытесненного из кэша wildcard-домена, отправленная на другой домен, может
попасть в его decoy, в том числе на точный домен смешанной конфигурации.
Capability текущего домена, конечного списка точных доменов, известного
положительного кэша и подлинные bootstrap/session tokens процесса не передаются
в decoy в URI и заголовках, включая percent-encoded формы. Публичные URL, cookies
и заголовки не отклоняются лишь за сходство с credentials. Диагностические копии,
напротив, консервативно маскируют похожие строки, включая обрезанные префиксы;
байты публичных запросов/ответов и исходные хеши User-Agent не меняются. Поэтому
диагностика может маскировать и обычные длинные строки.

Перед вычислениями холодный запрос атомарно резервирует HMAC-бюджет для всех
профилей выбранной группы. При нехватке сразу возвращается HTTP 503 с no-store,
без очереди и частичного перебора. В пределах запроса одна таблица используется
для защиты от утечки credentials и аутентификации bridge. Попадание в кэш не
требует вычислений. Аутентифицированные carriers полностью обходят кэш таблиц
capability и их вычисление. Режимы fast-track Off/Shadow/Enforce по-прежнему
управляют проверкой корня; ошибочно размещённые credentials текущего домена
удерживаются локально в любом режиме.

FIFO-кэш заполняется только после успешной выдачи bootstrap для bridge/recovery.
`cache_hosts = 0` отключает хранение. Пределы количества записей и байтов независимы;
вытесненная запись продолжает занимать байтовый бюджет, пока запрос удерживает
ссылку на неё. Неудача вставки не отменяет корректный bootstrap; вытеснение не
сбрасывает квоты. Ключ кэша содержит уникальный идентификатор неизменяемого WEB
снимка, в том числе при reload внутри одного поколения runtime. Записи не
удерживают decoy или поколение runtime.

`max_vhosts` учитывает точные имена; `max_profiles` — точные привязки и один
общий набор профилей на каждую группу с wildcard. `max_rules` ограничивает число
шаблонов, а `max_profiles_per_request` — полный перебор группы wildcard. Все
пределы, кроме `cache_hosts`, должны быть положительными; HMAC burst должен
вмещать полную таблицу запроса. Проверяемый бюджет памяти включает шаблоны/правила,
кэш, рабочую память обработчиков и живые привязки доменов только при включённом
wildcard. С остальными стандартными лимитами прежних 1280 MiB недостаточно;
1290 MiB достаточно по текущему расчёту, а пример задаёт 1536 MiB. Бюджет и
обработка режима только с точными именами не меняются.

Флаг включения и все `web.limits` требуют перезапуска. После включения селекторы
и профили можно менять через reload. API может сохранить флаг и достаточные
лимиты как отложенные изменения. Добавление шаблонов до фактического перезапуска
отклоняется атомарно, даже если флаг уже записан в желаемой конфигурации. Для
отключения сначала замените шаблоны точными именами, затем перезапустите процесс
с выключенным флагом. Перед откатом на старую сборку удалите wildcard-селекторы,
новый флаг и таблицу лимитов.

## Server-side negotiation carrier

Для `websocket-lanes` отказ или таймаут до Upgrade отдельной lane запускает общее восстановление сессии. Сбой после Upgrade остаётся локальным для lane. Это свойство протокола не подтверждает совместимость восстановления нативных macOS/iOS клиентов после фонового режима.

Неизменяемая основа bridge кэшируется, а nonce, bootstrap, host и base path подставляются заново для каждого ответа. Обработка истечения сроков использует консервативные оценки ближайших сроков, не продлевая сроки. Эти внутренние оптимизации не меняют форматы протокола, лимиты приёма или таймауты и сами по себе не доказывают сокращения полного времени подключения.

Auto-negotiation необязателен и выключен, пока `carriers` не задан явным непустым массивом. Настроенный `carrier` остаётся последним fallback и добавляется ровно один раз, даже если уже присутствует в массиве:

```toml
[web]
enabled = true
carrier = "https"
carriers = ["websocket-lanes", "websocket", "https-lanes"]
carrier_learning = true
carrier_negotiation_aggressiveness = "conservative"

[web.timeouts]
carrier_negotiation_deadlines_secs = [3, 5, 8, 12]
carrier_health_secs = 30
carrier_learning_secs = 600
bridge_request_secs = 10
bridge_retry_secs = 90
bridge_recovery_secs = 15
carrier_probe_coalesce_ms = 0
```

Сгенерированный bridge отправляет канонические headers `X-Carrier-Capabilities`, `X-Carrier-Attempt` и, после первой попытки, `X-Carrier-Failure` в запросе `/session`. Каждый успешный automatic response возвращает `X-Carrier-Mode`, `X-Carrier-Attempt`, `X-Carrier-Candidate-Count`, `X-Carrier-Deadline` и `X-Carrier-State`. Bridge запускает локальный cumulative clock непосредственно перед первым запросом `/session`, а сервер фиксирует отдельный absolute chain deadline при приёме первой automatic attempt. Оба используют настроенные offsets и не сбрасываются при replacement. Для одного, двух, трёх и четырёх effective candidates checkpoints attempts равны соответственно `[d3]`, `[d0, d3]`, `[d0, d1, d3]` и `[d0, d1, d2, d3]`; финальному candidate всегда принадлежит `d3`. Successor остаётся допустимым до собственного checkpoint. Состояния: `provisional`, `committed` и `healthy`.

Bridge отправляет additive status objects v1 с полями `state`, `phase`, `reason` и `deadline_ms`. `phase=provisional` следует после аутентифицированного `WELCOME`; `state=connected,phase=committed` отправляется только после того, как выбранный transport подтвердит реальный прогресс `OPEN` или `DATA`. Initialization port имеет собственный pre-`HELLO` deadline `bridge_request_secs`, а навигация страницы терминальна для этого экземпляра документа. Более позднее initialization message не может оживить закрытый или оставшийся в BFCache bridge.

Попытки строго последовательны. Принятый прогресс `OPEN` или `DATA` немедленно фиксирует выбранный carrier и окончательно закрывает границу replacement. Аутентифицированный `409` для committed chain повторяет metadata зафиксированного carrier и является terminal response, а не разрешением перейти дальше. Точный replay `/session` применяется только пока результат этого запроса неоднозначен. После аутентифицированного выбора provisional carrier transport failure сразу запрашивает следующую attempt; если предыдущий probe всё же успел committed, сервер возвращает terminal `409` и не разрешает небезопасный replacement. Финальный абсолютный deadline на сервере также ограничивает lifetime successor, ответ которого клиент не получил. In-place переключение после commit по-прежнему не поддерживается; сохранившийся bridge восстанавливается созданием новой server session.

После commit при HTTP failure сначала точно повторяется замороженный request с текущим bearer. Успешный replay сохраняет текущую session. Потеря WebSocket либо событие foreground, online или native после scheduler gap не короче `reconnect_grace_secs` запускает одну recovery epoch. Bridge выполняет ровно один GET к исходному настроенному base root с `bridge=<capability>`, `Accept: application/vnd.telemt.web-recovery+json` и необязательной authorization текущим bearer. Положительный ответ — не кэшируемый JSON document размером не более 1024 байт со свежим bootstrap и текущими limits, timeouts и negotiation policy. Telemt выдаёт этот bootstrap до синхронного завершения совпавшей текущей session, поэтому пересоздание остаётся возможным при capacity в одну session. Неизвестный или уже retired bearer получает то же положительное representation; malformed recovery headers, выключенная admission, pause, drain и capacity rejection следуют по очищенному decoy path.

Recovery epoch имеет единый абсолютный wall/monotonic deadline `bridge_recovery_secs`, один request recovery document и bounded carrier retries с резервной базовой паузой от 250 мс до 2 с с учётом подсказок сервера и политики jitter страницы. Активный recovery status повторяется не чаще одного раза в 2,5 секунды. Новая incarnation прерывает и освобождает старые requests, sockets, lanes и queues, отправляет один synthetic `CLOSE` для каждого ещё активного native stream, подавляет второй `WELCOME` и выполняет commit только после реального carrier progress. Retired stream IDs сохраняются в bounded set, чтобы корректные поздние frames не попали в новый stream; native side должна выделить новый stream ID. Частые native reconnect attempts допустимы, но не продлевают recovery epoch и не удерживают старое состояние incarnation. Уничтожение WebView уничтожает этого recovery owner; после этого native supervisor должен создать новый bridge document.

Ответы Telemt при перегрузке содержат `Retry-After: 1` и `X-Telemt-Retry-After-Ms: 250`. Только статус `503` с этой точной парой заголовков задаёт сгенерированному мосту **базовую паузу 250 мс**. При `web.retry_jitter.enabled = false` пауза равна 250 мс; при включении добавляется настроенная случайная задержка. Для остальных ответов действуют стандартная обработка `Retry-After` или резервный backoff, описанные ниже. Ранее загруженные страницы JavaScript-моста без поддержки миллисекундной подсказки используют секундную паузу до загрузки новой страницы; обновлять приложение Telegram для этого не нужно. Лимиты попыток, абсолютные бюджеты, отмена и ограничения admission не меняются.

Каждая обычная carrier HTTP-операция bridge имеет абсолютный budget `bridge_retry_secs` и не более девяти attempts. `bridge_request_secs` охватывает Fetch response head и полное чтение response body; для downlink attempt дополнительно разрешён настроенный long-poll interval. Network failures и ответы `408`, `429`, `502`, `503` или `504` используют положительную подсказку сервера или экспоненциальный backoff с действующей политикой jitter; `Retry-After` не может расширить абсолютный budget. При `carrier_probe_coalesce_ms = 0` первый упорядоченный probe с `OPEN` отправляется немедленно. Значение до 10 мс позволяет включить соответствующий `DATA`, пришедший в этом окне; multiplexed carriers сохраняют весь предшествующий порядок frames, а lane carriers забирают только выбранную lane. HTTP downlink может запускаться одновременно с первым upload; доставка в native-клиент ждёт первого корректного ACK/commit upload. Multiplexed WebSocket Upgrade может начаться сразу после его выбора ответом `/session` и затем включить queued probe data; lane WebSocket ждёт известного stream ID.

Response bodies читаются потоково с явными bounds endpoint: `/session` содержит ровно восемь байт, успешный `/down` — не более `carrier_batch_bytes`, а bodyless responses допускают ноль байт. Заявленный overflow отклоняется до чтения; overflow при streaming или избыточное число chunks отменяет reader, а bodies retryable responses отменяются до backoff. Финальный cleanup bridge отправляет не более одного аутентифицированного `DELETE`; канонические transport failures копируются в `X-Carrier-Failure` для диагностики, а navigation и explicit close остаются non-learning reasons.

Automatic WebSocket использует `tproxy-auto-v1.<session-token>` или `tproxy-auto-lane-v1.<session-token>.<stream-id>`. Первое принятое binary message с реальным прогрессом `OPEN` или `DATA` фиксирует carrier; затем сервер пишет пустой binary commit ACK именно в это connection. Ping/Pong не фиксирует carrier и не считается learning evidence.

Committed attempt становится healthy, только когда transport-specific двунаправленный evidence остаётся корректным в течение `carrier_health_secs`. HTTPS требует принятый `DATA`, подтверждённый непустой post-commit downlink batch и аутентифицированную активность не раньше health deadline. WebSocket требует записи точного commit ACK, последующего принятого `OPEN` или `DATA` от того же owner и сохранения этого owner живым до конца интервала. Health publication, owner eviction и close имеют единственного terminal winner. Более раннее закрытие нейтрально для ranking evidence, но отображается как diagnostic outcome `closed_before_health`.

Обучение process-local, in-memory, positive-only и ограничено `max_carrier_learning_entries`. Оно ранжирует только поддерживаемые клиентом настроенные candidates, всегда оставляет fallback последним и сохраняет настроенный порядок при равных scores. Evidence User-Agent и профиля имеет основной вес; допустимый IP служит только tie-breaker. Для IP evidence требуется ровно один явный глобально маршрутизируемый `X-Forwarded-For`; private, loopback, link-local, carrier-grade NAT, documentation, multicast и их IPv4-mapped эквиваленты исключаются. Категории ошибок от клиента и request latency используются только для диагностики и не создают отрицательный или ranking evidence. `conservative` требует 3 outcomes User-Agent или 8 outcomes профиля в 4 cohorts и отключает IP evidence; `balanced` использует соответственно 2, 6 в 3 cohorts и 3 outcomes допустимого IP; `aggressive` — 1, 4 в 2 cohorts и 1 outcome IP. Смена generation при неизменной learning semantics сохраняет evidence и атомарно перепубликует его generation fence. Выключение обучения или изменение aggressiveness, lifetime evidence либо health window увеличивает evidence epoch и отсоединяет несовместимое состояние; stale outcomes не могут заполнить его снова.

`https` остаётся default. Окно upload согласуется в диапазоне от 1 до 4; сгенерированный мост предлагает `X-Telemt-Up-Window: 4`, а окно 1 сохраняет последовательную отправку. В `https-lanes` lane zero отведена под session control, а каждому ненулевому logical stream соответствует своя lane. У каждой lane собственные uplink sequence, retry digest, downlink cursor, unacknowledged replay batch, очередь и lifecycle newest-poll-wins. Поэтому медленный stream не блокирует другой stream на уровне WEB-протокола.

Это устраняет сериализацию между WEB-streams на уровне приложения. Публичный HTTP/2 всё ещё работает поверх одного или нескольких TCP-connections, поэтому потеря пакетов может вызвать transport-level head-of-line blocking; `https-lanes` не является HTTP/3- или QUIC-carrier.

Все lane queues и resident response bodies входят в существующие per-session и process-wide byte/item budgets. Telemt дополнительно ограничивает одну lane значениями `pending_bytes_per_lane` и `pending_items_per_lane`; сгенерированный bridge ограничивает свои очереди 8 MiB и 1024 элементами. Lane long polls могут занимать не более половины `web.limits.max_http_handlers`, оставляя handler capacity для session creation, uplink, DELETE и другой control work. Для `https` требуется `max_http_handlers >= 2`, для `https-lanes` — `max_http_handlers >= 4`.

Суффиксы `/api/v1/up` и `/api/v1/down` не меняются и добавляются к настроенному base. В `https-lanes` каждый запрос к ним содержит один канонический десятичный `X-Lane-ID`. Uplink sequence начинается с `1`, а downlink cursor — с `0` независимо для каждой lane. Lane zero принимает только session `PONG`; все frames ненулевой lane должны иметь тот же stream ID, а новая lane должна начинаться с `OPEN`. Канонический downlink с cursor zero, пришедший немного раньше `OPEN` своей lane, ждёт до `lane_open_wait_secs` без создания lane state; число таких ожиданий ограничено per-session и process auxiliary permits. Истечение таймаута возвращает пустой `204`, а отсутствующая lane с продвинутым cursor остаётся protocol failure и уходит в decoy. После отправки всей queued и unacknowledged downlink data закрытой lane Telemt возвращает пустой ответ с `X-Lane-Closed: 1`, и bridge прекращает её polling. Retry остаются byte-identical и повторяют исходный acknowledgement или downlink batch.

Оба WebSocket carrier по-прежнему создают и удаляют parent session через HTTPS, после чего используют строгий bodyless Upgrade GET по настроенному base плюс `/api/v1/ws`. `websocket` передаёт в `Sec-WebSocket-Protocol` ровно `tproxy-v1.<session-token>`; binary messages являются упорядоченными carrier batches, а ошибка протокола, deadline или connection закрывает всю parent session. `websocket-lanes` передаёт ровно `tproxy-lane-v1.<session-token>.<stream-id>`, где stream ID записан каноническим десятичным числом из диапазона `1..=16777215`. Первое binary message должно начинаться с `OPEN`, все frames должны содержать этот stream ID, а сбой после Upgrade закрывает только данную lane. Lane-zero WebSocket отсутствует: HTTPS переносит `HELLO` и `WELCOME`, а liveness connection обеспечивает RFC 6455 Ping/Pong.

До HTTP `101` reservation WebSocket lane привязывается к точным process connection и incarnation lane; принятый `OPEN` передаёт ownership точному incarnation stream до запуска его backend task. Поздний poll, close или drop reservation от старого socket не может подтвердить, закрыть или освободить replacement, повторно использующий тот же числовой lane ID.

WebSocket codec buffers и находящиеся в обработке read/write messages делят process-owned `pending_bytes_global` с carrier queues и дополнительно ограничены `websocket_bytes_global`. Admission оставляет `websocket_http_connection_reserve` принятых connections для обычного HTTP и decoy. При admission replacement сначала глобально выбираются dead active connections, затем применяются уровни locality: та же session, тот же profile owner и тот же client IP. Не связанный с ними healthy victim допустим только когда requester использует меньше своей fair byte share, а owner victim — больше. Внутри одного уровня locality claimed или upgraded connections идут перед active lanes, lanes — перед active multiplexed sessions; дальнейший порядок детерминируют время последнего прогресса, создания и connection ID. Cleanup при memory pressure использует тот же dead-first и lifecycle-порядок, предпочитая owners выше fair share, но продолжает eviction, если все owners находятся на своей share или ниже. `max_websocket_evictions_in_flight` ограничивает одновременные точные eviction claims. Deadlines Upgrade, первого message, write, backpressure и eviction заморожены из parent session. После `long_poll_secs` без peer activity отправляется transport Ping, в том числе при непрерывном downlink traffic, а отсутствие peer activity в течение удвоенного creation-time интервала делает active connection кандидатом на cleanup.

Любая ошибка authentication, shape, lane reservation или capacity до Upgrade следует по очищенному decoy path и не раскрывает WebSocket-специфичный status. Точный subprotocol содержит session bearer и не должен попадать в logs.

Для WEB-listener обязательны `proxy_protocol = false` и `reuse_allow = false`. В нём нельзя использовать `client_mss`, `synlimit`, `announce` и `announce_ip`. Массив `web_trusted_proxy_cidrs` должен быть непустым и содержать только непосредственные адреса NGINX или HAProxy; сети `/0` запрещены.

Для `http_upstream` параметр `resolve` принимает `"never"` (по умолчанию) или `"startup"`. По умолчанию нужен IP-адрес из loopback, link-local или private диапазона. `startup` также разрешает DNS-имена: асинхронная подготовка конфигурации разрешает каждую уникальную пару имя/порт, проверяет все ответы по допустимым классам адресов и действующим WEB listeners и закрепляет первый адрес в порядке ответа resolver. Ошибка, пустой ответ, публичный адрес или прямая петля к listener отклоняют подготовку. В upstream authority сохраняется настроенное имя. DNS при обработке запросов и автоматического перехода к другим ответам нет; reload готовит новый снимок. `web.timeouts.decoy_resolve_secs` ограничивает отдельный DNS-запрос для каждой уникальной пары имя/порт. Запросы выполняются последовательно, общего таймаута подготовки нет. Косвенные петли через другие прокси оператор должен исключить самостоятельно.

В обычных запросах сохраняются метод, путь, query, заголовки, потоковое тело, статус и тело ответа, кроме hop-by-hop заголовков. Из некорректных carrier-запросов перед передачей в decoy удаляются credentials и тело.

Вместо origin можно использовать immutable snapshot статического сайта:

```toml
[web.vhosts.decoy]
mode = "static_directory"
directory = "/var/lib/telemt/public"
index = "index.html"
```

Статические файлы читаются при запуске и успешном reload конфигурации. Число элементов, размер одного файла и общий размер snapshot ограничены `[web.limits]`. Symlinks и пути с выходом из настроенного каталога запрещены. Не изменяйте каталог одновременно с построением snapshot в Telemt.

Все WEB-ключи и defaults перечислены в [справочнике конфигурации](../Config_params/CONFIG_PARAMS.ru.md#web).

### Настраиваемый jitter HTTP-повторов

`[web.retry_jitter]` добавляет независимо выбранную задержку к каждому существующему HTTP-повтору бриджа: сетевым ошибкам и ответам 408/429/502/503/504. Менять приложения Telegram не требуется. Без секции или при `enabled = false` сохраняются подсказка Telemt на 250 мс и прежний backoff/jitter.

```toml
[web.retry_jitter]
enabled = true
min_ms = 0
max_ms = 250
distribution = "uniform"
# Only for distribution = "triangular":
# peak_ms = 125
```

Диапазон задаёт **добавку**, а не полную паузу: подсказка Telemt 250 мс с этим примером даёт 250–500 мс. Без положительной серверной подсказки база остаётся 250, 500, 1000, затем 2000 мс. Включённый jitter заменяет прежний jitter до 25%. Корректный стандартный `Retry-After` во включённом режиме не сокращается прежним пределом в 30 секунд. Если пауза не помещается в оставшийся бюджет операции, бюджет истекает без раннего повтора.

Значения по умолчанию: `enabled = false`, `min_ms = 0`, `max_ms = 250`, `distribution = "uniform"`, `peak_ms` отсутствует. Требуется `0 <= min_ms <= max_ms <= 30000`. `uniform` выбирает целые миллисекунды равномерно; `triangular` использует треугольную плотность с округлением до миллисекунд. Необязательный пик по умолчанию находится посередине и должен входить в диапазон. Явный пик для `uniform`, неизвестные ключи/распределения и неверные границы отклоняются даже при выключенной опции. Одинаковые границы дают постоянную добавку.

Политика фиксируется в каждой странице бриджа. Reload через конфиг/API влияет на новые страницы; активные сохраняют настройки при recovery. Recovery JSON и HTTP-заголовки совместимости не меняются. Используется `crypto.getRandomValues`, при недоступности — `Math.random` для совместимости. Успешный трафик не задерживается. Лимиты попыток, общий бюджет, отмена и повтор неизменных payload/sequence сохраняются; более длинные паузы могут уменьшить число попыток, помещающихся в startup/recovery-бюджет.

Это размывает фиксированные интервалы повторов, но не гарантирует защиту от DPI. Планирование браузера, сетевые очереди и другие временные характеристики протокола остаются наблюдаемыми. Существующие примеры временной шкалы описывают выключенную опцию. Для включённого режима добавляйте выбранную задержку к каждой паузе повтора, а не к первому соединению или каждому кадру данных.

Политика меняет только уже предусмотренные паузы перед повтором. Более строгие ограничения отдельных вызовов сохраняются: обычный poll `/down` и вызов `/up` после commit выполняют одну попытку; их replay при восстановлении допускает две. Опция не создаёт новых циклов повторов. Она не продлевает `web.timeouts.bridge_retry_secs` и сроки запуска или восстановления.

## Терминация TLS на NGINX

```nginx
map $http_upgrade $telemt_connection_upgrade {
    default upgrade;
    ''      '';
}

upstream telemt_web {
    server 127.0.0.1:18080;
    keepalive 64;
}

server {
    listen 443 ssl;
    http2 on;
    server_name proxy.example.com;
    access_log off;

    ssl_certificate     /etc/letsencrypt/live/proxy.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/proxy.example.com/privkey.pem;

    client_max_body_size 2m;

    location / {
        proxy_pass http://telemt_web;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $telemt_connection_upgrade;

        proxy_connect_timeout 5s;
        proxy_send_timeout 65s;
        proxy_read_timeout 65s;
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_next_upstream off;
    }
}
```

Разместите `map` в контексте `http` NGINX. `client_max_body_size` должен быть не меньше `web.limits.max_body_bytes`. Read, send и client timeouts должны превышать как default long poll в 25 секунд, так и удвоенный WebSocket liveness interval; 65 секунд покрывают defaults. Перезаписывайте `X-Forwarded-For`, а не дополняйте его. Telemt принимает один корректно разбираемый IP-адрес; если доверенный TLS-терминатор не передал header, Telemt использует адрес непосредственного peer, но per-client limits и source policy тогда видят терминатор вместо реального клиента. Не включайте upstream retries: bridge выполняет byte-identical HTTPS retries, но установленный WebSocket никогда не replay’ится прозрачно.

Для prefix-only cohosting с `base_path = "telegram/web"` замените `location /` на `location ^~ /telegram/web/`. Оставьте `proxy_pass http://telemt_web;` без URI-компонента и не добавляйте `rewrite`: NGINX должен передавать исходный prefix. Запросы вне этого поддерева может обслуживать другой сайт, но все запросы внутри него должны идти в Telemt. Также задайте точный `location = /telegram/web`, который использует обычное non-WEB-поведение сайта или без изменений передаёт запрос в decoy path Telemt. Иначе NGINX может самостоятельно создать добавляющий слеш `301` для alias без слеша, который не входит в WEB-контракт.

Для `https-lanes` обязателен публичный HTTP/2; используйте эквивалентную HTTP/2-директиву, поддерживаемую установленной версией NGINX. WebSocket Upgrade требует HTTP/1.1, поэтому публичный endpoint должен также разрешать HTTP/1.1, а приватный hop NGINX-to-Telemt остаётся HTTP/1.1. Сохраняйте `Connection`, `Upgrade` и `Sec-WebSocket-*` ровно как в примере. Upstream connection capacity должна выдерживать ожидаемое число одновременных lane polls или WebSocket lanes; `keepalive` управляет idle pool и не является лимитом concurrency.

### Как отличить отказ соединения от WEB capacity

`connect() failed (111: Connection refused) while connecting to upstream` означает ошибку TCP connect до принятия socket процессом Telemt. Проверьте, что процесс Telemt запущен, effective address и port WEB-listener совпадают с upstream NGINX, оба процесса находятся в ожидаемых network namespace и address family, а локальный firewall не отклоняет соединение. Такое поведение могут вызвать ошибка bind при запуске, окончательное удаление listener или переключение NGINX на желаемый порт до того, как restart-only изменение listener стало эффективным. Давление на kernel listen backlog — отдельный случай, для которого обычно нужна host telemetry `ListenOverflows` и `ListenDrops`.

WEB capacity применяется после успешного `accept(2)`. Поэтому исчерпание `max_http_connections` приводит к настроенному outcome `drop`, `wait` или `respond`, но не к отказу upstream connect. У limits handler, body, lane, stream, queue и WebSocket собственные HTTP-, decoy- или stream-local failure boundaries. Operator pause и drain также оставляют WEB-listener привязанным и сами по себе не могут вызвать отказ соединения.

Используйте `GET /v1/runtime/web/status` только для корреляции состояния, принадлежащего Telemt. Для `ingress.accepting_connections` нужны running publication, доступный runtime и один живой acceptor на каждый effective WEB-listener. `capacity.saturated_resources`, типизированные rejection totals и overload outcomes показывают сбои после accept. `decoy_upstream` описывает только исходящий plain-HTTP hop Telemt к decoy. Ни одно из этих полей не утверждает, что публичный TLS endpoint NGINX доступен; проверяйте эту границу внешним TCP/TLS probe и telemetry NGINX или HAProxy.

## Терминация TLS на HAProxy

```haproxy
frontend public_https
    mode http
    no log
    bind :443 ssl crt /etc/haproxy/certs/proxy.example.com.pem alpn h2,http/1.1
    acl telemt_web_host hdr(host) -i proxy.example.com proxy.example.com:443
    use_backend telemt_web if telemt_web_host

backend telemt_web
    mode http
    option http-keep-alive
    retries 0
    timeout connect 5s
    timeout server 65s
    http-request set-header Host proxy.example.com
    http-request del-header X-Forwarded-For
    http-request set-header X-Forwarded-For %[src]
    server telemt_web_1 127.0.0.1:18080 check
```

Во frontend или секции `defaults` также задайте `timeout client 65s` или больше для default WebSocket liveness interval. Для `https-lanes` публичный ALPN HAProxy должен содержать `h2`, а для WebSocket Upgrade — `http/1.1`. Сохраняйте `Connection`, `Upgrade` и `Sec-WebSocket-*`; не переписывайте path, raw query, body и carrier headers `Authorization`, `Content-Type`, `X-Up-Seq`, `X-Down-Cursor`, `X-Lane-ID`. Для prefix-only cohosting добавьте `acl telemt_web_path path_beg /telegram/web/` и потребуйте одновременно host- и path-ACL в `use_backend`; не удаляйте prefix.

## Терминация TLS на Caddy

```caddyfile
{
	servers {
		protocols h1 h2
	}
}

proxy.example.com {
	reverse_proxy 127.0.0.1:18080 {
		header_up X-Forwarded-For {remote_host}
		flush_interval -1
		stream_close_delay 5m
	}
}
```

Caddy сам получает и продлевает публичный сертификат для адреса сайта. Он передаёт исходный `Host` и заголовки `Connection`, `Upgrade` и `Sec-WebSocket-*` без изменений и проксирует WebSocket Upgrade без дополнительных директив; не добавляйте `header_up Host`. Публичные HTTP/2 (нужен для `https-lanes`) и HTTP/1.1 (нужен для WebSocket Upgrade) включены по умолчанию, а приватный участок Caddy → Telemt остаётся HTTP/1.1. Глобальная опция `protocols h1 h2` убирает HTTP/3 с пути WEB: контракт WEB описывает только HTTP/1.1 и HTTP/2. Она действует на все сайты этого сервера Caddy.

`header_up X-Forwarded-For {remote_host}` перезаписывает заголовок одним адресом. Без неё Caddy дописывает адрес к входящему `X-Forwarded-For` от пиров из `trusted_proxies`, а Telemt принимает только один разбираемый IP-адрес. Если сам Caddy стоит за L4-балансировщиком с `listener_wrappers { proxy_protocol }`, `{remote_host}` — адрес клиента из заголовка PROXY. `flush_interval -1` отключает буферизацию ответа для long polls и downlink. Тела запросов Caddy по умолчанию передаёт потоком; не включайте `request_buffers`.

У `reverse_proxy` в Caddy по умолчанию нет read/write timeout и лимита тела запроса, поэтому 25-секундный long poll и WebSocket liveness interval проходят без изменений. Если заданы серверные `timeouts` или `request_body max_size`, держите их выше 65 секунд и не меньше `web.limits.max_body_bytes` соответственно. С одним upstream Caddy не повторяет неудачные запросы; не добавляйте `lb_retries` и `lb_try_duration`. При reload конфигурации Caddy по умолчанию сразу закрывает upgraded-соединения. `stream_close_delay` держит установленные WebSocket lanes открытыми на заданное время после reload.

Для prefix-only cohosting с `base_path = "telegram/web"` направляйте поддерево через `handle`, а не `handle_path`: `handle_path` срезает prefix.

```caddyfile
proxy.example.com {
	handle /telegram/web/* {
		reverse_proxy 127.0.0.1:18080 {
			header_up X-Forwarded-For {remote_host}
			flush_interval -1
			stream_close_delay 5m
		}
	}

	handle {
		# ordinary site
	}
}
```

Маршрутизация Caddy не добавляет редирект со слэшем: `/telegram/web` без завершающего слэша уходит в обработчик обычного сайта. Убедитесь, что и этот обработчик не редиректит его; например, `file_server` перенаправляет запрос каталога на вариант со слэшем.

Caddy не пишет access log без директивы `log`. Если журнал нужен, скройте bridge capability и bearer credentials:

```caddyfile
log {
	format filter {
		request>uri query {
			replace bridge REDACTED
		}
		request>headers>Authorization delete
		request>headers>Sec-Websocket-Protocol delete
	}
}
```

В `web_trusted_proxy_cidrs` укажите адрес, с которого Caddy подключается к Telemt, например `["127.0.0.1/32"]` для конфигурации выше.

## Lifecycle и reload

| Конфигурация | Поведение runtime |
| --- | --- |
| Состав WEB-listeners, bind address и trust policy | Принадлежат процессу; перезапустите Telemt. |
| `web.allow_wildcard_hosts` и любое значение `[web.limits]` | Process-owned контракт памяти и ресурсов; перезапустите Telemt. |
| `web.enabled`, policy carrier/negotiation, `web.debug`, timeouts, vhosts, profiles и decoys | Применяются config watcher или runtime generation reload. |
| `web.retry_jitter` | Reload действует только для новых страниц моста. Уже загруженные страницы сохраняют политику при recovery; для применения изменений нужна новая страница. |
| Изменение `base_path` vhost | Атомарно переключает маршрутизацию новых HTTP-запросов и derivation capability. Выпустите новую сгенерированную ссылку. Уже upgraded WebSockets и начатые маршрутизированные обмены продолжаются. Последующие запросы к старому base с подлинным для процесса bootstrap- или session-token получают локальный no-store `404`, а ставшая неактивной прежняя capability обрабатывается как обычный decoy traffic. Существующий session bearer остаётся пригодным только на новом точном base, а неиспользованный bootstrap, выданный для старой capability, не может создать session на новом base. |
| Operator pause/drain state | Process-owned и ephemeral; переживает generation reload, никогда не записывает конфигурацию и после перезапуска процесса возвращается в `running`. |
| Существующие HTTP connections и WEB sessions | Сохраняют HTTP idle limit, carrier candidates, лимиты, body timeout, lifetime replay-marker закрытого token и абсолютные session/negotiation deadlines своего момента создания; каждый выданный bridge содержит собственные request, retry, recovery и probe-coalescing значения. Recovery epoch фиксирует текущий bridge budget, а успешное recovery representation обновляет policy для последующих epochs и новой session. WebSocket Upgrade, open, write, backpressure и eviction operations используют замороженные deadlines parent session. Новые bridges получают активную policy, а новые logical streams используют активное relay generation. `web.retry_jitter` и HTTP-метод carrier остаются свойствами страницы и не обновляются при recovery. |
| Завершение процесса | Один раз фиксирует последнее применённое значение `web.timeouts.shutdown_secs` и использует единый абсолютный deadline для listener acceptors и connections, WEB sessions и auxiliary tasks. Последовательные компоненты не получают отдельные полные бюджеты. |

Каждый logical stream сохраняет client IP своей сессии и владеет уникальным в пределах процесса ненулевым synthetic source port до завершения relay. Это сохраняет один стабильный непересекающийся source/destination tuple для Direct и Middle-End KDF routing.

HTTP idle accounting защищает только явно ограниченные фазы request body, long poll, подключения/response head decoy и ожидания Upgrade. Собственный deadline операции остаётся точным; если в этот момент её lease ещё существует, connection watchdog даёт запланированной задаче не более одного connection-idle interval для публикации timeout/result, после чего принудительно закрывает connection. Между обменами и после готовности response head прогресс сбрасывает idle-таймер, а зависший response body остаётся ограничен idle timeout. Завершение старой фазы не может снять deadline-защиту, которой уже владеет новая фаза.

`OPEN` резервирует bounded ownership logical stream и tuple, но не занимает permit `max_connections` relay generation. Telemt получает этот permit только после первого внутреннего байта; замороженный first-byte deadline и stream limits ограничивают silent opens, а исчерпание capacity закрывает только затронутый stream.

Рассматривайте изменение `base_path` на работающей системе как миграцию маршрута, несущего credentials. Прекратите выдавать или распространять старые ссылки, подготовьте новую ссылку, по возможности выполните drain затронутых sessions, примените reload, проверьте новый маршрут через публичный TLS endpoint и только затем распространяйте новую ссылку. Пока ещё могут приходить старые capabilities или tokens, направляйте в Telemt и старый, и новый frontend prefixes: credential-aware локальный отказ должен выполнить Telemt. Один vhost не может одновременно принимать оба base. Для реального overlap window нужен второй hostname/vhost, а если необходимо сохранить тот же host — отдельная process или deployment boundary.

## Управление через API

Конфигурация WEB, статус runtime и bounded runtime-управление доступны на одном аутентифицированном API-listener. `/web-status` остаётся read-only HTML-диагностикой; операции, изменяющие состояние, существуют только под `/v1/runtime/web`.

| Операция | Поддержка API |
| --- | --- |
| Чтение или изменение `[web]`, vhosts, profiles, decoys, timeouts или limits | Да, через `GET` или `PATCH /v1/config`. Производный snapshot `web.runtime` не возвращается и недоступен для записи. Вложенные tables сливаются по полям; arrays целиком заменяют прежний array. Изменения `web.allow_wildcard_hosts` и `[web.limits]` откладываются до перезапуска процесса. Добавлять шаблоны можно только после включения wildcard в действующем процессе. |
| Сохранение `server.listeners` | Да, через `PATCH /v1/config`, но изменённый WEB-listener остаётся deferred до перезапуска процесса. |
| Применение WEB-конфигурации, изменённой вне API | Да, через `POST /v1/system/reload` с последующей проверкой статуса операции. |
| Просмотр bounded серверных WEB request- и lifecycle-деталей | Да, через аутентифицированный `GET /web-status`. |
| Просмотр lifecycle, capacity planes, состояния learning/debug и активных сессий | Да, через `GET /v1/runtime/web/status` и `/v1/runtime/web/sessions`. |
| Закрытие выбранных активных WEB-сессий | Да, через асинхронную операцию `POST /v1/runtime/web/sessions/close`. |
| Приостановка, deadline-drain или возобновление новой WEB-работы | Да, через `/v1/runtime/web/lifecycle/{pause,drain,resume}`. |
| Очистка debug-записей или сброс carrier learning | Да, через соответствующие runtime POST endpoints. |
| Управление `[access.users]` | Да, через `/v1/users`. Создание пользователя не создаёт WEB-профиль. |
| Отзыв отдельного пользователя | Да. `/v1/users/{username}/disable` немедленно обновляет admission и завершает активные сессии пользователя. |

Привяжите API к loopback, оставьте узким whitelist непосредственных peers, настройте точное значение authorization header и используйте `read_only = false` только там, где нужны мутации:

```toml
[server.api]
enabled = true
listen = "127.0.0.1:9091"
whitelist = ["127.0.0.0/8"]
auth_header = "Bearer replace-with-a-random-control-token"
read_only = false
```

API whitelist проверяет непосредственный TCP peer и не доверяет `X-Forwarded-For`. Изменения самой секции `[server.api]` требуют перезапуска процесса.

### Статус и управление runtime

`GET /v1/runtime/web/status` всегда возвращает опубликованный ingress lifecycle (`starting`, `no_web_listener`, `running`, `draining`, `drained` или `deadline_exceeded`), его epoch и возраст, effective addresses listeners и обратно совместимую runtime availability. `ingress` независимо сообщает configured listeners, live acceptors, accepting state, accept totals и стабильную причину. `capacity` сообщает effective policy перегрузки принятых sockets, использование фиксированных ресурсов, мгновенную saturation, partial planes, типизированные rejection decisions и overload outcomes. `decoy_upstream` сообщает фиксированные outcomes и возраст последнего внутреннего результата origin. `decoy_fasttrack` сообщает effective restart-frozen mode и полный фиксированный набор dispositions, даже если runtime manager недоступен. `carrier_negotiation` всегда сообщает фиксированные matrices selection, client failure и terminal health/learning outcomes из publication ownership. Пока process-owned WEB runtime существует, `operator_lifecycle` независимо показывает `running`, `paused`, `draining`, `force_closing` или `drained`, собственные epoch и admission flags, а также активный или последний drain. Поле `runtime` добавляет случайный 128-битный `runtime_instance`, активное поколение, неизменяемые limits, capacity counters отдельных planes, epochs carrier-learning/debug и суммарные counters. Status собирается неблокирующим чтением каждого plane: занятый plane пропускается и указывается в `partial`; endpoint никогда не ожидает data plane, не выполняет cleanup и не изменяет его.

Prometheus экспортирует те же process-owned planes как семейства `telemt_web_*` с фиксированной cardinality: one-hot states ingress и operator, listener/accept counters, использование и saturation capacity, типизированные terminal rejections, outcomes перегрузки принятых sockets, внутренние outcomes decoy origin и totals sessions/streams/carriers. Decoy routing добавляет one-hot `telemt_web_decoy_fasttrack_mode` и фиксированный `telemt_web_decoy_fasttrack_requests_total{disposition}`. Carrier negotiation использует `telemt_web_carrier_selections_total`, `telemt_web_carrier_reported_failures_total`, `telemt_web_carrier_learning_outcomes_total`, one-hot gauges learning state/policy и gauges used/limit entries. Labels — только закрытые enums или фиксированные имена ресурсов; user, host, client IP, token, profile key, runtime instance, listener address и generation ID никогда не используются как labels. Успешный outcome `wait` не увеличивает rejection counter.

`GET /v1/runtime/web/sessions` возвращает не более 50 сессий по умолчанию и не более 200 при заданном `limit`. Упорядоченный scan ограничен 1000 кандидатами. `cursor` и `session_ref` имеют opaque canonical вид `ws1.<runtime-instance>.<lowercase-hex-id>`; точный `session_ref` нельзя сочетать с `cursor` или `limit`. Доступны фильтры `ip`, `host`, `user`, `user_agent_id`, `key_id`, `carrier` и `state`; повторяющиеся или неизвестные query fields отклоняются. Детальная операция — `GET /v1/runtime/web/sessions/{session_ref}`. Сохранённый tombstone закрытой сессии возвращает `410`; занятый точный snapshot — `503 web_snapshot_busy`. Ответы содержат только bounded несекретные metadata и никогда не раскрывают bootstrap/session bearers, capabilities, hashes секретов или synthetic/KDF ports.

Каждый runtime POST требует ровно `Content-Type: application/json`, отклоняет неизвестные JSON fields, наследует API authentication, whitelist и `read_only`, а также содержит текущий `runtime_instance` как ABA-fence. Доступные операции:

- `POST /v1/runtime/web/lifecycle/pause` с `{"runtime_instance":"..."}`. После linearizable fence операция блокирует новые bootstrap, session incarnation, replacement и logical-stream admission. Существующие carrier exchanges и streams продолжаются, точный session replay остаётся доступным, а отказ bridge сохраняется на decoy route.
- `POST /v1/runtime/web/lifecycle/drain` с `{"runtime_instance":"...","timeout_secs":30}`. Операция возвращает `202`, сохраняет ту же admission fence закрытой и асинхронно ожидает sessions, streams и session-owned WebSockets. На monotonic deadline она сигнализирует close всем оставшимся live sessions и сообщает `force_closing`, пока не подтверждён ноль. И естественное, и принудительное завершение остаются закрытыми до resume. Одновременный второй drain возвращает `409 web_lifecycle_in_progress`.
- `POST /v1/runtime/web/lifecycle/resume` с `{"runtime_instance":"..."}`. Операция отменяет активный drain и повторно открывает только operator admission. Если forced close уже committed, прежнюю cancellation sessions нельзя отменить. Gates config, user, generation и terminal shutdown по-прежнему имеют приоритет.
- `POST /v1/runtime/web/sessions/close` с одним selector: `{"kind":"refs","session_refs":[...]}`, `{"kind":"filter",...}` или `{"kind":"all"}`. Точные refs ограничены 200, filter должен быть непустым, одновременно выполняется не более одной close operation, а `all` отклоняется, пока effective issuance включён. Ответ `202` содержит `operation_id`; опрашивайте `GET /v1/runtime/web/operations/{operation_id}`. Операция chunks по 128 сканирует только сессии не выше submission high-water mark.
- `POST /v1/runtime/web/debug/clear` с `{"runtime_instance":"..."}`. Ответ содержит число удалённых записей, bytes, всё ещё удерживаемые уже отрисовываемыми snapshots, и новый epoch. In-flight writers старого epoch не могут снова заполнить ring.
- `POST /v1/runtime/web/carrier-learning/reset` с тем же body. Операция очищает сохранённый process-local evidence и увеличивает learning epoch; уже замороженные attempt chains и активные сессии не изменяются.

Для детерминированного close-all отправьте patch `{"web":{"enabled":false}}` с включённым runtime reload, дождитесь `runtime.manager.issuance_enabled = false`, отправьте selector `all` с тем же `runtime_instance` и опрашивайте operation до terminal state. Отключение WEB прекращает новую выдачу bootstrap/session credentials, но никогда не закрывает существующие сессии неявно.

Operator lifecycle относится только к WEB и не меняет глобальные readiness/liveness, нативные TCP/Unix listeners, TLS-fronting или fallback behavior. Reservation WebSocket lane, сделанный до pause, уже считается допущенной logical work: он может завершить open и продолжает учитываться в drain. Lifecycle rejection не расходует rate/quota tokens и не добавляет relay lock в hot path.

### Серверная WEB-отладка

Включите bounded сбор в конфигурационном файле, которому принадлежит эта секция:

```toml
[web.debug]
enabled = true
capture_lifecycle = true
sideband = true
capture_headers = true
capture_timings = true
capture_frames = true
body_capture = "metadata"
body_prefix_bytes = 4096
decoy_body_prefix_bytes = 4096
default_window_secs = 180
max_window_secs = 3600
```

Откройте `http://127.0.0.1:9091/web-status`, используя те же whitelist непосредственных peers и точный header `Authorization`, что и для API. Завершающий slash разрешён. Допускается только `GET`. Страница поддерживает фильтры `window_secs`, канонический `ip`, числовой `session`, регистронезависимый `user_agent` и `key`. Повторяйте `group_by=ip`, `group_by=session`, `group_by=user_agent` или `group_by=key` для построения сгруппированных сводок; `limit` ограничен диапазоном `1..=1000`. HTTP rows раскрываются от request до response с method, path, очищенными headers, метаданными или байтами body, timing points, frames и типизированными lifecycle events, включая carrier attempt, commit, healthy, reported failure, точную причину close, peer gap и переходы predecessor восстановленной session. Для WebSocket добавляются очищенный handshake `GET` → `101` и bounded per-message direction, message type, payload/body capture, processing time, connection/lane identifiers и разобранные inner frames. Raw subprotocol и session tokens никогда не сохраняются.

Process-owned кольцевой буфер переживает замену runtime generation. Изменения capture policy очищают несовместимые сохранённые записи; изменения только окна наблюдения этого не делают. По умолчанию кольцо ограничено 65536 записями и 64 MiB сохранённых плюс находящихся в обработке данных, HTML-response — 8 MiB, grouping — 1024 группами; одновременно page permits могут удерживать не более двух response bodies. Изменяйте `web.limits.debug_records_capacity` или `web.limits.debug_bytes_global` только с перезапуском процесса. Hot prefix, который помещается только в одновременно увеличенную restart-only ёмкость, откладывается до этого перезапуска.

`body_capture = "off"` исключает bodies, `metadata` сохраняет длину и terminal state, `prefix` — настроенные prefixes, а `full` — распознанные carrier bodies до `web.limits.max_body_bytes`. Обычные decoy bodies даже в режиме `full` ограничены `decoy_body_prefix_bytes`. Queries и raw capabilities никогда не сохраняются; значения credential headers исключаются; известные WEB capabilities и bearer tokens удаляются из захваченных bodies; отображаемый ключ является несекретным domain-separated fingerprint. Timing заканчивается на polling Hyper body и не означает kernel flush или TCP acknowledgment.

Sideband reporting сгенерированного bridge действует, только когда `enabled`, `capture_lifecycle` и `sideband` одновременно равны `true`. Policy поддерживает hot reload, но reporter содержат только новые выданные bridge pages. Каждая страница может не более одного раза сообщить каждое из восьми фиксированных событий: `runtime_started`, `status_posted`, `hello_received`, `boundary_timeout`, `hello_timeout`, `client_close_before_hello`, `document_unloaded_before_hello` и `runtime_error_before_hello`. Reports являются точными каноническими JSON POST к `BASEapi/v1/diagnostic`, используют bootstrap bearer, не расходуя его, и не участвуют в carrier framing. Malformed или unauthenticated reports следуют по очищенному decoy path.

После атомарного изменения TOML-файла администратором или системой управления конфигурацией задайте в `TELEMT_API_AUTH` точное значение `auth_header` и отправьте наблюдаемый generation reload:

```bash
curl -sS -X POST http://127.0.0.1:9091/v1/system/reload \
  -H "Authorization: ${TELEMT_API_AUTH}" \
  -H 'Content-Type: application/json' \
  -d '{"mode":"drain","timeout_secs":30,"failure_policy":"rollback"}'

# Use data.reload_id from the response.
curl -sS http://127.0.0.1:9091/v1/system/reload/RELOAD_ID \
  -H "Authorization: ${TELEMT_API_AUTH}"
```

Терминальный статус `succeeded` подтверждает активацию runtime. Изменённые carrier, candidates, deadlines или learning policy используют новые bridge sessions; существующие сессии и начатые attempt chains не мигрируют. Если `deferred_process_fields` содержит `server.listeners`, `web.allow_wildcard_hosts` или `web.limits`, файл валиден и сохранён, но эти настройки всё ещё требуют перезапуска Telemt.

Операции с access users используют существующие endpoints, например:

```bash
curl -sS -X POST http://127.0.0.1:9091/v1/users/web-user/disable \
  -H "Authorization: ${TELEMT_API_AUTH}"

curl -sS -X POST http://127.0.0.1:9091/v1/users/web-user/rotate-secret \
  -H "Authorization: ${TELEMT_API_AUTH}" \
  -H 'Content-Type: application/json' \
  -d '{}'
```

После ротации секрета config watcher перестраивает WEB capabilities. Users API возвращает секрет, но не URL `tg://webproxy`; соберите ссылку из настроенного hostname и представления `plain` или `dd` соответствующего профиля. Перед удалением пользователя, на которого ссылается WEB-профиль, сначала удалите и примените этот профиль, чтобы итоговая конфигурация оставалась валидной.

Полный контракт запросов, revisions, ошибок и всех user endpoints приведён в [документации Control API](../Architecture/API/API.md).

## Инварианты развёртывания

- Никогда не публикуйте plain HTTP WEB-listener в недоверенной сети. Закрепите это host firewall rules, даже если listener использует loopback.
- Отключите логирование request target и authorization на TLS-терминаторе либо используйте проверенный формат с редактированием. Raw queries содержат bridge capabilities, а `Authorization` — bootstrap или session bearer credentials.
- Если URI или headers содержат активную capability либо любой подлинный token, выпущенный текущим процессом, но запрос не соответствует carrier contract, Telemt отклоняет его локально. Такие credentials никогда не пересылаются в decoy. Просто канонически выглядящее поддельное значение остаётся обычным decoy traffic.
- Сохраняйте один стабильный публичный адрес на vhost. Если DNS возвращает несколько ingress addresses, каждый deployment должен использовать адрес своего внешнего пути.
- Bootstrap- и session-registries локальны для процесса. Для multi-process или multi-host upstream pool нужна affinity всего vhost: исходный и recovery root GET, создание сессии, uplink, downlink, WebSocket Upgrade и DELETE. Одному процессу Telemt дополнительная affinity не нужна.
- Неиспользованный bootstrap переживает reload конфигурации, только если остаётся активной точная identity профиля: host, `public_addr`, user, secret mode, carrier candidates, negotiation deadlines и capability. Уже созданные sessions сохраняют неизменные carrier и identity профиля и остаются lifecycle-bounded.
- Decoy входит в anti-probing contract. До распространения ссылок проверьте через публичный TLS endpoint его обычный ответ 404 и response timing.

## Первичная проверка

1. Запустите пересобранный Telemt с WEB-конфигурацией и убедитесь, что приватный listener привязан.
2. Через публичный TLS endpoint проверьте, что GET корня настроенного base, alias без завершающего слеша, неизвестный path внутри base и некорректный query `bridge` возвращают ожидаемый обычный сайт или настроенный decoy без синтезированного redirect. При prefix-only cohosting также убедитесь, что TLS-терминатор сохраняет base path побайтно.
3. Убедитесь, что Telemt получает один корректно разбираемый адрес `X-Forwarded-For` и `Host: proxy.example.com` либо `Host: proxy.example.com:443`.
4. Импортируйте напечатанную ссылку `tg://webproxy` в целевую сборку Telegram Desktop и установите соединение через прокси.
5. Для `https-lanes` подтвердите согласование HTTP/2 на публичном connection и проверьте как минимум два одновременных logical streams; приватный hop к Telemt остаётся HTTP/1.1.
6. Для `websocket` подтвердите один response `101`, binary relay traffic и RFC 6455 Ping/Pong после 25 секунд. Для `websocket-lanes` проверьте как минимум два одновременных stream sockets и убедитесь, что закрытие или повреждение одной lane не закрывает sibling или parent session.
7. Проверьте один HTTP replay и пересоздание session после scheduler gap, затем удерживайте long poll дольше 25 секунд, чтобы frontend timeouts не обрывали carrier.
8. Проверяйте лимиты пользователя и logical MTProxy connections по logical-stream counters, а не по числу HTTP connections.
9. При включённом auto-negotiation проверьте настроенную последовательность, replay точно той же попытки после намеренно потерянного response, terminal-поведение после commit и lifecycle rows `carrier_committed`/`carrier_healthy` в `/web-status`. Убедитесь, что нативный клиент без metadata использует фиксированный `carrier` без automatic response headers, а явные capabilities остаются неизменными.

## Диагностика

| Симптом | Что проверить |
| --- | --- |
| WEB-конфигурация валидна на диске, но поведение listener’а не изменилось | Проверьте `deferred_process_fields`; listener и `web.allow_wildcard_hosts` / `[web.limits]` требуют перезапуска. |
| Carrier-запросы попадают в decoy | Проверьте точный vhost, secret mode ссылки, CIDR непосредственного proxy и единственное корректно разбираемое значение `X-Forwarded-For`. |
| Ссылка перестала работать после изменения `base_path` | Импортируйте заново напечатанную path-ссылку и убедитесь, что полный новый prefix без изменений попадает в Telemt. Существующие sessions могут восстановиться только через новый точный base; старые capabilities нельзя использовать повторно. |
| `/telegram/web` перенаправляет на `/telegram/web/` | Добавьте точный non-WEB handler для path без слеша. В WEB-контракт Telemt входит только настроенное поддерево с завершающим слешем. |
| Downlink `https-lanes`, участвующий в гонке, попадает в decoy с `404` | Убедитесь, что он начинается с `X-Down-Cursor: 0`, сохраняйте `X-Lane-ID` и задайте `lane_open_wait_secs` выше наблюдаемого разрыва down-before-`OPEN`. Продвинутый cursor отсутствующей lane намеренно закрывается fail-closed. |
| Auto-negotiation переходит дальше после уже принятого трафика | Такое поведение некорректно. Проверьте аутентифицированный replay `X-Carrier-State` и lifecycle row commit carrier; ответ `committed` или `healthy` terminal и требует новой сессии. |
| Long polls разрываются через фиксированный интервал | Поднимите client, server, send и read timeouts NGINX/HAProxy/Caddy выше `web.timeouts.long_poll_secs`. |
| WebSocket Upgrade попадает в decoy вместо `101` | Сохраните HTTP/1.1 `Connection: Upgrade`, `Upgrade: websocket`, единственный точный `Sec-WebSocket-Protocol` и канонический bodyless request по настроенному base плюс `/api/v1/ws`. Также проверьте соответствие carrier/session и process connection reserve. |
| Один stream `websocket-lanes` закрылся, а siblings остались подключены | Это штатная failure boundary. Проверьте message/frame rows этой lane в `/web-status`; malformed, cross-lane, write-timeout и backend-close закрывают только затронутую lane. |
| `/web-status` пуст | Убедитесь, что `[web.debug].enabled = true`, примените конфигурацию, выберите окно в пределах `max_window_secs` и создайте новый WEB-трафик после изменения policy. |
| `https-lanes` работает, но streams всё ещё блокируют друг друга | Проверьте согласование публичного HTTP/2, сохранение `X-Lane-ID` и достаточное число upstream connections TLS-терминатора для параллельных приватных HTTP/1.1 polls. |
| Telegram Desktop отклоняет ссылку | Не указывайте порт, используйте валидный FQDN, внешний порт 443 и только `plain` или `dd`. |
| Один узел работает, но load-balanced pool нестабилен | Настройте affinity всего vhost: WEB credential registries локальны для процесса. |
