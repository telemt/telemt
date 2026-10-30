# Runtime-модель Telemt

## Область описания
Документ фиксирует ключевые runtime-понятия пайплайна Middle-End (ME) и оркестрации вокруг него.

Фокус:
- `ME Pool / Reader / Writer / Refill / Registry`
- `Adaptive Floor`
- `Trio-State`
- `Generation Lifecycle`

## Базовые сущности

### ME Pool
`ME Pool` — центральный оркестратор всех Middle-End writer-ов.

Зона ответственности:
- хранит инвентарь writer-ов по DC/family/endpoint;
- управляет выбором writer-а и маршрутизацией;
- ведёт состояние поколений (`active`, `warm`, `draining` контекст);
- применяет runtime-политики (floor, refill, reconnect, reinit, fallback);
- отдаёт сигналы готовности для admission-логики (conditional accept/cast).

Что не делает:
- не декодирует клиентский протокол;
- не реализует бизнес-политику пользователя (квоты/лимиты).

### ME Writer
`ME Writer` — долгоживущий ME RPC-канал к конкретному endpoint (`ip:port`), у которого есть:
- канал команд на отправку;
- связанный reader loop для входящего потока;
- флаги состояния/деградации;
- метаданные contour/state и generation.

Writer — это фактический data-plane носитель клиентских сессий после бинда.

### ME Reader
`ME Reader` — входной parser/dispatcher одного writer-а:
- читает и расшифровывает ME RPC-фреймы;
- проверяет sequence/checksum;
- маршрутизирует payload в client-каналы через `Registry`;
- обрабатывает close/ack/data и обновляет телеметрию.

Инженерный принцип:
- Reader должен оставаться неблокирующим.
- Backpressure одной клиентской сессии не должен останавливать весь поток writer-а.

### Refill
`Refill` — механизм восстановления покрытия writer-ов при просадке:
- восстановление на том же endpoint в первую очередь;
- восстановление по DC до требуемого floor;
- опциональные outage/shadow-режимы для хрупких single-endpoint DC.

Refill работает асинхронно и не должен блокировать hotpath.

### Registry
`Registry` — маршрутизационный индекс между ME и клиентскими сессиями:
- `conn_id -> канал ответа клиенту`;
- map биндов `conn_id <-> writer_id`;
- send routes writer-ов и их replacement state;
- снимки активности writer-ов и idle-трекинг.

Ключевые инварианты:
- один `conn_id` маршрутизируется максимум в один активный канал ответа;
- потеря writer-а приводит к безопасному unbind/cleanup и отправке close;
- именно `Registry` является источником истины по активным ME-биндам.
- binding lock registry линеаризует client binds, публикацию writer-а и переход, закрывающий replacement victim для новых binds.

Каждый клиентский маршрут с lease резервирует ёмкость очистки на всё время жизни. При его удалении горячий маршрут убирается синхронно, а очистка bindings передаётся ограниченному worker с уже выданным резервом. Отмена не должна оставлять маршрут или терять cleanup permit. Нулевой `server.max_connections` снимает общий клиентский лимит и не уменьшает эту ёмкость до 128; положительные значения сохраняют запас для очистки. Целевые количества writer-ов и бюджеты Data Plane не меняются.

## Adaptive Floor

### Что это
`Adaptive Floor` — runtime-политика, которая динамически меняет целевое число writer-ов на DC в зависимости от активности, а не держит всегда фиксированный статический floor.

### Зачем
Цели:
- уменьшить churn на idle-трафике;
- сохранить достаточную прогретую ёмкость для быстрых всплесков;
- снизить лишние reconnect-штормы на нестабильных endpoint.

### Модель поведения
- при активности floor стремится к статическому требованию;
- при длительном idle floor может снижаться до безопасного минимума;
- grace/recovery окна не дают системе "флапать" слишком резко.

### Ограничения безопасности
- нельзя нарушать минимальный floor выживаемости DC-группы;
- refill обязан быстро нарастить покрытие по запросу;
- адаптация не должна принудительно ронять уже привязанные healthy-сессии.

## Trio-State

`Trio-State` — контурная роль writer-а:
- `Warm`
- `Active`
- `Draining`

### Семантика состояний
- `Warm`: writer подключён и валиден, но не основной для новых биндов.
- `Active`: приоритетный для новых биндов и обычного трафика.
- `Draining`: новые обычные бинды не назначаются; текущие сессии живут до правил graceful-вывода.

### Логика переходов
- `Warm -> Active`: когда достигнуты условия покрытия/готовности.
- `Active -> Draining`: при swap поколения, замене endpoint или контролируемом выводе.
- `Draining -> removed`: после естественного опустошения, при effective force-close deadline либо через threshold/control-path eviction. `me_pool_drain_ttl_secs` — порог предупреждений и нижняя граница force-close, а не самостоятельный deadline удаления.

Writer replacement имеет отдельный registry-local lifecycle: `Open -> Preparing -> Retiring`. `Preparing` исключает дублирующую replacement work, но намеренно разрешает новые client binds. Commit повторно проверяет victim под binding lock; `Retiring` отклоняет новые binds. Отмена незакоммиченного reservation возвращает `Open`, а contour writer-а независимо остаётся `Warm`, `Active` или `Draining`.

Такое разделение снижает SPOF-риски и делает cutover предсказуемым.

## Generation Lifecycle

Generation изолирует эпохи пула при reinit/reconfiguration.

### Фазы жизненного цикла
1. `Bootstrap`: поднимается начальный набор writer-ов.
2. `Warmup`: создаётся и валидируется новое поколение.
3. `Activation`: generation атомарно становится active после commit-time проверки настроенной доли coverage и stale-binding policy.
4. `Drain`: подходящие по policy старые writers сохраняются как ограниченный stale fallback; покрытые старые writers становятся недоступны для новых binds и входят в retirement во время commit, после чего могут закрыться сразу по его завершении.
5. `Retire`: draining writers удаляются после опустошения либо по force-close, threshold или явной control policy.

### Операционные гарантии
- activation атомарна, но committed topology может содержать отсутствующие DC-family groups, если достигнут `me_pool_min_fresh_ratio` и `me_bind_stale_mode` разрешает ограниченный stale fallback. Режим `never` запрещает отсутствующие groups;
- generation handover ограничен policy и не даёт универсальной zero-drop гарантии: покрытые старые writers могут retire с закрытием их sessions сразу после commit, а для непокрытых groups сохраняются только выбранные stale writers;
- pending generation владеет только writer-ами, принятыми для её generation и текущей endpoint map; устаревшие задачи не могут публиковать состояние в более новую generation;
- pending generation привязана к desired-map hash и endpoint revision и переиспользуется не более 1800 секунд;
- replacement сначала подготавливает successor; под единым binding guard commit сначала переводит predecessor в `Retiring`, а затем регистрирует successor до освобождения guard. Неудачная или отменённая до этой границы подготовка сохраняет predecessor и освобождает reservation;
- pool-state telemetry публикует число и дефицит pending writers, отсутствующие DC-family groups, актуальность map, orphan warm writers и счётчики фаз replacement `preparing`/`retiring`.

### Готовность и приём клиентов
Готовность пула не равна "все endpoint полностью насыщены".
Типичная стратегия:
- открыть admission при минимально достаточном alive-покрытии по DC;
- параллельно продолжать saturation для multi-endpoint DC.

Это уменьшает startup latency и сохраняет выход на полную ёмкость.

## Как понятия связаны между собой

- `Generation` задаёт эпохи пула.
- `Trio-State` задаёт роль каждого writer-а внутри/между эпохами.
- `Adaptive Floor` задаёт, сколько ёмкости нужно сейчас.
- `Refill` — исполнитель, который закрывает разницу между desired и current capacity.
- `Registry` гарантирует корректную маршрутизацию сессий, пока всё выше меняется.

## Архитектурный подход

### Слоистая модель
Runtime специально разделён на две плоскости:
- `Control Plane`: принимает решения о целевой топологии и политиках (`floor`, `generation swap`, `refill`, `fallback`).
- `Data Plane`: исполняет транспорт сессий и пакетов (`reader`, `writer`, маршрутизация, ack, close).

Ключевое правило:
- Control Plane может менять состав writer-ов и policy.
- Data Plane должен оставаться стабильным и низколатентным в момент этих изменений.

### Модель владения состоянием
Владение разделено по доменам:
- `MePool` владеет inventory writer-ов, contour lifecycle и runtime policy state.
- Reinit coordinator владеет authority active/pending generation, привязанной к map hash и endpoint revision.
- `Registry` владеет routing-биндами клиентских сессий, send routes writer-ов и replacement state.
- `Writer task` владеет исходящей прогрессией ME-сокета.
- `Reader task` владеет входящим парсингом и dispatch-событиями.

Это ограничивает побочные мутации и локализует инварианты.

### Обязанности Control Plane
Control Plane работает событийно и policy-ориентированно:
- стартовая инициализация и readiness-gate;
- runtime reinit (периодический и/или по изменению конфигурации);
- проверки покрытия по DC/family/endpoint group;
- применение floor-политики (static/adaptive);
- планирование refill и orchestration retry;
- переходы поколений (`warm -> active`, прежний `active -> draining`).

Для него важнее детерминизм, чем агрессивная краткосрочная реакция.

### Обязанности Data Plane
Data Plane ориентирован на пропускную способность и предсказуемую задержку:
- bind клиентской сессии к writer-у;
- per-frame parsing/validation/dispatch;
- распространение ack/close;
- корректная реакция на missing conn/closed channel;
- минимальный лог-шум в hotpath.

Data Plane не должен ждать операций, не критичных для корректности текущего фрейма.

## Конкурентность и синхронизация

### Принципы конкурентности
- Изоляция по writer-у: у каждого writer-а независимые send/read loop.
- Изоляция по сессии: состояние канала локально для `conn_id`.
- Асинхронное восстановление: refill/reconnect выполняются вне пакетного hotpath.

### Стратегия синхронизации
- Для shared map используются короткие и узкие lock-секции.
- Read-heavy пути избегают длительных write-lock окон.
- Решения по backpressure локализованы на границе route/channel.
- Generation и replacement commits используют порядок locks `writers -> registry binding -> reinit coordinator`.
- После получения registry publication guard до согласованной публикации и retirement state нет cancellation point.

Цель:
- медленный consumer должен деградировать локально, не останавливая глобальный прогресс writer-а.

### Cancellation и shutdown
Reader/Writer loop должны быть cancellation-aware:
- явные cancel token / close command;
- безопасный unbind/cleanup через registry;
- RAII replacement reservations возвращают `Preparing` в `Open`, если подготовка отменена до commit;
- детерминированный порядок: stop admission -> drain/close -> release resources.

## Модель согласованности

### Согласованность сессии
Для одного `conn_id`:
- одновременно ровно один активный route-target;
- close/unbind операции идемпотентны;
- потеря writer-а не оставляет dangling-бинды.

### Согласованность поколения
Гарантии generation:
- commit повторно проверяет generation, desired-map hash, endpoint revision и fresh coverage под publication barriers;
- promotion требует `me_pool_min_fresh_ratio`; отсутствующие DC-family groups дополнительно требуют stale-binding mode, отличного от `never`;
- writers предыдущей generation сохраняются только там, где их требует выбранная stale-fallback policy. Покрытые writers становятся недоступны для новых binds при commit и могут закрыться сразу после него;
- draining writers удаляются после опустошения, при effective force-close deadline (`0` сначала выбирает safety fallback 300 секунд, после чего drain TTL остаётся нижней границей) либо по threshold/control-path eviction; один drain TTL только вызывает предупреждения.

### Согласованность политик
Изменение policy (`adaptive/static floor`, fallback mode, retries) не должно ломать инварианты маршрутизации уже активных сессий.

## Backpressure и управление потоком

### Route-level backpressure
Route-каналы намеренно bounded.
При росте нагрузки:
- кратковременный burst поглощается;
- длительная перегрузка переходит в контролируемую drop-семантику;
- все drop-сценарии должны быть прозрачно видны в метриках.

### Приоритет неблокирующего Reader
Входящий ME-reader path не должен сериализоваться из-за одной перегруженной клиентской сессии.
Практически это означает:
- использовать неблокирующую попытку route в parser loop;
- выносить тяжёлое восстановление в асинхронные side-path.

## Стратегия доменов отказа

### Отказ отдельного endpoint
Сначала применяется endpoint-local recovery:
- reconnect в тот же endpoint;
- затем замена endpoint внутри той же DC-группы (если доступно).

### Деградация уровня DC
Если DC-группа не набирает floor:
- сервис сохраняется на остаточном покрытии (если policy разрешает);
- saturation refill продолжается асинхронно в фоне.

### Потеря готовности всего пула
Если достаточного ME-покрытия нет:
- admission gate может временно закрыть приём новых подключений (conditional policy);
- уже активные сессии продолжают работать, пока их маршрут остаётся healthy.

## Архитектурные заметки по производительности

### Дисциплина hotpath
Допустимо в hotpath:
- фиксированный и дешёвый parsing/validation;
- bounded channel operations;
- precomputed/low-allocation доступ к данным.

Нежелательно в hotpath:
- повторные дорогие decode;
- широкие lock-секции с `await` внутри;
- высокочастотный подробный logging.

### Стабильность важнее пиков
Архитектура приоритетно выбирает стабильную пропускную способность и предсказуемую latency, а не краткосрочные пики ценой churn и long-tail reconnect.

## Правила эволюции модели

Чтобы расширять модель безопасно:
- новые policy knobs сначала внедрять в Control Plane;
- контракты Data Plane (`conn_id`, route/close семантика) держать стабильными;
- перед дефолтным включением проверять generation/registry инварианты;
- новые recovery/retry стратегии вводить через явный config-флаг.

## Нюансы отказов и восстановления

Завершение задачи отправки от клиента в ME или задачи доставки ME-ответов клиенту завершает связанный relay даже при бездействующем клиенте; очистка по-прежнему ограничена существующими сроками. Открытый исправный sender без трафика сам по себе не считается отказавшим.

- падение single-endpoint DC — штатный деградированный сценарий; приоритет: быстрый reconnect и, при необходимости, shadow/probing;
- idle-close со стороны peer должен считаться нормальным событием при upstream idle-timeout;
- backoff reconnect-логики должен ограничивать синхронный churn, но сохранять быстрые первые попытки;
- fallback (`ME -> direct DC`) — это переключаемая policy-ветка, а не автоматический признак бага транспорта.

## Краткий словарь
- `Coverage`: достаточное число живых writer-ов для политики приёма по DC.
- `Floor`: целевая минимальная ёмкость writer-ов.
- `Churn`: частые циклы reconnect/remove writer-ов.
- `Hotpath`: пер-пакетный/пер-коннектный путь, где любые лишние ожидания и аллокации особенно дороги.
