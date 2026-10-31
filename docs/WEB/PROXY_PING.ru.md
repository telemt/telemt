# Ping в списке прокси: RPC Ping/Pong и задержки WEB

[English](PROXY_PING.en.md) | [Русский](PROXY_PING.ru.md) | [Deutsch](PROXY_PING.de.md)

Наблюдаемые **1000–1500 мс для WEB против 50–150 мс для Classic/DD/EE** могут относиться к измерениям с разными границами. В Android локальный сокет WEB-проверки становится готов раньше, чем обязательно готов удалённый WEB-поток. Оставшееся открытие потока и работа транспорта могут попасть в показанный результат. Код не задаёт фиксированный секундный штраф для каждого успешного WEB-ping.

Эти числа предоставлены оператором и не воспроизведены при подготовке документа. Анализ исходников подтверждает механизмы, но не устанавливает причину задержки в конкретном развёртывании.

## Клиенты и измерения

Проверено **2026-10-31** по DrKLO Android `3de37c8cfb039452be7398909461da6288babf15` и Telegram iOS `279f89e4d4f63f17227bf877dc3d8990f22ecd58`. Установленные релизы и форки могут отличаться.

| Измерение | Что охватывает | Поведение WEB |
| --- | --- | --- |
| Ping в списке прокси Android | Зашифрованный MTProto `TL_ping` / `TL_pong` через проверяемый прокси | Отдельный WEB-транспорт проверки, затем нативная проверка через локальный сокет. |
| Ping в списке прокси iOS | Проверка связности `req_pq` / `resPQ`; отсчёт от `connectionOpened` | Записи `.web` исключены из проверки; неактивный WEB-прокси отображается как непроверенный. |
| ICMP ping | IP echo до выбранного хоста с учётом маршрутизации и политики ICMP | Не измеряет прикладную пересылку и Telegram DC. |
| WEB transport `FRAME_PING` / `FRAME_PONG` или WebSocket keepalive | Жизнеспособность транспорта/сессии | Это не отображаемый Android результат MTProto. |
| Telemt ME RPC Ping/Pong | Один путь от Telemt до ME, включая локальную очередь writer и планирование flush | Не включает клиент, WebView и публичный TLS-фронтенд. |

Источники: [точка входа Android][android-entry], [нативные запросы][android-native], [фильтр iOS][ios-filter], [проверка iOS][ios-probe], [интерфейс iOS][ios-ui]. Поэтому формулу WEB-ping Android нельзя переносить на WEB-строку текущего iOS.

Android показывает последний результат проверки без медианы или EMA и пропускает новую проверку, если предыдущая была менее двух минут назад. У подключённого прокси тоже может отображаться сохранённый результат: это не непрерывное измерение RTT активной сессии. WEB-проверка создаёт собственный транспорт, а не использует напрямую активный транспорт приложения. См. [обновление списка][android-ui] и [WEB-транспорт][android-transport].

## Где Android запускает и останавливает таймер

Для Classic/DD/EE нативный callback готовности приходит после удалённого TCP-соединения и необходимой подготовки транспорта прокси, включая EE FakeTLS. Обработка запроса обновляет временную метку перед отправкой или повторной отправкой проверки. Поэтому обычный успешный замер исключает это начальное установление транспорта, но включает последующую пересылку и обратный путь. См. [готовность сокета][android-socket] и [обработку запросов][android-native].

Для WEB запуск моста, начальная HTTPS-загрузка, HELLO/WELCOME и дополнительные **500 мс** ожидания предшествуют `native_checkProxy`; эти 500 мс не прибавляются к показанному ping. WELCOME подтверждает WEB-сессию, а не готовность потока до Telegram DC. Затем нативная проверка подключается к `127.0.0.1`: готовность этого сокета не ждёт завершения удалённого OPEN. Java accept/OPEN и обновление нативной временной метки могут выполняться в разном порядке. Учитывается только работа, оставшаяся внутри интервала измерения. См. [порядок проверки][android-tester], [локальный сокет и WELCOME][android-transport], [создание серверной сессии][session] и [обработку потока][backend].

Схемы показывают обычный успешный путь, но не гарантируют порядок событий между потоками выполнения:

```mermaid
sequenceDiagram
    participant C as Android native checker
    participant P as Classic/DD/EE proxy
    participant D as Telegram DC
    C->>P: DNS / TCP / proxy transport setup
    Note over C,P: Remote transport ready; measurement timestamp refreshed
    C->>P: Encrypted TL_ping
    P->>D: Relay
    D->>P: TL_pong
    P->>C: Relay
    Note over C: Display elapsed time from latest request timestamp
```

```mermaid
sequenceDiagram
    participant C as Android native checker
    participant B as Local socket / Java / WebView
    participant T as TLS frontend / Telemt
    participant D as Telegram DC
    B->>T: Bridge load, HELLO / session creation
    T->>B: WELCOME
    Note over B: Wait 500 ms before native_checkProxy
    C->>B: Connect to 127.0.0.1
    Note over C,B: Local socket ready; measurement timestamp refreshed
    Note over B,T: OPEN may race with the native timestamp update
    C->>B: MTProxy header and encrypted TL_ping
    B->>T: OPEN / DATA over selected carrier
    T->>D: Stream setup and relay via Direct / ME
    D->>T: TL_pong
    T->>B: Downlink DATA
    B->>C: Local socket delivery
    Note over C: Display elapsed time from latest request timestamp
```

`TL_pong` завершает замер относительно последней временной метки запроса. Принудительная обработка или повторная отправка могут обновить её: результат не обязательно равен полному времени неудачной попытки с повторами. Проверка использует [существующий ключ авторизации DC][android-key]; полный обмен для создания нового ключа MTProto не является обязательной частью каждой проверки.

## Вклад TLS

Публичное TLS-соединение завершается в NGINX, HAProxy или Caddy. Telemt получает обычный HTTP/1.1 на приватном listener. Внешний HTTP/2 и внутренний HTTP/1.1 — разные соединения; версии протокола на этих участках могут различаться. EE FakeTLS — маскирующий транспорт MTProxy, а не браузерное HTTPS-соединение с проверкой сертификата. WEB переносит plain/DD MTProxy; EE не является форматом секрета WEB. См. [руководство WEB](WEB_PROXY.ru.md).

Для нового соединения без потерь обычный TCP-handshake занимает примерно один RTT между клиентом и фронтендом. Полный TLS 1.3 handshake обычно добавляет один RTT, полный TLS 1.2 — два. Это оценка обменов протокола без DNS, обработки, проверки сертификата, планирования и повторной передачи, а не измеренный бюджет задержки WEB. Возобновление TLS-сессии может изменить обмен. См. [TLS 1.3][tls13] и [TLS 1.2][tls12].

Начальный TLS для загрузки моста обычно происходит до измерения Android. Дополнительные HTTP-соединения или WebSocket Upgrade могут оказаться внутри него; повторное использование соединений нужно подтверждать трассировкой. Постоянное HTTPS-соединение и установленный WebSocket не выполняют новый TLS-handshake для каждого ping. `cache: 'no-store'` управляет кешированием, а не повторным использованием TCP/TLS. Для объяснения и диагностики не требуется отключать проверку сертификатов или включать TLS 0-RTT. См. [постоянные HTTP-соединения][http1] и [запросы моста][request].

## HTTP, WebSocket и другие источники задержки

| Фактор | Влияние и подтверждение |
| --- | --- |
| HTTP uplink | Генерируемый мост предлагает `X-Telemt-Up-Window: 4`; сервер принимает 1–4, при отсутствии согласования используется 1. Окно 1 ждёт ACK перед следующей загрузкой, окно 4 допускает ограниченный параллелизм. Не весь HTTP работает по схеме «отправить и ждать». См. [согласование][runtime] и [обработчик сессии][session]. |
| Первый downlink | `/down` может запускаться одновременно с `/up`; обязательного дополнительного последовательного ACK RTT нет. Первичная доставка в нативный клиент ждёт первого корректного upload ACK/commit. Кадры доставляются по мере поступления. См. [conveyor][conveyor] и [downlink][downlink]. |
| Long polling | `long_poll_secs=25` ограничивает ожидание при отсутствии данных. Готовые данные немедленно будят poll. Промежутки между запросами и занятые слоты соединений браузера всё же могут задержать доставку. См. [серверный polling][poll]. |
| Общие ресурсы транспорта | `https` использует общую очередь загрузки; `https-lanes` разделяет логические линии. WebSocket после Upgrade передаёт кадры без POST на каждый кадр; `websocket-lanes` разделяет сокеты. Сеть, flow control и ресурсы WebView остаются общими. HTTP/2 мультиплексирует потоки, но не устраняет все задержки от перегрузки и flow control. См. [HTTP/2][http2] и [руководство по транспортам](WEB_PROXY.ru.md). |
| Буферизация фронтенда | Буферизация запросов/ответов или отсутствие поддержки streaming/Upgrade могут задерживать короткие сообщения. Сверьте настройки с существующим примером NGINX, сохраняя маршрутизацию, аутентификацию и лимиты. |
| Планирование клиента | Java accept/read, UI dispatch, WebView/JavaScript и возврат в нативный код добавляют очереди. Нагрузка CPU, энергосбережение и смена мобильной сети могут усиливать задержки. |
| Пересылка и сеть | Могут учитываться оставшийся admission потока, внутренний MTProxy-handshake, подключение Direct или регистрация ME, ответ Telegram, потери/повторная передача и очереди. Готовая WEB-сессия не доказывает готовность upstream. |
| Ошибки и повторы | Telemt может вернуть `503` с `Retry-After: 1`. Мост учитывает его; для других повторов backoff начинается с 250 мс и удваивается до 2000 мс плюс jitter примерно до 25%, в пределах бюджета повторов. Повторяемые HTTP-статусы включают 408/429/502/503/504. Прежде чем объяснять секундную ступень этим механизмом, нужно увидеть события в трассировке. См. [ответы][response] и [повторы][request]. |

Дедлайны не являются обязательными паузами. Стандартные 10 с для запроса моста, 90 с бюджета повторов, 30 с ожидания первого байта потока и 10 с handshake потока нельзя складывать в обычный ping. `carrier_probe_coalesce_ms=0` отключает соответствующую дополнительную задержку объединения проб. Дедлайны переключения транспорта относятся к неудачным попыткам, а не к каждому успешному обмену. См. [значения по умолчанию](../../src/config/types/web/defaults.rs).

Условно WEB-замер включает **оставшуюся подготовку + передачу через транспорт и сеть + очереди + ответ Telegram + задержки повторов, попавшие внутрь таймера**. Этапы перекрываются; складывать все таймауты или назначать отдельный RTT каждому HTTP endpoint некорректно. Готовый транспорт может сократить подготовку, но Android проверяет прокси через отдельный транспорт. WebSocket не всегда быстрее; используйте только поддерживаемые клиентом транспорты. Для совместимости с текущим iOS используется `https`.

## Диагностика с сохранением защит

1. Запишите клиент/сборку, версию Android WebView, транспорт, публичный endpoint, семейство IP, сеть, маршрут Direct/ME, DC и нагрузку. Сравнивайте при одинаковых условиях. Учитывайте двухминутное кеширование Android: повторное чтение интерфейса не означает новый замер.
2. Разделяйте три эксперимента: новую проверку в списке прокси; новый логический поток на готовом транспорте; прикладной RPC в установленной MTProto-сессии. Последние два требуют подходящих средств измерения в клиенте и не предоставляются автоматически списком прокси. Собирайте отдельные замеры и распределения, а не сравнивайте единичный холодный замер с прогретым.
3. Используйте аутентифицированный `GET /web-status` и существующие настройки `[web.debug]`: `capture_timings=true`, `capture_frames=true`, `body_capture="metadata"`. Включите ограниченный сбор по [руководству диагностики WEB](WEB_PROXY.ru.md), затем восстановите предыдущее состояние. Payload, capabilities и секреты для этой задачи не нужны.
4. Сопоставьте создание сессии, выбор/commit/ошибку транспорта, `stream_admitted`, `stream_first_byte`, `handshake_succeeded`, OPEN/DATA, HTTP-статусы и повторы. `relay_started` предшествует работе с upstream и не означает готовность DC. `GET /v1/runtime/web/status` и `GET /v1/runtime/web/sessions` дают контекст ёмкости и давления очередей, а не сквозной RTT.
5. `request_body_us`, `response_ready_us` и `response_body_us` — смещения от входа в обработчик. Это не независимые длительности для сложения и не моменты отправки в сеть или TCP ACK от другой стороны. Сравнивайте смещения там, где они записаны и имеют подходящий смысл. См. [определения timing-полей][timings].
6. Добавьте измерения соединений/TLS/запросов фронтенда и временные метки клиента, чтобы найти задержку вне Telemt. Проверьте повторное использование соединений, согласованный HTTP, буферизацию и Upgrade. Sideband-события запуска моста/HELLO не дают полную временную шкалу клиента. Для сравнения разных хостов синхронизируйте часы либо используйте локальные длительности.
7. При ME сопоставьте существующий trace `ME RTT sample` (`rtt_ms`, `ema_ms`, `base_ms`, `degraded`). Метка ставится до очереди writer/flush; EMA состоит из 80% прежнего значения и 20% нового замера. Планирование keepalive до этой метки не учитывается. Низкий ME RTT при высоком Android ping указывает на работу вне измеренного участка ME, но не определяет конкретную причину. См. [writer][writer] и [reader][reader].

Примеры интерпретации: быстрая обработка Telemt при поздней доставке клиенту направляет проверку к фронтенду, сети и очередям клиента; `503` вместе с `Retry-After: 1` подтверждает задержку повтора; длительная работа upstream требует изучения Direct/ME. Ни один из признаков сам по себе не доказывает, что 1000–1500 мс вызваны криптографией TLS. При сборе данных сохраняйте совместимость, проверку сертификатов, лимиты admission и backpressure.

## Границы подтверждения

Документ описывает изученные исходники, а не сквозной тест на устройствах. Ссылки Android/iOS закрепляют указанные ревизии; ссылки Telemt ведут к сопровождающей документ реализации рабочего дерева, включая локальные WEB-изменения, и не утверждают идентичность всех опубликованных пакетов. Документация не меняет клиент, сервер, таймауты или настройки безопасности.

[android-entry]: https://github.com/DrKLO/Telegram/blob/3de37c8cfb039452be7398909461da6288babf15/TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java#L752-L765
[android-tester]: https://github.com/DrKLO/Telegram/blob/3de37c8cfb039452be7398909461da6288babf15/TMessagesProj/src/main/java/org/telegram/utils/proxy/WebProxyConnectionTester.java#L111-L172
[android-transport]: https://github.com/DrKLO/Telegram/blob/3de37c8cfb039452be7398909461da6288babf15/TMessagesProj/src/main/java/org/telegram/utils/proxy/WebProxyTransport.java
[android-native]: https://github.com/DrKLO/Telegram/blob/3de37c8cfb039452be7398909461da6288babf15/TMessagesProj/jni/tgnet/ConnectionsManager.cpp
[android-socket]: https://github.com/DrKLO/Telegram/blob/3de37c8cfb039452be7398909461da6288babf15/TMessagesProj/jni/tgnet/ConnectionSocket.cpp
[android-key]: https://github.com/DrKLO/Telegram/blob/3de37c8cfb039452be7398909461da6288babf15/TMessagesProj/jni/tgnet/Datacenter.cpp#L1312-L1323
[android-ui]: https://github.com/DrKLO/Telegram/blob/3de37c8cfb039452be7398909461da6288babf15/TMessagesProj/src/main/java/org/telegram/ui/ProxyListActivity.java#L671-L687
[ios-filter]: https://github.com/TelegramMessenger/Telegram-iOS/blob/279f89e4d4f63f17227bf877dc3d8990f22ecd58/submodules/TelegramCore/Sources/Network/ProxyServersStatuses.swift#L54-L65
[ios-probe]: https://github.com/TelegramMessenger/Telegram-iOS/blob/279f89e4d4f63f17227bf877dc3d8990f22ecd58/submodules/MtProtoKit/Sources/MTProxyConnectivity.m#L57-L99
[ios-ui]: https://github.com/TelegramMessenger/Telegram-iOS/blob/279f89e4d4f63f17227bf877dc3d8990f22ecd58/submodules/SettingsUI/Sources/Data%20and%20Storage/ProxyListSettingsController.swift#L273-L310
[tls13]: https://datatracker.ietf.org/doc/html/rfc8446#section-2
[tls12]: https://datatracker.ietf.org/doc/html/rfc5246#section-7.3
[http1]: https://www.rfc-editor.org/rfc/rfc9112#section-9.3
[http2]: https://datatracker.ietf.org/doc/html/rfc9113#section-5
[session]: ../../src/web/http/session.rs
[backend]: ../../src/web/session/backend.rs
[runtime]: ../../src/web/bridge/runtime.js
[conveyor]: ../../src/web/bridge/conveyor.js
[downlink]: ../../src/web/bridge/downlink.js
[poll]: ../../src/web/session/downlink.rs
[request]: ../../src/web/bridge/request.js
[response]: ../../src/web/http/response.rs
[timings]: ../../src/web/trace/types.rs
[writer]: ../../src/transport/middle_proxy/pool_writer.rs
[reader]: ../../src/transport/middle_proxy/reader.rs
