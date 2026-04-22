# Partial degradation для маршрутизации Middle-End

## Проблема

До этого изменения conditional admission для ME фактически работал как глобальный бинарный переключатель для новых сессий:

- если у каждого настроенного DC был хотя бы один живой ME writer, новые сессии шли через Middle-End;
- если хотя бы один настроенный DC терял покрытие по writers, система начинала двигаться к глобальному fallback.

Это было безопасно, но слишком грубо. Один деградировавший DC мог перевести на direct даже те DC, которые оставались полностью здоровыми.

## Что изменилось

Теперь Telemt разделяет два вопроса:

1. Можно ли вообще использовать ME хотя бы для части DC?
2. Можно ли использовать ME для конкретного DC, который нужен этой сессии?

Это даёт partial degradation для новых сессий:

- если готовы все покрываемые DC, Telemt ведёт себя как раньше и маршрутизирует новые сессии через Middle-End;
- если готова только часть покрываемых DC, Telemt оставляет Middle-End глобально включённым для новых сессий;
- дальше каждая новая сессия отдельно проверяет готовность именно для своего target DC;
- если для target DC есть живое ME-покрытие, сессия идёт через Middle-End;
- если для target DC живого ME-покрытия нет, только эта сессия уходит в Direct-DC.

## Архитектурная идея

Изменение специально сделано узким по области действия:

- оно не заменяет существующий глобальный `RouteRuntimeController`;
- оно не вводит новый per-session cutover state machine;
- оно только улучшает выбор маршрута для новых сессий при асимметричной деградации ME между DC.

За счёт этого сохраняется текущая модель relay и cutover, но убирается важный all-or-nothing сценарий деградации.

## Поведение во время работы

### Слой admission

ME admission gate теперь различает:

- полную готовность: у каждого покрываемого настроенного DC есть хотя бы один живой writer;
- частичную готовность: хотя бы у одного покрываемого настроенного DC есть хотя бы один живой writer;
- отсутствие готовности: ни у одного покрываемого настроенного DC нет живого writer coverage.

Если есть partial readiness, admission gate остаётся открытым, а глобальный route mode остаётся `Middle`.

### Слой выбора маршрута для сессии

Когда новая аутентифицированная сессия собирается идти через Middle-End, Telemt дополнительно проверяет, готов ли ME именно для target DC этой сессии.

- target DC готов: сессия идёт через ME;
- target DC не готов: сессия уходит в Direct-DC;
- остальные сессии это не затрагивает.

## Почему это полезно

Это даёт реальный выигрыш в боевых условиях:

- здоровые DC продолжают пользоваться преимуществами ME даже если один DC деградировал;
- локальная потеря writers больше не приводит к лишней глобальной деградации;
- восстановление становится мягче, потому что прокси реже приходится переключать весь трафик между режимами all-ME и all-direct.

## Какие инварианты сохранены

Изменение сохраняет базовое текущее поведение:

- уточнённый выбор маршрута применяется только к новым сессиям;
- уже активные relay-сессии по-прежнему живут по существующей глобальной cutover-семантике;
- контракты MTProto и KDF routing не менялись;
- в relay path не добавлена блокирующая работа.

## Ограничения

Это не полноценная новая per-family или per-session routing subsystem.

Корректнее воспринимать это как targeted hardening:

- readiness всё ещё построен поверх существующего глобального route runtime;
- fallback делается per target DC, а не через полностью независимый route domain;
- существующие сессии не мигрируют между режимами ME и direct.

## Как проверять

Полезный сценарий проверки:

1. Настроить ME endpoints для нескольких DC.
2. Добиться ситуации, в которой один DC теряет все живые ME writers, а другой остаётся здоровым.
3. Убедиться, что admission остаётся открытым и не уводит всё сразу в глобальный direct routing.
4. Убедиться, что сессии для здорового DC продолжают идти через ME.
5. Убедиться, что сессии для деградировавшего DC уходят в Direct-DC.

Дополнительно это поведение покрыто targeted тестами pool-status для:

- partial readiness при неполном покрытии DC;
- readiness check, привязанного к конкретному target DC.

## Дополнительное усиление admission coverage

Во время live-проверки этой фичи обнаружился ещё один failure mode.

В IPv4-only инсталляции single-endpoint outage мог временно перевести runtime
state семьи в suppression. Изначально admission coverage snapshot использовал
тот же family gate, что и drain coverage, поэтому временная suppression могла
сделать configured family set пустым, хотя у других DC ещё оставались живые
writers.

На практике это давало плохую последовательность:

1. partial degradation корректно активировался для проблемного DC;
2. admission snapshot на короткое время схлопывался в `covered_dcs=0 ready_dcs=0`;
3. прокси ошибочно переводил новые сессии в глобальный direct fallback.

Исправление переводит admission coverage для partial-degradation на configured
ME families, а не на temporary suppression gate, который используется для drain
coverage. Это сохраняет правильную семантику:

- один деградировавший DC больше не стирает admission coverage для остальных
  здоровых DC;
- partial degradation остаётся активным и не схлопывается в ложный global
  not-ready state;
- после восстановления admission возвращается в `covered_dcs == ready_dcs`
  без лишнего глобального cutover.

Дополнительно была уточнена transition-семантика логов: сообщение
`ME partial degradation cleared` теперь пишется только при настоящем
восстановлении полной covered readiness, а не при пустом coverage snapshot.

## Как проводилась live-проверка

Фича проверялась на реальной IPv4-only инсталляции через controlled
single-endpoint fault injection для DC3 по ME-path.

### Базовое состояние

Перед fault injection проверялось:

- `Conditional-admission gate: open / ME pool READY`
- полная ME connectivity для всех настроенных DC
- `telemt_me_no_writer_failfast_total = 0`
- `telemt_me_hybrid_timeout_total = 0`

### Fault injection

Блокировался только ME endpoint одного DC, при этом Direct-DC оставался
доступным:

```bash
sudo iptables -I DOCKER-USER 1 \
  -s 172.21.0.2 \
  -d 149.154.175.100 \
  -p tcp --dport 8888 \
  -j DROP
```

Эта команда специально ломает только ME path для данного DC. Direct
connectivity на `443` при этом сохраняется.

### Ожидаемое поведение в деградации

С исправлением ожидаемые логи такие:

- `ME target DC became unavailable for session routing`
- `ME partial degradation activated covered_dcs=12 ready_dcs=11`
- повторяющиеся single-endpoint outage reconnect attempts только для
  затронутого DC

Admission-метрики тоже должны отражать деградацию:

- `telemt_me_admission_configured_dcs = 12`
- `telemt_me_admission_ready_dcs < 12`
- `telemt_me_partial_degradation_active = 1`

Что больше не должно происходить:

- `covered_dcs=0 ready_dcs=0`
- `ME pool not-ready; routing new sessions via Direct-DC (fast mode)`
- глобальный controlled route cutover для остальных middle sessions

### Восстановление

После снятия firewall-правила:

```bash
sudo iptables -D DOCKER-USER \
  -s 172.21.0.2 \
  -d 149.154.175.100 \
  -p tcp --dport 8888 \
  -j DROP
```

ожидались и были получены такие логи:

- `Single-endpoint outage reconnect succeeded`
- `ME target DC recovered for session routing`
- `ME partial degradation cleared covered_dcs=12 ready_dcs=12`
- `ME writer floor restored for DC`

Admission-метрики должны вернуться в healthy baseline:

- `telemt_me_admission_configured_dcs = 12`
- `telemt_me_admission_ready_dcs = 12`
- `telemt_me_partial_degradation_active = 0`

### Результат

После добавленного admission hardening фикса получилось следующее:

- partial degradation корректно активировался только для проблемного DC;
- здоровые DC продолжили работать через Middle-End;
- admission layer больше не схлопывался в ложный `0/0` state;
- восстановление возвращало пул в full-ready без глобального fallback event.

Это подтверждает, что ветка теперь соответствует исходной цели partial
degradation: один деградировавший DC больше не приводит к лишнему
all-or-nothing collapse всей admission-логики для новых сессий.

## Один полный тест-кейс

Ниже зафиксирован полный end-to-end сценарий, который был успешно выполнен на
live-инсталляции.

### 1. Healthy baseline

Перед fault injection наблюдалось:

- лог: `Conditional-admission gate: open / ME pool READY`
- метрики:
  - `telemt_me_admission_configured_dcs 12`
  - `telemt_me_admission_ready_dcs 12`
  - `telemt_me_partial_degradation_active 0`

Это подтверждает, что admission layer стартует из состояния полной готовности.

### 2. Single-endpoint outage для DC3

ME endpoint `149.154.175.100:8888` был заблокирован через `iptables`.

Во время fault window наблюдалось:

- лог: `ME target DC became unavailable for session routing dc=3`
- лог: `ME partial degradation activated covered_dcs=12 ready_dcs=11`
- лог: повторяющиеся `Single-endpoint outage reconnect scheduled` для `dc=3` и `dc=-3`
- отсутствовал глобальный `ME pool not-ready` fallback
- отсутствовал глобальный cutover для остальных middle sessions

Метрики в деградированном состоянии:

- `telemt_me_admission_configured_dcs 12`
- `telemt_me_admission_ready_dcs 10`
- `telemt_me_partial_degradation_active 1`
- `telemt_me_no_writer_failfast_total 0`
- `telemt_me_hybrid_timeout_total 0`

Значение `ready_dcs` опустилось ниже первого transition log, потому что позже в
outage вошли и `dc=3`, и `dc=-3`. Это ожидаемо и полезно: метрики показывают
реальную глубину деградации, а не только бинарный флаг.

### 3. Recovery после снятия блокировки

После удаления firewall rule восстановление завершилось без глобального
fallback.

Наблюдавшиеся recovery-логи:

- `Single-endpoint outage reconnect succeeded dc=-3`
- `ME target DC recovered for session routing dc=-3`
- `Single-endpoint outage reconnect succeeded dc=3`
- `ME partial degradation cleared covered_dcs=12 ready_dcs=12`
- `ME writer floor restored for DC dc=-3`
- `ME writer floor restored for DC dc=3`

Recovery-метрики:

- `telemt_me_admission_configured_dcs 12`
- `telemt_me_admission_ready_dcs 12`
- `telemt_me_partial_degradation_active 0`

### Итог

Этот live-тест подтверждает целевое поведение end to end:

- один деградировавший DC больше не схлопывает глобальный ME admission;
- здоровые DC продолжают работать через Middle-End;
- деградировавший DC остаётся в локальном retry/recovery контуре;
- admission-метрики теперь явно показывают и деградацию, и восстановление.
