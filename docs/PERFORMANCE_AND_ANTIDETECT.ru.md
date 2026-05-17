# Telemt: рекомендации по производительности и анти-детекту

> Документ собран по результатам аудита исходников (`src/`) и `config.toml` на коммите ветки
> `claude/performance-optimization-recommendations-yxCVE`. Все ссылки `file:line` указывают на
> актуальное состояние кода на момент сборки документа — при больших рефакторах номера строк
> могут поплыть, пользуйтесь именами функций.

---

## Статус реализации (TODO A–K из плана)

Часть рекомендаций уже переведена в код в этой ветке. Срез на текущий коммит:

| ID | Рекомендация | Статус | Где |
|---|---|---|---|
| A | Шардинг IpTracker | **Отложено** — большой рефакторинг (~1100 LOC, adversarial-тесты), выделено в отдельный TODO | `src/ip_tracker.rs` (`TODO(perf)`) |
| B | Accept-loop шардинг | **Частично** — userspace-шардинг (N таск на listener) сделан, kernel-level SO_REUSEPORT с N сокетами оставлен как TODO | `src/maestro/listeners.rs::spawn_tcp_accept_loops` (env `TELEMT_ACCEPT_SHARDS`) |
| C | Шардинг `Semaphore` `max_connections` | **Сделано** — `split_max_connections()` делит лимит на N подсемафоров по числу accept-shard | `src/maestro/listeners.rs::split_max_connections` |
| D | `DashMap::with_shard_amount(num_cpus*4)` | **Сделано** — `Stats::user_stats` и `traffic_limiter` шардированы по CPU | `src/stats/mod.rs`, `src/proxy/traffic_limiter.rs` |
| E | Per-core buffer pool | **Сделано** — `BufferPool` стал façade'ом над N `BufferPoolShard`, thread-sticky выбор шарда | `src/stream/buffer_pool.rs` |
| F | `me_c2me_channel_capacity` дефолт | **Сделано** — уже 1024 (`DEFAULT_ME_C2ME_CHANNEL_CAPACITY`) | `src/config/defaults.rs:28` |
| G | DNS-кэш в `tls_front/fetcher` | **Сделано** — short-TTL LRU перед `lookup_host` | `src/tls_front/fetcher.rs` |
| H | Убрать `spawn_blocking` для unknown-DC лога | **Не требуется** — `should_log_unknown_dc` уже rate-limit'ит по distinct DC (max-set фильтр), spawn_blocking не вызывается часто | `src/proxy/direct_relay.rs:66–85, 482–494` |
| I | Явный `tokio::runtime::Builder` | **Сделано** — `TELEMT_WORKER_THREADS`, `TELEMT_MAX_BLOCKING_THREADS`, повышены `event_interval`/`global_queue_interval` | `src/main.rs` |
| J | 3 task → 2 в middle-relay | **Отложено** — большой рефакторинг hot-path средневой релейной машины, требует отдельной сессии и нагрузочных тестов | `src/proxy/middle_relay.rs:1260, 1307` |
| K | `Arc<AcceptContext>` на accept fan-out | **Сделано** — TCP accept loop делает 1 `Arc::clone` вместо ~12 | `src/maestro/listeners.rs::AcceptContext` |

**Анти-детект, статус:**

| Пункт | Статус | Где |
|---|---|---|
| GREASE по умолчанию (2.1) | **Сделано** — `grease_enabled = true` | `src/config/types.rs::EmulationConfig` |
| Ротация cipher suite в эмулируемом ServerHello (2.2) | **Частично** — при отсутствии upstream-профиля выбор по hash(ClientHello digest) | `src/tls_front/emulator.rs` |
| ECH parsing (2.3) | **Не сделано** — оставлено как roadmap |  |
| Timing jitter ServerHello (2.4), Decoy records (2.5), ALPN profiles (2.6), Bad CH → mask-host fallback (2.7), Multi-host masking (2.8) | **Не сделано** — рекомендации остаются в этом документе |  |

Все нереализованные пункты сохранены ниже с file:line, оценкой эффекта и эскизом подхода — чтобы можно было поднять их в отдельной фокусной сессии.

---

## 0. TL;DR

### Почему на мощной VM ресурсы не утилизируются (главное)

Три одноточечных сериализатора, которые объясняют «плато CPU» при росте числа пользователей:

| # | Узкое место | Файл / строка | ROI |
|---|---|---|---|
| 1 | Один `tokio::spawn(accept_loop)` на каждый listener — TCP-accepts сериализуются одним тредом | `src/maestro/listeners.rs:360–393` | **Очень высокий** |
| 2 | Глобальный `Semaphore::acquire_owned()` для `max_connections` — все accept-таски бьются в один atomic semaphore | `src/maestro/listeners.rs:71, 259, 269, 414, 424` | **Высокий** |
| 3 | `RwLock<HashMap>` в `IpTracker` берёт write-lock на КАЖДЫЙ accept/disconnect | `src/ip_tracker.rs:23–24, 121–149` | **Очень высокий** |

Поверх этого — ещё ~8 мест с фиксируемой контенцией, см. раздел 1bis.

### Top-5 быстрых побед в коде по производительности

1. **Шардинг IpTracker** на 16–64 sub-map (`parking_lot::Mutex`) → +30–60 % утилизации CPU на ≥16 ядрах.
2. **N accept-tasks per listener** (или N listeners с `SO_REUSEPORT`) → +2–4× accepts/sec.
3. **Шардинг `Semaphore` лимита соединений** по accept-shard id → +10–20 % при насыщении.
4. **`DashMap::with_shard_amount(num_cpus * 4)`** в `Stats::user_stats` → -lock contention на горячем пути телеметрии.
5. **DNS-кэш** в `tls_front/fetcher` + убрать `spawn_blocking` для file-log → разгружает blocking-pool.

### Top-5 быстрых побед по анти-детекту

1. **Включить GREASE по умолчанию** — реализация готова, флаг просто в `false`.
2. **Рандомизация cipher suite и порядка extensions** в эмулируемом ServerHello.
3. **Log-normal jitter для `min_server_hello_delay_ms`** + включить по умолчанию.
4. **Forward bad ClientHello на masking host** вместо back-off/drop — против active probing.
5. **Список mask-host'ов с подбором по SNI** + ротация `tls_domain` через hot-reload.

---

## 1bis. Почему мощная VM не утилизируется — детально

Симптом: чем мощнее VM, тем хуже она утилизируется при росте соединений. Это классический funnel —
горячий путь принятия соединения и стейт пользователя сериализуются через несколько одноточечных
синхронизаций.

### 1bis.1 Один accept-loop на listener

`src/maestro/listeners.rs:360–393` — для каждого `TcpListener` создаётся ровно один
`tokio::spawn(accept_loop)`. На 32+ ядрах один таск физически не выгребает SYN backlog (особенно на
SYN-флуде или массовом реконнекте). Флаг `SO_REUSEPORT` уже выставлен на сокете
(`src/transport/socket.rs:313–320`), но это даст эффект только если приложение реально открывает N
сокетов и привязывает N accept-loop'ов.

Что сделать:

- Добавить конфиг `[server] accept_shards = N` (auto = `num_cpus / max(1, len(listeners))`).
- В `Listeners::run`/`build_listeners` создавать N сокетов под один логический listener с
  `SO_REUSEPORT` и spawn’ить N независимых accept-loop'ов.
- Альтернатива (без N сокетов): один `TcpListener`, но N таск-копий, читающих из него — даст
  меньше эффекта (kernel всё равно сериализует accept), но проще в реализации.

Ожидаемый эффект: 2–4× accepts/sec под насыщением; CPU-utilization выходит с «пилы» на «полку».

### 1bis.2 Глобальный `Semaphore` для `max_connections`

`src/maestro/listeners.rs:71, 259, 269, 414, 424` — `max_connections.clone().acquire_owned().await`.
Все accept-таски на всех ядрах бьются в один atomic semaphore. Каждый `acquire`/`release` —
cross-core sync с cache-line bouncing.

Что сделать:

- Шардировать лимит на N независимых `Semaphore`, по `max_connections / N` в каждом. Accept-shard
  бьёт в «свой» семафор.
- Или soft-лимит через `AtomicUsize::fetch_add` + проверку, с `Relaxed`-ordering на happy path и
  `acquire_load` только при превышении (см. паттерн «counted-out limiter»).

### 1bis.3 `RwLock<HashMap>` в `IpTracker`

`src/ip_tracker.rs:23–24`:

```rust
active_ips: Arc<RwLock<HashMap<String, HashMap<IpAddr, usize>>>>,
recent_ips: Arc<RwLock<HashMap<String, HashMap<IpAddr, Instant>>>>,
```

Это, скорее всего, **главная причина плато CPU**. Write-lock берётся на каждый accept (`add_ip`,
`ip_tracker.rs:121–149`) и на каждый disconnect.

Что сделать:

- Шардирование на 16–64 sub-map'а: `Vec<parking_lot::Mutex<HashMap<...>>>`. Зависимость
  `parking_lot` уже есть в `Cargo.toml`.
- Хеш-функция: `hash(user) % N` (или `hash(user, ip) % N`). Оставаться внутри одного шарда при
  add/remove одной (user, ip) пары — обязательное условие корректности.
- `max_ips`/`default_max_ips` (`ip_tracker.rs:30–33`) тоже под `RwLock`, но они read-heavy и пишутся
  только при config-reload — можно заменить на `arc_swap::ArcSwap` (зависимость есть).

Ожидаемый эффект: +30–60 % утилизации на 16+ ядрах.

### 1bis.4 `DashMap user_stats` — дефолтных 64 шардов мало

`src/stats/mod.rs:293` — `user_stats: DashMap<String, Arc<UserStats>>`. `DashMap::new()` берёт 64
шарда, на 64+ vCPU контенция возвращается.

Что сделать:

- `DashMap::with_shard_amount((num_cpus * 4).next_power_of_two())`.
- На «touch»-пути (`stats/mod.rs:437–441`) — рассмотреть thread_local-счётчики с flush раз в
  секунду через `tokio::time::interval`.

### 1bis.5 12 `Arc::clone` на каждый accept

`src/maestro/listeners.rs:445–456` — на каждое принятое соединение клонируются ~12 Arc'ов
(`stats`, `upstream_manager`, `ip_tracker`, `beobachten`, `shared`, ...). Каждый `clone` — atomic
`fetch_add` в refcount; на 100k conn/sec × 12 = 1.2M cross-core atomic ops в секунду.

Что сделать:

- Завести `Arc<ConnCtx>` со всем нужным, единожды создаваемый при старте; `spawn` получает один
  `Arc::clone(&ctx)`.
- Внутри handler — обращение через поля `ctx`, без дополнительных clone'ов до момента, когда нужен
  отдельный owned `Arc` (например для long-lived child task).

### 1bis.6 Узкий mpsc C2ME в middle-relay

`src/proxy/middle_relay.rs:1248–1258` — `C2ME_CHANNEL_CAPACITY_FALLBACK = 128`. На burst'е producer
блокируется → пул отправляющих клиентов накапливается на семафоре канала.

Что сделать:

- Поднять дефолт до 512–1024.
- Сделать функцией от `max_connections` (или числа активных DC writers).
- Метрика: время ожидания на `send().await` — экспонировать в `/metrics`.

### 1bis.7 3 task на каждое соединение в middle-relay

`src/proxy/middle_relay.rs:1260, 1307` — `c2me_sender` + `me_writer` + основной loop = 3
`tokio::spawn` на соединение. На 100k conn = 300k task в global scheduler queue, плюс accept-task
≠ workers тогда теряют локальность.

Что сделать:

- Объединить `me_writer` и основной loop в одну таску через `tokio::select!` (батчинг внутри уже
  есть). Это убирает ~⅓ task'ов.
- Опционально: `tokio::task::LocalSet` per worker thread — task остаётся ближе к ядру, лучше
  локальность кэша.

### 1bis.8 `spawn_blocking` для file-log в hot path

`src/proxy/direct_relay.rs:484` — на каждое unknown-DC событие. Blocking-pool tokio дефолтом 512,
при шторме unknown DC он забивается и блокирует другие spawn_blocking (DNS getaddrinfo, файловые
операции).

Что сделать:

- Использовать `tracing_appender::non_blocking` (зависимость есть) и стандартный `tracing::warn!` —
  всё уже доступно.
- Дополнительно: ratelimit логирования unknown DC (раз в N секунд на ключ), чтобы не топить лог
  при злоупотреблении.

### 1bis.9 DNS lookup на каждый cert-fetch без кэша

`src/tls_front/fetcher.rs:862` — `tokio::net::lookup_host((host, port)).await` без видимого кэша.
`tokio::net::lookup_host` под капотом идёт в blocking-pool через `getaddrinfo` — каждый раз.

Что сделать:

- Добавить `lru::LruCache<(String, u16), (Vec<SocketAddr>, Instant)>` с TTL=60 с (`lru` уже в
  deps).
- Под `parking_lot::Mutex` (или per-shard) — он short-held, contention минимальна.

### 1bis.10 Buffer pool без per-core шардинга

`src/stream/buffer_pool.rs:25–84` — один `ArrayQueue`. Lock-free, но на >16 ядрах cache-line
bouncing виден.

Что сделать:

- `Arc<[BufferPool; N]>` по `num_cpus`. Селектор — `core_affinity::get_core_ids()` или round-robin
  `AtomicUsize`. Per-shard атомики `hits/misses/dropped_pool_full`, агрегировать на экспорте
  метрик.
- Поднять `DEFAULT_MAX_BUFFERS` с 1024 до 2048–4096 (есть `src/stream/buffer_pool.rs:20`).

### 1bis.11 Последовательные `await` в handshake

`src/proxy/handshake.rs:1480, 1533, 1654` — несколько `maybe_apply_server_hello_delay(config).await`
подряд. Каждый — отдельный `Sleep`, который пинает scheduler.

Что сделать:

- Подсчитать общую задержку и сделать **один** sleep.
- Где независимые шаги выполняют I/O — связать `tokio::try_join!`.

### 1bis.12 `tokio::main` без явных параметров

`src/main.rs:69–81` — multi-thread runtime используется по умолчанию, но без явного контроля.

Что сделать:

```rust
let rt = tokio::runtime::Builder::new_multi_thread()
    .worker_threads(cfg.runtime.worker_threads.unwrap_or_else(num_cpus::get))
    .max_blocking_threads(cfg.runtime.max_blocking_threads.unwrap_or(1024))
    .enable_all()
    .event_interval(31)
    .global_queue_interval(31)
    .thread_name("telemt-worker")
    .build()?;
```

Опционально (под `--cfg tokio_unstable`): pinning worker'ов к ядрам через `core_affinity` в
`on_thread_start` hook'е.

### Сводная таблица scalability-побед

| # | Изменение | Ожидаемый эффект | Объём |
|---|-----------|------------------|-------|
| A | Шардирование `IpTracker` (1bis.3) | +30–60 % CPU utilization при ≥16 ядрах | 80–150 строк |
| B | N accept-loop / `SO_REUSEPORT` шардинг (1bis.1) | +2–4× accepts/sec | 30–60 строк |
| C | Шардирование `Semaphore` лимита (1bis.2) | +10–20 % утилизации под насыщением | 30–50 строк |
| D | `DashMap::with_shard_amount(num_cpus*4)` (1bis.4) | -lock contention в stats | 5–10 строк |
| E | Per-core buffer pool (1bis.10) | -2–5 % CPU | 100–200 строк |
| F | Поднять `me_c2me_channel_capacity` (1bis.6) | устраняет backpressure-funnel | 1 строка (default) |
| G | DNS cache в fetcher (1bis.9) | -DNS latency, -overload blocking-pool | 40–60 строк |
| H | Убрать `spawn_blocking` для file-log (1bis.8) | разгружает blocking-pool | 20–40 строк |
| I | Явный `tokio::runtime::Builder` (1bis.12) | +10 % throughput на 32+ ядрах | 30 строк |
| J | Объединить 3 task → 2 в middle-relay (1bis.7) | -⅓ task count, лучше scheduling | 60–120 строк |
| K | Единый `Arc<ConnCtx>` на accept (1bis.5) | -1M atomic ops/sec на 100k conn | 40–80 строк |

> **Важно.** Эти оценки — гипотезы по чтению кода. Подтвердить порядок ROI до merge'а на конкретной
> нагрузке: см. раздел 4 «Как профилировать».

---

## 1. Производительность (hot-path)

### 1.1 Bidirectional relay

- `src/proxy/relay.rs`, `src/proxy/direct_relay.rs:330–348`, `src/proxy/middle_relay.rs` —
  `tokio::io::copy_bidirectional_with_sizes`. Это уже норм (не блокирует HOL), но обе стороны
  идут через userspace copy.
- Для **направления `direct_relay` (без middle-proxy)** имеет смысл добавить опциональный путь
  через `splice(2)` на Linux (`nix::fcntl::splice`, зависимость `nix` уже в `Cargo.toml`). Это
  даст zero-copy на C2S/S2C без шифрования (где relay просто прокидывает байты).
- Для зашифрованного middle-proxy пути splice неприменим — оставить userspace copy.

### 1.2 Buffer pool: per-core шардинг и больше буферов

- `src/stream/buffer_pool.rs:25–42, 66–84` — один `ArrayQueue` + общий счётчик hits/misses.
- `DEFAULT_MAX_BUFFERS = 1024` (`buffer_pool.rs:20`) мал для 100k соединений — пул быстро
  исчерпывается, идёт re-alloc.
- Рекомендация:
  - Шардировать пул: `Vec<Arc<BufferPool>>` длиной `num_cpus`.
  - Селектор шарда: `core_affinity::get_core_ids()`-based, или, проще, `tokio` runtime worker-id
    через `tokio::runtime::Handle::current().runtime_flavor()` + round-robin.
  - Per-shard атомики, агрегировать на экспорте метрик.
  - Поднять `DEFAULT_MAX_BUFFERS` до 2048–4096.

### 1.3 Размеры буферов копирования

`src/config/defaults.rs:36–37`:

```rust
const DEFAULT_DIRECT_RELAY_COPY_BUF_C2S_BYTES: usize = 64 * 1024;
const DEFAULT_DIRECT_RELAY_COPY_BUF_S2C_BYTES: usize = 256 * 1024;
```

При 100k соединений это ~30 GiB RAM только на relay-буферы. Профиль «high-density»:

- `direct_relay_copy_buf_c2s_bytes = 32768`
- `direct_relay_copy_buf_s2c_bytes = 131072`

Экономит ~16 GiB на 100k conn. Trade-off — небольшой throughput-loss на одиночных соединениях с
очень крупными chunk'ами; для типичного MTProto/Telegram-трафика практически незаметен.

### 1.4 Listener и `listen_backlog`

- `src/config/defaults.rs:218–224`: `default_server_max_connections = 10_000`,
  `default_listen_backlog = 1024`. Для 100k conn — мало.
- В конфиге high-load: `listen_backlog = 4096–8192`, `max_connections = 100_000`.
- Параметр `accept_permit_timeout_ms = 250` (`defaults.rs:52`) можно опустить до 100 мс для
  быстрого rejection вместо очереди.

### 1.5 Crypto hot path: build-флаги

- `src/stream/crypto_stream.rs:169–200`, `src/crypto/aes.rs:70–71` — `apply_keystream()` per-frame.
  Hardware AES-NI используется автоматически в crate `ctr`/`aes`, но только если он включён на
  этапе компиляции.
- Сборка release под целевой CPU:

  ```bash
  RUSTFLAGS="-C target-cpu=native" cargo build --release
  ```

  Либо явно: `RUSTFLAGS="-C target-feature=+aes,+sse4.1,+avx2"` (более переносимо).
- Документировать это в `Dockerfile` (через `ARG RUSTFLAGS=...` или `ENV`), сейчас в `Dockerfile`
  такого нет.
- Micro-batching: коалесцировать 2–4 фрейма перед `apply_keystream` — даст эффект только на очень
  мелких фреймах, требует профилирования через `benches/crypto_bench.rs`.

### 1.6 IpTracker и stats: переход на parking_lot и шардинг

См. 1bis.3, 1bis.4. Полностью переехать с `std::sync::Mutex`/`RwLock` на `parking_lot::Mutex` на
горячих путях (зависимость уже есть). У `parking_lot` нет poison, быстрее под contention, нет
`unwrap()` после lock'а.

### 1.7 Middle-proxy upstream

- `src/transport/middle_proxy/pool.rs`, `src/transport/upstream.rs` — много стейта, нет явного
  батчинга фреймов на upstream.
- Перед оптимизацией — снять flamegraph: возможно, узким местом окажется не сама отправка, а
  C2ME-канал (см. 1bis.6).
- Если батчинг нужен — коалесцировать 2–4 фрейма перед `AsyncWriteExt::write_all`.

### 1.8 Дефолты конфига под high-density (100k conn)

| Параметр | Текущий | Рекомендуемый |
|---|---|---|
| `server.max_connections` | 10 000 | 100 000 |
| `server.listen_backlog` | 1 024 | 4 096–8 192 |
| `server.accept_permit_timeout_ms` | 250 | 100 |
| `direct_relay_copy_buf_c2s_bytes` | 65 536 | 32 768 |
| `direct_relay_copy_buf_s2c_bytes` | 262 144 | 131 072 |
| `buffer_pool` `max_buffers` | 1 024 | 2 048–4 096 |
| `me_c2me_channel_capacity` | 128 (fallback) | 512–1 024 |

---

## 2. Анти-детект (anti-detect)

### 2.1 GREASE — включить по умолчанию

- `src/config/types.rs:1663–1684` — `grease_enabled: bool = false`.
- `src/tls_front/fetcher.rs:464–571` — реализация уже готова: GREASE-значения в cipher_suites,
  supported_groups, extensions. RFC 8701-совместимо.
- Рекомендация: дефолт `true`. Текущий JA3 без GREASE — стабильный сигнатурный fingerprint.

### 2.2 Cipher suite и порядок extensions — рандомизация

- `src/tls_front/emulator.rs` — hardcoded `TLS_AES_128_GCM_SHA256` если не задан профиль.
- Что добавить:
  - Ротация cipher suite между `TLS_AES_128_GCM_SHA256` и `TLS_AES_256_GCM_SHA384` (TLS 1.3),
    выбор детерминирован по `hash(sni || time_bucket)` — фингерпринт стабилен в окне, но не один
    на всех.
  - Рандомизация порядка расширений (key_share, supported_versions, alpn, ...). Реальные клиенты
    варьируют порядок — фиксированный порядок выдаёт MTProxy.

### 2.3 ECH (Encrypted Client Hello) — хотя бы парсинг

- В коде ECH-extension (`0xfe0d`) не обнаружено.
- Минимум: распарсить ECH-extension в `src/protocol/tls.rs` и корректно проигнорировать (не
  падать, не подсвечиваться отсутствием).
- Полная серверная поддержка ECH — отдельная задача (roadmap, см. раздел 3).

### 2.4 ServerHello timing jitter

- `src/proxy/handshake.rs` — `min_server_hello_delay_ms` есть в конфиге, но не обязателен.
- Рекомендация:
  - Дефолт включить (30–80 мс).
  - Распределение — log-normal, а не uniform (точнее повторяет реальный TLS handshake response
    time, где есть длинный хвост).
  - Параметры: median ~50 мс, σ ~0.4 (в log-domain).

### 2.5 Decoy / padding-jitter на TLS records

- `src/tls_front/emulator.rs:18–35` — 3 % jitter на размеры записей.
- Расширить:
  - С вероятностью 1–5 % вставлять «пустые» / мелкие `ApplicationData` records между настоящими
    (mimic NewSessionTicket / KeyUpdate).
  - Варьировать ClientHello-side профили в `tls_front/cache` так, чтобы у одного SNI разные
    клиенты выглядели чуть по-разному (не идентичные длины record'ов).

### 2.6 ALPN profiles — расширить

- `src/proxy/masking.rs` — поддерживает `h2` и `http/1.1`.
- Расширить набор: `h2`, `http/1.1`, `http/1.0`, опционально `h2c`.
- Ротация по SNI-профилю (`github.com` обычно `h2`, мелкие сайты — `http/1.1`).

### 2.7 Active probing — forward вместо drop

- `src/proxy/handshake.rs` — `AuthProbeState` с back-off 25–1000 мс.
- На bad ClientHello прокси сейчас закрывает / тротлит → DPI видит «странное» поведение, которое
  можно классифицировать.
- Рекомендация: всегда форвардить bad ClientHello на masking host (полный TLS handshake
  терминируется реальным upstream). Тогда у активного probe-сканера нет разницы между «реальный
  сайт» и «MTProxy с маскировкой».

### 2.8 Несколько mask host'ов с подбором по SNI

- `src/proxy/masking.rs` — single mask_host.
- Добавить список mask host'ов в конфиг:

  ```toml
  [censorship.masking]
  hosts = ["github.com", "cloudflare.com", "wikipedia.org"]
  match_by_sni = true   # если SNI ∈ hosts → форвард на этот же host
  default = "github.com"
  ```

- Эффект: внешний наблюдатель видит «нормальную» связку SNI↔destination для большого диапазона
  трафика.

### 2.9 Replay protection — параметры

- `src/stats/mod.rs` `ReplayChecker` — sharded LRU, TTL уже есть.
- Документировать в `docs/Config_params` рекомендуемые значения `window` / `tls_window` под
  нагрузку и риск-профиль (slow clients vs CPU).

### 2.10 Operational anti-detect

- **Не публиковать `tls_domain`** в открытых каналах — он же SNI; публичная утечка снижает
  стоимость энумерации.
- Ротация `tls_domain` периодическая (раз в N недель) через hot-reload (механизм уже есть —
  `src/config/hot_reload.rs`). Старые ссылки сохранят валидность только до ротации.
- Несколько `tls_domain` одновременно (если конфиг это уже поддерживает в `[[server.listeners]]` —
  ротация по слушающим IP).

---

## 3. Roadmap (вне quick wins)

- Полноценный server-side ECH (требует ECH config publication через DNS HTTPS RR).
- kTLS / io_uring backend для splice-zero-copy и offload AES в kernel.
- Внешний JA3-feed для auto-ротации emulated TLS-профилей.
- HTTP/2 multiplexing на upstream к Telegram middle-proxy (если протокол позволит).

---

## 4. Как профилировать перед merge'ом

Без OS-тюнинга, только инструменты разработчика. Минимальный набор:

- **`tokio-console`** (`features = ["tokio_unstable", "console-subscriber"]`) — видно time-on-CPU
  каждого task'а, лишние spawn'ы, sleep'ы, lock waits. Включается на dev-сборке.
- **`cargo flamegraph`** под синтетической нагрузкой (`tcpkali -c 50000 -T 60s`). На flamegraph
  немедленно видно, какая функция «полка»: `IpTracker::add_ip`, `Semaphore::acquire`, `apply_keystream`.
- **`perf stat -e cache-misses,cache-references,context-switches,LLC-load-misses ./telemt config.toml`**
  под нагрузкой — высокий `cache-misses` коррелирует с atomic contention (Arc-clone, hot RwLock).
- **Внутренние метрики**: уже есть `accept_permit_timeout_total`, `me_child_join_timeout_total`,
  `buffer_pool.{hits,misses,dropped_pool_full}` (`src/stream/buffer_pool.rs:33–41`). При шардинге —
  добавить per-shard counters и top-N горячих shard'ов.
- **`/proc/<pid>/status` `voluntary_ctxt_switches`** — резкий рост = много блокировок.

---

## 5. Ссылочный индекс файлов (что трогать)

Производительность:

- `src/main.rs:69–81` — runtime builder (1bis.12).
- `src/maestro/listeners.rs:51–97, 71, 259, 269, 360–393, 414, 424, 445–456` — accept-loop, semaphore,
  Arc-clone fan-out (1bis.1, 1bis.2, 1bis.5).
- `src/ip_tracker.rs:23–24, 30–33, 121–149` — шардирование (1bis.3).
- `src/stats/mod.rs:91–92, 293, 437–441` — `DashMap` shard_amount, touch path (1bis.4).
- `src/proxy/middle_relay.rs:1248–1258, 1260, 1307` — mpsc capacity, task fan-out (1bis.6, 1bis.7).
- `src/proxy/direct_relay.rs:330–348, 484` — splice path, spawn_blocking log (1.1, 1bis.8).
- `src/tls_front/fetcher.rs:862` — DNS cache (1bis.9).
- `src/stream/buffer_pool.rs:20, 25–84` — per-core sharding (1bis.10, 1.2).
- `src/stream/crypto_stream.rs:169–200`, `src/crypto/aes.rs:70–71` — AES-NI build flags (1.5).
- `src/proxy/handshake.rs:1480, 1533, 1654` — sequential awaits (1bis.11).
- `src/proxy/traffic_limiter.rs:15, 440` — `REGISTRY_SHARDS = 64` (сейчас норм, но смотреть при
  >64 vCPU).
- `src/config/defaults.rs:36–37, 52, 218–224, 454–460` — high-density дефолты (1.3, 1.4, 1.8).
- `src/transport/socket.rs:313–320` — `SO_REUSEPORT` уже включён (использовать через accept-шардинг).

Анти-детект:

- `src/config/types.rs:1663–1684` — `grease_enabled` дефолт (2.1).
- `src/tls_front/fetcher.rs:464–571` — GREASE-реализация (готова) (2.1).
- `src/tls_front/emulator.rs:18–35, 287` — jitter, TLS 1.3 paths (2.2, 2.5).
- `src/proxy/handshake.rs` — `AuthProbeState`, `min_server_hello_delay_ms` (2.4, 2.7).
- `src/proxy/masking.rs:127–147` — mask shape, mask host (2.6, 2.8).
- `src/protocol/tls.rs:88–89` — time skew, ECH parsing extension point (2.3).
- `src/protocol/obfuscation.rs` — MTProto obfuscated2 (контекст, не трогаем).
- `src/stats/mod.rs` — `ReplayChecker` (2.9).

---

## 6. Что важно НЕ ломать при изменениях

- Семантику `IpTracker::add_ip`/`remove_ip`: per-(user, ip) inc/dec должно остаться атомарным
  внутри одного шарда — нельзя считать с одного шарда, писать в другой.
- Корректность `Semaphore` лимита: сумма по шардам должна давать `max_connections`; распределение
  по шардам — round-robin, иначе один шард будет переполняться при skew’е (например, если все
  accept-task'и читают из одного listener'а).
- Поведение `min_server_hello_delay_ms`: если включаем по умолчанию — убедиться, что у
  существующих клиентов нет таймаутов handshake. Релиз с предупреждением в CHANGELOG.
- При изменении дефолта `grease_enabled` на `true` — проверить совместимость с emulated profile
  cache (`src/tls_front/cache.rs`): возможно, надо инвалидировать cache при смене флага.
