# Справочник параметров конфигурации Telemt

В этом документе перечислены все ключи конфигурации, принимаемые `config.toml`.

> [!NOTE]
>
> Этот справочник был составлен с помощью искусственного интеллекта и сверен с базой кода (схема конфигурации, значения по умолчанию и логика проверки).

> [!WARNING]
>
> Параметры конфигурации, подробно описанные в этом документе, предназначены для опытных пользователей и для целей тонкой настройки. Изменение этих параметров без четкого понимания их функции может привести к нестабильности приложения или другому неожиданному поведению. Пожалуйста, действуйте осторожно и на свой страх и риск.

# Содержание
 - [Ключи верхнего уровня](#top-level-keys)
 - [general](#general)
 - [general.modes](#generalmodes)
 - [general.links](#generallinks)
 - [general.telemetry](#generaltelemetry)
 - [network](#network)
 - [server](#server)
 - [server.conntrack_control](#serverconntrack_control)
 - [server.api](#serverapi)
 - [server.listeners](#serverlisteners)
 - [timeouts](#timeouts)
 - [censorship](#censorship)
 - [censorship.tls_fetch](#censorshiptls_fetch)
 - [access](#access)
 - [upstreams](#upstreams)

# Ключи верхнего уровня

| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`include`](#include) | `String` (специальная директива) | — |
| [`show_link`](#show_link) | `"*"` or `String[]` | `[]` (`ShowLink::None`) |
| [`dc_overrides`](#dc_overrides) | `Map<String, String or String[]>` | `{}` |
| [`default_dc`](#default_dc) | `u8` | — (эффективный резервный вариант: `2` в ME маршрутизации) |

## include
  - **Ограничения / валидация**: значение должно быть одной строкой в виде `include = "path/to/file.toml"`. Значения параметра обрабатываются перед анализом TOML. Максимальное количество - 10.
  - **Описание**: Включает еще один файл TOML с помощью `include = "relative/or/absolute/path.toml"`; добавленные файлы обрабатываются рекурсивно.
  - **Пример**:

    ```toml
    include = "secrets.toml"
    ```
## show_link
  - **Ограничения / валидация**: принимает `"*"` или массив имен пользователей. Пустой массив означает «не показывать никому».
  - **Описание**: Устаревший селектор видимости ссылок (`«*»` для всех пользователей или списка имен пользователей).
  - **Пример**:

    ```toml
    # show links for all configured users
    show_link = "*"

    # or: show links only for selected users
    # show_link = ["alice", "bob"]
    ```
## dc_overrides
  - **Ограничения / валидация**: значение должно быть положительным целым числом в формате строки (например, `"203"`). Значения разбираются как `SocketAddr` (`ip:port`). Пустые строки игнорируются.
  - **Описание**: Переопределяет DC эндпоинты для запросов с нестандартными DC; задается в виде строки с индексом DC, значение — один или несколько адресов `ip:port`.
  - **Пример**:

    ```toml
    [dc_overrides]
    "201" = "149.154.175.50:443"
    "203" = ["149.154.175.100:443", "91.105.192.100:443"]
    ```
## default_dc
  - **Ограничения / валидация**: целочисленное значение в диапазоне `1..=5`. Если значение выходит за пределы диапазона, клиент направляется к DC1; Middle-end маршрутизация направляет клиента к DC2, если DC1 не задан.
  - **Описание**: DC по умолчанию, используемый для нестандартных DC. Когда клиент запрашивает неизвестный/нестандартный DC без переопределения, telemt направляет его в этот кластер по умолчанию.
  - **Пример**:

    ```toml
    # When a client requests an unknown/non-standard DC with no override,
    # route it to this default cluster (1..=5).
    default_dc = 2
    ```

# [general]

| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`data_path`](#data_path) | `String` | — |
| [`prefer_ipv6`](#prefer_ipv6) | `bool` | `false` |
| [`fast_mode`](#fast_mode) | `bool` | `true` |
| [`use_middle_proxy`](#use_middle_proxy) | `bool` | `true` |
| [`proxy_secret_path`](#proxy_secret_path) | `String` | `"proxy-secret"` |
| [`proxy_config_v4_cache_path`](#proxy_config_v4_cache_path) | `String` | `"cache/proxy-config-v4.txt"` |
| [`proxy_config_v6_cache_path`](#proxy_config_v6_cache_path) | `String` | `"cache/proxy-config-v6.txt"` |
| [`ad_tag`](#ad_tag) | `String` | — |
| [`middle_proxy_nat_ip`](#middle_proxy_nat_ip) | `IpAddr` | — |
| [`middle_proxy_nat_probe`](#middle_proxy_nat_probe) | `bool` | `true` |
| [`middle_proxy_nat_stun`](#middle_proxy_nat_stun) | `String` | — |
| [`middle_proxy_nat_stun_servers`](#middle_proxy_nat_stun_servers) | `String[]` | `[]` |
| [`stun_nat_probe_concurrency`](#stun_nat_probe_concurrency) | `usize` | `8` |
| [`middle_proxy_pool_size`](#middle_proxy_pool_size) | `usize` | `8` |
| [`middle_proxy_warm_standby`](#middle_proxy_warm_standby) | `usize` | `16` |
| [`me_init_retry_attempts`](#me_init_retry_attempts) | `u32` | `0` |
| [`me2dc_fallback`](#me2dc_fallback) | `bool` | `true` |
| [`me2dc_fast`](#me2dc_fast) | `bool` | `false` |
| [`me_keepalive_enabled`](#me_keepalive_enabled) | `bool` | `true` |
| [`me_keepalive_interval_secs`](#me_keepalive_interval_secs) | `u64` | `8` |
| [`me_keepalive_jitter_secs`](#me_keepalive_jitter_secs) | `u64` | `2` |
| [`me_keepalive_payload_random`](#me_keepalive_payload_random) | `bool` | `true` |
| [`rpc_proxy_req_every`](#rpc_proxy_req_every) | `u64` | `0` |
| [`me_writer_cmd_channel_capacity`](#me_writer_cmd_channel_capacity) | `usize` | `4096` |
| [`me_route_channel_capacity`](#me_route_channel_capacity) | `usize` | `768` |
| [`me_c2me_channel_capacity`](#me_c2me_channel_capacity) | `usize` | `1024` |
| [`me_c2me_send_timeout_ms`](#me_c2me_send_timeout_ms) | `u64` | `4000` |
| [`me_reader_route_data_wait_ms`](#me_reader_route_data_wait_ms) | `u64` | `2` |
| [`me_d2c_flush_batch_max_frames`](#me_d2c_flush_batch_max_frames) | `usize` | `32` |
| [`me_d2c_flush_batch_max_bytes`](#me_d2c_flush_batch_max_bytes) | `usize` | `131072` |
| [`me_d2c_flush_batch_max_delay_us`](#me_d2c_flush_batch_max_delay_us) | `u64` | `500` |
| [`me_d2c_ack_flush_immediate`](#me_d2c_ack_flush_immediate) | `bool` | `true` |
| [`me_quota_soft_overshoot_bytes`](#me_quota_soft_overshoot_bytes) | `u64` | `65536` |
| [`me_d2c_frame_buf_shrink_threshold_bytes`](#me_d2c_frame_buf_shrink_threshold_bytes) | `usize` | `262144` |
| [`direct_relay_copy_buf_c2s_bytes`](#direct_relay_copy_buf_c2s_bytes) | `usize` | `65536` |
| [`direct_relay_copy_buf_s2c_bytes`](#direct_relay_copy_buf_s2c_bytes) | `usize` | `262144` |
| [`crypto_pending_buffer`](#crypto_pending_buffer) | `usize` | `262144` |
| [`max_client_frame`](#max_client_frame) | `usize` | `16777216` |
| [`desync_all_full`](#desync_all_full) | `bool` | `false` |
| [`beobachten`](#beobachten) | `bool` | `true` |
| [`beobachten_minutes`](#beobachten_minutes) | `u64` | `10` |
| [`beobachten_flush_secs`](#beobachten_flush_secs) | `u64` | `15` |
| [`beobachten_file`](#beobachten_file) | `String` | `"cache/beobachten.txt"` |
| [`hardswap`](#hardswap) | `bool` | `true` |
| [`me_warmup_stagger_enabled`](#me_warmup_stagger_enabled) | `bool` | `true` |
| [`me_warmup_step_delay_ms`](#me_warmup_step_delay_ms) | `u64` | `500` |
| [`me_warmup_step_jitter_ms`](#me_warmup_step_jitter_ms) | `u64` | `300` |
| [`me_reconnect_max_concurrent_per_dc`](#me_reconnect_max_concurrent_per_dc) | `u32` | `8` |
| [`me_reconnect_backoff_base_ms`](#me_reconnect_backoff_base_ms) | `u64` | `500` |
| [`me_reconnect_backoff_cap_ms`](#me_reconnect_backoff_cap_ms) | `u64` | `30000` |
| [`me_reconnect_fast_retry_count`](#me_reconnect_fast_retry_count) | `u32` | `16` |
| [`me_single_endpoint_shadow_writers`](#me_single_endpoint_shadow_writers) | `u8` | `2` |
| [`me_single_endpoint_outage_mode_enabled`](#me_single_endpoint_outage_mode_enabled) | `bool` | `true` |
| [`me_single_endpoint_outage_disable_quarantine`](#me_single_endpoint_outage_disable_quarantine) | `bool` | `true` |
| [`me_single_endpoint_outage_backoff_min_ms`](#me_single_endpoint_outage_backoff_min_ms) | `u64` | `250` |
| [`me_single_endpoint_outage_backoff_max_ms`](#me_single_endpoint_outage_backoff_max_ms) | `u64` | `3000` |
| [`me_single_endpoint_shadow_rotate_every_secs`](#me_single_endpoint_shadow_rotate_every_secs) | `u64` | `900` |
| [`me_floor_mode`](#me_floor_mode) | `"static"` or `"adaptive"` | `"adaptive"` |
| [`me_adaptive_floor_idle_secs`](#me_adaptive_floor_idle_secs) | `u64` | `90` |
| [`me_adaptive_floor_min_writers_single_endpoint`](#me_adaptive_floor_min_writers_single_endpoint) | `u8` | `1` |
| [`me_adaptive_floor_min_writers_multi_endpoint`](#me_adaptive_floor_min_writers_multi_endpoint) | `u8` | `1` |
| [`me_adaptive_floor_recover_grace_secs`](#me_adaptive_floor_recover_grace_secs) | `u64` | `180` |
| [`me_adaptive_floor_writers_per_core_total`](#me_adaptive_floor_writers_per_core_total) | `u16` | `48` |
| [`me_adaptive_floor_cpu_cores_override`](#me_adaptive_floor_cpu_cores_override) | `u16` | `0` |
| [`me_adaptive_floor_max_extra_writers_single_per_core`](#me_adaptive_floor_max_extra_writers_single_per_core) | `u16` | `1` |
| [`me_adaptive_floor_max_extra_writers_multi_per_core`](#me_adaptive_floor_max_extra_writers_multi_per_core) | `u16` | `2` |
| [`me_adaptive_floor_max_active_writers_per_core`](#me_adaptive_floor_max_active_writers_per_core) | `u16` | `64` |
| [`me_adaptive_floor_max_warm_writers_per_core`](#me_adaptive_floor_max_warm_writers_per_core) | `u16` | `64` |
| [`me_adaptive_floor_max_active_writers_global`](#me_adaptive_floor_max_active_writers_global) | `u32` | `256` |
| [`me_adaptive_floor_max_warm_writers_global`](#me_adaptive_floor_max_warm_writers_global) | `u32` | `256` |
| [`upstream_connect_retry_attempts`](#upstream_connect_retry_attempts) | `u32` | `2` |
| [`upstream_connect_retry_backoff_ms`](#upstream_connect_retry_backoff_ms) | `u64` | `100` |
| [`upstream_connect_budget_ms`](#upstream_connect_budget_ms) | `u64` | `3000` |
| [`upstream_unhealthy_fail_threshold`](#upstream_unhealthy_fail_threshold) | `u32` | `5` |
| [`upstream_connect_failfast_hard_errors`](#upstream_connect_failfast_hard_errors) | `bool` | `false` |
| [`stun_iface_mismatch_ignore`](#stun_iface_mismatch_ignore) | `bool` | `false` |
| [`unknown_dc_log_path`](#unknown_dc_log_path) | `String` | `"unknown-dc.txt"` |
| [`unknown_dc_file_log_enabled`](#unknown_dc_file_log_enabled) | `bool` | `false` |
| [`log_level`](#log_level) | `"debug"`, `"verbose"`, `"normal"`, or `"silent"` | `"normal"` |
| [`disable_colors`](#disable_colors) | `bool` | `false` |
| [`me_socks_kdf_policy`](#me_socks_kdf_policy) | `"strict"` or `"compat"` | `"strict"` |
| [`me_route_backpressure_base_timeout_ms`](#me_route_backpressure_base_timeout_ms) | `u64` | `25` |
| [`me_route_backpressure_high_timeout_ms`](#me_route_backpressure_high_timeout_ms) | `u64` | `120` |
| [`me_route_backpressure_high_watermark_pct`](#me_route_backpressure_high_watermark_pct) | `u8` | `80` |
| [`me_health_interval_ms_unhealthy`](#me_health_interval_ms_unhealthy) | `u64` | `1000` |
| [`me_health_interval_ms_healthy`](#me_health_interval_ms_healthy) | `u64` | `3000` |
| [`me_admission_poll_ms`](#me_admission_poll_ms) | `u64` | `1000` |
| [`me_warn_rate_limit_ms`](#me_warn_rate_limit_ms) | `u64` | `5000` |
| [`me_route_no_writer_mode`](#me_route_no_writer_mode) | `"async_recovery_failfast"`, `"inline_recovery_legacy"`, or `"hybrid_async_persistent"` | `"hybrid_async_persistent"` |
| [`me_route_no_writer_wait_ms`](#me_route_no_writer_wait_ms) | `u64` | `250` |
| [`me_route_hybrid_max_wait_ms`](#me_route_hybrid_max_wait_ms) | `u64` | `3000` |
| [`me_route_blocking_send_timeout_ms`](#me_route_blocking_send_timeout_ms) | `u64` | `250` |
| [`me_route_inline_recovery_attempts`](#me_route_inline_recovery_attempts) | `u32` | `3` |
| [`me_route_inline_recovery_wait_ms`](#me_route_inline_recovery_wait_ms) | `u64` | `3000` |
| [`fast_mode_min_tls_record`](#fast_mode_min_tls_record) | `usize` | `0` |
| [`update_every`](#update_every) | `u64` | `300` |
| [`me_reinit_every_secs`](#me_reinit_every_secs) | `u64` | `900` |
| [`me_hardswap_warmup_delay_min_ms`](#me_hardswap_warmup_delay_min_ms) | `u64` | `1000` |
| [`me_hardswap_warmup_delay_max_ms`](#me_hardswap_warmup_delay_max_ms) | `u64` | `2000` |
| [`me_hardswap_warmup_extra_passes`](#me_hardswap_warmup_extra_passes) | `u8` | `3` |
| [`me_hardswap_warmup_pass_backoff_base_ms`](#me_hardswap_warmup_pass_backoff_base_ms) | `u64` | `500` |
| [`me_config_stable_snapshots`](#me_config_stable_snapshots) | `u8` | `2` |
| [`me_config_apply_cooldown_secs`](#me_config_apply_cooldown_secs) | `u64` | `300` |
| [`me_snapshot_require_http_2xx`](#me_snapshot_require_http_2xx) | `bool` | `true` |
| [`me_snapshot_reject_empty_map`](#me_snapshot_reject_empty_map) | `bool` | `true` |
| [`me_snapshot_min_proxy_for_lines`](#me_snapshot_min_proxy_for_lines) | `u32` | `1` |
| [`proxy_secret_stable_snapshots`](#proxy_secret_stable_snapshots) | `u8` | `2` |
| [`proxy_secret_rotate_runtime`](#proxy_secret_rotate_runtime) | `bool` | `true` |
| [`me_secret_atomic_snapshot`](#me_secret_atomic_snapshot) | `bool` | `true` |
| [`proxy_secret_len_max`](#proxy_secret_len_max) | `usize` | `256` |
| [`me_pool_drain_ttl_secs`](#me_pool_drain_ttl_secs) | `u64` | `90` |
| [`me_instadrain`](#me_instadrain) | `bool` | `false` |
| [`me_pool_drain_threshold`](#me_pool_drain_threshold) | `u64` | `32` |
| [`me_pool_drain_soft_evict_enabled`](#me_pool_drain_soft_evict_enabled) | `bool` | `true` |
| [`me_pool_drain_soft_evict_grace_secs`](#me_pool_drain_soft_evict_grace_secs) | `u64` | `10` |
| [`me_pool_drain_soft_evict_per_writer`](#me_pool_drain_soft_evict_per_writer) | `u8` | `2` |
| [`me_pool_drain_soft_evict_budget_per_core`](#me_pool_drain_soft_evict_budget_per_core) | `u16` | `16` |
| [`me_pool_drain_soft_evict_cooldown_ms`](#me_pool_drain_soft_evict_cooldown_ms) | `u64` | `1000` |
| [`me_bind_stale_mode`](#me_bind_stale_mode) | `"never"`, `"ttl"`, or `"always"` | `"ttl"` |
| [`me_bind_stale_ttl_secs`](#me_bind_stale_ttl_secs) | `u64` | `90` |
| [`me_pool_min_fresh_ratio`](#me_pool_min_fresh_ratio) | `f32` | `0.8` |
| [`me_reinit_drain_timeout_secs`](#me_reinit_drain_timeout_secs) | `u64` | `90` |
| [`proxy_secret_auto_reload_secs`](#proxy_secret_auto_reload_secs) | `u64` | `3600` |
| [`proxy_config_auto_reload_secs`](#proxy_config_auto_reload_secs) | `u64` | `3600` |
| [`me_reinit_singleflight`](#me_reinit_singleflight) | `bool` | `true` |
| [`me_reinit_trigger_channel`](#me_reinit_trigger_channel) | `usize` | `64` |
| [`me_reinit_coalesce_window_ms`](#me_reinit_coalesce_window_ms) | `u64` | `200` |
| [`me_deterministic_writer_sort`](#me_deterministic_writer_sort) | `bool` | `true` |
| [`me_writer_pick_mode`](#me_writer_pick_mode) | `"sorted_rr"` or `"p2c"` | `"p2c"` |
| [`me_writer_pick_sample_size`](#me_writer_pick_sample_size) | `u8` | `3` |
| [`ntp_check`](#ntp_check) | `bool` | `true` |
| [`ntp_servers`](#ntp_servers) | `String[]` | `["pool.ntp.org"]` |
| [`auto_degradation_enabled`](#auto_degradation_enabled) | `bool` | `true` |
| [`degradation_min_unavailable_dc_groups`](#degradation_min_unavailable_dc_groups) | `u8` | `2` |
| [`rst_on_close`](#rst_on_close) | `"off"`, `"errors"` или `"always"` | `"off"` |

## data_path
  - **Ограничения / валидация**: `String` (необязательный параметр).
  - **Описание**: Необязательный путь к каталогу данных состояния telemt.
  - **Пример**:

    ```toml
    [general]
    data_path = "/var/lib/telemt"
    ```
## prefer_ipv6
  - **Ограничения / валидация**: Устарело. Используйте `network.prefer`.
  - **Описание**: Устаревший флаг предпочтения IPv6 перенесен в `network.prefer`.
  - **Пример**:

    ```toml
    [network]
    prefer = 6
    ```
## fast_mode
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает оптимизированные маршруты для обработки трафика.
  - **Пример**:

    ```toml
    [general]
    fast_mode = true
    ```
## use_middle_proxy
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает режим ME; если значение `false`, telemt возвращается к прямой DC-маршрутизации.
  - **Пример**:

    ```toml
    [general]
    use_middle_proxy = true
    ```
## proxy_secret_path
  - **Ограничения / валидация**: `String`. Если этот параметр не указан, используется путь по умолчанию — «proxy-secret». Пустые значения принимаются TOML/serde, но во время выполнения произойдет ошибка (invalid file path).
  - **Описание**: Путь к файлу кэша `proxy-secret` инфраструктуры Telegram, используемому ME-handshake/аутентификацией RPC. Telemt всегда сначала пытается выполнить новую загрузку с https://core.telegram.org/getProxySecret (если не установлен `proxy_secret_url`), в случае успеха кэширует ее по этому пути и возвращается к чтению кэшированного файла в случае сбоя загрузки.
  - **Пример**:

    ```toml
    [general]
    proxy_secret_path = "proxy-secret"
    ```
## proxy_secret_url
  - **Ограничения / валидация**: `String`. Если не указан, используется `"https://core.telegram.org/getProxySecret"`.
  - **Описание**: Необязательный URL для получения файла `proxy-secret` используемого ME-handshake/аутентификацией RPC. Telemt всегда сначала пытается выполнить новую загрузку с этого URL (если не задан, используется https://core.telegram.org/getProxySecret).
  - **Пример**:

    ```toml
    [general]
    proxy_secret_url = "https://core.telegram.org/getProxySecret"
    ```
## proxy_config_v4_cache_path
  - **Ограничения / валидация**: `String`. Если используется, значение не должно быть пустым или содержать только пробелы.
  - **Описание**: Необязательный путь к кэшу для необработанного (raw) снимка getProxyConfig (IPv4). При запуске Telemt сначала пытается получить свежий снимок; в случае сбоя выборки или пустого снимка он возвращается к этому файлу кэша, если он присутствует и не пуст.
  - **Пример**:

    ```toml
    [general]
    proxy_config_v4_cache_path = "cache/proxy-config-v4.txt"
    ```
## proxy_config_v4_url
  - **Ограничения / валидация**: `String`. Если не указан, используется `"https://core.telegram.org/getProxyConfig"`.
  - **Описание**: Необязательный URL для получения `getProxyConfig` (IPv4). Telemt при всегда пытается выполнить новую загрузку с этого URL (и если не задан, использует `https://core.telegram.org/getProxyConfig`).
  - **Example**:
  
    ```toml
    [general]
    proxy_config_v4_url = "https://core.telegram.org/getProxyConfig"
    ```
## proxy_config_v6_cache_path
  - **Ограничения / валидация**: `String`. Если используется, значение не должно быть пустым или содержать только пробелы.
  - **Описание**: Необязательный путь к кэшу для необработанного (raw) снимка getProxyConfigV6 (IPv6). При запуске Telemt сначала пытается получить свежий снимок; в случае сбоя выборки или пустого снимка он возвращается к этому файлу кэша, если он присутствует и не пуст.
  - **Пример**:

    ```toml
    [general]
    proxy_config_v6_cache_path = "cache/proxy-config-v6.txt"
    ```
## proxy_config_v6_url
- **Ограничения / валидация**: `String`. Если не указан, используется `"https://core.telegram.org/getProxyConfigV6"`.
- **Описание**: Необязательный URL для получения `getProxyConfigV6` (IPv6). Telemt при всегда пытается выполнить новую загрузку с этого URL (и если не задан, использует `https://core.telegram.org/getProxyConfigV6`).
- **Example**:

  ```toml
  [general]
  proxy_config_v6_url = "https://core.telegram.org/getProxyConfigV6"
  ```
## ad_tag
  - **Ограничения / валидация**: `String` (необязательный параметр). Если используется, значение должно быть ровно 32 символа в шестнадцатеричной системе; недопустимые значения отключаются во время загрузки конфигурации.
  - **Описание**: Глобальный резервный спонсируемый канал `ad_tag` (используется, когда у пользователя нет переопределения в `access.user_ad_tags`). Тег со всеми нулями принимается, но не имеет никакого эффекта, пока не будет заменен реальным тегом от `@MTProxybot`.
  - **Пример**:

    ```toml
    [general]
    ad_tag = "00112233445566778899aabbccddeeff"
    ```
## middle_proxy_nat_ip
  - **Ограничения / валидация**: `IpAddr` (необязательный параметр).
  - **Описание**: При установке этого параметра указанное значение публичного IP-адреса NAT используется в качестве адреса ME.
  - **Пример**:

    ```toml
    [general]
    middle_proxy_nat_ip = "203.0.113.10"
    ```
## middle_proxy_nat_probe
  - **Ограничения / валидация**: `bool`. Возможность проверки ограничивается значением параметра `network.stun_use` (когда `network.stun_use = false`, STUN-проверка отключается, даже если этот флаг имеет значение `true`).
  - **Описание**: Позволяет проверить NAT на основе STUN для обнаружения общедоступного IP, используемого при получении ключа ME в средах NAT.
  - **Пример**:

    ```toml
    [general]
    middle_proxy_nat_probe = true
    ```
## middle_proxy_nat_stun
  - **Ограничения / валидация**: Устарело. Используйте `network.stun_servers`.
  - **Описание**: Устаревший сервер STUN для проверки NAT. Во время загрузки конфигурации он объединяется с `network.stun_servers`, если `network.stun_servers` не задан явно.
  - **Пример**:

    ```toml
    [network]
    stun_servers = ["stun.l.google.com:19302"]
    ```
## middle_proxy_nat_stun_servers
  - **Ограничения / валидация**: Устарело. Используйте `network.stun_servers`.
  - **Описание**: Устаревший список STUN серверов для проверки NAT-fallback. Во время загрузки конфигурации значение параметра объединяется с `network.stun_servers`, если `network.stun_servers` не задан явно.
  - **Пример**:

    ```toml
    [network]
    stun_servers = ["stun.l.google.com:19302"]
    ```
## stun_nat_probe_concurrency
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Максимальное количество параллельных тестов STUN для обнаружения NAT/публичного эндпоинта.
  - **Пример**:

    ```toml
    [general]
    stun_nat_probe_concurrency = 8
    ```
## middle_proxy_pool_size
  - **Ограничения / валидация**: `usize`.
  - **Описание**: Размер пула записи ME.
  - **Пример**:

    ```toml
    [general]
    middle_proxy_pool_size = 8
    ```
## middle_proxy_warm_standby
  - **Ограничения / валидация**: `usize`.
  - **Описание**: Количество предварительно инициализированных резервных подключений ME.
  - **Пример**:

    ```toml
    [general]
    middle_proxy_warm_standby = 16
    ```
## me_init_retry_attempts
  - **Ограничения / валидация**: `0..=1_000_000` (`0` означает неограниченное количество повторов).
  - **Описание**: Количество повторных попыток инициализации пула ME.
  - **Пример**:

    ```toml
    [general]
    me_init_retry_attempts = 0
    ```
## me2dc_fallback
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Перейти из режима ME в режим прямого соединения (DC) в случае сбоя запуска ME.
  - **Пример**:

    ```toml
    [general]
    me2dc_fallback = true
    ```
## me2dc_fast
  - **Ограничения / валидация**: `bool`. Используется только, когда `use_middle_proxy = true` и `me2dc_fallback = true`.
  - **Описание**: Режим для быстрого перехода между режимами ME->DC для новых сеансов.
  - **Пример**:

    ```toml
    [general]
    use_middle_proxy = true
    me2dc_fallback = true
    me2dc_fast = false
    ```
## me_keepalive_enabled
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает периодическое добавление дополнительных кадров для ME keepalive-сообщений.
  - **Пример**:

    ```toml
    [general]
    me_keepalive_enabled = true
    ```
## me_keepalive_interval_secs
  - **Ограничения / валидация**: `u64` (секунд).
  - **Описание**: Базовый интервал ME keepalive-сообщений в секундах.
  - **Пример**:

    ```toml
    [general]
    me_keepalive_interval_secs = 8
    ```
## me_keepalive_jitter_secs
  - **Ограничения / валидация**: `u64` (секунд).
  - **Описание**: Случайная задержка (джиттер) keepalive-сообщений в секундах, которая используется для уменьшения синхронных "всплесков" нагрузки.
  - **Пример**:

    ```toml
    [general]
    me_keepalive_jitter_secs = 2
    ```
## me_keepalive_payload_random
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Заполняет данные (payload) keepalive-пакетов случайными байтами вместо фиксированных нулей.
  - **Пример**:

    ```toml
    [general]
    me_keepalive_payload_random = true
    ```
## rpc_proxy_req_every
  - **Ограничения / валидация**: `0` или в пределах `10..=300` (секунд).
  - **Описание**: Интервал для отправки сигналов активности службы `RPC_PROXY_REQ` для ME (`0` отключает).
  - **Пример**:

    ```toml
    [general]
    rpc_proxy_req_every = 0
    ```
## me_writer_cmd_channel_capacity
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Ёмкость (размер) канала команд для каждого отправителя.
  - **Пример**:

    ```toml
    [general]
    me_writer_cmd_channel_capacity = 4096
    ```
## me_route_channel_capacity
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Количество ответов от ME, которое может одновременно находиться “в пути” или в очереди для одного соединения.
  - **Пример**:

    ```toml
    [general]
    me_route_channel_capacity = 768
    ```
## me_c2me_channel_capacity
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Емкость очереди команд для каждого клиента (client reader -> ME sender).
  - **Пример**:

    ```toml
    [general]
    me_c2me_channel_capacity = 1024
    ```
## me_c2me_send_timeout_ms
  - **Ограничения / валидация**: `0..=60000` (миллисекунд).
  - **Описание**: Максимальное ожидание постановки в очередь команд client->ME, если очередь для каждого клиента заполнена (`0` сохраняет устаревшее неограниченное ожидание).
  - **Пример**:

    ```toml
    [general]
    me_c2me_send_timeout_ms = 4000
    ```
## me_reader_route_data_wait_ms
  - **Ограничения / валидация**: `0..=20` (миллисекунд).
  - **Описание**: Ограничение времени ожидания при маршрутизации данных ME в очереди конкретного соединения (0 = без ожидания).
  - **Пример**:

    ```toml
    [general]
    me_reader_route_data_wait_ms = 2
    ```
## me_d2c_flush_batch_max_frames
  - **Ограничения / валидация**: Должно быть в пределах `1..=512`.
  - **Описание**: Максимальное количество кадров (фреймов) от ME к клиенту, объединяемых перед отправкой.
  - **Пример**:

    ```toml
    [general]
    me_d2c_flush_batch_max_frames = 32
    ```
## me_d2c_flush_batch_max_bytes
  - **Ограничения / валидация**: Должно быть в пределах `4096..=2097152` (байт).
  - **Описание**: Максимальный объём данных (в байтах) от ME к клиенту, который можно объединить перед отправкой.
  - **Пример**:

    ```toml
    [general]
    me_d2c_flush_batch_max_bytes = 131072
    ```
## me_d2c_flush_batch_max_delay_us
  - **Ограничения / валидация**: `0..=5000` (миллисекунд).
  - **Описание**: Максимальное время ожидания (в миллисекундах) для накопления дополнительных фреймов от ME к клиенту перед отправкой (0 = без ожидания).
  - **Пример**:

    ```toml
    [general]
    me_d2c_flush_batch_max_delay_us = 500
    ```
## me_d2c_ack_flush_immediate
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Сбрасывать буфер записи клиента сразу после быстрой отправки подтверждения (quick-ack).
  - **Пример**:

    ```toml
    [general]
    me_d2c_ack_flush_immediate = true
    ```
## me_quota_soft_overshoot_bytes
  - **Ограничения / валидация**: `0..=16777216` (байт).
  - **Описание**: Дополнительный допустимый объём (в байтах) на маршрут, который разрешён сверх квоты, прежде чем механизм записи начнёт принудительно отбрасывать данные этого маршрута.
  - **Пример**:

    ```toml
    [general]
    me_quota_soft_overshoot_bytes = 65536
    ```
## me_d2c_frame_buf_shrink_threshold_bytes
  - **Ограничения / валидация**: Должно быть в пределах `4096..=16777216` (байт).
  - **Описание**: Порог, при котором слишком большие буферы агрегации фреймов ME>client уменьшаются (сжимаются) после отправки.
  - **Пример**:

    ```toml
    [general]
    me_d2c_frame_buf_shrink_threshold_bytes = 262144
    ```
## direct_relay_copy_buf_c2s_bytes
  - **Ограничения / валидация**: Должно быть в пределах `4096..=1048576` (байт).
  - **Описание**: Размер буфера копирования для направления client > DC в режиме прямой пересылки (direct relay).
  - **Пример**:

    ```toml
    [general]
    direct_relay_copy_buf_c2s_bytes = 65536
    ```
## direct_relay_copy_buf_s2c_bytes
  - **Ограничения / валидация**: Должно быть в пределах `8192..=2097152` (байт).
  - **Описание**: CoРазмер буфера копирования для направления DC > клиент в режиме прямой пересылки (direct relay).
  - **Пример**:

    ```toml
    [general]
    direct_relay_copy_buf_s2c_bytes = 262144
    ```
## crypto_pending_buffer
  - **Ограничения / валидация**: `usize` (байт).
  - **Описание**:Максимальный объём ожидающих (неотправленных) зашифрованных данных в буфере client writer (в байтах).
  - **Пример**:

    ```toml
    [general]
    crypto_pending_buffer = 262144
    ```
## max_client_frame
  - **Ограничения / валидация**: `usize` (байт).
  - **Описание**: Максимально допустимый размер кадра MTProto клиента (в байтах).
  - **Пример**:

    ```toml
    [general]
    max_client_frame = 16777216
    ```
## desync_all_full
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Создавать полные журналы крипто-рассинхронизации для каждого события
  - **Пример**:

    ```toml
    [general]
    desync_all_full = false
    ```
## beobachten
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает "криминалистическое" наблюдения для каждого IP-адреса. Анализирует поведение всех подключений и записывает возможные типы клиентов, которые посылают active-probing запросы.
  - **Пример**:

    ```toml
    [general]
    beobachten = true
    ```
## beobachten_minutes
  - **Ограничения / валидация**: Должно быть `> 0` (минут).
  - **Описание**: Время хранения (минуты) для сегментов наблюдения по каждому IP-адресу.
  - **Пример**:

    ```toml
    [general]
    beobachten_minutes = 10
    ```
## beobachten_flush_secs
  - **Ограничения / валидация**: Должно быть `> 0` (секунд).
  - **Описание**: Время удаления моментального снимка (в секундах) для файла наблюдения.
  - **Пример**:

    ```toml
    [general]
    beobachten_flush_secs = 15
    ```
## beobachten_file
  - **Ограничения / валидация**: Не должно быть пустым или содержать только пробелы.
  - **Описание**: Путь к выходному снэпшоту наблюдения.
  - **Пример**:

    ```toml
    [general]
    beobachten_file = "cache/beobachten.txt"
    ```
## hardswap
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включить стратегию ME-hardswap на основе генерации.
  - **Пример**:

    ```toml
    [general]
    hardswap = true
    ```
## me_warmup_stagger_enabled
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Распределить во времени дополнительные стадии "прогрева" ME, чтобы избежать всплесков нагрузки на соединения.
  - **Пример**:

    ```toml
    [general]
    me_warmup_stagger_enabled = true
    ```
## me_warmup_step_delay_ms
  - **Ограничения / валидация**: `u64` (миллисекунд).
  - **Описание**: Базовая задержка в миллисекундах между этапами "прогрева".
  - **Пример**:

    ```toml
    [general]
    me_warmup_step_delay_ms = 500
    ```
## me_warmup_step_jitter_ms
  - **Ограничения / валидация**: `u64` (миллисекунд).
  - **Описание**: Дополнительная случайная задержка (джиттер) в миллисекундах для шагов "прогрева".
  - **Пример**:

    ```toml
    [general]
    me_warmup_step_jitter_ms = 300
    ```
## me_reconnect_max_concurrent_per_dc
  - **Ограничения / валидация**: `u32`.
  - **Описание**: Ограничить количество одновременно работающих процессов переподключения (reconnect workers) к DC во время восстановления работоспособности.
  - **Пример**:

    ```toml
    [general]
    me_reconnect_max_concurrent_per_dc = 8
    ```
## me_reconnect_backoff_base_ms
  - **Ограничения / валидация**: `u64` (миллисекунд).
  - **Описание**: Базовая задержка повторного подключения в миллисекундах.
  - **Пример**:

    ```toml
    [general]
    me_reconnect_backoff_base_ms = 500
    ```
## me_reconnect_backoff_cap_ms
  - **Ограничения / валидация**: `u64` (миллисекунд).
  - **Описание**: Максимальная задержка повторного подключения в миллисекундах.
  - **Пример**:

    ```toml
    [general]
    me_reconnect_backoff_cap_ms = 30000
    ```
## me_reconnect_fast_retry_count
  - **Ограничения / валидация**: `u32`.
  - **Описание**: Лимит немедленных повторных попыток подключения перед тем, как включается долгий backoff (увеличивающаяся задержка между попытками).
  - **Пример**:

    ```toml
    [general]
    me_reconnect_fast_retry_count = 16
    ```
## me_single_endpoint_shadow_writers
  - **Ограничения / валидация**: Должно быть в пределах `0..=32`.
  - **Описание**: Количество дополнительных резервных writer-процессов для групп DC, у которых есть только один конечный узел (endpoint).
  - **Пример**:

    ```toml
    [general]
    me_single_endpoint_shadow_writers = 2
    ```
## me_single_endpoint_outage_mode_enabled
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает агрессивный режим восстановления после сбоя для групп DC, когда доступен только один endpoint.
  - **Пример**:

    ```toml
    [general]
    me_single_endpoint_outage_mode_enabled = true
    ```
## me_single_endpoint_outage_disable_quarantine
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Игнорировать карантин endpoint’а в режиме сбоя, когда доступен только один endpoint.
  - **Пример**:

    ```toml
    [general]
    me_single_endpoint_outage_disable_quarantine = true
    ```
## me_single_endpoint_outage_backoff_min_ms
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунд) и меньше или равно `me_single_endpoint_outage_backoff_max_ms`.
  - **Описание**: Минимальная задержка между повторными попытками переподключения (reconnect backoff) в режиме сбоя с единственным endpoint’ом.
  - **Пример**:

    ```toml
    [general]
    me_single_endpoint_outage_backoff_min_ms = 250
    ```
## me_single_endpoint_outage_backoff_max_ms
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунд) и больше или равно  `me_single_endpoint_outage_backoff_min_ms`.
  - **Описание**: Максимальная задержка между попытками переподключения (reconnect backoff) в режиме сбоя с единственным endpoint’ом.
  - **Пример**:

    ```toml
    [general]
    me_single_endpoint_outage_backoff_max_ms = 3000
    ```
## me_single_endpoint_shadow_rotate_every_secs
  - **Ограничения / валидация**: `u64` (секунды). `0` отключает периодическую ротацию.
  - **Описание**: Интервал периодической ротации резервного (shadow) writer’а для DC-групп с единственным endpoint’ом
  - **Пример**:

    ```toml
    [general]
    me_single_endpoint_shadow_rotate_every_secs = 900
    ```
## me_floor_mode
  - **Ограничения / валидация**: `"static"` или `"adaptive"`.
  - **Описание**: Режим политики нижнего порога (минимального ограничения) для целевых узлов/получателей ME writer’а.
  - **Пример**:

    ```toml
    [general]
    me_floor_mode = "adaptive"
    ```
## me_adaptive_floor_idle_secs
  - **Ограничения / валидация**: `u64` (секунды).
  - **Описание**: Время простоя, после которого адаптивный нижний порог (adaptive floor) может уменьшить целевой лимит writer’а для единственного endpoint’а.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_idle_secs = 90
    ```
## me_adaptive_floor_min_writers_single_endpoint
  - **Ограничения / валидация**: Должно быть в пределах `1..=32`.
  - **Описание**: Минимально допустимое количество writer’ов в DC-группах с одним endpoint’ом в режиме адаптивного нижнего порога (adaptive floor).
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_min_writers_single_endpoint = 1
    ```
## me_adaptive_floor_min_writers_multi_endpoint
  - **Ограничения / валидация**: Должно быть в пределах `1..=32`.
  - **Описание**: Минимально допустимое количество writer’ов в DC-группах с несколькими endpoint’ами в режиме адаптивного нижнего порога (adaptive floor).
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_min_writers_multi_endpoint = 1
    ```
## me_adaptive_floor_recover_grace_secs
  - **Ограничения / валидация**: `u64` (секунды).
  - **Описание**: Период “льготного ожидания”, в течение которого сохраняется фиксированный (static) нижний порог после появления активности в адаптивном режиме
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_recover_grace_secs = 180
    ```
## me_adaptive_floor_writers_per_core_total
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Глобальный лимит записи ME writer’а на каждое логическое CPU-ядро в адаптивном режиме.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_writers_per_core_total = 48
    ```
## me_adaptive_floor_cpu_cores_override
  - **Ограничения / валидация**: `u16`. `0` - использовать автоматическое обнаружение во время выполнения.
  - **Описание**: Переопределить количество логических CPU-ядер, используемых при расчёте адаптивного нижнего порога (adaptive floor).
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_cpu_cores_override = 0
    ```
## me_adaptive_floor_max_extra_writers_single_per_core
  - **Ограничения / валидация**: `u16`.
  - **Описание**: Максимальное количество дополнительных writer-процессов на одно CPU-ядро сверх базового требуемого уровня для DC-групп с единственным endpoint’ом.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_max_extra_writers_single_per_core = 1
    ```
## me_adaptive_floor_max_extra_writers_multi_per_core
  - **Ограничения / валидация**: `u16`.
  - **Описание**: Максимальное количество дополнительных writer-процессов на одно CPU-ядро сверх базового требуемого уровня для DC-групп с несколькими endpoint’ами.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_max_extra_writers_multi_per_core = 2
    ```
## me_adaptive_floor_max_active_writers_per_core
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Лимит количества ME writer-процессов на одно логическое CPU-ядро.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_max_active_writers_per_core = 64
    ```
## me_adaptive_floor_max_warm_writers_per_core
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Лимит количества “разогретых” (warm) ME writer-процессов на одно логическое CPU-ядро.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_max_warm_writers_per_core = 64
    ```
## me_adaptive_floor_max_active_writers_global
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Глобальный лимит количества ME writer-процессов.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_max_active_writers_global = 256
    ```
## me_adaptive_floor_max_warm_writers_global
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Глобальный лимит количества “разогретых” (warm) ME writer-процессов.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_max_warm_writers_global = 256
    ```
## upstream_connect_retry_attempts
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Количество попыток подключения к выбранному upstream'у перед тем, как вернуть ошибку или перейти к fallback.
  - **Пример**:

    ```toml
    [general]
    upstream_connect_retry_attempts = 2
    ```
## upstream_connect_retry_backoff_ms
  - **Ограничения / валидация**: `u64` (миллисекунды). `0` - отключает задержку отсрочки (повторные попытки становятся немедленными).
  - **Описание**: Задержка в миллисекундах между попытками подключения к upstream.
  - **Пример**:

    ```toml
    [general]
    upstream_connect_retry_backoff_ms = 100
    ```
## upstream_connect_budget_ms
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунд).
  - **Описание**: Общий лимит времени (в миллисекундах), измеряемый по реальному времени (wall-clock), на одну попытку подключения к upstream с учётом всех повторных попыток.
  - **Пример**:

    ```toml
    [general]
    upstream_connect_budget_ms = 3000
    ```
## upstream_unhealthy_fail_threshold
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Количество неудачных запросов подряд, после которого upstream помечается, как неработоспособный.
  - **Пример**:

    ```toml
    [general]
    upstream_unhealthy_fail_threshold = 5
    ```
## upstream_connect_failfast_hard_errors
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Если включено (true), telemt пропускает дополнительные повторные попытки для постоянных ошибок подключения к upstream.
  - **Пример**:

    ```toml
    [general]
    upstream_connect_failfast_hard_errors = false
    ```
## stun_iface_mismatch_ignore
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Флаг совместимости, зарезервированный для будущего использования. Сейчас этот параметр читается (парсится), но не используется средой выполнения.
  - **Пример**:

    ```toml
    [general]
    stun_iface_mismatch_ignore = false
    ```
## unknown_dc_log_path
  - **Ограничения / валидация**: `String` (необязательный параметр). Путь должен быть без `..` и с существующим родительским каталогом, иначе он будет отклонён во время выполнения.
  - **Описание**: Путь к файлу логов для неизвестных (нестандартных) DC-запросов, который используется только если `unknown_dc_file_log_enabled = true`. Чтобы отключить файловое логирование, не указывйте этот параметр.
  - **Пример**:

    ```toml
    [general]
    unknown_dc_log_path = "unknown-dc.txt"
    ```
## unknown_dc_file_log_enabled
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включить файловое логирование неизвестных DC (записывает строки вида `dc_idx=<N>`). Требует, чтобы был задан `unknown_dc_log_path`. На не-Unix платформах может не поддерживаться. Логирование очищается от дубликатов и имеет ограничения: записываются только первые ~1024 уникальных неизвестных DC-индексов.
  - **Пример**:

    ```toml
    [general]
    unknown_dc_file_log_enabled = false
    ```
## log_level
  - **Ограничения / валидация**: `"debug"`, `"verbose"`, `"normal"`, или `"silent"`.
  - **Описание**: Уровень детализации логов во время работы системы, который используется только если переменная окружения `RUST_LOG` не задана. Если `RUST_LOG` задана, она имеет приоритет и переопределяет этот параметр.
  - **Пример**:

    ```toml
    [general]
    log_level = "normal"
    ```
## disable_colors
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Отключает ANSI-цвета в логах. Это влияет только на форматирование вывода и не меняет уровень логирования и фильтрацию сообщений..
  - **Пример**:

    ```toml
    [general]
    disable_colors = false
    ```
## me_socks_kdf_policy
  - **Ограничения / валидация**: `"strict"` или `"compat"`.
  - **Описание**: Политика fallback-поведения KDF, привязанная к SOCKS, для Middle-End-handshake.
  - **Пример**:

    ```toml
    [general]
    me_socks_kdf_policy = "strict"
    ```
## me_route_backpressure_base_timeout_ms
  - **Ограничения / валидация**: Должно быть в пределах `1..=5000` (миллисекунд).
  - **Описание**: Базовый таймаут (в миллисекундах) ожидания при режиме **backpressure** (ситуация, при которой данные обрабатываются медленне, чем получаются) для отправки через ME route-channel.
  - **Пример**:

    ```toml
    [general]
    me_route_backpressure_base_timeout_ms = 25
    ```
## me_route_backpressure_high_timeout_ms
  - **Ограничения / валидация**: Должно быть в пределах `1..=5000` (миллисекунд) и больше или равно `me_route_backpressure_base_timeout_ms`.
  - **Описание**: Увеличенный таймаут ожидания (в миллисекундах) при режиме **backpressure**, когда заполненность очереди превышает порог.
  - **Пример**:

    ```toml
    [general]
    me_route_backpressure_high_timeout_ms = 120
    ```
## me_route_backpressure_high_watermark_pct
  - **Ограничения / валидация**: Должно быть в пределах `1..=100` (процентов).
  - **Описание**: Порог заполненности очереди (в процентах), при превышении которого система переключается на увеличенный таймаут **backpressure**.
  - **Пример**:

    ```toml
    [general]
    me_route_backpressure_high_watermark_pct = 80
    ```
## me_health_interval_ms_unhealthy
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунд).
  - **Описание**: Интервал проверки состояния (health monitoring), который используется, когда покрытие ME-writer’ов ухудшено (деградировало).
  - **Пример**:

    ```toml
    [general]
    me_health_interval_ms_unhealthy = 1000
    ```
## me_health_interval_ms_healthy
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунд).
  - **Описание**: Интервал проверки состояния (health monitoring), который используется, когда покрытие ME-writer’ов стабильно.
  - **Пример**:

    ```toml
    [general]
    me_health_interval_ms_healthy = 3000
    ```
## me_admission_poll_ms
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунд).
  - **Описание**: Интервал опроса (polling interval) для проверки состояния приема при выполнении условий (conditional admission).
  - **Пример**:

    ```toml
    [general]
    me_admission_poll_ms = 1000
    ```
## me_warn_rate_limit_ms
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунд).
  - **Описание**: Период "затухания" (cooldown) для повторяющихся предупреждающих логов ME, чтобы ограничить их частоту.
  - **Пример**:

    ```toml
    [general]
    me_warn_rate_limit_ms = 5000
    ```
## me_route_no_writer_mode
  - **Ограничения / валидация**: `"async_recovery_failfast"`, `"inline_recovery_legacy"`, or `"hybrid_async_persistent"`.
  - **Описание**: Поведение ME-маршрута, когда ни один writer не доступен.
  - **Пример**:

    ```toml
    [general]
    me_route_no_writer_mode = "hybrid_async_persistent"
    ```
## me_route_no_writer_wait_ms
  - **Ограничения / валидация**: Должно быть в пределах `10..=5000` (миллисекунды).
  - **Описание**: Максимальное время ожидания, используемое в режиме **async-recovery failfast** перед переходом к fallback.
  - **Пример**:

    ```toml
    [general]
    me_route_no_writer_wait_ms = 250
    ```
## me_route_hybrid_max_wait_ms
  - **Ограничения / валидация**: Должно быть в пределах `50..=60000` (миллисекунд).
  - **Описание**: Максимальное суммарное время ожидания в гибридном режиме без writer’а перед failfast fallback.
  - **Пример**:

    ```toml
    [general]
    me_route_hybrid_max_wait_ms = 3000
    ```
## me_route_blocking_send_timeout_ms
  - **Ограничения / валидация**: Должно быть в пределах `0..=5000` (миллисекунд). `0` - неограниченное время ожидания.
  - **Описание**: Максимальное время ожидания для блокировки отправки через канал маршрутизации при fallback.
  - **Пример**:

    ```toml
    [general]
    me_route_blocking_send_timeout_ms = 250
    ```
## me_route_inline_recovery_attempts
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Количество попыток inline-восстановления в legacy-режиме
  - **Пример**:

    ```toml
    [general]
    me_route_inline_recovery_attempts = 3
    ```
## me_route_inline_recovery_wait_ms
  - **Ограничения / валидация**: Должно быть в пределах `10..=30000` (миллисекунд).
  - **Описание**: Максимальное время ожидания inline-восстановления в legacy-режиме.
  - **Пример**:

    ```toml
    [general]
    me_route_inline_recovery_wait_ms = 3000
    ```
## fast_mode_min_tls_record
  - **Ограничения / валидация**: `usize` (bytes). `0` disables the limit.
  - **Описание**: Минимальный размер TLS-записи при включённой агрегации fast-mode.
  - **Пример**:

    ```toml
    [general]
    fast_mode_min_tls_record = 0
    ```
## update_every
  - **Ограничения / валидация**: `u64` (секунд). Должно быть `> 0`. Если этот ключ не задан явно, могут использоваться устаревшие параметры `proxy_secret_auto_reload_secs` и `proxy_config_auto_reload_secs` (их эффективное минимальное значение должно быть `> 0`).
  - **Описание**: Унифицированный интервал обновления задач ME-updater’а (getProxyConfig, getProxyConfigV6, getProxySecret). При установке переопределяет устаревшие интервалы автообновления прокси-сервера.
  - **Пример**:

    ```toml
    [general]
    update_every = 300
    ```
## me_reinit_every_secs
  - **Ограничения / валидация**: Должно быть `> 0` (секунд).
  - **Описание**: Интервал для выполнения цикла повторной инициализации ME с нулевым временем простоя.
  - **Пример**:

    ```toml
    [general]
    me_reinit_every_secs = 900
    ```
## me_hardswap_warmup_delay_min_ms
  - **Ограничения / валидация**: `u64` (миллисекунд). Должно быть `<= me_hardswap_warmup_delay_max_ms`.
  - **Описание**: Нижняя граница задержки между шагами "прогрева" при "принудительном" изменении состояния.
  - **Пример**:

    ```toml
    [general]
    me_hardswap_warmup_delay_min_ms = 1000
    ```
## me_hardswap_warmup_delay_max_ms
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунд).
  - **Описание**: Верхняя граница задержки между шагами "прогрева" при "принудительном" изменении состояния.
  - **Пример**:

    ```toml
    [general]
    me_hardswap_warmup_delay_max_ms = 2000
    ```
## me_hardswap_warmup_extra_passes
  - **Ограничения / валидация**: Должно быть в пределах `[0, 10]`.
  - **Описание**: Количество дополнительных циклов "прогрева" сверх базового при "принудительном" изменении состояния.
  - **Пример**:

    ```toml
    [general]
    # default: 3 (allowed range: 0..=10)
    me_hardswap_warmup_extra_passes = 3
    ```
## me_hardswap_warmup_pass_backoff_base_ms
  - **Ограничения / валидация**: `u64` (миллисекунд). Должно быть `> 0`.
  - **Описание**: Базовая задержка повторной попытки между дополнительными проходами "прогрева" при "принудительном" изменении состояния, если нижний порог ещё не достигнут.
  - **Пример**:

    ```toml
    [general]
    # default: 500
    me_hardswap_warmup_pass_backoff_base_ms = 500
    ```
## me_config_stable_snapshots
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Количество одинаковых подряд снимков конфигурации ME, необходимых для применения изменений.
  - **Пример**:

    ```toml
    [general]
    # require 3 identical snapshots before applying ME endpoint map updates
    me_config_stable_snapshots = 3
    ```
## me_config_apply_cooldown_secs
  - **Ограничения / валидация**: `u64`.
  - **Описание**: Время восстановления между примененными обновлениями карты конечных точек ME. `0` отключает время восстановления.
  - **Пример**:

    ```toml
    [general]
    # allow applying stable snapshots immediately (no cooldown)
    me_config_apply_cooldown_secs = 0
    ```
## me_snapshot_require_http_2xx
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Требовать HTTP-ответы **2xx** для применения снимков конфигурации ME. Если `false`, **не-2xx** ответы также могут быть проанализированы/учтены программой обновления.
  - **Пример**:

    ```toml
    [general]
    # allow applying snapshots even when the HTTP status is non-2xx
    me_snapshot_require_http_2xx = false
    ```
## me_snapshot_reject_empty_map
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Отклоняет пустые snapshot-конфигурации ME (без endpoint’ов). Если установлено значение `false`, пустой snapshot может быть применён (при выполнении других условий), что может временно очистить или уменьшить карту ME.
  - **Пример**:

    ```toml
    [general]
    # allow applying empty snapshots (use with care)
    me_snapshot_reject_empty_map = false
    ```
## me_snapshot_min_proxy_for_lines
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Минимальное количество проанализированных строк `proxy_for`, необходимое для принятия снимка.
  - **Пример**:

    ```toml
    [general]
    # require at least 10 proxy_for rows before accepting a snapshot
    me_snapshot_min_proxy_for_lines = 10
    ```
## proxy_secret_stable_snapshots
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Количество идентичных снимков с секретом прокси-сервера, необходимых для ротации.
  - **Пример**:

    ```toml
    [general]
    # require 2 identical getProxySecret snapshots before rotating at runtime
    proxy_secret_stable_snapshots = 2
    ```
## proxy_secret_rotate_runtime
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает ротацию proxy-secret на основе снапшотов, получаемых от обновляющего компонента.
  - **Пример**:

    ```toml
    [general]
    # disable runtime proxy-secret rotation (startup still uses proxy_secret_path/proxy_secret_len_max)
    proxy_secret_rotate_runtime = false
    ```
## me_secret_atomic_snapshot
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Сохраняет селекторные и секретные байты из одного и того же снимка атомарно. Если `general.use_middle_proxy = true`, автоматически включается при загрузке конфигурации для согласованности KDF-данных ME.
  - **Пример**:

    ```toml
    [general]
    # NOTE: when use_middle_proxy=true, Telemt will auto-enable this during load
    me_secret_atomic_snapshot = false
    ```
## proxy_secret_len_max
  - **Ограничения / валидация**: Должно быть в пределах `[32, 4096]`.
  - **Описание**: Верхний предел длины (в байтах) принимаемого proxy-secret во время запуска и обновления.
  - **Пример**:

    ```toml
    [general]
    # default: 256 (bytes)
    proxy_secret_len_max = 256
    ```
## me_pool_drain_ttl_secs
  - **Ограничения / валидация**: `u64` (секунды). `0` - отключает период drain-TTL и подавляет предупреждения drain-TTL для ненулевых (непустых) writer’ов, находящихся в состоянии **draining**.
  - **Описание**: Временной интервал Drain-TTL для устаревших ME writer’ов после изменения карты endpoint’ов. В течение TTL устаревшие writer’ы могут использоваться только как fallback для новых биндов (в зависимости от политики биндов).
  - **Пример**:

    ```toml
    [general]
    # disable drain TTL (draining writers won't emit "past drain TTL" warnings)
    me_pool_drain_ttl_secs = 0
    ```
## me_instadrain
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Принудительно удаляет устаревшие writer’ы на следующем цикле очистки, обходя TTL и таймаут ожидания.
  - **Пример**:

    ```toml
    [general]
    # default: false
    me_instadrain = false
    ```
## me_pool_drain_threshold
  - **Ограничения / валидация**: `u64`. Установите значение `0`, чтобы отключить очистку на основе пороговых значений.
  - **Описание**: Максимальное количество устаревших writer’ов, после которого самые старые принудительно закрываются в пакетном режиме.
  - **Пример**:

    ```toml
    [general]
    # default: 32
    me_pool_drain_threshold = 32
    ```
## me_pool_drain_soft_evict_enabled
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает постепенное удаление устаревших writer’ов во время очистки/повторной инициализации вместо их немедленного закрытия.
  - **Пример**:

    ```toml
    [general]
    # default: true
    me_pool_drain_soft_evict_enabled = true
    ```
## me_pool_drain_soft_evict_grace_secs
  - **Ограничения / валидация**: `u64` (секунд). Должно быть в пределах `[0, 3600]`.
  - **Описание**: Дополнительный период ожидания после TTL перед началом этапа мягкого удаления.
  - **Пример**:

    ```toml
    [general]
    # default: 10
    me_pool_drain_soft_evict_grace_secs = 10
    ```
## me_pool_drain_soft_evict_per_writer
  - **Ограничения / валидация**: `1..=16`.
  - **Описание**: Максимальное количество устаревших маршрутов, вытесняемых за один проход мягкого удаления на один writer.
  - **Пример**:

    ```toml
    [general]
    # default: 2
    me_pool_drain_soft_evict_per_writer = 2
    ```
## me_pool_drain_soft_evict_budget_per_core
  - **Ограничения / валидация**: `1..=64`.
  - **Описание**: Лимиты работы мягкого удаления на одно CPU-ядро за один проход.
  - **Пример**:

    ```toml
    [general]
    # default: 16
    me_pool_drain_soft_evict_budget_per_core = 16
    ```
## me_pool_drain_soft_evict_cooldown_ms
  - **Ограничения / валидация**: `u64` (миллисекунд). Должно быть `> 0`.
  - **Описание**: Время восстановления между повторяющимися мягкими удалениями одного и того же writer’а.
  - **Пример**:

    ```toml
    [general]
    # default: 1000
    me_pool_drain_soft_evict_cooldown_ms = 1000
    ```
## me_bind_stale_mode
  - **Ограничения / валидация**: `"never"`, `"ttl"` или `"always"`.
  - **Описание**: Политика разрешения новых биндов к устаревшим writer’ам.
  - **Пример**:

    ```toml
    [general]
    # allow stale binds only for a limited time window
    me_bind_stale_mode = "ttl"
    ```
## me_bind_stale_ttl_secs
  - **Ограничения / валидация**: `u64`.
  - **Описание**: TTL для разрешения биндов к устаревшим writer’ам при режиме `ttl`.
  - **Пример**:

    ```toml
    [general]
    me_bind_stale_mode = "ttl"
    me_bind_stale_ttl_secs = 90
    ```
## me_pool_min_fresh_ratio
  - **Ограничения / валидация**: Должно быть в пределах `[0.0, 1.0]`.
  - **Описание**: Минимальный коэффициент актуального (fresh) покрытия DC перед началом удаления устаревших writer’ов.
  - **Пример**:

    ```toml
    [general]
    # require >=90% desired-DC coverage before draining stale writers
    me_pool_min_fresh_ratio = 0.9
    ```
## me_reinit_drain_timeout_secs
  - **Ограничения / валидация**: `u64`. `0` - используется безопасный системный fallback. Если значение `> 0` и `< me_pool_drain_ttl_secs`, повышает его до значения TTL.
  - **Описание**: Таймаут принудительного закрытия устаревших writer’ов при очистке/повторной инициализации. При `0` используется безопасный системный fallback (300 секунд).
  - **Пример**:

    ```toml
    [general]
    # use runtime safety fallback force-close timeout (300s)
    me_reinit_drain_timeout_secs = 0
    ```
## proxy_secret_auto_reload_secs
  - **Ограничения / валидация**: Устарело. Используйте `general.update_every`. Если `general.update_every` не задан, эффективный интервал обновления равен `min(proxy_secret_auto_reload_secs, proxy_config_auto_reload_secs)` и должен быть `> 0`.
  - **Описание**: Интервал обновления устаревшего секрета прокси-сервера. Используется только, если `general.update_every` не задан.
  - **Пример**:

    ```toml
    [general]
    # legacy mode: omit update_every to use proxy_*_auto_reload_secs
    proxy_secret_auto_reload_secs = 600
    proxy_config_auto_reload_secs = 120
    # effective updater interval = min(600, 120) = 120 seconds
    ```
## proxy_config_auto_reload_secs
  - **Ограничения / валидация**: Устарело. Используйте `general.update_every`. Если `general.update_every` не задан, эффективный устаревший интервал обновления равен `min(proxy_secret_auto_reload_secs, proxy_config_auto_reload_secs)` и должен быть `> 0`.
  - **Описание**: Интервал обновления устаревшей конфигурации ME. Используется только, если `general.update_every` не задан.
  - **Пример**:

    ```toml
    [general]
    # legacy mode: omit update_every to use proxy_*_auto_reload_secs
    proxy_secret_auto_reload_secs = 600
    proxy_config_auto_reload_secs = 120
    # effective updater interval = min(600, 120) = 120 seconds
    ```
## me_reinit_singleflight
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Упорядочивать циклы повторной инициализации ME, поступающие от разных источников триггеров.
  - **Пример**:

    ```toml
    [general]
    me_reinit_singleflight = true
    ```
## me_reinit_trigger_channel
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Емкость очереди триггеров для планировщика повторной инициализации.
  - **Пример**:

    ```toml
    [general]
    me_reinit_trigger_channel = 64
    ```
## me_reinit_coalesce_window_ms
  - **Ограничения / валидация**: `u64`.
  - **Описание**: Время объединения (coalescing) триггеров перед запуском переинициализации (в мс).
  - **Пример**:

    ```toml
    [general]
    me_reinit_coalesce_window_ms = 200
    ```
## me_deterministic_writer_sort
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включить детерминированную сортировку кандидатов при выборе writer’а.
  - **Пример**:

    ```toml
    [general]
    me_deterministic_writer_sort = true
    ```
## me_writer_pick_mode
  - **Ограничения / валидация**: `"sorted_rr"` or `"p2c"`.
  - **Описание**: Режим выбора writer’а для бинда маршрута.
  - **Пример**:

    ```toml
    [general]
    me_writer_pick_mode = "p2c"
    ```
## me_writer_pick_sample_size
  - **Ограничения / валидация**: `2..=4`.
  - **Описание**: Количество кандидатов, отобранных сборщиком в режиме p2c.
  - **Пример**:

    ```toml
    [general]
    me_writer_pick_mode = "p2c"
    me_writer_pick_sample_size = 3
    ```
## ntp_check
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Зарезервировано для будущего использования. Сейчас параметр читается, но не используется системой.
  - **Пример**:

    ```toml
    [general]
    ntp_check = true
    ```
## ntp_servers
  - **Ограничения / валидация**: `String[]`.
  - **Описание**: Зарезервировано для будущего использования. Сейчас параметр читается, но не используется системой.
  - **Пример**:

    ```toml
    [general]
    ntp_servers = ["pool.ntp.org"]
    ```
## auto_degradation_enabled
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Зарезервировано для будущего использования. Сейчас параметр читается, но не используется системой.
  - **Пример**:

    ```toml
    [general]
    auto_degradation_enabled = true
    ```
## degradation_min_unavailable_dc_groups
  - **Ограничения / валидация**: `u8`.
  - **Описание**: Зарезервировано для будущего использования. Сейчас параметр читается, но не используется системой.
  - **Пример**:

    ```toml
    [general]
    degradation_min_unavailable_dc_groups = 2
    ```

## rst_on_close
  - **Ограничения / валидация**: `"off"`, `"errors"`, `"always"`.
  - **Описание**: Управляет поведением `SO_LINGER(0)` на принятых клиентских TCP-сокетах.
    На высоконагруженных прокси-серверах накапливаются `FIN-WAIT-1` и осиротевшие (orphan) сокеты от соединений, которые не завершают Telegram-рукопожатие (сканеры, DPI-зонды, боты).
    Эта опция позволяет отправлять немедленный `RST` вместо корректного `FIN` для таких соединений, мгновенно освобождая ресурсы ядра.
    - `"off"` — по умолчанию. Обычный `FIN` при закрытии всех соединений; поведение не меняется.
    - `"errors"` — `SO_LINGER(0)` устанавливается при `accept()`. Если клиент успешно проходит аутентификацию, linger сбрасывается и relay-сессия закрывается корректно через `FIN`. Соединения, закрытые до завершения рукопожатия (таймауты, ошибки крипто, сканеры), отправляют `RST`.
    - `"always"` — `SO_LINGER(0)` устанавливается при `accept()` и никогда не сбрасывается. Все закрытия отправляют `RST` независимо от результата рукопожатия.
  - **Пример**:

    ```toml
    [general]
    rst_on_close = "errors"
    ```


# [general.modes]


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`classic`](#classic) | `bool` | `false` |
| [`secure`](#secure) | `bool` | `false` |
| [`tls`](#tls) | `bool` | `true` |

## classic
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает классический режим MTProxy.
  - **Пример**:

    ```toml
    [general.modes]
    classic = true
    ```
## secure
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает защищённый режим (dd-ссылки).
  - **Пример**:

    ```toml
    [general.modes]
    secure = true
    ```
## tls
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает режим TLS (ee-ссылки).
  - **Пример**:

    ```toml
    [general.modes]
    tls = true
    ```


# [general.links]


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`show`](#show) | `"*"` or `String[]` | `"*"` |
| [`public_host`](#public_host) | `String` | — |
| [`public_port`](#public_port) | `u16` | — |

## show
  - **Ограничения / валидация**: `"*"` или `String[]`. Пустое значение означает, что нельзя показывать никому.
  - **Описание**: Определяет пользователей, для которых показываются proxy-ссылки tg:// при запуске.
  - **Пример**:

    ```toml
    [general.links]
    show = "*"
    # or:
    # show = ["alice", "bob"]
    ```
## public_host
  - **Ограничения / валидация**: `String` (необязательный параметр).
  - **Описание**: Переопределение общедоступного имени хоста/IP-адреса, используемое для сгенерированных ссылок `tg://` (перезаписывает автоматически определённый IP).
  - **Пример**:

    ```toml
    [general.links]
    public_host = "proxy.example.com"
    ```
## public_port
  - **Ограничения / валидация**: `u16` (необязательный параметр).
  - **Описание**: Публичный порт для генерации tg:// ссылок (перезаписывает server.port).
  - **Пример**:

    ```toml
    [general.links]
    public_port = 443
    ```


# [general.telemetry]


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`core_enabled`](#core_enabled) | `bool` | `true` |
| [`user_enabled`](#user_enabled) | `bool` | `true` |
| [`me_level`](#me_level) | `"silent"`, `"normal"`, or `"debug"` | `"normal"` |

## core_enabled
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает метрики ядра (hot-path telemetry counters).
  - **Пример**:

    ```toml
    [general.telemetry]
    core_enabled = true
    ```
## user_enabled
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает счетчики телеметрии для каждого пользователя.
  - **Пример**:

    ```toml
    [general.telemetry]
    user_enabled = true
    ```
## me_level
  - **Ограничения / валидация**: `"silent"`, `"normal"`или `"debug"`.
  - **Описание**: Уровень детализации телеметрии Middle-End.
  - **Пример**:

    ```toml
    [general.telemetry]
    me_level = "normal"
    ```


# [network]


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`ipv4`](#ipv4) | `bool` | `true` |
| [`ipv6`](#ipv6) | `bool` | `false` |
| [`prefer`](#prefer) | `u8` | `4` |
| [`multipath`](#multipath) | `bool` | `false` |
| [`stun_use`](#stun_use) | `bool` | `true` |
| [`stun_servers`](#stun_servers) | `String[]` | Встроенный STUN-лист (13 записей) |
| [`stun_tcp_fallback`](#stun_tcp_fallback) | `bool` | `true` |
| [`http_ip_detect_urls`](#http_ip_detect_urls) | `String[]` | `["https://ifconfig.me/ip", "https://api.ipify.org"]` |
| [`cache_public_ip_path`](#cache_public_ip_path) | `String` | `"cache/public_ip.txt"` |
| [`dns_overrides`](#dns_overrides) | `String[]` | `[]` |

## ipv4
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает возможность подключения по IPv4.
  - **Пример**:

    ```toml
    [network]
    ipv4 = true
    ```
## ipv6
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает возможность подключения по IPv6. Если не задан - используется значение `false`.
  - **Пример**:

    ```toml
    [network]
    # enable IPv6 explicitly
    ipv6 = true

    # or: disable IPv6 explicitly
    # ipv6 = false
    ```
## prefer
  - **Ограничения / валидация**: Должно быть `4` или `6`. Если `prefer = 4`, а `ipv4 = false`, Telemt принудительно использует `prefer = 6`. Если `prefer = 6`, а `ipv6 = false`, Telemt принудительно использует `prefer = 4`.
  - **Описание**: Предпочтительный IP-протокол (IPv4 или IPv6) при выборе, если доступны оба.
  - **Пример**:

    ```toml
    [network]
    prefer = 6
    ```
## multipath
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает многопоточное (multipath) сетевое поведение, если оно поддерживается платформой и средой выполняния.
  - **Пример**:

    ```toml
    [network]
    multipath = true
    ```
## stun_use
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Глобальный переключатель STUN; если установлено значение «false», проверка STUN отключается и остается только обнаружение без STUN.
  - **Пример**:

    ```toml
    [network]
    stun_use = false
    ```
## stun_servers
  - **Ограничения / валидация**: `String[]`. Значения обрезаются; пустые значения удаляются; список очищается от дубликатов. Если этот ключ **не** задан явно, Telemt использует встроенный список STUN по умолчанию.
  - **Описание**: Список STUN-серверов для определения публичного IP-адреса.
  - **Пример**:

    ```toml
    [network]
    stun_servers = [
      "stun.l.google.com:19302",
      "stun.stunprotocol.org:3478",
    ]
    ```
## stun_tcp_fallback
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает резервный TCP для STUN в случае недоступности UDP-соединения.
  - **Пример**:

    ```toml
    [network]
    stun_tcp_fallback = true
    ```
## http_ip_detect_urls
  - **Ограничения / валидация**: `String[]`.
  - **Описание**: HTTP-эндпоинты, используемые для определения публичного IP (резервный вариант после STUN).
  - **Пример**:

    ```toml
    [network]
    http_ip_detect_urls = ["https://ifconfig.me/ip", "https://api.ipify.org"]
    ```
## cache_public_ip_path
  - **Ограничения / валидация**: `String`.
  - **Описание**: Путь к файлу, в котором кэшируется определённый публичный IP.
  - **Пример**:

    ```toml
    [network]
    cache_public_ip_path = "cache/public_ip.txt"
    ```
## dns_overrides
  - **Ограничения / валидация**: `String[]`. Каждая запись должна использовать формат `host:port:ip`.
    - `host`: доменное имя (не должно быть пустым и не должно содержать `:`)
    - `port`: `u16`
    - `ip`: IPv4 (`1.2.3.4`) или IPv6 в квадратных скобках (`[2001:db8::1]`). **Значения IPv6 без скобок отклоняются!**
  - **Описание**: Переопределение DNS во время работы для `host:port`-соединений. Позволяет принудительно задавать IP для указанных доменов, не изменяя системный DNS.
  - **Пример**:

    ```toml
    [network]
    dns_overrides = [
      "example.com:443:127.0.0.1",
      "example.net:8443:[2001:db8::10]",
    ]
    ```


# [server]


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`port`](#port) | `u16` | `443` |
| [`listen_addr_ipv4`](#listen_addr_ipv4) | `String` | `"0.0.0.0"` |
| [`listen_addr_ipv6`](#listen_addr_ipv6) | `String` | `"::"` |
| [`listen_unix_sock`](#listen_unix_sock) | `String` | — |
| [`listen_unix_sock_perm`](#listen_unix_sock_perm) | `String` | — |
| [`listen_tcp`](#listen_tcp) | `bool` | — (auto) |
| [`proxy_protocol`](#proxy_protocol) | `bool` | `false` |
| [`proxy_protocol_header_timeout_ms`](#proxy_protocol_header_timeout_ms) | `u64` | `500` |
| [`proxy_protocol_trusted_cidrs`](#proxy_protocol_trusted_cidrs) | `IpNetwork[]` | `[]` |
| [`metrics_port`](#metrics_port) | `u16` | — |
| [`metrics_listen`](#metrics_listen) | `String` | — |
| [`metrics_whitelist`](#metrics_whitelist) | `IpNetwork[]` | `["127.0.0.1/32", "::1/128"]` |
| [`max_connections`](#max_connections) | `u32` | `10000` |
| [`accept_permit_timeout_ms`](#accept_permit_timeout_ms) | `u64` | `250` |

## port
  - **Ограничения / валидация**: `u16`.
  - **Описание**: Main proxy listen port (TCP).
  - **Пример**:

    ```toml
    [server]
    port = 443
    ```
## listen_addr_ipv4
  - **Ограничения / валидация**: `String` (необязательный параметр). Если задан, должен содержать валидный IPv4-адрес в формате строки.
  - **Описание**: Прослушиваемый адрес в формате IPv4 (не задавайте этот параметр, если необходимо отключить прослушивание по IPv4).
  - **Пример**:

    ```toml
    [server]
    listen_addr_ipv4 = "0.0.0.0"
    ```
## listen_addr_ipv6
  - **Ограничения / валидация**: `String` (необязательный параметр). Если задан, должен содержать валидный IPv6-адрес в формате строки.
  - **Описание**: Прослушиваемый адрес в формате  IPv6 (не задавайте этот параметр, если необходимо отключить прослушивание по IPv6).
  - **Пример**:

    ```toml
    [server]
    listen_addr_ipv6 = "::"
    ```
## listen_unix_sock
  - **Ограничения / валидация**: `String` (необязательный параметр). Не должен быть пустым, если задан. Unix only.
  - **Описание**: Путь к Unix-сокету для прослушивания. Если этот параметр задан, `server.listen_tcp` по умолчанию устанавливается в `false` (если только не переопределён явно).
  - **Пример**:

    ```toml
    [server]
    listen_unix_sock = "/run/telemt.sock"
    ```
## listen_unix_sock_perm
  - **Ограничения / валидация**: `String` (необязательный параметр). Если задан, должен содержать восьмеричную строку со значением прав, например `"0666"` или `"0777"`.
  - **Описание**: Необязательные права доступа для Unix-сокета, применяемые после биндинга через chmod. Если параметр не указан, права не изменяются и используются настройки umask.
  - **Пример**:

    ```toml
    [server]
    listen_unix_sock = "/run/telemt.sock"
    listen_unix_sock_perm = "0666"
    ```
## listen_tcp
  - **Ограничения / валидация**: `bool` (необязательный параметр). Если этот параметр не задан, Telemt автоматически использует:
- `true`, если `listen_unix_sock` не задан;
- `false`, если задан `listen_unix_sock`.
  - **Описание**: Явное переопределение включения или отключения TCP-прослушивания.
  - **Пример**:

    ```toml
    [server]
    # force-enable TCP even when also binding a unix socket
    listen_unix_sock = "/run/telemt.sock"
    listen_tcp = true
    ```
## proxy_protocol
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает поддержку разбора PROXY protocol от HAProxy (v1/v2) на входящих соединениях. При включении исходный IP клиента берётся из PROXY-заголовка.
  - **Пример**:

    ```toml
    [server]
    proxy_protocol = true
    ```
## proxy_protocol_header_timeout_ms
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунд).
  - **Описание**: Таймаут чтения и анализа заголовков протокола PROXY (мс).
  - **Пример**:

    ```toml
    [server]
    proxy_protocol = true
    proxy_protocol_header_timeout_ms = 500
    ```
## proxy_protocol_trusted_cidrs
  - **Ограничения / валидация**: `IpNetwork[]`.
    - Если этот параметр не задан, по умолчанию в качестве доверенных используются доверительные все CIDR (`0.0.0.0/0` и `::/0`).
    - Если явно задан пустой массив, все заголовки PROXY отклоняются.
  - **Описание**: Список доверенных CIDR-диапазонов, которым разрешено передавать PROXY protocol-заголовки (механизм безопасности).
  - **Пример**:

    ```toml
    [server]
    proxy_protocol = true
    proxy_protocol_trusted_cidrs = ["127.0.0.1/32", "10.0.0.0/8"]
    ```
## metrics_port
  - **Ограничения / валидация**: `u16` (необязательный параметр).
  - **Описание**: Порт для Prometheus-совместимого endpoint’а метрик. При задании включает прослушивание метрик (поведение прослушивания может быть переопределено через `metrics_listen`).
  - **Пример**:

    ```toml
    [server]
    metrics_port = 9090
    ```
## metrics_listen
  - **Ограничения / валидация**: `String` (необязательный параметр). Если задан, значение должно быть в формате `IP:PORT`.
  - **Описание**: Полный адрес привязки метрик (`IP:PORT`), переопределяет `metrics_port` и запускает прослушивание только на указанном адресе..
  - **Пример**:

    ```toml
    [server]
    metrics_listen = "127.0.0.1:9090"
    ```
## metrics_whitelist
  - **Ограничения / валидация**: `IpNetwork[]`.
  - **Описание**: Белый список CIDR для доступа к endpoint’у метрик.
  - **Пример**:

    ```toml
    [server]
    metrics_port = 9090
    metrics_whitelist = ["127.0.0.1/32", "::1/128"]
    ```
## max_connections
  - **Ограничения / валидация**: `u32`. `0` - без ограничений.
  - **Описание**: Максимальное количество одновременных клиентских соединений.
  - **Пример**:

    ```toml
    [server]
    max_connections = 10000
    ```
## accept_permit_timeout_ms
  - **Ограничения / валидация**: `0..=60000` (milliseconds). `0` - неограниченное время ожидания.
  - **Описание**: Максимальное время ожидания получения разрешения на подключение, прежде чем принятое соединение будет разорвано.
  - **Пример**:

    ```toml
    [server]
    accept_permit_timeout_ms = 250
    ```


Примечание. Когда `server.proxy_protocol` включен, входящие заголовки протокола PROXY анализируются с первых байтов соединения, а исходный адрес клиента заменяется на `src_addr` из заголовка. В целях безопасности IP-адрес прямого соединения проверяется по `server.proxy_protocol_trusted_cidrs`; если этот список пуст, заголовки PROXY отклоняются и соединение считается ненадежным.

# [server.conntrack_control]

Примечание. Рабочий процесс `conntrack-control` работает **только в Linux**. В других операционных системах не запускается; если inline_conntrack_control имеет значение `true`, в логи записывается предупреждение. Для эффективной работы также требуется **CAP_NET_ADMIN** и пригодный к использованию бэкенд (nft или iptables/ip6tables в PATH). Утилита `conntrack` используется для удаления необязательных записей таблицы под нагрузкой.


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`inline_conntrack_control`](#inline_conntrack_control) | `bool` | `true` |
| [`mode`](#mode) | `String` | `"tracked"` |
| [`backend`](#backend) | `String` | `"auto"` |
| [`profile`](#profile) | `String` | `"balanced"` |
| [`hybrid_listener_ips`](#hybrid_listener_ips) | `IpAddr[]` | `[]` |
| [`pressure_high_watermark_pct`](#pressure_high_watermark_pct) | `u8` | `85` |
| [`pressure_low_watermark_pct`](#pressure_low_watermark_pct) | `u8` | `70` |
| [`delete_budget_per_sec`](#delete_budget_per_sec) | `u64` | `4096` |

## inline_conntrack_control
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Главный переключатель для задачи conntrack-control: согласовывает правила сетевого фильтра **raw/notrack** для входяшего трафика (см. `mode`), раз в секунду измеряет нагрузку и при активном режиме нагрузки может выполнять удаления через **`conntrack -D`** для подходящих событий закрытия соединений (см. `delete_budget_per_sec`). Если отключён (`false`), notrack-правила удаляются, а удаление при нагрузке отключается.
  - **Пример**:

    ```toml
    [server.conntrack_control]
    inline_conntrack_control = true
    ```
## mode
  - **Ограничения / валидация**: `tracked`, `notrack` или `hybrid` (чувствителен к регистру, используется нижний регистр).
  - **Описание**: 
    - **`tracked`**: не устанавливать notrack-правила, соединения полностью отслеживаются conntrack.
    - **`notrack`**: помечает входящий TCP-трафик к server.port как notrack; цели берутся из `[server.listeners]`, либо из `server.listen_addr_ipv4 / server.listen_addr_ipv6` (неуказанные адреса означают «любой» для этого семейства).
    - **`hybrid`**: notrack применяется только к адресам из `hybrid_listener_ips` (не должно быть пустым, проверяется при загрузке), остальные соединения отслеживаются обычным образом.
  - **Пример**:

    ```toml
    [server.conntrack_control]
    mode = "notrack"
    ```
## backend
  - **Ограничения / валидация**: `auto`, `nftables`или `iptables` (чувствителен к регистру, используется нижний регистр).
  - **Описание**: Выбор набора инструментов для применения notrack-правил. 
    - **`auto`**: использует `nft`, если доступен, иначе - `iptables`/`ip6tables`.
    - **`nftables / iptables`**: принудительно выбирает соответствующий backend; при отсутствии бинарника правила не применяются. В nft-режиме используется таблица `inet telemt_conntrack`, в `iptables` — цепочка TELEMT_NOTRACK в таблице raw.
  - **Пример**:

    ```toml
    [server.conntrack_control]
    backend = "auto"
    ```
## profile
  - **Ограничения / валидация**: `conservative`, `balanced`или `aggressive` (чувствителен к регистру, используется нижний регистр).
  - **Описание**: При активном режиме **conntrack pressure mode** граничивает таймауты для снижения нагрузки: idle-время клиента, таймауты активности direct relay и политики idle middle relay. Более агрессивные профили используют более короткие ограничения.
  - **Пример**:

    ```toml
    [server.conntrack_control]
    profile = "balanced"
    ```
## hybrid_listener_ips
  - **Ограничения / валидация**: `IpAddr[]`. Значение не должно быть пустым, если `mode = "hybrid"`. Игнорируется для режимов `tracked` / `notrack`.
  - **Описание**: Явный список прослушиваемых IP-адресов, к которым применяется notrack в hybrid-режиме (разделяется на IPv4 и IPv6 правила).
  - **Пример**:

    ```toml
    [server.conntrack_control]
    mode = "hybrid"
    hybrid_listener_ips = ["203.0.113.10", "2001:db8::1"]
    ```
## pressure_high_watermark_pct
  - **Ограничения / валидация**: Должно быть в пределах `[1, 100]`.
  - **Описание**: Порог входа в **conntrack pressure mode**. Переход происходит при любом из следующих условий: заполненность соединений относительно `server.max_connections` (в процентах, если `max_connections > 0`), **использование файловых дескрипторов** относительно мягкого лимита `RLIMIT_NOFILE`, **ненулевое** значение `accept_permit_timeout` или дельта относитель счетчика **ME c2me send-full**. Сравниваются соответствующие проценты с верхней отметкой указанных параметров (см. update_pressure_state в conntrack_control.rs).
  - **Пример**:

    ```toml
    [server.conntrack_control]
    pressure_high_watermark_pct = 85
    ```
## pressure_low_watermark_pct
  - **Ограничения / валидация**: Должно быть **сторого ниже** значения `pressure_high_watermark_pct`.
  - **Описание**: Режим **conntrack pressure mode** отключается только после **трех** последовательных односекундных выборок, когда все сигналы находятся на уровне этой нижней границы или ниже, а дельты времени ожидания приема/ME-очереди равны нулю (гистерезис).
  - **Пример**:

    ```toml
    [server.conntrack_control]
    pressure_low_watermark_pct = 70
    ```
## delete_budget_per_sec
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Максимальное количество попыток удаления через `conntrack -D` в секунду во время режима **conntrack pressure mode**. Ограничение реализовано через токен-бакет; применяется только к событиям закрытия с причинами **timeout**, **pressure** или **reset**.
  - **Пример**:

    ```toml
    [server.conntrack_control]
    delete_budget_per_sec = 4096
    ```


# [server.api]

Примечание: В этом разделе также задается устаревший параметр `[server.admin_api]` (аналогично `[server.api]`).


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`enabled`](#enabled) | `bool` | `true` |
| [`listen`](#listen) | `String` | `"0.0.0.0:9091"` |
| [`whitelist`](#whitelist) | `IpNetwork[]` | `["127.0.0.0/8"]` |
| [`auth_header`](#auth_header) | `String` | `""` |
| [`request_body_limit_bytes`](#request_body_limit_bytes) | `usize` | `65536` |
| [`minimal_runtime_enabled`](#minimal_runtime_enabled) | `bool` | `true` |
| [`minimal_runtime_cache_ttl_ms`](#minimal_runtime_cache_ttl_ms) | `u64` | `1000` |
| [`runtime_edge_enabled`](#runtime_edge_enabled) | `bool` | `false` |
| [`runtime_edge_cache_ttl_ms`](#runtime_edge_cache_ttl_ms) | `u64` | `1000` |
| [`runtime_edge_top_n`](#runtime_edge_top_n) | `usize` | `10` |
| [`runtime_edge_events_capacity`](#runtime_edge_events_capacity) | `usize` | `256` |
| [`read_only`](#read_only) | `bool` | `false` |

## enabled
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает возможность управления через REST API.
  - **Пример**:

    ```toml
    [server.api]
    enabled = true
    ```
## listen
  - **Ограничения / валидация**: `String`. Должно быть в формате `IP:PORT`.
  - **Описание**: Адрес биндинга API в формате `IP:PORT`.
  - **Пример**:

    ```toml
    [server.api]
    listen = "0.0.0.0:9091"
    ```
## whitelist
  - **Ограничения / валидация**: `IpNetwork[]`.
  - **Описание**: Список CIDR-адресов, которым разрешён доступ к API.
  - **Пример**:

    ```toml
    [server.api]
    whitelist = ["127.0.0.0/8"]
    ```
## auth_header
  - **Ограничения / валидация**: `String`. Пустая строка отключает проверку заголовка аутентификации.
  - **Описание**: Точное ожидаемое значение заголовка `Authorization` (static shared secret).
  - **Пример**:

    ```toml
    [server.api]
    auth_header = "Bearer MY_TOKEN"
    ```
## request_body_limit_bytes
  - **Ограничения / валидация**: Должно быть `> 0` (байт).
  - **Описание**: Максимальный принимаемый размер тела HTTP-запроса (в байтах).
  - **Пример**:

    ```toml
    [server.api]
    request_body_limit_bytes = 65536
    ```
## minimal_runtime_enabled
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает логику минимальных runtime-снимков endpoint’а.
  - **Пример**:

    ```toml
    [server.api]
    minimal_runtime_enabled = true
    ```
## minimal_runtime_cache_ttl_ms
  - **Ограничения / валидация**: `0..=60000` (миллисекунд). `0` - отключает кэширование.
  - **Описание**: Время жизни минимальных runtime-снимков (в мс).
  - **Пример**:

    ```toml
    [server.api]
    minimal_runtime_cache_ttl_ms = 1000
    ```
## runtime_edge_enabled
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает runtime endpoint’ы для edge-данных (статистики/метрик).
  - **Пример**:

    ```toml
    [server.api]
    runtime_edge_enabled = false
    ```
## runtime_edge_cache_ttl_ms
  - **Ограничения / валидация**: `0..=60000` (миллисекунд).
  - **Описание**: Время жизни кэша (в миллисекундах) для агрегированных данных (payload’ов) runtime edge.
  - **Пример**:

    ```toml
    [server.api]
    runtime_edge_cache_ttl_ms = 1000
    ```
## runtime_edge_top_n
  - **Ограничения / валидация**: `1..=1000`.
  - **Описание**: Размер выборки Top-N для рейтинга (leaderboard) edge-соединений.
  - **Пример**:

    ```toml
    [server.api]
    runtime_edge_top_n = 10
    ```
## runtime_edge_events_capacity
  - **Ограничения / валидация**: `16..=4096`.
  - **Описание**: Ёмкость кольцевого буфера для runtime edge-событий.
  - **Пример**:

    ```toml
    [server.api]
    runtime_edge_events_capacity = 256
    ```
## read_only
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Переводит API в режим "только чтение".
  - **Пример**:

    ```toml
    [server.api]
    read_only = false
    ```


# [[server.listeners]]


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`ip`](#ip) | `IpAddr` | — |
| [`announce`](#announce) | `String` | — |
| [`announce_ip`](#announce_ip) | `IpAddr` | — |
| [`proxy_protocol`](#proxy_protocol) | `bool` | — |
| [`reuse_allow`](#reuse_allow) | `bool` | `false` |

## ip
  - **Ограничения / валидация**: Обязательный параметр. Значение должно содержать IP-адрес в формате строки.
  - **Описание**: Адрес для listener’а.
  - **Пример**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    ```
## announce
  - **Ограничения / валидация**: `String` (необязательный параметр). Не должен быть пустым, если задан.
  - **Описание**: Публичный IP-адрес или домен, объявляемый в proxy-ссылках для данного listener’а. Имеет приоритет над `announce_ip`.
  - **Пример**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    announce = "proxy.example.com"
    ```
## announce_ip
  - **Ограничения / валидация**: `IpAddr` (необязательный параметр). Устарел. Используйте `announce`.
  - **Описание**: Устаревший параметр для анонсирования IP. Во время загрузки конфигурации он переносится в `announce` если `announce` не задан.
  - **Пример**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    announce_ip = "203.0.113.10"
    ```
## proxy_protocol
  - **Ограничения / валидация**: `bool` (необязательный параметр). Если задан, перезаписывает значение `server.proxy_protocol` для этого listener’а.
  - **Описание**: Переопределение протокола PROXY для каждого listener’а.
  - **Пример**:

    ```toml
    [server]
    proxy_protocol = false

    [[server.listeners]]
    ip = "0.0.0.0"
    proxy_protocol = true
    ```
## reuse_allow"
- `reuse_allow`
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает `SO_REUSEPORT` для совместного использования привязки нескольких экземпляров (позволяет нескольким экземплярам telemt прослушивать один и тот же `ip:port`).
  - **Пример**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    reuse_allow = false
    ```


# [timeouts]


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`client_handshake`](#client_handshake) | `u64` | `30` |
| [`relay_idle_policy_v2_enabled`](#relay_idle_policy_v2_enabled) | `bool` | `true` |
| [`relay_client_idle_soft_secs`](#relay_client_idle_soft_secs) | `u64` | `120` |
| [`relay_client_idle_hard_secs`](#relay_client_idle_hard_secs) | `u64` | `360` |
| [`relay_idle_grace_after_downstream_activity_secs`](#relay_idle_grace_after_downstream_activity_secs) | `u64` | `30` |
| [`tg_connect`](#tg_connect) | `u64` | `10` |
| [`client_keepalive`](#client_keepalive) | `u64` | `15` |
| [`client_ack`](#client_ack) | `u64` | `90` |
| [`me_one_retry`](#me_one_retry) | `u8` | `12` |
| [`me_one_timeout_ms`](#me_one_timeout_ms) | `u64` | `1200` |

## client_handshake
  - **Ограничения / валидация**: Должно быть `> 0`. Значение указано в секундах. Также используется в качестве верхней границы некоторых задержек эмуляции TLS (см. `censorship.server_hello_delay_max_ms`).
  - **Описание**: Таймаут выполнения "рукопожатия" для клиента (в секундах).
  - **Пример**:

    ```toml
    [timeouts]
    client_handshake = 30
    ```
## relay_idle_policy_v2_enabled
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает политику простоя клиента для промежуточного узла.
  - **Пример**:

    ```toml
    [timeouts]
    relay_idle_policy_v2_enabled = true
    ```
## relay_client_idle_soft_secs
  - **Ограничения / валидация**: Должно быть `> 0`; Должно быть меньше или равно `relay_client_idle_hard_secs`.
  - **Описание**: Мягкий порог простоя (в секундах) для неактивности uplink клиента в промежуточном узле. При достижении этого порога сессия помечается как кандидат на простой и может быть удалена в зависимости от политики.
  - **Пример**:

    ```toml
    [timeouts]
    relay_client_idle_soft_secs = 120
    ```
## relay_client_idle_hard_secs
  - **Ограничения / валидация**: Должно быть `> 0`; Должно быть больше или равно`relay_client_idle_soft_secs`.
  - **Описание**: Жёсткий порог простоя (в секундах) для неактивности uplink клиента в промежуточном узле. При достижении этого порога сессия принудительно закрывается.
  - **Пример**:

    ```toml
    [timeouts]
    relay_client_idle_hard_secs = 360
    ```
## relay_idle_grace_after_downstream_activity_secs
  - **Ограничения / валидация**: Должно быть `<= relay_client_idle_hard_secs`.
  - **Описание**: Дополнительный период отсрочки жёсткого простоя (в секундах), добавляемый после недавней активности downstream.
  - **Пример**:

    ```toml
    [timeouts]
    relay_idle_grace_after_downstream_activity_secs = 30
    ```
## tg_connect
  - **Ограничения / валидация**: `u64` (секунд).
  - **Описание**: Таймаут подключения к upstream-серверу Telegram (в секундах).
  - **Пример**:

    ```toml
    [timeouts]
    tg_connect = 10
    ```
## client_keepalive
  - **Ограничения / валидация**: `u64` (секунд).
  - **Описание**: Таймаут keepalive для клиента..
  - **Пример**:

    ```toml
    [timeouts]
    client_keepalive = 15
    ```
## client_ack
  - **Ограничения / валидация**: `u64` (секунд).
  - **Описание**: Таймаут подтверждения (ACK) от клиента в секундах.
  - **Пример**:

    ```toml
    [timeouts]
    client_ack = 90
    ```
## me_one_retry
  - **Ограничения / валидация**: `u8`.
  - **Описание**: Лимит быстрых попыток переподключения в сценариях DC с единственным endpoint'ом.
  - **Пример**:

    ```toml
    [timeouts]
    me_one_retry = 12
    ```
## me_one_timeout_ms
  - **Ограничения / валидация**: `u64` (миллисекунд).
  - **Описание**: Таймаут на одну быструю попытку переподключения (в миллисекундах) в логике reconnect для DC с единственным endpoint'ом.
  - **Пример**:

    ```toml
    [timeouts]
    me_one_timeout_ms = 1200
    ```


# [censorship]


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`tls_domain`](#tls_domain) | `String` | `"petrovich.ru"` |
| [`tls_domains`](#tls_domains) | `String[]` | `[]` |
| [`unknown_sni_action`](#unknown_sni_action) | `"drop"`, `"mask"`, `"accept"`, `"reject_handshake"` | `"drop"` |
| [`tls_fetch_scope`](#tls_fetch_scope) | `String` | `""` |
| [`tls_fetch`](#tls_fetch) | `Table` | built-in defaults |
| [`mask`](#mask) | `bool` | `true` |
| [`mask_host`](#mask_host) | `String` | — |
| [`mask_port`](#mask_port) | `u16` | `443` |
| [`mask_unix_sock`](#mask_unix_sock) | `String` | — |
| [`fake_cert_len`](#fake_cert_len) | `usize` | `2048` |
| [`tls_emulation`](#tls_emulation) | `bool` | `true` |
| [`tls_front_dir`](#tls_front_dir) | `String` | `"tlsfront"` |
| [`server_hello_delay_min_ms`](#server_hello_delay_min_ms) | `u64` | `0` |
| [`server_hello_delay_max_ms`](#server_hello_delay_max_ms) | `u64` | `0` |
| [`tls_new_session_tickets`](#tls_new_session_tickets) | `u8` | `0` |
| [`tls_full_cert_ttl_secs`](#tls_full_cert_ttl_secs) | `u64` | `90` |
| [`alpn_enforce`](#alpn_enforce) | `bool` | `true` |
| [`mask_proxy_protocol`](#mask_proxy_protocol) | `u8` | `0` |
| [`mask_shape_hardening`](#mask_shape_hardening) | `bool` | `true` |
| [`mask_shape_hardening_aggressive_mode`](#mask_shape_hardening_aggressive_mode) | `bool` | `false` |
| [`mask_shape_bucket_floor_bytes`](#mask_shape_bucket_floor_bytes) | `usize` | `512` |
| [`mask_shape_bucket_cap_bytes`](#mask_shape_bucket_cap_bytes) | `usize` | `4096` |
| [`mask_shape_above_cap_blur`](#mask_shape_above_cap_blur) | `bool` | `false` |
| [`mask_shape_above_cap_blur_max_bytes`](#mask_shape_above_cap_blur_max_bytes) | `usize` | `512` |
| [`mask_relay_max_bytes`](#mask_relay_max_bytes) | `usize` | `5242880` |
| [`mask_relay_timeout_ms`](mask_relay_timeout_ms) | `u64` | `60_000` |
| [`mask_relay_idle_timeout_ms`](mask_relay_idle_timeout_ms) | `u64` | `5_000` |
| [`mask_classifier_prefetch_timeout_ms`](#mask_classifier_prefetch_timeout_ms) | `u64` | `5` |
| [`mask_timing_normalization_enabled`](#mask_timing_normalization_enabled) | `bool` | `false` |
| [`mask_timing_normalization_floor_ms`](#mask_timing_normalization_floor_ms) | `u64` | `0` |
| [`mask_timing_normalization_ceiling_ms`](#mask_timing_normalization_ceiling_ms) | `u64` | `0` |

## tls_domain
  - **Ограничения / валидация**: Не должно быть пустым. Не должно содержать пробелы или `/`.
  - **Описание**: Основной TLS-домен, используемый в профиле FakeTLS handshake и как домен SNI по умолчанию.
  - **Пример**:

    ```toml
    [censorship]
    tls_domain = "example.com"
    ```
## tls_domains
  - **Ограничения / валидация**: `String[]`. Когда задан, значение объединяется с `tls_domain` и очищается от дубликатов (первичный tls_domain всегда остается первым).
  - **Описание**: Дополнительные домены TLS для создания нескольких прокси-ссылок.
  - **Пример**:

    ```toml
    [censorship]
    tls_domain = "example.com"
    tls_domains = ["example.net", "example.org"]
    ```
## unknown_sni_action
  - **Ограничения / валидация**: `"drop"`, `"mask"`, `"accept"` или `"reject_handshake"`.
  - **Описание**: Действие для TLS ClientHello с неизвестным/ненастроенным SNI.
    - `drop` — закрыть соединение без ответа (молчаливый FIN после применения `server_hello_delay`). Поведение, неотличимое по таймингу от Success-ветки, но более «тихое», чем у обычного веб-сервера.
    - `mask` — прозрачно проксировать соединение на `mask_host:mask_port` (TLS-fronting). Клиент получает настоящий ServerHello от реального бэкенда с его сертификатом. Максимальный камуфляж, но порождает исходящее соединение на каждый чужой запрос.
    - `accept` — притвориться, что SNI валиден, и продолжить auth-путь. Снижает защиту от активного пробинга; осмысленно только в узких сценариях.
    - `reject_handshake` — отправить фатальный TLS-alert `unrecognized_name` (RFC 6066, AlertDescription = 112) и закрыть соединение. Поведение, идентичное современному nginx с `ssl_reject_handshake on;` на дефолтном vhost'е: на wire-уровне выглядит как обычный HTTPS-сервер, у которого просто нет такого домена. Рекомендуется, если цель — максимальная похожесть на стоковый веб-сервер, а не tls-fronting. `server_hello_delay` на эту ветку не применяется, чтобы alert улетал «мгновенно», как у эталонного nginx.
  - **Пример**:

    ```toml
    [censorship]
    unknown_sni_action = "reject_handshake"
    ```
## tls_fetch_scope
  - **Ограничения / валидация**: `String`. Значение обрезается во время загрузки; значение, состоящее только из пробелов, становится пустым.
  - **Описание**: Тег области upstream, используемый для TLS-front метаданных при их получении. Пустое значение сохраняет стандартное поведение маршрутизации upstream.
  - **Пример**:

    ```toml
    [censorship]
    tls_fetch_scope = "fetch"
    ```
# censorship.tls_fetch
  - **Ограничения / валидация**: Таблица, см. секцию `[censorship.tls_fetch]` ниже.
  - **Описание**: Настройки стратегии получения TLS-front метаданных (поведение загрузки и обновления bootstrap и данных эмуляции TLS)..
  - **Пример**:

    ```toml
    [censorship.tls_fetch]
    strict_route = true
    attempt_timeout_ms = 5000
    total_budget_ms = 15000
    ```
## mask
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает режим маскировки/верхнего уровня. Принимаются все SNI, которые похожи на заданный в `tls_domain`.
  - **Пример**:

    ```toml
    [censorship]
    mask = true
    ```
## mask_host
  - **Ограничения / валидация**: `String` (необязательный параметр).
    - Если задан параметр `mask_unix_sock`, `mask_host` не должен быть задан.
    - Если не задан параметр `mask_host` и `mask_unix_sock` не задан, Telemt по умолчанию устанавливает для `mask_host` значение `tls_domain`.
  - **Описание**: Хост, используемый для маскировки при TLS-fronting.
  - **Пример**:

    ```toml
    [censorship]
    mask_host = "www.cloudflare.com"
    ```
## mask_port
  - **Ограничения / валидация**: `u16`.
  - **Описание**: Порт маскирующего upstream для TLS fronting.
  - **Пример**:

    ```toml
    [censorship]
    mask_port = 443
    ```
## mask_unix_sock
  - **Ограничения / валидация**: `String` (optional).
    - Значение не должно быть пустым, если задан.
    - Unix only;
    - На Unix системах, должно быть \(\le 107\) байт (ограничение длины пути).
    - Взаимоисключающий с `mask_host`.
  - **Описание**: Путь к Unix-сокету для mask-бэкенда вместо использования TCP `mask_host`/`mask_port`.
  - **Пример**:

    ```toml
    [censorship]
    mask_unix_sock = "/run/telemt/mask.sock"
    ```
## fake_cert_len
  - **Ограничения / валидация**: `usize`. Когда `tls_emulation = false` и используется значение по умолчанию, Telemt может рандомизировать его при запуске для обеспечения вариативности.
  - **Описание**: Длина синтетического сертификатного payload’а, используемого при отсутствии данных для эмуляции.
  - **Пример**:

    ```toml
    [censorship]
    fake_cert_len = 2048
    ```
## tls_emulation
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает эмуляцию поведения сертификата/TLS из кэшированных реальных сайтов.
  - **Пример**:

    ```toml
    [censorship]
    tls_emulation = true
    ```
## tls_front_dir
  - **Ограничения / валидация**: `String`.
  - **Описание**: Путь к директории для хранения кэша сайтов.
  - **Пример**:

    ```toml
    [censorship]
    tls_front_dir = "tlsfront"
    ```
## server_hello_delay_min_ms
  - **Ограничения / валидация**: `u64` (миллисекунд).
  - **Описание**: Минимальная задержка `server_hello` (в миллисекундах) для защиты от идентификации по fingerprint'у.
  - **Пример**:

    ```toml
    [censorship]
    server_hello_delay_min_ms = 0
    ```
## server_hello_delay_max_ms
  - **Ограничения / валидация**: `u64` (миллисекунд). Должно быть \(<\) `timeouts.client_handshake * 1000`.
  - **Описание**: Максимальная задержка `server_hello` (в миллисекундах) для защиты от идентификации по fingerprint'у.
  - **Пример**:

    ```toml
    [timeouts]
    client_handshake = 30

    [censorship]
    server_hello_delay_max_ms = 0
    ```
## tls_new_session_tickets
  - **Ограничения / валидация**: `u8`.
  - **Описание**: Количество сообщений `NewSessionTicket`, отправляемых после рукопожатия.
  - **Пример**:

    ```toml
    [censorship]
    tls_new_session_tickets = 0
    ```
## tls_full_cert_ttl_secs
  - **Ограничения / валидация**: `u64` (секунд).
  - **Описание**: TTL для отправки полного сертификатного payload’а для каждой пары (домен, IP клиента).
  - **Пример**:

    ```toml
    [censorship]
    tls_full_cert_ttl_secs = 90
    ```
## alpn_enforce
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Принудительно изменяет поведение возврата ALPN в соответствии с предпочтениями клиента.
  - **Пример**:

    ```toml
    [censorship]
    alpn_enforce = true
    ```
## mask_proxy_protocol
  - **Ограничения / валидация**: `u8`. `0` = выключен, `1` = v1 (текстовый), `2` = v2 (бинарный).
  - **Описание**: Отправляет заголовок PROXY protocol при подключении к mask-бэкенду, позволяя бэкенду видеть реальный IP клиента.
  - **Пример**:

    ```toml
    [censorship]
    mask_proxy_protocol = 0
    ```
## mask_shape_hardening
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Усиливает защиту канала формирования/маскировки (shape-channel) трафика client->mask за счёт контролируемого добавления хвостового padding'а к границам групп данных при завершении работы mask relay.
  - **Пример**:

    ```toml
    [censorship]
    mask_shape_hardening = true
    ```
## mask_shape_hardening_aggressive_mode
  - **Ограничения / валидация**: Требует, чтобы `mask_shape_hardening = true`.
  - **Описание**: Опциональный агрессивный профиль формирования трафика (более сильное противодействие классификаторам с изменённой логикой шейпинга).
  - **Пример**:

    ```toml
    [censorship]
    mask_shape_hardening = true
    mask_shape_hardening_aggressive_mode = false
    ```
## mask_shape_bucket_floor_bytes
  - **Ограничения / валидация**: Должно быть `> 0`; должно быть меньше или равно`mask_shape_bucket_cap_bytes`.
  - **Описание**: Минимальный размер группы данных, используемый при усилении канала формирования/маскировки трафика (shape-channel).
  - **Пример**:

    ```toml
    [censorship]
    mask_shape_bucket_floor_bytes = 512
    ```
## mask_shape_bucket_cap_bytes
  - **Ограничения / валидация**: Должно быть `>= mask_shape_bucket_floor_bytes`.
  - **Описание**: Максимальный размер группы данных, используемого для усиления канала формирования/маскировки трафика (shape-channel); трафик, превышающий этот лимит, больше не подвергается bucket-padding'у.
  - **Пример**:

    ```toml
    [censorship]
    mask_shape_bucket_cap_bytes = 4096
    ```
## mask_shape_above_cap_blur
  - **Ограничения / валидация**: Требует, чтобы  `mask_shape_hardening = true`.
  - **Описание**: Добавляет ограниченное количество случайных байтов в конец данных (tail), даже если передаваемый размер уже превышает лимит.
  - **Пример**:

    ```toml
    [censorship]
    mask_shape_hardening = true
    mask_shape_above_cap_blur = false
    ```
## mask_shape_above_cap_blur_max_bytes
  - **Ограничения / валидация**: Должно быть `<= 1048576`. Должно быть `> 0`, если `mask_shape_above_cap_blur = true`.
  - **Описание**: Максимальное количество случайных дополнительных байтов, добавляемых сверх лимита, когда включено размытие данных(blur).
  - **Пример**:

    ```toml
    [censorship]
    mask_shape_above_cap_blur = true
    mask_shape_above_cap_blur_max_bytes = 64
    ```
## mask_relay_max_bytes
  - **Ограничения / валидация**: Должно быть `> 0`; Должно быть меньше или равно `67108864`.
  - **Описание**: Максимальное количество байт, передаваемых в каждом направлении, на неаутентифицированной fallback маскировке.
  - **Пример**:

    ```toml
    [censorship]
    mask_relay_max_bytes = 5242880
    ```

## mask_relay_timeout_ms
  - **Constraints / validation**: Должно быть больше или равно  `mask_relay_idle_timeout_ms`.
  - **Description**: Жёсткий лимит по реальному времени (wall-clock) для полного маскирующего проксирования на fallback-путях без MTProto. Увеличивайте значение, если целевой сервис маскирования является долгоживущим (например, WebSocket-соединение). Значение по умолчанию: 60 000 мс (1 минута).
  - **Example**:

    ```toml
    [censorship]
    mask_relay_timeout_ms = 60000
    ```
## mask_relay_idle_timeout_ms
  - **Constraints / validation**: Должно быть меньше или равно `mask_relay_timeout_ms`.
  - **Description**: Тайм-аут простоя на каждую операцию чтения (per-read idle timeout) в маскирующем прокси и drain-пайплайнах. Ограничивает потребление ресурсов при атаках типа slow-loris и сканировании портов. Если операция чтения блокируется дольше заданного времени, соединение считается заброшенным и закрывается. Значение по умолчанию: 5 000 мс (5 с).
  - **Example**:

    ```toml
    [censorship]
    mask_relay_idle_timeout_ms = 5000
    ```

## mask_classifier_prefetch_timeout_ms
  - **Ограничения / валидация**: Должно быть в пределах `[5, 50]` (миллисекунд).
  - **Описание**: Лимит времени ожидания (в миллисекундах) для расширения первых входящих данных в режиме fallback-маскировки.
  - **Пример**:

    ```toml
    [censorship]
    mask_classifier_prefetch_timeout_ms = 5
    ```
## mask_timing_normalization_enabled
  - **Ограничения / валидация**: Когда `true`, требует, чтобы  `mask_timing_normalization_floor_ms > 0` и `mask_timing_normalization_ceiling_ms` был больше или равен `mask_timing_normalization_floor_ms`. Значение должно быть меньше или равно `60000`.
  - **Описание**: Включает выравнивание и сглаживание временных паттернов (таймингов) трафика после применения маскировки.
  - **Пример**:

    ```toml
    [censorship]
    mask_timing_normalization_enabled = false
    ```
## mask_timing_normalization_floor_ms
  - **Ограничения / валидация**: Должно быть `> 0`, если `mask_timing_normalization_enabled = true`; Должно быть меньше или равно `mask_timing_normalization_ceiling_ms`.
  - **Описание**: Lower bound (ms) for masking outcome normalization target.
  - **Пример**:

    ```toml
    [censorship]
    mask_timing_normalization_floor_ms = 0
    ```
## mask_timing_normalization_ceiling_ms
  - **Ограничения / валидация**: Должно быть `>= mask_timing_normalization_floor_ms`; Должно быть `<= 60000`.
  - **Описание**: Минимально допустимое значение таймингов/задержек, к которому система “приводит” (нормализует) поведение маскированного трафика.
  - **Пример**:

    ```toml
    [censorship]
    mask_timing_normalization_ceiling_ms = 0
    ```

## Примечания по усилению shape-channel (`[censorship]`)

Эти параметры предназначены для снижения одного конкретного источника fingerprinting при маскировке: точного количества байт, отправляемых от прокси к `mask_host` при невалидном или зондирующем (probe) трафике.

Без усиления защиты цензор часто может очень точно сопоставить длину входящего пробного запроса с длиной, наблюдаемой на стороне бэкенда (например, `5 + body_sent` на ранних этапах отклонения TLS). Это является сигналом для классификации на основе длины.

Когда `mask_shape_hardening = true`, Telemt дополняет (padding) хвост потока **client → mask** до границы группы данных при завершении работы промежуточного звена:

- Сначала измеряется общее количество байт, отправленных в mask.
- Затем выбирается bucket (группа данных), используя степени двойки, начиная с `mask_shape_bucket_floor_bytes`.
- Padding добавляется только если общее количество байт меньше`mask_shape_bucket_cap_bytes`.
- Если количество байт уже превышает cap, дополнительные данные не добавляются

Это означает, что несколько близких по размеру пробных запросов (probe) объединяются в одну и ту же группу данных, наблюдаемых на стороне backend'а, что усложняет активную классификацию.

Что каждый параметр меняет на практике:

- `mask_shape_hardening`
  Включает или отключает весь этап формирования (shaping) длины на fallback'е.
Если `false`, наблюдаемая на backend длина остаётся близкой к реальной длине переданного probe-запроса.
Если `true`, при быстром завершении соединения промежуточное звено может добавлять случайные padding-байты, чтобы итоговый размер попадал в заданную группу данных.
- `mask_shape_bucket_floor_bytes`
Устанавливает первую границу bucket’а, используемого для небольших probe-запросов.
Например: при значении 512 некорректный probe-запрос, который в обычном случае передал бы 37 байт, может быть дополнен до 512 байт при корректном завершении соединения (clean EOF).
Более высокие значения `mask_shape_bucket_floor_bytes` лучше скрывают очень маленькие probe-запросы, но увеличивают объём исходящего трафика.
- `mask_shape_bucket_cap_bytes`
Устанавливает наибольший bucket, до которого Telemt может выполнять padding по bucket-логике.
Например: при значении cap = `4096` итоговые `1800` байт могут быть дополнены до `2048` или `4096` в зависимости от "лестницы" bucket’ов, но если объём уже превышает `4096` байт, дальнейшее bucket-дополнение не выполняется.
Более высокие значения cap расширяют диапазон, в котором размеры объединяются в классы, но также увеличивают максимальные накладные расходы.
- Clean EOF имеет значение в conservative режиме
В профиле по умолчанию padding формы трафика намеренно реализован консервативно: он применяется только при корректном завершении соединения (clean relay shutdown), а не при каждом таймауте или "капельной" (drip) передаче.
Это позволяет избежать появления новых артефактов тайм-аута, которые некоторые серверные части или тесты интерпретируют как отдельные fingerprint'ы.

Практические компромиссы:

- Улучшенная защита от fingerprinting'a для канала формирования/маскировки трафика.
- Немного выше выходные накладные расходы для небольших зондов из-за padding'а.
- Система намеренно использует "консервативный" режим и это поведение включено по умолчанию.

Рекомендуемые начальные настройки:

- `mask_shape_hardening = true` (default)
- `mask_shape_bucket_floor_bytes = 512`
- `mask_shape_bucket_cap_bytes = 4096`

## Уточнения по агрессивным режимам работы (`[censorship]`)

`mask_shape_hardening_aggressive_mode` - это параметр, который включается вручную и предназначен для более сильного противодействия классификаторам.

- Значение по умолчанию - `false`, чтобы сохранить консервативное поведение по тайм-ауту.
- Требует, чтобы `mask_shape_hardening = true`.
- Когда включено, не завершающиеся (non-EOF) запросы для маскировки, не передающие данные на backend, могут подвергаться shaping’у (формированию трафика).
- Когда включено вместе с "размытием" трафика выше порога cap, случайный дополнительный tail использует `[1, max]` instead of `[0, max]`.

Что меняется при включении агрессивного режима:

- Могут быть сформированы пути тайм-аута, не требующие бэкенда.
В режиме по умолчанию клиент, который держит сокет полуоткрытым и имеет тайм-аут, обычно не будет получать заполнение формы по этому пути.
В агрессивном режиме Telemt все равно может применять shaping к такому backend-silent соединению, если от backend не было получено ответа.
Это специально предназначено для активных зондов, которые пытаются избежать EOF, чтобы сохранить точную наблюдаемую длину.
- "Размытие" трафика выше порога cap всегда добавляет как минимум один байт.
В режиме по умолчанию для размытия трафика (blur) над максимальным пределом может быть выбрано значение «0», поэтому некоторые зонды слишком большого размера по-прежнему попадают на точную базовую длину пересылки.
В агрессивном режиме эта базовая выборка удаляется автоматически.
- Компромисс
Агрессивный режим повышает устойчивость к активным классификаторам на основе длины, но он более жесткие ограничения и менее консервативен.
Если вам важна строгая совместимость с логикой таймаутов и no-tail semantics, лучше оставить его выключенным.
Если же ваша модель угроз включает повторяющееся активное зондирование со стороны цензора, этот режим является более сильным вариантом защиты.

Используйте этот режим только в том случае, если ваша модель угроз отдает приоритет устойчивости классификатора над строгой совместимостью с консервативной семантикой маскировки.

## О "размытии" трафика (`[censorship]`)

`mask_shape_above_cap_blur` Добавляет второй этап blur (размытия) для очень больших probe-запросов, которые уже превышают `mask_shape_bucket_cap_bytes`.

- Рандомное дополнение конца данных `[0, mask_shape_above_cap_blur_max_bytes]` добавляется в режиме по умолчанию.
- В агрессивном режиме система всегда добавляет хотя бы немного дополнительных байт в конец трафика: `[1, mask_shape_above_cap_blur_max_bytes]`.
- Система хуже “раскрывает” точный размер больших запросов, но делает это так, чтобы не сильно увеличивать лишний трафик.
- Используйте `mask_shape_above_cap_blur_max_bytes` в базовом режиме, чтобы избежать ненужного роста исходящего трафика

Что это означает на практике:

- Без above-cap blur
  Probe-запрос, который пересылает `5005` байт, всё равно будет выглядеть для backend как `5005` байт, если он уже превышает cap.
- С включённым above-cap blur
Тот же самый probe-запрос может выглядеть как любое значение в ограниченном диапазоне выше его исходной длины.
  Например, если `mask_shape_above_cap_blur_max_bytes = 64`:
  Наблюдаемый на backend размер становится диапазоном `5005..5069` в режиме по умолчанию или `5006..5069` в агрессивном режиме.
- Выбор `mask_shape_above_cap_blur_max_bytes`
Малые значения уменьшают cost, но сохраняют большую различимость между сильно различающимися классами трафика, которые по размеру существенно больше обычного.
Большие значения сильнее размывают (blur) классы трафика, которые по размеру существенно больше обычного, но увеличивают исходящий трафик и вариативность выходных данных.

## Примечания по нормализации таймингов (`[censorship]`)

`mask_timing_normalization_enabled` сглаживает разницу во времени между результатами маскировки, применяя целевой диапазон длительности.

- Случайное целевое значение выбирается в `[mask_timing_normalization_floor_ms, mask_timing_normalization_ceiling_ms]`.
- Быстрые запросы задерживаются до выбранной цели.
- Медленные запросы мягко ограничиваются верхним пределом.

Рекомендованный начальный конфиг для шейпинга таймингов:

- `mask_timing_normalization_enabled = true`
- `mask_timing_normalization_floor_ms = 180`
- `mask_timing_normalization_ceiling_ms = 320`

Если ваш backend или сеть сильно ограничены по пропускной способности, сначала уменьшите cap. Если в вашей среде пробные запросы (probes) всё ещё слишком легко различимы, постепенно увеличивайте нижнее значение.


# [censorship.tls_fetch]


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`profiles`](#profiles) | `String[]` | `["modern_chrome_like", "modern_firefox_like", "compat_tls12", "legacy_minimal"]` |
| [`strict_route`](#strict_route) | `bool` | `true` |
| [`attempt_timeout_ms`](#attempt_timeout_ms) | `u64` | `5000` |
| [`total_budget_ms`](#total_budget_ms) | `u64` | `15000` |
| [`grease_enabled`](#grease_enabled) | `bool` | `false` |
| [`deterministic`](#deterministic) | `bool` | `false` |
| [`profile_cache_ttl_secs`](#profile_cache_ttl_secs) | `u64` | `600` |

## profiles
  - **Ограничения / валидация**: `String[]`. Пустой список возвращает значения по умолчанию; дубликаты удаляются с сохранением порядка.
  - **Описание**: Упорядоченная цепочка fallback-профилей ClientHello для получения TLS-front метаданных.
  - **Пример**:

    ```toml
    [censorship.tls_fetch]
    profiles = ["modern_chrome_like", "compat_tls12"]
    ```
## strict_route
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Если значние `true` и настроен upstream-маршрут, то при ошибках подключения к upstream TLS-запрос завершается с ошибкой вместо перехода на прямое TCP-соединение.
  - **Пример**:

    ```toml
    [censorship.tls_fetch]
    strict_route = true
    ```
## attempt_timeout_ms
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунд).
  - **Описание**: Лимит таймаута на одну попытку получения профиля TLS (мс).
  - **Пример**:

    ```toml
    [censorship.tls_fetch]
    attempt_timeout_ms = 5000
    ```
## total_budget_ms
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунд).
  - **Описание**: Общий бюджет “реального времени” (wall-clock) на все попытки получения данных через TLS (в миллисекундах).
  - **Пример**:

    ```toml
    [censorship.tls_fetch]
    total_budget_ms = 15000
    ```
## grease_enabled
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает случайные GREASE-style значения в выбранных расширениях ClientHello для получения трафика.
  - **Пример**:

    ```toml
    [censorship.tls_fetch]
    grease_enabled = false
    ```
## deterministic
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Включает детерминированную случайность ClientHello для отладки и тестов. Dместо настоящей случайности в TLS ClientHello используется фиксированная (повторяемая) “псевдослучайность”, чтобы поведение можно было воспроизводить.
  - **Пример**:

    ```toml
    [censorship.tls_fetch]
    deterministic = false
    ```
## profile_cache_ttl_secs
  - **Ограничения / валидация**: `u64` (секунд). `0` - отключает кэширование.
  - **Описание**: Время жизни (TTL) записей кэша “победившего профиля” (winner-profile), используемых для получения данных через TLS.
  - **Пример**:

    ```toml
    [censorship.tls_fetch]
    profile_cache_ttl_secs = 600
    ```

# [access]


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`users`](#users) | `Map<String, String>` | `{"default": "000…000"}` |
| [`user_ad_tags`](#user_ad_tags) | `Map<String, String>` | `{}` |
| [`user_max_tcp_conns`](#user_max_tcp_conns) | `Map<String, usize>` | `{}` |
| [`user_max_tcp_conns_global_each`](#user_max_tcp_conns_global_each) | `usize` | `0` |
| [`user_expirations`](#user_expirations) | `Map<String, DateTime<Utc>>` | `{}` |
| [`user_data_quota`](#user_data_quota) | `Map<String, u64>` | `{}` |
| [`user_max_unique_ips`](#user_max_unique_ips) | `Map<String, usize>` | `{}` |
| [`user_max_unique_ips_global_each`](#user_max_unique_ips_global_each) | `usize` | `0` |
| [`user_max_unique_ips_mode`](#user_max_unique_ips_mode) | `"active_window"`, `"time_window"`, or `"combined"` | `"active_window"` |
| [`user_max_unique_ips_window_secs`](#user_max_unique_ips_window_secs) | `u64` | `30` |
| [`replay_check_len`](#replay_check_len) | `usize` | `65536` |
| [`replay_window_secs`](#replay_window_secs) | `u64` | `120` |
| [`ignore_time_skew`](#ignore_time_skew) | `bool` | `false` |

## users
  - **Ограничения / валидация**: Не должно быть пустым (должен существовать хотя бы один пользователь). Каждое значение должно состоять **ровно из 32 шестнадцатеричных символов**.
  - **Описание**: Учетные данные пользователей, используемые для аутентификации клиентов. Ключи — это имена пользователей; значения являются секретами MTProxy.
  - **Пример**:

    ```toml
    [access.users]
    alice = "00112233445566778899aabbccddeeff"
    bob   = "0123456789abcdef0123456789abcdef"
    ```
## user_ad_tags
  - **Ограничения / валидация**: Каждое значение должно содержать **ровно 32 шестнадцатеричных символа** (тот же формат, что и в `general.ad_tag`). Тег со всеми нулями разрешен, но в логи будет записано предупреждение.
  - **Описание**: Переопределение рекламного тега спонсируемого канала для каждого пользователя. Когда у пользователя есть запись здесь, она имеет приоритет над `general.ad_tag`.
  - **Пример**:

    ```toml
    [general]
    ad_tag = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    [access.user_ad_tags]
    alice = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ```
## user_max_tcp_conns
  - **Ограничения / валидация**: `Map<String, usize>`.
  - **Описание**: Максимальное количество одновременных TCP-соединений для каждого пользователя.
  - **Пример**:

    ```toml
    [access.user_max_tcp_conns]
    alice = 500
    ```
## user_max_tcp_conns_global_each
  - **Ограничения / валидация**: `usize`. `0` - отключает лимит.
  - **Описание**: Глобальное максимальное количество одновременных TCP-соединений для каждого пользователя, применяется, когда у пользователя **нет** записи в `[access.user_max_tcp_conns]` (отсутствующее или равное `0` значения подпадают под это условие). Ограничения на пользователя, превышающие `0` в параметре `user_max_tcp_conns`, имеют приоритет.
  - **Пример**:

    ```toml
    [access]
    user_max_tcp_conns_global_each = 200

    [access.user_max_tcp_conns]
    alice = 500   # uses 500, not the global cap
    # bob has no entry > uses 200
    ```
## user_expirations
  - **Ограничения / валидация**: `Map<String, DateTime<Utc>>`. Каждое значение должно быть валидной датой и временем в формате RFC3339/ISO-8601.
  - **Описание**: Временные метки истечения срока действия учетной записи пользователя (UTC).
  - **Пример**:

    ```toml
    [access.user_expirations]
    alice = "2026-12-31T23:59:59Z"
    ```
## user_data_quota
  - **Ограничения / валидация**: `Map<String, u64>`.
  - **Описание**: Квота трафика на пользователя в байтах.
  - **Пример**:

    ```toml
    [access.user_data_quota]
    alice = 1073741824 # 1 GiB
    ```
## user_max_unique_ips
  - **Ограничения / валидация**: `Map<String, usize>`.
  - **Описание**: Ограничение на количество уникальных IP-адресов, с которых выполняется подключение, для каждого пользователя.
  - **Пример**:

    ```toml
    [access.user_max_unique_ips]
    alice = 16
    ```
## user_max_unique_ips_global_each
  - **Ограничения / валидация**: `usize`. `0` - отключает лимит.
  - **Описание**: Глобальный лимит на количество уникальных IP-адресов, с которых выполняется подключение, для каждого пользователя, когда у пользователя нет индивидуального переопределения в `[access.user_max_unique_ips]`.
  - **Пример**:

    ```toml
    [access]
    user_max_unique_ips_global_each = 8
    ```
## user_max_unique_ips_mode
  - **Ограничения / валидация**: `"active_window"`, `"time_window"`, `"combined"`.
  - **Описание**: Режим учета лимита уникальных IP-адресов.
  - **Пример**:

    ```toml
    [access]
    user_max_unique_ips_mode = "active_window"
    ```
## user_max_unique_ips_window_secs
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Размер временного окна (в секундах), используемого режимами учёта уникальных IP, которые работают с ограничением по времени (значения `"time_window"` и `"combined"`).
  - **Пример**:

    ```toml
    [access]
    user_max_unique_ips_window_secs = 30
    ```
## replay_check_len
  - **Ограничения / валидация**: `usize`.
  - **Описание**: Количество последних сообщений/запросов, которое система запоминает, чтобы не допустить их повторной отправки (replay).
  - **Пример**:

    ```toml
    [access]
    replay_check_len = 65536
    ```
## replay_window_secs
  - **Ограничения / валидация**: `u64`.
  - **Описание**: Как долго система "помнит" уже обработанные запросы, чтобы не принять их повторно (в секундах).
  - **Пример**:

    ```toml
    [access]
    replay_window_secs = 120
    ```
## ignore_time_skew
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Отключает проверку расхождения (смещения) времени между клиентом и сервером в валидации защиты от повторной отправки (replay)
  - **Пример**:

    ```toml
    [access]
    ignore_time_skew = false
    ```


# [[upstreams]]


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`type`](#type) | `"direct"`, `"socks4"`, `"socks5"`, or `"shadowsocks"` | — |
| [`weight`](#weight) | `u16` | `1` |
| [`enabled`](#enabled) | `bool` | `true` |
| [`scopes`](#scopes) | `String` | `""` |
| [`interface`](#interface) | `String` | — |
| [`bind_addresses`](#bind_addresses) | `String[]` | — |
| [`url`](#url) | `String` | — |
| [`address`](#address) | `String` | — |
| [`user_id`](#user_id) | `String` | — |
| [`username`](#username) | `String` | — |
| [`password`](#password) | `String` | — |

## type
  - **Ограничения / валидация**: Обязательный параметр.`"direct"`, `"socks4"`, `"socks5"`, `"shadowsocks"`.
  - **Описание**: Выбирает реализацию upstream-транспорта для этой записи в `[[upstreams]]`.
  - **Пример**:

    ```toml
    [[upstreams]]
    type = "direct"

    [[upstreams]]
    type = "socks5"
    address = "127.0.0.1:9050"

    [[upstreams]]
    type = "shadowsocks"
    url = "ss://2022-blake3-aes-256-gcm:BASE64PASSWORD@127.0.0.1:8388"
    ```
## weight
  - **Ограничения / валидация**: `u16` (0..=65535).
  - **Описание**: Приоритет, используемый при случайном выборе upstream-сервера (чем выше значение, тем чаще он выбирается).
  - **Пример**:

    ```toml
    [[upstreams]]
    type = "direct"
    weight = 10
    ```
## enabled
  - **Ограничения / валидация**: `bool`.
  - **Описание**: Если установлено значение `false`, эта запись игнорируется и не используется при выборе upstream-сервера
  - **Пример**:

    ```toml
    [[upstreams]]
    type = "socks5"
    address = "127.0.0.1:9050"
    enabled = false
    ```
## scopes
  - **Ограничения / валидация**: `String`. CСписок, разделенный запятыми; пробелы обрезаются во время сопоставления
  - **Описание**: Теги области (`scope`), используемые для фильтрации upstream-серверов на уровне запроса. Если в запросе указан `scope`, выбираются только те upstream’ы, у которых поле `scopes` содержит этот тег. Если scope в запросе не указан, допускаются только upstream’ы с пустым scopes.
  - **Пример**:

    ```toml
    [[upstreams]]
    type = "socks4"
    address = "10.0.0.10:1080"
    scopes = "me, fetch, dc2"
    ```
## interface
  - **Ограничения / валидация**: `String` (необязательный параметр).
    - для `"direct"`: может быть IP-адресом (используется как явный local bind) или именем сетевого интерфейса ОС (резолвится в IP во время выполнения; только Unix).
    - для `"socks4"`/`"socks5"`: поддерживает только, если `address` - это `IP:port`; если `address` - это имя хоста, interface binding игнорируется.
    - для `"shadowsocks"`: passed to the shadowsocks connector as an optional outbound bind hint.
  - **Описание**: Передаётся в коннектор Shadowsocks как необязательная подсказка для outbound bind.
  - **Пример**:

    ```toml
    [[upstreams]]
    type = "direct"
    interface = "eth0"

    [[upstreams]]
    type = "socks5"
    address = "203.0.113.10:1080"
    interface = "192.0.2.10" # explicit local bind IP
    ```
## bind_addresses
  - **Ограничения / валидация**: `String[]` (необязательный параметр). Применяется в случае, если `type = "direct"`.
    - Каждая запись должна быть IP-адресом в формате строки.
    - Во время выполнения Telemt выбирает адрес, соответствующий целевому семейству (IPv4 или IPv6). Если установлен параметр «bind_addresses», и ни один из них не соответствует целевому семейству, попытка подключения считается неудачной.
  - **Описание**: Явно заданные локальные source адреса для исходящих прямых TCP-соединений. Если указано несколько адресов, они выбираются по алгоритму round-robin.
  - **Пример**:

    ```toml
    [[upstreams]]
    type = "direct"
    bind_addresses = ["192.0.2.10", "192.0.2.11"]
    ```
## url
  - **Ограничения / валидация**: Применяется в случае, если `type = "shadowsocks"`.
    - Должен быть действительный URL-адрес Shadowsocks, принятый `shadowsocks` контейнером.
    - Плагины Shadowsocks не поддерживаются.
    - Требует, чтобы `general.use_middle_proxy = false` ( Shadowsocks upstreams отклоняются в режиме ME (Middle-End)).
  - **Описание**: URL-адрес сервера Shadowsocks, используемый для подключения к Telegram через Shadowsocks.
  - **Пример**:

    ```toml
    [general]
    use_middle_proxy = false

    [[upstreams]]
    type = "shadowsocks"
    url = "ss://2022-blake3-aes-256-gcm:BASE64PASSWORD@127.0.0.1:8388"
    ```
## address
  - **Ограничения / валидация**: Необходим в случае, если `type = "socks4"` и `type = "socks5"`. Значение должно быть в формате `host:port` или `ip:port`.
  - **Описание**: Endpoint прокси-сервера SOCKS, используемый для  upstream-подключений.
  - **Пример**:

    ```toml
    [[upstreams]]
    type = "socks5"
    address = "127.0.0.1:9050"
    ```
## user_id
  - **Ограничения / валидация**: `String` (необязательный параметр). Используется только при `type = "socks4"`.
  - **Описание**: User ID для команды CONNECT в SOCKS4. Примечание: если для запроса выбран scope, Telemt может переопределить это значение на выбранный scope.
  - **Пример**:

    ```toml
    [[upstreams]]
    type = "socks4"
    address = "127.0.0.1:1080"
    user_id = "telemt"
    ```
## username
  - **Ограничения / валидация**: `String` (необязательный параметр). Используется только при `type = "socks5"`.
  - **Описание**: Имя пользователя SOCKS5 (для аутентификации по username/password). Примечание: если для запроса выбран scope, Telemt может переопределить это значение на выбранный scope.
  - **Пример**:

    ```toml
    [[upstreams]]
    type = "socks5"
    address = "127.0.0.1:9050"
    username = "alice"
    ```
## password
  - **Ограничения / валидация**: `String` (необязательный параметр). Используется только при `type = "socks5"`.
  - **Описание**: Пароль SOCKS5 (для аутентификации по username/password). Примечание: если для запроса выбран scope, Telemt может переопределить это значение на выбранный scope.
  - **Пример**:

    ```toml
    [[upstreams]]
    type = "socks5"
    address = "127.0.0.1:9050"
    username = "alice"
    password = "secret"
    ```
