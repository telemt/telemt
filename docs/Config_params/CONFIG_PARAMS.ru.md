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
 - [[server.listeners]](#serverlisteners)
 - [timeouts](#timeouts)
 - [censorship](#censorship)
 - [censorship.tls_fetch](#censorshiptls_fetch)
 - [access](#access)
 - [[upstreams]](#upstreams)

# Ключи верхнего уровня

| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`include`](#cfg-top-include) | `String` (special directive) | — |
| [`show_link`](#cfg-top-show_link) | `"*"` or `String[]` | `[]` (`ShowLink::None`) |
| [`dc_overrides`](#cfg-top-dc_overrides) | `Map<String, String or String[]>` | `{}` |
| [`default_dc`](#cfg-top-default_dc) | `u8` | — (effective fallback: `2` in ME routing) |

## "cfg-top-include"
- `include`
  - **Ограничения / валидация**: Должна быть однострочной директивой в форме `include = "path/to/file.toml"`. Включения расширяются перед анализом TOML. Максимальная глубина включения — 10.
  - **Описание**: Включает еще один файл TOML с помощью `include = "relative/or/absolute/path.toml"`; включения обрабатываются рекурсивно перед анализом.
  - **Пример**:

    ```toml
    include = "secrets.toml"
    ```
## "cfg-top-show_link"
- `show_link`
  - **Ограничения / валидация**: Принимает `"*"` или массив имен пользователей. Пустой массив означает «не показывать ничего».
  - **Описание**: Устаревший селектор видимости ссылок верхнего уровня («*»` для всех пользователей или списка явных имен пользователей).
  - **Пример**:

    ```toml
    # show links for all configured users
    show_link = "*"

    # or: show links only for selected users
    # show_link = ["alice", "bob"]
    ```
## "cfg-top-dc_overrides"
- `dc_overrides`
  - **Ограничения / валидация**: Ключ должен быть положительным целочисленным индексом DC, закодированным как строка (например, `"203"`). Значения должны анализироваться как `SocketAddr` (`ip:port`). Пустые строки игнорируются.
  - **Описание**: Переопределяет конечные точки контроллера домена для нестандартных контроллеров домена; ключ — индексная строка контроллера домена, значение — один или несколько адресов `ip:port`.
  - **Пример**:

    ```toml
    [dc_overrides]
    "201" = "149.154.175.50:443"
    "203" = ["149.154.175.100:443", "91.105.192.100:443"]
    ```
## "cfg-top-default_dc"
- `default_dc`
  - **Ограничения / валидация**: Предполагаемый диапазон: «1..=5». Если этот параметр выходит за пределы диапазона, время выполнения возвращается к поведению DC1 в прямом реле; Маршрутизация среднего уровня возвращается к значению «2», если она не установлена.
  - **Описание**: Индекс контроллера домена по умолчанию, используемый для несопоставленных нестандартных контроллеров домена.
  - **Пример**:

    ```toml
    # When a client requests an unknown/non-standard DC with no override,
    # route it to this default cluster (1..=5).
    default_dc = 2
    ```

# [general]

| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`data_path`](#cfg-general-data_path) | `String` | — |
| [`prefer_ipv6`](#cfg-general-prefer_ipv6) | `bool` | `false` |
| [`fast_mode`](#cfg-general-fast_mode) | `bool` | `true` |
| [`use_middle_proxy`](#cfg-general-use_middle_proxy) | `bool` | `true` |
| [`proxy_secret_path`](#cfg-general-proxy_secret_path) | `String` | `"proxy-secret"` |
| [`proxy_config_v4_cache_path`](#cfg-general-proxy_config_v4_cache_path) | `String` | `"cache/proxy-config-v4.txt"` |
| [`proxy_config_v6_cache_path`](#cfg-general-proxy_config_v6_cache_path) | `String` | `"cache/proxy-config-v6.txt"` |
| [`ad_tag`](#cfg-general-ad_tag) | `String` | — |
| [`middle_proxy_nat_ip`](#cfg-general-middle_proxy_nat_ip) | `IpAddr` | — |
| [`middle_proxy_nat_probe`](#cfg-general-middle_proxy_nat_probe) | `bool` | `true` |
| [`middle_proxy_nat_stun`](#cfg-general-middle_proxy_nat_stun) | `String` | — |
| [`middle_proxy_nat_stun_servers`](#cfg-general-middle_proxy_nat_stun_servers) | `String[]` | `[]` |
| [`stun_nat_probe_concurrency`](#cfg-general-stun_nat_probe_concurrency) | `usize` | `8` |
| [`middle_proxy_pool_size`](#cfg-general-middle_proxy_pool_size) | `usize` | `8` |
| [`middle_proxy_warm_standby`](#cfg-general-middle_proxy_warm_standby) | `usize` | `16` |
| [`me_init_retry_attempts`](#cfg-general-me_init_retry_attempts) | `u32` | `0` |
| [`me2dc_fallback`](#cfg-general-me2dc_fallback) | `bool` | `true` |
| [`me2dc_fast`](#cfg-general-me2dc_fast) | `bool` | `false` |
| [`me_keepalive_enabled`](#cfg-general-me_keepalive_enabled) | `bool` | `true` |
| [`me_keepalive_interval_secs`](#cfg-general-me_keepalive_interval_secs) | `u64` | `8` |
| [`me_keepalive_jitter_secs`](#cfg-general-me_keepalive_jitter_secs) | `u64` | `2` |
| [`me_keepalive_payload_random`](#cfg-general-me_keepalive_payload_random) | `bool` | `true` |
| [`rpc_proxy_req_every`](#cfg-general-rpc_proxy_req_every) | `u64` | `0` |
| [`me_writer_cmd_channel_capacity`](#cfg-general-me_writer_cmd_channel_capacity) | `usize` | `4096` |
| [`me_route_channel_capacity`](#cfg-general-me_route_channel_capacity) | `usize` | `768` |
| [`me_c2me_channel_capacity`](#cfg-general-me_c2me_channel_capacity) | `usize` | `1024` |
| [`me_c2me_send_timeout_ms`](#cfg-general-me_c2me_send_timeout_ms) | `u64` | `4000` |
| [`me_reader_route_data_wait_ms`](#cfg-general-me_reader_route_data_wait_ms) | `u64` | `2` |
| [`me_d2c_flush_batch_max_frames`](#cfg-general-me_d2c_flush_batch_max_frames) | `usize` | `32` |
| [`me_d2c_flush_batch_max_bytes`](#cfg-general-me_d2c_flush_batch_max_bytes) | `usize` | `131072` |
| [`me_d2c_flush_batch_max_delay_us`](#cfg-general-me_d2c_flush_batch_max_delay_us) | `u64` | `500` |
| [`me_d2c_ack_flush_immediate`](#cfg-general-me_d2c_ack_flush_immediate) | `bool` | `true` |
| [`me_quota_soft_overshoot_bytes`](#cfg-general-me_quota_soft_overshoot_bytes) | `u64` | `65536` |
| [`me_d2c_frame_buf_shrink_threshold_bytes`](#cfg-general-me_d2c_frame_buf_shrink_threshold_bytes) | `usize` | `262144` |
| [`direct_relay_copy_buf_c2s_bytes`](#cfg-general-direct_relay_copy_buf_c2s_bytes) | `usize` | `65536` |
| [`direct_relay_copy_buf_s2c_bytes`](#cfg-general-direct_relay_copy_buf_s2c_bytes) | `usize` | `262144` |
| [`crypto_pending_buffer`](#cfg-general-crypto_pending_buffer) | `usize` | `262144` |
| [`max_client_frame`](#cfg-general-max_client_frame) | `usize` | `16777216` |
| [`desync_all_full`](#cfg-general-desync_all_full) | `bool` | `false` |
| [`beobachten`](#cfg-general-beobachten) | `bool` | `true` |
| [`beobachten_minutes`](#cfg-general-beobachten_minutes) | `u64` | `10` |
| [`beobachten_flush_secs`](#cfg-general-beobachten_flush_secs) | `u64` | `15` |
| [`beobachten_file`](#cfg-general-beobachten_file) | `String` | `"cache/beobachten.txt"` |
| [`hardswap`](#cfg-general-hardswap) | `bool` | `true` |
| [`me_warmup_stagger_enabled`](#cfg-general-me_warmup_stagger_enabled) | `bool` | `true` |
| [`me_warmup_step_delay_ms`](#cfg-general-me_warmup_step_delay_ms) | `u64` | `500` |
| [`me_warmup_step_jitter_ms`](#cfg-general-me_warmup_step_jitter_ms) | `u64` | `300` |
| [`me_reconnect_max_concurrent_per_dc`](#cfg-general-me_reconnect_max_concurrent_per_dc) | `u32` | `8` |
| [`me_reconnect_backoff_base_ms`](#cfg-general-me_reconnect_backoff_base_ms) | `u64` | `500` |
| [`me_reconnect_backoff_cap_ms`](#cfg-general-me_reconnect_backoff_cap_ms) | `u64` | `30000` |
| [`me_reconnect_fast_retry_count`](#cfg-general-me_reconnect_fast_retry_count) | `u32` | `16` |
| [`me_single_endpoint_shadow_writers`](#cfg-general-me_single_endpoint_shadow_writers) | `u8` | `2` |
| [`me_single_endpoint_outage_mode_enabled`](#cfg-general-me_single_endpoint_outage_mode_enabled) | `bool` | `true` |
| [`me_single_endpoint_outage_disable_quarantine`](#cfg-general-me_single_endpoint_outage_disable_quarantine) | `bool` | `true` |
| [`me_single_endpoint_outage_backoff_min_ms`](#cfg-general-me_single_endpoint_outage_backoff_min_ms) | `u64` | `250` |
| [`me_single_endpoint_outage_backoff_max_ms`](#cfg-general-me_single_endpoint_outage_backoff_max_ms) | `u64` | `3000` |
| [`me_single_endpoint_shadow_rotate_every_secs`](#cfg-general-me_single_endpoint_shadow_rotate_every_secs) | `u64` | `900` |
| [`me_floor_mode`](#cfg-general-me_floor_mode) | `"static"` or `"adaptive"` | `"adaptive"` |
| [`me_adaptive_floor_idle_secs`](#cfg-general-me_adaptive_floor_idle_secs) | `u64` | `90` |
| [`me_adaptive_floor_min_writers_single_endpoint`](#cfg-general-me_adaptive_floor_min_writers_single_endpoint) | `u8` | `1` |
| [`me_adaptive_floor_min_writers_multi_endpoint`](#cfg-general-me_adaptive_floor_min_writers_multi_endpoint) | `u8` | `1` |
| [`me_adaptive_floor_recover_grace_secs`](#cfg-general-me_adaptive_floor_recover_grace_secs) | `u64` | `180` |
| [`me_adaptive_floor_writers_per_core_total`](#cfg-general-me_adaptive_floor_writers_per_core_total) | `u16` | `48` |
| [`me_adaptive_floor_cpu_cores_override`](#cfg-general-me_adaptive_floor_cpu_cores_override) | `u16` | `0` |
| [`me_adaptive_floor_max_extra_writers_single_per_core`](#cfg-general-me_adaptive_floor_max_extra_writers_single_per_core) | `u16` | `1` |
| [`me_adaptive_floor_max_extra_writers_multi_per_core`](#cfg-general-me_adaptive_floor_max_extra_writers_multi_per_core) | `u16` | `2` |
| [`me_adaptive_floor_max_active_writers_per_core`](#cfg-general-me_adaptive_floor_max_active_writers_per_core) | `u16` | `64` |
| [`me_adaptive_floor_max_warm_writers_per_core`](#cfg-general-me_adaptive_floor_max_warm_writers_per_core) | `u16` | `64` |
| [`me_adaptive_floor_max_active_writers_global`](#cfg-general-me_adaptive_floor_max_active_writers_global) | `u32` | `256` |
| [`me_adaptive_floor_max_warm_writers_global`](#cfg-general-me_adaptive_floor_max_warm_writers_global) | `u32` | `256` |
| [`upstream_connect_retry_attempts`](#cfg-general-upstream_connect_retry_attempts) | `u32` | `2` |
| [`upstream_connect_retry_backoff_ms`](#cfg-general-upstream_connect_retry_backoff_ms) | `u64` | `100` |
| [`upstream_connect_budget_ms`](#cfg-general-upstream_connect_budget_ms) | `u64` | `3000` |
| [`upstream_unhealthy_fail_threshold`](#cfg-general-upstream_unhealthy_fail_threshold) | `u32` | `5` |
| [`upstream_connect_failfast_hard_errors`](#cfg-general-upstream_connect_failfast_hard_errors) | `bool` | `false` |
| [`stun_iface_mismatch_ignore`](#cfg-general-stun_iface_mismatch_ignore) | `bool` | `false` |
| [`unknown_dc_log_path`](#cfg-general-unknown_dc_log_path) | `String` | `"unknown-dc.txt"` |
| [`unknown_dc_file_log_enabled`](#cfg-general-unknown_dc_file_log_enabled) | `bool` | `false` |
| [`log_level`](#cfg-general-log_level) | `"debug"`, `"verbose"`, `"normal"`, or `"silent"` | `"normal"` |
| [`disable_colors`](#cfg-general-disable_colors) | `bool` | `false` |
| [`me_socks_kdf_policy`](#cfg-general-me_socks_kdf_policy) | `"strict"` or `"compat"` | `"strict"` |
| [`me_route_backpressure_base_timeout_ms`](#cfg-general-me_route_backpressure_base_timeout_ms) | `u64` | `25` |
| [`me_route_backpressure_high_timeout_ms`](#cfg-general-me_route_backpressure_high_timeout_ms) | `u64` | `120` |
| [`me_route_backpressure_high_watermark_pct`](#cfg-general-me_route_backpressure_high_watermark_pct) | `u8` | `80` |
| [`me_health_interval_ms_unhealthy`](#cfg-general-me_health_interval_ms_unhealthy) | `u64` | `1000` |
| [`me_health_interval_ms_healthy`](#cfg-general-me_health_interval_ms_healthy) | `u64` | `3000` |
| [`me_admission_poll_ms`](#cfg-general-me_admission_poll_ms) | `u64` | `1000` |
| [`me_warn_rate_limit_ms`](#cfg-general-me_warn_rate_limit_ms) | `u64` | `5000` |
| [`me_route_no_writer_mode`](#cfg-general-me_route_no_writer_mode) | `"async_recovery_failfast"`, `"inline_recovery_legacy"`, or `"hybrid_async_persistent"` | `"hybrid_async_persistent"` |
| [`me_route_no_writer_wait_ms`](#cfg-general-me_route_no_writer_wait_ms) | `u64` | `250` |
| [`me_route_hybrid_max_wait_ms`](#cfg-general-me_route_hybrid_max_wait_ms) | `u64` | `3000` |
| [`me_route_blocking_send_timeout_ms`](#cfg-general-me_route_blocking_send_timeout_ms) | `u64` | `250` |
| [`me_route_inline_recovery_attempts`](#cfg-general-me_route_inline_recovery_attempts) | `u32` | `3` |
| [`me_route_inline_recovery_wait_ms`](#cfg-general-me_route_inline_recovery_wait_ms) | `u64` | `3000` |
| [`fast_mode_min_tls_record`](#cfg-general-fast_mode_min_tls_record) | `usize` | `0` |
| [`update_every`](#cfg-general-update_every) | `u64` | `300` |
| [`me_reinit_every_secs`](#cfg-general-me_reinit_every_secs) | `u64` | `900` |
| [`me_hardswap_warmup_delay_min_ms`](#cfg-general-me_hardswap_warmup_delay_min_ms) | `u64` | `1000` |
| [`me_hardswap_warmup_delay_max_ms`](#cfg-general-me_hardswap_warmup_delay_max_ms) | `u64` | `2000` |
| [`me_hardswap_warmup_extra_passes`](#cfg-general-me_hardswap_warmup_extra_passes) | `u8` | `3` |
| [`me_hardswap_warmup_pass_backoff_base_ms`](#cfg-general-me_hardswap_warmup_pass_backoff_base_ms) | `u64` | `500` |
| [`me_config_stable_snapshots`](#cfg-general-me_config_stable_snapshots) | `u8` | `2` |
| [`me_config_apply_cooldown_secs`](#cfg-general-me_config_apply_cooldown_secs) | `u64` | `300` |
| [`me_snapshot_require_http_2xx`](#cfg-general-me_snapshot_require_http_2xx) | `bool` | `true` |
| [`me_snapshot_reject_empty_map`](#cfg-general-me_snapshot_reject_empty_map) | `bool` | `true` |
| [`me_snapshot_min_proxy_for_lines`](#cfg-general-me_snapshot_min_proxy_for_lines) | `u32` | `1` |
| [`proxy_secret_stable_snapshots`](#cfg-general-proxy_secret_stable_snapshots) | `u8` | `2` |
| [`proxy_secret_rotate_runtime`](#cfg-general-proxy_secret_rotate_runtime) | `bool` | `true` |
| [`me_secret_atomic_snapshot`](#cfg-general-me_secret_atomic_snapshot) | `bool` | `true` |
| [`proxy_secret_len_max`](#cfg-general-proxy_secret_len_max) | `usize` | `256` |
| [`me_pool_drain_ttl_secs`](#cfg-general-me_pool_drain_ttl_secs) | `u64` | `90` |
| [`me_instadrain`](#cfg-general-me_instadrain) | `bool` | `false` |
| [`me_pool_drain_threshold`](#cfg-general-me_pool_drain_threshold) | `u64` | `32` |
| [`me_pool_drain_soft_evict_enabled`](#cfg-general-me_pool_drain_soft_evict_enabled) | `bool` | `true` |
| [`me_pool_drain_soft_evict_grace_secs`](#cfg-general-me_pool_drain_soft_evict_grace_secs) | `u64` | `10` |
| [`me_pool_drain_soft_evict_per_writer`](#cfg-general-me_pool_drain_soft_evict_per_writer) | `u8` | `2` |
| [`me_pool_drain_soft_evict_budget_per_core`](#cfg-general-me_pool_drain_soft_evict_budget_per_core) | `u16` | `16` |
| [`me_pool_drain_soft_evict_cooldown_ms`](#cfg-general-me_pool_drain_soft_evict_cooldown_ms) | `u64` | `1000` |
| [`me_bind_stale_mode`](#cfg-general-me_bind_stale_mode) | `"never"`, `"ttl"`, or `"always"` | `"ttl"` |
| [`me_bind_stale_ttl_secs`](#cfg-general-me_bind_stale_ttl_secs) | `u64` | `90` |
| [`me_pool_min_fresh_ratio`](#cfg-general-me_pool_min_fresh_ratio) | `f32` | `0.8` |
| [`me_reinit_drain_timeout_secs`](#cfg-general-me_reinit_drain_timeout_secs) | `u64` | `90` |
| [`proxy_secret_auto_reload_secs`](#cfg-general-proxy_secret_auto_reload_secs) | `u64` | `3600` |
| [`proxy_config_auto_reload_secs`](#cfg-general-proxy_config_auto_reload_secs) | `u64` | `3600` |
| [`me_reinit_singleflight`](#cfg-general-me_reinit_singleflight) | `bool` | `true` |
| [`me_reinit_trigger_channel`](#cfg-general-me_reinit_trigger_channel) | `usize` | `64` |
| [`me_reinit_coalesce_window_ms`](#cfg-general-me_reinit_coalesce_window_ms) | `u64` | `200` |
| [`me_deterministic_writer_sort`](#cfg-general-me_deterministic_writer_sort) | `bool` | `true` |
| [`me_writer_pick_mode`](#cfg-general-me_writer_pick_mode) | `"sorted_rr"` or `"p2c"` | `"p2c"` |
| [`me_writer_pick_sample_size`](#cfg-general-me_writer_pick_sample_size) | `u8` | `3` |
| [`ntp_check`](#cfg-general-ntp_check) | `bool` | `true` |
| [`ntp_servers`](#cfg-general-ntp_servers) | `String[]` | `["pool.ntp.org"]` |
| [`auto_degradation_enabled`](#cfg-general-auto_degradation_enabled) | `bool` | `true` |
| [`degradation_min_unavailable_dc_groups`](#cfg-general-degradation_min_unavailable_dc_groups) | `u8` | `2` |
| [`rst_on_close`](#cfg-general-rst_on_close) | `"off"`, `"errors"` или `"always"` | `"off"` |

## "cfg-general-data_path"
- `data_path`
  - **Ограничения / валидация**: `Строка` (необязательно).
  - **Описание**: Необязательный путь к каталогу данных времени выполнения.
  - **Пример**:

    ```toml
    [general]
    data_path = "/var/lib/telemt"
    ```
## "cfg-general-prefer_ipv6"
- `prefer_ipv6`
  - **Ограничения / валидация**: Устарело. Используйте `network.prefer`.
  - **Описание**: Устаревший устаревший флаг предпочтения IPv6 перенесен в network.prefer.
  - **Пример**:

    ```toml
    [network]
    prefer = 6
    ```
## "cfg-general-fast_mode"
- `fast_mode`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает оптимизацию быстрого пути для обработки трафика.
  - **Пример**:

    ```toml
    [general]
    fast_mode = true
    ```
## "cfg-general-use_middle_proxy"
- `use_middle_proxy`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает транспортный режим ME; если значение false, среда выполнения возвращается к прямой маршрутизации постоянного тока.
  - **Пример**:

    ```toml
    [general]
    use_middle_proxy = true
    ```
## "cfg-general-proxy_secret_path"
- `proxy_secret_path`
  - **Ограничения / валидация**: `Строка`. Если этот параметр опущен, путь по умолчанию — «proxy-secret». Пустые значения принимаются TOML/serde, но, скорее всего, во время выполнения произойдет ошибка (неверный путь к файлу).
  - **Описание**: Путь к файлу кэша `proxy-secret` инфраструктуры Telegram, используемому ME-рукопожатием/аутентификацией RPC. Telemt всегда сначала пытается выполнить новую загрузку с https://core.telegram.org/getProxySecret, в случае успеха кэширует ее по этому пути и возвращается к чтению кэшированного файла (любого возраста) в случае сбоя загрузки.
  - **Пример**:

    ```toml
    [general]
    proxy_secret_path = "proxy-secret"
    ```
## "cfg-general-proxy_config_v4_cache_path"
- `proxy_config_v4_cache_path`
  - **Ограничения / валидация**: `Строка`. Если установлено, оно не должно быть пустым или содержать только пробелы.
  - **Описание**: Необязательный путь к дисковому кэшу для необработанного снимка getProxyConfig (IPv4). При запуске Telemt сначала пытается получить свежий снимок; в случае сбоя выборки или пустого снимка он возвращается к этому файлу кэша, если он присутствует и не пуст.
  - **Пример**:

    ```toml
    [general]
    proxy_config_v4_cache_path = "cache/proxy-config-v4.txt"
    ```
## "cfg-general-proxy_config_v6_cache_path"
- `proxy_config_v6_cache_path`
  - **Ограничения / валидация**: `Строка`. Если установлено, оно не должно быть пустым или содержать только пробелы.
  - **Описание**: Необязательный путь к дисковому кэшу для необработанного снимка getProxyConfigV6 (IPv6). При запуске Telemt сначала пытается получить свежий снимок; в случае сбоя выборки или пустого снимка он возвращается к этому файлу кэша, если он присутствует и не пуст.
  - **Пример**:

    ```toml
    [general]
    proxy_config_v6_cache_path = "cache/proxy-config-v6.txt"
    ```
## "cfg-general-ad_tag"
- `ad_tag`
  - **Ограничения / валидация**: `Строка` (необязательно). Если установлено, должно быть ровно 32 шестнадцатеричных символа; недопустимые значения отключаются во время загрузки конфигурации.
  - **Описание**: Глобальный резервный спонсируемый канал `ad_tag` (используется, когда у пользователя нет переопределения в `access.user_ad_tags`). Тег со всеми нулями принимается, но не имеет никакого эффекта (и о нем предупреждается), пока не будет заменен реальным тегом от `@MTProxybot`.
  - **Пример**:

    ```toml
    [general]
    ad_tag = "00112233445566778899aabbccddeeff"
    ```
## "cfg-general-middle_proxy_nat_ip"
- `middle_proxy_nat_ip`
  - **Ограничения / валидация**: `IpAddr` (необязательно).
  - **Описание**: Ручное переопределение общедоступного IP-адреса NAT используется в качестве материала ME-адреса, если оно установлено.
  - **Пример**:

    ```toml
    [general]
    middle_proxy_nat_ip = "203.0.113.10"
    ```
## "cfg-general-middle_proxy_nat_probe"
- `middle_proxy_nat_probe`
  - **Ограничения / валидация**: `бул`. Эффективное зондирование ограничивается `network.stun_use` (когда `network.stun_use = false`, STUN-зондирование отключается, даже если этот флаг имеет значение `true`).
  - **Описание**: Позволяет зондировать NAT на основе STUN для обнаружения общедоступного IP-порта, используемого при получении ключа ME в средах NAT.
  - **Пример**:

    ```toml
    [general]
    middle_proxy_nat_probe = true
    ```
## "cfg-general-middle_proxy_nat_stun"
- `middle_proxy_nat_stun`
  - **Ограничения / валидация**: Устарело. Используйте `network.stun_servers`.
  - **Описание**: Устаревший устаревший одиночный сервер STUN для проверки NAT. Во время загрузки конфигурации он объединяется с `network.stun_servers`, если `network.stun_servers` не задан явно.
  - **Пример**:

    ```toml
    [network]
    stun_servers = ["stun.l.google.com:19302"]
    ```
## "cfg-general-middle_proxy_nat_stun_servers"
- `middle_proxy_nat_stun_servers`
  - **Ограничения / валидация**: Устарело. Используйте `network.stun_servers`.
  - **Описание**: Устаревший устаревший список STUN для резервного копирования NAT. Во время загрузки конфигурации он объединяется с `network.stun_servers`, если `network.stun_servers` не задан явно.
  - **Пример**:

    ```toml
    [network]
    stun_servers = ["stun.l.google.com:19302"]
    ```
## "cfg-general-stun_nat_probe_concurrency"
- `stun_nat_probe_concurrency`
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Максимальное количество параллельных тестов STUN во время обнаружения NAT/публичной конечной точки.
  - **Пример**:

    ```toml
    [general]
    stun_nat_probe_concurrency = 8
    ```
## "cfg-general-middle_proxy_pool_size"
- `middle_proxy_pool_size`
  - **Ограничения / валидация**: `использовать`. Эффективное значение — «max(value, 1)» во время выполнения (поэтому «0» ведет себя как «1»).
  - **Описание**: Целевой размер активного пула устройств записи ME.
  - **Пример**:

    ```toml
    [general]
    middle_proxy_pool_size = 8
    ```
## "cfg-general-middle_proxy_warm_standby"
- `middle_proxy_warm_standby`
  - **Ограничения / валидация**: `использовать`.
  - **Описание**: Количество подключений ME в теплом резерве, предварительно инициализированных.
  - **Пример**:

    ```toml
    [general]
    middle_proxy_warm_standby = 16
    ```
## "cfg-general-me_init_retry_attempts"
- `me_init_retry_attempts`
  - **Ограничения / валидация**: `0..=1_000_000` (`0` означает неограниченное количество повторов).
  - **Описание**: Повторные попытки инициализации пула ME.
  - **Пример**:

    ```toml
    [general]
    me_init_retry_attempts = 0
    ```
## "cfg-general-me2dc_fallback"
- `me2dc_fallback`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Позволяет перейти из режима ME в режим прямого постоянного тока в случае сбоя запуска ME.
  - **Пример**:

    ```toml
    [general]
    me2dc_fallback = true
    ```
## "cfg-general-me2dc_fast"
- `me2dc_fast`
  - **Ограничения / валидация**: `бул`. Активен только тогда, когда `use_middle_proxy = true` и `me2dc_fallback = true`.
  - **Описание**: Fast ME->Режим прямого возврата для новых сеансов.
  - **Пример**:

    ```toml
    [general]
    use_middle_proxy = true
    me2dc_fallback = true
    me2dc_fast = false
    ```
## "cfg-general-me_keepalive_enabled"
- `me_keepalive_enabled`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает периодические дополнительные кадры поддержки активности ME.
  - **Пример**:

    ```toml
    [general]
    me_keepalive_enabled = true
    ```
## "cfg-general-me_keepalive_interval_secs"
- `me_keepalive_interval_secs`
  - **Ограничения / валидация**: `u64` (секунды).
  - **Описание**: Базовый интервал поддержки активности ME в секундах.
  - **Пример**:

    ```toml
    [general]
    me_keepalive_interval_secs = 8
    ```
## "cfg-general-me_keepalive_jitter_secs"
- `me_keepalive_jitter_secs`
  - **Ограничения / валидация**: `u64` (секунды).
  - **Описание**: Джиттер Keepalive за считанные секунды для уменьшения синхронизированных пакетов.
  - **Пример**:

    ```toml
    [general]
    me_keepalive_jitter_secs = 2
    ```
## "cfg-general-me_keepalive_payload_random"
- `me_keepalive_payload_random`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Случайным образом изменяет байты полезной нагрузки поддержки активности вместо фиксированной нулевой полезной нагрузки.
  - **Пример**:

    ```toml
    [general]
    me_keepalive_payload_random = true
    ```
## "cfg-general-rpc_proxy_req_every"
- `rpc_proxy_req_every`
  - **Ограничения / валидация**: `0` или в пределах `10..=300` (секунд).
  - **Описание**: Интервал для сигналов активности службы `RPC_PROXY_REQ` для ME (`0` отключает).
  - **Пример**:

    ```toml
    [general]
    rpc_proxy_req_every = 0
    ```
## "cfg-general-me_writer_cmd_channel_capacity"
- `me_writer_cmd_channel_capacity`
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Пропускная способность командного канала для каждого записывающего устройства.
  - **Пример**:

    ```toml
    [general]
    me_writer_cmd_channel_capacity = 4096
    ```
## "cfg-general-me_route_channel_capacity"
- `me_route_channel_capacity`
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Пропускная способность канала маршрута ответа ME для каждого соединения.
  - **Пример**:

    ```toml
    [general]
    me_route_channel_capacity = 768
    ```
## "cfg-general-me_c2me_channel_capacity"
- `me_c2me_channel_capacity`
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Емкость очереди команд для каждого клиента (читатель клиента -> отправитель ME).
  - **Пример**:

    ```toml
    [general]
    me_c2me_channel_capacity = 1024
    ```
## "cfg-general-me_c2me_send_timeout_ms"
- `me_c2me_send_timeout_ms`
  - **Ограничения / валидация**: `0..=60000` (миллисекунды).
  - **Описание**: Максимальное ожидание постановки в очередь команд клиент->ME, когда очередь для каждого клиента заполнена (`0` сохраняет устаревшее неограниченное ожидание).
  - **Пример**:

    ```toml
    [general]
    me_c2me_send_timeout_ms = 4000
    ```
## "cfg-general-me_reader_route_data_wait_ms"
- `me_reader_route_data_wait_ms`
  - **Ограничения / валидация**: `0..=20` (миллисекунды).
  - **Описание**: Ограниченное ожидание маршрутизации ME DATA в очередь для каждого соединения (`0` = нет ожидания).
  - **Пример**:

    ```toml
    [general]
    me_reader_route_data_wait_ms = 2
    ```
## "cfg-general-me_d2c_flush_batch_max_frames"
- `me_d2c_flush_batch_max_frames`
  - **Ограничения / валидация**: Должно быть в пределах `1..=512`.
  - **Описание**: Макс. ME->клиентские кадры объединяются перед очисткой.
  - **Пример**:

    ```toml
    [general]
    me_d2c_flush_batch_max_frames = 32
    ```
## "cfg-general-me_d2c_flush_batch_max_bytes"
- `me_d2c_flush_batch_max_bytes`
  - **Ограничения / валидация**: Должно быть в пределах `4096..=2097152` (байт).
  - **Описание**: Максимальное количество байтов полезной нагрузки ME->клиента, объединенных перед сбросом.
  - **Пример**:

    ```toml
    [general]
    me_d2c_flush_batch_max_bytes = 131072
    ```
## "cfg-general-me_d2c_flush_batch_max_delay_us"
- `me_d2c_flush_batch_max_delay_us`
  - **Ограничения / валидация**: `0..=5000` (микросекунды).
  - **Описание**: Максимальное время ожидания в микросекундах для объединения большего количества кадров ME->клиента (`0` отключает объединение по времени).
  - **Пример**:

    ```toml
    [general]
    me_d2c_flush_batch_max_delay_us = 500
    ```
## "cfg-general-me_d2c_ack_flush_immediate"
- `me_d2c_ack_flush_immediate`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Сбрасывает запись клиента сразу после записи быстрого подтверждения.
  - **Пример**:

    ```toml
    [general]
    me_d2c_ack_flush_immediate = true
    ```
## "cfg-general-me_quota_soft_overshoot_bytes"
- `me_quota_soft_overshoot_bytes`
  - **Ограничения / валидация**: `0..=16777216` (байты).
  - **Описание**: Дополнительные квоты для каждого маршрута (в байтах) допускаются до того, как принудительное применение квот на стороне записи отбрасывает данные маршрута.
  - **Пример**:

    ```toml
    [general]
    me_quota_soft_overshoot_bytes = 65536
    ```
## "cfg-general-me_d2c_frame_buf_shrink_threshold_bytes"
- `me_d2c_frame_buf_shrink_threshold_bytes`
  - **Ограничения / валидация**: Должно быть в пределах `4096..=16777216` (байт).
  - **Описание**: Пороговое значение для сжатия слишком больших буферов агрегации кадров ME->клиента после очистки.
  - **Пример**:

    ```toml
    [general]
    me_d2c_frame_buf_shrink_threshold_bytes = 262144
    ```
## "cfg-general-direct_relay_copy_buf_c2s_bytes"
- `direct_relay_copy_buf_c2s_bytes`
  - **Ограничения / валидация**: Должно быть в пределах `4096..=1048576` (байт).
  - **Описание**: Размер буфера копирования для направления клиент->DC в прямой ретрансляции.
  - **Пример**:

    ```toml
    [general]
    direct_relay_copy_buf_c2s_bytes = 65536
    ```
## "cfg-general-direct_relay_copy_buf_s2c_bytes"
- `direct_relay_copy_buf_s2c_bytes`
  - **Ограничения / валидация**: Должно быть в пределах `8192..=2097152` (байт).
  - **Описание**: Размер буфера копирования для направления DC->клиент при прямой ретрансляции.
  - **Пример**:

    ```toml
    [general]
    direct_relay_copy_buf_s2c_bytes = 262144
    ```
## "cfg-general-crypto_pending_buffer"
- `crypto_pending_buffer`
  - **Ограничения / валидация**: `использовать` (байты).
  - **Описание**: Максимальный буфер ожидающего зашифрованного текста на каждого клиента-писателя (в байтах).
  - **Пример**:

    ```toml
    [general]
    crypto_pending_buffer = 262144
    ```
## "cfg-general-max_client_frame"
- `max_client_frame`
  - **Ограничения / валидация**: `использовать` (байты).
  - **Описание**: Максимально допустимый размер кадра MTProto клиента (в байтах).
  - **Пример**:

    ```toml
    [general]
    max_client_frame = 16777216
    ```
## "cfg-general-desync_all_full"
- `desync_all_full`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Создает полные журналы крипто-рассинхронизации для каждого события.
  - **Пример**:

    ```toml
    [general]
    desync_all_full = false
    ```
## "cfg-general-beobachten"
- `beobachten`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает сегменты криминалистического наблюдения для каждого IP-адреса.
  - **Пример**:

    ```toml
    [general]
    beobachten = true
    ```
## "cfg-general-beobachten_minutes"
- `beobachten_minutes`
  - **Ограничения / валидация**: Должно быть `> 0` (минуты).
  - **Описание**: Окно хранения (минуты) для сегментов наблюдения по каждому IP-адресу.
  - **Пример**:

    ```toml
    [general]
    beobachten_minutes = 10
    ```
## "cfg-general-beobachten_flush_secs"
- `beobachten_flush_secs`
  - **Ограничения / валидация**: Должно быть `> 0` (секунды).
  - **Описание**: Интервал сброса моментального снимка (в секундах) для выходного файла наблюдения.
  - **Пример**:

    ```toml
    [general]
    beobachten_flush_secs = 15
    ```
## "cfg-general-beobachten_file"
- `beobachten_file`
  - **Ограничения / валидация**: Не должно быть пустым или содержать только пробелы.
  - **Описание**: Путь к выходному файлу снимка наблюдения.
  - **Пример**:

    ```toml
    [general]
    beobachten_file = "cache/beobachten.txt"
    ```
## "cfg-general-hardswap"
- `hardswap`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает стратегию жесткой замены ME на основе генерации.
  - **Пример**:

    ```toml
    [general]
    hardswap = true
    ```
## "cfg-general-me_warmup_stagger_enabled"
- `me_warmup_stagger_enabled`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Перемещает дополнительные шкалы прогрева ME, чтобы избежать всплесков соединения.
  - **Пример**:

    ```toml
    [general]
    me_warmup_stagger_enabled = true
    ```
## "cfg-general-me_warmup_step_delay_ms"
- `me_warmup_step_delay_ms`
  - **Ограничения / валидация**: `u64` (миллисекунды).
  - **Описание**: Базовая задержка в миллисекундах между этапами набора прогрева.
  - **Пример**:

    ```toml
    [general]
    me_warmup_step_delay_ms = 500
    ```
## "cfg-general-me_warmup_step_jitter_ms"
- `me_warmup_step_jitter_ms`
  - **Ограничения / валидация**: `u64` (миллисекунды).
  - **Описание**: Дополнительная случайная задержка в миллисекундах для шагов разминки.
  - **Пример**:

    ```toml
    [general]
    me_warmup_step_jitter_ms = 300
    ```
## "cfg-general-me_reconnect_max_concurrent_per_dc"
- `me_reconnect_max_concurrent_per_dc`
  - **Ограничения / валидация**: `u32`. Эффективное значение — «max(value, 1)» во время выполнения (поэтому «0» ведет себя как «1»).
  - **Описание**: Ограничивает число одновременных рабочих повторных подключений на каждый контроллер домена во время восстановления работоспособности.
  - **Пример**:

    ```toml
    [general]
    me_reconnect_max_concurrent_per_dc = 8
    ```
## "cfg-general-me_reconnect_backoff_base_ms"
- `me_reconnect_backoff_base_ms`
  - **Ограничения / валидация**: `u64` (миллисекунды).
  - **Описание**: Начальная задержка повторного подключения в миллисекундах.
  - **Пример**:

    ```toml
    [general]
    me_reconnect_backoff_base_ms = 500
    ```
## "cfg-general-me_reconnect_backoff_cap_ms"
- `me_reconnect_backoff_cap_ms`
  - **Ограничения / валидация**: `u64` (миллисекунды).
  - **Описание**: Максимальное ограничение задержки повторного подключения в миллисекундах.
  - **Пример**:

    ```toml
    [general]
    me_reconnect_backoff_cap_ms = 30000
    ```
## "cfg-general-me_reconnect_fast_retry_count"
- `me_reconnect_fast_retry_count`
  - **Ограничения / валидация**: `u32`. Эффективное значение — «max(value, 1)» во время выполнения (поэтому «0» ведет себя как «1»).
  - **Описание**: Немедленный бюджет повторных попыток, прежде чем применяется поведение длительной отсрочки.
  - **Пример**:

    ```toml
    [general]
    me_reconnect_fast_retry_count = 16
    ```
## "cfg-general-me_single_endpoint_shadow_writers"
- `me_single_endpoint_shadow_writers`
  - **Ограничения / валидация**: Должно быть в пределах `0..=32`.
  - **Описание**: Дополнительные резервные модули записи для групп DC только с одной конечной точкой.
  - **Пример**:

    ```toml
    [general]
    me_single_endpoint_shadow_writers = 2
    ```
## "cfg-general-me_single_endpoint_outage_mode_enabled"
- `me_single_endpoint_outage_mode_enabled`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает агрессивный режим восстановления после сбоя для групп DC только с одной конечной точкой.
  - **Пример**:

    ```toml
    [general]
    me_single_endpoint_outage_mode_enabled = true
    ```
## "cfg-general-me_single_endpoint_outage_disable_quarantine"
- `me_single_endpoint_outage_disable_quarantine`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Игнорирует карантин конечной точки в режиме отключения одной конечной точки.
  - **Пример**:

    ```toml
    [general]
    me_single_endpoint_outage_disable_quarantine = true
    ```
## "cfg-general-me_single_endpoint_outage_backoff_min_ms"
- `me_single_endpoint_outage_backoff_min_ms`
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунды) и `<= me_single_endpoint_outage_backoff_max_ms`.
  - **Описание**: Минимальная задержка повторного подключения в режиме отключения одной конечной точки.
  - **Пример**:

    ```toml
    [general]
    me_single_endpoint_outage_backoff_min_ms = 250
    ```
## "cfg-general-me_single_endpoint_outage_backoff_max_ms"
- `me_single_endpoint_outage_backoff_max_ms`
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунды) и `>= me_single_endpoint_outage_backoff_min_ms`.
  - **Описание**: Максимальная задержка повторного подключения в режиме отключения одной конечной точки.
  - **Пример**:

    ```toml
    [general]
    me_single_endpoint_outage_backoff_max_ms = 3000
    ```
## "cfg-general-me_single_endpoint_shadow_rotate_every_secs"
- `me_single_endpoint_shadow_rotate_every_secs`
  - **Ограничения / валидация**: `u64` (секунды). `0` отключает периодическое вращение тени.
  - **Описание**: Периодический интервал ротации теневого записывающего устройства для групп DC с одной конечной точкой.
  - **Пример**:

    ```toml
    [general]
    me_single_endpoint_shadow_rotate_every_secs = 900
    ```
## "cfg-general-me_floor_mode"
- `me_floor_mode`
  - **Ограничения / валидация**: «статический» или «адаптивный».
  - **Описание**: Режим политики пола для целей записи ME.
  - **Пример**:

    ```toml
    [general]
    me_floor_mode = "adaptive"
    ```
## "cfg-general-me_adaptive_floor_idle_secs"
- `me_adaptive_floor_idle_secs`
  - **Ограничения / валидация**: `u64` (секунды).
  - **Описание**: Время простоя перед адаптивным ограничением может уменьшить целевую задачу записи с одной конечной точкой.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_idle_secs = 90
    ```
## "cfg-general-me_adaptive_floor_min_writers_single_endpoint"
- `me_adaptive_floor_min_writers_single_endpoint`
  - **Ограничения / валидация**: Должно быть в пределах `1..=32`.
  - **Описание**: Минимальная цель записи для групп DC с одной конечной точкой в ​​адаптивном режиме пола.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_min_writers_single_endpoint = 1
    ```
## "cfg-general-me_adaptive_floor_min_writers_multi_endpoint"
- `me_adaptive_floor_min_writers_multi_endpoint`
  - **Ограничения / валидация**: Должно быть в пределах `1..=32`.
  - **Описание**: Минимальная цель записи для групп DC с несколькими конечными точками в адаптивном режиме пола.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_min_writers_multi_endpoint = 1
    ```
## "cfg-general-me_adaptive_floor_recover_grace_secs"
- `me_adaptive_floor_recover_grace_secs`
  - **Ограничения / валидация**: `u64` (секунды).
  - **Описание**: Льготный период для сохранения статического минимума после активности в адаптивном режиме.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_recover_grace_secs = 180
    ```
## "cfg-general-me_adaptive_floor_writers_per_core_total"
- `me_adaptive_floor_writers_per_core_total`
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Глобальный бюджет записи ME на логическое ядро ​​ЦП в адаптивном режиме.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_writers_per_core_total = 48
    ```
## "cfg-general-me_adaptive_floor_cpu_cores_override"
- `me_adaptive_floor_cpu_cores_override`
  - **Ограничения / валидация**: `u16`. `0` использует автоматическое обнаружение во время выполнения.
  - **Описание**: Переопределить количество логических ядер ЦП, используемое для адаптивных вычислений минимального уровня.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_cpu_cores_override = 0
    ```
## "cfg-general-me_adaptive_floor_max_extra_writers_single_per_core"
- `me_adaptive_floor_max_extra_writers_single_per_core`
  - **Ограничения / валидация**: `u16`.
  - **Описание**: Максимальное количество дополнительных устройств записи на ядро ​​выше базового требуемого уровня для групп DC с одной конечной точкой.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_max_extra_writers_single_per_core = 1
    ```
## "cfg-general-me_adaptive_floor_max_extra_writers_multi_per_core"
- `me_adaptive_floor_max_extra_writers_multi_per_core`
  - **Ограничения / валидация**: `u16`.
  - **Описание**: Максимальное количество дополнительных устройств записи на ядро ​​выше базового требуемого уровня для групп DC с несколькими конечными точками.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_max_extra_writers_multi_per_core = 2
    ```
## "cfg-general-me_adaptive_floor_max_active_writers_per_core"
- `me_adaptive_floor_max_active_writers_per_core`
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Жесткое ограничение для активных устройств записи ME на логическое ядро ​​ЦП.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_max_active_writers_per_core = 64
    ```
## "cfg-general-me_adaptive_floor_max_warm_writers_per_core"
- `me_adaptive_floor_max_warm_writers_per_core`
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Жесткое ограничение для теплых авторов ME на логическое ядро ​​ЦП.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_max_warm_writers_per_core = 64
    ```
## "cfg-general-me_adaptive_floor_max_active_writers_global"
- `me_adaptive_floor_max_active_writers_global`
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Жесткий глобальный лимит для активных авторов ME.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_max_active_writers_global = 256
    ```
## "cfg-general-me_adaptive_floor_max_warm_writers_global"
- `me_adaptive_floor_max_warm_writers_global`
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Жесткий глобальный лимит для теплых писателей ME.
  - **Пример**:

    ```toml
    [general]
    me_adaptive_floor_max_warm_writers_global = 256
    ```
## "cfg-general-upstream_connect_retry_attempts"
- `upstream_connect_retry_attempts`
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Попытки подключения для выбранного восходящего потока перед возвратом ошибки/резервного варианта.
  - **Пример**:

    ```toml
    [general]
    upstream_connect_retry_attempts = 2
    ```
## "cfg-general-upstream_connect_retry_backoff_ms"
- `upstream_connect_retry_backoff_ms`
  - **Ограничения / валидация**: `u64` (миллисекунды). `0` отключает задержку отсрочки (повторные попытки становятся немедленными).
  - **Описание**: Задержка в миллисекундах между попытками восходящего соединения.
  - **Пример**:

    ```toml
    [general]
    upstream_connect_retry_backoff_ms = 100
    ```
## "cfg-general-upstream_connect_budget_ms"
- `upstream_connect_budget_ms`
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунды).
  - **Описание**: Общий бюджет настенных часов в миллисекундах для одного запроса восходящего соединения при повторных попытках.
  - **Пример**:

    ```toml
    [general]
    upstream_connect_budget_ms = 3000
    ```
## "cfg-general-upstream_unhealthy_fail_threshold"
- `upstream_unhealthy_fail_threshold`
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Последовательные неудачные запросы до того, как восходящий поток будет помечен как неработоспособный.
  - **Пример**:

    ```toml
    [general]
    upstream_unhealthy_fail_threshold = 5
    ```
## "cfg-general-upstream_connect_failfast_hard_errors"
- `upstream_connect_failfast_hard_errors`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Если установлено значение true, дополнительные попытки пропускаются при серьезных непереходных ошибках восходящего соединения.
  - **Пример**:

    ```toml
    [general]
    upstream_connect_failfast_hard_errors = false
    ```
## "cfg-general-stun_iface_mismatch_ignore"
- `stun_iface_mismatch_ignore`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Флаг совместимости зарезервирован для использования в будущем. В настоящее время этот ключ анализируется, но не используется средой выполнения.
  - **Пример**:

    ```toml
    [general]
    stun_iface_mismatch_ignore = false
    ```
## "cfg-general-unknown_dc_log_path"
- `unknown_dc_log_path`
  - **Ограничения / валидация**: `Строка` (необязательно). Должен быть безопасный путь (никаких компонентов `..`, родительский каталог должен существовать); небезопасные пути отклоняются во время выполнения.
  - **Описание**: Путь к файлу журнала для неизвестных (нестандартных) запросов DC, когда `unknown_dc_file_log_enabled = true`. Опустите этот ключ, чтобы отключить ведение журнала файлов.
  - **Пример**:

    ```toml
    [general]
    unknown_dc_log_path = "unknown-dc.txt"
    ```
## "cfg-general-unknown_dc_file_log_enabled"
- `unknown_dc_file_log_enabled`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает ведение журнала файла неизвестного DC (записывает строки `dc_idx=<N>`). Требуется установить `unknown_dc_log_path` и на платформах, отличных от Unix, может не поддерживаться. Ведение журналов дедуплицировано и ограничено (записываются только первые ~ 1024 различных неизвестных индекса DC).
  - **Пример**:

    ```toml
    [general]
    unknown_dc_file_log_enabled = false
    ```
## "cfg-general-log_level"
- `log_level`
  - **Ограничения / валидация**: «отладка», «многословный», «нормальный» или «тихий».
  - **Описание**: Уровень детализации журналирования во время выполнения (используется, если RUST_LOG не установлен). Если в среде установлен RUST_LOG, он имеет приоритет над этим параметром.
  - **Пример**:

    ```toml
    [general]
    log_level = "normal"
    ```
## "cfg-general-disable_colors"
- `disable_colors`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Отключает цвета ANSI в журналах (полезно для файлов/systemd). Это влияет только на форматирование журнала и не меняет уровень/фильтрацию журнала.
  - **Пример**:

    ```toml
    [general]
    disable_colors = false
    ```
## "cfg-general-me_socks_kdf_policy"
- `me_socks_kdf_policy`
  - **Ограничения / валидация**: «строгий» или «совместимый».
  - **Описание**: Резервная политика KDF, связанная с SOCKS, для рукопожатия среднего уровня.
  - **Пример**:

    ```toml
    [general]
    me_socks_kdf_policy = "strict"
    ```
## "cfg-general-me_route_backpressure_base_timeout_ms"
- `me_route_backpressure_base_timeout_ms`
  - **Ограничения / валидация**: Должно быть в пределах `1..=5000` (миллисекунд).
  - **Описание**: Тайм-аут базового противодавления в миллисекундах для отправки по каналу маршрута ME.
  - **Пример**:

    ```toml
    [general]
    me_route_backpressure_base_timeout_ms = 25
    ```
## "cfg-general-me_route_backpressure_high_timeout_ms"
- `me_route_backpressure_high_timeout_ms`
  - **Ограничения / валидация**: Должно быть в пределах `1..=5000` (миллисекунды) и `>= me_route_backpressure_base_timeout_ms`.
  - **Описание**: Тайм-аут высокого противодавления в миллисекундах, когда занятость очереди превышает водяной знак.
  - **Пример**:

    ```toml
    [general]
    me_route_backpressure_high_timeout_ms = 120
    ```
## "cfg-general-me_route_backpressure_high_watermark_pct"
- `me_route_backpressure_high_watermark_pct`
  - **Ограничения / валидация**: Должно быть в пределах `1..=100` (процентов).
  - **Описание**: Пороговое значение процента занятости очереди для переключения на тайм-аут высокого противодавления.
  - **Пример**:

    ```toml
    [general]
    me_route_backpressure_high_watermark_pct = 80
    ```
## "cfg-general-me_health_interval_ms_unhealthy"
- `me_health_interval_ms_unhealthy`
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунды).
  - **Описание**: Интервал мониторинга работоспособности, когда покрытие записи ME ухудшается.
  - **Пример**:

    ```toml
    [general]
    me_health_interval_ms_unhealthy = 1000
    ```
## "cfg-general-me_health_interval_ms_healthy"
- `me_health_interval_ms_healthy`
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунды).
  - **Описание**: Интервал мониторинга работоспособности, пока покрытие записи ME стабильно/работоспособно.
  - **Пример**:

    ```toml
    [general]
    me_health_interval_ms_healthy = 3000
    ```
## "cfg-general-me_admission_poll_ms"
- `me_admission_poll_ms`
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунды).
  - **Описание**: Интервал опроса для проверок состояния условного приема.
  - **Пример**:

    ```toml
    [general]
    me_admission_poll_ms = 1000
    ```
## "cfg-general-me_warn_rate_limit_ms"
- `me_warn_rate_limit_ms`
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунды).
  - **Описание**: Время восстановления повторяющихся журналов предупреждений ME.
  - **Пример**:

    ```toml
    [general]
    me_warn_rate_limit_ms = 5000
    ```
## "cfg-general-me_route_no_writer_mode"
- `me_route_no_writer_mode`
  - **Ограничения / валидация**: `"async_recovery_failfast"`, `"inline_recovery_legacy"` или `"hybrid_async_persistent"`.
  - **Описание**: Поведение маршрута ME, когда ни один писатель не доступен немедленно.
  - **Пример**:

    ```toml
    [general]
    me_route_no_writer_mode = "hybrid_async_persistent"
    ```
## "cfg-general-me_route_no_writer_wait_ms"
- `me_route_no_writer_wait_ms`
  - **Ограничения / валидация**: Должно быть в пределах `10..=5000` (миллисекунд).
  - **Описание**: Максимальное время ожидания, используемое в быстром режиме асинхронного восстановления перед откатом.
  - **Пример**:

    ```toml
    [general]
    me_route_no_writer_wait_ms = 250
    ```
## "cfg-general-me_route_hybrid_max_wait_ms"
- `me_route_hybrid_max_wait_ms`
  - **Ограничения / валидация**: Должно быть в пределах `50..=60000` (миллисекунд).
  - **Описание**: Максимальное совокупное время ожидания в гибридном режиме без записи перед отказоустойчивым переходом.
  - **Пример**:

    ```toml
    [general]
    me_route_hybrid_max_wait_ms = 3000
    ```
## "cfg-general-me_route_blocking_send_timeout_ms"
- `me_route_blocking_send_timeout_ms`
  - **Ограничения / валидация**: Должно быть в пределах `0..=5000` (миллисекунд). `0` сохраняет устаревшее неограниченное поведение ожидания.
  - **Описание**: Максимальное ожидание блокировки резервной отправки маршрутного канала.
  - **Пример**:

    ```toml
    [general]
    me_route_blocking_send_timeout_ms = 250
    ```
## "cfg-general-me_route_inline_recovery_attempts"
- `me_route_inline_recovery_attempts`
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Количество попыток оперативного восстановления в устаревшем режиме.
  - **Пример**:

    ```toml
    [general]
    me_route_inline_recovery_attempts = 3
    ```
## "cfg-general-me_route_inline_recovery_wait_ms"
- `me_route_inline_recovery_wait_ms`
  - **Ограничения / валидация**: Должно быть в пределах `10..=30000` (миллисекунд).
  - **Описание**: Максимальное время ожидания встроенного восстановления в устаревшем режиме.
  - **Пример**:

    ```toml
    [general]
    me_route_inline_recovery_wait_ms = 3000
    ```
## "cfg-general-fast_mode_min_tls_record"
- `fast_mode_min_tls_record`
  - **Ограничения / валидация**: `использовать` (байты). `0` отключает ограничение.
  - **Описание**: Минимальный размер записи TLS при включенном объединении в быстром режиме.
  - **Пример**:

    ```toml
    [general]
    fast_mode_min_tls_record = 0
    ```
## "cfg-general-update_every"
- `update_every`
  - **Ограничения / валидация**: `u64` (секунды). Если установлено, должно быть `> 0`. Если этот ключ не установлен явно, можно использовать устаревшие `proxy_secret_auto_reload_secs` и `proxy_config_auto_reload_secs` (их эффективный минимум должен быть `> 0`).
  - **Описание**: Единый интервал обновления для задач обновления ME (getProxyConfig, getProxyConfigV6, getProxySecret). Если этот параметр установлен, он переопределяет устаревшие интервалы перезагрузки прокси-сервера.
  - **Пример**:

    ```toml
    [general]
    update_every = 300
    ```
## "cfg-general-me_reinit_every_secs"
- `me_reinit_every_secs`
  - **Ограничения / валидация**: Должно быть `> 0` (секунды).
  - **Описание**: Периодический интервал для цикла повторной инициализации ME с нулевым временем простоя.
  - **Пример**:

    ```toml
    [general]
    me_reinit_every_secs = 900
    ```
## "cfg-general-me_hardswap_warmup_delay_min_ms"
- `me_hardswap_warmup_delay_min_ms`
  - **Ограничения / валидация**: `u64` (миллисекунды). Должно быть `<= me_hardswap_warmup_delay_max_ms`.
  - **Описание**: Нижняя граница интервала прогрева жесткой замены.
  - **Пример**:

    ```toml
    [general]
    me_hardswap_warmup_delay_min_ms = 1000
    ```
## "cfg-general-me_hardswap_warmup_delay_max_ms"
- `me_hardswap_warmup_delay_max_ms`
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунды).
  - **Описание**: Верхняя граница интервала прогрева жесткой замены.
  - **Пример**:

    ```toml
    [general]
    me_hardswap_warmup_delay_max_ms = 2000
    ```
## "cfg-general-me_hardswap_warmup_extra_passes"
- `me_hardswap_warmup_extra_passes`
  - **Ограничения / валидация**: Должно быть в пределах `[0, 10]`.
  - **Описание**: Дополнительные прогрева проходят после базового прохода за один цикл жесткой замены.
  - **Пример**:

    ```toml
    [general]
    # default: 3 (allowed range: 0..=10)
    me_hardswap_warmup_extra_passes = 3
    ```
## "cfg-general-me_hardswap_warmup_pass_backoff_base_ms"
- `me_hardswap_warmup_pass_backoff_base_ms`
  - **Ограничения / валидация**: `u64` (миллисекунды). Должно быть `> 0`.
  - **Описание**: Базовая задержка между дополнительными проходами по замене жесткого диска, когда пол еще не завершен.
  - **Пример**:

    ```toml
    [general]
    # default: 500
    me_hardswap_warmup_pass_backoff_base_ms = 500
    ```
## "cfg-general-me_config_stable_snapshots"
- `me_config_stable_snapshots`
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Количество идентичных снимков конфигурации ME, необходимое для применения.
  - **Пример**:

    ```toml
    [general]
    # require 3 identical snapshots before applying ME endpoint map updates
    me_config_stable_snapshots = 3
    ```
## "cfg-general-me_config_apply_cooldown_secs"
- `me_config_apply_cooldown_secs`
  - **Ограничения / валидация**: `u64`.
  - **Описание**: Время восстановления между примененными обновлениями карты конечных точек ME. `0` отключает время восстановления.
  - **Пример**:

    ```toml
    [general]
    # allow applying stable snapshots immediately (no cooldown)
    me_config_apply_cooldown_secs = 0
    ```
## "cfg-general-me_snapshot_require_http_2xx"
- `me_snapshot_require_http_2xx`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Для применения снимков конфигурации ME требуется 2xx HTTP-ответа. Если установлено значение «false», ответы, отличные от 2xx, все равно могут быть проанализированы/учтены программой обновления.
  - **Пример**:

    ```toml
    [general]
    # allow applying snapshots even when the HTTP status is non-2xx
    me_snapshot_require_http_2xx = false
    ```
## "cfg-general-me_snapshot_reject_empty_map"
- `me_snapshot_reject_empty_map`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Отклоняет пустые снимки конфигурации ME (без конечных точек). Если установлено значение «false», может быть применен пустой снимок (с учетом других ворот), что может временно уменьшить/очистить карту ME.
  - **Пример**:

    ```toml
    [general]
    # allow applying empty snapshots (use with care)
    me_snapshot_reject_empty_map = false
    ```
## "cfg-general-me_snapshot_min_proxy_for_lines"
- `me_snapshot_min_proxy_for_lines`
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Минимальное количество проанализированных строк `proxy_for`, необходимое для принятия снимка.
  - **Пример**:

    ```toml
    [general]
    # require at least 10 proxy_for rows before accepting a snapshot
    me_snapshot_min_proxy_for_lines = 10
    ```
## "cfg-general-proxy_secret_stable_snapshots"
- `proxy_secret_stable_snapshots`
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Количество идентичных снимков с секретом прокси-сервера, необходимых перед ротацией.
  - **Пример**:

    ```toml
    [general]
    # require 2 identical getProxySecret snapshots before rotating at runtime
    proxy_secret_stable_snapshots = 2
    ```
## "cfg-general-proxy_secret_rotate_runtime"
- `proxy_secret_rotate_runtime`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает ротацию секретов прокси-сервера во время выполнения из снимков средства обновления.
  - **Пример**:

    ```toml
    [general]
    # disable runtime proxy-secret rotation (startup still uses proxy_secret_path/proxy_secret_len_max)
    proxy_secret_rotate_runtime = false
    ```
## "cfg-general-me_secret_atomic_snapshot"
- `me_secret_atomic_snapshot`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Сохраняет селекторные и секретные байты из одного и того же снимка атомарно. Если `general.use_middle_proxy = true`, это автоматически включается во время загрузки конфигурации, чтобы обеспечить согласованность материала ME KDF.
  - **Пример**:

    ```toml
    [general]
    # NOTE: when use_middle_proxy=true, Telemt will auto-enable this during load
    me_secret_atomic_snapshot = false
    ```
## "cfg-general-proxy_secret_len_max"
- `proxy_secret_len_max`
  - **Ограничения / валидация**: Должно быть в пределах `[32, 4096]`.
  - **Описание**: Верхний предел длины (в байтах) принимаемого прокси-секрета во время запуска и обновления среды выполнения.
  - **Пример**:

    ```toml
    [general]
    # default: 256 (bytes)
    proxy_secret_len_max = 256
    ```
## "cfg-general-me_pool_drain_ttl_secs"
- `me_pool_drain_ttl_secs`
  - **Ограничения / валидация**: `u64` (секунды). `0` отключает окно дренажного TTL (и подавляет предупреждения дренажного TTL для непустых записывающих устройств дренажа).
  - **Описание**: Временной интервал Drain-TTL для устаревших модулей записи ME после изменения карты конечных точек. Во время TTL устаревшие средства записи можно использовать только в качестве резерва для новых привязок (в зависимости от политики привязки).
  - **Пример**:

    ```toml
    [general]
    # disable drain TTL (draining writers won't emit "past drain TTL" warnings)
    me_pool_drain_ttl_secs = 0
    ```
## "cfg-general-me_instadrain"
- `me_instadrain`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Принудительно удаляет устаревшие записи записи при следующем такте очистки, минуя ожидание TTL/крайнего срока.
  - **Пример**:

    ```toml
    [general]
    # default: false
    me_instadrain = false
    ```
## "cfg-general-me_pool_drain_threshold"
- `me_pool_drain_threshold`
  - **Ограничения / валидация**: `u64`. Установите значение «0», чтобы отключить очистку на основе пороговых значений.
  - **Описание**: Максимальное количество устаревших источников записи, прежде чем самые старые из них будут принудительно закрыты в пакетном режиме.
  - **Пример**:

    ```toml
    [general]
    # default: 32
    me_pool_drain_threshold = 32
    ```
## "cfg-general-me_pool_drain_soft_evict_enabled"
- `me_pool_drain_soft_evict_enabled`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает постепенное мягкое удаление устаревших средств записи во время очистки/повторной инициализации вместо немедленного жесткого закрытия.
  - **Пример**:

    ```toml
    [general]
    # default: true
    me_pool_drain_soft_evict_enabled = true
    ```
## "cfg-general-me_pool_drain_soft_evict_grace_secs"
- `me_pool_drain_soft_evict_grace_secs`
  - **Ограничения / валидация**: `u64` (секунды). Должно быть в пределах `[0, 3600]`.
  - **Описание**: Дополнительная льгота (после слива TTL) перед началом этапа мягкого вытеснения.
  - **Пример**:

    ```toml
    [general]
    # default: 10
    me_pool_drain_soft_evict_grace_secs = 10
    ```
## "cfg-general-me_pool_drain_soft_evict_per_writer"
- `me_pool_drain_soft_evict_per_writer`
  - **Ограничения / валидация**: `1..=16`.
  - **Описание**: Максимальное количество устаревших маршрутов, мягко вытесняемых на одного автора за один проход выселения.
  - **Пример**:

    ```toml
    [general]
    # default: 2
    me_pool_drain_soft_evict_per_writer = 2
    ```
## "cfg-general-me_pool_drain_soft_evict_budget_per_core"
- `me_pool_drain_soft_evict_budget_per_core`
  - **Ограничения / валидация**: `1..=64`.
  - **Описание**: Бюджет на ядро ​​ограничивает совокупную работу по мягкому вытеснению за проход.
  - **Пример**:

    ```toml
    [general]
    # default: 16
    me_pool_drain_soft_evict_budget_per_core = 16
    ```
## "cfg-general-me_pool_drain_soft_evict_cooldown_ms"
- `me_pool_drain_soft_evict_cooldown_ms`
  - **Ограничения / валидация**: `u64` (миллисекунды). Должно быть `> 0`.
  - **Описание**: Время восстановления между повторяющимися мягкими выселениями одного и того же автора.
  - **Пример**:

    ```toml
    [general]
    # default: 1000
    me_pool_drain_soft_evict_cooldown_ms = 1000
    ```
## "cfg-general-me_bind_stale_mode"
- `me_bind_stale_mode`
  - **Ограничения / валидация**: «никогда», «ttl» или «всегда».
  - **Описание**: Политика в отношении новых ограничений для устаревших истощающих авторов.
  - **Пример**:

    ```toml
    [general]
    # allow stale binds only for a limited time window
    me_bind_stale_mode = "ttl"
    ```
## "cfg-general-me_bind_stale_ttl_secs"
- `me_bind_stale_ttl_secs`
  - **Ограничения / валидация**: `u64`.
  - **Описание**: TTL для допуска устаревшей привязки, когда устаревший режим — «ttl».
  - **Пример**:

    ```toml
    [general]
    me_bind_stale_mode = "ttl"
    me_bind_stale_ttl_secs = 90
    ```
## "cfg-general-me_pool_min_fresh_ratio"
- `me_pool_min_fresh_ratio`
  - **Ограничения / валидация**: Должно быть в пределах `[0.0, 1.0]`.
  - **Описание**: Минимальный коэффициент покрытия свежих желаемых DC, прежде чем устаревшие авторы будут истощены.
  - **Пример**:

    ```toml
    [general]
    # require >=90% desired-DC coverage before draining stale writers
    me_pool_min_fresh_ratio = 0.9
    ```
## "cfg-general-me_reinit_drain_timeout_secs"
- `me_reinit_drain_timeout_secs`
  - **Ограничения / валидация**: `u64`. `0` использует тайм-аут принудительного закрытия для обеспечения безопасности во время выполнения. Если `> 0` и `< me_pool_drain_ttl_secs`, среда выполнения увеличивает значение TTL.
  - **Описание**: Тайм-аут принудительного закрытия для слива устаревших авторов. Если установлено значение «0», эффективный тайм-аут представляет собой резервный режим безопасности во время выполнения (300 секунд).
  - **Пример**:

    ```toml
    [general]
    # use runtime safety fallback force-close timeout (300s)
    me_reinit_drain_timeout_secs = 0
    ```
## "cfg-general-proxy_secret_auto_reload_secs"
- `proxy_secret_auto_reload_secs`
  - **Ограничения / валидация**: Устарело. Используйте `general.update_every`. Если `general.update_every` не задан явно, эффективный устаревший интервал обновления равен `min(proxy_secret_auto_reload_secs, proxy_config_auto_reload_secs)` и должен быть `> 0`.
  - **Описание**: Устаревший устаревший интервал обновления секрета прокси-сервера. Используется только в том случае, если `general.update_every` не установлен.
  - **Пример**:

    ```toml
    [general]
    # legacy mode: omit update_every to use proxy_*_auto_reload_secs
    proxy_secret_auto_reload_secs = 600
    proxy_config_auto_reload_secs = 120
    # effective updater interval = min(600, 120) = 120 seconds
    ```
## "cfg-general-proxy_config_auto_reload_secs"
- `proxy_config_auto_reload_secs`
  - **Ограничения / валидация**: Устарело. Используйте `general.update_every`. Если `general.update_every` не задан явно, эффективный устаревший интервал обновления равен `min(proxy_secret_auto_reload_secs, proxy_config_auto_reload_secs)` и должен быть `> 0`.
  - **Описание**: Устаревший интервал обновления устаревшей конфигурации ME. Используется только в том случае, если `general.update_every` не установлен.
  - **Пример**:

    ```toml
    [general]
    # legacy mode: omit update_every to use proxy_*_auto_reload_secs
    proxy_secret_auto_reload_secs = 600
    proxy_config_auto_reload_secs = 120
    # effective updater interval = min(600, 120) = 120 seconds
    ```
## "cfg-general-me_reinit_singleflight"
- `me_reinit_singleflight`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Сериализует циклы повторной инициализации ME по источникам триггера.
  - **Пример**:

    ```toml
    [general]
    me_reinit_singleflight = true
    ```
## "cfg-general-me_reinit_trigger_channel"
- `me_reinit_trigger_channel`
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Емкость очереди триггеров для планировщика повторной инициализации.
  - **Пример**:

    ```toml
    [general]
    me_reinit_trigger_channel = 64
    ```
## "cfg-general-me_reinit_coalesce_window_ms"
- `me_reinit_coalesce_window_ms`
  - **Ограничения / валидация**: `u64`.
  - **Описание**: Запустить окно объединения триггеров перед началом повторной инициализации (мс).
  - **Пример**:

    ```toml
    [general]
    me_reinit_coalesce_window_ms = 200
    ```
## "cfg-general-me_deterministic_writer_sort"
- `me_deterministic_writer_sort`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает детерминированную сортировку кандидатов для пути привязки записи.
  - **Пример**:

    ```toml
    [general]
    me_deterministic_writer_sort = true
    ```
## "cfg-general-me_writer_pick_mode"
- `me_writer_pick_mode`
  - **Ограничения / валидация**: `"sorted_rr"` или `"p2c"`.
  - **Описание**: Режим выбора записывающего устройства для пути привязки маршрута.
  - **Пример**:

    ```toml
    [general]
    me_writer_pick_mode = "p2c"
    ```
## "cfg-general-me_writer_pick_sample_size"
- `me_writer_pick_sample_size`
  - **Ограничения / валидация**: `2..=4`.
  - **Описание**: Количество кандидатов, отобранных сборщиком в режиме p2c.
  - **Пример**:

    ```toml
    [general]
    me_writer_pick_mode = "p2c"
    me_writer_pick_sample_size = 3
    ```
## "cfg-general-ntp_check"
- `ntp_check`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Зарезервировано для будущего использования. В настоящее время этот ключ анализируется, но не используется средой выполнения.
  - **Пример**:

    ```toml
    [general]
    ntp_check = true
    ```
## "cfg-general-ntp_servers"
- `ntp_servers`
  - **Ограничения / валидация**: `Строка[]`.
  - **Описание**: Зарезервировано для будущего использования. В настоящее время этот ключ анализируется, но не используется средой выполнения.
  - **Пример**:

    ```toml
    [general]
    ntp_servers = ["pool.ntp.org"]
    ```
## "cfg-general-auto_degradation_enabled"
- `auto_degradation_enabled`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Зарезервировано для будущего использования. В настоящее время этот ключ анализируется, но не используется средой выполнения.
  - **Пример**:

    ```toml
    [general]
    auto_degradation_enabled = true
    ```
## "cfg-general-degradation_min_unavailable_dc_groups"
- `degradation_min_unavailable_dc_groups`
  - **Ограничения / валидация**: `u8`.
  - **Описание**: Зарезервировано для будущего использования. В настоящее время этот ключ анализируется, но не используется средой выполнения.
  - **Пример**:

    ```toml
    [general]
    degradation_min_unavailable_dc_groups = 2
    ```
## "cfg-general-rst_on_close"
- `rst_on_close`
  - **Ограничения / валидация**: одно из `"off"`, `"errors"`, `"always"`.
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
| [`classic`](#cfg-general-modes-classic) | `bool` | `false` |
| [`secure`](#cfg-general-modes-secure) | `bool` | `false` |
| [`tls`](#cfg-general-modes-tls) | `bool` | `true` |

## "cfg-general-modes-classic"
- `classic`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает классический режим MTProxy.
  - **Пример**:

    ```toml
    [general.modes]
    classic = true
    ```
## "cfg-general-modes-secure"
- `secure`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает безопасный режим.
  - **Пример**:

    ```toml
    [general.modes]
    secure = true
    ```
## "cfg-general-modes-tls"
- `tls`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает режим TLS.
  - **Пример**:

    ```toml
    [general.modes]
    tls = true
    ```


# [general.links]


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`show`](#cfg-general-links-show) | `"*"` or `String[]` | `"*"` |
| [`public_host`](#cfg-general-links-public_host) | `String` | — |
| [`public_port`](#cfg-general-links-public_port) | `u16` | — |

## "cfg-general-links-show"
- `show`
  - **Ограничения / валидация**: `"*"` или `String[]`. Пустой массив означает «не показывать ничего».
  - **Описание**: Выбирает пользователей, чьи прокси-ссылки `tg://` отображаются при запуске.
  - **Пример**:

    ```toml
    [general.links]
    show = "*"
    # or:
    # show = ["alice", "bob"]
    ```
## "cfg-general-links-public_host"
- `public_host`
  - **Ограничения / валидация**: `Строка` (необязательно).
  - **Описание**: Переопределение общедоступного имени хоста/IP-адреса, используемое для сгенерированных ссылок `tg://` (переопределяет обнаруженный IP-адрес).
  - **Пример**:

    ```toml
    [general.links]
    public_host = "proxy.example.com"
    ```
## "cfg-general-links-public_port"
- `public_port`
  - **Ограничения / валидация**: `u16` (необязательно).
  - **Описание**: Переопределение общедоступного порта, используемое для сгенерированных ссылок `tg://` (переопределяет `server.port`).
  - **Пример**:

    ```toml
    [general.links]
    public_port = 443
    ```


# [general.telemetry]


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`core_enabled`](#cfg-general-telemetry-core_enabled) | `bool` | `true` |
| [`user_enabled`](#cfg-general-telemetry-user_enabled) | `bool` | `true` |
| [`me_level`](#cfg-general-telemetry-me_level) | `"silent"`, `"normal"`, or `"debug"` | `"normal"` |

## "cfg-general-telemetry-core_enabled"
- `core_enabled`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает основные счетчики телеметрии горячего пути.
  - **Пример**:

    ```toml
    [general.telemetry]
    core_enabled = true
    ```
## "cfg-general-telemetry-user_enabled"
- `user_enabled`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает счетчики телеметрии для каждого пользователя.
  - **Пример**:

    ```toml
    [general.telemetry]
    user_enabled = true
    ```
## "cfg-general-telemetry-me_level"
- `me_level`
  - **Ограничения / валидация**: «тихий», «нормальный» или «отладка».
  - **Описание**: Средний уровень детализации телеметрии.
  - **Пример**:

    ```toml
    [general.telemetry]
    me_level = "normal"
    ```


# [network]


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`ipv4`](#cfg-network-ipv4) | `bool` | `true` |
| [`ipv6`](#cfg-network-ipv6) | `bool` | `false` |
| [`prefer`](#cfg-network-prefer) | `u8` | `4` |
| [`multipath`](#cfg-network-multipath) | `bool` | `false` |
| [`stun_use`](#cfg-network-stun_use) | `bool` | `true` |
| [`stun_servers`](#cfg-network-stun_servers) | `String[]` | Built-in STUN list (13 hosts) |
| [`stun_tcp_fallback`](#cfg-network-stun_tcp_fallback) | `bool` | `true` |
| [`http_ip_detect_urls`](#cfg-network-http_ip_detect_urls) | `String[]` | `["https://ifconfig.me/ip", "https://api.ipify.org"]` |
| [`cache_public_ip_path`](#cfg-network-cache_public_ip_path) | `String` | `"cache/public_ip.txt"` |
| [`dns_overrides`](#cfg-network-dns_overrides) | `String[]` | `[]` |

## "cfg-network-ipv4"
- `ipv4`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает сеть IPv4.
  - **Пример**:

    ```toml
    [network]
    ipv4 = true
    ```
## "cfg-network-ipv6"
- `ipv6`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает/выключает сеть IPv6. Если этот параметр опущен, по умолчанию используется значение «false».
  - **Пример**:

    ```toml
    [network]
    # enable IPv6 explicitly
    ipv6 = true

    # or: disable IPv6 explicitly
    # ipv6 = false
    ```
## "cfg-network-prefer"
- `prefer`
  - **Ограничения / валидация**: Должно быть `4` или `6`. Если `prefer = 4`, а `ipv4 = false`, Telemt принудительно использует `prefer = 6`. Если `prefer = 6`, а `ipv6 = false`, Telemt принудительно использует `prefer = 4`.
  - **Описание**: Предпочтительное семейство IP для выбора, если доступны оба семейства.
  - **Пример**:

    ```toml
    [network]
    prefer = 6
    ```
## "cfg-network-multipath"
- `multipath`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает многопутевое поведение, если это поддерживается платформой и средой выполнения.
  - **Пример**:

    ```toml
    [network]
    multipath = true
    ```
## "cfg-network-stun_use"
- `stun_use`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Глобальный переключатель STUN; если установлено значение «false», проверка STUN отключается и остается только обнаружение без STUN.
  - **Пример**:

    ```toml
    [network]
    stun_use = false
    ```
## "cfg-network-stun_servers"
- `stun_servers`
  - **Ограничения / валидация**: `Строка[]`. Значения обрезаются; пустые значения удаляются; список дедуплицируется. Если этот ключ **не** установлен явно, Telemt сохраняет встроенный список STUN по умолчанию.
  - **Описание**: Список серверов STUN для обнаружения общедоступных IP-адресов.
  - **Пример**:

    ```toml
    [network]
    stun_servers = [
      "stun.l.google.com:19302",
      "stun.stunprotocol.org:3478",
    ]
    ```
## "cfg-network-stun_tcp_fallback"
- `stun_tcp_fallback`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает резервный TCP для STUN, когда путь UDP заблокирован/недоступен.
  - **Пример**:

    ```toml
    [network]
    stun_tcp_fallback = true
    ```
## "cfg-network-http_ip_detect_urls"
- `http_ip_detect_urls`
  - **Ограничения / валидация**: `Строка[]`.
  - **Описание**: Конечные точки HTTP, используемые для обнаружения общедоступных IP-адресов (резервный вариант после STUN).
  - **Пример**:

    ```toml
    [network]
    http_ip_detect_urls = ["https://ifconfig.me/ip", "https://api.ipify.org"]
    ```
## "cfg-network-cache_public_ip_path"
- `cache_public_ip_path`
  - **Ограничения / валидация**: `Строка`.
  - **Описание**: Путь к файлу, используемый для кэширования обнаруженного общедоступного IP-адреса.
  - **Пример**:

    ```toml
    [network]
    cache_public_ip_path = "cache/public_ip.txt"
    ```
## "cfg-network-dns_overrides"
- `dns_overrides`
  - **Ограничения / валидация**: `Строка[]`. Каждая запись должна использовать формат «хост:порт:ip».
- `host`: имя домена (должно быть непустым и не должно содержать `:`)
- `порт`: `u16`
- `ip`: IPv4 (`1.2.3.4`) или IPv6 в квадратных скобках (`[2001:db8::1]`). **IPv6 без скобок отклонен**.
  - **Описание**: Переопределения DNS во время выполнения для целей `host:port`. Полезно для принудительного использования определенных IP-адресов для определенных вышестоящих доменов, не затрагивая системный DNS.
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
| [`port`](#cfg-server-port) | `u16` | `443` |
| [`listen_addr_ipv4`](#cfg-server-listen_addr_ipv4) | `String` | `"0.0.0.0"` |
| [`listen_addr_ipv6`](#cfg-server-listen_addr_ipv6) | `String` | `"::"` |
| [`listen_unix_sock`](#cfg-server-listen_unix_sock) | `String` | — |
| [`listen_unix_sock_perm`](#cfg-server-listen_unix_sock_perm) | `String` | — |
| [`listen_tcp`](#cfg-server-listen_tcp) | `bool` | — (auto) |
| [`proxy_protocol`](#cfg-server-proxy_protocol) | `bool` | `false` |
| [`proxy_protocol_header_timeout_ms`](#cfg-server-proxy_protocol_header_timeout_ms) | `u64` | `500` |
| [`proxy_protocol_trusted_cidrs`](#cfg-server-proxy_protocol_trusted_cidrs) | `IpNetwork[]` | `[]` |
| [`metrics_port`](#cfg-server-metrics_port) | `u16` | — |
| [`metrics_listen`](#cfg-server-metrics_listen) | `String` | — |
| [`metrics_whitelist`](#cfg-server-metrics_whitelist) | `IpNetwork[]` | `["127.0.0.1/32", "::1/128"]` |
| [`max_connections`](#cfg-server-max_connections) | `u32` | `10000` |
| [`accept_permit_timeout_ms`](#cfg-server-accept_permit_timeout_ms) | `u64` | `250` |

## "cfg-server-port"
- `port`
  - **Ограничения / валидация**: `u16`.
  - **Описание**: Порт прослушивания основного прокси (TCP).
  - **Пример**:

    ```toml
    [server]
    port = 443
    ```
## "cfg-server-listen_addr_ipv4"
- `listen_addr_ipv4`
  - **Ограничения / валидация**: `Строка` (необязательно). Если установлено, это должна быть действительная строка адреса IPv4.
  - **Описание**: Адрес привязки IPv4 для прослушивателя TCP (опустите этот ключ, чтобы отключить привязку IPv4).
  - **Пример**:

    ```toml
    [server]
    listen_addr_ipv4 = "0.0.0.0"
    ```
## "cfg-server-listen_addr_ipv6"
- `listen_addr_ipv6`
  - **Ограничения / валидация**: `Строка` (необязательно). Если установлено, это должна быть действительная строка адреса IPv6.
  - **Описание**: Адрес привязки IPv6 для прослушивателя TCP (опустите этот ключ, чтобы отключить привязку IPv6).
  - **Пример**:

    ```toml
    [server]
    listen_addr_ipv6 = "::"
    ```
## "cfg-server-listen_unix_sock"
- `listen_unix_sock`
  - **Ограничения / валидация**: `Строка` (необязательно). Не должно быть пустым, если установлено. Только Юникс.
  - **Описание**: Путь сокета Unix для прослушивателя. Если установлено, `server.listen_tcp` по умолчанию имеет значение `false` (если не указано иное явно).
  - **Пример**:

    ```toml
    [server]
    listen_unix_sock = "/run/telemt.sock"
    ```
## "cfg-server-listen_unix_sock_perm"
- `listen_unix_sock_perm`
  - **Ограничения / валидация**: `Строка` (необязательно). Если установлено, это должна быть восьмеричная строка разрешения, например `"0666"` или `"0777"`.
  - **Описание**: Дополнительные разрешения для файлов сокетов Unix, применяемые после привязки (chmod). Если этот параметр опущен, разрешения не изменяются (наследует umask).
  - **Пример**:

    ```toml
    [server]
    listen_unix_sock = "/run/telemt.sock"
    listen_unix_sock_perm = "0666"
    ```
## "cfg-server-listen_tcp"
- `listen_tcp`
  - **Ограничения / валидация**: `bool` (необязательно). Если этот параметр опущен, Telemt автоматически обнаруживает:
- `true`, если `listen_unix_sock` не установлен
- «false», если установлен «listen_unix_sock».
  - **Описание**: Явный прослушиватель TCP включает/отключает переопределение.
  - **Пример**:

    ```toml
    [server]
    # force-enable TCP even when also binding a unix socket
    listen_unix_sock = "/run/telemt.sock"
    listen_tcp = true
    ```
## "cfg-server-proxy_protocol"
- `proxy_protocol`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает анализ протокола HAProxy PROXY при входящих соединениях (PROXY v1/v2). Если этот параметр включен, исходный адрес клиента берется из заголовка PROXY.
  - **Пример**:

    ```toml
    [server]
    proxy_protocol = true
    ```
## "cfg-server-proxy_protocol_header_timeout_ms"
- `proxy_protocol_header_timeout_ms`
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунды).
  - **Описание**: Таймаут чтения и анализа заголовков протокола PROXY (мс).
  - **Пример**:

    ```toml
    [server]
    proxy_protocol = true
    proxy_protocol_header_timeout_ms = 500
    ```
## "cfg-server-proxy_protocol_trusted_cidrs"
- `proxy_protocol_trusted_cidrs`
  - **Ограничения / валидация**: `IpNetwork[]`.
- Если этот параметр опущен, по умолчанию используются доверительные все CIDR (`0.0.0.0/0` и `::/0`).
- Если явно задан пустой массив, все заголовки PROXY отклоняются.
  - **Описание**: CIDR доверенного источника позволяют предоставлять заголовки протокола PROXY (контроль безопасности).
  - **Пример**:

    ```toml
    [server]
    proxy_protocol = true
    proxy_protocol_trusted_cidrs = ["127.0.0.1/32", "10.0.0.0/8"]
    ```
## "cfg-server-metrics_port"
- `metrics_port`
  - **Ограничения / валидация**: `u16` (необязательно).
  - **Описание**: Порт конечной точки метрик, совместимый с Prometheus. Если установлено, включает прослушиватель метрик (поведение привязки можно переопределить с помощью `metrics_listen`).
  - **Пример**:

    ```toml
    [server]
    metrics_port = 9090
    ```
## "cfg-server-metrics_listen"
- `metrics_listen`
  - **Ограничения / валидация**: `Строка` (необязательно). Если установлено, оно должно быть в формате IP:PORT.
  - **Описание**: Полный адрес привязки метрик (`IP:PORT`) переопределяет `metrics_port` и привязывается только к указанному адресу.
  - **Пример**:

    ```toml
    [server]
    metrics_listen = "127.0.0.1:9090"
    ```
## "cfg-server-metrics_whitelist"
- `metrics_whitelist`
  - **Ограничения / валидация**: `IpNetwork[]`.
  - **Описание**: Белый список CIDR для доступа к конечной точке метрик.
  - **Пример**:

    ```toml
    [server]
    metrics_port = 9090
    metrics_whitelist = ["127.0.0.1/32", "::1/128"]
    ```
## "cfg-server-max_connections"
- `max_connections`
  - **Ограничения / валидация**: `u32`. `0` означает неограниченный.
  - **Описание**: Максимальное количество одновременных клиентских подключений.
  - **Пример**:

    ```toml
    [server]
    max_connections = 10000
    ```
## "cfg-server-accept_permit_timeout_ms"
- `accept_permit_timeout_ms`
  - **Ограничения / валидация**: `0..=60000` (миллисекунды). `0` сохраняет устаревшее неограниченное поведение ожидания.
  - **Описание**: Максимальное время ожидания получения разрешения на слот подключения, прежде чем принятое соединение будет разорвано.
  - **Пример**:

    ```toml
    [server]
    accept_permit_timeout_ms = 250
    ```


Примечание. Когда `server.proxy_protocol` включен, входящие заголовки протокола PROXY анализируются с первых байтов соединения, а исходный адрес клиента заменяется на `src_addr` из заголовка. В целях безопасности IP-адрес однорангового источника (адрес прямого соединения) проверяется по `server.proxy_protocol_trusted_cidrs`; если этот список пуст, заголовки PROXY отклоняются и соединение считается ненадежным.

# [server.conntrack_control]

Примечание. Рабочий процесс conntrack-control работает **только в Linux**. В других операционных системах не запускается; если inline_conntrack_control имеет значение true, записывается предупреждение. Для эффективной работы также требуется **CAP_NET_ADMIN** и пригодный к использованию бэкенд (nft или iptables/ip6tables в PATH). Утилита `conntrack` используется для удаления необязательных записей таблицы под давлением.


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`inline_conntrack_control`](#cfg-server-conntrack_control-inline_conntrack_control) | `bool` | `true` |
| [`mode`](#cfg-server-conntrack_control-mode) | `String` | `"tracked"` |
| [`backend`](#cfg-server-conntrack_control-backend) | `String` | `"auto"` |
| [`profile`](#cfg-server-conntrack_control-profile) | `String` | `"balanced"` |
| [`hybrid_listener_ips`](#cfg-server-conntrack_control-hybrid_listener_ips) | `IpAddr[]` | `[]` |
| [`pressure_high_watermark_pct`](#cfg-server-conntrack_control-pressure_high_watermark_pct) | `u8` | `85` |
| [`pressure_low_watermark_pct`](#cfg-server-conntrack_control-pressure_low_watermark_pct) | `u8` | `70` |
| [`delete_budget_per_sec`](#cfg-server-conntrack_control-delete_budget_per_sec) | `u64` | `4096` |

## "cfg-server-conntrack_control-inline_conntrack_control"
- `inline_conntrack_control`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Главный переключатель для задачи conntrack-control во время выполнения: согласовывает правила сетевого фильтра **raw/notrack** для входа прослушивателя (см. `mode`), образцы загружаются каждую секунду и может запускать **`conntrack -D`** удаления для квалификации событий закрытия, пока **pressure mode** активен (см. `delete_budget_per_sec`). Если установлено значение false, правила отслеживания очищаются, а принудительное удаление отключается.
  - **Пример**:

    ```toml
    [server.conntrack_control]
    inline_conntrack_control = true
    ```
## "cfg-server-conntrack_control-mode"
- `mode`
  - **Ограничения / валидация**: Один из вариантов: «отслеживаемый», «без отслеживания», «гибридный» (регистронезависимый; сериализованный нижний регистр).
  - **Описание**: **`tracked`**: не устанавливать правила telemt notrack (соединения остаются в состоянии conntrack). **`notrack`**: пометить совпадение входящего TCP с `server.port` как notrack — целевые объекты получаются из `[[server.listeners]]`, если таковые имеются, в противном случае из `server.listen_addr_ipv4` / `server.listen_addr_ipv6` (неуказанные адреса означают «любой» для этого семейства). **`hybrid`**: не отслеживать только адреса, перечисленные в `hybrid_listener_ips` (должно быть непустым; проверяется при загрузке).
  - **Пример**:

    ```toml
    [server.conntrack_control]
    mode = "notrack"
    ```
## "cfg-server-conntrack_control-backend"
- `backend`
  - **Ограничения / валидация**: Один из `auto`, `nftables`, `iptables` (без учета регистра; сериализованный нижний регистр).
  - **Описание**: Какой набор команд применяет правила отслеживания. **`auto`**: используйте `nft`, если он присутствует в `PATH`, иначе `iptables`/`ip6tables`, если он присутствует. **`nftables`** / **`iptables`**: принудительно использовать этот бэкэнд; отсутствие двоичного кода означает, что правила невозможно применить. Путь nft использует таблицу `inet telemt_conntrack` и необработанный перехват предварительной маршрутизации; iptables использует цепочку TELEMT_NOTRACK в таблице raw.
  - **Пример**:

    ```toml
    [server.conntrack_control]
    backend = "auto"
    ```
## "cfg-server-conntrack_control-profile"
- `profile`
  - **Ограничения / валидация**: Один из «консервативных», «сбалансированных», «агрессивных» (без учета регистра; сериализованный нижний регистр).
  - **Описание**: Когда **режим давления conntrack** активен (водяные знаки `pressure_*`), ограничиваются тайм-ауты простоя и активности, чтобы уменьшить отток коннтреков: например. **первый байт простоя клиента** (`client.rs`), **тайм-аут активности прямой ретрансляции** (`direct_relay.rs`) и **политика простоя среднего реле** (`middle_relay.rs` через `ConntrackPressureProfile::*_cap_secs` / `direct_activity_timeout_secs`). В более агрессивных профилях используются более короткие заглушки.
  - **Пример**:

    ```toml
    [server.conntrack_control]
    profile = "balanced"
    ```
## "cfg-server-conntrack_control-hybrid_listener_ips"
- `hybrid_listener_ips`
  - **Ограничения / валидация**: `IpAddr[]`. Должно быть **непустым**, когда `mode = "hybrid"`. Игнорируется для отслеживаемых/безотслеживаемых сообщений.
  - **Описание**: Явные адреса прослушивателя, которые получают правила nottrack в гибридном режиме (разделенные на правила IPv4 и IPv6 в зависимости от реализации).
  - **Пример**:

    ```toml
    [server.conntrack_control]
    mode = "hybrid"
    hybrid_listener_ips = ["203.0.113.10", "2001:db8::1"]
    ```
## "cfg-server-conntrack_control-pressure_high_watermark_pct"
- `pressure_high_watermark_pct`
  - **Ограничения / валидация**: Должно быть в пределах `[1, 100]`.
  - **Описание**: Режим давления **входит** при любом из следующих событий: заполнение соединения или `server.max_connections` (в процентах, если `max_connections > 0`), **использование файлового дескриптора** и программное обеспечение процесса `RLIMIT_NOFILE`, **ненулевое** событие `accept_permit_timeout` в последнем окне примера или дельта счетчика **ME c2me send-full**. Ввод сравнивает соответствующие проценты с этой верхней отметкой (см. update_pressure_state в conntrack_control.rs).
  - **Пример**:

    ```toml
    [server.conntrack_control]
    pressure_high_watermark_pct = 85
    ```
## "cfg-server-conntrack_control-pressure_low_watermark_pct"
- `pressure_low_watermark_pct`
  - **Ограничения / валидация**: Должно быть **строго меньше** `pressure_high_watermark_pct`.
  - **Описание**: Режим давления **сбрасывается** только после **трех** последовательных односекундных выборок, когда все сигналы находятся на уровне этой нижней границы или ниже, а дельты времени ожидания приема/ME-очереди равны нулю (гистерезис).
  - **Пример**:

    ```toml
    [server.conntrack_control]
    pressure_low_watermark_pct = 70
    ```
## "cfg-server-conntrack_control-delete_budget_per_sec"
- `delete_budget_per_sec`
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Максимальное количество попыток **`conntrack -D`** **в секунду** при активном режиме давления (корзина токенов пополняется каждую секунду). Удаление выполняется только для событий закрытия по причинам **тайм-аут**, **давление** или **сброс**; каждая попытка потребляет токен независимо от результата.
  - **Пример**:

    ```toml
    [server.conntrack_control]
    delete_budget_per_sec = 4096
    ```


# [server.api]

Примечание. В этом разделе также принимается устаревший псевдоним `[server.admin_api]` (та же схема, что и `[server.api]`).


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`enabled`](#cfg-server-api-enabled) | `bool` | `true` |
| [`listen`](#cfg-server-api-listen) | `String` | `"0.0.0.0:9091"` |
| [`whitelist`](#cfg-server-api-whitelist) | `IpNetwork[]` | `["127.0.0.0/8"]` |
| [`auth_header`](#cfg-server-api-auth_header) | `String` | `""` |
| [`request_body_limit_bytes`](#cfg-server-api-request_body_limit_bytes) | `usize` | `65536` |
| [`minimal_runtime_enabled`](#cfg-server-api-minimal_runtime_enabled) | `bool` | `true` |
| [`minimal_runtime_cache_ttl_ms`](#cfg-server-api-minimal_runtime_cache_ttl_ms) | `u64` | `1000` |
| [`runtime_edge_enabled`](#cfg-server-api-runtime_edge_enabled) | `bool` | `false` |
| [`runtime_edge_cache_ttl_ms`](#cfg-server-api-runtime_edge_cache_ttl_ms) | `u64` | `1000` |
| [`runtime_edge_top_n`](#cfg-server-api-runtime_edge_top_n) | `usize` | `10` |
| [`runtime_edge_events_capacity`](#cfg-server-api-runtime_edge_events_capacity) | `usize` | `256` |
| [`read_only`](#cfg-server-api-read_only) | `bool` | `false` |

## "cfg-server-api-enabled"
- `enabled`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает REST API плоскости управления.
  - **Пример**:

    ```toml
    [server.api]
    enabled = true
    ```
## "cfg-server-api-listen"
- `listen`
  - **Ограничения / валидация**: `Строка`. Должен быть в формате IP:PORT.
  - **Описание**: Адрес привязки API в формате IP:PORT.
  - **Пример**:

    ```toml
    [server.api]
    listen = "0.0.0.0:9091"
    ```
## "cfg-server-api-whitelist"
- `whitelist`
  - **Ограничения / валидация**: `IpNetwork[]`.
  - **Описание**: Белый список CIDR разрешил доступ к API.
  - **Пример**:

    ```toml
    [server.api]
    whitelist = ["127.0.0.0/8"]
    ```
## "cfg-server-api-auth_header"
- `auth_header`
  - **Ограничения / валидация**: `Строка`. Пустая строка отключает проверку заголовка аутентификации.
  - **Описание**: Точное ожидаемое значение заголовка `Authorization` (статический общий секрет).
  - **Пример**:

    ```toml
    [server.api]
    auth_header = "Bearer MY_TOKEN"
    ```
## "cfg-server-api-request_body_limit_bytes"
- `request_body_limit_bytes`
  - **Ограничения / валидация**: Должно быть `> 0` (байты).
  - **Описание**: Максимальный принимаемый размер тела HTTP-запроса (в байтах).
  - **Пример**:

    ```toml
    [server.api]
    request_body_limit_bytes = 65536
    ```
## "cfg-server-api-minimal_runtime_enabled"
- `minimal_runtime_enabled`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает минимальную логику конечной точки снимков времени выполнения.
  - **Пример**:

    ```toml
    [server.api]
    minimal_runtime_enabled = true
    ```
## "cfg-server-api-minimal_runtime_cache_ttl_ms"
- `minimal_runtime_cache_ttl_ms`
  - **Ограничения / валидация**: `0..=60000` (миллисекунды). `0` отключает кеш.
  - **Описание**: Срок жизни кэша для минимальных снимков времени выполнения (мс).
  - **Пример**:

    ```toml
    [server.api]
    minimal_runtime_cache_ttl_ms = 1000
    ```
## "cfg-server-api-runtime_edge_enabled"
- `runtime_edge_enabled`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает конечные точки границ среды выполнения.
  - **Пример**:

    ```toml
    [server.api]
    runtime_edge_enabled = false
    ```
## "cfg-server-api-runtime_edge_cache_ttl_ms"
- `runtime_edge_cache_ttl_ms`
  - **Ограничения / валидация**: `0..=60000` (миллисекунды).
  - **Описание**: Срок жизни кэша для полезных данных агрегации границ во время выполнения (мс).
  - **Пример**:

    ```toml
    [server.api]
    runtime_edge_cache_ttl_ms = 1000
    ```
## "cfg-server-api-runtime_edge_top_n"
- `runtime_edge_top_n`
  - **Ограничения / валидация**: `1..=1000`.
  - **Описание**: Размер Top-N для таблицы лидеров краевых соединений.
  - **Пример**:

    ```toml
    [server.api]
    runtime_edge_top_n = 10
    ```
## "cfg-server-api-runtime_edge_events_capacity"
- `runtime_edge_events_capacity`
  - **Ограничения / валидация**: `16..=4096`.
  - **Описание**: Емкость кольцевого буфера для пограничных событий во время выполнения.
  - **Пример**:

    ```toml
    [server.api]
    runtime_edge_events_capacity = 256
    ```
## "cfg-server-api-read_only"
- `read_only`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Отклоняет изменение конечных точек API, если оно включено.
  - **Пример**:

    ```toml
    [server.api]
    read_only = false
    ```


# [[server.listeners]]


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`ip`](#cfg-server-listeners-ip) | `IpAddr` | — |
| [`announce`](#cfg-server-listeners-announce) | `String` | — |
| [`announce_ip`](#cfg-server-listeners-announce_ip) | `IpAddr` | — |
| [`proxy_protocol`](#cfg-server-listeners-proxy_protocol) | `bool` | — |
| [`reuse_allow`](#cfg-server-listeners-reuse_allow) | `bool` | `false` |

## "cfg-server-listeners-ip"
- `ip`
  - **Ограничения / валидация**: Обязательное поле. Должен быть IPAddr.
  - **Описание**: IP-адрес привязки прослушивателя.
  - **Пример**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    ```
## "cfg-server-listeners-announce"
- `announce`
  - **Ограничения / валидация**: `Строка` (необязательно). Не должно быть пустым, если установлено.
  - **Описание**: Публичный IP-адрес/домен, объявленный в прокси-ссылках для этого прослушивателя. Имеет приоритет над announce_ip.
  - **Пример**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    announce = "proxy.example.com"
    ```
## "cfg-server-listeners-announce_ip"
- `announce_ip`
  - **Ограничения / валидация**: `IpAddr` (необязательно). Устарело. Используйте «объявить».
  - **Описание**: Устаревший устаревший IP-адрес объявления. Во время загрузки конфигурации он переводится в «announce», если «announce» не установлен.
  - **Пример**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    announce_ip = "203.0.113.10"
    ```
## "cfg-server-listeners-proxy_protocol"
- `proxy_protocol`
  - **Ограничения / валидация**: `bool` (необязательно). Если установлено, переопределяет `server.proxy_protocol` для этого прослушивателя.
  - **Описание**: Переопределение протокола PROXY для каждого слушателя.
  - **Пример**:

    ```toml
    [server]
    proxy_protocol = false

    [[server.listeners]]
    ip = "0.0.0.0"
    proxy_protocol = true
    ```
## "cfg-server-listeners-reuse_allow"
- `reuse_allow`
  - **Ограничения / валидация**: `бул`.
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
| [`client_handshake`](#cfg-timeouts-client_handshake) | `u64` | `30` |
| [`relay_idle_policy_v2_enabled`](#cfg-timeouts-relay_idle_policy_v2_enabled) | `bool` | `true` |
| [`relay_client_idle_soft_secs`](#cfg-timeouts-relay_client_idle_soft_secs) | `u64` | `120` |
| [`relay_client_idle_hard_secs`](#cfg-timeouts-relay_client_idle_hard_secs) | `u64` | `360` |
| [`relay_idle_grace_after_downstream_activity_secs`](#cfg-timeouts-relay_idle_grace_after_downstream_activity_secs) | `u64` | `30` |
| [`tg_connect`](#cfg-timeouts-tg_connect) | `u64` | `10` |
| [`client_keepalive`](#cfg-timeouts-client_keepalive) | `u64` | `15` |
| [`client_ack`](#cfg-timeouts-client_ack) | `u64` | `90` |
| [`me_one_retry`](#cfg-timeouts-me_one_retry) | `u8` | `12` |
| [`me_one_timeout_ms`](#cfg-timeouts-me_one_timeout_ms) | `u64` | `1200` |

## "cfg-timeouts-client_handshake"
- `client_handshake`
  - **Ограничения / валидация**: Должно быть `> 0`. Значение указано в секундах. Также используется в качестве верхней границы некоторых задержек эмуляции TLS (см. `censorship.server_hello_delay_max_ms`).
  - **Описание**: Тайм-аут установления связи клиента (в секундах).
  - **Пример**:

    ```toml
    [timeouts]
    client_handshake = 30
    ```
## "cfg-timeouts-relay_idle_policy_v2_enabled"
- `relay_idle_policy_v2_enabled`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает политику простоя клиента среднего/жесткого промежуточного реле.
  - **Пример**:

    ```toml
    [timeouts]
    relay_idle_policy_v2_enabled = true
    ```
## "cfg-timeouts-relay_client_idle_soft_secs"
- `relay_client_idle_soft_secs`
  - **Ограничения / валидация**: Должно быть `> 0`; должно быть `<=lay_client_idle_hard_secs`.
  - **Описание**: Порог мягкого простоя (в секундах) для неактивности восходящей линии связи клиента среднего ретранслятора. Достижение этого порога отмечает сеанс как бездействующего кандидата (в зависимости от политики он может подлежать очистке).
  - **Пример**:

    ```toml
    [timeouts]
    relay_client_idle_soft_secs = 120
    ```
## "cfg-timeouts-relay_client_idle_hard_secs"
- `relay_client_idle_hard_secs`
  - **Ограничения / валидация**: Должно быть `> 0`; должно быть `>=lay_client_idle_soft_secs`.
  - **Описание**: Порог жесткого простоя (в секундах) для неактивности восходящей линии связи клиента среднего ретранслятора. Достижение этого порога закрывает сессию.
  - **Пример**:

    ```toml
    [timeouts]
    relay_client_idle_hard_secs = 360
    ```
## "cfg-timeouts-relay_idle_grace_after_downstream_activity_secs"
- `relay_idle_grace_after_downstream_activity_secs`
  - **Ограничения / валидация**: Должно быть `<=lay_client_idle_hard_secs`.
  - **Описание**: Дополнительный льготный период жесткого простоя (в секундах), добавленный после недавней активности в нисходящем направлении.
  - **Пример**:

    ```toml
    [timeouts]
    relay_idle_grace_after_downstream_activity_secs = 30
    ```
## "cfg-timeouts-tg_connect"
- `tg_connect`
  - **Ограничения / валидация**: `u64`. Значение указано в секундах.
  - **Описание**: Тайм-аут восходящего соединения Telegram (в секундах).
  - **Пример**:

    ```toml
    [timeouts]
    tg_connect = 10
    ```
## "cfg-timeouts-client_keepalive"
- `client_keepalive`
  - **Ограничения / валидация**: `u64`. Значение указано в секундах.
  - **Описание**: Тайм-аут поддержки активности клиента (в секундах).
  - **Пример**:

    ```toml
    [timeouts]
    client_keepalive = 15
    ```
## "cfg-timeouts-client_ack"
- `client_ack`
  - **Ограничения / валидация**: `u64`. Значение указано в секундах.
  - **Описание**: Таймаут подтверждения клиента (в секундах).
  - **Пример**:

    ```toml
    [timeouts]
    client_ack = 90
    ```
## "cfg-timeouts-me_one_retry"
- `me_one_retry`
  - **Ограничения / валидация**: `u8`.
  - **Описание**: Бюджет попыток быстрого повторного подключения для сценариев DC с одной конечной точкой.
  - **Пример**:

    ```toml
    [timeouts]
    me_one_retry = 12
    ```
## "cfg-timeouts-me_one_timeout_ms"
- `me_one_timeout_ms`
  - **Ограничения / валидация**: `u64`. Значение указано в миллисекундах.
  - **Описание**: Тайм-аут на быструю попытку (мс) для логики повторного подключения постоянного тока с одной конечной точкой.
  - **Пример**:

    ```toml
    [timeouts]
    me_one_timeout_ms = 1200
    ```


# [censorship]


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`tls_domain`](#cfg-censorship-tls_domain) | `String` | `"petrovich.ru"` |
| [`tls_domains`](#cfg-censorship-tls_domains) | `String[]` | `[]` |
| [`unknown_sni_action`](#cfg-censorship-unknown_sni_action) | `"drop"`, `"mask"`, `"accept"` | `"drop"` |
| [`tls_fetch_scope`](#cfg-censorship-tls_fetch_scope) | `String` | `""` |
| [`tls_fetch`](#cfg-censorship-tls_fetch) | `Table` | built-in defaults |
| [`mask`](#cfg-censorship-mask) | `bool` | `true` |
| [`mask_host`](#cfg-censorship-mask_host) | `String` | — |
| [`mask_port`](#cfg-censorship-mask_port) | `u16` | `443` |
| [`mask_unix_sock`](#cfg-censorship-mask_unix_sock) | `String` | — |
| [`fake_cert_len`](#cfg-censorship-fake_cert_len) | `usize` | `2048` |
| [`tls_emulation`](#cfg-censorship-tls_emulation) | `bool` | `true` |
| [`tls_front_dir`](#cfg-censorship-tls_front_dir) | `String` | `"tlsfront"` |
| [`server_hello_delay_min_ms`](#cfg-censorship-server_hello_delay_min_ms) | `u64` | `0` |
| [`server_hello_delay_max_ms`](#cfg-censorship-server_hello_delay_max_ms) | `u64` | `0` |
| [`tls_new_session_tickets`](#cfg-censorship-tls_new_session_tickets) | `u8` | `0` |
| [`tls_full_cert_ttl_secs`](#cfg-censorship-tls_full_cert_ttl_secs) | `u64` | `90` |
| [`alpn_enforce`](#cfg-censorship-alpn_enforce) | `bool` | `true` |
| [`mask_proxy_protocol`](#cfg-censorship-mask_proxy_protocol) | `u8` | `0` |
| [`mask_shape_hardening`](#cfg-censorship-mask_shape_hardening) | `bool` | `true` |
| [`mask_shape_hardening_aggressive_mode`](#cfg-censorship-mask_shape_hardening_aggressive_mode) | `bool` | `false` |
| [`mask_shape_bucket_floor_bytes`](#cfg-censorship-mask_shape_bucket_floor_bytes) | `usize` | `512` |
| [`mask_shape_bucket_cap_bytes`](#cfg-censorship-mask_shape_bucket_cap_bytes) | `usize` | `4096` |
| [`mask_shape_above_cap_blur`](#cfg-censorship-mask_shape_above_cap_blur) | `bool` | `false` |
| [`mask_shape_above_cap_blur_max_bytes`](#cfg-censorship-mask_shape_above_cap_blur_max_bytes) | `usize` | `512` |
| [`mask_relay_max_bytes`](#cfg-censorship-mask_relay_max_bytes) | `usize` | `5242880` |
| [`mask_classifier_prefetch_timeout_ms`](#cfg-censorship-mask_classifier_prefetch_timeout_ms) | `u64` | `5` |
| [`mask_timing_normalization_enabled`](#cfg-censorship-mask_timing_normalization_enabled) | `bool` | `false` |
| [`mask_timing_normalization_floor_ms`](#cfg-censorship-mask_timing_normalization_floor_ms) | `u64` | `0` |
| [`mask_timing_normalization_ceiling_ms`](#cfg-censorship-mask_timing_normalization_ceiling_ms) | `u64` | `0` |

## "cfg-censorship-tls_domain"
- `tls_domain`
  - **Ограничения / валидация**: Должно быть непустое доменное имя. Не должно содержать пробелов или `/`.
  - **Описание**: Основной домен TLS, используемый в профиле подтверждения FakeTLS и в качестве домена SNI по умолчанию.
  - **Пример**:

    ```toml
    [censorship]
    tls_domain = "example.com"
    ```
## "cfg-censorship-tls_domains"
- `tls_domains`
  - **Ограничения / валидация**: `Строка[]`. Если установлено, значения объединяются с tls_domain и дедуплицируются (первичный tls_domain всегда остается первым).
  - **Описание**: Дополнительные домены TLS для создания нескольких прокси-ссылок.
  - **Пример**:

    ```toml
    [censorship]
    tls_domain = "example.com"
    tls_domains = ["example.net", "example.org"]
    ```
## "cfg-censorship-unknown_sni_action"
- `unknown_sni_action`
  - **Ограничения / валидация**: «drop», «mask» или «accept».
  - **Описание**: Действие для TLS ClientHello с неизвестным/ненастроенным SNI.
  - **Пример**:

    ```toml
    [censorship]
    unknown_sni_action = "drop"
    ```
## "cfg-censorship-tls_fetch_scope"
- `tls_fetch_scope`
  - **Ограничения / валидация**: `Строка`. Значение обрезается во время загрузки; whitespace-only становится пустым.
  - **Описание**: Тег области восходящего потока, используемый для выборки метаданных TLS-фронт. Пустое значение сохраняет поведение восходящей маршрутизации по умолчанию.
  - **Пример**:

    ```toml
    [censorship]
    tls_fetch_scope = "fetch"
    ```
## "cfg-censorship-tls_fetch"
- `tls_fetch`
  - **Ограничения / валидация**: Стол. См. раздел «[censorship.tls_fetch]» ниже.
  - **Описание**: Настройки стратегии выборки метаданных TLS (начальная загрузка + поведение обновления для данных эмуляции TLS).
  - **Пример**:

    ```toml
    [censorship.tls_fetch]
    strict_route = true
    attempt_timeout_ms = 5000
    total_budget_ms = 15000
    ```
## "cfg-censorship-mask"
- `mask`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает режим маскировки/переднего реле.
  - **Пример**:

    ```toml
    [censorship]
    mask = true
    ```
## "cfg-censorship-mask_host"
- `mask_host`
  - **Ограничения / валидация**: `Строка` (необязательно).
- Если установлена ​​маска_unix_sock, маска_хост должна быть опущена (взаимоисключающая).
- Если `mask_host` не установлен и `mask_unix_sock` не установлен, Telemt по умолчанию устанавливает для `mask_host` значение `tls_domain`.
  - **Описание**: Хост восходящей маски для фронтального реле TLS.
  - **Пример**:

    ```toml
    [censorship]
    mask_host = "www.cloudflare.com"
    ```
## "cfg-censorship-mask_port"
- `mask_port`
  - **Ограничения / валидация**: `u16`.
  - **Описание**: Восходящий порт маски для фронтального реле TLS.
  - **Пример**:

    ```toml
    [censorship]
    mask_port = 443
    ```
## "cfg-censorship-mask_unix_sock"
- `mask_unix_sock`
  - **Ограничения / валидация**: `Строка` (необязательно).
- Не должно быть пустым, если установлено.
- Только Unix; отклонено на платформах, отличных от Unix.
- В Unix должно быть \(\le 107\) байт (ограничение длины пути).
- Взаимоисключающий с `mask_host`.
  - **Описание**: Путь сокета Unix для серверной части маски вместо TCP `mask_host`/`mask_port`.
  - **Пример**:

    ```toml
    [censorship]
    mask_unix_sock = "/run/telemt/mask.sock"
    ```
## "cfg-censorship-fake_cert_len"
- `fake_cert_len`
  - **Ограничения / валидация**: `использовать`. Когда `tls_emulation = false` и используется значение по умолчанию, Telemt может рандомизировать его при запуске для обеспечения вариативности.
  - **Описание**: Длина полезных данных синтетического сертификата, когда данные эмуляции недоступны.
  - **Пример**:

    ```toml
    [censorship]
    fake_cert_len = 2048
    ```
## "cfg-censorship-tls_emulation"
- `tls_emulation`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает эмуляцию поведения сертификата/TLS из кэшированных реальных фронтов.
  - **Пример**:

    ```toml
    [censorship]
    tls_emulation = true
    ```
## "cfg-censorship-tls_front_dir"
- `tls_front_dir`
  - **Ограничения / валидация**: `Строка`.
  - **Описание**: Путь к каталогу для хранения переднего кэша TLS.
  - **Пример**:

    ```toml
    [censorship]
    tls_front_dir = "tlsfront"
    ```
## "cfg-censorship-server_hello_delay_min_ms"
- `server_hello_delay_min_ms`
  - **Ограничения / валидация**: `u64` (миллисекунды).
  - **Описание**: Минимальная задержка server_hello для защиты от отпечатков пальцев (мс).
  - **Пример**:

    ```toml
    [censorship]
    server_hello_delay_min_ms = 0
    ```
## "cfg-censorship-server_hello_delay_max_ms"
- `server_hello_delay_max_ms`
  - **Ограничения / валидация**: `u64` (миллисекунды). Должно быть \(<\) `timeouts.client_handshake * 1000`.
  - **Описание**: Максимальная задержка `server_hello` для защиты от отпечатков пальцев (мс).
  - **Пример**:

    ```toml
    [timeouts]
    client_handshake = 30

    [censorship]
    server_hello_delay_max_ms = 0
    ```
## "cfg-censorship-tls_new_session_tickets"
- `tls_new_session_tickets`
  - **Ограничения / валидация**: `u8`.
  - **Описание**: Количество сообщений NewSessionTicket, отправляемых после рукопожатия.
  - **Пример**:

    ```toml
    [censorship]
    tls_new_session_tickets = 0
    ```
## "cfg-censorship-tls_full_cert_ttl_secs"
- `tls_full_cert_ttl_secs`
  - **Ограничения / валидация**: `u64` (секунды).
  - **Описание**: TTL для отправки полной полезной нагрузки сертификата для каждого кортежа (домен, IP-адрес клиента).
  - **Пример**:

    ```toml
    [censorship]
    tls_full_cert_ttl_secs = 90
    ```
## "cfg-censorship-alpn_enforce"
- `alpn_enforce`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Обеспечивает поведение эха ALPN в зависимости от предпочтений клиента.
  - **Пример**:

    ```toml
    [censorship]
    alpn_enforce = true
    ```
## "cfg-censorship-mask_proxy_protocol"
- `mask_proxy_protocol`
  - **Ограничения / валидация**: `u8`. `0` = отключено, `1` = v1 (текст), `2` = v2 (двоичный).
  - **Описание**: Отправляет заголовок протокола PROXY при подключении к серверной части маски, позволяя серверной части видеть реальный IP-адрес клиента.
  - **Пример**:

    ```toml
    [censorship]
    mask_proxy_protocol = 0
    ```
## "cfg-censorship-mask_shape_hardening"
- `mask_shape_hardening`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает усиление жесткости канала формы клиента->маски путем применения контролируемого заполнения хвоста к границам сегмента при отключении реле маски.
  - **Пример**:

    ```toml
    [censorship]
    mask_shape_hardening = true
    ```
## "cfg-censorship-mask_shape_hardening_aggressive_mode"
- `mask_shape_hardening_aggressive_mode`
  - **Ограничения / валидация**: Требуется «mask_shape_hardening = true».
  - **Описание**: Включите агрессивный профиль формирования (более сильное антиклассификаторское поведение с различной семантикой формирования).
  - **Пример**:

    ```toml
    [censorship]
    mask_shape_hardening = true
    mask_shape_hardening_aggressive_mode = false
    ```
## "cfg-censorship-mask_shape_bucket_floor_bytes"
- `mask_shape_bucket_floor_bytes`
  - **Ограничения / валидация**: Должно быть `> 0`; должно быть `<= Mask_shape_bucket_cap_bytes`.
  - **Описание**: Минимальный размер ковша, используемый при закалке в форме канала.
  - **Пример**:

    ```toml
    [censorship]
    mask_shape_bucket_floor_bytes = 512
    ```
## "cfg-censorship-mask_shape_bucket_cap_bytes"
- `mask_shape_bucket_cap_bytes`
  - **Ограничения / валидация**: Должно быть `>= Mask_shape_bucket_floor_bytes`.
  - **Описание**: Максимальный размер ковша, используемый при фасонно-канальной закалке; трафик, превышающий ограничение, не дополняется дальше.
  - **Пример**:

    ```toml
    [censorship]
    mask_shape_bucket_cap_bytes = 4096
    ```
## "cfg-censorship-mask_shape_above_cap_blur"
- `mask_shape_above_cap_blur`
  - **Ограничения / валидация**: Требуется «mask_shape_hardening = true».
  - **Описание**: Добавляет ограниченные рандомизированные хвостовые байты, даже если пересылаемый размер уже превышает ограничение.
  - **Пример**:

    ```toml
    [censorship]
    mask_shape_hardening = true
    mask_shape_above_cap_blur = false
    ```
## "cfg-censorship-mask_shape_above_cap_blur_max_bytes"
- `mask_shape_above_cap_blur_max_bytes`
  - **Ограничения / валидация**: Должно быть `<= 1048576`. Должно быть `> 0`, когда `mask_shape_above_cap_blur = true`.
  - **Описание**: Максимальное количество случайных дополнительных байтов, добавляемых выше ограничения, если включено размытие выше ограничения.
  - **Пример**:

    ```toml
    [censorship]
    mask_shape_above_cap_blur = true
    mask_shape_above_cap_blur_max_bytes = 64
    ```
## "cfg-censorship-mask_relay_max_bytes"
- `mask_relay_max_bytes`
  - **Ограничения / валидация**: Должно быть `> 0`; должно быть `<= 67108864`.
  - **Описание**: Максимальное количество ретранслируемых байтов в каждом направлении по резервному пути маскировки без аутентификации.
  - **Пример**:

    ```toml
    [censorship]
    mask_relay_max_bytes = 5242880
    ```
## "cfg-censorship-mask_classifier_prefetch_timeout_ms"
- `mask_classifier_prefetch_timeout_ms`
  - **Ограничения / валидация**: Должно быть в пределах `[5, 50]` (миллисекунды).
  - **Описание**: Бюджет тайм-аута (мс) для расширения фрагментированного начального окна классификатора при откате маскирования.
  - **Пример**:

    ```toml
    [censorship]
    mask_classifier_prefetch_timeout_ms = 5
    ```
## "cfg-censorship-mask_timing_normalization_enabled"
- `mask_timing_normalization_enabled`
  - **Ограничения / валидация**: Если задано значение true, требуется маска_timing_normalization_floor_ms > 0 и маска_timing_normalization_ceiling_ms >= Mask_timing_normalization_floor_ms. Потолок должен быть `<= 60000`.
  - **Описание**: Включает нормализацию временного конверта для результатов маскировки.
  - **Пример**:

    ```toml
    [censorship]
    mask_timing_normalization_enabled = false
    ```
## "cfg-censorship-mask_timing_normalization_floor_ms"
- `mask_timing_normalization_floor_ms`
  - **Ограничения / валидация**: Должно быть `> 0`, если нормализация времени включена; должно быть `<= Mask_timing_normalization_ceiling_ms`.
  - **Описание**: Нижняя граница (мс) для маскировки цели нормализации результата.
  - **Пример**:

    ```toml
    [censorship]
    mask_timing_normalization_floor_ms = 0
    ```
## "cfg-censorship-mask_timing_normalization_ceiling_ms"
- `mask_timing_normalization_ceiling_ms`
  - **Ограничения / валидация**: Должно быть `>= Mask_timing_normalization_floor_ms`; должно быть `<= 60000`.
  - **Описание**: Верхняя граница (мс) для маскировки цели нормализации результата.
  - **Пример**:

    ```toml
    [censorship]
    mask_timing_normalization_ceiling_ms = 0
    ```

## Shape-channel hardening notes (`[censorship]`)

Эти параметры предназначены для уменьшения одного конкретного источника отпечатков пальцев во время маскировки: точного количества байтов, отправленных с прокси-сервера на «mask_host» для недействительного или пробного трафика.

Без усиления цензор часто может очень точно сопоставить входную длину зонда с длиной, наблюдаемой серверной частью (например: `5 + body_sent` на ранних путях отклонения TLS). Это создает сигнал классификатора на основе длины.

When `mask_shape_hardening = true`, Telemt pads the **client->mask** stream tail to a bucket boundary at relay shutdown:

- Сначала измеряется общее количество байтов, отправленных в маску.
- Ведро выбирается с использованием степеней двойки, начиная с «mask_shape_bucket_floor_bytes».
— Заполнение добавляется только в том случае, если общее количество байтов меньше «mask_shape_bucket_cap_bytes».
- Если байты уже превышают ограничение, дополнительное дополнение не добавляется.

Это означает, что несколько близлежащих размеров зондов объединяются в один и тот же класс размеров, наблюдаемый серверной частью, что усложняет активную классификацию.

Что каждый параметр меняет на практике:

- `mask_shape_hardening`
Включает или отключает весь этот этап формирования длины на резервном пути.
Если установлено значение «false», длина, наблюдаемая серверной частью, остается близкой к реальной длине пересылаемого зонда.
Если задано значение true, при чистом отключении реле могут добавляться случайные байты заполнения для перемещения итоговой суммы в корзину.
- `mask_shape_bucket_floor_bytes`
Устанавливает первую границу сегмента, используемую для небольших зондов.
Пример: с этажом «512» некорректный зонд, который в противном случае пересылал бы «37» байтов, может быть расширен до «512» байтов в чистом EOF.
Большие минимальные значения лучше скрывают очень маленькие зонды, но увеличивают стоимость выхода.
- `mask_shape_bucket_cap_bytes`
Устанавливает самый большой сегмент, который Telemt будет дополнять логикой сегмента.
Пример: с ограничением `4096` общее количество пересылаемых байтов `1800` может быть дополнено до `2048` или `4096` в зависимости от лестницы сегментов, но общее количество, уже превышающее `4096`, не будет дополняться дальше.
Большие значения ограничения увеличивают диапазон, в котором сворачиваются классы размеров, но также увеличивают накладные расходы в худшем случае.
- Чистый EOF имеет значение в консервативном режиме.
В профиле по умолчанию заполнение формы намеренно консервативно: оно применяется при чистом отключении реле, а не при каждом тайм-ауте или пути утечки.
Это позволяет избежать появления новых артефактов тайм-аута, которые некоторые серверные части или тесты интерпретируют как отдельные отпечатки пальцев.

Практические компромиссы:

- Улучшена защита от отпечатков пальцев на канале размера/формы.
- Немного выше выходные накладные расходы для небольших зондов из-за заполнения.
- Поведение намеренно консервативно и включено по умолчанию.

Рекомендуемый стартовый профиль:

- `mask_shape_hardening = true` (default)
- `mask_shape_bucket_floor_bytes = 512`
- `mask_shape_bucket_cap_bytes = 4096`

## Aggressive mode notes (`[censorship]`)

«mask_shape_hardening_aggressive_mode» — это дополнительный профиль для более высокого давления антиклассификатора.

- По умолчанию установлено значение «false», чтобы сохранить консервативное поведение по тайм-ауту/без хвоста.
- Requires `mask_shape_hardening = true`.
- Если этот параметр включен, могут формироваться бесшумные пути маскировки без EOF.
- При включении вместе с размытием над верхним пределом случайный дополнительный хвост использует `[1, max]` вместо `[0, max]`.

Что меняется при включении агрессивного режима:

- Могут быть сформированы пути тайм-аута, не требующие бэкенда.
В режиме по умолчанию клиент, который держит сокет полуоткрытым и имеет тайм-аут, обычно не будет получать заполнение формы по этому пути.
В агрессивном режиме Telemt все равно может формировать этот сеанс без звука, если никакие байты серверной части не были возвращены.
Это специально предназначено для активных зондов, которые пытаются избежать EOF, чтобы сохранить точную наблюдаемую длину.
- Размытие над заглавной буквой всегда добавляет хотя бы один байт.
В режиме по умолчанию для размытия над пределом может быть выбрано значение «0», поэтому некоторые зонды слишком большого размера по-прежнему попадают на точную базовую длину пересылки.
В агрессивном режиме эта базовая выборка удаляется автоматически.
- Компромисс
Агрессивный режим повышает устойчивость к активным классификаторам длины, но он более упрям ​​и менее консервативен.
Если в вашем развертывании приоритетом является строгая совместимость с семантикой тайм-аута/без хвоста, оставьте ее отключенной.
Если ваша модель угроз включает в себя повторяющиеся активные проверки цензором, этот режим является более сильным профилем.

Используйте этот режим только в том случае, если ваша модель угроз отдает приоритет устойчивости классификатора над строгой совместимостью с консервативной семантикой маскировки.

## Above-cap blur notes (`[censorship]`)

«mask_shape_above_cap_blur» добавляет размытие второго этапа для очень больших зондов, которые уже находятся выше «mask_shape_bucket_cap_bytes».

- В режиме по умолчанию добавляется случайный хвост в `[0, Mask_shape_above_cap_blur_max_bytes]`.
— В агрессивном режиме случайный хвост становится строго положительным: `[1, Mask_shape_above_cap_blur_max_bytes]`.
- Это уменьшает утечку точного размера выше ограничения при ограниченных накладных расходах.
— Сохраняйте «mask_shape_above_cap_blur_max_bytes» консервативным, чтобы избежать ненужного роста выходного сигнала.

Операционное значение:

- Без размытия над шапкой
Зонд, который пересылает 5005 байтов, по-прежнему будет выглядеть как 5005 байт на серверную часть, если он уже превышает ограничение.
- С включенным размытием над шапкой
Тот же самый зонд может выглядеть как любое значение в ограниченном окне, превышающем его базовую длину.
  Example with `mask_shape_above_cap_blur_max_bytes = 64`:
наблюдаемый на сервере размер становится «5005..5069» в режиме по умолчанию или «5006..5069» в агрессивном режиме.
- Выбор `mask_shape_above_cap_blur_max_bytes`
Небольшие значения снижают затраты, но сохраняют большую степень разделения между удаленными друг от друга негабаритными классами.
Большие значения размывают слишком большие классы более агрессивно, но добавляют больше исходящих издержек и большую дисперсию выходных данных.

## Timing normalization envelope notes (`[censorship]`)

`mask_timing_normalization_enabled` сглаживает разницу во времени между результатами маскировки, применяя целевой диапазон длительности.

- Случайная цель выбирается в `[mask_timing_normalization_floor_ms, Mask_timing_normalization_ceiling_ms]`.
- Быстрые пути задерживаются до выбранной цели.
- Медленные пути не обязательно заканчиваются у потолка (огибающая формируется с максимальной эффективностью, а не усекается).

Рекомендуемый стартовый профиль для формирования тайминга:

- `mask_timing_normalization_enabled = true`
- `mask_timing_normalization_floor_ms = 180`
- `mask_timing_normalization_ceiling_ms = 320`

Если ваша серверная часть или сеть сильно ограничена в пропускной способности, сначала уменьшите ограничение. Если датчики все еще слишком различимы в вашей среде, постепенно увеличивайте минимальное значение.

# [censorship.tls_fetch]


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`profiles`](#cfg-censorship-tls_fetch-profiles) | `String[]` | `["modern_chrome_like", "modern_firefox_like", "compat_tls12", "legacy_minimal"]` |
| [`strict_route`](#cfg-censorship-tls_fetch-strict_route) | `bool` | `true` |
| [`attempt_timeout_ms`](#cfg-censorship-tls_fetch-attempt_timeout_ms) | `u64` | `5000` |
| [`total_budget_ms`](#cfg-censorship-tls_fetch-total_budget_ms) | `u64` | `15000` |
| [`grease_enabled`](#cfg-censorship-tls_fetch-grease_enabled) | `bool` | `false` |
| [`deterministic`](#cfg-censorship-tls_fetch-deterministic) | `bool` | `false` |
| [`profile_cache_ttl_secs`](#cfg-censorship-tls_fetch-profile_cache_ttl_secs) | `u64` | `600` |

## "cfg-censorship-tls_fetch-profiles"
- `profiles`
  - **Ограничения / валидация**: `Строка[]`. Пустой список возвращает значения по умолчанию; значения дедуплицируются с сохранением порядка.
  - **Описание**: Упорядоченная резервная цепочка профиля ClientHello для выборки метаданных TLS-фронт.
  - **Пример**:

    ```toml
    [censorship.tls_fetch]
    profiles = ["modern_chrome_like", "compat_tls12"]
    ```
## "cfg-censorship-tls_fetch-strict_route"
- `strict_route`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Если true и восходящий маршрут настроен, выборка TLS не закрывается из-за ошибок восходящего соединения вместо возврата к прямому TCP.
  - **Пример**:

    ```toml
    [censorship.tls_fetch]
    strict_route = true
    ```
## "cfg-censorship-tls_fetch-attempt_timeout_ms"
- `attempt_timeout_ms`
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунды).
  - **Описание**: Бюджет таймаута на одну попытку получения профиля TLS (мс).
  - **Пример**:

    ```toml
    [censorship.tls_fetch]
    attempt_timeout_ms = 5000
    ```
## "cfg-censorship-tls_fetch-total_budget_ms"
- `total_budget_ms`
  - **Ограничения / валидация**: Должно быть `> 0` (миллисекунды).
  - **Описание**: Общий бюджет настенных часов для всех попыток TLS-выборки (мс).
  - **Пример**:

    ```toml
    [censorship.tls_fetch]
    total_budget_ms = 15000
    ```
## "cfg-censorship-tls_fetch-grease_enabled"
- `grease_enabled`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает случайные значения в стиле GREASE в выбранных расширениях ClientHello для получения трафика.
  - **Пример**:

    ```toml
    [censorship.tls_fetch]
    grease_enabled = false
    ```
## "cfg-censorship-tls_fetch-deterministic"
- `deterministic`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Включает детерминированную случайность ClientHello для отладки/тестирования.
  - **Пример**:

    ```toml
    [censorship.tls_fetch]
    deterministic = false
    ```
## "cfg-censorship-tls_fetch-profile_cache_ttl_secs"
- `profile_cache_ttl_secs`
  - **Ограничения / валидация**: `u64` (секунды). `0` отключает кеш.
  - **Описание**: TTL для записей кэша профиля победителя, используемых путем выборки TLS.
  - **Пример**:

    ```toml
    [censorship.tls_fetch]
    profile_cache_ttl_secs = 600
    ```


# [access]


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`users`](#cfg-access-users) | `Map<String, String>` | `{"default": "000…000"}` |
| [`user_ad_tags`](#cfg-access-user_ad_tags) | `Map<String, String>` | `{}` |
| [`user_max_tcp_conns`](#cfg-access-user_max_tcp_conns) | `Map<String, usize>` | `{}` |
| [`user_max_tcp_conns_global_each`](#cfg-access-user_max_tcp_conns_global_each) | `usize` | `0` |
| [`user_expirations`](#cfg-access-user_expirations) | `Map<String, DateTime<Utc>>` | `{}` |
| [`user_data_quota`](#cfg-access-user_data_quota) | `Map<String, u64>` | `{}` |
| [`user_max_unique_ips`](#cfg-access-user_max_unique_ips) | `Map<String, usize>` | `{}` |
| [`user_max_unique_ips_global_each`](#cfg-access-user_max_unique_ips_global_each) | `usize` | `0` |
| [`user_max_unique_ips_mode`](#cfg-access-user_max_unique_ips_mode) | `"active_window"`, `"time_window"`, or `"combined"` | `"active_window"` |
| [`user_max_unique_ips_window_secs`](#cfg-access-user_max_unique_ips_window_secs) | `u64` | `30` |
| [`replay_check_len`](#cfg-access-replay_check_len) | `usize` | `65536` |
| [`replay_window_secs`](#cfg-access-replay_window_secs) | `u64` | `120` |
| [`ignore_time_skew`](#cfg-access-ignore_time_skew) | `bool` | `false` |

## "cfg-access-users"
- `users`
  - **Ограничения / валидация**: Не должно быть пустым (должен существовать хотя бы один пользователь). Каждое значение должно состоять **ровно из 32 шестнадцатеричных символов**.
  - **Описание**: Карта учетных данных пользователя, используемая для аутентификации клиента. Ключи — это имена пользователей; значения являются секретами MTProxy.
  - **Пример**:

    ```toml
    [access.users]
    alice = "00112233445566778899aabbccddeeff"
    bob   = "0123456789abcdef0123456789abcdef"
    ```
## "cfg-access-user_ad_tags"
- `user_ad_tags`
  - **Ограничения / валидация**: Каждое значение должно содержать **ровно 32 шестнадцатеричных символа** (тот же формат, что и `general.ad_tag`). Тег со всеми нулями разрешен, но регистрирует предупреждение.
  - **Описание**: Переопределение рекламного тега спонсируемого канала для каждого пользователя. Когда у пользователя есть запись здесь, она имеет приоритет над `general.ad_tag`.
  - **Пример**:

    ```toml
    [general]
    ad_tag = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    [access.user_ad_tags]
    alice = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ```
## "cfg-access-user_max_tcp_conns"
- `user_max_tcp_conns`
  - **Ограничения / валидация**: `Карта<String, использовать>`.
  - **Описание**: Максимальное количество одновременных TCP-соединений для каждого пользователя.
  - **Пример**:

    ```toml
    [access.user_max_tcp_conns]
    alice = 500
    ```
## "cfg-access-user_max_tcp_conns_global_each"
- `user_max_tcp_conns_global_each`
  - **Ограничения / валидация**: `использовать`. `0` отключает унаследованный лимит.
  - **Описание**: Глобальное максимальное количество одновременных TCP-соединений для каждого пользователя, применяется, когда у пользователя **нет положительной** записи в `[access.user_max_tcp_conns]` (отсутствующий ключ или значение `0` подпадают под этот параметр). Ограничения на пользователя, превышающие «0» в «user_max_tcp_conns», имеют приоритет.
  - **Пример**:

    ```toml
    [access]
    user_max_tcp_conns_global_each = 200

    [access.user_max_tcp_conns]
    alice = 500   # uses 500, not the global cap
    # bob has no entry → uses 200
    ```
## "cfg-access-user_expirations"
- `user_expirations`
  - **Ограничения / валидация**: `Карта<String, DateTime<Utc>>`. Каждое значение должно быть допустимой датой и временем RFC3339/ISO-8601.
  - **Описание**: Временные метки истечения срока действия учетной записи пользователя (UTC).
  - **Пример**:

    ```toml
    [access.user_expirations]
    alice = "2026-12-31T23:59:59Z"
    ```
## "cfg-access-user_data_quota"
- `user_data_quota`
  - **Ограничения / валидация**: `Карта<String, u64>`.
  - **Описание**: Квота трафика на пользователя в байтах.
  - **Пример**:

    ```toml
    [access.user_data_quota]
    alice = 1073741824 # 1 GiB
    ```
## "cfg-access-user_max_unique_ips"
- `user_max_unique_ips`
  - **Ограничения / валидация**: `Карта<String, использовать>`.
  - **Описание**: Ограничения на уникальные исходные IP-адреса для каждого пользователя.
  - **Пример**:

    ```toml
    [access.user_max_unique_ips]
    alice = 16
    ```
## "cfg-access-user_max_unique_ips_global_each"
- `user_max_unique_ips_global_each`
  - **Ограничения / валидация**: `использовать`. `0` отключает унаследованный лимит.
  - **Описание**: Глобальный лимит уникального IP-адреса для каждого пользователя применяется, когда у пользователя нет индивидуального переопределения в `[access.user_max_unique_ips]`.
  - **Пример**:

    ```toml
    [access]
    user_max_unique_ips_global_each = 8
    ```
## "cfg-access-user_max_unique_ips_mode"
- `user_max_unique_ips_mode`
  - **Ограничения / валидация**: Должно быть одно из «active_window», «time_window», «combined».
  - **Описание**: Режим учета лимита уникальных IP-адресов источника.
  - **Пример**:

    ```toml
    [access]
    user_max_unique_ips_mode = "active_window"
    ```
## "cfg-access-user_max_unique_ips_window_secs"
- `user_max_unique_ips_window_secs`
  - **Ограничения / валидация**: Должно быть `> 0`.
  - **Описание**: Размер окна (в секундах), используемый режимами учета уникальных IP-адресов, включающими временное окно («time_window» и «комбинированный»).
  - **Пример**:

    ```toml
    [access]
    user_max_unique_ips_window_secs = 30
    ```
## "cfg-access-replay_check_len"
- `replay_check_len`
  - **Ограничения / валидация**: `использовать`.
  - **Описание**: Длина хранилища для защиты от повторения (количество записей, отслеживаемых на предмет обнаружения дубликатов).
  - **Пример**:

    ```toml
    [access]
    replay_check_len = 65536
    ```
## "cfg-access-replay_window_secs"
- `replay_window_secs`
  - **Ограничения / валидация**: `u64`.
  - **Описание**: Временное окно защиты от повтора в секундах.
  - **Пример**:

    ```toml
    [access]
    replay_window_secs = 120
    ```
## "cfg-access-ignore_time_skew"
- `ignore_time_skew`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Отключает проверку перекоса временных меток клиента и сервера при проверке воспроизведения, если она включена.
  - **Пример**:

    ```toml
    [access]
    ignore_time_skew = false
    ```


# [[upstreams]]


| Ключ | Тип | По умолчанию |
| --- | ---- | ------- |
| [`type`](#cfg-upstreams-type) | `"direct"`, `"socks4"`, `"socks5"`, or `"shadowsocks"` | — |
| [`weight`](#cfg-upstreams-weight) | `u16` | `1` |
| [`enabled`](#cfg-upstreams-enabled) | `bool` | `true` |
| [`scopes`](#cfg-upstreams-scopes) | `String` | `""` |
| [`interface`](#cfg-upstreams-interface) | `String` | — |
| [`bind_addresses`](#cfg-upstreams-bind_addresses) | `String[]` | — |
| [`url`](#cfg-upstreams-url) | `String` | — |
| [`address`](#cfg-upstreams-address) | `String` | — |
| [`user_id`](#cfg-upstreams-user_id) | `String` | — |
| [`username`](#cfg-upstreams-username) | `String` | — |
| [`password`](#cfg-upstreams-password) | `String` | — |

## "cfg-upstreams-type"
- `type`
  - **Ограничения / валидация**: Обязательное поле. Должен быть одним из: `"direct"`, `"socks4"`, `"socks5"`, `"shadowsocks"`.
  - **Описание**: Выбирает реализацию восходящего транспорта для этой записи `[[upstreams]]`.
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
## "cfg-upstreams-weight"
- `weight`
  - **Ограничения / валидация**: `u16` (0..=65535).
  - **Описание**: Базовый вес, используемый взвешенно-случайным выбором в восходящем направлении (выше = выбирается чаще).
  - **Пример**:

    ```toml
    [[upstreams]]
    type = "direct"
    weight = 10
    ```
## "cfg-upstreams-enabled"
- `enabled`
  - **Ограничения / валидация**: `бул`.
  - **Описание**: Если установлено значение false, эта запись игнорируется и не используется для выбора в восходящем направлении.
  - **Пример**:

    ```toml
    [[upstreams]]
    type = "socks5"
    address = "127.0.0.1:9050"
    enabled = false
    ```
## "cfg-upstreams-scopes"
- `scopes`
  - **Ограничения / валидация**: `Строка`. Список, разделенный запятыми; пробелы обрезаются во время сопоставления.
  - **Описание**: Теги области, используемые для восходящей фильтрации на уровне запроса. Если в запросе указана область, могут быть выбраны только восходящие потоки, чьи `области` содержат этот тег. Если в запросе не указана область, допускаются только восходящие потоки с пустыми «областями».
  - **Пример**:

    ```toml
    [[upstreams]]
    type = "socks4"
    address = "10.0.0.10:1080"
    scopes = "me, fetch, dc2"
    ```
## "cfg-upstreams-interface"
- `interface`
  - **Ограничения / валидация**: `Строка` (необязательно).
- Для «прямого»: может быть IP-адрес (используемый как явная локальная привязка) или имя интерфейса ОС (преобразующееся в IP-адрес во время выполнения; только для Unix).
- Для `"socks4"`/`"socks5"`: поддерживается только тогда, когда `address` является литералом`IP:port`; когда `address` является именем хоста, привязка интерфейса игнорируется.
- Для `"shadowsocks"`: передается в коннектор Shadowsocks как необязательная подсказка для исходящей привязки.
  - **Описание**: Необязательный исходящий интерфейс/подсказка локальной привязки для восходящего сокета подключения.
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
## "cfg-upstreams-bind_addresses"
- `bind_addresses`
  - **Ограничения / валидация**: `String[]` (необязательно). Применяется только к `type = "direct"`.
- Каждая запись должна представлять собой строку IP-адреса.
- Во время выполнения Telemt выбирает адрес, соответствующий целевому семейству (IPv4 или IPv6). Если установлен параметр «bind_addresses», и ни один из них не соответствует целевому семейству, попытка подключения не удалась.
  - **Описание**: Явные локальные адреса источника для исходящих прямых TCP-подключений. Если указано несколько адресов, выбор осуществляется по кругу.
  - **Пример**:

    ```toml
    [[upstreams]]
    type = "direct"
    bind_addresses = ["192.0.2.10", "192.0.2.11"]
    ```
## "cfg-upstreams-url"
- `url`
  - **Ограничения / валидация**: Применяется только к `type = "shadowsocks"`.
- Должен быть действительный URL-адрес Shadowsocks, принятый ящиком Shadowsocks.
- Плагины Shadowsocks не поддерживаются.
    - Requires `general.use_middle_proxy = false` (shadowsocks upstreams are rejected in ME mode).
  - **Описание**: URL-адрес сервера Shadowsocks, используемый для подключения к Telegram через ретранслятор Shadowsocks.
  - **Пример**:

    ```toml
    [general]
    use_middle_proxy = false

    [[upstreams]]
    type = "shadowsocks"
    url = "ss://2022-blake3-aes-256-gcm:BASE64PASSWORD@127.0.0.1:8388"
    ```
## "cfg-upstreams-address"
- `address`
  - **Ограничения / валидация**: Требуется для `type = "socks4"` и `type = "socks5"`. Должно быть `host:port` или `ip:port`.
  - **Описание**: Конечная точка прокси-сервера SOCKS, используемая для восходящих подключений.
  - **Пример**:

    ```toml
    [[upstreams]]
    type = "socks5"
    address = "127.0.0.1:9050"
    ```
## "cfg-upstreams-user_id"
- `user_id`
  - **Ограничения / валидация**: `Строка` (необязательно). Только для `type="socks4"`.
  - **Описание**: Идентификатор пользователя SOCKS4 CONNECT. Примечание. Когда выбрана область запроса, Telemt может переопределить ее с помощью выбранного значения области.
  - **Пример**:

    ```toml
    [[upstreams]]
    type = "socks4"
    address = "127.0.0.1:1080"
    user_id = "telemt"
    ```
## "cfg-upstreams-username"
- `username`
  - **Ограничения / валидация**: `Строка` (необязательно). Только для `type="socks5"`.
  - **Описание**: Имя пользователя SOCKS5 (для аутентификации по имени пользователя и паролю). Примечание. Когда выбрана область запроса, Telemt может переопределить ее с помощью выбранного значения области.
  - **Пример**:

    ```toml
    [[upstreams]]
    type = "socks5"
    address = "127.0.0.1:9050"
    username = "alice"
    ```
## "cfg-upstreams-password"
- `password`
  - **Ограничения / валидация**: `Строка` (необязательно). Только для `type="socks5"`.
  - **Описание**: Пароль SOCKS5 (для аутентификации по имени пользователя и паролю). Примечание. Когда выбрана область запроса, Telemt может переопределить ее с помощью выбранного значения области.
  - **Пример**:

    ```toml
    [[upstreams]]
    type = "socks5"
    address = "127.0.0.1:9050"
    username = "alice"
    password = "secret"
    ```


