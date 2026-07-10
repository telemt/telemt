# Telemt-Referenz der Konfigurationsparameter

Dieses Dokument listet alle Konfigurationsschlüssel auf, die `config.toml` akzeptiert.

> [!NOTE]
>
> Diese Referenz wurde mit Unterstützung von KI erstellt und gegen die Codebasis geprüft (Config-Schema, Default-Werte und Validierungslogik).

> [!WARNING]
>
> Die in diesem Dokument beschriebenen Konfigurationsparameter richten sich an erfahrene Nutzer und dienen dem Feintuning. Änderungen ohne klares Verständnis der jeweiligen Funktion können zu Instabilität oder anderem unerwarteten Verhalten führen. Gehen Sie entsprechend vorsichtig und auf eigenes Risiko vor.

> `Hot-Reload` zeigt an, ob ein geänderter Wert vom Config-Watcher ohne Prozessneustart übernommen wird; `✘` bedeutet, dass für den Runtime-Effekt ein Neustart erforderlich ist.

# Inhaltsverzeichnis
 - [Schlüssel auf oberster Ebene](#top-level-keys)
 - [logging](#logging)
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

# Schlüssel auf oberster Ebene

| Schlüssel | Typ | Default | Hot-Reload |
| --- | --- | --- | --- |
| [`include`](#include) | `String` (Proberdirektive) | — | `✔` |
| [`show_link`](#show_link) | `"*"` oder `String[]` | `[]` (`ShowLink::None`) | `✘` |
| [`logging`](#logging) | Tabelle | Default-Werte | `✘` |
| [`dc_overrides`](#dc_overrides) | `Map<String, String or String[]>` | `{}` | `✘` |
| [`default_dc`](#default_dc) | `u8` | — (effektiver Fallback: `2` im ME-Routing) | `✘` |
| [`beobachten`](#beobachten) | `bool` | `true` | `✘` |
| [`beobachten_minutes`](#beobachten_minutes) | `u64` | `10` | `✘` |
| [`beobachten_flush_secs`](#beobachten_flush_secs) | `u64` | `15` | `✘` |
| [`beobachten_file`](#beobachten_file) | `String` | `"cache/beobachten.txt"` | `✘` |

## include
  - **Einschränkungen / Validierung**: Muss eine einzeilige Direktive in der Form `include = "path/to/file.toml"` sein. Includes werden vor dem Parsen von TOML erweitert. Die maximale Einschlusstiefe beträgt 10.
  - **Beschreibung**: Fügt eine weitere TOML-Datei mit `include = "relative/or/absolute/path.toml"` hinzu; Includes werden vor dem Parsen rekursiv verarbeitet.
  - **Beispiel**:

    ```toml
    include = "secrets.toml"
    ```
## show_link
  - **Einschränkungen / Validierung**: Akzeptiert `"*"` oder ein Array von Usernamen. Leeres Array bedeutet „keine anzeigen“.
  - **Beschreibung**: Alter Link-Sichtbarkeitsselektor der obersten Ebene (`"*"` für alle User oder explizite Usernamenliste).
  - **Beispiel**:

    ```toml
    # Links für alle konfigurierten User anzeigen
    show_link = "*"

    # oder: Links nur für ausgewählte User anzeigen
    # show_link = ["alice", "bob"]
    ```
## dc_overrides
  - **Einschränkungen / Validierung**: Schlüssel muss ein positiver ganzzahliger DC-Index sein, der als String codiert ist (z. B. `"203"`). Werte müssen als `SocketAddr` (`ip:port`) geparst werden. Leere Strings werden ignoriert.
  - **Beschreibung**: Überschreibt DC-Endpunkte für nicht standardisierte DCs; der Schlüssel ist der DC-Index als String, der Wert ist eine oder mehrere `ip:port`-Adressen.
  - **Beispiel**:

    ```toml
    [dc_overrides]
    "201" = "149.154.175.50:443"
    "203" = ["149.154.175.100:443", "91.105.192.100:443"]
    ```
## default_dc
  - **Einschränkungen / Validierung**: Vorgesehener Bereich ist `1..=5`. Wenn der Wert außerhalb dieses Bereichs liegt, fällt die Runtime im Direct-Relay auf DC1-Verhalten zurück; Middle-End-Routing fällt auf `2` zurück, wenn kein Wert gesetzt ist.
  - **Beschreibung**: Default-DC-Index, der für nicht zugeordnete, nicht standardisierte DCs verwendet wird.
  - **Beispiel**:

    ```toml
    # Wenn ein Client ein unbekanntes/nicht standardisiertes DC ohne Override anfordert,
    # wird er an diesen Default-Cluster weitergeleitet (1..=5).
    default_dc = 2
    ```

# [logging]

| Schlüssel | Typ | Default | Hot-Reload |
| --- | --- | --- | --- |
| [`destination`](#loggingdestination) | `"stderr"` / `"syslog"` / `"file"` | `"stderr"` | `✘` |
| [`path`](#loggingpath) | `String` | — | `✘` |
| [`rotation`](#loggingrotation) | `"never"` / `"minutely"` / `"hourly"` / `"daily"` / `"weekly"` | `"never"` | `✘` |
| [`max_size_bytes`](#loggingmax_size_bytes) | `u64` | `0` | `✘` |
| [`max_files`](#loggingmax_files) | `usize` | `0` | `✘` |
| [`max_age_secs`](#loggingmax_age_secs) | `u64` | `0` | `✘` |

## logging.destination
  - **Einschränkungen / Validierung**: Muss `stderr`, `syslog` oder `file` sein. `syslog` wird nur auf Unix-Plattformen unterstützt. `file` erfordert `logging.path`.
  - **Beschreibung**: Wählt das Runtime-Log-Ziel aus. CLI-Flags überschreiben diesen Wert.
  - **Beispiel**:

    ```toml
    [logging]
    destination = "file"
    path = "/var/log/telemt.log"
    ```
## logging.path
  - **Einschränkungen / Validierung**: Erforderlich, wenn `logging.destination = "file"`; darf nicht leer sein.
  - **Beschreibung**: Dateipfad, der für die File-Logging verwendet wird. Bei der Zeitrotation wird der Dateiname als rollierendes Präfix verwendet.
  - **Beispiel**:

    ```toml
    [logging]
    destination = "file"
    path = "/var/log/telemt.log"
    ```
## logging.rotation
  - **Einschränkungen / Validierung**: Muss `never`, `minutely`, `hourly`, `daily` oder `weekly` sein.
  - **Beschreibung**: Zeitbasiertes Dateirotationsintervall. `weekly` rotiert an der sonntäglichen UTC-Grenze. `never` schreibt genau auf `logging.path`, es sei denn, die Größenrotation ist aktiviert.
  - **Beispiel**:

    ```toml
    [logging]
    destination = "file"
    path = "/var/log/telemt.log"
    rotation = "daily"
    ```
## logging.max_size_bytes
  - **Einschränkungen / Validierung**: `0` deaktiviert die Größenrotation.
  - **Beschreibung**: Rotiert Logdateien vor dem Schreiben des nächsten Datensatzes, wenn die aktive Datei nicht leer ist und dieser Datensatz diese Byte-Grenze überschreiten würde. Datensätze werden als Ganzes geschrieben und nicht aufgeteilt.
  - **Beispiel**:

    ```toml
    [logging]
    destination = "file"
    path = "/var/log/telemt.log"
    max_size_bytes = 104857600
    ```
## logging.max_files
  - **Einschränkungen / Validierung**: `0` deaktiviert die zählungsbasierte Aufbewahrung.
  - **Beschreibung**: Behält höchstens so viele übereinstimmende Logdateien, wobei die aktive Datei und die rotierten Archive gezählt werden. Die aktive Datei wird durch die Aufbewahrungsbereinigung niemals gelöscht.
  - **Beispiel**:

    ```toml
    [logging]
    destination = "file"
    path = "/var/log/telemt.log"
    rotation = "daily"
    max_files = 14
    ```
## logging.max_age_secs
  - **Einschränkungen / Validierung**: `0` deaktiviert die altersbasierte Aufbewahrung.
  - **Beschreibung**: Entfernt rotierte Logdateien, die älter als diese Anzahl von Sekunden sind, basierend auf der Dateiänderungszeit. Die aktive Datei wird durch die Aufbewahrungsbereinigung niemals gelöscht.
  - **Beispiel**:

    ```toml
    [logging]
    destination = "file"
    path = "/var/log/telemt.log"
    rotation = "daily"
    max_age_secs = 1209600
    ```

# [general]


| Schlüssel | Typ | Default | Hot-Reload |
| --- | --- | --- | --- |
| [`data_path`](#data_path) | `String` | — | `✘` |
| [`quota_state_path`](#quota_state_path) | `Path` | `"telemt.limit.json"` | `✘` |
| [`config_strict`](#config_strict) | `bool` | `false` | `✘` |
| [`prefer_ipv6`](#prefer_ipv6) | `bool` | `false` | `✘` |
| [`fast_mode`](#fast_mode) | `bool` | `true` | `✘` |
| [`use_middle_proxy`](#use_middle_proxy) | `bool` | `true` | `✘` |
| [`proxy_secret_path`](#proxy_secret_path) | `String` | `"proxy-secret"` | `✘` |
| [`proxy_secret_url`](#proxy_secret_url) | `String` | `"https://core.telegram.org/getProxySecret"` | `✘` |
| [`proxy_config_v4_cache_path`](#proxy_config_v4_cache_path) | `String` | `"cache/proxy-config-v4.txt"` | `✘` |
| [`proxy_config_v4_url`](#proxy_config_v4_url) | `String` | `"https://core.telegram.org/getProxyConfig"` | `✘` |
| [`proxy_config_v6_cache_path`](#proxy_config_v6_cache_path) | `String` | `"cache/proxy-config-v6.txt"` | `✘` |
| [`proxy_config_v6_url`](#proxy_config_v6_url) | `String` | `"https://core.telegram.org/getProxyConfigV6"` | `✘` |
| [`ad_tag`](#ad_tag) | `String` | — | `✔` |
| [`middle_proxy_nat_ip`](#middle_proxy_nat_ip) | `IpAddr` | — | `✘` |
| [`middle_proxy_nat_probe`](#middle_proxy_nat_probe) | `bool` | `true` | `✘` |
| [`middle_proxy_nat_stun`](#middle_proxy_nat_stun) | `String` | — | `✘` |
| [`middle_proxy_nat_stun_servers`](#middle_proxy_nat_stun_servers) | `String[]` | `[]` | `✘` |
| [`stun_nat_probe_concurrency`](#stun_nat_probe_concurrency) | `usize` | `8` | `✘` |
| [`middle_proxy_pool_size`](#middle_proxy_pool_size) | `usize` | `8` | `✘` |
| [`middle_proxy_warm_standby`](#middle_proxy_warm_standby) | `usize` | `16` | `✘` |
| [`me_init_retry_attempts`](#me_init_retry_attempts) | `u32` | `0` | `✘` |
| [`me2dc_fallback`](#me2dc_fallback) | `bool` | `true` | `✘` |
| [`me2dc_fast`](#me2dc_fast) | `bool` | `false` | `✘` |
| [`me_keepalive_enabled`](#me_keepalive_enabled) | `bool` | `true` | `✘` |
| [`me_keepalive_interval_secs`](#me_keepalive_interval_secs) | `u64` | `8` | `✘` |
| [`me_keepalive_jitter_secs`](#me_keepalive_jitter_secs) | `u64` | `2` | `✘` |
| [`me_keepalive_payload_random`](#me_keepalive_payload_random) | `bool` | `true` | `✘` |
| [`rpc_proxy_req_every`](#rpc_proxy_req_every) | `u64` | `0` | `✘` |
| [`me_writer_cmd_channel_capacity`](#me_writer_cmd_channel_capacity) | `usize` | `4096` | `✘` |
| [`me_route_channel_capacity`](#me_route_channel_capacity) | `usize` | `768` | `✘` |
| [`me_c2me_channel_capacity`](#me_c2me_channel_capacity) | `usize` | `1024` | `✘` |
| [`me_c2me_send_timeout_ms`](#me_c2me_send_timeout_ms) | `u64` | `4000` | `✘` |
| [`me_reader_route_data_wait_ms`](#me_reader_route_data_wait_ms) | `u64` | `2` | `✔` |
| [`me_d2c_flush_batch_max_frames`](#me_d2c_flush_batch_max_frames) | `usize` | `32` | `✔` |
| [`me_d2c_flush_batch_max_bytes`](#me_d2c_flush_batch_max_bytes) | `usize` | `131072` | `✔` |
| [`me_d2c_flush_batch_max_delay_us`](#me_d2c_flush_batch_max_delay_us) | `u64` | `500` | `✔` |
| [`me_d2c_ack_flush_immediate`](#me_d2c_ack_flush_immediate) | `bool` | `true` | `✔` |
| [`me_quota_soft_overshoot_bytes`](#me_quota_soft_overshoot_bytes) | `u64` | `65536` | `✔` |
| [`me_d2c_frame_buf_shrink_threshold_bytes`](#me_d2c_frame_buf_shrink_threshold_bytes) | `usize` | `262144` | `✔` |
| [`direct_relay_copy_buf_c2s_bytes`](#direct_relay_copy_buf_c2s_bytes) | `usize` | `65536` | `✔` |
| [`direct_relay_copy_buf_s2c_bytes`](#direct_relay_copy_buf_s2c_bytes) | `usize` | `262144` | `✔` |
| [`crypto_pending_buffer`](#crypto_pending_buffer) | `usize` | `262144` | `✘` |
| [`max_client_frame`](#max_client_frame) | `usize` | `16777216` | `✘` |
| [`desync_all_full`](#desync_all_full) | `bool` | `false` | `✔` |
| [`beobachten`](#beobachten) | `bool` | `true` | `✘` |
| [`beobachten_minutes`](#beobachten_minutes) | `u64` | `10` | `✘` |
| [`beobachten_flush_secs`](#beobachten_flush_secs) | `u64` | `15` | `✘` |
| [`beobachten_file`](#beobachten_file) | `String` | `"cache/beobachten.txt"` | `✘` |
| [`hardswap`](#hardswap) | `bool` | `true` | `✔` |
| [`me_warmup_stagger_enabled`](#me_warmup_stagger_enabled) | `bool` | `true` | `✘` |
| [`me_warmup_step_delay_ms`](#me_warmup_step_delay_ms) | `u64` | `500` | `✘` |
| [`me_warmup_step_jitter_ms`](#me_warmup_step_jitter_ms) | `u64` | `300` | `✘` |
| [`me_reconnect_max_concurrent_per_dc`](#me_reconnect_max_concurrent_per_dc) | `u32` | `8` | `✘` |
| [`me_reconnect_backoff_base_ms`](#me_reconnect_backoff_base_ms) | `u64` | `500` | `✘` |
| [`me_reconnect_backoff_cap_ms`](#me_reconnect_backoff_cap_ms) | `u64` | `30000` | `✘` |
| [`me_reconnect_fast_retry_count`](#me_reconnect_fast_retry_count) | `u32` | `16` | `✘` |
| [`me_single_endpoint_shadow_writers`](#me_single_endpoint_shadow_writers) | `u8` | `2` | `✔` |
| [`me_single_endpoint_outage_mode_enabled`](#me_single_endpoint_outage_mode_enabled) | `bool` | `true` | `✔` |
| [`me_single_endpoint_outage_disable_quarantine`](#me_single_endpoint_outage_disable_quarantine) | `bool` | `true` | `✔` |
| [`me_single_endpoint_outage_backoff_min_ms`](#me_single_endpoint_outage_backoff_min_ms) | `u64` | `250` | `✔` |
| [`me_single_endpoint_outage_backoff_max_ms`](#me_single_endpoint_outage_backoff_max_ms) | `u64` | `3000` | `✔` |
| [`me_single_endpoint_shadow_rotate_every_secs`](#me_single_endpoint_shadow_rotate_every_secs) | `u64` | `900` | `✔` |
| [`me_floor_mode`](#me_floor_mode) | `"static"` oder `"adaptive"` | `"adaptive"` | `✔` |
| [`me_adaptive_floor_idle_secs`](#me_adaptive_floor_idle_secs) | `u64` | `90` | `✔` |
| [`me_adaptive_floor_min_writers_single_endpoint`](#me_adaptive_floor_min_writers_single_endpoint) | `u8` | `1` | `✔` |
| [`me_adaptive_floor_min_writers_multi_endpoint`](#me_adaptive_floor_min_writers_multi_endpoint) | `u8` | `1` | `✔` |
| [`me_adaptive_floor_recover_grace_secs`](#me_adaptive_floor_recover_grace_secs) | `u64` | `180` | `✔` |
| [`me_adaptive_floor_writers_per_core_total`](#me_adaptive_floor_writers_per_core_total) | `u16` | `48` | `✔` |
| [`me_adaptive_floor_cpu_cores_override`](#me_adaptive_floor_cpu_cores_override) | `u16` | `0` | `✔` |
| [`me_adaptive_floor_max_extra_writers_single_per_core`](#me_adaptive_floor_max_extra_writers_single_per_core) | `u16` | `1` | `✔` |
| [`me_adaptive_floor_max_extra_writers_multi_per_core`](#me_adaptive_floor_max_extra_writers_multi_per_core) | `u16` | `2` | `✔` |
| [`me_adaptive_floor_max_active_writers_per_core`](#me_adaptive_floor_max_active_writers_per_core) | `u16` | `64` | `✔` |
| [`me_adaptive_floor_max_warm_writers_per_core`](#me_adaptive_floor_max_warm_writers_per_core) | `u16` | `64` | `✔` |
| [`me_adaptive_floor_max_active_writers_global`](#me_adaptive_floor_max_active_writers_global) | `u32` | `256` | `✔` |
| [`me_adaptive_floor_max_warm_writers_global`](#me_adaptive_floor_max_warm_writers_global) | `u32` | `256` | `✔` |
| [`upstream_connect_retry_attempts`](#upstream_connect_retry_attempts) | `u32` | `2` | `✘` |
| [`upstream_connect_retry_backoff_ms`](#upstream_connect_retry_backoff_ms) | `u64` | `100` | `✘` |
| [`upstream_connect_budget_ms`](#upstream_connect_budget_ms) | `u64` | `3000` | `✘` |
| [`tg_connect`](#tg_connect) | `u64` | `10` | `✘` |
| [`upstream_unhealthy_fail_threshold`](#upstream_unhealthy_fail_threshold) | `u32` | `5` | `✘` |
| [`upstream_connect_failfast_hard_errors`](#upstream_connect_failfast_hard_errors) | `bool` | `false` | `✘` |
| [`stun_iface_mismatch_ignore`](#stun_iface_mismatch_ignore) | `bool` | `false` | `✘` |
| [`unknown_dc_log_path`](#unknown_dc_log_path) | `String` | `"unknown-dc.txt"` | `✘` |
| [`unknown_dc_file_log_enabled`](#unknown_dc_file_log_enabled) | `bool` | `false` | `✘` |
| [`log_level`](#log_level) | `"debug"`, `"verbose"`, `"normal"` oder `"silent"` | `"normal"` | `✔` |
| [`disable_colors`](#disable_colors) | `bool` | `false` | `✘` |
| [`me_socks_kdf_policy`](#me_socks_kdf_policy) | `"strict"` oder `"compat"` | `"strict"` | `✔` |
| [`me_route_backpressure_enabled`](#me_route_backpressure_enabled) | `bool` | `false` | `✔` |
| [`me_route_fairshare_enabled`](#me_route_fairshare_enabled) | `bool` | `false` | `✔` |
| [`me_route_backpressure_base_timeout_ms`](#me_route_backpressure_base_timeout_ms) | `u64` | `25` | `✔` |
| [`me_route_backpressure_high_timeout_ms`](#me_route_backpressure_high_timeout_ms) | `u64` | `120` | `✔` |
| [`me_route_backpressure_high_watermark_pct`](#me_route_backpressure_high_watermark_pct) | `u8` | `80` | `✔` |
| [`me_health_interval_ms_unhealthy`](#me_health_interval_ms_unhealthy) | `u64` | `1000` | `✔` |
| [`me_health_interval_ms_healthy`](#me_health_interval_ms_healthy) | `u64` | `3000` | `✔` |
| [`me_admission_poll_ms`](#me_admission_poll_ms) | `u64` | `1000` | `✔` |
| [`me_warn_rate_limit_ms`](#me_warn_rate_limit_ms) | `u64` | `5000` | `✔` |
| [`me_route_no_writer_mode`](#me_route_no_writer_mode) | `"async_recovery_failfast"`, `"inline_recovery_legacy"` oder `"hybrid_async_persistent"` | `"hybrid_async_persistent"` | `✘` |
| [`me_route_no_writer_wait_ms`](#me_route_no_writer_wait_ms) | `u64` | `250` | `✘` |
| [`me_route_hybrid_max_wait_ms`](#me_route_hybrid_max_wait_ms) | `u64` | `3000` | `✘` |
| [`me_route_blocking_send_timeout_ms`](#me_route_blocking_send_timeout_ms) | `u64` | `250` | `✘` |
| [`me_route_inline_recovery_attempts`](#me_route_inline_recovery_attempts) | `u32` | `3` | `✘` |
| [`me_route_inline_recovery_wait_ms`](#me_route_inline_recovery_wait_ms) | `u64` | `3000` | `✘` |
| [`fast_mode_min_tls_record`](#fast_mode_min_tls_record) | `usize` | `0` | `✘` |
| [`update_every`](#update_every) | `u64` | `300` | `✔` |
| [`me_reinit_every_secs`](#me_reinit_every_secs) | `u64` | `900` | `✔` |
| [`me_hardswap_warmup_delay_min_ms`](#me_hardswap_warmup_delay_min_ms) | `u64` | `1000` | `✔` |
| [`me_hardswap_warmup_delay_max_ms`](#me_hardswap_warmup_delay_max_ms) | `u64` | `2000` | `✔` |
| [`me_hardswap_warmup_extra_passes`](#me_hardswap_warmup_extra_passes) | `u8` | `3` | `✔` |
| [`me_hardswap_warmup_pass_backoff_base_ms`](#me_hardswap_warmup_pass_backoff_base_ms) | `u64` | `500` | `✔` |
| [`me_config_stable_snapshots`](#me_config_stable_snapshots) | `u8` | `2` | `✔` |
| [`me_config_apply_cooldown_secs`](#me_config_apply_cooldown_secs) | `u64` | `300` | `✔` |
| [`me_snapshot_require_http_2xx`](#me_snapshot_require_http_2xx) | `bool` | `true` | `✔` |
| [`me_snapshot_reject_empty_map`](#me_snapshot_reject_empty_map) | `bool` | `true` | `✔` |
| [`me_snapshot_min_proxy_for_lines`](#me_snapshot_min_proxy_for_lines) | `u32` | `1` | `✔` |
| [`proxy_secret_stable_snapshots`](#proxy_secret_stable_snapshots) | `u8` | `2` | `✔` |
| [`proxy_secret_rotate_runtime`](#proxy_secret_rotate_runtime) | `bool` | `true` | `✔` |
| [`me_secret_atomic_snapshot`](#me_secret_atomic_snapshot) | `bool` | `true` | `✔` |
| [`proxy_secret_len_max`](#proxy_secret_len_max) | `usize` | `256` | `✔` |
| [`me_pool_drain_ttl_secs`](#me_pool_drain_ttl_secs) | `u64` | `90` | `✔` |
| [`me_instadrain`](#me_instadrain) | `bool` | `false` | `✔` |
| [`me_pool_drain_threshold`](#me_pool_drain_threshold) | `u64` | `32` | `✔` |
| [`me_pool_drain_soft_evict_enabled`](#me_pool_drain_soft_evict_enabled) | `bool` | `true` | `✘` |
| [`me_pool_drain_soft_evict_grace_secs`](#me_pool_drain_soft_evict_grace_secs) | `u64` | `10` | `✘` |
| [`me_pool_drain_soft_evict_per_writer`](#me_pool_drain_soft_evict_per_writer) | `u8` | `2` | `✘` |
| [`me_pool_drain_soft_evict_budget_per_core`](#me_pool_drain_soft_evict_budget_per_core) | `u16` | `16` | `✘` |
| [`me_pool_drain_soft_evict_cooldown_ms`](#me_pool_drain_soft_evict_cooldown_ms) | `u64` | `1000` | `✘` |
| [`me_bind_stale_mode`](#me_bind_stale_mode) | `"never"`, `"ttl"` oder `"always"` | `"ttl"` | `✔` |
| [`me_bind_stale_ttl_secs`](#me_bind_stale_ttl_secs) | `u64` | `90` | `✔` |
| [`me_pool_min_fresh_ratio`](#me_pool_min_fresh_ratio) | `f32` | `0.8` | `✔` |
| [`me_reinit_drain_timeout_secs`](#me_reinit_drain_timeout_secs) | `u64` | `90` | `✔` |
| [`proxy_secret_auto_reload_secs`](#proxy_secret_auto_reload_secs) | `u64` | `3600` | `✔` |
| [`proxy_config_auto_reload_secs`](#proxy_config_auto_reload_secs) | `u64` | `3600` | `✔` |
| [`me_reinit_singleflight`](#me_reinit_singleflight) | `bool` | `true` | `✔` |
| [`me_reinit_trigger_channel`](#me_reinit_trigger_channel) | `usize` | `64` | `✘` |
| [`me_reinit_coalesce_window_ms`](#me_reinit_coalesce_window_ms) | `u64` | `200` | `✔` |
| [`me_deterministic_writer_sort`](#me_deterministic_writer_sort) | `bool` | `true` | `✔` |
| [`me_writer_pick_mode`](#me_writer_pick_mode) | `"sorted_rr"` oder `"p2c"` | `"p2c"` | `✔` |
| [`me_writer_pick_sample_size`](#me_writer_pick_sample_size) | `u8` | `3` | `✔` |
| [`ntp_check`](#ntp_check) | `bool` | `true` | `✘` |
| [`ntp_servers`](#ntp_servers) | `String[]` | `["pool.ntp.org"]` | `✘` |
| [`auto_degradation_enabled`](#auto_degradation_enabled) | `bool` | `true` | `✘` |
| [`degradation_min_unavailable_dc_groups`](#degradation_min_unavailable_dc_groups) | `u8` | `2` | `✘` |
| [`rst_on_close`](#rst_on_close) | `"off"`, `"errors"` oder `"always"` | `"off"` | `✘` |

## data_path
  - **Einschränkungen / Validierung**: `String` (optional).
  - **Beschreibung**: Optionaler Runtimedatenverzeichnispfad.
  - **Beispiel**:

    ```toml
    [general]
    data_path = "/var/lib/telemt"
    ```
## quota_state_path
  - **Einschränkungen / Validierung**: `Path`. Relative Pfade werden aus dem Arbeitsverzeichnis des Prozesses aufgelöst.
  - **Beschreibung**: JSON-Statusdatei, die verwendet wird, um den Kontingentverbrauch pro User während der Runtime beizubehalten.
  - **Beispiel**:

    ```toml
    [general]
    quota_state_path = "telemt.limit.json"
    ```
## config_strict
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Lehnt unbekannte TOML-Schlüssel während des Ladens der Konfiguration ab. Der Start schlägt schnell fehl; Hot-Reload lehnt den neuen Snapshot ab und behält die aktuelle Konfiguration bei.
  - **Beispiel**:

    ```toml
    [general]
    config_strict = true
    ```
## prefer_ipv6
  - **Einschränkungen / Validierung**: Veraltet. Verwenden Sie `network.prefer`.
  - **Beschreibung**: Veraltetes Legacy-Einstellungsflag IPv6 wurde nach `network.prefer` migriert.
  - **Beispiel**:

    ```toml
    [network]
    prefer = 6
    ```
## fast_mode
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Ermöglicht Fast-Path-Optimierungen für die Traffic-Verarbeitung.
  - **Beispiel**:

    ```toml
    [general]
    fast_mode = true
    ```
## use_middle_proxy
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert den Transportmodus ME; Wenn `false`, greift die Runtime auf direktes DC-Routing zurück.
  - **Beispiel**:

    ```toml
    [general]
    use_middle_proxy = true
    ```
## proxy_secret_path
  - **Einschränkungen / Validierung**: `String`. Wenn ausgelassen, lautet der Standardpfad `"proxy-secret"`. Leere Werte werden von TOML/serde akzeptiert, schlagen jedoch wahrscheinlich zur Runtime fehl (ungültiger Dateipfad).
  - **Beschreibung**: Pfad zur Telegram-Infrastruktur `proxy-secret` Cache-Datei, die von ME Handshake/RPC-Authentifizierung verwendet wird. Telemt versucht immer zuerst einen neuen Download von `https://core.telegram.org/getProxySecret` (es sei denn, `proxy_secret_url` ist festgelegt), speichert ihn bei Erfolg auf diesem Pfad zwischen und greift bei einem Download-Fehler auf das Lesen der zwischengespeicherten Datei (beliebiges Alter) zurück.
  - **Beispiel**:

    ```toml
    [general]
    proxy_secret_path = "proxy-secret"
    ```
## proxy_secret_url
  - **Einschränkungen / Validierung**: `String`. Wenn ausgelassen, wird `"https://core.telegram.org/getProxySecret"` verwendet.
  - **Beschreibung**: Optionale URL zum Abrufen der von ME Handshake/RPC-Authentifizierung verwendeten Datei `proxy-secret`. Telemt versucht immer zuerst einen neuen Download von dieser URL (mit Fallback auf `https://core.telegram.org/getProxySecret`, falls nicht vorhanden).
  - **Beispiel**:

    ```toml
    [general]
    proxy_secret_url = "https://core.telegram.org/getProxySecret"
    ```
## proxy_config_v4_cache_path
  - **Einschränkungen / Validierung**: `String`. Wenn gesetzt, darf es nicht leer/nur Leerzeichen sein.
  - **Beschreibung**: Optionaler Disk-Cache-Pfad für den Raw-Snapshot `getProxyConfig` (IPv4). Beim Start versucht Telemt zunächst, einen neuen Snapshot abzurufen; Bei einem Abruffehler oder einem leeren Snapshot wird auf diese Cache-Datei zurückgegriffen, sofern vorhanden und nicht leer.
  - **Beispiel**:

    ```toml
    [general]
    proxy_config_v4_cache_path = "cache/proxy-config-v4.txt"
    ```
## proxy_config_v4_url
- **Einschränkungen / Validierung**: `String`. Wenn ausgelassen, wird `"https://core.telegram.org/getProxyConfig"` verwendet.
- **Beschreibung**: Optionale URL zum Abrufen von Raw-`getProxyConfig` (IPv4). Telemt versucht immer zuerst einen neuen Download von dieser URL (mit Fallback auf `https://core.telegram.org/getProxyConfig`, falls nicht vorhanden).
- **Beispiel**:

  ```toml
  [general]
  proxy_config_v4_url = "https://core.telegram.org/getProxyConfig"
  ```
## proxy_config_v6_cache_path
  - **Einschränkungen / Validierung**: `String`. Wenn gesetzt, darf es nicht leer/nur Leerzeichen sein.
  - **Beschreibung**: Optionaler Disk-Cache-Pfad für den Raw-Snapshot `getProxyConfigV6` (IPv6). Beim Start versucht Telemt zunächst, einen neuen Snapshot abzurufen; Bei einem Abruffehler oder einem leeren Snapshot wird auf diese Cache-Datei zurückgegriffen, sofern vorhanden und nicht leer.
  - **Beispiel**:

    ```toml
    [general]
    proxy_config_v6_cache_path = "cache/proxy-config-v6.txt"
    ```
## proxy_config_v6_url
- **Einschränkungen / Validierung**: `String`. Wenn ausgelassen, wird `"https://core.telegram.org/getProxyConfigV6"` verwendet.
- **Beschreibung**: Optionale URL zum Abrufen von Raw-`getProxyConfigV6` (IPv6). Telemt versucht immer zuerst einen neuen Download von dieser URL (mit Fallback auf `https://core.telegram.org/getProxyConfigV6`, falls nicht vorhanden).
- **Beispiel**:

  ```toml
  [general]
  proxy_config_v6_url = "https://core.telegram.org/getProxyConfigV6"
  ```
## ad_tag
  - **Einschränkungen / Validierung**: `String` (optional). Wenn gesetzt, müssen genau 32 Hexadezimalzeichen vorhanden sein. Ungültige Werte werden während des Ladens der Konfiguration deaktiviert.
  - **Beschreibung**: Globaler Fallback-Sponsored-Channel `ad_tag` (wird verwendet, wenn der User keine Override in `access.user_ad_tags` hat). Ein Tag, der nur aus Nullen besteht, wird akzeptiert, hat aber keine Auswirkung (und es wird davor gewarnt), bis er durch einen echten Tag von `@MTProxybot`.
  - **Beispiel**:

    ```toml
    [general]
    ad_tag = "00112233445566778899aabbccddeeff"
    ```
## middle_proxy_nat_ip
  - **Einschränkungen / Validierung**: `IpAddr` (optional).
  - **Beschreibung**: Manuelle öffentliche NAT IP-Override, die bei Festlegung als ME-Adressmaterial verwendet wird.
  - **Beispiel**:

    ```toml
    [general]
    middle_proxy_nat_ip = "203.0.113.10"
    ```
## middle_proxy_nat_probe
  - **Einschränkungen / Validierung**: `bool`. Die effektive Prüfung wird durch `network.stun_use` begrenzt (bei `network.stun_use = false` ist die Prüfung mit STUN deaktiviert, auch wenn dieses Flag `true` ist).
  - **Beschreibung**: Ermöglicht STUN-basierte NAT-Prüfungen zur Erkennung des öffentlichen IP:Ports, der von der ME-Schlüsselableitung in NAT-Umgebungen verwendet wird.
  - **Beispiel**:

    ```toml
    [general]
    middle_proxy_nat_probe = true
    ```
## middle_proxy_nat_stun
  - **Einschränkungen / Validierung**: Veraltet. Verwenden Sie `network.stun_servers`.
  - **Beschreibung**: Veralteter älterer einzelner STUN-Server für NAT-Prüfungen. Während des Ladens der Konfiguration wird es in `network.stun_servers` zusammengeführt, es sei denn, `network.stun_servers` ist explizit festgelegt.
  - **Beispiel**:

    ```toml
    [network]
    stun_servers = ["stun.l.google.com:19302"]
    ```
## middle_proxy_nat_stun_servers
  - **Einschränkungen / Validierung**: Veraltet. Verwenden Sie `network.stun_servers`.
  - **Beschreibung**: Veraltete Legacy-STUN-Liste für NAT-Probing-Fallback. Während des Ladens der Konfiguration wird es in `network.stun_servers` zusammengeführt, es sei denn, `network.stun_servers` ist explizit festgelegt.
  - **Beispiel**:

    ```toml
    [network]
    stun_servers = ["stun.l.google.com:19302"]
    ```
## stun_nat_probe_concurrency
  - **Einschränkungen / Validierung**: Muss `> 0` sein.
  - **Beschreibung**: Maximale Anzahl paralleler STUN-Prüfungen während der NAT/öffentlichen Endpunkterkennung.
  - **Beispiel**:

    ```toml
    [general]
    stun_nat_probe_concurrency = 8
    ```
## middle_proxy_pool_size
  - **Einschränkungen / Validierung**: `usize`. Der effektive Wert ist `max(value, 1)` zur Runtime (daher verhält sich `0` wie `1`).
  - **Beschreibung**: Zielgröße des aktiven ME Writer-Pools.
  - **Beispiel**:

    ```toml
    [general]
    middle_proxy_pool_size = 8
    ```
## middle_proxy_warm_standby
  - **Einschränkungen / Validierung**: `usize`.
  - **Beschreibung**: Anzahl der Warm-Standby-Verbindungen ME, die vorinitialisiert bleiben.
  - **Beispiel**:

    ```toml
    [general]
    middle_proxy_warm_standby = 16
    ```
## me_init_retry_attempts
  - **Einschränkungen / Validierung**: `0..=1_000_000` (`0` bedeutet unbegrenzte Wiederholungsversuche).
  - **Beschreibung**: Startversuche für ME-Poolinitialisierung.
  - **Beispiel**:

    ```toml
    [general]
    me_init_retry_attempts = 0
    ```
## me2dc_fallback
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Ermöglicht Direct-DC Fallback, wenn ME nicht verfügbar ist. Mit `use_middle_proxy = true` öffnet der Startup zuerst das Direct-DC-Routing und verschiebt neue Sitzungen nach ME, nachdem die ME-Bereitschaft festgestellt wurde.
  - **Beispiel**:

    ```toml
    [general]
    me2dc_fallback = true
    ```
## me2dc_fast
  - **Einschränkungen / Validierung**: `bool`. Nur aktiv, wenn `use_middle_proxy = true` und `me2dc_fallback = true`.
  - **Beschreibung**: Schneller ME->Direct Fallback-Modus für neue Sitzungen, nachdem ME mindestens einmal bereit war. Der anfängliche Direct-First-Start-Fallback wird durch `me2dc_fallback`.
  - **Beispiel**:

    ```toml
    [general]
    use_middle_proxy = true
    me2dc_fallback = true
    me2dc_fast = true
    ```
## me_keepalive_enabled
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert regelmäßige ME Keepalive-Padding-Frames.
  - **Beispiel**:

    ```toml
    [general]
    me_keepalive_enabled = true
    ```
## me_keepalive_interval_secs
  - **Einschränkungen / Validierung**: `u64` (Sekunden).
  - **Beschreibung**: Basis ME Keepalive-Intervall in Sekunden.
  - **Beispiel**:

    ```toml
    [general]
    me_keepalive_interval_secs = 8
    ```
## me_keepalive_jitter_secs
  - **Einschränkungen / Validierung**: `u64` (Sekunden).
  - **Beschreibung**: Keepalive Jitter in Sekunden, um synchronisierte Bursts zu reduzieren.
  - **Beispiel**:

    ```toml
    [general]
    me_keepalive_jitter_secs = 2
    ```
## me_keepalive_payload_random
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Zufällige Anzahl der Keepalive-Payloadbytes anstelle einer festen Null-Payload.
  - **Beispiel**:

    ```toml
    [general]
    me_keepalive_payload_random = true
    ```
## rpc_proxy_req_every
  - **Einschränkungen / Validierung**: `0` oder innerhalb von `10..=300` (Sekunden).
  - **Beschreibung**: Intervall für Service-`RPC_PROXY_REQ`-Aktivitätssignale an ME (`0` deaktiviert).
  - **Beispiel**:

    ```toml
    [general]
    rpc_proxy_req_every = 0
    ```
## me_writer_cmd_channel_capacity
  - **Einschränkungen / Validierung**: Muss `> 0` sein.
  - **Beschreibung**: Kapazität des Befehlskanals pro Autor.
  - **Beispiel**:

    ```toml
    [general]
    me_writer_cmd_channel_capacity = 4096
    ```
## me_route_channel_capacity
  - **Einschränkungen / Validierung**: Muss `> 0` sein.
  - **Beschreibung**: Kapazität des ME-Antwortroutenkanals pro Verbindung.
  - **Beispiel**:

    ```toml
    [general]
    me_route_channel_capacity = 768
    ```
## me_c2me_channel_capacity
  - **Einschränkungen / Validierung**: Muss `> 0` sein.
  - **Beschreibung**: Kapazität der Befehlswarteschlange pro Client (Client-Leser -> ME Absender).
  - **Beispiel**:

    ```toml
    [general]
    me_c2me_channel_capacity = 1024
    ```
## me_c2me_send_timeout_ms
  - **Einschränkungen / Validierung**: `0..=60000` (Millisekunden).
  - **Beschreibung**: Maximale Wartezeit für das Einreihen von Client-Befehlen in die Warteschlange ME, wenn die Warteschlange pro Client voll ist (`0` behält die veraltete unbegrenzte Wartezeit bei).
  - **Beispiel**:

    ```toml
    [general]
    me_c2me_send_timeout_ms = 4000
    ```
## me_reader_route_data_wait_ms
  - **Einschränkungen / Validierung**: `0..=20` (Millisekunden).
  - **Beschreibung**: Begrenzte Wartezeit für die Weiterleitung von ME DATEN an die Warteschlange pro Verbindung (`0` = keine Wartezeit).
  - **Beispiel**:

    ```toml
    [general]
    me_reader_route_data_wait_ms = 2
    ```
## me_d2c_flush_batch_max_frames
  - **Einschränkungen / Validierung**: Muss innerhalb von `1..=512` liegen.
  - **Beschreibung**: Max ME->Client-Frames wurden vor dem Flush zusammengeführt.
  - **Beispiel**:

    ```toml
    [general]
    me_d2c_flush_batch_max_frames = 32
    ```
## me_d2c_flush_batch_max_bytes
  - **Einschränkungen / Validierung**: Muss innerhalb von `4096..=2097152` (Bytes) liegen.
  - **Beschreibung**: Max. ME->Client-Payloadbytes, die vor dem Leeren zusammengeführt werden.
  - **Beispiel**:

    ```toml
    [general]
    me_d2c_flush_batch_max_bytes = 131072
    ```
## me_d2c_flush_batch_max_delay_us
  - **Einschränkungen / Validierung**: `0..=5000` (Mikrosekunden).
  - **Beschreibung**: Maximale Mikrosekunden-Wartezeit für die Zusammenführung weiterer ME->Client-Frames (`0` deaktiviert die zeitgesteuerte Zusammenführung).
  - **Beispiel**:

    ```toml
    [general]
    me_d2c_flush_batch_max_delay_us = 500
    ```
## me_d2c_ack_flush_immediate
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Leert den Client-Writer sofort nach dem Quick-Ack-Schreiben.
  - **Beispiel**:

    ```toml
    [general]
    me_d2c_ack_flush_immediate = true
    ```
## me_quota_soft_overshoot_bytes
  - **Einschränkungen / Validierung**: `0..=16777216` (Byte).
  - **Beschreibung**: Zusätzliches Kontingent pro Route (Bytes) wird toleriert, bevor die schreiberseitige Kontingentdurchsetzung Routendaten löscht.
  - **Beispiel**:

    ```toml
    [general]
    me_quota_soft_overshoot_bytes = 65536
    ```
## me_d2c_frame_buf_shrink_threshold_bytes
  - **Einschränkungen / Validierung**: Muss innerhalb von `4096..=16777216` (Bytes) liegen.
  - **Beschreibung**: Schwellenwert für die Verkleinerung übergroßer ME->Client-Frame-Aggregationspuffer nach dem Leeren.
  - **Beispiel**:

    ```toml
    [general]
    me_d2c_frame_buf_shrink_threshold_bytes = 262144
    ```
## direct_relay_copy_buf_c2s_bytes
  - **Einschränkungen / Validierung**: Muss innerhalb von `4096..=1048576` (Bytes) liegen.
  - **Beschreibung**: Puffergröße für Client->DC-Richtung im direkten Relay kopieren.
  - **Beispiel**:

    ```toml
    [general]
    direct_relay_copy_buf_c2s_bytes = 65536
    ```
## direct_relay_copy_buf_s2c_bytes
  - **Einschränkungen / Validierung**: Muss innerhalb von `8192..=2097152` (Bytes) liegen.
  - **Beschreibung**: Puffergröße für DC->Client-Richtung im direkten Relay kopieren.
  - **Beispiel**:

    ```toml
    [general]
    direct_relay_copy_buf_s2c_bytes = 262144
    ```
## crypto_pending_buffer
  - **Einschränkungen / Validierung**: `usize` (Byte).
  - **Beschreibung**: Maximaler Puffer für ausstehenden Chiffretext pro Client-Writer (Byte).
  - **Beispiel**:

    ```toml
    [general]
    crypto_pending_buffer = 262144
    ```
## max_client_frame
  - **Einschränkungen / Validierung**: `usize` (Byte).
  - **Beschreibung**: Maximal zulässige Client-Framegröße MTProto (Byte).
  - **Beispiel**:

    ```toml
    [general]
    max_client_frame = 16777216
    ```
## desync_all_full
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Gibt vollständige forensische Krypto-Desync-Protokolle für jedes Ereignis aus.
  - **Beispiel**:

    ```toml
    [general]
    desync_all_full = false
    ```
## beobachten
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert forensische Beobachtungs-Buckets pro IP und hängt TLS JA3/JA4-Fingerprint-Snapshots an die Beobachten-Ausgabe an, sofern verfügbar.
  - **Beispiel**:

    ```toml
    [general]
    beobachten = true
    ```
## beobachten_minutes
  - **Einschränkungen / Validierung**: Muss `> 0` (Minuten) sein.
  - **Beschreibung**: Aufbewahrungsfenster (Minuten) für Per-IP-Beobachtungs-Buckets und speicherinterne TLS Fingerprint-Buckets.
  - **Beispiel**:

    ```toml
    [general]
    beobachten_minutes = 10
    ```
## beobachten_flush_secs
  - **Einschränkungen / Validierung**: Muss `> 0` (Sekunden) sein.
  - **Beschreibung**: Snapshot Spülintervall (Sekunden) für die Beobachtungsausgabedatei.
  - **Beispiel**:

    ```toml
    [general]
    beobachten_flush_secs = 15
    ```
## beobachten_file
  - **Einschränkungen / Validierung**: Darf nicht leer/nur Leerzeichen sein.
  - **Beschreibung**: Pfad der Beobachtungs-Snapshot-Ausgabedatei.
  - **Beispiel**:

    ```toml
    [general]
    beobachten_file = "cache/beobachten.txt"
    ```
## hardswap
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Ermöglicht generationsbasierte ME Hardswap-Strategie.
  - **Beispiel**:

    ```toml
    [general]
    hardswap = true
    ```
## me_warmup_stagger_enabled
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Staggers zusätzliche ME Warmup-Zyklen, um Verbindungsspitzen zu vermeiden.
  - **Beispiel**:

    ```toml
    [general]
    me_warmup_stagger_enabled = true
    ```
## me_warmup_step_delay_ms
  - **Einschränkungen / Validierung**: `u64` (Millisekunden).
  - **Beschreibung**: Basisverzögerung in Millisekunden zwischen Warmup-Dial-Schritten.
  - **Beispiel**:

    ```toml
    [general]
    me_warmup_step_delay_ms = 500
    ```
## me_warmup_step_jitter_ms
  - **Einschränkungen / Validierung**: `u64` (Millisekunden).
  - **Beschreibung**: Zusätzliche zufällige Verzögerung in Millisekunden für Warmup-Schritte.
  - **Beispiel**:

    ```toml
    [general]
    me_warmup_step_jitter_ms = 300
    ```
## me_reconnect_max_concurrent_per_dc
  - **Einschränkungen / Validierung**: `u32`. Der effektive Wert ist `max(value, 1)` zur Runtime (daher verhält sich `0` wie `1`).
  - **Beschreibung**: Begrenzt gleichzeitige Reconnect-Worker pro DC während der Gesundheitswiederherstellung.
  - **Beispiel**:

    ```toml
    [general]
    me_reconnect_max_concurrent_per_dc = 8
    ```
## me_reconnect_backoff_base_ms
  - **Einschränkungen / Validierung**: `u64` (Millisekunden).
  - **Beschreibung**: Anfänglicher Reconnect-Backoff in Millisekunden.
  - **Beispiel**:

    ```toml
    [general]
    me_reconnect_backoff_base_ms = 500
    ```
## me_reconnect_backoff_cap_ms
  - **Einschränkungen / Validierung**: `u64` (Millisekunden).
  - **Beschreibung**: Maximale Reconnect-Backoff-Obergrenze in Millisekunden.
  - **Beispiel**:

    ```toml
    [general]
    me_reconnect_backoff_cap_ms = 30000
    ```
## me_reconnect_fast_retry_count
  - **Einschränkungen / Validierung**: `u32`. Der effektive Wert ist `max(value, 1)` zur Runtime (daher verhält sich `0` wie `1`).
  - **Beschreibung**: Sofortiges Retry-Budget, bevor langes Backoff-Verhalten angewendet wird.
  - **Beispiel**:

    ```toml
    [general]
    me_reconnect_fast_retry_count = 16
    ```
## me_single_endpoint_shadow_writers
  - **Einschränkungen / Validierung**: Muss innerhalb von `0..=32` liegen.
  - **Beschreibung**: Zusätzliche Reserve-Writer für DC Gruppen mit genau einem Endpunkt.
  - **Beispiel**:

    ```toml
    [general]
    me_single_endpoint_shadow_writers = 2
    ```
## me_single_endpoint_outage_mode_enabled
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert den aggressiven Ausfallwiederherstellungsmodus für DC Gruppen mit genau einem Endpunkt.
  - **Beispiel**:

    ```toml
    [general]
    me_single_endpoint_outage_mode_enabled = true
    ```
## me_single_endpoint_outage_disable_quarantine
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Ignoriert die Endpunktquarantäne im Einzelendpunkt-Ausfallmodus.
  - **Beispiel**:

    ```toml
    [general]
    me_single_endpoint_outage_disable_quarantine = true
    ```
## me_single_endpoint_outage_backoff_min_ms
  - **Einschränkungen / Validierung**: Muss `> 0` (Millisekunden) und `<= me_single_endpoint_outage_backoff_max_ms` sein.
  - **Beschreibung**: Mindestwiederverbindungs-Backoff im Single-Endpoint-Ausfallmodus.
  - **Beispiel**:

    ```toml
    [general]
    me_single_endpoint_outage_backoff_min_ms = 250
    ```
## me_single_endpoint_outage_backoff_max_ms
  - **Einschränkungen / Validierung**: Muss `> 0` (Millisekunden) und `>= me_single_endpoint_outage_backoff_min_ms` sein.
  - **Beschreibung**: Maximaler Reconnect-Backoff im Single-Endpoint-Ausfallmodus.
  - **Beispiel**:

    ```toml
    [general]
    me_single_endpoint_outage_backoff_max_ms = 3000
    ```
## me_single_endpoint_shadow_rotate_every_secs
  - **Einschränkungen / Validierung**: `u64` (Sekunden). `0` deaktiviert die periodische Schattenrotation.
  - **Beschreibung**: Periodisches Shadow-Writer-Rotationsintervall für Einzelendpunkt-DC-Gruppen.
  - **Beispiel**:

    ```toml
    [general]
    me_single_endpoint_shadow_rotate_every_secs = 900
    ```
## me_floor_mode
  - **Einschränkungen / Validierung**: `"static"` oder `"adaptive"`.
  - **Beschreibung**: Floor-Policy-Modus für ME Writer-Ziele.
  - **Beispiel**:

    ```toml
    [general]
    me_floor_mode = "adaptive"
    ```
## me_adaptive_floor_idle_secs
  - **Einschränkungen / Validierung**: `u64` (Sekunden).
  - **Beschreibung**: Die Leerlaufzeit vor der adaptiven Untergrenze kann das Ziel des Single-Endpoint-Writers verringern.
  - **Beispiel**:

    ```toml
    [general]
    me_adaptive_floor_idle_secs = 90
    ```
## me_adaptive_floor_min_writers_single_endpoint
  - **Einschränkungen / Validierung**: Muss innerhalb von `1..=32` liegen.
  - **Beschreibung**: Mindest-Writer-Ziel für Einzelendpunkt-DC-Gruppen im adaptiven Floor-Modus.
  - **Beispiel**:

    ```toml
    [general]
    me_adaptive_floor_min_writers_single_endpoint = 1
    ```
## me_adaptive_floor_min_writers_multi_endpoint
  - **Einschränkungen / Validierung**: Muss innerhalb von `1..=32` liegen.
  - **Beschreibung**: Mindest-Writer-Ziel für DC-Gruppen mit mehreren Endpunkten im adaptiven Floor-Modus.
  - **Beispiel**:

    ```toml
    [general]
    me_adaptive_floor_min_writers_multi_endpoint = 1
    ```
## me_adaptive_floor_recover_grace_secs
  - **Einschränkungen / Validierung**: `u64` (Sekunden).
  - **Beschreibung**: Schonfrist zum Beibehalten des Static-Floor nach der Aktivität im adaptiven Modus.
  - **Beispiel**:

    ```toml
    [general]
    me_adaptive_floor_recover_grace_secs = 180
    ```
## me_adaptive_floor_writers_per_core_total
  - **Einschränkungen / Validierung**: Muss `> 0` sein.
  - **Beschreibung**: Globales ME-Writer-Budget pro logischem CPU-Kern im adaptiven Modus.
  - **Beispiel**:

    ```toml
    [general]
    me_adaptive_floor_writers_per_core_total = 48
    ```
## me_adaptive_floor_cpu_cores_override
  - **Einschränkungen / Validierung**: `u16`. `0` verwendet die automatische Runtime-Erkennung.
  - **Beschreibung**: Logische CPU-Kernanzahl überschreiben, die für adaptive Floor-Berechnungen verwendet wird.
  - **Beispiel**:

    ```toml
    [general]
    me_adaptive_floor_cpu_cores_override = 0
    ```
## me_adaptive_floor_max_extra_writers_single_per_core
  - **Einschränkungen / Validierung**: `u16`.
  - **Beschreibung**: Max. zusätzliche Writer pro Kern über der erforderlichen Baseline-Floor für Einzelendpunkt-DC-Gruppen.
  - **Beispiel**:

    ```toml
    [general]
    me_adaptive_floor_max_extra_writers_single_per_core = 1
    ```
## me_adaptive_floor_max_extra_writers_multi_per_core
  - **Einschränkungen / Validierung**: `u16`.
  - **Beschreibung**: Max. zusätzliche Writer pro Kern über der erforderlichen Baseline-Floor für DC-Gruppen mit mehreren Endpunkten.
  - **Beispiel**:

    ```toml
    [general]
    me_adaptive_floor_max_extra_writers_multi_per_core = 2
    ```
## me_adaptive_floor_max_active_writers_per_core
  - **Einschränkungen / Validierung**: Muss `> 0` sein.
  - **Beschreibung**: Feste Obergrenze für aktive ME-Writer pro logischem CPU-Kern.
  - **Beispiel**:

    ```toml
    [general]
    me_adaptive_floor_max_active_writers_per_core = 64
    ```
## me_adaptive_floor_max_warm_writers_per_core
  - **Einschränkungen / Validierung**: Muss `> 0` sein.
  - **Beschreibung**: Feste Obergrenze für warme ME-Writer pro logischem CPU-Kern.
  - **Beispiel**:

    ```toml
    [general]
    me_adaptive_floor_max_warm_writers_per_core = 64
    ```
## me_adaptive_floor_max_active_writers_global
  - **Einschränkungen / Validierung**: Muss `> 0` sein.
  - **Beschreibung**: Feste globale Obergrenze für aktive ME-Writer.
  - **Beispiel**:

    ```toml
    [general]
    me_adaptive_floor_max_active_writers_global = 256
    ```
## me_adaptive_floor_max_warm_writers_global
  - **Einschränkungen / Validierung**: Muss `> 0` sein.
  - **Beschreibung**: Feste globale Obergrenze für warme ME-Writer.
  - **Beispiel**:

    ```toml
    [general]
    me_adaptive_floor_max_warm_writers_global = 256
    ```
## upstream_connect_retry_attempts
  - **Einschränkungen / Validierung**: Muss `> 0` sein.
  - **Beschreibung**: Verbindungsversuche für den ausgewählten Upstream, bevor ein Fehler/Fallback zurückgegeben wird.
  - **Beispiel**:

    ```toml
    [general]
    upstream_connect_retry_attempts = 2
    ```
## upstream_connect_retry_backoff_ms
  - **Einschränkungen / Validierung**: `u64` (Millisekunden). `0` deaktiviert die Backoff-Verzögerung (Wiederholungsversuche erfolgen sofort).
  - **Beschreibung**: Verzögerung in Millisekunden zwischen Upstream-Verbindungsversuchen.
  - **Beispiel**:

    ```toml
    [general]
    upstream_connect_retry_backoff_ms = 100
    ```
## upstream_connect_budget_ms
  - **Einschränkungen / Validierung**: Muss `> 0` (Millisekunden) sein.
  - **Beschreibung**: Gesamtwanduhrbudget in Millisekunden für eine Upstream-Verbindungsanforderung über mehrere Wiederholungsversuche hinweg.
  - **Beispiel**:

    ```toml
    [general]
    upstream_connect_budget_ms = 3000
    ```
## tg_connect
  - **Einschränkungen / Validierung**: Muss `> 0` (Sekunden) sein.
  - **Beschreibung**: Upstream Telegram-Verbindungszeitüberschreitung.
  - **Beispiel**:

    ```toml
    [general]
    tg_connect = 10
    ```
## upstream_unhealthy_fail_threshold
  - **Einschränkungen / Validierung**: Muss `> 0` sein.
  - **Beschreibung**: Aufeinanderfolgende fehlgeschlagene Anfragen, bevor der Upstream als fehlerhaft markiert wird.
  - **Beispiel**:

    ```toml
    [general]
    upstream_unhealthy_fail_threshold = 5
    ```
## upstream_connect_failfast_hard_errors
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Wenn „true“, werden zusätzliche Wiederholungsversuche für schwere, nicht vorübergehende Upstream-Verbindungsfehler übersprungen.
  - **Beispiel**:

    ```toml
    [general]
    upstream_connect_failfast_hard_errors = false
    ```
## stun_iface_mismatch_ignore
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Kompatibilitätsflag für zukünftige Verwendung reserviert. Derzeit wird dieser Schlüssel geparst, aber nicht von der Runtime verwendet.
  - **Beispiel**:

    ```toml
    [general]
    stun_iface_mismatch_ignore = false
    ```
## unknown_dc_log_path
  - **Einschränkungen / Validierung**: `String` (optional). Muss ein sicherer Pfad sein (keine `..`-Komponenten, übergeordnetes Verzeichnis muss vorhanden sein); Unsichere Pfade werden zur Runtime abgelehnt.
  - **Beschreibung**: Logdateipfad für unbekannte (nicht standardisierte) DC-Anfragen, wenn `unknown_dc_file_log_enabled = true`. Lassen Sie diesen Schlüssel weg, um die File-Logging zu deaktivieren.
  - **Beispiel**:

    ```toml
    [general]
    unknown_dc_log_path = "unknown-dc.txt"
    ```
## unknown_dc_file_log_enabled
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert die Logging unbekannter DC-Dateien (schreibt `dc_idx=<N>` Zeilen). Erfordert die Einstellung von `unknown_dc_log_path` und wird auf Nicht-Unix-Plattformen möglicherweise nicht unterstützt. Die Logging erfolgt dedupliziert und begrenzt (nur die ersten ~1024 eindeutigen unbekannten DC-Indizes werden aufgezeichnet).
  - **Beispiel**:

    ```toml
    [general]
    unknown_dc_file_log_enabled = false
    ```
## log_level
  - **Einschränkungen / Validierung**: `"debug"`, `"verbose"`, `"normal"` oder `"silent"`.
  - **Beschreibung**: Runtime Ausführlichkeitsstufe der Logging (wird verwendet, wenn `RUST_LOG` nicht festgelegt ist). Wenn `RUST_LOG` in der Umgebung festgelegt ist, hat es Vorrang vor dieser Einstellung.
  - **Beispiel**:

    ```toml
    [general]
    log_level = "normal"
    ```
## disable_colors
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Deaktiviert ANSI-Farben in Protokollen (nützlich für files/systemd). Dies betrifft nur die Protokollformatierung und ändert nicht die Protokollebene/Filterung.
  - **Beispiel**:

    ```toml
    [general]
    disable_colors = false
    ```
## me_socks_kdf_policy
  - **Einschränkungen / Validierung**: `"strict"` oder `"compat"`.
  - **Beschreibung**: SOCKS-gebundene KDF-Fallback-Richtlinie für Middle-End-Handshake.
  - **Beispiel**:

    ```toml
    [general]
    me_socks_kdf_policy = "strict"
    ```
## me_route_backpressure_enabled
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Ermöglicht Kanaldruck-abhängige Routensende-Timeouts.
  - **Beispiel**:

    ```toml
    [general]
    me_route_backpressure_enabled = false
    ```
## me_route_fairshare_enabled
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Ermöglicht die Fair-Share-Routing-Zulassung für alle Writer.
  - **Beispiel**:

    ```toml
    [general]
    me_route_fairshare_enabled = false
    ```
## me_route_backpressure_base_timeout_ms
  - **Einschränkungen / Validierung**: Muss innerhalb von `1..=5000` (Millisekunden) liegen.
  - **Beschreibung**: Basis-Gegendruck-Timeout in Millisekunden für ME Route-Channel-Senden.
  - **Beispiel**:

    ```toml
    [general]
    me_route_backpressure_base_timeout_ms = 25
    ```
## me_route_backpressure_high_timeout_ms
  - **Einschränkungen / Validierung**: Muss innerhalb von `1..=5000` (Millisekunden) und `>= me_route_backpressure_base_timeout_ms` liegen.
  - **Beschreibung**: Zeitüberschreitung bei hohem Gegendruck in Millisekunden, wenn die Queue-Belegung über dem Watermark liegt.
  - **Beispiel**:

    ```toml
    [general]
    me_route_backpressure_high_timeout_ms = 120
    ```
## me_route_backpressure_high_watermark_pct
  - **Einschränkungen / Validierung**: Muss innerhalb von `1..=100` (Prozent) liegen.
  - **Beschreibung**: Prozentualer Schwellenwert für die Queue-Belegung für den Wechsel zum Zeitlimit für hohen Gegendruck.
  - **Beispiel**:

    ```toml
    [general]
    me_route_backpressure_high_watermark_pct = 80
    ```
## me_health_interval_ms_unhealthy
  - **Einschränkungen / Validierung**: Muss `> 0` (Millisekunden) sein.
  - **Beschreibung**: Integritätsüberwachungsintervall, während die Writer-Abdeckung von ME herabgesetzt ist.
  - **Beispiel**:

    ```toml
    [general]
    me_health_interval_ms_unhealthy = 1000
    ```
## me_health_interval_ms_healthy
  - **Einschränkungen / Validierung**: Muss `> 0` (Millisekunden) sein.
  - **Beschreibung**: Integritätsüberwachungsintervall, während die ME Writer-Abdeckung stabil/fehlerfrei ist.
  - **Beispiel**:

    ```toml
    [general]
    me_health_interval_ms_healthy = 3000
    ```
## me_admission_poll_ms
  - **Einschränkungen / Validierung**: Muss `> 0` (Millisekunden) sein.
  - **Beschreibung**: Abfrageintervall für Statusprüfungen bei bedingter Zulassung.
  - **Beispiel**:

    ```toml
    [general]
    me_admission_poll_ms = 1000
    ```
## me_warn_rate_limit_ms
  - **Einschränkungen / Validierung**: Muss `> 0` (Millisekunden) sein.
  - **Beschreibung**: Abklingzeit für sich wiederholende ME-Warnungsprotokolle.
  - **Beispiel**:

    ```toml
    [general]
    me_warn_rate_limit_ms = 5000
    ```
## me_route_no_writer_mode
  - **Einschränkungen / Validierung**: `"async_recovery_failfast"`, `"inline_recovery_legacy"` oder `"hybrid_async_persistent"`.
  - **Beschreibung**: ME Routenverhalten, wenn kein Writer sofort verfügbar ist.
  - **Beispiel**:

    ```toml
    [general]
    me_route_no_writer_mode = "hybrid_async_persistent"
    ```
## me_route_no_writer_wait_ms
  - **Einschränkungen / Validierung**: Muss innerhalb von `10..=5000` (Millisekunden) liegen.
  - **Beschreibung**: Maximale Wartezeit, die vom Async-Recovery-Failfast-Modus verwendet wird, bevor ein Rückfall erfolgt.
  - **Beispiel**:

    ```toml
    [general]
    me_route_no_writer_wait_ms = 250
    ```
## me_route_hybrid_max_wait_ms
  - **Einschränkungen / Validierung**: Muss innerhalb von `50..=60000` (Millisekunden) liegen.
  - **Beschreibung**: Maximale kumulative Wartezeit im Hybrid-No-Writer-Modus vor Failfast-Fallback.
  - **Beispiel**:

    ```toml
    [general]
    me_route_hybrid_max_wait_ms = 3000
    ```
## me_route_blocking_send_timeout_ms
  - **Einschränkungen / Validierung**: Muss innerhalb von `0..=5000` (Millisekunden) liegen. `0` behält das alte unbegrenzte Warteverhalten bei.
  - **Beschreibung**: Maximale Wartezeit für das Blockieren des Route-Channel-Sende-Fallbacks.
  - **Beispiel**:

    ```toml
    [general]
    me_route_blocking_send_timeout_ms = 250
    ```
## me_route_inline_recovery_attempts
  - **Einschränkungen / Validierung**: Muss `> 0` sein.
  - **Beschreibung**: Anzahl der Inline-Wiederherstellungsversuche im Legacy-Modus.
  - **Beispiel**:

    ```toml
    [general]
    me_route_inline_recovery_attempts = 3
    ```
## me_route_inline_recovery_wait_ms
  - **Einschränkungen / Validierung**: Muss innerhalb von `10..=30000` (Millisekunden) liegen.
  - **Beschreibung**: Maximale Inline-Wiederherstellungswartezeit im Legacy-Modus.
  - **Beispiel**:

    ```toml
    [general]
    me_route_inline_recovery_wait_ms = 3000
    ```
## fast_mode_min_tls_record
  - **Einschränkungen / Validierung**: `usize` (Byte). `0` deaktiviert das Limit.
  - **Beschreibung**: Minimale TLS-Datensatzgröße, wenn die Zusammenführung im Schnellmodus aktiviert ist.
  - **Beispiel**:

    ```toml
    [general]
    fast_mode_min_tls_record = 0
    ```
## update_every
  - **Einschränkungen / Validierung**: `u64` (Sekunden). Wenn gesetzt, muss `> 0` sein. Wenn dieser Schlüssel nicht explizit festgelegt ist, können die alten Versionen `proxy_secret_auto_reload_secs` und `proxy_config_auto_reload_secs` verwendet werden (ihr effektives Minimum muss `> 0` sein).
  - **Beschreibung**: Einheitliches Aktualisierungsintervall für ME Updater-Aufgaben (`getProxyConfig`, `getProxyConfigV6`, `getProxySecret`). Wenn es festgelegt ist, überschreibt es die Neuladeintervalle des Legacy-Proxys.
  - **Beispiel**:

    ```toml
    [general]
    update_every = 300
    ```
## me_reinit_every_secs
  - **Einschränkungen / Validierung**: Muss `> 0` (Sekunden) sein.
  - **Beschreibung**: Periodisches Intervall für einen Reinitialisierungszyklus ohne Ausfallzeit ME.
  - **Beispiel**:

    ```toml
    [general]
    me_reinit_every_secs = 900
    ```
## me_hardswap_warmup_delay_min_ms
  - **Einschränkungen / Validierung**: `u64` (Millisekunden). Muss `<= me_hardswap_warmup_delay_max_ms` sein.
  - **Beschreibung**: Untergrenze für den Hardswap-Warmup-Dial-Abstand.
  - **Beispiel**:

    ```toml
    [general]
    me_hardswap_warmup_delay_min_ms = 1000
    ```
## me_hardswap_warmup_delay_max_ms
  - **Einschränkungen / Validierung**: Muss `> 0` (Millisekunden) sein.
  - **Beschreibung**: Obergrenze für den Hardswap-Warmup-Dial-Abstand.
  - **Beispiel**:

    ```toml
    [general]
    me_hardswap_warmup_delay_max_ms = 2000
    ```
## me_hardswap_warmup_extra_passes
  - **Einschränkungen / Validierung**: Muss innerhalb von `[0, 10]` liegen.
  - **Beschreibung**: Zusätzliche Warmup-Passes nach dem Basispass in einem Hardswap-Zyklus.
  - **Beispiel**:

    ```toml
    [general]
    # Standard: 3 (erlaubter Bereich: 0..=10)
    me_hardswap_warmup_extra_passes = 3
    ```
## me_hardswap_warmup_pass_backoff_base_ms
  - **Einschränkungen / Validierung**: `u64` (Millisekunden). Muss `> 0` sein.
  - **Beschreibung**: Basis-Backoff zwischen zusätzlichen Hardswap-Warmup-Passes, wenn der Floor noch unvollständig ist.
  - **Beispiel**:

    ```toml
    [general]
    # Standard: 500
    me_hardswap_warmup_pass_backoff_base_ms = 500
    ```
## me_config_stable_snapshots
  - **Einschränkungen / Validierung**: Muss `> 0` sein.
  - **Beschreibung**: Anzahl identischer ME Config-Snapshots, die vor der Anwendung erforderlich sind.
  - **Beispiel**:

    ```toml
    [general]
    # erfordern drei identische Snapshots, bevor ME Endpunktkartenaktualisierungen angewendet werden
    me_config_stable_snapshots = 3
    ```
## me_config_apply_cooldown_secs
  - **Einschränkungen / Validierung**: `u64`.
  - **Beschreibung**: Abklingzeit zwischen angewendeten ME Endpoint-Map-Updates. `0` deaktiviert die Abklingzeit.
  - **Beispiel**:

    ```toml
    [general]
    # erlaubt die sofortige Anwendung stabiler Snapshots (keine Abklingzeit)
    me_config_apply_cooldown_secs = 0
    ```
## me_snapshot_require_http_2xx
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Erfordert 2xx HTTP-Antworten zum Anwenden von ME-Config-Snapshots. Bei `false` können Nicht-2xx-Antworten weiterhin vom Updater geparst/berücksichtigt werden.
  - **Beispiel**:

    ```toml
    [general]
    # ermöglicht das Anwenden von Snapshots, auch wenn der HTTP-Status nicht 2xx ist
    me_snapshot_require_http_2xx = false
    ```
## me_snapshot_reject_empty_map
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Lehnt leere ME-Config-Snapshots ab (keine Endpunkte). Bei `false` kann ein leerer Snapshot angewendet werden (vorbehaltlich anderer Gates), wodurch die ME-Map möglicherweise vorübergehend reduziert/löscht wird.
  - **Beispiel**:

    ```toml
    [general]
    # Anwenden leerer Snapshots zulassen (mit Vorsicht verwenden)
    me_snapshot_reject_empty_map = false
    ```
## me_snapshot_min_proxy_for_lines
  - **Einschränkungen / Validierung**: Muss `> 0` sein.
  - **Beschreibung**: Mindestens geparste `proxy_for` Zeilen erforderlich, um Snapshots zu akzeptieren.
  - **Beispiel**:

    ```toml
    [general]
    # erfordern mindestens 10 Proxy_for-Zeilen, bevor ein Snapshot akzeptiert wird
    me_snapshot_min_proxy_for_lines = 10
    ```
## proxy_secret_stable_snapshots
  - **Einschränkungen / Validierung**: Muss `> 0` sein.
  - **Beschreibung**: Anzahl identischer Proxy-Secret-Snapshots, die vor der Rotation erforderlich sind.
  - **Beispiel**:

    ```toml
    [general]
    # erfordern zwei identische getProxySecret-Snapshots, bevor sie zur Runtime rotieren
    proxy_secret_stable_snapshots = 2
    ```
## proxy_secret_rotate_runtime
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Ermöglicht die Rotation von Proxy-Geheimnissen zur Runtime aus Updater-Snapshots.
  - **Beispiel**:

    ```toml
    [general]
    # Deaktivieren Sie die Proxy-Secret-Rotation zur Runtime (Start verwendet weiterhin Proxy_secret_path/proxy_secret_len_max)
    proxy_secret_rotate_runtime = false
    ```
## me_secret_atomic_snapshot
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Behält Selektor- und Secret-Bytes atomar aus demselben Snapshot. Bei `general.use_middle_proxy = true` wird dies beim Laden der Konfiguration automatisch aktiviert, um die Kohärenz des ME KDF-Materials zu gewährleisten.
  - **Beispiel**:

    ```toml
    [general]
    # HINWEIS: Wenn use_middle_proxy=true, wird Telemt dies beim Laden automatisch aktivieren
    me_secret_atomic_snapshot = false
    ```
## proxy_secret_len_max
  - **Einschränkungen / Validierung**: Muss innerhalb von `[32, 4096]` liegen.
  - **Beschreibung**: Obere Längenbeschränkung (Byte) für akzeptiertes Proxy-Geheimnis während des Starts und der Runtimeaktualisierung.
  - **Beispiel**:

    ```toml
    [general]
    # Standard: 256 (Byte)
    proxy_secret_len_max = 256
    ```
## me_pool_drain_ttl_secs
  - **Einschränkungen / Validierung**: `u64` (Sekunden). `0` deaktiviert das Drain-TTL-Fenster (und unterdrückt Drain-TTL-Warnungen für nicht leere Draining-Writer).
  - **Beschreibung**: Drain-TTL-Zeitfenster für stale ME-Writer nach Änderungen der Endpoint-Map. Während der TTL dürfen stale Writer nur als Fallback für neue Bindungen verwendet werden (abhängig von der Bindungsrichtlinie).
  - **Beispiel**:

    ```toml
    [general]
    # Drain TTL deaktivieren (Draining Writer geben keine „Past Drain TTL“-Warnungen aus)
    me_pool_drain_ttl_secs = 0
    ```
## me_instadrain
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Erzwingt, dass stale Writer beim nächsten Bereinigungsschritt entfernt werden, wodurch die TTL/Deadline-Wartezeit umgangen wird.
  - **Beispiel**:

    ```toml
    [general]
    # Standard: false
    me_instadrain = false
    ```
## me_pool_drain_threshold
  - **Einschränkungen / Validierung**: `u64`. Auf `0` setzen, um die schwellenwertbasierte Bereinigung zu deaktivieren.
  - **Beschreibung**: Maximale Anzahl stale Writer, bevor die ältesten stapelweise geschlossen werden.
  - **Beispiel**:

    ```toml
    [general]
    # default: 32
    me_pool_drain_threshold = 32
    ```
## me_pool_drain_soft_evict_enabled
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Ermöglicht schrittweise Soft-Eviction von stale Writern während des Drain/Reinit anstelle eines sofortigen harten Schließens.
  - **Beispiel**:

    ```toml
    [general]
    # default: true
    me_pool_drain_soft_evict_enabled = true
    ```
## me_pool_drain_soft_evict_grace_secs
  - **Einschränkungen / Validierung**: `u64` (seconds). Must be within `[0, 3600]`.
  - **Beschreibung**: Zusätzliche Grace nach der Drain-TTL, bevor die Soft-Eviction-Phase beginnt.
  - **Beispiel**:

    ```toml
    [general]
    # default: 10
    me_pool_drain_soft_evict_grace_secs = 10
    ```
## me_pool_drain_soft_evict_per_writer
  - **Einschränkungen / Validierung**: `1..=16`.
  - **Beschreibung**: Maximale Anzahl stale Routes, die pro Writer in einem Eviction-Pass soft-evicted werden.
  - **Beispiel**:

    ```toml
    [general]
    # default: 2
    me_pool_drain_soft_evict_per_writer = 2
    ```
## me_pool_drain_soft_evict_budget_per_core
  - **Einschränkungen / Validierung**: `1..=64`.
  - **Beschreibung**: Budget pro Kern begrenzt die gesamte Soft-Eviction-Arbeit pro Durchgang.
  - **Beispiel**:

    ```toml
    [general]
    # default: 16
    me_pool_drain_soft_evict_budget_per_core = 16
    ```
## me_pool_drain_soft_evict_cooldown_ms
  - **Einschränkungen / Validierung**: `u64` (Millisekunden). Muss `> 0` sein.
  - **Beschreibung**: Cooldown zwischen wiederholter Soft-Eviction auf demselben Writer.
  - **Beispiel**:

    ```toml
    [general]
    # default: 1000
    me_pool_drain_soft_evict_cooldown_ms = 1000
    ```
## me_bind_stale_mode
  - **Einschränkungen / Validierung**: `"never"`, `"ttl"` oder `"always"`.
  - **Beschreibung**: Policy für neue Binds auf stale draining Writern.
  - **Beispiel**:

    ```toml
    [general]
    # veraltete Bindungen nur für ein begrenztes Zeitfenster zulassen
    me_bind_stale_mode = "ttl"
    ```
## me_bind_stale_ttl_secs
  - **Einschränkungen / Validierung**: `u64`.
  - **Beschreibung**: TTL für stale Bind-Zulassung, wenn der stale mode `ttl` ist.
  - **Beispiel**:

    ```toml
    [general]
    me_bind_stale_mode = "ttl"
    me_bind_stale_ttl_secs = 90
    ```
## me_pool_min_fresh_ratio
  - **Einschränkungen / Validierung**: Muss innerhalb von `[0.0, 1.0]` liegen.
  - **Beschreibung**: Mindestanteil frischer Desired-DC-Coverage, bevor stale Writer gedraint werden.
  - **Beispiel**:

    ```toml
    [general]
    # erfordern >=90 % der gewünschten DC-Abdeckung, bevor stale Writer gedraint werden
    me_pool_min_fresh_ratio = 0.9
    ```
## me_reinit_drain_timeout_secs
  - **Einschränkungen / Validierung**: `u64`. `0` verwendet das Runtime-Sicherheits-Fallback-Timeout für erzwungenes Schließen. Wenn `> 0` und `< me_pool_drain_ttl_secs`, erhöht die Runtime den Wert auf TTL.
  - **Beschreibung**: Force-Close-Timeout für draining stale Writer. Bei der Einstellung `0` entspricht das effektive Timeout dem Runtime-Safety-Fallback (300 Sekunden).
  - **Beispiel**:

    ```toml
    [general]
    # Runtime-Safety-Fallback-Force-Close-Timeout (300 s) verwenden
    me_reinit_drain_timeout_secs = 0
    ```
## proxy_secret_auto_reload_secs
  - **Einschränkungen / Validierung**: Veraltet. Verwenden Sie `general.update_every`. Wenn `general.update_every` nicht explizit festgelegt ist, beträgt das effektive Legacy-Aktualisierungsintervall `min(proxy_secret_auto_reload_secs, proxy_config_auto_reload_secs)` und muss `> 0` betragen.
  - **Beschreibung**: Veraltetes Aktualisierungsintervall für Legacy-Proxy-Geheimnisse. Wird nur verwendet, wenn `general.update_every` nicht festgelegt ist.
  - **Beispiel**:

    ```toml
    [general]
    # Legacy-Modus: update_every weglassen, um Proxy_*_auto_reload_secs zu verwenden
    proxy_secret_auto_reload_secs = 600
    proxy_config_auto_reload_secs = 120
    # effektives Aktualisierungsintervall = min(600, 120) = 120 Sekunden
    ```
## proxy_config_auto_reload_secs
  - **Einschränkungen / Validierung**: Veraltet. Verwenden Sie `general.update_every`. Wenn `general.update_every` nicht explizit festgelegt ist, beträgt das effektive Legacy-Aktualisierungsintervall `min(proxy_secret_auto_reload_secs, proxy_config_auto_reload_secs)` und muss `> 0` betragen.
  - **Beschreibung**: Veraltetes Legacy-Konfigurationsaktualisierungsintervall ME. Wird nur verwendet, wenn `general.update_every` nicht festgelegt ist.
  - **Beispiel**:

    ```toml
    [general]
    # Legacy-Modus: update_every weglassen, um Proxy_*_auto_reload_secs zu verwenden
    proxy_secret_auto_reload_secs = 600
    proxy_config_auto_reload_secs = 120
    # effektives Aktualisierungsintervall = min(600, 120) = 120 Sekunden
    ```
## me_reinit_singleflight
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Serialisiert ME Neuinitialisierungszyklen über Triggerquellen hinweg.
  - **Beispiel**:

    ```toml
    [general]
    me_reinit_singleflight = true
    ```
## me_reinit_trigger_channel
  - **Einschränkungen / Validierung**: Muss `> 0` sein.
  - **Beschreibung**: Trigger-Queue-Kapazität für Reinit-Planer.
  - **Beispiel**:

    ```toml
    [general]
    me_reinit_trigger_channel = 64
    ```
## me_reinit_coalesce_window_ms
  - **Einschränkungen / Validierung**: `u64`.
  - **Beschreibung**: Zusammenführungsfenster auslösen, bevor Reinit gestartet wird (ms).
  - **Beispiel**:

    ```toml
    [general]
    me_reinit_coalesce_window_ms = 200
    ```
## me_deterministic_writer_sort
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Ermöglicht die deterministische Kandidatensortierung für den Writer-Bindungspfad.
  - **Beispiel**:

    ```toml
    [general]
    me_deterministic_writer_sort = true
    ```
## me_writer_pick_mode
  - **Einschränkungen / Validierung**: `"sorted_rr"` oder `"p2c"`.
  - **Beschreibung**: Writer-Auswahlmodus für Routenbindungspfad.
  - **Beispiel**:

    ```toml
    [general]
    me_writer_pick_mode = "p2c"
    ```
## me_writer_pick_sample_size
  - **Einschränkungen / Validierung**: `2..=4`.
  - **Beschreibung**: Anzahl der Kandidaten, die vom Picker im `p2c`-Modus ausgewählt wurden.
  - **Beispiel**:

    ```toml
    [general]
    me_writer_pick_mode = "p2c"
    me_writer_pick_sample_size = 3
    ```
## ntp_check
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Reserviert für zukünftige Verwendung. Derzeit wird dieser Schlüssel geparst, aber nicht von der Runtime verwendet.
  - **Beispiel**:

    ```toml
    [general]
    ntp_check = true
    ```
## ntp_servers
  - **Einschränkungen / Validierung**: `String[]`.
  - **Beschreibung**: Reserviert für zukünftige Verwendung. Derzeit wird dieser Schlüssel geparst, aber nicht von der Runtime verwendet.
  - **Beispiel**:

    ```toml
    [general]
    ntp_servers = ["pool.ntp.org"]
    ```
## auto_degradation_enabled
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Reserviert für zukünftige Verwendung. Derzeit wird dieser Schlüssel geparst, aber nicht von der Runtime verwendet.
  - **Beispiel**:

    ```toml
    [general]
    auto_degradation_enabled = true
    ```
## degradation_min_unavailable_dc_groups
  - **Einschränkungen / Validierung**: `u8`.
  - **Beschreibung**: Reserviert für zukünftige Verwendung. Derzeit wird dieser Schlüssel geparst, aber nicht von der Runtime verwendet.
  - **Beispiel**:

    ```toml
    [general]
    degradation_min_unavailable_dc_groups = 2
    ```
## rst_on_close
  - **Einschränkungen / Validierung**: einer von `"off"`, `"errors"`, `"always"`.
  - **Beschreibung**: Steuert das `SO_LINGER(0)`-Verhalten auf akzeptierten Client-TCP-Sockets.
 Proxyserver mit hohem Traffic sammeln `FIN-WAIT-1` und verwaiste Sockets von Verbindungen an, die den Telegram-Handshake nie abschließen (Scanner, DPI-Probes, Bots).
 Diese Option ermöglicht das Senden eines sofortigen `RST` anstelle eines ordnungsgemäßen `FIN` für solche Verbindungen, wodurch Kernelressourcen sofort freigegeben werden.
 – `"off"` – Standard. Normal `FIN` bei allen Schließungen; Keine Verhaltensänderung.
 – `"errors"` – `SO_LINGER(0)` ist auf `accept()` festgelegt. Wenn der Client die Authentifizierung erfolgreich abschließt, wird die Verzögerung gelöscht und die Relay-Sitzung wird ordnungsgemäß mit `FIN` geschlossen. Verbindungen, die vor Abschluss des Handshakes geschlossen wurden (Zeitüberschreitungen, fehlerhafte Verschlüsselung, Scanner), senden `RST`.
 – `"always"` – `SO_LINGER(0)` ist auf `accept()` festgelegt und wird nie gelöscht. Alle Schließungen senden `RST` unabhängig vom Handshake-Ergebnis.
  - **Beispiel**:

    ```toml
    [general]
    rst_on_close = "errors"
    ```

# [general.modes]


| Schlüssel | Typ | Default | Hot-Reload |
| --- | --- | --- | --- |
| [`classic`](#classic) | `bool` | `false` | `✘` |
| [`secure`](#secure) | `bool` | `false` | `✘` |
| [`tls`](#tls) | `bool` | `true` | `✘` |

## classic
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert den klassischen MTProxy-Modus.
  - **Beispiel**:

    ```toml
    [general.modes]
    classic = true
    ```
## secure
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert den sicheren Modus.
  - **Beispiel**:

    ```toml
    [general.modes]
    secure = true
    ```
## tls
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert den TLS-Modus.
  - **Beispiel**:

    ```toml
    [general.modes]
    tls = true
    ```


# [general.links]


| Schlüssel | Typ | Default | Hot-Reload |
| --- | --- | --- | --- |
| [`show`](#show) | `"*"` oder `String[]` | `"*"` | `✘` |
| [`public_host`](#public_host) | `String` | — | `✘` |
| [`public_port`](#public_port) | `u16` | — | `✘` |

## show
  - **Einschränkungen / Validierung**: `"*"` oder `String[]`. Ein leeres Array bedeutet „keine anzeigen“.
  - **Beschreibung**: Wählt User aus, deren `tg://` Proxy-Links beim Start angezeigt werden.
  - **Beispiel**:

    ```toml
    [general.links]
    show = "*"
    # oder:
    # show = ["alice", "bob"]
    ```
## public_host
  - **Einschränkungen / Validierung**: `String` (optional).
  - **Beschreibung**: Öffentliche Hostname-/IP-Override, die für generierte `tg://`-Links verwendet wird (überschreibt erkannte IP).
  - **Beispiel**:

    ```toml
    [general.links]
    public_host = "proxy.example.com"
    ```
## public_port
  - **Einschränkungen / Validierung**: `u16` (optional).
  - **Beschreibung**: Override des öffentlichen Ports, die für generierte `tg://`-Links verwendet wird (überschreibt `server.port`).
  - **Beispiel**:

    ```toml
    [general.links]
    public_port = 443
    ```


# [general.telemetry]


| Schlüssel | Typ | Default | Hot-Reload |
| --- | --- | --- | --- |
| [`core_enabled`](#core_enabled) | `bool` | `true` | `✔` |
| [`user_enabled`](#user_enabled) | `bool` | `true` | `✔` |
| [`me_level`](#me_level) | `"silent"`, `"normal"` oder `"debug"` | `"normal"` | `✔` |

## core_enabled
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert Kern-Hot-Path-Telemetriezähler.
  - **Beispiel**:

    ```toml
    [general.telemetry]
    core_enabled = true
    ```
## user_enabled
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert Telemetriezähler pro User.
  - **Beispiel**:

    ```toml
    [general.telemetry]
    user_enabled = true
    ```
## me_level
  - **Einschränkungen / Validierung**: `"silent"`, `"normal"` oder `"debug"`.
  - **Beschreibung**: Middle-End Ausführlichkeitsgrad der Telemetrie.
  - **Beispiel**:

    ```toml
    [general.telemetry]
    me_level = "normal"
    ```


# [network]


| Schlüssel | Typ | Default | Hot-Reload |
| --- | --- | --- | --- |
| [`ipv4`](#ipv4) | `bool` | `true` | `✘` |
| [`ipv6`](#ipv6) | `bool` | `false` | `✘` |
| [`prefer`](#prefer) | `u8` | `4` | `✘` |
| [`multipath`](#multipath) | `bool` | `false` | `✘` |
| [`stun_use`](#stun_use) | `bool` | `true` | `✘` |
| [`stun_servers`](#stun_servers) | `String[]` | Integrierte STUN-Liste (13 Hosts) | `✘` |
| [`stun_tcp_fallback`](#stun_tcp_fallback) | `bool` | `true` | `✘` |
| [`http_ip_detect_urls`](#http_ip_detect_urls) | `String[]` | `["https://ifconfig.me/ip", "https://api.ipify.org"]` | `✘` |
| [`cache_public_ip_path`](#cache_public_ip_path) | `String` | `"cache/public_ip.txt"` | `✘` |
| [`dns_overrides`](#dns_overrides) | `String[]` | `[]` | `✔` |

## ipv4
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert IPv4 Netzwerk.
  - **Beispiel**:

    ```toml
    [network]
    ipv4 = true
    ```
## ipv6
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert/deaktiviert IPv6 Netzwerk. Wenn ausgelassen, wird standardmäßig `false`.
  - **Beispiel**:

    ```toml
    [network]
    # IPv6 explizit aktivieren
    ipv6 = true

    # oder: IPv6 explizit deaktivieren
    # ipv6 = false
    ```
## prefer
  - **Einschränkungen / Validierung**: Muss `4` oder `6` sein. Wenn `prefer = 4` während `ipv4 = false`, erzwingt Telemt `prefer = 6`. Wenn `prefer = 6` während `ipv6 = false`, erzwingt Telemt `prefer = 4`.
  - **Beschreibung**: Bevorzugte IP-Familie zur Auswahl, wenn beide Familien verfügbar sind.
  - **Beispiel**:

    ```toml
    [network]
    prefer = 6
    ```
## multipath
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Ermöglicht Multipath-Verhalten, sofern von der Plattform und der Runtime unterstützt.
  - **Beispiel**:

    ```toml
    [network]
    multipath = true
    ```
## stun_use
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Globaler STUN-Schalter; Wenn `false`, ist die STUN-Prüfung deaktiviert und es bleibt nur die Nicht-STUN-Erkennung übrig.
  - **Beispiel**:

    ```toml
    [network]
    stun_use = false
    ```
## stun_servers
  - **Einschränkungen / Validierung**: `String[]`. Werte werden gekürzt; leere Werte werden entfernt; Liste ist dedupliziert. Wenn dieser Schlüssel **nicht** explizit festgelegt ist, behält Telemt die integrierte Standardliste STUN bei.
  - **Beschreibung**: STUN Serverliste für öffentliche IP-Erkennung.
  - **Beispiel**:

    ```toml
    [network]
    stun_servers = [
      "stun.l.google.com:19302",
      "stun.stunprotocol.org:3478",
    ]
    ```
## stun_tcp_fallback
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert TCP Fallback für STUN, wenn der UDP-Pfad blockiert/nicht verfügbar ist.
  - **Beispiel**:

    ```toml
    [network]
    stun_tcp_fallback = true
    ```
## http_ip_detect_urls
  - **Einschränkungen / Validierung**: `String[]`.
  - **Beschreibung**: HTTP Endpunkte, die für die öffentliche IP-Erkennung verwendet werden (Fallback nach STUN).
  - **Beispiel**:

    ```toml
    [network]
    http_ip_detect_urls = ["https://ifconfig.me/ip", "https://api.ipify.org"]
    ```
## cache_public_ip_path
  - **Einschränkungen / Validierung**: `String`.
  - **Beschreibung**: Dateipfad, der zum Zwischenspeichern der erkannten öffentlichen IP verwendet wird.
  - **Beispiel**:

    ```toml
    [network]
    cache_public_ip_path = "cache/public_ip.txt"
    ```
## dns_overrides
  - **Einschränkungen / Validierung**: `String[]`. Jeder Eintrag muss das Format `host:port:ip` verwenden.
 – `host`: Domänenname (darf nicht leer sein und darf nicht `:` enthalten)
 – `port`: `u16`
 – `ip`: IPv4 (`1.2.3.4`) oder in Klammern IPv6 (`[2001:db8::1]`). **Ungeklammertes IPv6 wird abgelehnt**.
  - **Beschreibung**: Runtime DNS-Overrideen für `host:port`-Ziele. Nützlich, um bestimmte IP-Adressen für bestimmte Upstream-Domänen zu erzwingen, ohne das System-DNS zu berühren.
  - **Beispiel**:

    ```toml
    [network]
    dns_overrides = [
      "example.com:443:127.0.0.1",
      "example.net:8443:[2001:db8::10]",
    ]
    ```


# [server]


| Schlüssel | Typ | Default | Hot-Reload |
| --- | --- | --- | --- |
| [`port`](#port) | `u16` | `443` | `✘` |
| [`listen_addr_ipv4`](#listen_addr_ipv4) | `String` | `"0.0.0.0"` | `✘` |
| [`listen_addr_ipv6`](#listen_addr_ipv6) | `String` | `"::"` | `✘` |
| [`listen_unix_sock`](#listen_unix_sock) | `String` | — | `✘` |
| [`listen_unix_sock_perm`](#listen_unix_sock_perm) | `String` | — | `✘` |
| [`listen_tcp`](#listen_tcp) | `bool` | — (automatisch) | `✘` |
| [`client_mss`](#client_mss) | `String` | `""` | `✘` |
| [`client_mss_bulk`](#client_mss_bulk) | `String` | `""` | `✘` |
| [`proxy_protocol`](#proxy_protocol) | `bool` | `false` | `✘` |
| [`proxy_protocol_header_timeout_ms`](#proxy_protocol_header_timeout_ms) | `u64` | `500` | `✘` |
| [`proxy_protocol_trusted_cidrs`](#proxy_protocol_trusted_cidrs) | `IpNetwork[]` | `[]` | `✘` |
| [`metrics_port`](#metrics_port) | `u16` | — | `✘` |
| [`metrics_listen`](#metrics_listen) | `String` | — | `✘` |
| [`metrics_whitelist`](#metrics_whitelist) | `IpNetwork[]` | `["127.0.0.1/32", "::1/128"]` | `✘` |
| [`api`](#serverapi) | `Table` | integrierte Standardeinstellungen | `✘` |
| [`admin_api`](#serverapi) | `Table` | Alias ​​für `api` | `✘` |
| [`listeners`](#serverlisteners) | `Table[]` | abgeleitet von Legacy-Listener-Feldern | `✘` |
| [`max_connections`](#max_connections) | `u32` | `10000` | `✘` |
| [`accept_permit_timeout_ms`](#accept_permit_timeout_ms) | `u64` | `250` | `✘` |
| [`listen_backlog`](#listen_backlog) | `u32` | `1024` | `✘` |
| [`conntrack_control`](#serverconntrack_control) | `Table` | integrierte Standardeinstellungen | `✘` |

## port
  - **Einschränkungen / Validierung**: `u16`.
  - **Beschreibung**: Haupt-Proxy-Abhörport (TCP).
  - **Beispiel**:

    ```toml
    [server]
    port = 443
    ```
## listen_backlog
  - **Einschränkungen / Validierung**: `u32`. `0` verwendet das Standard-Backlog-Verhalten des Betriebssystems.
  - **Beschreibung**: Listen-Backlog, der an `listen(2)` für TCP Sockets übergeben wird.
  - **Beispiel**:

    ```toml
    [server]
    listen_backlog = 1024
    ```
## listen_addr_ipv4
  - **Einschränkungen / Validierung**: `String` (optional). Wenn gesetzt, muss es sich um eine gültige IPv4-Adresszeichenfolge handeln.
  - **Beschreibung**: IPv4-Bindungsadresse für TCP-Listener (lassen Sie diesen Schlüssel weg, um die IPv4-Bindung zu deaktivieren).
  - **Beispiel**:

    ```toml
    [server]
    listen_addr_ipv4 = "0.0.0.0"
    ```
## listen_addr_ipv6
  - **Einschränkungen / Validierung**: `String` (optional). Wenn gesetzt, muss es sich um eine gültige IPv6-Adresszeichenfolge handeln.
  - **Beschreibung**: IPv6-Bindungsadresse für TCP-Listener (lassen Sie diesen Schlüssel weg, um die IPv6-Bindung zu deaktivieren).
  - **Beispiel**:

    ```toml
    [server]
    listen_addr_ipv6 = "::"
    ```
## listen_unix_sock
  - **Einschränkungen / Validierung**: `String` (optional). Darf beim Festlegen nicht leer sein. Nur Unix.
  - **Beschreibung**: Unix Socket-Pfad für den Listener. Wenn gesetzt, ist `server.listen_tcp` standardmäßig `false` (sofern nicht explizit überschrieben).
  - **Beispiel**:

    ```toml
    [server]
    listen_unix_sock = "/run/telemt.sock"
    ```
## listen_unix_sock_perm
  - **Einschränkungen / Validierung**: `String` (optional). Wenn gesetzt, sollte es sich um eine oktale Berechtigungszeichenfolge wie `"0666"` oder `"0777"` handeln.
  - **Beschreibung**: Optionale Unix-Socketdateiberechtigungen, die nach der Bindung (chmod) angewendet werden. Wenn ausgelassen, werden die Berechtigungen nicht geändert (erbt umask).
  - **Beispiel**:

    ```toml
    [server]
    listen_unix_sock = "/run/telemt.sock"
    listen_unix_sock_perm = "0666"
    ```
## listen_tcp
  - **Einschränkungen / Validierung**: `bool` (optional). Wenn ausgelassen, erkennt Telemt automatisch Folgendes:
 – `true` wenn `listen_unix_sock` nicht festgelegt ist
 – `false` wenn `listen_unix_sock` festgelegt ist
  - **Beschreibung**: Explizite TCP-Listener-Aktivierungs-/Deaktivierungsüberschreibung.
  - **Beispiel**:

    ```toml
    [server]
    # Erzwingen Sie die Aktivierung von TCP, auch wenn auch ein Unix-Socket gebunden wird
    listen_unix_sock = "/run/telemt.sock"
    listen_tcp = true
    ```
## client_mss
  - **Einschränkungen / Validierung**: `String`. Leer oder ausgelassen bedeutet: Kernel-MSS nicht verändern. Presets: `"extreme-low"` = `88`, `"tspu"` = `92`, `"2in8"` = `256`. Benutzerdefinierte Dezimalwerte müssen im Bereich `88..=4096` liegen.
  - **Beschreibung**: Client-facing TCP-MSS, das vor `listen(2)` auf TCP-Listener-Sockets gesetzt wird, damit Linux den Wert im SYN/ACK annoncieren kann. Betrifft nur die clientseitigen Proxy-TCP-Listener, nicht API, Metriken, Unix-Sockets, Telegram-Upstreams, ME-Sockets oder Mask-Backend-Verbindungen. Änderungen erfordern Listener-Neustart/Rebind.
  - **Betreiberhinweis**: Das zweistufige `synlimit`-Profil verlangt nicht, dass Telemt MSS automatisch deaktiviert. Betreiber, die externe Host-Tuning-Rezepte übernehmen, sollten bewusst entscheiden, ob MSS-Shaping für Handshake-Fragmentierung aktiv bleibt oder zugunsten höheren Medien-Durchsatzes deaktiviert wird.
  - **Performance-Hinweis**: Niedriges MSS erhöht die Paketanzahl vorhersehbar. Der ungefähre Segmentmultiplikator ist `ceil(1460 / client_mss)`.
  - **Beispiel**:

    ```toml
    [server]
    client_mss = "tspu"
    ```
## client_mss_bulk
  - **Einschränkungen / Validierung**: `String`. Gleiche Grammatik wie [`client_mss`](#client_mss): leer/ausgelassen, Presets `"extreme-low"`/`"tspu"`/`"2in8"` oder ein Dezimalwert in `88..=4096`.
  - **Beschreibung**: Optionale MSS für die Bulk-Phase. Wenn gesetzt, gilt das niedrige `client_mss` nur während der TLS-Handshake gesendet wird, einschließlich des von DPI inspizierten ServerHello. Sobald die Verbindung in den Relay-Betrieb wechselt, wird das MSS des Client-Sockets für die Bulk-Datenphase auf `client_mss_bulk` erhöht. So bleibt die Anti-DPI-Handshake-Fragmentierung erhalten, während Payload wieder in normal großen Paketen läuft; die ausgehende Paketanzahl sinkt ungefähr um den `client_mss`-Segmentmultiplikator (z. B. ~10x mit `"tspu"`). Nützlich auf Hosts, deren Abuse-Erkennung Pakete pro Sekunde statt Bandbreite zählt. Leer/ausgelassen bedeutet: Handshake-MSS für die gesamte Verbindung beibehalten (bisheriges Verhalten). Nur Linux; auf anderen Plattformen ein No-Op.
  - **Beispiel**:

    ```toml
    [server]
    client_mss = "tspu"
    client_mss_bulk = "1400"
    ```
## proxy_protocol
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert die Analyse des HAProxy PROXY-Protokolls für eingehende Verbindungen (PROXY v1/v2). Wenn diese Option aktiviert ist, wird die Client-Source-Adresse aus dem PROXY-Header übernommen.
  - **Beispiel**:

    ```toml
    [server]
    proxy_protocol = true
    ```
## proxy_protocol_header_timeout_ms
  - **Einschränkungen / Validierung**: Muss `> 0` (Millisekunden) sein.
  - **Beschreibung**: Timeout für das Lesen und Parsen von PROXY Protokoll-Headern (ms).
  - **Beispiel**:

    ```toml
    [server]
    proxy_protocol = true
    proxy_protocol_header_timeout_ms = 500
    ```
## proxy_protocol_trusted_cidrs
  - **Einschränkungen / Validierung**: `IpNetwork[]`.
 – Wenn ausgelassen, werden standardmäßig „All Trust-CIDRs“ (`0.0.0.0/0` und `::/0`) verwendet. 
 > In der Produktion hinter HAProxy/nginx sollten Sie lieber explizite vertrauenswürdige CIDRs festlegen, anstatt sich auf diesen Fallback zu verlassen.
 – Wenn explizit auf ein leeres Array festgelegt, werden alle PROXY-Header abgelehnt.
  - **Beschreibung**: Vertrauenswürdige Quell-CIDRs dürfen PROXY Protokollheader bereitstellen (Sicherheitskontrolle).
  - **Beispiel**:

    ```toml
    [server]
    proxy_protocol = true
    proxy_protocol_trusted_cidrs = ["127.0.0.1/32", "10.0.0.0/8"]
    ```
## metrics_port
  - **Einschränkungen / Validierung**: `u16` (optional).
  - **Beschreibung**: Prometheus-kompatibler Metrik-Endpunktport. Wenn gesetzt, wird der Metrik-Listener aktiviert (Bindungsverhalten kann durch `metrics_listen` überschrieben werden).
  - **Beispiel**:

    ```toml
    [server]
    metrics_port = 9090
    ```
## metrics_listen
  - **Einschränkungen / Validierung**: `String` (optional). Wenn gesetzt, muss es im `IP:PORT`-Format vorliegen.
  - **Beschreibung**: Vollständige Messwertbindungsadresse (`IP:PORT`), überschreibt `metrics_port` und bindet nur an die angegebene Adresse.
  - **Beispiel**:

    ```toml
    [server]
    metrics_listen = "127.0.0.1:9090"
    ```
## metrics_whitelist
  - **Einschränkungen / Validierung**: `IpNetwork[]`.
  - **Beschreibung**: CIDR-Allowlist für Metrik-Endpunktzugriff.
  - **Beispiel**:

    ```toml
    [server]
    metrics_port = 9090
    metrics_whitelist = ["127.0.0.1/32", "::1/128"]
    ```
## max_connections
  - **Einschränkungen / Validierung**: `u32`. `0` bedeutet unbegrenzt.
  - **Beschreibung**: Maximale Anzahl gleichzeitiger Clientverbindungen.
  - **Beispiel**:

    ```toml
    [server]
    max_connections = 10000
    ```
## accept_permit_timeout_ms
  - **Einschränkungen / Validierung**: `0..=60000` (Millisekunden). `0` behält das alte unbegrenzte Warteverhalten bei.
  - **Beschreibung**: Maximale Wartezeit für den Erhalt einer Verbindungs-Slot-Genehmigung, bevor die akzeptierte Verbindung getrennt wird.
  - **Beispiel**:

    ```toml
    [server]
    accept_permit_timeout_ms = 250
    ```


Hinweis: Wenn `server.proxy_protocol` aktiviert ist, werden eingehende PROXY-Protokollheader aus den ersten Bytes der Verbindung geparst und die Client-Source-Adresse wird durch `src_addr` aus dem Header ersetzt. Aus Sicherheitsgründen wird die Peer-Source-IP (die direkte Verbindungsadresse) anhand von `server.proxy_protocol_trusted_cidrs` überprüft. Wenn diese Liste leer ist, werden PROXY-Header abgelehnt und die Verbindung gilt als nicht vertrauenswürdig.

# [server.conntrack_control]

Hinweis: Der conntrack-control Worker wird **nur auf Linux** ausgeführt. Auf anderen Betriebssystemen wird es nicht gestartet; Wenn `inline_conntrack_control` den Wert `true` hat, wird eine Warnung protokolliert. Für einen effektiven Betrieb sind außerdem **CAP_NET_ADMIN** und ein nutzbares Backend (`nft` oder `iptables` / `ip6tables` auf `PATH` erforderlich. Das Dienstprogramm `conntrack` wird zum optionalen Löschen von Tabelleneinträgen unter Druck verwendet.


| Schlüssel | Typ | Default | Hot-Reload |
| --- | --- | --- | --- |
| [`inline_conntrack_control`](#inline_conntrack_control) | `bool` | `true` | `✘` |
| [`mode`](#mode) | `String` | `"tracked"` | `✘` |
| [`backend`](#backend) | `String` | `"auto"` | `✘` |
| [`profile`](#profile) | `String` | `"balanced"` | `✘` |
| [`hybrid_listener_ips`](#hybrid_listener_ips) | `IpAddr[]` | `[]` | `✘` |
| [`pressure_high_watermark_pct`](#pressure_high_watermark_pct) | `u8` | `85` | `✘` |
| [`pressure_low_watermark_pct`](#pressure_low_watermark_pct) | `u8` | `70` | `✘` |
| [`delete_budget_per_sec`](#delete_budget_per_sec) | `u64` | `4096` | `✘` |

## inline_conntrack_control
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Hauptschalter für die Runtime-conntrack-Kontrollaufgabe: gleicht **raw/notrack** netfilter-Regeln für den Listener-Eingang ab (siehe `mode`), lädt jede Sekunde Samples und kann **`conntrack -D`** Deletes für qualifizierende Close-Events ausführen, während der **Pressure-Modus** aktiv ist (siehe `delete_budget_per_sec`). Bei `false` werden die Notrack-Regeln gelöscht und pressure-gesteuerte Deletes deaktiviert.
  - **Beispiel**:

    ```toml
    [server.conntrack_control]
    inline_conntrack_control = true
    ```
## mode
  - **Einschränkungen / Validierung**: Einer von `tracked`, `notrack`, `hybrid` (Groß- und Kleinschreibung wird nicht beachtet; serialisierte Kleinschreibung).
  - **Beschreibung**: **`tracked`**: Telemt-Notrack-Regeln nicht installieren (Verbindungen bleiben in conntrack). **`notrack`**: Markieren Sie passenden Eingang TCP zu `server.port` als notrack – Ziele werden von `[[server.listeners]]` abgeleitet, falls vorhanden, andernfalls von `server.listen_addr_ipv4` / `server.listen_addr_ipv6` (nicht angegebene Adressen bedeuten „beliebig“ für diese Familie). **`hybrid`**: notrack nur für Adressen, die in `hybrid_listener_ips` aufgeführt sind (darf nicht leer sein; beim Laden validiert).
  - **Beispiel**:

    ```toml
    [server.conntrack_control]
    mode = "notrack"
    ```
## backend
  - **Einschränkungen / Validierung**: Einer von `auto`, `nftables`, `iptables` (Groß-/Kleinschreibung wird nicht beachtet; serialisierte Kleinschreibung).
  - **Beschreibung**: Welches Command-Set wendet Notrack-Regeln an? **`auto`**: `nft` verwenden, falls vorhanden auf `PATH`, sonst `iptables`/`ip6tables`, falls vorhanden. **`nftables`** / **`iptables`**: dieses Backend erzwingen; Fehlende Binaries bedeuten, dass Regeln nicht angewendet werden können. Der NFT-Pfad verwendet die Tabelle `inet telemt_conntrack` und einen Prerouting-Raw-Hook; iptables verwendet die Kette `TELEMT_NOTRACK` in der Tabelle `raw`.
  - **Beispiel**:

    ```toml
    [server.conntrack_control]
    backend = "auto"
    ```
## profile
  - **Einschränkungen / Validierung**: Einer von `conservative`, `balanced`, `aggressive` (Groß- und Kleinschreibung wird nicht berücksichtigt; serialisierte Kleinschreibung).
  - **Beschreibung**: Wenn **conntrack Pressure-Modus** aktiv ist (`pressure_*` Watermark), werden Leerlauf- und Aktivitäts-Timeouts begrenzt, um conntrack churn zu reduzieren: z. B. **Client-Leerlauf im ersten Byte** (`client.rs`), **Timeout für direkte Relay-Aktivität** (`direct_relay.rs`) und **Idle-Policy-Caps im mittleren Relay** (`middle_relay.rs` über `ConntrackPressureProfile::*_cap_secs` / `direct_activity_timeout_secs`). Aggressivere Profile verwenden kürzere Caps.
  - **Beispiel**:

    ```toml
    [server.conntrack_control]
    profile = "balanced"
    ```
## hybrid_listener_ips
  - **Einschränkungen / Validierung**: `IpAddr[]`. Muss **nicht leer** sein, wenn `mode = "hybrid"`. Ignoriert für `tracked` / `notrack`.
  - **Beschreibung**: Explizite Listener-Adressen, die Notrack-Regeln im Hybridmodus empfangen (aufgeteilt in IPv4 vs. IPv6 Regeln durch die Implementierung).
  - **Beispiel**:

    ```toml
    [server.conntrack_control]
    mode = "hybrid"
    hybrid_listener_ips = ["203.0.113.10", "2001:db8::1"]
    ```
## pressure_high_watermark_pct
  - **Einschränkungen / Validierung**: Muss innerhalb von `[1, 100]` liegen.
  - **Beschreibung**: Der Pressure-Modus **tritt ein**, wenn Folgendes zutrifft: Verbindungsfüllung vs. `server.max_connections` (Prozentsatz, wenn `max_connections > 0`), **File-Descriptor**-Nutzung vs. Prozess-Soft `RLIMIT_NOFILE`, **ungleich Null** `accept_permit_timeout`-Ereignisse im letzten Sample-Fenster oder **ME c2me send-full**-Zählerdelta. Der Eintrag vergleicht relevante Prozentsätze mit dieser Obergrenze (siehe `update_pressure_state` in `conntrack_control.rs`).
  - **Beispiel**:

    ```toml
    [server.conntrack_control]
    pressure_high_watermark_pct = 85
    ```
## pressure_low_watermark_pct
  - **Einschränkungen / Validierung**: Muss **unbedingt kleiner als** `pressure_high_watermark_pct` sein.
  - **Beschreibung**: Der Pressure-Modus **verlässt den Pressure-Zustand** erst nach **drei** aufeinanderfolgenden Ein-Sekunden-Samples, bei denen alle Signale bei oder unter diesem Low-Watermark liegen und die Accept-Timeout-/ME-Queue-Deltas Null sind (Hysterese).
  - **Beispiel**:

    ```toml
    [server.conntrack_control]
    pressure_low_watermark_pct = 70
    ```
## delete_budget_per_sec
  - **Einschränkungen / Validierung**: Muss `> 0` sein.
  - **Beschreibung**: Maximale Anzahl von **`conntrack -D`** Versuchen **pro Sekunde**, während der Pressure-Modus aktiv ist (Token-Bucket wird jede Sekunde aufgefüllt). Deletes laufen nur für Close-Events mit den Gründen **Timeout**, **Pressure** oder **Reset** ausgeführt. Jeder Versuch verbraucht einen Token, unabhängig vom Ergebnis.
  - **Beispiel**:

    ```toml
    [server.conntrack_control]
    delete_budget_per_sec = 4096
    ```


# [server.api]

Hinweis: Dieser Abschnitt akzeptiert auch den Legacy-Alias `[server.admin_api]` (gleiches Schema wie `[server.api]`).


| Schlüssel | Typ | Default | Hot-Reload |
| --- | --- | --- | --- |
| [`enabled`](#enabled) | `bool` | `true` | `✘` |
| [`listen`](#listen) | `String` | `"0.0.0.0:9091"` | `✘` |
| [`whitelist`](#whitelist) | `IpNetwork[]` | `["127.0.0.0/8"]` | `✘` |
| [`auth_header`](#auth_header) | `String` | `""` | `✘` |
| [`request_body_limit_bytes`](#request_body_limit_bytes) | `usize` | `65536` | `✘` |
| [`minimal_runtime_enabled`](#minimal_runtime_enabled) | `bool` | `true` | `✘` |
| [`minimal_runtime_cache_ttl_ms`](#minimal_runtime_cache_ttl_ms) | `u64` | `1000` | `✘` |
| [`runtime_edge_enabled`](#runtime_edge_enabled) | `bool` | `false` | `✘` |
| [`runtime_edge_cache_ttl_ms`](#runtime_edge_cache_ttl_ms) | `u64` | `1000` | `✘` |
| [`runtime_edge_top_n`](#runtime_edge_top_n) | `usize` | `10` | `✘` |
| [`runtime_edge_events_capacity`](#runtime_edge_events_capacity) | `usize` | `256` | `✘` |
| [`read_only`](#read_only) | `bool` | `false` | `✘` |
| [`gray_action`](#gray_action) | `"drop"`, `"api"` oder `"200"` | `"drop"` | `✘` |

## enabled
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert die Steuerungsebene REST API.
  - **Beispiel**:

    ```toml
    [server.api]
    enabled = true
    ```
## gray_action
  - **Einschränkungen / Validierung**: `"drop"`, `"api"` oder `"200"`.
  - **Beschreibung**: API-Antwortrichtlinie für graue/eingeschränkte Staaten: Anfrage verwerfen, normale API-Antwort bereitstellen oder `200 OK` erzwingen.
  - **Beispiel**:

    ```toml
    [server.api]
    gray_action = "drop"
    ```
## listen
  - **Einschränkungen / Validierung**: `String`. Muss im `IP:PORT`-Format vorliegen.
  - **Beschreibung**: API Bindungsadresse im `IP:PORT`-Format.
  - **Beispiel**:

    ```toml
    [server.api]
    listen = "0.0.0.0:9091"
    ```
## whitelist
  - **Einschränkungen / Validierung**: `IpNetwork[]`.
  - **Beschreibung**: CIDR-Allowlist darf auf API zugreifen.
  - **Beispiel**:

    ```toml
    [server.api]
    whitelist = ["127.0.0.0/8"]
    ```
## auth_header
  - **Einschränkungen / Validierung**: `String`. Eine leere String deaktiviert die Authentifizierungsheader-Validierung.
  - **Beschreibung**: Genauer erwarteter `Authorization`-Headerwert (statisches gemeinsames Geheimnis).
  - **Beispiel**:

    ```toml
    [server.api]
    auth_header = "Bearer MY_TOKEN"
    ```
## request_body_limit_bytes
  - **Einschränkungen / Validierung**: Muss `> 0` (Byte) sein.
  - **Beschreibung**: Maximal akzeptierte HTTP-Anfragetextgröße (Byte).
  - **Beispiel**:

    ```toml
    [server.api]
    request_body_limit_bytes = 65536
    ```
## minimal_runtime_enabled
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Ermöglicht minimale Runtime-Snapshots-Endpunktlogik.
  - **Beispiel**:

    ```toml
    [server.api]
    minimal_runtime_enabled = true
    ```
## minimal_runtime_cache_ttl_ms
  - **Einschränkungen / Validierung**: `0..=60000` (Millisekunden). `0` deaktiviert den Cache.
  - **Beschreibung**: Cache TTL für minimale Runtime-Snapshots (ms).
  - **Beispiel**:

    ```toml
    [server.api]
    minimal_runtime_cache_ttl_ms = 1000
    ```
## runtime_edge_enabled
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert Runtime-Edge-Endpunkte.
  - **Beispiel**:

    ```toml
    [server.api]
    runtime_edge_enabled = false
    ```
## runtime_edge_cache_ttl_ms
  - **Einschränkungen / Validierung**: `0..=60000` (Millisekunden).
  - **Beschreibung**: Cache TTL für Runtime-Edge-Aggregation-Payloaden (ms).
  - **Beispiel**:

    ```toml
    [server.api]
    runtime_edge_cache_ttl_ms = 1000
    ```
## runtime_edge_top_n
  - **Einschränkungen / Validierung**: `1..=1000`.
  - **Beschreibung**: Top-N-Größe für Edge-Verbindung und TLS Fingerprint-Bestenlisten-Snapshots.
  - **Beispiel**:

    ```toml
    [server.api]
    runtime_edge_top_n = 10
    ```
## runtime_edge_events_capacity
  - **Einschränkungen / Validierung**: `16..=4096`.
  - **Beschreibung**: Ringpufferkapazität für Runtime-Edge-Ereignisse.
  - **Beispiel**:

    ```toml
    [server.api]
    runtime_edge_events_capacity = 256
    ```
## read_only
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Lehnt mutierende API-Endpunkte ab, wenn diese aktiviert sind.
  - **Beispiel**:

    ```toml
    [server.api]
    read_only = false
    ```


# [[server.listeners]]


| Schlüssel | Typ | Default | Hot-Reload |
| --- | --- | --- | --- |
| [`ip`](#ip) | `IpAddr` | — | `✘` |
| [`port`](#port-serverlisteners) | `u16` | `server.port` | `✘` |
| [`client_mss`](#client_mss-serverlisteners) | `String` | `[server].client_mss` | `✘` |
| [`synlimit`](#synlimit-serverlisteners) | `false`, `"iptables"` oder `"nftables"` | `false` | `✔` |
| [`synlimit_seconds`](#synlimit_seconds-serverlisteners) | `u32` | `60` | `✔` |
| [`synlimit_hitcount`](#synlimit_hitcount-serverlisteners) | `u32` | `48` | `✔` |
| [`synlimit_burst`](#synlimit_burst-serverlisteners) | `u32` | `1` | `✔` |
| [`synlimit_ios_seconds`](#synlimit_ios_seconds-serverlisteners) | `u32` | `1` | `✔` |
| [`synlimit_ios_hitcount`](#synlimit_ios_hitcount-serverlisteners) | `u32` | `12` | `✔` |
| [`synlimit_ios_burst`](#synlimit_ios_burst-serverlisteners) | `u32` | `24` | `✔` |
| [`synlimit_hashlimit_expire_ms`](#synlimit_hashlimit_expire_ms-serverlisteners) | `u32` | `60000` | `✔` |
| [`synlimit_hashlimit_size`](#synlimit_hashlimit_size-serverlisteners) | `u32` | `32768` | `✔` |
| [`announce`](#announce) | `String` | — | `✘` |
| [`announce_ip`](#announce_ip) | `IpAddr` | — | `✘` |
| [`proxy_protocol`](#proxy_protocol) | `bool` | — | `✘` |
| [`reuse_allow`](#reuse_allow) | `bool` | `false` | `✘` |

## ip
  - **Einschränkungen / Validierung**: Erforderliches Feld. Muss ein `IpAddr` sein.
  - **Beschreibung**: Listener-Bindungs-IP.
  - **Beispiel**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    ```
## port (server.listeners)
  - **Einschränkungen / Validierung**: `u16` (optional). Wenn ausgelassen, wird auf `server.port`.
  - **Beschreibung**: Port pro Listener TCP.
  - **Beispiel**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    port = 443
    ```
## client_mss (server.listeners)
  - **Einschränkungen / Validierung**: `String` (optional). Gleiche Werte wie `[server].client_mss`.
  - **Beschreibung**: Pro-Listener-MSS-Override. Wenn ausgelassen, erbt `[server].client_mss`; Wenn es auf eine leere String festgelegt ist, wird das MSS-Shaping für diesen Listener deaktiviert, selbst wenn der globale Wert festgelegt ist. Änderungen erfordern einen Neustart/eine erneute Bindung des Listeners.
  - **Beispiel**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    port = 443
    client_mss = "256"
    ```
## synlimit (server.listeners)
  - **Einschränkungen / Validierung**: `false`, `"iptables"` oder `"nftables"`. Ausgelassen oder `false` deaktiviert SYN-Limiting für diesen Listener.
  - **Beschreibung**: Installiert pro Listener zweistufige Linux-netfilter-SYN-Fix-Regeln für den Listener-Port. `"iptables"` nutzt `iptables`/`ip6tables`-Filterregeln mit `hashlimit`, `length` und TTL/hop-limit Matches. `"nftables"` nutzt Telemt-eigene Tabellen mit per-source `meter`-Regeln und äquivalenten IPv4/IPv6-Classifieren. Die Regeln werden früh in `INPUT` eingefügt, akzeptieren SYN-Pakete unterhalb des Limits und lehnen SYN-Pakete oberhalb des Limits mit TCP RST ab, damit Clients zügig retryen statt auf ein stilles DROP-Timeout zu warten. Der generische Bucket wird über `synlimit_seconds`, `synlimit_hitcount` und `synlimit_burst` gesteuert; der iOS-ähnliche TTL/length-Bucket über `synlimit_ios_*`. Regeln werden zur Runtime reconciled und beim graceful Telemt-Shutdown entfernt; nach `SIGKILL` kann der Prozess sie nicht mehr bereinigen. Erfordert CAP_NET_ADMIN. `synlimit*` ist für vorhandene Listener-Endpunkte hot-reloadfähig; Änderungen an Listener-`ip` oder `port` erfordern weiterhin Restart/Rebind.
  - **Betreiberhinweis**: Telemt persistiert keine Regeln mit `iptables-persistent`, schreibt nicht nach `/etc/sysctl.d`, ändert keine systemd-Limits und modifiziert `client_mss` nicht. Host-Level-Tuning muss manuell angewendet werden, falls die Deployment-Policy es verlangt.
  - **Beispiel**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    port = 443
    synlimit = "iptables"

    [[server.listeners]]
    ip = "::"
    port = 443
    synlimit = "nftables"
    ```
## synlimit_seconds (server.listeners)
  - **Einschränkungen / Validierung**: `u32`, muss `> 0` sein. Der Default ist `60`.
  - **Beschreibung**: Generisches SYN-Fix-Token-Bucket-Intervall. Die Rate beträgt `synlimit_hitcount / synlimit_seconds` und wird in native netfilter-Rateneinheiten (`second`, `minute`, `hour` oder `day` gerendert. Dieser Bucket verarbeitet SYN-Pakete, die nicht mit dem iOS-ähnlichen Klassifizierer TTL/length übereinstimmen.
  - **Beispiel**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    port = 443
    synlimit = "iptables"
    synlimit_seconds = 60
    ```
## synlimit_hitcount (server.listeners)
  - **Einschränkungen / Validierung**: `u32`, muss `> 0` sein. Der Default ist `48`.
  - **Beschreibung**: Generischer SYN-Fix-Token-Bucket-Ratenbetrag. Zusammen mit `synlimit_seconds` definiert es die zulässige Source-IP-SYN-Rate, bevor überschüssige SYN-Pakete TCP RST empfangen.
  - **Beispiel**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    port = 443
    synlimit = "iptables"
    synlimit_hitcount = 48
    ```
## synlimit_burst (server.listeners)
  - **Einschränkungen / Validierung**: `u32`, muss `> 0` sein. Der Default ist `1`.
  - **Beschreibung**: Generische SYN-Fix-Token-Bucket-Burst-Größe. Höhere Werte ermöglichen kurze Verbindungsstöße von derselben Source-IP, bevor die stabile `synlimit_hitcount / synlimit_seconds`-Rate durchgesetzt wird.
  - **Beispiel**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    port = 443
    synlimit = "iptables"
    synlimit_burst = 1
    ```
## synlimit_ios_seconds (server.listeners)
  - **Einschränkungen / Validierung**: `u32`, muss `> 0` sein. Der Default ist `1`.
  - **Beschreibung**: Token-Bucket-Intervall für SYN-Pakete, die dem iOS-ähnlichen Classifier entsprechen. IPv4 entspricht der Paketlänge `64` und TTL `< 65`; IPv6 entspricht der Paketlänge `84` und dem Hop-Limit `< 65`.
  - **Beispiel**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    port = 443
    synlimit = "iptables"
    synlimit_ios_seconds = 1
    ```
## synlimit_ios_hitcount (server.listeners)
  - **Einschränkungen / Validierung**: `u32`, muss `> 0` sein. Der Default ist `12`.
  - **Beschreibung**: Token-Bucket-Ratenbetrag für den iOS-ähnlichen SYN-Classifier.
  - **Beispiel**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    port = 443
    synlimit = "iptables"
    synlimit_ios_hitcount = 12
    ```
## synlimit_ios_burst (server.listeners)
  - **Einschränkungen / Validierung**: `u32`, muss `> 0` sein. Der Default ist `24`.
  - **Beschreibung**: Token-Bucket-Burst-Größe für den iOS-ähnlichen SYN-Classifier.
  - **Beispiel**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    port = 443
    synlimit = "iptables"
    synlimit_ios_burst = 24
    ```
## synlimit_hashlimit_expire_ms (server.listeners)
  - **Einschränkungen / Validierung**: `u32`, muss `> 0` sein. Der Default ist `60000`.
  - **Beschreibung**: Eintragsablauf in Millisekunden für iptables/ip6tables Hashlimit-Buckets. nftables-Messgeräte verwenden den vom Kernel verwalteten Zustand und machen diesen genauen Knopf nicht verfügbar.
  - **Beispiel**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    port = 443
    synlimit = "iptables"
    synlimit_hashlimit_expire_ms = 60000
    ```
## synlimit_hashlimit_size (server.listeners)
  - **Einschränkungen / Validierung**: `u32`, muss `> 0` sein. Der Default ist `32768`.
  - **Beschreibung**: Hash-Tabellengröße für iptables/ip6tables Hashlimit-Buckets. nftables-Messgeräte verwenden den vom Kernel verwalteten Zustand und machen diesen genauen Knopf nicht verfügbar.
  - **Beispiel**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    port = 443
    synlimit = "iptables"
    synlimit_hashlimit_size = 32768
    ```
## announce
  - **Einschränkungen / Validierung**: `String` (optional). Darf beim Setzen nicht leer sein.
  - **Beschreibung**: Öffentliche IP/Domäne in Proxy-Links für diesen Listener angekündigt. Hat Vorrang vor `announce_ip`.
  - **Beispiel**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    announce = "proxy.example.com"
    ```
## announce_ip
  - **Einschränkungen / Validierung**: `IpAddr` (optional). Veraltet. Verwenden Sie `announce`.
  - **Beschreibung**: Veraltete Legacy-Ankündigungs-IP. Während des Ladens der Konfiguration wird es nach `announce` migriert, wenn `announce` nicht festgelegt ist.
  - **Beispiel**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    announce_ip = "203.0.113.10"
    ```
## proxy_protocol
  - **Einschränkungen / Validierung**: `bool` (optional). Wenn gesetzt, wird `server.proxy_protocol` für diesen Listener überschrieben.
  - **Beschreibung**: Pro-Listener-PROXY-Protokollüberschreibung.
  - **Beispiel**:

    ```toml
    [server]
    proxy_protocol = false

    [[server.listeners]]
    ip = "0.0.0.0"
    proxy_protocol = true
    ```
## reuse_allow
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert `SO_REUSEPORT` für die Bind-Freigabe mehrerer Instanzen (ermöglicht mehreren Telemt-Instanzen, auf demselben `ip:port` zu lauschen).
  - **Beispiel**:

    ```toml
    [[server.listeners]]
    ip = "0.0.0.0"
    reuse_allow = false
    ```


# [timeouts]


| Schlüssel | Typ | Default | Hot-Reload |
| --- | --- | --- | --- |
| [`client_first_byte_idle_secs`](#client_first_byte_idle_secs) | `u64` | `300` | `✘` |
| [`client_handshake`](#client_handshake) | `u64` | `30` | `✘` |
| [`relay_idle_policy_v2_enabled`](#relay_idle_policy_v2_enabled) | `bool` | `true` | `✘` |
| [`relay_client_idle_soft_secs`](#relay_client_idle_soft_secs) | `u64` | `120` | `✘` |
| [`relay_client_idle_hard_secs`](#relay_client_idle_hard_secs) | `u64` | `360` | `✘` |
| [`relay_idle_grace_after_downstream_activity_secs`](#relay_idle_grace_after_downstream_activity_secs) | `u64` | `30` | `✘` |
| [`client_keepalive`](#client_keepalive) | `u64` | `15` | `✘` |
| [`client_ack`](#client_ack) | `u64` | `90` | `✘` |
| [`me_one_retry`](#me_one_retry) | `u8` | `12` | `✘` |
| [`me_one_timeout_ms`](#me_one_timeout_ms) | `u64` | `1200` | `✘` |

## client_handshake
  - **Einschränkungen / Validierung**: Muss `> 0` sein. Der Wert wird in Sekunden angegeben. Wird auch als Obergrenze für einige TLS Emulationsverzögerungen verwendet (siehe `censorship.server_hello_delay_max_ms`).
  - **Beschreibung**: Client-Handshake-Timeout (Sekunden).
  - **Beispiel**:

    ```toml
    [timeouts]
    client_handshake = 30
    ```
## client_first_byte_idle_secs
  - **Einschränkungen / Validierung**: `u64` (Sekunden). `0` deaktiviert die Erzwingung des Leerlaufs im ersten Byte.
  - **Beschreibung**: Maximale Leerlaufzeit zum Warten auf das erste Client-Payloadbyte nach dem Sitzungsaufbau.
  - **Beispiel**:

    ```toml
    [timeouts]
    client_first_byte_idle_secs = 300
    ```
## relay_idle_policy_v2_enabled
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert Soft-/Hard-Middle-Relay-Client-Leerlaufrichtlinie.
  - **Beispiel**:

    ```toml
    [timeouts]
    relay_idle_policy_v2_enabled = true
    ```
## relay_client_idle_soft_secs
  - **Einschränkungen / Validierung**: Muss `> 0` sein; muss `<= relay_client_idle_hard_secs` sein.
  - **Beschreibung**: Soft-Idle-Schwellenwert (Sekunden) für Inaktivität des Middle-Relay-Client-Uplinks. Das Erreichen dieses Schwellenwerts markiert die Sitzung als Leerlaufkandidaten (je nach Richtlinie kann sie möglicherweise bereinigt werden).
  - **Beispiel**:

    ```toml
    [timeouts]
    relay_client_idle_soft_secs = 120
    ```
## relay_client_idle_hard_secs
  - **Einschränkungen / Validierung**: Muss `> 0` sein; muss `>= relay_client_idle_soft_secs` sein.
  - **Beschreibung**: Harter Leerlaufschwellenwert (Sekunden) für Inaktivität des Middle-Relay-Client-Uplinks. Wenn dieser Schwellenwert erreicht wird, wird die Sitzung geschlossen.
  - **Beispiel**:

    ```toml
    [timeouts]
    relay_client_idle_hard_secs = 360
    ```
## relay_idle_grace_after_downstream_activity_secs
  - **Einschränkungen / Validierung**: Muss `<= relay_client_idle_hard_secs` sein.
  - **Beschreibung**: Zusätzliche Hard-Idle-Kulanzfrist (Sekunden) wurde nach der letzten Downstream-Aktivität hinzugefügt.
  - **Beispiel**:

    ```toml
    [timeouts]
    relay_idle_grace_after_downstream_activity_secs = 30
    ```
## client_keepalive
  - **Einschränkungen / Validierung**: `u64`. Der Wert wird in Sekunden angegeben.
  - **Beschreibung**: Client-Keepalive-Timeout (Sekunden).
  - **Beispiel**:

    ```toml
    [timeouts]
    client_keepalive = 15
    ```
## client_ack
  - **Einschränkungen / Validierung**: `u64`. Der Wert wird in Sekunden angegeben.
  - **Beschreibung**: Client ACK Timeout (Sekunden).
  - **Beispiel**:

    ```toml
    [timeouts]
    client_ack = 90
    ```
## me_one_retry
  - **Einschränkungen / Validierung**: `u8`.
  - **Beschreibung**: Budget für schnelle Wiederverbindungsversuche für Einzelendpunkt-DC-Szenarien.
  - **Beispiel**:

    ```toml
    [timeouts]
    me_one_retry = 12
    ```
## me_one_timeout_ms
  - **Einschränkungen / Validierung**: `u64`. Der Wert wird in Millisekunden angegeben.
  - **Beschreibung**: Timeout pro Schnellversuch (ms) für DC-Wiederverbindungslogik für einen einzelnen Endpunkt.
  - **Beispiel**:

    ```toml
    [timeouts]
    me_one_timeout_ms = 1200
    ```


# [censorship]


| Schlüssel | Typ | Default | Hot-Reload |
| --- | --- | --- | --- |
| [`tls_domain`](#tls_domain) | `String` | `"petrovich.ru"` | `✘` |
| [`tls_domains`](#tls_domains) | `String[]` | `[]` | `✘` |
| [`unknown_sni_action`](#unknown_sni_action) | `"drop"`, `"mask"`, `"accept"`, `"reject_handshake"` | `"drop"` | `✘` |
| [`tls_fetch_scope`](#tls_fetch_scope) | `String` | `""` | `✘` |
| [`tls_fetch`](#tls_fetch) | `Table` | integrierte Standardeinstellungen | `✘` |
| [`mask`](#mask) | `bool` | `true` | `✘` |
| [`mask_host`](#mask_host) | `String` | — | `✘` |
| [`mask_port`](#mask_port) | `u16` | `443` | `✘` |
| [`mask_unix_sock`](#mask_unix_sock) | `String` | — | `✘` |
| [`fake_cert_len`](#fake_cert_len) | `usize` | `2048` | `✘` |
| [`tls_emulation`](#tls_emulation) | `bool` | `true` | `✘` |
| [`tls_front_dir`](#tls_front_dir) | `String` | `"tlsfront"` | `✘` |
| [`server_hello_delay_min_ms`](#server_hello_delay_min_ms) | `u64` | `0` | `✘` |
| [`server_hello_delay_max_ms`](#server_hello_delay_max_ms) | `u64` | `0` | `✘` |
| [`tls_new_session_tickets`](#tls_new_session_tickets) | `u8` | `0` | `✘` |
| [`tls_full_cert_ttl_secs`](#tls_full_cert_ttl_secs) | `u64` | `90` | `✘` |
| [`serverhello_compact`](#serverhello_compact) | `bool` | `false` | `✘` |
| [`alpn_enforce`](#alpn_enforce) | `bool` | `true` | `✘` |
| [`mask_proxy_protocol`](#mask_proxy_protocol) | `u8` | `0` | `✘` |
| [`mask_shape_hardening`](#mask_shape_hardening) | `bool` | `true` | `✘` |
| [`mask_shape_hardening_aggressive_mode`](#mask_shape_hardening_aggressive_mode) | `bool` | `false` | `✘` |
| [`mask_shape_bucket_floor_bytes`](#mask_shape_bucket_floor_bytes) | `usize` | `512` | `✘` |
| [`mask_shape_bucket_cap_bytes`](#mask_shape_bucket_cap_bytes) | `usize` | `4096` | `✘` |
| [`mask_shape_above_cap_blur`](#mask_shape_above_cap_blur) | `bool` | `false` | `✘` |
| [`mask_shape_above_cap_blur_max_bytes`](#mask_shape_above_cap_blur_max_bytes) | `usize` | `512` | `✘` |
| [`mask_relay_max_bytes`](#mask_relay_max_bytes) | `usize` | `5242880` | `✘` |
| [`mask_relay_timeout_ms`](#mask_relay_timeout_ms) | `u64` | `60_000` | `✘` |
| [`mask_relay_idle_timeout_ms`](#mask_relay_idle_timeout_ms) | `u64` | `5_000` | `✘` |
| [`mask_classifier_prefetch_timeout_ms`](#mask_classifier_prefetch_timeout_ms) | `u64` | `5` | `✘` |
| [`mask_timing_normalization_enabled`](#mask_timing_normalization_enabled) | `bool` | `false` | `✘` |
| [`mask_timing_normalization_floor_ms`](#mask_timing_normalization_floor_ms) | `u64` | `0` | `✘` |
| [`mask_timing_normalization_ceiling_ms`](#mask_timing_normalization_ceiling_ms) | `u64` | `0` | `✘` |

## tls_domain
  - **Einschränkungen / Validierung**: Muss ein nicht leerer Domainname sein. Darf keine Leerzeichen und kein `/` enthalten.
  - **Beschreibung**: Primäre Domäne, die für das Fake-TLS-Masking-/Fronting-Profil verwendet wird und als Standard-SNI-Domäne für Clients angezeigt wird.
    Dieser Wert wird Teil der generierten `ee`-Links; eine Änderung macht zuvor generierte Links ungültig.
  - **Beispiel**:

    ```toml
    [censorship]
    tls_domain = "example.com"
    ```
## tls_domains
  - **Einschränkungen / Validierung**: `String[]`. Wenn gesetzt, werden Werte mit `tls_domain` zusammengeführt und dedupliziert (primäres `tls_domain` bleibt immer zuerst).
  - **Beschreibung**: Zusätzliche TLS-Domänen zum Generieren mehrerer Proxy-Links.
  - **Beispiel**:

    ```toml
    [censorship]
    tls_domain = "example.com"
    tls_domains = ["example.net", "example.org"]
    ```
## unknown_sni_action
  - **Einschränkungen / Validierung**: `"drop"`, `"mask"`, `"accept"` oder `"reject_handshake"`.
  - **Beschreibung**: Aktion für TLS ClientHello mit unbekanntem/nicht konfiguriertem SNI.
    - `drop` — schließt die Verbindung ohne Antwort (stilles FIN nach Anwendung von `server_hello_delay`). Timing-identisch zum Success-Zweig, aber auf dem Wire leiser als ein echter Webserver.
    - `mask` — proxyt die Verbindung transparent zu `mask_host:mask_port` (TLS-Fronting). Der Client erhält ein echtes ServerHello vom Backend mit dessen echtem Zertifikat. Maximale Tarnung, öffnet aber für jede fehlgeleitete Anfrage eine ausgehende Verbindung.
    - `accept` — behandelt SNI so, als wäre es gültig, und fährt im Auth-Pfad fort. Schwächt die Resistenz gegen aktives Probing; nur in engen Szenarien sinnvoll.
    - `reject_handshake` — sendet einen fatalen TLS-Alert `unrecognized_name` (RFC 6066, AlertDescription = 112) und schließt die Verbindung. Auf dem Wire identisch zu einem modernen nginx mit `ssl_reject_handshake on;` im Default-vhost: wirkt wie ein gewöhnlicher HTTPS-Server, der den angefragten Namen schlicht nicht hostet. Empfohlen, wenn maximale Parität mit einem Standard-Webserver wichtiger ist als TLS-Fronting. `server_hello_delay` wird absichtlich **nicht** auf diesen Zweig angewendet, sodass der Alert wie bei Referenz-nginx „sofort“ gesendet wird.
  - **Beispiel**:

    ```toml
    [censorship]
    unknown_sni_action = "reject_handshake"
    ```
## tls_fetch_scope
  - **Einschränkungen / Validierung**: `String`. Der Wert wird beim Laden getrimmt; whitespace-only wird leer.
  - **Beschreibung**: Upstream-Scope-Tag für TLS-Front-Metadatenabrufe. Ein leerer Wert behält das Default-Upstream-Routing bei.
  - **Beispiel**:

    ```toml
    [censorship]
    tls_fetch_scope = "fetch"
    ```
## tls_fetch
  - **Einschränkungen / Validierung**: Tabelle. Siehe Abschnitt `[censorship.tls_fetch]` unten.
  - **Beschreibung**: Einstellungen für die TLS-Front-Metadatenstrategie (Bootstrap + Refresh-Verhalten für TLS-Emulationsdaten).
  - **Beispiel**:

    ```toml
    [censorship.tls_fetch]
    strict_route = true
    attempt_timeout_ms = 5000
    total_budget_ms = 15000
    ```
## mask
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert den Masking-/Fronting-Relay-Modus.
  - **Beispiel**:

    ```toml
    [censorship]
    mask = true
    ```
## mask_host
  - **Einschränkungen / Validierung**: `String` (optional).
    - Wenn `mask_unix_sock` gesetzt ist, muss `mask_host` ausgelassen werden (mutually exclusive).
    - Wenn weder `mask_host` noch `mask_unix_sock` gesetzt ist, verwendet Telemt standardmäßig `tls_domain` als `mask_host`.
  - **Beschreibung**: Upstream-Mask-Host für das TLS-Fronting-Relay.
  - **Beispiel**:

    ```toml
    [censorship]
    mask_host = "www.cloudflare.com"
    ```
## mask_port
  - **Einschränkungen / Validierung**: `u16`.
  - **Beschreibung**: Upstream-Mask-Port für das TLS-Fronting-Relay.
  - **Beispiel**:

    ```toml
    [censorship]
    mask_port = 443
    ```
## exclusive_mask
  - **Einschränkungen / Validierung**: TOML-Map. Schlüssel müssen SNI-Domainnamen sein. Werte müssen `host:port` mit `port > 0` sein; IPv6-Literale müssen geklammert sein.
  - **Beschreibung**: Per-SNI TCP-Mask-Ziele für Fallback-Traffic. Wenn die SNI eines TLS ClientHello einen Schlüssel trifft, relayed Telemt diese nicht authentifizierte Verbindung zum gemappten Ziel. Sonstiger Fallback-Traffic nutzt weiterhin das vorhandene `mask_host`/`mask_port` oder das SNI-aware Default-Masking-Verhalten.
  - **Beispiel**:

    ```toml
    [censorship]
    tls_domains = ["petrovich.ru", "bsi.bund.de", "telekom.com"]

    [censorship.exclusive_mask]
    "bsi.bund.de" = "127.0.0.1:443"
    ```
## mask_unix_sock
  - **Einschränkungen / Validierung**: `String` (optional).
    - Darf nicht leer sein, wenn gesetzt.
    - Nur Unix; auf Nicht-Unix-Plattformen abgelehnt.
    - Auf Unix muss der Pfad \(\le 107\) Bytes lang sein.
    - Mutually exclusive mit `mask_host`.
  - **Beschreibung**: Unix-Socket-Pfad für das Mask-Backend statt TCP `mask_host`/`mask_port`.
  - **Beispiel**:

    ```toml
    [censorship]
    mask_unix_sock = "/run/telemt/mask.sock"
    ```
## fake_cert_len
  - **Einschränkungen / Validierung**: `usize`. Wenn `tls_emulation = false` und der Default-Wert verwendet wird, kann Telemt diesen Wert beim Start für mehr Varianz randomisieren.
  - **Beschreibung**: Länge der Payload des synthetischen Zertifikats, wenn Emulationsdaten nicht verfügbar sind.
  - **Beispiel**:

    ```toml
    [censorship]
    fake_cert_len = 2048
    ```
## tls_emulation
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Ermöglicht die Verhaltensemulation von Zertifikaten/TLS von zwischengespeicherten realen Fronten.
  - **Beispiel**:

    ```toml
    [censorship]
    tls_emulation = true
    ```
## tls_front_dir
  - **Einschränkungen / Validierung**: `String`.
  - **Beschreibung**: Verzeichnispfad für TLS-Front-Cache-Speicher.
  - **Beispiel**:

    ```toml
    [censorship]
    tls_front_dir = "tlsfront"
    ```
## server_hello_delay_min_ms
  - **Einschränkungen / Validierung**: `u64` (Millisekunden).
  - **Beschreibung**: Mindestverzögerung von `server_hello` für Anti-Fingerprint-Verhalten (ms).
  - **Beispiel**:

    ```toml
    [censorship]
    server_hello_delay_min_ms = 0
    ```
## server_hello_delay_max_ms
  - **Einschränkungen / Validierung**: `u64` (Millisekunden). Muss \(<\) `timeouts.client_handshake * 1000`.
  - **Beschreibung**: Maximale `server_hello` Verzögerung für Anti-Fingerprint-Verhalten (ms).
  - **Beispiel**:

    ```toml
    [timeouts]
    client_handshake = 30

    [censorship]
    server_hello_delay_max_ms = 0
    ```
## tls_new_session_tickets
  - **Einschränkungen / Validierung**: `u8`.
  - **Beschreibung**: Anzahl der `NewSessionTicket` Nachrichten, die nach dem Handshake ausgegeben werden sollen.
  - **Beispiel**:

    ```toml
    [censorship]
    tls_new_session_tickets = 0
    ```
## tls_full_cert_ttl_secs
  - **Einschränkungen / Validierung**: `u64` (Sekunden).
  - **Beschreibung**: TTL zum Senden der vollständigen Zertifikat-Payload pro (Domäne, Client-IP)-Tupel.
  - **Beispiel**:

    ```toml
    [censorship]
    tls_full_cert_ttl_secs = 90
    ```
## serverhello_compact
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Ermöglicht das kompakte ServerHello/Fake-TLS-Profil, um die Signatur der Antwortgröße zu reduzieren.
  - **Beispiel**:

    ```toml
    [censorship]
    serverhello_compact = false
    ```
## alpn_enforce
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Erzwingt das Echoverhalten von ALPN basierend auf der Clientpräferenz.
  - **Beispiel**:

    ```toml
    [censorship]
    alpn_enforce = true
    ```
## mask_proxy_protocol
  - **Einschränkungen / Validierung**: `u8`. `0` = deaktiviert, `1` = v1 (Text), `2` = v2 (binär).
  - **Beschreibung**: Sendet den Protokoll-Header PROXY, wenn eine Verbindung zum Mask-Backend hergestellt wird, sodass das Backend die echte Client-IP sehen kann.
  - **Beispiel**:

    ```toml
    [censorship]
    mask_proxy_protocol = 0
    ```
## mask_shape_hardening
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert Client->Mask Shape-Channel-Hardening, indem beim Shutdown des Mask-Relay kontrolliertes Tail-Padding auf Bucket-Grenzen angewendet wird.
  - **Beispiel**:

    ```toml
    [censorship]
    mask_shape_hardening = true
    ```
## mask_shape_hardening_aggressive_mode
  - **Einschränkungen / Validierung**: Erfordert `mask_shape_hardening = true`.
  - **Beschreibung**: Aggressives Shaping-Profil aktivieren (stärkeres Anti-Classifier-Verhalten mit unterschiedlicher Shaping-Semantik).
  - **Beispiel**:

    ```toml
    [censorship]
    mask_shape_hardening = true
    mask_shape_hardening_aggressive_mode = false
    ```
## mask_shape_bucket_floor_bytes
  - **Einschränkungen / Validierung**: Muss `> 0` sein; muss `<= mask_shape_bucket_cap_bytes` sein.
  - **Beschreibung**: Minimale Bucket-Größe für Shape-Channel-Hardening.
  - **Beispiel**:

    ```toml
    [censorship]
    mask_shape_bucket_floor_bytes = 512
    ```
## mask_shape_bucket_cap_bytes
  - **Einschränkungen / Validierung**: Muss `>= mask_shape_bucket_floor_bytes` sein.
  - **Beschreibung**: Maximale Bucket-Größe für Shape-Channel-Hardening; Traffic oberhalb des Caps wird nicht weiter bucket-gepaddet.
  - **Beispiel**:

    ```toml
    [censorship]
    mask_shape_bucket_cap_bytes = 4096
    ```
## mask_shape_above_cap_blur
  - **Einschränkungen / Validierung**: Erfordert `mask_shape_hardening = true`.
  - **Beschreibung**: Fügt begrenzte, randomisierte Endbytes hinzu, selbst wenn die weitergeleitete Größe bereits die Obergrenze überschreitet.
  - **Beispiel**:

    ```toml
    [censorship]
    mask_shape_hardening = true
    mask_shape_above_cap_blur = false
    ```
## mask_shape_above_cap_blur_max_bytes
  - **Einschränkungen / Validierung**: Muss `<= 1048576` sein. Muss `> 0` sein, wenn `mask_shape_above_cap_blur = true`.
  - **Beschreibung**: Maximale Anzahl zufälliger Zusatzbytes oberhalb des Caps, wenn above-cap blur aktiv ist.
  - **Beispiel**:

    ```toml
    [censorship]
    mask_shape_above_cap_blur = true
    mask_shape_above_cap_blur_max_bytes = 64
    ```
## mask_relay_max_bytes
  - **Einschränkungen / Validierung**: Muss `> 0` sein; muss `<= 67108864` sein.
  - **Beschreibung**: Maximal weitergeleitete Bytes pro Richtung auf dem nicht authentifizierten Masking-Fallback-Pfad.
  - **Beispiel**:

    ```toml
    [censorship]
    mask_relay_max_bytes = 5242880
    ```
## mask_relay_timeout_ms
  - **Einschränkungen / Validierung**: Sollte `>= mask_relay_idle_timeout_ms` sein.
  - **Beschreibung**: Wall-clock-Obergrenze für das komplette Mask-Relay auf Nicht-MTProto-Fallbackpfaden. Erhöhen, wenn das Mask-Ziel ein langlebiger Dienst ist (z. B. WebSocket). Default: 60.000 ms (1 Minute).
  - **Beispiel**:

    ```toml
    [censorship]
    mask_relay_timeout_ms = 60000
    ```
## mask_relay_idle_timeout_ms
  - **Einschränkungen / Validierung**: Sollte `<= mask_relay_timeout_ms` sein.
  - **Beschreibung**: Per-read idle timeout für Mask-Relay- und Drain-Pfade. Begrenzt Ressourcenverbrauch durch Slow-Loris-Angriffe und Port-Scanner. Ein Read, der länger als dieser Wert hängt, gilt als abgebrochene Verbindung. Default: 5.000 ms (5 s).
  - **Beispiel**:

    ```toml
    [censorship]
    mask_relay_idle_timeout_ms = 5000
    ```
## mask_classifier_prefetch_timeout_ms
  - **Einschränkungen / Validierung**: Muss innerhalb von `[5, 50]` (Millisekunden) liegen.
  - **Beschreibung**: Timeout-Budget (ms) für die Erweiterung des fragmentierten anfänglichen Classifierfensters beim Masking-Fallback.
  - **Beispiel**:

    ```toml
    [censorship]
    mask_classifier_prefetch_timeout_ms = 5
    ```
## mask_timing_normalization_enabled
  - **Einschränkungen / Validierung**: Wenn `true`, sind `mask_timing_normalization_floor_ms > 0` und `mask_timing_normalization_ceiling_ms >= mask_timing_normalization_floor_ms` erforderlich. Die Obergrenze muss `<= 60000`.
  - **Beschreibung**: Aktiviert die Normalisierung der Timing-Hüllkurve für Masking-Ergebnisse.
  - **Beispiel**:

    ```toml
    [censorship]
    mask_timing_normalization_enabled = false
    ```
## mask_timing_normalization_floor_ms
  - **Einschränkungen / Validierung**: Muss `> 0` sein, wenn die Timing-Normalisierung aktiviert ist; muss `<= mask_timing_normalization_ceiling_ms` sein.
  - **Beschreibung**: Untergrenze (ms) für das Normalisierungsziel von Masking-Ergebnissen.
  - **Beispiel**:

    ```toml
    [censorship]
    mask_timing_normalization_floor_ms = 0
    ```
## mask_timing_normalization_ceiling_ms
  - **Einschränkungen / Validierung**: Muss `>= mask_timing_normalization_floor_ms` sein; muss `<= 60000` sein.
  - **Beschreibung**: Obergrenze (ms) für das Normalisierungsziel von Masking-Ergebnissen.
  - **Beispiel**:

    ```toml
    [censorship]
    mask_timing_normalization_ceiling_ms = 0
    ```

## Shape-channel hardening notes (`[censorship]`)

Diese Parameter reduzieren eine konkrete Fingerprint-Quelle im Masking-Pfad: die exakte Bytezahl, die der Proxy bei ungültigem oder sondierendem Traffic an `mask_host` sendet.

Ohne Hardening kann ein Zensor die Länge der Probe häufig sehr genau mit der vom Backend beobachteten Länge korrelieren, zum Beispiel `5 + body_sent` auf frühen TLS-Reject-Pfaden. Daraus entsteht ein längenbasiertes Classifiersignal.

Wenn `mask_shape_hardening = true`, padded Telemt das Ende des **client->mask**-Streams beim Relay-Shutdown auf eine Bucket-Grenze:

- Zuerst wird die Gesamtzahl der an das Mask-Ziel gesendeten Bytes gemessen.
- Der Bucket wird über Zweierpotenzen ab `mask_shape_bucket_floor_bytes` gewählt.
- Padding wird nur hinzugefügt, wenn die Gesamtzahl unter `mask_shape_bucket_cap_bytes` liegt.
- Wenn die Bytezahl bereits über dem Cap liegt, wird kein weiteres Padding hinzugefügt.

Dadurch fallen mehrere nahe Probe-Größen in dieselbe vom Backend beobachtete Größenklasse, was aktive Klassifizierung erschwert.

Was jeder Parameter in der Praxis ändert:

- `mask_shape_hardening`
Aktiviert oder deaktiviert diese gesamte Length-Shaping-Phase auf dem Fallback-Pfad.
Bei `false` bleibt die vom Backend beobachtete Länge nah an der tatsächlich weitergeleiteten Probe-Länge.
Bei `true` kann ein sauberer Relay-Shutdown zufällige Padding-Bytes anhängen, um die Summe in einen Bucket zu verschieben.
- `mask_shape_bucket_floor_bytes`
Legt die erste Bucket-Grenze für kleine Probes fest.
Beispiel: Mit Floor `512` kann eine fehlerhafte Probe, die sonst `37` Bytes weiterleiten würde, bei sauberem EOF auf `512` Bytes erweitert werden.
Größere Floor-Werte verstecken sehr kleine Probes besser, erhöhen aber die Egress-Kosten.
- `mask_shape_bucket_cap_bytes`
Legt den größten Bucket fest, bis zu dem Telemt mit Bucket-Logik padded.
Beispiel: Mit Cap `4096` kann eine weitergeleitete Gesamtlänge von `1800` Bytes je nach Bucket-Leiter auf `2048` oder `4096` gepaddet werden; eine Summe, die bereits über `4096` liegt, wird nicht weiter gepaddet.
Größere Caps erweitern den Bereich, in dem Größenklassen reduziert werden, erhöhen aber auch den Worst-Case-Overhead.
- Sauberes EOF ist im konservativen Modus wichtig
Im Default-Profil ist Shape-Padding bewusst konservativ: Es wird beim sauberen Relay-Shutdown angewendet, nicht auf jedem Timeout-/Drop-Pfad.
So werden neue Timeout-Tail-Artefakte vermieden, die manche Backends oder Tests als separaten Fingerprint interpretieren könnten.

Praktische Kompromisse:

- Besserer Schutz gegen Fingerprinting über Größen-/Shape-Kanäle.
- Durch Padding etwas höherer Egress-Overhead bei kleinen Probes.
- Das Verhalten ist absichtlich konservativ und standardmäßig aktiviert.

Empfohlenes Startprofil:

- `mask_shape_hardening = true` (Standard)
- `mask_shape_bucket_floor_bytes = 512`
- `mask_shape_bucket_cap_bytes = 4096`

## Aggressive mode notes (`[censorship]`)

`mask_shape_hardening_aggressive_mode` ist ein Opt-in-Profil für stärkeren Anti-Classifier-Druck.

- Die Standardeinstellung ist `false`, um ein konservatives Timeout-/No-Tail-Verhalten beizubehalten.
- Erfordert `mask_shape_hardening = true`.
- Wenn aktiviert, können backend-stille Nicht-EOF-Masking-Pfade geshaped werden.
- Zusammen mit above-cap blur nutzt der zufällige Zusatz-Tail `[1, max]` statt `[0, max]`.

Was ändert sich, wenn der aggressive Modus aktiviert ist:

- Backend-silent Timeout-Pfade können geshaped werden
Im Default-Modus erhält ein Client, der den Socket halb offen hält und einen Timeout auslöst, auf diesem Pfad normalerweise kein Shape-Padding.
Im aggressiven Modus kann Telemt eine solche backend-silent Session trotzdem shapen, sofern keine Backend-Bytes zurückgegeben wurden.
Das zielt speziell auf aktive Probes, die EOF vermeiden wollen, um eine exakte vom Backend beobachtete Länge zu behalten.
- Above-cap blur hängt immer mindestens ein Byte an
Im Default-Modus darf above-cap blur `0` wählen, sodass manche übergroßen Probes weiterhin auf ihrer exakten weitergeleiteten Basislänge landen.
Im aggressiven Modus wird dieses exakte Basis-Sample durch Konstruktion entfernt.
- Kompromiss
Der aggressive Modus verbessert die Resistenz gegen aktive Length-Classifier, ist aber weniger konservativ.
Wenn Ihr Deployment strikte Kompatibilität mit Timeout-/No-Tail-Semantik priorisiert, lassen Sie ihn deaktiviert.
Wenn Ihr Threat Model wiederholte aktive Probes durch einen Zensor umfasst, ist dieser Modus das stärkere Profil.

Verwenden Sie diesen Modus nur, wenn Ihr Threat Model Classifier-Resistenz höher priorisiert als strikte Kompatibilität mit konservativer Masking-Semantik.

## Above-cap blur notes (`[censorship]`)

`mask_shape_above_cap_blur` fügt eine zweite Blur-Stufe für sehr große Probes hinzu, die bereits über `mask_shape_bucket_cap_bytes` liegen.

- Im Standardmodus wird ein zufälliges Ende in `[0, mask_shape_above_cap_blur_max_bytes]` angehängt.
- Im aggressiven Modus ist der zufällige Tail strikt positiv: `[1, mask_shape_above_cap_blur_max_bytes]`.
- Das reduziert exakte Leakage oberhalb des Caps bei begrenztem Overhead.
- Halten Sie `mask_shape_above_cap_blur_max_bytes` konservativ, um unnötiges Egress-Wachstum zu vermeiden.

Betriebliche Bedeutung:

- Ohne above-cap blur
Eine Probe, die `5005` Bytes weiterleitet, sieht für das Backend weiterhin wie `5005` Bytes aus, wenn sie bereits über dem Cap liegt.
- Mit aktiviertem above-cap blur
Dieselbe Probe kann wie jeder Wert in einem begrenzten Fenster oberhalb ihrer Basislänge aussehen.
Beispiel mit `mask_shape_above_cap_blur_max_bytes = 64`:
Die vom Backend beobachtete Größe wird im Default-Modus zu `5005..5069` oder im aggressiven Modus zu `5006..5069`.
- Auswahl von `mask_shape_above_cap_blur_max_bytes`
Kleine Werte senken Kosten, lassen weit auseinanderliegende übergroße Klassen aber besser trennbar.
Größere Werte verwischen übergroße Klassen stärker, verursachen aber mehr Egress-Overhead und mehr Output-Varianz.

## Timing normalization envelope notes (`[censorship]`)

`mask_timing_normalization_enabled` glättet zeitliche Unterschiede zwischen Masking-Ergebnissen durch eine Ziel-Dauer-Hüllkurve.

- Ein zufälliges Ziel wird in `[mask_timing_normalization_floor_ms, mask_timing_normalization_ceiling_ms]` ausgewählt.
- Schnelle Pfade werden bis zum ausgewählten Ziel verzögert.
- Langsame Pfade werden nicht hart auf das Ceiling gezwungen; die Hüllkurve wird best-effort geshaped, nicht abgeschnitten.

Empfohlenes Startprofil für Timing-Shaping:

- `mask_timing_normalization_enabled = true`
- `mask_timing_normalization_floor_ms = 180`
- `mask_timing_normalization_ceiling_ms = 320`

Wenn Backend oder Netzwerk stark bandbreitenbeschränkt sind, reduzieren Sie zuerst das Ceiling. Wenn Probes in Ihrer Umgebung weiterhin zu gut unterscheidbar sind, erhöhen Sie den Floor schrittweise.


# [censorship.tls_fetch]


| Schlüssel | Typ | Default | Hot-Reload |
| --- | --- | --- | --- |
| [`profiles`](#profiles) | `String[]` | `["modern_chrome_like", "modern_firefox_like", "compat_tls12", "legacy_minimal"]` | `✘` |
| [`strict_route`](#strict_route) | `bool` | `true` | `✘` |
| [`attempt_timeout_ms`](#attempt_timeout_ms) | `u64` | `5000` | `✘` |
| [`total_budget_ms`](#total_budget_ms) | `u64` | `15000` | `✘` |
| [`grease_enabled`](#grease_enabled) | `bool` | `false` | `✘` |
| [`deterministic`](#deterministic) | `bool` | `false` | `✘` |
| [`profile_cache_ttl_secs`](#profile_cache_ttl_secs) | `u64` | `600` | `✘` |

## profiles
  - **Einschränkungen / Validierung**: `String[]`. Bei leerer Liste werden die Default-Werte wiederhergestellt. Werte werden unter Beibehaltung der Reihenfolge dedupliziert.
  - **Beschreibung**: Angeordnete ClientHello-Profil-Fallback-Kette für TLS-Front-Metadatenabruf.
  - **Beispiel**:

    ```toml
    [censorship.tls_fetch]
    profiles = ["modern_chrome_like", "compat_tls12"]
    ```
## strict_route
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Wenn `true` und eine Upstream-Route konfiguriert ist, schlägt der Abruf von TLS bei Upstream-Verbindungsfehlern fehl, anstatt auf die direkte Route TCP zurückzugreifen.
  - **Beispiel**:

    ```toml
    [censorship.tls_fetch]
    strict_route = true
    ```
## attempt_timeout_ms
  - **Einschränkungen / Validierung**: Muss `> 0` (Millisekunden) sein.
  - **Beschreibung**: Timeout-Budget pro TLS-Profilabrufversuch (ms).
  - **Beispiel**:

    ```toml
    [censorship.tls_fetch]
    attempt_timeout_ms = 5000
    ```
## total_budget_ms
  - **Einschränkungen / Validierung**: Muss `> 0` (Millisekunden) sein.
  - **Beschreibung**: Gesamtwanduhrbudget über alle TLS-Abrufversuche (ms).
  - **Beispiel**:

    ```toml
    [censorship.tls_fetch]
    total_budget_ms = 15000
    ```
## grease_enabled
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Aktiviert Zufallswerte im GREASE-Stil in ausgewählten ClientHello-Erweiterungen für den Abrufverkehr.
  - **Beispiel**:

    ```toml
    [censorship.tls_fetch]
    grease_enabled = false
    ```
## deterministic
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Ermöglicht deterministische ClientHello Zufälligkeit für Debugging/Tests.
  - **Beispiel**:

    ```toml
    [censorship.tls_fetch]
    deterministic = false
    ```
## profile_cache_ttl_secs
  - **Einschränkungen / Validierung**: `u64` (Sekunden). `0` deaktiviert den Cache.
  - **Beschreibung**: TTL für Gewinnerprofil-Cache-Einträge, die vom TLS-Abrufpfad verwendet werden.
  - **Beispiel**:

    ```toml
    [censorship.tls_fetch]
    profile_cache_ttl_secs = 600
    ```

# [access]


| Schlüssel | Typ | Default | Hot-Reload |
| --- | --- | --- | --- |
| [`users`](#users) | `Map<String, String>` | `{"default": "000…000"}` | `✔` |
| [`user_enabled`](#user_enabled-1) | `Map<String, bool>` | `{}` | `✔` |
| [`user_ad_tags`](#user_ad_tags) | `Map<String, String>` | `{}` | `✔` |
| [`user_max_tcp_conns`](#user_max_tcp_conns) | `Map<String, usize>` | `{}` | `✔` |
| [`user_max_tcp_conns_global_each`](#user_max_tcp_conns_global_each) | `usize` | `0` | `✔` |
| [`user_expirations`](#user_expirations) | `Map<String, DateTime<Utc>>` | `{}` | `✔` |
| [`user_data_quota`](#user_data_quota) | `Map<String, u64>` | `{}` | `✔` |
| [`user_max_unique_ips`](#user_max_unique_ips) | `Map<String, usize>` | `{}` | `✔` |
| [`user_max_unique_ips_global_each`](#user_max_unique_ips_global_each) | `usize` | `0` | `✔` |
| [`user_max_unique_ips_mode`](#user_max_unique_ips_mode) | `"active_window"`, `"time_window"` oder `"combined"` | `"active_window"` | `✔` |
| [`user_max_unique_ips_window_secs`](#user_max_unique_ips_window_secs) | `u64` | `30` | `✔` |
| [`user_source_deny`](#user_source_deny) | `Map<String, IpNetwork[]>` | `{}` | `✘` |
| [`replay_check_len`](#replay_check_len) | `usize` | `65536` | `✘` |
| [`replay_window_secs`](#replay_window_secs) | `u64` | `120` | `✘` |
| [`ignore_time_skew`](#ignore_time_skew) | `bool` | `false` | `✘` |
| [`user_rate_limits`](#user_rate_limits) | `Map<String, RateLimitBps>` | `{}` | `✔` |
| [`cidr_rate_limits`](#cidr_rate_limits) | `Map<CidrRateLimitKey, RateLimitBps>` | `{}` | `✔` |

## users
  - **Einschränkungen / Validierung**: Darf nicht leer sein (mindestens ein User muss vorhanden sein). Jeder Wert muss **genau 32 Hexadezimalzeichen** umfassen.
  - **Beschreibung**: Zuordnung der Useranmeldeinformationen, die für die Clientauthentifizierung verwendet wird. Schlüssel sind Usernamen; Werte sind MTProxy Geheimnisse.
  - **Beispiel**:

    ```toml
    [access.users]
    alice = "00112233445566778899aabbccddeeff"
    bob   = "0123456789abcdef0123456789abcdef"
    ```
## user_enabled
  - **Einschränkungen / Validierung**: `Map<String, bool>`.
  - **Beschreibung**: Optionale Aktivierungsüberschreibungen pro User. Fehlende User sind standardmäßig aktiviert. Ein Wert von `false` deaktiviert neue Sitzungen für diesen User; Das Festlegen des Werts auf `true` wird akzeptiert, entspricht jedoch dem Entfernen der Override. API Aktivierungsoperationen entfernen die Override, während Deaktivierungsoperationen `false` schreiben.
 – **Runtime Verhalten**: Beim Hot-Reload wird diese Karte sofort angewendet. Durch API oder Neuladen der Konfiguration deaktivierte User werden nach erfolgreicher Authentifizierung abgelehnt und aktive Runtimesitzungen für diesen Usernamen werden abgebrochen.
  - **Beispiel**:

    ```toml
    [access.user_enabled]
    alice = false
    ```
## user_ad_tags
  - **Einschränkungen / Validierung**: Jeder Wert muss aus **genau 32 Hexadezimalzeichen** bestehen (gleiches Format wie `general.ad_tag`). Ein All-Null-Tag ist zulässig, protokolliert jedoch eine Warnung.
  - **Beschreibung**: Override des Anzeigen-Tags für gesponserte Kanäle pro User. Wenn ein User hier einen Eintrag hat, hat dieser Vorrang vor `general.ad_tag`.
  - **Beispiel**:

    ```toml
    [general]
    ad_tag = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    [access.user_ad_tags]
    alice = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ```
## user_max_tcp_conns
  - **Einschränkungen / Validierung**: `Map<String, usize>`.
  - **Beschreibung**: Maximale Anzahl gleichzeitiger TCP-Verbindungen pro User.
  - **Beispiel**:

    ```toml
    [access.user_max_tcp_conns]
    alice = 500
    ```
## user_max_tcp_conns_global_each
  - **Einschränkungen / Validierung**: `usize`. `0` deaktiviert das geerbte Limit.
  - **Beschreibung**: Globale maximale Anzahl gleichzeitiger TCP-Verbindungen pro User, angewendet, wenn ein User **keinen positiven** Eintrag in `[access.user_max_tcp_conns]` hat (ein fehlender Schlüssel oder ein Wert von `0`, beides fällt auf diese Einstellung). Grenzwerte pro User, die größer als `0` in `user_max_tcp_conns` sind, haben Vorrang.
  - **Beispiel**:

    ```toml
    [access]
    user_max_tcp_conns_global_each = 200

    [access.user_max_tcp_conns]
    alice = 500   # uses 500, not the global cap
    # bob hat keinen Eintrag → verwendet 200
    ```
## user_expirations
  - **Einschränkungen / Validierung**: `Map<String, DateTime<Utc>>`. Jeder Wert muss eine gültige RFC3339/ISO-8601-Datumszeit sein.
  - **Beschreibung**: Ablaufzeitstempel pro Userkonto (UTC).
  - **Beispiel**:

    ```toml
    [access.user_expirations]
    alice = "2026-12-31T23:59:59Z"
    ```
## user_data_quota
  - **Einschränkungen / Validierung**: `Map<String, u64>`.
  - **Beschreibung**: Trafficskontingent pro User in Bytes.
  - **Beispiel**:

    ```toml
    [access.user_data_quota]
    alice = 1073741824 # 1 GiB
    ```
## user_max_unique_ips
  - **Einschränkungen / Validierung**: `Map<String, usize>`.
  - **Beschreibung**: Eindeutige Source-IP-Limits pro User.
  - **Beispiel**:

    ```toml
    [access.user_max_unique_ips]
    alice = 16
    ```
## user_max_unique_ips_global_each
  - **Einschränkungen / Validierung**: `usize`. `0` deaktiviert das geerbte Limit.
  - **Beschreibung**: Globales eindeutiges IP-Limit pro User, das angewendet wird, wenn ein User in `[access.user_max_unique_ips]` keine individuelle Override hat.
  - **Beispiel**:

    ```toml
    [access]
    user_max_unique_ips_global_each = 8
    ```
## user_max_unique_ips_mode
  - **Einschränkungen / Validierung**: Muss einer von `"active_window"`, `"time_window"`, `"combined"` sein.
  - **Beschreibung**: Eindeutiger Source-IP-Limit-Abrechnungsmodus.
  - **Beispiel**:

    ```toml
    [access]
    user_max_unique_ips_mode = "active_window"
    ```
## user_max_unique_ips_window_secs
  - **Einschränkungen / Validierung**: Muss `> 0` sein.
  - **Beschreibung**: Fenstergröße (Sekunden), die von Abrechnungsmodi mit eindeutiger IP verwendet wird, die ein Zeitfenster enthalten (`"time_window"` und `"combined"`).
  - **Beispiel**:

    ```toml
    [access]
    user_max_unique_ips_window_secs = 30
    ```
## user_source_deny
  - **Einschränkungen / Validierung**: Tabelle `username -> IpNetwork[]`. Jedes Netzwerk muss als CIDR parsen (zum Beispiel `203.0.113.0/24` oder `2001:db8::/32`).
  - **Beschreibung**: Source-IP/CIDR-Verweigerungsliste pro User wird **nach erfolgreicher Authentifizierung** in den Handshake-Pfaden TLS und MTProto angewendet. Eine übereinstimmende Source-IP wird über denselben Fail-Closed-Pfad wie eine ungültige Authentifizierung abgelehnt.
  - **Beispiel**:

    ```toml
    [access.user_source_deny]
    alice = ["203.0.113.0/24", "2001:db8:abcd::/48"]
    bob = ["198.51.100.42/32"]
    ```

 – **Wie es funktioniert (kurze Überprüfung)**:
 – Verbindung von User `alice` und Quelle `203.0.113.55` -> abgelehnt (entspricht `203.0.113.0/24`)
 – Verbindung von User `alice` und Quelle `198.51.100.10` -> durch diesen Regelsatz zulässig (keine Übereinstimmung)
## replay_check_len
  - **Einschränkungen / Validierung**: `usize`.
  - **Beschreibung**: Speicherlänge des Wiedergabeschutzes (Anzahl der Einträge, die zur Duplikaterkennung verfolgt werden).
  - **Beispiel**:

    ```toml
    [access]
    replay_check_len = 65536
    ```
## replay_window_secs
  - **Einschränkungen / Validierung**: `u64`.
  - **Beschreibung**: Wiedergabeschutz-Zeitfenster in Sekunden.
  - **Beispiel**:

    ```toml
    [access]
    replay_window_secs = 120
    ```
## ignore_time_skew
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Deaktiviert Client/Server-Zeitstempelabweichungsprüfungen bei der Wiedergabevalidierung, wenn aktiviert.
  - **Beispiel**:

    ```toml
    [access]
    ignore_time_skew = false
    ```


## user_rate_limits
  - **Einschränkungen / Validierung**: Tabelle `username -> { up_bps, down_bps }`. Mindestens eine Richtung muss ungleich Null sein.
  - **Beschreibung**: Bandbreitenobergrenzen pro User in Bits/Sekunde für Upload (`up_bps`) und Download (`down_bps`).
  - **Beispiel**:

    ```toml
    [access.user_rate_limits]
    alice = { up_bps = 1048576, down_bps = 2097152 }
    ```
## cidr_rate_limits
  - **Einschränkungen / Validierung**: Tabelle `CIDR oder Auto-Template -> { up_bps, down_bps }`. Explizite CIDR-Schlüssel müssen als `IpNetwork` parsbar sein; Auto-Template-Schlüssel müssen `*4/N` (`N=0..32`), `*6/N` (`N=0..128`) oder `*/N` (`N=0..32`) verwenden. Mindestens eine Richtung muss ungleich Null sein. Doppelte normalisierte Auto-Templates werden abgelehnt.
  - **Beschreibung**: Source-Subnetz-Bandbreitenlimits, die zusätzlich zu Per-User-Limits greifen. Explizite CIDR-Regeln verwenden Longest-Prefix-Wins und haben Vorrang vor Auto-Templates. Auto-Templates erzeugen Buckets lazy pro passendem Source-Subnetz: `*4/N` für IPv4, `*6/N` für IPv6 und `*/N` als Dual-Stack-Shorthand, bei dem IPv4 `/N` und IPv6 `/(N * 4)` nutzt.
  - **Beispiel**:

    ```toml
    [access.cidr_rate_limits]
    "203.0.113.0/24" = { up_bps = 0, down_bps = 1048576 }
    "*4/32" = { up_bps = 262144, down_bps = 1048576 }
    "*6/64" = { up_bps = 262144, down_bps = 1048576 }
    ```
# [[upstreams]]


| Schlüssel | Typ | Default | Hot-Reload |
| --- | --- | --- | --- |
| [`type`](#type) | `"direct"`, `"socks4"`, `"socks5"` oder `"shadowsocks"` | — | `✘` |
| [`weight`](#weight) | `u16` | `1` | `✘` |
| [`enabled`](#enabled) | `bool` | `true` | `✘` |
| [`scopes`](#scopes) | `String` | `""` | `✘` |
| [`ipv4`](#ipv4-upstreams) | `bool` | — (automatisch) | `✘` |
| [`ipv6`](#ipv6-upstreams) | `bool` | — (automatisch) | `✘` |
| [`prefer`](#prefer-upstreams) | `4` oder `6` | gültig `[network].prefer` | `✘` |
| [`interface`](#interface) | `String` | — | `✘` |
| [`bind_addresses`](#bind_addresses) | `String[]` | — | `✘` |
| [`bindtodevice`](#bindtodevice) | `String` | — | `✘` |
| [`force_bind`](#force_bind) | `String` | — | `✘` |
| [`url`](#url) | `String` | — | `✘` |
| [`address`](#address) | `String` | — | `✘` |
| [`user_id`](#user_id) | `String` | — | `✘` |
| [`username`](#username) | `String` | — | `✘` |
| [`password`](#password) | `String` | — | `✘` |

## type
  - **Einschränkungen / Validierung**: Erforderliches Feld. Muss einer von sein: `"direct"`, `"socks4"`, `"socks5"`, `"shadowsocks"`.
  - **Beschreibung**: Wählt die Upstream-Transportimplementierung für diesen `[[upstreams]]`-Eintrag aus.
  - **Beispiel**:

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
  - **Einschränkungen / Validierung**: `u16` (0..=65535).
  - **Beschreibung**: Basisgewichtung, die von der gewichteten zufälligen Upstream-Auswahl verwendet wird (höher = häufiger ausgewählt).
  - **Beispiel**:

    ```toml
    [[upstreams]]
    type = "direct"
    weight = 10
    ```
## enabled
  - **Einschränkungen / Validierung**: `bool`.
  - **Beschreibung**: Bei `false` wird dieser Eintrag ignoriert und nicht für eine Upstream-Auswahl verwendet.
  - **Beispiel**:

    ```toml
    [[upstreams]]
    type = "socks5"
    address = "127.0.0.1:9050"
    enabled = false
    ```
## scopes
  - **Einschränkungen / Validierung**: `String`. Durch Kommas getrennte Liste; Leerzeichen werden beim Abgleich entfernt.
  - **Beschreibung**: Scope-Tags, die für die Upstream-Filterung auf Anfrageebene verwendet werden. Wenn eine Anfrage einen Bereich angibt, können nur Upstreams ausgewählt werden, deren `scopes` dieses Tag enthält. Wenn eine Anfrage keinen Bereich angibt, sind nur Upstreams mit leerem `scopes` berechtigt.
  - **Beispiel**:

    ```toml
    [[upstreams]]
    type = "socks4"
    address = "10.0.0.10:1080"
    scopes = "me, fetch, dc2"
    ```
## ipv4 (upstreams)
  - **Einschränkungen / Validierung**: `bool` (optional).
  - **Beschreibung**: Erlaubt IPv4 DC Ziele für diesen Upstream. Wenn ausgelassen, erkennt Telemt die Unterstützung automatisch anhand des Runtimekonnektivitätsstatus.
  - **Beispiel**:

    ```toml
    [[upstreams]]
    type = "direct"
    ipv4 = true
    ```
## ipv6 (upstreams)
  - **Einschränkungen / Validierung**: `bool` (optional).
  - **Beschreibung**: Erlaubt IPv6 DC Ziele für diesen Upstream. Wenn ausgelassen, erkennt Telemt die Unterstützung automatisch anhand des Runtimekonnektivitätsstatus. Legen Sie dies auf `true` fest, wenn der Upstream-Proxy vom lokalen Host über IPv4 erreichbar ist, der Proxy selbst jedoch über IPv6 eine Verbindung zu Telegram-DCs herstellen kann.
  - **Beispiel**:

    ```toml
    [[upstreams]]
    type = "direct"
    ipv6 = false
    ```
## prefer (upstreams)
  - **Einschränkungen / Validierung**: Optionale Ganzzahl. Muss `4` oder `6` sein.
  - **Beschreibung**: Überschreibt die IP-Familienpräferenz für Telegram-DC-Ziele, die über diesen Upstream ausgewählt wurden. Wenn ausgelassen, erbt der Upstream die effektive globale `[network].prefer`-Entscheidung. Verwenden Sie `prefer = 6` zusammen mit `ipv6 = true` für einen SOCKS- oder Shadowsocks-Upstream, der über IPv6 ausgehen kann, selbst wenn der lokale Telemt-Host nur IPv4 ist.
  - **Beispiel**:

    ```toml
    [[upstreams]]
    type = "socks5"
    address = "192.0.2.10:1080"
    ipv6 = true
    prefer = 6
    ```
## interface
  - **Einschränkungen / Validierung**: `String` (optional).
 – Für `"direct"`: kann eine IP-Adresse (wird als explizite lokale Bindung verwendet) oder ein Betriebssystemschnittstellenname (zur Runtime in eine IP aufgelöst; nur Unix) sein.
 – Für `"socks4"`/`"socks5"`: wird nur unterstützt, wenn `address` ein `IP:port`-Literal ist; Wenn `address` ein Hostname ist, wird die Schnittstellenbindung ignoriert.
 – Für `"shadowsocks"`: als optionaler ausgehender Bindungshinweis an den Shadowsocks-Connector übergeben.
  - **Beschreibung**: Optionale ausgehende Schnittstelle/lokaler Bindungshinweis für den Upstream-Verbindungssocket.
  - **Beispiel**:

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
  - **Einschränkungen / Validierung**: `String[]` (optional). Gilt nur für `type = "direct"`.
 – Jeder Eintrag sollte eine IP-Adresszeichenfolge sein.
 – Zur Runtime wählt Telemt eine Adresse aus, die der Zielfamilie entspricht (IPv4 vs. IPv6). Wenn `bind_addresses` festgelegt ist und keiner der Zielfamilie entspricht, schlägt der Verbindungsversuch fehl.
  - **Beschreibung**: Explizite lokale Source-Adressen für ausgehende direkte TCP-Verbindungen. Wenn mehrere Adressen angegeben werden, erfolgt die Auswahl im Round-Robin-Verfahren.
  - **Beispiel**:

    ```toml
    [[upstreams]]
    type = "direct"
    bind_addresses = ["192.0.2.10", "192.0.2.11"]
    ```
## bindtodevice
  - **Einschränkungen / Validierung**: `String` (optional). Gilt nur für `type = "direct"` und ist nur Linux.
  - **Beschreibung**: Hartes Schnittstellen-Pinning über `SO_BINDTODEVICE` für ausgehende direkte TCP-Verbindungen.
  - **Beispiel**:

    ```toml
    [[upstreams]]
    type = "direct"
    bindtodevice = "eth0"
    ```
## force_bind
  - **Einschränkungen / Validierung**: `String` (optional). Alias für `bindtodevice`.
  - **Beschreibung**: Abwärtskompatibler Alias für Linux `SO_BINDTODEVICE` Hard-Interface-Pinning.
  - **Beispiel**:

    ```toml
    [[upstreams]]
    type = "direct"
    force_bind = "eth0"
    ```
## url
  - **Einschränkungen / Validierung**: Gilt nur für `type = "shadowsocks"`.
 – Muss eine gültige Shadowsocks-URL sein, die von der `shadowsocks`-Kiste akzeptiert wird.
 – Shadowsocks Plugins werden nicht unterstützt.
 – Erfordert `general.use_middle_proxy = false` (Shadowsocks-Upstreams werden im ME-Modus abgelehnt).
  - **Beschreibung**: Shadowsocks Server-URL, die für die Verbindung zu Telegram über ein Shadowsocks-Relay verwendet wird.
  - **Beispiel**:

    ```toml
    [general]
    use_middle_proxy = false

    [[upstreams]]
    type = "shadowsocks"
    url = "ss://2022-blake3-aes-256-gcm:BASE64PASSWORD@127.0.0.1:8388"
    ```
## address
  - **Einschränkungen / Validierung**: Erforderlich für `type = "socks4"` und `type = "socks5"`. Muss `host:port` oder `ip:port` sein.
  - **Beschreibung**: SOCKS-Proxyserver-Endpunkt, der für Upstream-Verbindungen verwendet wird.
  - **Beispiel**:

    ```toml
    [[upstreams]]
    type = "socks5"
    address = "127.0.0.1:9050"
    ```
## user_id
  - **Einschränkungen / Validierung**: `String` (optional). Nur für `type = "socks4"`.
  - **Beschreibung**: SOCKS4 CONNECT-User-ID. Hinweis: Wenn ein Anforderungsbereich ausgewählt ist, kann Telemt diesen möglicherweise mit dem ausgewählten Bereichswert überschreiben.
  - **Beispiel**:

    ```toml
    [[upstreams]]
    type = "socks4"
    address = "127.0.0.1:1080"
    user_id = "telemt"
    ```
## username
  - **Einschränkungen / Validierung**: `String` (optional). Nur für `type = "socks5"`.
  - **Beschreibung**: SOCKS5 Username (für Username/Passwort-Authentifizierung). Hinweis: Wenn ein Anforderungsbereich ausgewählt ist, kann Telemt diesen möglicherweise mit dem ausgewählten Bereichswert überschreiben.
  - **Beispiel**:

    ```toml
    [[upstreams]]
    type = "socks5"
    address = "127.0.0.1:9050"
    username = "alice"
    ```
## password
  - **Einschränkungen / Validierung**: `String` (optional). Nur für `type = "socks5"`.
  - **Beschreibung**: SOCKS5 Passwort (für Username/Passwort-Authentifizierung). Hinweis: Wenn ein Anforderungsbereich ausgewählt ist, kann Telemt diesen möglicherweise mit dem ausgewählten Bereichswert überschreiben.
  - **Beispiel**:

    ```toml
    [[upstreams]]
    type = "socks5"
    address = "127.0.0.1:9050"
    username = "alice"
    password = "secret"
    ```
