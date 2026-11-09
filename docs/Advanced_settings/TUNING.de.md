# Telemt Tuning-Leitfaden: Middle-End und Upstreams

[English](TUNING.en.md) · [Русский](TUNING.ru.md) · [Deutsch](TUNING.de.md) · [EN / RU / DE terminology](../TERMINOLOGY.md)

Dieses Dokument beschreibt das aktuelle Laufzeitverhalten für Middle-End (ME) und Upstream-Routing basierend auf:
- `src/config/types.rs`
- `src/config/defaults.rs`
- `src/config/load.rs`
- `src/transport/upstream.rs`

Die unten angegebenen `Default`-Werte sind Code-Defaults (bei fehlendem Schlüssel), nicht zwingend die Werte aus `config.full.toml`.

`Option<T>` und `null` in Typ- und Standardwertspalten beschreiben optionale interne Werte. TOML kennt kein `null`-Literal. Für die alten Aktualisierungsintervalle lassen Sie `general.update_every` weg und setzen die alten Schlüssel ausdrücklich; andernfalls beträgt das einheitliche Standardintervall 300 Sekunden. Null-Werte in Objektfeldern eines Konfigurations-PATCH werden ignoriert und entfernen keine Einstellungen.

## Middle-End-Parameter

### 1) ME-Grundmodus, NAT und STUN

| Parameter | Typ | Default | Einschränkungen / Validierung | Laufzeiteffekt | Beispiel |
|---|---|---:|---|---|---|
| `general.use_middle_proxy` | `bool` | `true` | keine | Aktiviert den ME-Transportmodus. Bei `false` wird Direct-Modus verwendet. | `use_middle_proxy = true` |
| `general.proxy_secret_path` | `Option<String>` | `"proxy-secret"` | Pfad kann `null` sein | Pfad zur Telegram-Infrastrukturdatei `proxy-secret`. | `proxy_secret_path = "proxy-secret"` |
| `general.middle_proxy_nat_ip` | `Option<IpAddr>` | `null` | gültige IP bei gesetztem Wert | Manueller Override der öffentlichen NAT-IP für ME-Adressmaterial. | `middle_proxy_nat_ip = "203.0.113.10"` |
| `general.middle_proxy_nat_probe` | `bool` | `true` | keine | Aktiviert NAT-Probing, wenn ME-Modus und `network.stun_use` beide aktiviert sind. | `middle_proxy_nat_probe = true` |
| `general.stun_nat_probe_concurrency` | `usize` | `8` | muss `> 0` sein | Maximale parallele STUN-Probes während NAT-Erkennung. | `stun_nat_probe_concurrency = 16` |
| `network.stun_use` | `bool` | `true` | keine | Globaler STUN-Schalter. Bei `false` wird STUN deaktiviert. | `stun_use = true` |
| `network.stun_servers` | `Vec<String>` | integrierter öffentlicher Pool | Duplikate/leer werden entfernt | Primäre STUN-Serverliste für NAT/Public-Endpoint-Erkennung. | `stun_servers = ["stun1.l.google.com:19302"]` |
| `network.stun_tcp_fallback` | `bool` | `true` | keine | Aktiviert TCP-Fallback, wenn UDP-STUN blockiert ist. | `stun_tcp_fallback = true` |
| `network.http_ip_detect_urls` | `Vec<String>` | `ifconfig.me` + `api.ipify.org` | keine | HTTP-Fallback zur öffentlichen IPv4-Erkennung, falls STUN ausfällt. | `http_ip_detect_urls = ["https://api.ipify.org"]` |
| `general.stun_iface_mismatch_ignore` | `bool` | `false` | keine | Reserviertes Feld in der aktuellen Revision (derzeit kein aktiver Runtime-Verbrauch). | `stun_iface_mismatch_ignore = false` |
| `timeouts.me_one_retry` | `u8` | `12` | keine | Anzahl schneller Reconnect-Versuche bei Single-Endpoint-DC-Fällen. | `me_one_retry = 6` |
| `timeouts.me_one_timeout_ms` | `u64` | `1200` | keine | Timeout pro schnellem Einzelversuch (ms). | `me_one_timeout_ms = 1500` |

### 2) Poolgröße, Keepalive und Reconnect-Policy

| Parameter | Typ | Default | Einschränkungen / Validierung | Laufzeiteffekt | Beispiel |
|---|---|---:|---|---|---|
| `general.middle_proxy_pool_size` | `usize` | `8` | keine | Nicht erzwingender Kompatibilitäts-/Startup-Log-Wert; aktive Writer-Ziele stammen aus der DC-Family-Floor-Policy. | `middle_proxy_pool_size = 12` |
| `general.middle_proxy_warm_standby` | `usize` | `16` | keine | Reserviertes Kompatibilitätsfeld in der aktuellen Revision (kein aktiver Runtime-Consumer). | `middle_proxy_warm_standby = 16` |
| `general.me_keepalive_enabled` | `bool` | `true` | keine | Aktiviert periodischen ME-Keepalive/Ping-Traffic. | `me_keepalive_enabled = true` |
| `general.me_keepalive_interval_secs` | `u64` | `8` | keine | Basisintervall für Keepalive (Sekunden). | `me_keepalive_interval_secs = 20` |
| `general.me_keepalive_jitter_secs` | `u64` | `2` | keine | Keepalive-Jitter zur Vermeidung synchroner Peaks. | `me_keepalive_jitter_secs = 3` |
| `general.me_keepalive_payload_random` | `bool` | `true` | keine | Randomisiert Keepalive-Payload-Bytes. | `me_keepalive_payload_random = true` |
| `general.me_warmup_stagger_enabled` | `bool` | `true` | keine | Aktiviert gestaffeltes Warmup zusätzlicher ME-Verbindungen. | `me_warmup_stagger_enabled = true` |
| `general.me_warmup_step_delay_ms` | `u64` | `500` | keine | Basisverzögerung zwischen Warmup-Schritten (ms). | `me_warmup_step_delay_ms = 300` |
| `general.me_warmup_step_jitter_ms` | `u64` | `300` | keine | Zusätzlicher zufälliger Warmup-Jitter (ms). | `me_warmup_step_jitter_ms = 200` |
| `general.me_reconnect_max_concurrent_per_dc` | `u32` | `8` | keine | Begrenzung paralleler Reconnect-Worker pro DC. | `me_reconnect_max_concurrent_per_dc = 12` |
| `general.me_reconnect_backoff_base_ms` | `u64` | `500` | keine | Initiales Reconnect-Backoff (ms). | `me_reconnect_backoff_base_ms = 250` |
| `general.me_reconnect_backoff_cap_ms` | `u64` | `30000` | keine | Maximales Reconnect-Backoff (ms). | `me_reconnect_backoff_cap_ms = 10000` |
| `general.me_reconnect_fast_retry_count` | `u32` | `16` | keine | Budget für Sofort-Retries vor längerem Backoff. | `me_reconnect_fast_retry_count = 8` |
| `general.me_writer_byte_budget_bytes` | `usize` | `33570816` | Vielfaches von `16384`; dynamisches Minimum für `max_client_frame`; Maximum `268435456` | Begrenzte Byte-Permits für die ausgehende Staging-Queue jedes ME-Writers. | `me_writer_byte_budget_bytes = 33570816` |

### 3) Reinit/Hardswap, Secret-Rotation und Degradation

| Parameter | Typ | Default | Einschränkungen / Validierung | Laufzeiteffekt | Beispiel |
|---|---|---:|---|---|---|
| `general.hardswap` | `bool` | `true` | keine | Aktiviert generation-basierte Hardswap-Strategie für den ME-Pool. | `hardswap = true` |
| `general.me_reinit_every_secs` | `u64` | `900` | muss `> 0` sein | Intervall für periodische ME-Reinitialisierung. | `me_reinit_every_secs = 600` |
| `general.me_reinit_singleflight` | `bool` | `true` | keine | Serialisiert Reinit-Zyklen aus allen Triggerquellen. | `me_reinit_singleflight = true` |
| `general.me_reinit_max_concurrency` | `usize` | `2` | Bereich `[1,8]`; effektiver Wert `1` bei Singleflight | Begrenzt parallele Generation-Warmups; weitere Trigger werden zu einem Rerun zusammengeführt. | `me_reinit_max_concurrency = 2` |
| `general.me_reinit_trigger_channel` | `usize` | `64` | Bereich `[1,4096]` | Begrenzt eingereihte Reinit-Trigger in jeder Runtime-Generation. | `me_reinit_trigger_channel = 64` |
| `general.me_reinit_coalesce_window_ms` | `u64` | `200` | keine | Fasst Trigger-Bursts vor einem Reinit-Zyklus zusammen. | `me_reinit_coalesce_window_ms = 200` |
| `general.me_hardswap_warmup_delay_min_ms` | `u64` | `1000` | muss `<= me_hardswap_warmup_delay_max_ms` sein | Untere Grenze für Warmup-Dial-Abstände. | `me_hardswap_warmup_delay_min_ms = 500` |
| `general.me_hardswap_warmup_delay_max_ms` | `u64` | `2000` | muss `> 0` sein | Obere Grenze für Warmup-Dial-Abstände. | `me_hardswap_warmup_delay_max_ms = 1200` |
| `general.me_hardswap_warmup_extra_passes` | `u8` | `3` | Bereich `[0,10]` | Zusätzliche Warmup-Pässe nach dem Basispass. | `me_hardswap_warmup_extra_passes = 2` |
| `general.me_hardswap_warmup_pass_backoff_base_ms` | `u64` | `500` | muss `> 0` sein | Basis-Backoff zwischen zusätzlichen Warmup-Pässen. | `me_hardswap_warmup_pass_backoff_base_ms = 400` |
| `general.me_config_stable_snapshots` | `u8` | `2` | muss `> 0` sein | Anzahl identischer ME-Config-Snapshots vor Apply. | `me_config_stable_snapshots = 3` |
| `general.me_config_apply_cooldown_secs` | `u64` | `300` | keine | Cooldown zwischen angewendeten ME-Map-Updates. | `me_config_apply_cooldown_secs = 120` |
| `general.proxy_secret_stable_snapshots` | `u8` | `2` | muss `> 0` sein | Anzahl identischer Secret-Snapshots vor Rotation. | `proxy_secret_stable_snapshots = 3` |
| `general.proxy_secret_rotate_runtime` | `bool` | `true` | keine | Aktiviert Runtime-Rotation des Proxy-Secrets. | `proxy_secret_rotate_runtime = true` |
| `general.proxy_secret_len_max` | `usize` | `256` | Bereich `[32,4096]` | Obergrenze für akzeptierte Secret-Länge. | `proxy_secret_len_max = 512` |
| `general.update_every` | `Option<u64>` | `300` | wenn gesetzt: `> 0`; ohne diesen Schlüssel mit expliziten alten Intervallen: deren Minimum | Einheitliches Refresh-Intervall für ME-Config + Secret-Updater. | `update_every = 300` |
| `general.me_pool_drain_ttl_secs` | `u64` | `90` | keine | Altersschwelle für Warnungen bei langem Drain und Untergrenze der Force-Close-Normalisierung; gewährt keine stale Binds. | `me_pool_drain_ttl_secs = 120` |
| `general.me_bind_stale_mode` | `"never"`, `"ttl"` oder `"always"` | `"never"` | keine | Steuert neue Bindings auf draining stale Writer für nicht abgedeckte DC-Family-Gruppen. | `me_bind_stale_mode = "never"` |
| `general.me_bind_stale_ttl_secs` | `u64` | `90` | keine | Stale-Bind-Fenster nur für `me_bind_stale_mode = "ttl"`; `0` deaktiviert den TTL-Ablauf für zulässige draining Writer. | `me_bind_stale_ttl_secs = 90` |
| `general.me_pool_min_fresh_ratio` | `f32` | `0.8` | Bereich `[0.0,1.0]` | Mindestverhältnis frischer DC-Family-Coverage beim Commit. | `me_pool_min_fresh_ratio = 0.9` |
| `general.me_reinit_drain_timeout_secs` | `u64` | `90` | `0` nutzt den 300-Sekunden-Sicherheitsfallback; ein effektiver Wert unter der Drain-TTL wird auf die TTL angehoben | Force-Close-Timeout für draining stale Writer. | `me_reinit_drain_timeout_secs = 0` |
| `general.auto_degradation_enabled` | `bool` | `true` | keine | Reserviertes Kompatibilitätsfeld in aktueller Revision (kein aktiver Runtime-Consumer). | `auto_degradation_enabled = true` |
| `general.degradation_min_unavailable_dc_groups` | `u8` | `2` | keine | Reservierter Kompatibilitäts-Schwellenwert in aktueller Revision (kein aktiver Runtime-Consumer). | `degradation_min_unavailable_dc_groups = 2` |

Eine für Hardswap vorbereitete Generation darf nur übernommen werden, solange der Hash der gewünschten ME-Zuordnung und die Revision der Verbindungsziele unverändert sind. Wiederholungsversuche verwenden sie höchstens 1800 Sekunden; danach wird eine neue Generation angelegt. Vor der Übernahme prüft Telemt diese Voraussetzungen erneut. Der Anteil der durch neue Verbindungen abgedeckten Gruppen aus DC und IP-Adressfamilie muss mindestens `me_pool_min_fresh_ratio` betragen. Bei `me_bind_stale_mode = "never"` blockiert jede fehlende Gruppe die Übernahme. Mit `ttl` oder `always` dürfen für solche Gruppen ältere Verbindungen innerhalb der gewählten Richtlinie weiterverwendet werden. Alte ME Writer bereits abgedeckter Gruppen können sofort außer Betrieb genommen werden. Der atomare Wechsel der Richtlinie garantiert daher nicht den Erhalt aller Verbindungen.

Der Austausch eines einzelnen ME Writers verwendet die Zustände `Open -> Preparing -> Retiring` und berücksichtigt den Abbruch der Operation. `Preparing` verhindert einen zweiten Austausch desselben Writers, lässt aber neue Stream-Zuordnungen zu. Unter der Sperre des Zuordnungsregisters prüft Telemt den bisherigen Writer erneut, setzt ihn auf `Retiring`, um neue Zuordnungen zu sperren, installiert und veröffentlicht den Nachfolger und beginnt, den Vorgänger auslaufen zu lassen. Erst dann wird die Sperre freigegeben. Wird die Reservierung vor dieser Übernahmegrenze verworfen, gilt wieder `Open`.

`/v1/runtime/me_pool_state` zeigt das Alter der wartenden Generation, Anzahl und Defizit der ME Writer, fehlende DC-Gruppen, die Aktualität der Zuordnung, vorbereitete Verbindungen ohne Besitzer und die Phasen `preparing`/`retiring`. Die Messwerte `telemt_me_hardswap_*` und `telemt_me_writer_replacement_current` sind null, wenn die ME-Telemetrie auf `silent` steht oder kein aktiver Zustandsstand vorliegt. Werten Sie `telemt_me_hardswap_pending_map_current` zusammen mit `telemt_me_hardswap_pending` aus: Null kann auch bedeuten, dass keine Generation wartet, statt dass die Zuordnung veraltet ist. Die API liefert dann `null`. Richten Sie Alarme für ein Alter nahe 1800 Sekunden, anhaltende Defizite oder fehlende Gruppen, veraltete Zuordnungen, vorbereitete Verbindungen ohne Besitzer und festhängende Austauschphasen ein.

## Deprecated / Legacy Parameter

| Parameter | Status | Ersatz | Aktuelles Verhalten | Migrationshinweis |
|---|---|---|---|---|
| `general.middle_proxy_nat_stun` | Deprecated | `network.stun_servers` | Wird nur dann in `network.stun_servers` gemerged, wenn `network.stun_servers` nicht explizit gesetzt ist. | Wert nach `network.stun_servers` verschieben, Legacy-Key entfernen. |
| `general.middle_proxy_nat_stun_servers` | Deprecated | `network.stun_servers` | Wird nur dann in `network.stun_servers` gemerged, wenn `network.stun_servers` nicht explizit gesetzt ist. | Werte nach `network.stun_servers` verschieben, Legacy-Key entfernen. |
| `general.proxy_secret_auto_reload_secs` | Deprecated | `general.update_every` | Aktiv, wenn `update_every` fehlt und alte Intervalle ausdrücklich gesetzt sind. | `general.update_every` explizit setzen, Legacy-Key entfernen. |
| `general.proxy_config_auto_reload_secs` | Deprecated | `general.update_every` | Aktiv, wenn `update_every` fehlt und alte Intervalle ausdrücklich gesetzt sind. | `general.update_every` explizit setzen, Legacy-Key entfernen. |

## Wie Upstreams konfiguriert werden

### Upstream-Schema

| Feld | Gilt für | Typ | Pflicht | Default | Bedeutung |
|---|---|---|---|---|---|
| `[[upstreams]].type` | alle Upstreams | `"direct" \| "socks4" \| "socks5" \| "shadowsocks"` | ja | n/a | Upstream-Transporttyp. |
| `[[upstreams]].weight` | alle Upstreams | `u16` | nein | `1` | Basisgewicht für weighted-random Auswahl. |
| `[[upstreams]].enabled` | alle Upstreams | `bool` | nein | `true` | Deaktivierte Einträge werden beim Start ignoriert. |
| `[[upstreams]].scopes` | alle Upstreams | `String` | nein | `""` | Komma-separierte Scope-Tags für Request-Routing. |
| `[[upstreams]].ipv4` | alle Upstreams | `Option<bool>` | nein | `auto` | Erlaubt IPv4-DC-Ziele für diesen Upstream. |
| `[[upstreams]].ipv6` | alle Upstreams | `Option<bool>` | nein | `auto` | Erlaubt IPv6-DC-Ziele für diesen Upstream, inklusive Proxy-Egress unabhängig vom Host-IPv6. |
| `[[upstreams]].prefer` | alle Upstreams | `Option<4 \| 6>` | nein | effective `[network].prefer` | Pro-Upstream-Präferenz für die DC-Ziel-Adressfamilie. |
| `interface` | `direct` | `Option<String>` | nein | `null` | Interface-Name (z. B. `eth0`) oder lokale Literal-IP. |
| `bind_addresses` | `direct` | `Option<Vec<IpAddr>>` | nein | `null` | Explizite Source-IP-Kandidaten (strikter Vorrang vor `interface`). |
| `address` | `socks4` | `String` | ja | n/a | SOCKS4-Server (`ip:port` oder `host:port`). |
| `interface` | `socks4` | `Option<String>` | nein | `null` | Wird nur genutzt, wenn `address` als `ip:port` angegeben ist. |
| `user_id` | `socks4` | `Option<String>` | nein | `null` | SOCKS4 User-ID für CONNECT. |
| `address` | `socks5` | `String` | ja | n/a | SOCKS5-Server (`ip:port` oder `host:port`). |
| `interface` | `socks5` | `Option<String>` | nein | `null` | Wird nur genutzt, wenn `address` als `ip:port` angegeben ist. |
| `username` | `socks5` | `Option<String>` | nein | `null` | SOCKS5 Benutzername. |
| `password` | `socks5` | `Option<String>` | nein | `null` | SOCKS5 Passwort. |
| `url` | `shadowsocks` | `String` | ja | n/a | Shadowsocks-SIP002-URL (`ss://...`). In Runtime-APIs wird nur `host:port` offengelegt. |
| `interface` | `shadowsocks` | `Option<String>` | nein | `null` | Optionales ausgehendes Bind-Interface oder lokale Literal-IP. |

### Runtime-Regeln (wichtig)

1. Wenn `[[upstreams]]` fehlt, injiziert der Loader einen Default-`direct`-Upstream.
2. Scope-Filterung basiert auf exaktem Token-Match:
- mit Request-Scope -> nur Einträge, deren `scopes` genau dieses Token enthält;
- ohne Request-Scope -> nur Einträge mit leerem `scopes`.
3. Unter healthy Upstreams erfolgt die Auswahl per weighted random: `weight * latency_factor`.
4. Gibt es im gefilterten Set keinen healthy Upstream, wird zufällig aus dem gefilterten Set gewählt.
5. `direct`-Bind-Auflösung:
- zuerst `bind_addresses` (nur gleiche IP-Familie wie Target);
- bei `interface` (Name) + `bind_addresses` wird jede Candidate-IP gegen Interface-Adressen validiert;
- ungültige Kandidaten werden mit `WARN` verworfen;
- lässt eine nicht leere `bind_addresses`-Liste keinen gültigen Candidate derselben Familie übrig, schlägt die Verbindung mit einem Konfigurationsfehler fail-closed fehl;
- nur wenn `bind_addresses` fehlt oder leer ist, wird `interface` verwendet (Literal-IP oder Interface-Primäradresse); ergibt auch dies keine Adresse, bleibt Direct Connect ungebunden.
6. Für `socks4/socks5` mit Hostname-`address` ist Interface-Binding nicht unterstützt und wird mit Warnung ignoriert.
7. Runtime DNS Overrides werden für Hostname-Auflösung bei Upstream-Verbindungen genutzt.
8. Im ME-Modus wird der gewählte Upstream auch für den ME-TCP-Dial-Pfad verwendet.
9. Im ME-Modus ist bei `direct` mit bind/interface die STUN-Reflection bind-aware für KDF-Adressmaterial.
10. Im ME-Modus über SOCKS liefert ein gültiges öffentliches `BND.ADDR/BND.PORT` mit einem Port ungleich null das vollständige KDF-Quelltupel. Die Adressfamilie muss dem logischen ME-Ziel entsprechen, unabhängig von der TCP-Familie zum SOCKS-Server. IPv4-mapped Ziele benötigen ein natives IPv4-BND-Tupel; IPv4-compatible IPv6 bleibt IPv6.
11. `shadowsocks`-Upstreams erfordern `general.use_middle_proxy = false`. Mit aktiviertem ME-Modus schlägt das Laden der Config sofort fehl.

## Upstream-Konfigurationsbeispiele

### Beispiel 1: Minimaler direct Upstream

```toml
[[upstreams]]
type = "direct"
weight = 1
enabled = true
```

### Beispiel 2: direct mit Interface + expliziten bind IPs

```toml
[[upstreams]]
type = "direct"
interface = "eth0"
bind_addresses = ["192.168.1.100", "192.168.1.101"]
weight = 3
enabled = true
```

### Beispiel 3: SOCKS5 Upstream mit Authentifizierung

```toml
[[upstreams]]
type = "socks5"
address = "198.51.100.30:1080"
username = "proxy-user"
password = "proxy-pass"
weight = 2
enabled = true
```

### Beispiel 4: Shadowsocks-Upstream

```toml
[general]
use_middle_proxy = false

[[upstreams]]
type = "shadowsocks"
url = "ss://2022-blake3-aes-256-gcm:BASE64_KEY@198.51.100.50:8388"
weight = 2
enabled = true
```

### Upstream anhand des Benutzernamens auswählen

Im Direct-Relay wählt ein Benutzer namens `scope_premium` den exakten Scope `premium`. Der Suffix muss aus 1–64 ASCII-Buchstaben, Ziffern oder Bindestrichen bestehen. Ohne gültigen Suffix erfolgt die Auswahl ohne Scope. Gibt es zu einem gültigen Scope keinen passenden Upstream, schlägt die Verbindung fehl; sie weicht nicht auf eine unmarkierte Route aus. Scope-Tags erstellen keine Benutzer und ersetzen keine Authentifizierung.

Ein ausgewählter Scope ersetzt die SOCKS4-`user_id` sowie SOCKS5-Benutzername und -Passwort. Im Beispiel muss der SOCKS5-Server `premium` sowohl als Benutzername als auch als Passwort akzeptieren. Gewöhnliche Benutzer verwenden die unmarkierte direkte Route. Ersetzen Sie Secret und SOCKS-Adresse vor dem Einsatz.

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

Diese benutzerbezogene Auswahl gilt für Direct-Relay. ME-Verbindungen übergeben derzeit keinen Benutzerscope; das Tag `me` wählt daher nicht automatisch einen ME-Upstream. TLS-Profilabfragen verwenden die separate Einstellung `censorship.tls_fetch_scope`. Siehe [Scope-Filterung](../Config_params/CONFIG_PARAMS.de.md#scopes).


### Beispiel 6: ME-orientiertes Tuning-Profil

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
