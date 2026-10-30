# WEB-Proxy-Modus

[English](WEB_PROXY.en.md) | [Русский](WEB_PROXY.ru.md) | [Deutsch](WEB_PROXY.de.md)

Der WEB-Modus transportiert gewöhnliche MTProxy-Streams über begrenzte HTTPS- oder WebSocket-Carrier, die mit dem Proxy-Typ `WEB` von Telegram Desktop kompatibel sind. Telemt terminiert TLS nicht selbst: NGINX, HAProxy oder Caddy verwaltet das öffentliche Zertifikat und leitet unverschlüsseltes HTTP/1.1 an einen privaten Telemt-Listener weiter.

> [!IMPORTANT]
>
> Der WEB-Modus ist im aktuellen Quellcode implementiert und konfigurierbar. Für die erste Bereitstellung sind ein Binary aus einer Revision mit dieser Implementierung und ein Neustart des Telemt-Prozesses erforderlich. Veröffentlichte Pakete dürfen erst verwendet werden, nachdem geprüft wurde, dass sie dieselbe Revision enthalten. Die Ende-zu-Ende-Prüfung mit dem vorgesehenen Telegram-Desktop-Build und dem realen öffentlichen TLS-Endpunkt bleibt ein Abnahmeschritt des Betreibers.

## Datenpfad

```text
Telegram Desktop
    | HTTPS oder WSS :443
    v
NGINX, HAProxy oder Caddy (TLS-Terminierung, kanonischer Host und eine X-Forwarded-For-Adresse)
    | unverschlüsseltes HTTP/1.1 in einem privaten Netz
    v
Telemt-WEB-Listener
    |-- authentifizierter Carrier --> begrenzte logische MTProxy-Relays --> Telegram
    `-- gewöhnlicher oder ungültiger Request --> konfigurierte Decoy-Site
```

Leiten Sie den vollständigen konfigurierten WEB-Bereich an Telemt weiter. Beim standardmäßig leeren `base_path` ist dies der gesamte öffentliche vhost, andernfalls der exakte, mit einem Schrägstrich abgeschlossene Teilbaum. Wenn der TLS-Terminator innerhalb dieses Bereichs nur bekannte Carrier-Endpunkte trennt, unterscheiden sich gewöhnliches und authentifiziertes Verhalten beobachtbar und Telemt kann seine Decoy-Richtlinie nicht durchsetzen.

`BASE` bezeichnet `/` bei leerem `base_path`, andernfalls `/<base_path>/`. Die öffentlichen WEB-Routen sind relativ zu dieser exakten Basis:

| Methode | Pfad | Zweck |
| --- | --- | --- |
| `GET` | `BASE?bridge=<capability>` | Erstes Bridge-Dokument oder, mit Recovery-`Accept`-Header und optionalem Bearer, die Recovery-Repräsentation. |
| `POST`, `DELETE` | `BASEapi/v1/session` | Parent-Sitzung erstellen oder schließen. |
| `POST` | `BASEapi/v1/up` | Uplink des HTTPS-Carriers. |
| `POST` | `BASEapi/v1/down` | Downlink des HTTPS-Carriers. |
| `GET` | `BASEapi/v1/ws` | WebSocket-Upgrade. |

`POST BASEapi/v1/diagnostic` ist eine interne Sideband-Route der generierten Bridge und keine öffentliche Client-API. Das Routing ist groß-/kleinschreibungssensitiv und bytegenau: Es gibt keine Aliase, Varianten mit zusätzlichen oder percent-encoded Schrägstrichen und keine Query-Parameter an Carrier-Endpunkten. Ein falsch geformter Request mit einer vom aktuellen Prozess authentifizierten Capability oder einem solchen Bearer erhält lokal ein nicht cachebares `404`; ein nicht passender Request ohne authentisches Carrier-Material folgt dem konfigurierten Decoy. `base_path` ändert nur diese Routen des WEB-Listeners. Control API, `/web-status` und Prometheus-Metriken erhalten kein Präfix.

## Unterstützter Client-Vertrag

- Bei leerem `base_path` lautet der öffentliche Endpunkt `https://HOST:443/`, andernfalls `https://HOST:443/BASE/`. Der Basispfad ist groß-/kleinschreibungssensitiv und exakt; Telemt leitet ihn nicht um, normalisiert ihn nicht und entfernt ihn nicht vor der Decoy-Weiterleitung.
- Unterstützt werden 16-Byte-MTProxy-Secrets in den Modi `plain` und `dd`. FakeTLS-Secrets mit `ee` werden im WEB-Modus nicht unterstützt.
- `web.carrier` wählt den einzigen Carrier bei deaktivierter Auto-Negotiation und den letzten Fallback bei aktivierter Negotiation. `https` verwendet serialisierte HTTPS-Uplinks und Long Polling. `https-lanes` verwendet unabhängige HTTPS-Sequenzen und Polls pro logischem Stream. `websocket` verwendet einen geordneten WebSocket für alle Streams. `websocket-lanes` verwendet einen unabhängig verwalteten WebSocket für jeden logischen Stream ungleich null.
- Ein fehlendes `web.carriers` oder `web.carriers = false` deaktiviert Auto-Negotiation und Lernen. Ein nicht leeres Array aktiviert ausschließlich die sequenzielle Start-Negotiation; eine bereits festgeschriebene Sitzung wird nie migriert.
- Native Clients ohne kanonische Carrier-Negotiation-Header verwenden den konfigurierten festen `carrier`, auch wenn `carriers` die Negotiation für fähige Clients aktiviert. Das aktuelle Telegram iOS unterstützt nur `https`; für metadatafreies iOS muss der Betreiber daher `web.carrier = "https"` setzen, `https-lanes` wird nicht unterstützt. User-Agent-Werte einschließlich CFNetwork oder Darwin leiten niemals Capabilities ab. Sendet ein nativer iOS-Client explizite Negotiation-Metadaten, schneidet Telemt sie mit der serverautoritativen Obergrenze `{https}` und lehnt ein leeres Ergebnis ab; andere explizite Clients verwenden ihren angegebenen Capability-Satz.
- Capability-, Bootstrap- und Session-Zugangsdaten sind getrennte Werte mit begrenzter Lebensdauer. Carrier-Zugangsdaten sind geheim und dürfen nicht in Access-Logs erscheinen.
- Ein Bootstrap ist ein Bearer-Token und nicht an eine Quelladresse gebunden. Client-Adresse und IP-Familie dürfen sich zwischen dem Laden der Bridge und der Sitzungserstellung ändern. Die Ausstellungsadresse bleibt dem Limit ungenutzter Bootstraps zugeordnet; die Adresse des ersten gültigen Erstellungs-Requests wird der Sitzung zugeordnet.
- Die innere MTProxy-Authentifizierung ist auf den Benutzer und Secret-Modus des vhost-Profils beschränkt. Ein ungültiger innerer Handshake schließt nur seinen logischen Stream und gelangt niemals in den TCP-Masking-Pfad.

Telegram-Desktop-WEB-Links enthalten keinen Port, da der Client Port 443 voraussetzt:

```text
tg://webproxy?server=proxy.example.com&secret=0123456789abcdef0123456789abcdef
tg://webproxy?server=proxy.example.com&secret=dd0123456789abcdef0123456789abcdef
tg://webproxy?server=proxy.example.com%2Ftelegram%2Fweb&secret=cAABAgMEBQYHCAkKCwwNDg8
```

Telemt gibt beim Prozessstart Links für die durch `[general.links].show` ausgewählten WEB-Profile über das vorhandene Log-Target `telemt::links` aus. Root-Links behalten das bisherige hexadezimale Secret. Bei einem Pfad-Link ist `HOST/BASE` im Parameter `server` percent-encoded; das Secret ist ungepolstertes base64url von `0x70 || client_secret`, wobei `client_secret` im Modus `plain` das rohe 16-Byte-Secret und im Modus `dd` den Wert `0xdd || secret` bezeichnet. Die Users-API liefert nur das rohe Secret und keinen WEB-Link. `[general.links].public_host` und `public_port` wirken nur auf native Links und überschreiben keine WEB-vhost-Links.

## Voraussetzungen

- Ein eigener öffentlicher FQDN und ein gültiges TLS-Zertifikat auf NGINX oder HAProxy.
- Eine stabile öffentliche IP für diesen Hostnamen. `public_addr` muss genau diese konkrete IP auf Port 443 enthalten, da die Adresse Teil des Ziel-Tupels des inneren Relays ist.
- Ein privater oder lokaler HTTP-Pfad vom TLS-Terminator zu Telemt.
- Eine gewöhnliche Decoy-Site als privater HTTP-Origin oder unveränderlicher Snapshot eines lokalen Verzeichnisses.
- Ein kompatibler Telegram-Desktop-Build mit dem Proxy-Typ `WEB`.

Die weitergeleitete Client-Adresse darf eine andere IP-Familie als `public_addr` verwenden und sich während der Bootstrap-Lebensdauer ändern. `public_addr` muss weiterhin den exakten öffentlichen Endpoint der inneren MTProxy-Route bezeichnen.

## Minimale Telemt-Konfiguration

Das Beispiel bindet den WEB-Listener an Loopback und verwendet einen privaten HTTP-Decoy-Origin:

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

Die Behandlung überlasteter angenommener Sockets ist separat konfigurierbar. `drop` behält das bisherige Schließen nach `accept(2)` bei. `respond` schreibt ohne Request-Parsing eine leere, wiederholbare `503`-Antwort. `wait` wartet außerhalb der Accept-Schleife auf gewöhnliche Verbindungskapazität und wechselt danach in die normale HTTP-Verarbeitung; bei Timeout wird dieselbe `503` geschrieben. Warten und Schreiben verwenden pro Phase `web.timeouts.http_overload_timeout_ms`. `web.limits.max_http_overload_connections` begrenzt Sockets außerhalb der gewöhnlichen Kapazität und erfordert bei Änderung einen Prozessneustart; Aktion und Timeout sind hot-reload-fähig.

`base_path` ist standardmäßig leer. Ein nicht leerer Wert umfasst höchstens 128 ASCII-Bytes und besteht aus durch Schrägstriche getrennten Segmenten der Form `[A-Za-z0-9][A-Za-z0-9_-]*`, ohne führenden oder abschließenden Schrägstrich. Root-vhosts behalten die v1-Capability-Ableitung. Pfad-vhosts verwenden den v2-Kontext mit exakt kanonischem Host und Basispfad; eine Änderung der Groß-/Kleinschreibung oder eines Segments ändert daher sowohl Route als auch Capability.

`decoy_fasttrack_mode` steuert ausschließlich die Capability-Verarbeitung für `GET/HEAD` am konfigurierten Basis-Root. `off` ist der Default und behält den vollständigen bisherigen Scan ohne Fast-Track-Zähler bei. `shadow` erfasst, welche strukturell unmöglichen Requests den Scan umgehen könnten, führt ihn aber weiterhin vollständig aus. `enforce` umgeht Capability-Arbeit nur bei `HEAD` oder fehlender beziehungsweise nicht kanonischer `bridge`-Query. Jeder exakte kanonische Bridge-GET am Basis-Root scannt bei Treffer und Fehlschlag vollständig alle Profile des ausgewählten vhost. Die Einstellung erfordert einen Prozessneustart; Reload speichert den gewünschten Wert, meldet `web.decoy_fasttrack_mode` aber als zurückgestellt. Fast-Track schützt nicht vor gegnerischer CPU-Last, da ein Scanner stets kanonische Kandidaten senden kann; `enforce` kann außerdem eine öffentliche Timing-Klasse der Request-Form sichtbar machen, insbesondere bei einem statischen Decoy. Aktivieren Sie diesen Modus nicht ohne externe Timing-Messungen über den produktiven TLS-Terminator.

## Gemeinsame Profile für mehrere Hostnamen

Ersetzen Sie den Selektor `host` durch eine nicht leere Liste `hosts`, damit
mehrere Domains dieselben Profildefinitionen und denselben Decoy-Snapshot nutzen:

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

Dieses Fragment ergänzt den Zugangsbenutzer und WEB-Listener aus dem vorherigen
Beispiel. Geben Sie genau einen Selektor an: `host` oder `hosts`. Hostnamen werden
beim Laden normalisiert; danach identische Namen werden abgewiesen. Wildcard-Muster
und `*` erfordern die unten beschriebene ausdrückliche Aktivierung. Alle Mitglieder
teilen `base_path`, `public_addr`, Profile und Decoy. Bei abweichenden Einstellungen
sind getrennte Gruppen nötig. Der TLS-Terminator muss jeden aufgeführten Hostnamen
bedienen und den ursprünglichen kanonischen `Host` weiterreichen.

Jeder Hostname hat eigene Capabilities, Bootstrap-/Sitzungszuordnungen und
Profilquoten. Das Beispiel erlaubt bis zu acht Sitzungen dieses Profils je Domain,
weiterhin begrenzt durch Prozess-, IP- und Zugangsbenutzerlimits. Beim Start werden
Links für jeden ausgewählten Benutzer/jedes Profil und jeden konkreten Hostnamen
ausgegeben. Die Gruppierung leitet Clients nicht um und macht Zugangsdaten nicht
zwischen Aliasnamen übertragbar.

Bei exakten Namen zählt `max_vhosts` jeden Hostnamen und `max_profiles` jedes
Host-/Profilpaar. Acht Domains mit 100 Profilen benötigen beispielsweise mindestens
acht vhosts und 800 profiles. Statische Dateien und Bytes eines Gruppensnapshots
werden einmal gezählt; getrennte Gruppen behalten getrennte Snapshots. Konfigurierte
Sitzungsobergrenzen reservieren keine Sitzungen vorab. Gemeinsame unveränderliche
Richtlinien reduzieren Duplikate, Capability-Indizes wachsen aber weiterhin mit
der Anzahl der Host-/Profilpaare.

Installieren Sie zuerst die neue Binärdatei mit der bisherigen Konfiguration
einzelner `host`-Einträge. Fassen Sie danach gleich konfigurierte Einträge per Reload
zusammen. Gruppierung und Umordnung erhalten kompatible Bootstrap-Zugangsdaten,
Quotenidentitäten und Lerndaten der Profile. Das Entfernen eines Aliasnamens weist
neue Requests für diesen Namen ab, ohne neue Abbruchregeln für bestehende
Verbindungen einzuführen. Höhere Limits erfordern einen Neustart und müssen vor
dem Hinzufügen von Bindungen oberhalb der aktiven Grenzen wirksam sein. Vor einem
Downgrade auf eine Version ohne `hosts` müssen Gruppen wieder in einzelne
`host`-Einträge aufgeteilt und die Budgets statischer Snapshots geprüft werden.

## Automatische Wildcard-Hosts

Exakte `host`-/`hosts`-Einträge bleiben der Standard. Für beliebige Subdomains
setzen Sie `web.allow_wildcard_hosts = true` und starten Telemt neu. Die vorhandenen
Selektoren akzeptieren dann auch `*.example.com` und `*`, einschließlich gemischter
Listen aus exakten Namen und Mustern:

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

Das Beispiel ergänzt den zuvor gezeigten Listener und Zugangsbenutzer. Ein Request
wählt genau eine Gruppe: zuerst den exakten Host, dann das längste passende Suffix,
dann `*`. Ein Suffix erfasst Nachfahren beliebiger Tiefe, auch `a.b.example.com`,
aber nicht den Stammnamen `example.com`. Fehlgeschlagene Authentifizierung fällt
nicht auf eine andere Regel zurück. Eingebettete Wildcards, reguläre Ausdrücke und
nach der Normalisierung doppelte Selektoren zwischen Gruppen sind unzulässig.
Die ausgewählte Gruppe behält ihre festen Werte für `public_addr`, Basispfad,
Profile und Decoy. Der Request-Host bestimmt keine Upstream-Adresse.

In diesem Modus wird HTTP Host ohne Beachtung der ASCII-Groß-/Kleinschreibung
normalisiert; entfernt wird nur ein optionales wörtliches `:443`. Doppelte
Host-Header, IP-Literale, ungültige DNS-/ACE-Labels, abschließende Punkte und andere
Ports werden abgewiesen. `X-Forwarded-Host` wird nicht ausgewertet. Capabilities
verwenden den tatsächlichen kanonischen Hostnamen und die bestehende
Client-Ableitung; Clientänderungen sind nicht nötig. Sitzungs-/Stream-/Profilquoten
bleiben an das konkrete Tupel `(host, user, secret_mode)` gebunden; Prozess-, IP-
und Zugangsbenutzerlimits gelten weiterhin. Startlinks enthalten nur konfigurierte
exakte Hostnamen.

Das Frontend **muss zulässige Host-Werte einschränken**; das unverschlüsselte WEB-
Backend muss privat erreichbar bleiben. TLS-Zertifikate müssen jeden tatsächlichen
Client-Hostnamen abdecken. Dies ist eine ausdrückliche Sicherheitsgrenze: Eine
Capability für einen unbekannten oder aus dem Cache verdrängten fremden Wildcard-
Host kann bei Übermittlung an einen anderen Host dessen Decoy erreichen, auch bei
einem exakten Host in einer gemischten Konfiguration. Capabilities des aktuellen
Hosts, der endlichen exakten Hostliste und des bekannten Positiv-Caches sowie
authentische Bootstrap-/Sitzungstokens des Prozesses bleiben in Request-URI und
Header-Metadaten lokal, einschließlich percent-encoded Formen. Öffentliche URLs,
Cookies und Header werden nicht allein wegen ihrer Ähnlichkeit mit Zugangsdaten
abgewiesen. Diagnosekopien maskieren dagegen vorsorglich ähnlich aussehende Texte,
auch abgeschnittene Präfixe; öffentliche Request-/Response-Bytes und ursprüngliche
User-Agent-Hashes bleiben unverändert. Daher kann die Diagnose auch gewöhnliche
lange Zeichenfolgen maskieren.

Ein kalter Request reserviert vor jeder Ableitung atomar das HMAC-Budget für die
vollständige Profilzahl der ausgewählten Gruppe. Bei Erschöpfung folgt sofort
HTTP 503 mit no-store, ohne Warteschlange oder Teilscan. Ein Request verwendet
seine Tabelle sowohl zur Vermeidung von Credential-Lecks als auch zur Bridge-
Authentifizierung. Cachetreffer vermeiden die Ableitung. Authentifizierte Carrier
umgehen Capability-Tabellencache und Ableitung vollständig. Die Fast-Track-Modi
Off/Shadow/Enforce steuern weiterhin die Authentifizierung am Basis-Root;
fehlplatzierte Zugangsdaten des aktuellen Hosts bleiben in jedem Modus lokal.

Nur eine erfolgreiche Bootstrap-Ausgabe für Bridge/Recovery füllt den FIFO-Cache.
`cache_hosts = 0` deaktiviert die Speicherung. Eintrags- und Byteobergrenzen sind
unabhängig; verdrängte Einträge belasten das Bytebudget weiter, solange ein Request
sie referenziert. Ein fehlgeschlagener Cacheeintrag verwirft keinen gültigen
Bootstrap, und Verdrängung setzt keine Quoten zurück. Cacheschlüssel enthalten die
eindeutige ID des unveränderlichen WEB-Snapshots, auch bei Reloads innerhalb
derselben Runtime-Generation. Einträge halten weder Decoy noch Generation fest.

`max_vhosts` zählt exakte Einträge; `max_profiles` zählt exakte Bindungen sowie einen
gemeinsamen Profilsatz je Wildcard-Quellgruppe. `max_rules` begrenzt Muster und
`max_profiles_per_request` den vollständigen Scan einer Wildcard-Gruppe. Außer
`cache_hosts` müssen die Limits positiv sein; der HMAC-Burst muss eine vollständige
Request-Tabelle abdecken. Geprüfte Speicherreservierungen umfassen Vorlagen/Regeln,
Cache, Arbeitsspeicher der Handler und lebende Hostbindungen nur bei aktivem
Wildcard-Modus. Bei ansonsten standardmäßigen Limits reicht der bisherige Rahmen
von 1280 MiB nicht aus; 1290 MiB genügen nach aktueller Berechnung, das Beispiel
sieht 1536 MiB vor. Der Speicherrahmen und die Verarbeitung bei ausschließlich
exakten Hosts bleiben unverändert.

Der Aktivierungsparameter und alle `web.limits` erfordern einen Prozessneustart.
Nach der Aktivierung lassen sich Selektoren und Profile per Reload ändern. Ein
API-Update kann den Parameter und ausreichende Limits als zurückgestellte
Änderungen speichern. Muster vor dem tatsächlichen Neustart hinzuzufügen wird
atomar abgewiesen, auch wenn der Parameter bereits in der gewünschten Konfiguration
steht. Zum Deaktivieren ersetzen Sie zuerst Muster durch exakte Selektoren und
starten dann mit deaktiviertem Parameter neu. Vor einem Downgrade entfernen Sie
Wildcard-Selektoren, den neuen Parameter und die Limittabelle.

## Serverseitige Carrier-Negotiation

Bei `websocket-lanes` löst eine Ablehnung oder ein Timeout vor dem Upgrade einer Lane die gemeinsame Sitzungswiederherstellung aus. Fehler nach dem Upgrade bleiben auf die Lane begrenzt. Dieses Protokollverhalten belegt keine native macOS-/iOS-Kompatibilität bei Rückkehr aus dem Hintergrund.

Die unveränderliche Bridge-Grundstruktur wird gecacht; Nonce, Bootstrap, Host und Basispfad werden für jede Antwort frisch eingesetzt. Ablaufprüfungen nutzen konservative Hinweise auf Deadlines, ohne Ablaufgrenzen zu verlängern. Diese internen Optimierungen ändern weder Wire-Formate, Zulassungslimits noch konfigurierte Timeouts und belegen allein keine kürzere Ende-zu-Ende-Verbindungszeit.

Auto-Negotiation ist optional und bleibt deaktiviert, solange `carriers` nicht als explizites, nicht leeres Array gesetzt ist. Der konfigurierte `carrier` bleibt der letzte Fallback und wird genau einmal angehängt, auch wenn er bereits im Array steht:

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

Die erzeugte Bridge sendet bei `/session` die kanonischen Header `X-Carrier-Capabilities`, `X-Carrier-Attempt` und ab dem zweiten Versuch `X-Carrier-Failure`. Jede erfolgreiche automatische Response liefert `X-Carrier-Mode`, `X-Carrier-Attempt`, `X-Carrier-Candidate-Count`, `X-Carrier-Deadline` und `X-Carrier-State`. Die Bridge startet ihre lokale kumulative Uhr unmittelbar vor dem ersten `/session`-Request; der Server friert seine separate absolute Chain-Deadline bei Annahme des ersten automatischen Versuchs ein. Beide verwenden die konfigurierten Offsets und werden bei Ersatzversuchen nicht zurückgesetzt. Für einen bis vier effektive Kandidaten lauten die Attempt-Checkpoints entsprechend `[d3]`, `[d0, d3]`, `[d0, d1, d3]` und `[d0, d1, d2, d3]`; der letzte Kandidat verwendet immer `d3`. Ein Nachfolger bleibt bis zu seinem eigenen Checkpoint zulässig. Die Zustände sind `provisional`, `committed` und `healthy`.

Die Bridge sendet additive v1-Statusobjekte mit `state`, `phase`, `reason` und `deadline_ms`. `phase=provisional` folgt auf das authentifizierte `WELCOME`; `state=connected,phase=committed` wird erst gesendet, nachdem der ausgewählte Transport echten `OPEN`- oder `DATA`-Fortschritt bestätigt hat. Der Initialisierungsport besitzt eine eigene Pre-`HELLO`-Deadline `bridge_request_secs`, und eine Seitennavigation ist für diese Dokumentinstanz terminal. Eine spätere Initialisierungsnachricht kann eine geschlossene oder im BFCache gehaltene Bridge nicht wiederbeleben.

Versuche laufen streng sequenziell. Akzeptierter `OPEN`- oder `DATA`-Fortschritt schreibt den gewählten Carrier sofort fest und schließt die Ersatzgrenze endgültig. Ein authentifiziertes `409` für eine festgeschriebene Kette wiederholt deren Metadaten und ist terminal; es erlaubt keinen weiteren Versuch. Das exakte Replay von `/session` wird nur verwendet, solange dessen Ergebnis mehrdeutig ist. Nach der authentifizierten Auswahl eines provisional Carriers fordert ein Transportfehler direkt den nächsten Versuch an; wurde der vorherige Probe doch committed, antwortet der Server terminal mit `409`, statt einen unsicheren Ersatz zuzulassen. Die endgültige absolute Server-Deadline begrenzt auch einen Nachfolger, dessen Response den Client nie erreicht hat. Ein In-place-Wechsel nach dem Commit bleibt nicht unterstützt; eine überlebende Bridge stellt sich durch eine frische Serversitzung wieder her.

Nach dem Commit wiederholt ein HTTP-Fehler zunächst den exakten unveränderlichen Request mit dem aktuellen Bearer. Ein erfolgreicher Replay behält die aktuelle Sitzung. WebSocket-Verlust oder ein Foreground-, Online- oder natives Ereignis nach mindestens `reconnect_grace_secs` Scheduler-Lücke startet eine Recovery-Epoche. Die Bridge sendet genau einen GET an ihren ursprünglichen konfigurierten Basis-Root mit `bridge=<capability>`, `Accept: application/vnd.telemt.web-recovery+json` und optionaler aktueller Bearer-Authorization. Eine positive Antwort ist ein nicht cachebares JSON-Dokument mit höchstens 1024 Bytes, einem frischen Bootstrap und den aktuellen Limits, Timeouts sowie der Negotiation-Richtlinie. Telemt gibt diesen Bootstrap aus, bevor eine passende aktuelle Sitzung synchron beendet wird, sodass eine Neuerstellung auch bei Kapazität für nur eine Sitzung möglich bleibt. Unbekannte oder bereits beendete Bearer erhalten dieselbe positive Repräsentation; fehlerhafte Recovery-Header sowie deaktivierte Admission, Pause, Drain und Kapazitätsablehnung folgen dem bereinigten Decoy-Pfad.

Die Recovery-Epoche besitzt eine gemeinsame absolute Wall-/Monotonic-Deadline `bridge_recovery_secs`, genau einen Request für das Recovery-Dokument und begrenzte Carrier-Wiederholungen mit Backoff von 250 ms bis 2 s. Während der Recovery wird der Status höchstens alle 2,5 Sekunden wiederholt. Eine frische Inkarnation bricht alte Requests, Sockets, Lanes und Queues ab und gibt sie frei, sendet für jeden noch aktiven nativen Stream genau ein synthetisches `CLOSE`, unterdrückt ein zweites `WELCOME` und committed erst nach echtem Carrier-Fortschritt. Beendete Stream-IDs bleiben in einer begrenzten Menge, damit gültige verspätete Frames nicht in einen neuen Stream gelangen; die native Seite muss eine neue Stream-ID vergeben. Häufige native Reconnect-Versuche sind zulässig, verlängern aber weder die Recovery-Epoche noch halten sie alten Inkarnationszustand. Das Zerstören der WebView zerstört auch diesen Recovery-Owner; ein nativer Supervisor muss danach ein neues Bridge-Dokument erzeugen.

Jede reguläre HTTP-Carrier-Operation der Bridge besitzt ein absolutes Budget `bridge_retry_secs` und höchstens neun Versuche. `bridge_request_secs` umfasst sowohl den Fetch-Response-Head als auch das vollständige Lesen des Response-Bodys; ein Downlink-Versuch erhält zusätzlich das konfigurierte Long-Poll-Intervall. Netzwerkfehler und Antworten mit `408`, `429`, `502`, `503` oder `504` verwenden begrenzten exponentiellen Backoff, während `Retry-After` das absolute Budget nicht verlängern kann. `carrier_probe_coalesce_ms = 0` sendet den ersten geordneten `OPEN`-Probe sofort. Ein Wert bis 10 ms kann passendes `DATA` aus diesem Fenster aufnehmen; multiplexierte Carrier bewahren die vollständige vorhergehende Frame-Reihenfolge, Lane-Carrier beanspruchen nur die ausgewählte Lane. Vor der Probe-Bestätigung startet kein HTTP-Downlink. Ein multiplexierter WebSocket-Upgrade kann unmittelbar nach seiner Auswahl durch `/session` beginnen und danach eingereihte Probe-Daten aufnehmen; ein Lane-WebSocket wartet auf die bekannte Stream-ID.

Response-Bodys werden innerhalb expliziter Endpunktgrenzen gestreamt: `/session` enthält exakt acht Bytes, ein erfolgreicher `/down` höchstens `carrier_batch_bytes`, und bodylose Antworten akzeptieren null Bytes. Deklarierter Überlauf wird vor dem Lesen abgelehnt; ein Überlauf beim Streaming oder zu viele Chunks bricht den Reader ab, und Bodys wiederholbarer Antworten werden vor dem Backoff verworfen. Die terminale Bridge-Bereinigung sendet höchstens ein authentifiziertes `DELETE`. Kanonische Transportfehler werden für Diagnosen nach `X-Carrier-Failure` kopiert, Navigation und explizites Schließen bleiben nicht lernende Gründe.

Automatische WebSockets verwenden `tproxy-auto-v1.<session-token>` beziehungsweise `tproxy-auto-lane-v1.<session-token>.<stream-id>`. Die erste akzeptierte Binärnachricht mit echtem `OPEN`- oder `DATA`-Fortschritt schreibt den Carrier fest; danach schreibt der Server eine leere binäre Commit-Bestätigung auf genau diese Verbindung. Ping/Pong schreibt keinen Carrier fest und zählt nicht als Learning-Evidenz.

Ein festgeschriebener Versuch wird erst healthy, wenn transportspezifische bidirektionale Evidenz für `carrier_health_secs` gültig bleibt. HTTPS erfordert akzeptiertes `DATA`, einen bestätigten nicht leeren Post-Commit-Downlink-Batch sowie authentifizierte Aktivität an oder nach der Health-Deadline. WebSocket erfordert die geschriebene exakte Commit-Bestätigung, danach akzeptiertes `OPEN` oder `DATA` desselben Owners und einen bis zum Ende des Intervalls lebenden Owner. Health-Veröffentlichung, Owner-Eviction und Close besitzen genau einen terminalen Gewinner. Ein früheres Schließen bleibt für Ranking-Evidenz neutral, ist aber als Diagnoseergebnis `closed_before_health` sichtbar.

Das Lernen ist prozesslokal, speicherresident, ausschließlich positiv und durch `max_carrier_learning_entries` begrenzt. Es sortiert nur vom Client unterstützte konfigurierte Kandidaten, hält den konfigurierten Fallback stets zuletzt und bewahrt bei gleichen Scores die Konfigurationsreihenfolge. User-Agent- und Profilevidenz haben Primärgewicht; eine zulässige IP dient nur als Tie-Breaker. IP-Evidenz erfordert genau eine explizite, global routbare `X-Forwarded-For`-Adresse; private, Loopback-, Link-Local-, Carrier-Grade-NAT-, Dokumentations-, Multicast- und entsprechende IPv4-Mapped-Adressen sind ausgeschlossen. Vom Client gemeldete Fehlerkategorien und Request-Latenz sind ausschließlich diagnostisch und erzeugen weder negative noch Ranking-Evidenz. `conservative` erfordert 3 User-Agent-Ergebnisse oder 8 Profilergebnisse aus 4 Kohorten und deaktiviert IP-Evidenz; `balanced` verwendet 2, 6 aus 3 Kohorten und 3 zulässige IP-Ergebnisse; `aggressive` verwendet 1, 4 aus 2 Kohorten und 1 IP-Ergebnis. Ein Generationswechsel mit identischer Learning-Semantik bewahrt die Evidenz und veröffentlicht deren Generation-Fence atomar neu. Das Deaktivieren des Learnings oder eine Änderung von Aggressiveness, Evidenz-Lebensdauer oder Health-Fenster erhöht die Evidenz-Epoche und trennt inkompatiblen Zustand ab; veraltete Ergebnisse können ihn nicht erneut füllen.

`https` bleibt der Default und behält das ursprüngliche serialisierte Verhalten bei. Bei `https-lanes` ist Lane null für Session-Steuerung reserviert, und jeder logische Stream ungleich null erhält eine eigene Lane. Jede Lane besitzt eigene Uplink-Sequenzen, Retry-Digests, Downlink-Cursor, nicht bestätigte Replay-Batches, Queues und einen Newest-Poll-Wins-Lebenszyklus. Ein langsamer Stream blockiert daher keinen anderen Stream auf der WEB-Protokollebene.

Damit entfällt die Serialisierung zwischen WEB-Streams auf Anwendungsebene. Öffentliches HTTP/2 läuft weiterhin über eine oder mehrere TCP-Verbindungen, sodass Paketverlust Head-of-Line-Blocking auf Transportebene verursachen kann; `https-lanes` ist kein HTTP/3- oder QUIC-Carrier.

Alle Lane-Queues und residenten Response-Bodys bleiben innerhalb der vorhandenen Byte-/Item-Budgets pro Sitzung und Prozess. Telemt begrenzt jede Lane zusätzlich durch `pending_bytes_per_lane` und `pending_items_per_lane`; die erzeugte Bridge begrenzt ihre entsprechenden Queues auf 8 MiB und 1024 Elemente. Lane-Long-Polls dürfen höchstens die Hälfte von `web.limits.max_http_handlers` belegen, sodass Handler-Kapazität für Sitzungserstellung, Uplink, DELETE und andere Steuerarbeit verbleibt. `https` erfordert `max_http_handlers >= 2`, `https-lanes` erfordert `max_http_handlers >= 4`.

Die Suffixe `/api/v1/up` und `/api/v1/down` ändern sich nicht und werden an die konfigurierte Basis angehängt. Bei `https-lanes` enthält jeder Request an diese Pfade genau einen kanonischen dezimalen `X-Lane-ID`-Header. Die Uplink-Sequenz beginnt pro Lane unabhängig bei `1`, der Downlink-Cursor bei `0`. Lane null akzeptiert nur Session-`PONG`; jeder Frame einer Lane ungleich null muss dieselbe Stream-ID tragen, und eine neue Lane muss mit `OPEN` beginnen. Ein kanonischer Cursor-null-Downlink, der kurz vor dem `OPEN` seiner Lane eintrifft, wartet bis zu `lane_open_wait_secs`, ohne Lane-Zustand anzulegen; Grenzen pro Sitzung und prozessweite Hilfs-Permits begrenzen diese Wartefälle. Nach Ablauf folgt eine leere `204`-Response, während eine fehlende Lane mit fortgeschrittenem Cursor weiterhin als Protokollfehler über den Decoy-Pfad behandelt wird. Nachdem eingereihte und nicht bestätigte Downlink-Daten einer geschlossenen Lane vollständig abgearbeitet sind, antwortet Telemt leer mit `X-Lane-Closed: 1`, und die Bridge beendet deren Polling. Wiederholungen bleiben byte-identisch und spielen die ursprüngliche Bestätigung oder den Downlink-Batch erneut aus.

Beide WebSocket-Carrier erstellen und löschen die übergeordnete Sitzung weiterhin über HTTPS und verwenden danach einen strikten Upgrade-GET ohne Body an der konfigurierten Basis plus `/api/v1/ws`. `websocket` übermittelt in `Sec-WebSocket-Protocol` exakt `tproxy-v1.<session-token>`; binäre Messages sind geordnete Carrier-Batches, und ein Protokoll-, Deadline- oder Verbindungsfehler schließt die gesamte übergeordnete Sitzung. `websocket-lanes` übermittelt exakt `tproxy-lane-v1.<session-token>.<stream-id>`, wobei die Stream-ID kanonisch dezimal im Bereich `1..=16777215` steht. Die erste binäre Message muss mit `OPEN` beginnen, alle Frames müssen diese Stream-ID verwenden und ein Fehler nach dem Upgrade schließt nur diese Lane. Es gibt keinen Lane-null-WebSocket: HTTPS transportiert `HELLO` und `WELCOME`, während RFC-6455-Ping/Pong die Verbindungsliveness gewährleistet.

Vor HTTP `101` wird eine WebSocket-Lane-Reservierung an die exakte Prozessverbindung und Lane-Inkarnation gebunden; ein akzeptiertes `OPEN` überträgt die Ownership auf die exakte Stream-Inkarnation, bevor deren Backend-Task laufen kann. Ein verspäteter Poll, Close oder Reservierungs-Drop eines älteren Sockets kann einen Ersatz mit derselben numerischen Lane-ID weder bestätigen noch schließen oder freigeben.

WebSocket-Codec-Puffer und laufende Read-/Write-Messages teilen das prozesseigene Budget `pending_bytes_global` mit den Carrier-Queues und sind zusätzlich durch `websocket_bytes_global` begrenzt. Admission reserviert `websocket_http_connection_reserve` angenommene Verbindungen für gewöhnliches HTTP und Decoys. Bei einem Admission-Ersatz werden zuerst global tote aktive Verbindungen ausgewählt; danach gelten die Lokalitätsstufen gleiche Sitzung, gleicher Profil-Owner und gleiche Client-IP. Ein davon unabhängiges gesundes Opfer ist nur zulässig, wenn der Anforderer unter seinem fairen Byte-Anteil und der Owner des Opfers darüber liegt. Innerhalb einer Lokalitätsstufe stehen beanspruchte oder auf WebSocket hochgestufte Verbindungen vor aktiven Lanes und diese vor aktiven multiplexierten Sitzungen; letzter Fortschritt, Erstellungsreihenfolge und Verbindungs-ID lösen Gleichstände deterministisch auf. Das Cleanup bei Speicherdruck verwendet dieselbe Dead-first- und Lebenszyklusreihenfolge und bevorzugt Owner über ihrem fairen Anteil, setzt die Verdrängung aber auch fort, wenn alle Owner ihren Anteil einhalten. `max_websocket_evictions_in_flight` begrenzt gleichzeitige exakte Verdrängungs-Claims. Upgrade-, Erstnachrichten-, Write-, Backpressure- und Eviction-Deadlines stammen unveränderlich aus der Parent-Sitzung. Nach `long_poll_secs` ohne Peer-Aktivität wird auch bei kontinuierlichem Downlink-Verkehr ein Transport-Ping gesendet; fehlende Peer-Aktivität während des doppelten, beim Verbindungsaufbau festgelegten Intervalls macht eine aktive Verbindung zum Cleanup-Kandidaten.

Jeder Authentifizierungs-, Shape-, Lane-Reservierungs- oder Kapazitätsfehler vor dem Upgrade folgt dem bereinigten Decoy-Pfad und legt keinen WebSocket-spezifischen Status offen. Das exakte Subprotokoll enthält den Session-Bearer und darf nicht protokolliert werden.

Der WEB-Listener muss `proxy_protocol = false` und `reuse_allow = false` verwenden. `client_mss`, `synlimit`, `announce` und `announce_ip` sind nicht zulässig. `web_trusted_proxy_cidrs` muss nicht leer sein und darf nur die unmittelbar vorgeschalteten NGINX- oder HAProxy-Peers enthalten; `/0`-Netze werden abgelehnt.

Für `http_upstream` akzeptiert `resolve` die Werte `"never"` (Standard) und `"startup"`. Standardmäßig ist ein Loopback-, Link-Local- oder privates IP-Literal erforderlich. `startup` erlaubt zusätzlich DNS-Namen: Die asynchrone Konfigurationsvorbereitung löst jedes eindeutige Host-/Portpaar auf, prüft alle Antworten gegen erlaubte Adressklassen und effektive WEB-Listener und fixiert die erste Adresse in Resolver-Reihenfolge. Fehler, leere Antworten, öffentliche Adressen oder direkte Listener-Schleifen verwerfen die Vorbereitung. Der konfigurierte Hostname bleibt in der Upstream-Authority erhalten. Es gibt weder DNS während der Request-Verarbeitung noch automatischen Wechsel zu weiteren Antworten; Reload erstellt einen frischen Snapshot. `web.timeouts.decoy_resolve_secs` begrenzt jede DNS-Abfrage für ein eindeutiges Host-/Portpaar. Die Abfragen laufen nacheinander, ohne gemeinsame Deadline für die gesamte Vorbereitung. Indirekte Schleifen über weitere Weiterleitungsschichten müssen Betreiber ausschließen.

Gewöhnliche Requests behalten Methode, Pfad, Query, Header, gestreamten Body sowie Response-Status und Body, außer Hop-by-Hop-Headern. Fehlerhafte Carrier-Requests verlieren vor der Decoy-Weiterleitung Zugangsdaten und Bodys.

Alternativ kann ein unveränderlicher Snapshot einer statischen Site verwendet werden:

```toml
[web.vhosts.decoy]
mode = "static_directory"
directory = "/var/lib/telemt/public"
index = "index.html"
```

Statische Dateien werden beim Start und bei einem erfolgreichen Konfigurations-Reload gelesen. Eintragszahl, Dateigröße und Gesamtgröße des Snapshots werden durch `[web.limits]` begrenzt. Symlinks und Pfade außerhalb des konfigurierten Verzeichnisses werden abgelehnt. Ändern Sie das Verzeichnis nicht gleichzeitig, während Telemt einen Snapshot erstellt.

Alle WEB-Schlüssel und Defaults sind in der [Konfigurationsreferenz](../Config_params/CONFIG_PARAMS.de.md#web) aufgeführt.

## TLS-Terminierung mit NGINX

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

Platzieren Sie `map` im NGINX-Kontext `http`. `client_max_body_size` muss mindestens `web.limits.max_body_bytes` entsprechen. Read-, Send- und Client-Timeouts müssen sowohl den standardmäßigen 25-Sekunden-Long-Poll als auch das doppelte WebSocket-Liveness-Intervall überschreiten; 65 Sekunden decken die Defaults ab. Überschreiben Sie `X-Forwarded-For`, statt einen Wert anzuhängen. Telemt akzeptiert eine syntaktisch gültige IP-Adresse; fehlt der Header bei einem vertrauenswürdigen TLS-Terminator, verwendet Telemt die Adresse des direkten Peers, doch clientbezogene Limits und Quellrichtlinien sehen dann den Terminator statt des echten Clients. Aktivieren Sie keine Upstream-Wiederholungen: Die Bridge führt byte-identische HTTPS-Wiederholungen aus, ein etablierter WebSocket wird jedoch nie transparent wiederholt.

Ersetzen Sie für Prefix-only-Cohosting mit `base_path = "telegram/web"` die Zeile `location /` durch `location ^~ /telegram/web/`. Behalten Sie `proxy_pass http://telemt_web;` ohne URI-Komponente bei und fügen Sie kein `rewrite` hinzu; NGINX muss das ursprüngliche Präfix weitergeben. Requests außerhalb dieses Teilbaums dürfen eine andere Site verwenden, jeder Request innerhalb davon muss jedoch zu Telemt gehen. Definieren Sie außerdem ein exaktes `location = /telegram/web`, das das gewöhnliche Non-WEB-Verhalten der Site verwendet oder unverändert an Telemt und dessen Decoy-Pfad weiterleitet. Andernfalls kann NGINX für den Alias ohne Schrägstrich selbstständig ein slash-ergänzendes `301` erzeugen; dies gehört nicht zum WEB-Vertrag.

Öffentliches HTTP/2 ist für `https-lanes` obligatorisch; verwenden Sie die entsprechende HTTP/2-Direktive der installierten NGINX-Version. WebSocket-Upgrade erfordert HTTP/1.1, daher muss der öffentliche Endpunkt auch HTTP/1.1 zulassen und der private Hop von NGINX zu Telemt bleibt HTTP/1.1. Bewahren Sie `Connection`, `Upgrade` und `Sec-WebSocket-*` wie gezeigt unverändert. Die Upstream-Verbindungskapazität muss die erwarteten gleichzeitigen Lane-Polls oder WebSocket-Lanes tragen; `keepalive` steuert den Idle-Pool und ist keine Nebenläufigkeitsgrenze.

### Verbindungsablehnung und WEB-Kapazität unterscheiden

`connect() failed (111: Connection refused) while connecting to upstream` ist ein TCP-Verbindungsfehler, bevor Telemt einen Socket annimmt. Prüfen Sie, ob der Telemt-Prozess läuft, effektive WEB-Listener-Adresse und -Port mit dem NGINX-Upstream übereinstimmen, beide Prozesse denselben erwarteten Network Namespace und dieselbe Adressfamilie verwenden und keine lokale Firewall die Verbindung aktiv ablehnt. Ein Bind-Fehler beim Start, terminales Entfernen des Listeners oder das Umschalten von NGINX auf einen gewünschten Port, bevor eine neustartpflichtige Listener-Änderung effektiv wird, kann dieses Symptom erzeugen. Druck auf den Kernel-Listen-Backlog ist davon getrennt und erfordert üblicherweise Host-Telemetrie für `ListenOverflows` und `ListenDrops`.

WEB-Kapazität wird erst nach erfolgreichem `accept(2)` durchgesetzt. Erschöpftes `max_http_connections` erzeugt daher das konfigurierte Ergebnis `drop`, `wait` oder `respond`, aber keine Upstream-Verbindungsablehnung. Handler-, Body-, Lane-, Stream-, Queue- und WebSocket-Limits besitzen eigene HTTP-, Decoy- oder streamlokale Fehlergrenzen. Operator-Pause und -Drain lassen den WEB-Listener ebenfalls gebunden und können allein keine Ablehnung erzeugen.

Verwenden Sie `GET /v1/runtime/web/status`, um ausschließlich Telemt-eigenen Zustand zu korrelieren. `ingress.accepting_connections` erfordert eine laufende Veröffentlichung, eine lesbare Runtime und einen aktiven Acceptor für jeden effektiven WEB-Listener. `capacity.saturated_resources`, typisierte Rejection-Summen und Overload-Ergebnisse identifizieren Fehler nach dem Accept. `decoy_upstream` beschreibt nur Telemt's ausgehenden Plain-HTTP-Hop zum Decoy. Keines dieser Felder behauptet, dass der öffentliche NGINX-TLS-Endpunkt erreichbar ist; prüfen Sie diese Grenze mit einem externen TCP/TLS-Probe und NGINX- oder HAProxy-Telemetrie.

## TLS-Terminierung mit HAProxy

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

Im Frontend oder im Abschnitt `defaults` muss für das standardmäßige WebSocket-Liveness-Intervall auch `timeout client 65s` oder länger gesetzt sein. Für `https-lanes` muss das öffentliche HAProxy-ALPN `h2`, für WebSocket-Upgrade außerdem `http/1.1` enthalten. Bewahren Sie `Connection`, `Upgrade` und `Sec-WebSocket-*` unverändert; Pfad, Raw Query, Body sowie die Carrier-Header `Authorization`, `Content-Type`, `X-Up-Seq`, `X-Down-Cursor` und `X-Lane-ID` dürfen nicht umgeschrieben werden. Fügen Sie für Prefix-only-Cohosting `acl telemt_web_path path_beg /telegram/web/` hinzu und verlangen Sie in `use_backend` sowohl Host- als auch Pfad-ACL; entfernen Sie das Präfix nicht.

## TLS-Terminierung mit Caddy

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

Caddy bezieht und erneuert das öffentliche Zertifikat für die Site-Adresse automatisch. Den ursprünglichen `Host` sowie die Header `Connection`, `Upgrade` und `Sec-WebSocket-*` leitet Caddy unverändert weiter, WebSocket-Upgrade wird ohne zusätzliche Direktiven proxied; fügen Sie kein `header_up Host` hinzu. Öffentliches HTTP/2 (für `https-lanes`) und HTTP/1.1 (für WebSocket-Upgrade) sind standardmäßig aktiv, der private Abschnitt Caddy → Telemt bleibt HTTP/1.1. Die globale Option `protocols h1 h2` hält HTTP/3 aus dem WEB-Pfad heraus, weil der WEB-Vertrag nur HTTP/1.1 und HTTP/2 abdeckt. Sie gilt für alle Sites dieses Caddy-Servers.

`header_up X-Forwarded-For {remote_host}` überschreibt den Header mit genau einer Adresse. Ohne diese Zeile hängt Caddy bei Peers aus `trusted_proxies` an einen eingehenden `X-Forwarded-For` an, Telemt akzeptiert jedoch nur eine parsebare IP-Adresse. Steht Caddy selbst hinter einem L4-Balancer mit `listener_wrappers { proxy_protocol }`, ist `{remote_host}` die Client-Adresse aus dem PROXY-Header. `flush_interval -1` deaktiviert die Antwortpufferung für Long Polls und Downlinks. Request-Bodies streamt Caddy standardmäßig; aktivieren Sie kein `request_buffers`.

`reverse_proxy` hat in Caddy standardmäßig weder Read-/Write-Timeouts noch ein Body-Limit, daher passieren der 25-Sekunden-Long-Poll und das WebSocket-Liveness-Intervall unverändert. Sind serverweite `timeouts` oder `request_body max_size` gesetzt, müssen sie über 65 Sekunden bzw. mindestens bei `web.limits.max_body_bytes` liegen. Mit einem einzigen Upstream wiederholt Caddy fehlgeschlagene Anfragen nicht; fügen Sie weder `lb_retries` noch `lb_try_duration` hinzu. Bei einem Konfigurations-Reload schließt Caddy upgegradete Verbindungen standardmäßig sofort. `stream_close_delay` hält bestehende WebSocket-Lanes nach einem Reload für die angegebene Zeit offen.

Leiten Sie für Prefix-only-Cohosting mit `base_path = "telegram/web"` den Teilbaum über `handle` und nicht über `handle_path` weiter, denn `handle_path` entfernt das Präfix:

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

Das Routing von Caddy fügt keine Weiterleitung mit angehängtem Slash hinzu: `/telegram/web` ohne abschließenden Slash landet im Handler der gewöhnlichen Site. Stellen Sie sicher, dass auch dieser Handler nicht weiterleitet; `file_server` leitet etwa eine Verzeichnisanfrage auf die Variante mit Slash um.

Ohne `log`-Direktive schreibt Caddy kein Access-Log. Wird eines benötigt, schwärzen Sie Bridge-Capability und Bearer-Credentials:

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

Tragen Sie in `web_trusted_proxy_cidrs` die Adresse ein, von der aus Caddy Telemt erreicht, für die obige Konfiguration also `["127.0.0.1/32"]`.

## Lebenszyklus und Reload-Verhalten

| Konfiguration | Runtime-Verhalten |
| --- | --- |
| Bestand der WEB-Listener, Bind-Adresse und Vertrauensrichtlinie | Prozesseigen; Telemt neu starten. |
| `web.allow_wildcard_hosts` und jeder Wert in `[web.limits]` | Prozesseigener Speicher- und Ressourcenvertrag; Telemt neu starten. |
| `web.enabled`, Carrier-/Negotiation-Richtlinie, `web.debug`, Timeouts, vhosts, Profile und Decoys | Werden vom Config-Watcher oder durch einen Runtime-Generations-Reload angewendet. |
| Änderung des `base_path` eines vhost | Schaltet Routing neuer HTTP-Requests und Capability-Ableitung atomar um. Geben Sie den generierten Link neu aus. Bereits hochgestufte WebSockets und laufende geroutete Austauschvorgänge laufen weiter. Spätere Requests an die alte Basis mit einem prozessauthentischen Bootstrap- oder Session-Token erhalten ein lokales, nicht cachebares `404`; die nun inaktive alte Capability folgt der gewöhnlichen Decoy-Behandlung. Ein bestehender Session-Bearer bleibt nur an der neuen exakten Basis verwendbar, während ein für die alte Capability ausgegebener ungenutzter Bootstrap an der neuen Basis keine Sitzung erstellen kann. |
| Operator-Pause/-Drain-Zustand | Prozesseigen und flüchtig; übersteht einen Generations-Reload, schreibt niemals Konfiguration und wird nach einem Prozessneustart auf `running` zurückgesetzt. |
| Bestehende HTTP-Verbindungen und WEB-Sitzungen | Behalten HTTP-Idle-Grenze, Carrier-Kandidaten, Grenzen, Body-Timeout, Lebensdauer des Replay-Markers geschlossener Token sowie absolute Session-/Negotiation-Deadlines ihres Erstellungszeitpunkts; jede ausgegebene Bridge enthält ihre Request-, Retry-, Recovery- und Probe-Coalescing-Werte. Eine Recovery-Epoche fixiert ihr aktuelles Bridge-Budget; eine erfolgreiche Recovery-Repräsentation aktualisiert die Richtlinie für spätere Epochen und die frische Sitzung. WebSocket-Upgrade-, Open-, Write-, Backpressure- und Eviction-Vorgänge verwenden die unveränderlichen Deadlines der Parent-Sitzung. Neue Bridges verwenden die aktive Richtlinie, neue logische Streams die aktive Relay-Generation. |
| Beenden des Prozesses | Erfasst den zuletzt geladenen Wert von `web.timeouts.shutdown_secs` einmalig und verwendet dieselbe absolute Deadline für Listener-Acceptoren und Verbindungen sowie WEB-Sitzungen und Hilfstasks. Aufeinanderfolgende Komponenten erhalten keine separaten vollständigen Budgets. |

Jeder logische Stream behält die Client-IP seiner Sitzung und besitzt während der gesamten Relay-Lebensdauer einen prozessweit eindeutigen, von null verschiedenen synthetischen Quellport. Damit bleibt für Direct- und Middle-End-KDF-Routing ein stabiles, kollisionsfreies Quell-/Ziel-Tupel erhalten.

Die HTTP-Idle-Erfassung schützt nur explizit begrenzte Request-Body-, Long-Poll-, Decoy-Verbindungs-/Response-Head- und ausstehende Upgrade-Phasen. Die eigene Deadline der Operation bleibt exakt; besteht ihre Lease in diesem Moment noch, gewährt der Verbindungs-Watchdog dem eingeplanten Task höchstens ein Connection-Idle-Intervall zur Veröffentlichung seines Timeouts/Ergebnisses, bevor er die Verbindung erzwingend schließt. Zwischen Austauschvorgängen und nach Bereitstellung eines Response-Heads setzt Fortschritt den Idle-Timer zurück, während ein blockierter Response-Body weiterhin durch den Idle-Timeout begrenzt bleibt. Der Abschluss einer älteren Phase kann den Deadline-Schutz einer neueren Phase nicht freigeben.

Ein `OPEN` reserviert die begrenzte Eigentümerschaft für logischen Stream und Tupel, verbraucht jedoch noch kein `max_connections`-Permit der Relay-Generation. Telemt erwirbt dieses Permit erst nach dem ersten inneren Byte; die unveränderliche First-Byte-Deadline und Stream-Grenzen begrenzen stille Opens, und erschöpfte Kapazität schließt anschließend nur den betroffenen Stream.

Behandeln Sie eine Änderung von `base_path` im laufenden Betrieb als Migration einer Route mit Zugangsdaten. Geben Sie keine neuen alten Links mehr aus, bereiten Sie den neuen Link vor, drainen Sie betroffene Sitzungen soweit möglich, wenden Sie den Reload an, prüfen Sie die neue Route über den öffentlichen TLS-Endpunkt und verteilen Sie erst danach den neuen Link. Leiten Sie sowohl den alten als auch den neuen Frontend-Präfix weiterhin an Telemt, solange alte Capabilities oder Tokens eintreffen können; Telemt muss die zugangsdatenbewusste lokale Ablehnung durchführen. Ein vhost kann nicht gleichzeitig beide Basen akzeptieren. Ein echtes Überlappungsfenster erfordert einen zweiten Hostnamen/vhost und, falls derselbe Host erhalten bleiben muss, eine separate Prozess- oder Deployment-Grenze.

## Verwaltung über die API

WEB-Konfiguration, Runtime-Status und begrenzte Runtime-Steuerung verwenden denselben authentifizierten API-Listener. `/web-status` bleibt eine schreibgeschützte HTML-Diagnose; zustandsverändernde Operationen existieren ausschließlich unter `/v1/runtime/web`.

| Operation | API-Unterstützung |
| --- | --- |
| `[web]`, vhosts, Profile, Decoys, Timeouts oder Limits lesen oder ändern | Ja, über `GET` oder `PATCH /v1/config`. Der abgeleitete Snapshot `web.runtime` wird weder ausgegeben noch kann er geschrieben werden. Verschachtelte Tabellen werden feldweise zusammengeführt; Arrays ersetzen das bisherige Array vollständig. Änderungen an `web.allow_wildcard_hosts` und `[web.limits]` bleiben bis zum Prozessneustart zurückgestellt. Muster setzen einen bereits aktivierten Wildcard-Modus im laufenden Prozess voraus. |
| `server.listeners` speichern | Ja, über `PATCH /v1/config`; ein geänderter WEB-Listener bleibt jedoch bis zum Prozessneustart zurückgestellt. |
| Außerhalb der API geänderte WEB-Konfiguration anwenden | Ja, über `POST /v1/system/reload` und anschließende Abfrage des Vorgangsstatus. |
| Begrenzte serverseitige WEB-Request- und Lifecycle-Details untersuchen | Ja, über ein authentifiziertes `GET /web-status`. |
| Lifecycle, Kapazitätsebenen, Learning-/Debug-Zustand und aktive Sitzungen untersuchen | Ja, über `GET /v1/runtime/web/status` und `/v1/runtime/web/sessions`. |
| Ausgewählte aktive WEB-Sitzungen schließen | Ja, über die asynchrone Operation `POST /v1/runtime/web/sessions/close`. |
| Neue WEB-Arbeit pausieren, mit Deadline drainen oder fortsetzen | Ja, über `/v1/runtime/web/lifecycle/{pause,drain,resume}`. |
| Debug-Datensätze löschen oder Carrier-Learning zurücksetzen | Ja, über die entsprechenden Runtime-POST-Endpunkte. |
| `[access.users]` verwalten | Ja, über `/v1/users`. Das Erstellen eines Benutzers erzeugt kein WEB-Profil. |
| Einen Benutzer widerrufen | Ja. `/v1/users/{username}/disable` aktualisiert die Admission sofort und beendet die aktiven Sitzungen dieses Benutzers. |

Binden Sie die API an Loopback, halten Sie die Whitelist direkter Peers eng, konfigurieren Sie einen exakten Authorization-Header und verwenden Sie `read_only = false` nur dort, wo Mutationen erforderlich sind:

```toml
[server.api]
enabled = true
listen = "127.0.0.1:9091"
whitelist = ["127.0.0.0/8"]
auth_header = "Bearer replace-with-a-random-control-token"
read_only = false
```

Die API-Whitelist prüft den direkten TCP-Peer und vertraut `X-Forwarded-For` nicht. Änderungen an `[server.api]` selbst erfordern einen Prozessneustart.

### Runtime-Status und Steuerung

`GET /v1/runtime/web/status` liefert immer den veröffentlichten Ingress-Lifecycle (`starting`, `no_web_listener`, `running`, `draining`, `drained` oder `deadline_exceeded`), dessen Epoche und Alter, effektive Listener-Adressen und rückwärtskompatible Runtime-Verfügbarkeit. `ingress` meldet unabhängig konfigurierte Listener, aktive Acceptors, Accepting-Zustand, Accept-Summen und einen stabilen Grund. `capacity` meldet die effektive Policy für angenommene überlastete Sockets, feste Ressourcennutzung, momentane Sättigung, partielle Ebenen, typisierte Rejection-Entscheidungen und Overload-Ergebnisse. `decoy_upstream` meldet feste Ergebnisse und das Alter des letzten internen Origin-Ergebnisses. `decoy_fasttrack` meldet den effektiven, beim Neustart eingefrorenen Modus und die vollständige feste Dispositionsmenge auch bei nicht verfügbarer Runtime-Manager-Ebene. `carrier_negotiation` meldet stets feste Matrizen für Auswahl, vom Client gemeldete Fehler sowie terminale Health-/Learning-Ergebnisse aus Publication-Ownership. Solange die prozesseigene WEB-Runtime lebt, zeigt `operator_lifecycle` unabhängig `running`, `paused`, `draining`, `force_closing` oder `drained`, seine eigene Epoche und Admission-Flags sowie den aktiven oder letzten Drain. `runtime` ergänzt die zufällige 128-Bit-`runtime_instance`, die aktive Generation, unveränderliche Limits, ebenenlokale Kapazitätszähler, Carrier-Learning-/Debug-Epochen und Summen. Die Statuserfassung liest jede Ebene nicht blockierend: Eine umkämpfte Ebene wird ausgelassen und in `partial` benannt; der Endpunkt wartet nie auf die Datenebene, bereinigt sie nicht und verändert sie nicht.

Prometheus exportiert dieselben prozesseigenen Ebenen als `telemt_web_*`-Familien mit fester Kardinalität: One-Hot-Zustände für Ingress und Operator, Listener-/Accept-Zähler, Kapazitätsnutzung und -sättigung, typisierte terminale Ablehnungen, Ergebnisse überlasteter angenommener Sockets, interne Decoy-Origin-Ergebnisse sowie Session-/Stream-/Carrier-Summen. Das Decoy-Routing ergänzt `telemt_web_decoy_fasttrack_mode` als One-Hot-Gauge und `telemt_web_decoy_fasttrack_requests_total{disposition}` mit festen Dispositionen. Carrier-Negotiation verwendet `telemt_web_carrier_selections_total`, `telemt_web_carrier_reported_failures_total`, `telemt_web_carrier_learning_outcomes_total`, One-Hot-Gauges für Learning-Zustand und -Policy sowie Used-/Limit-Gauges für Einträge. Labels sind geschlossene Enums oder feste Ressourcennamen; Benutzer, Host, Client-IP, Token, Profilschlüssel, Runtime-Instanz, Listener-Adresse und Generation-ID werden nie zu Labels. Ein erfolgreicher `wait`-Ausgang erhöht keinen Rejection-Zähler.

`GET /v1/runtime/web/sessions` liefert standardmäßig höchstens 50 und bei gesetztem `limit` höchstens 200 Sitzungen. Der geordnete Scan ist auf 1000 Kandidaten begrenzt. `cursor` und `session_ref` verwenden die undurchsichtige kanonische Form `ws1.<runtime-instance>.<lowercase-hex-id>`; ein exakter `session_ref` darf nicht mit `cursor` oder `limit` kombiniert werden. Filter sind `ip`, `host`, `user`, `user_agent_id`, `key_id`, `carrier` und `state`; doppelte oder unbekannte Query-Felder werden abgelehnt. Der Detailpfad lautet `GET /v1/runtime/web/sessions/{session_ref}`. Ein gespeicherter Tombstone einer geschlossenen Sitzung ergibt `410`; ein umkämpfter exakter Snapshot ergibt `503 web_snapshot_busy`. Antworten enthalten nur begrenzte, nicht geheime Metadaten und niemals Bootstrap-/Session-Bearer, Capabilities, Secret-Hashes oder synthetische KDF-Ports.

Jeder Runtime-POST verlangt exakt `Content-Type: application/json`, lehnt unbekannte JSON-Felder ab, beachtet API-Authentifizierung, Whitelist und `read_only` und enthält die aktuelle `runtime_instance` als ABA-Sperre. Verfügbare Steuerungen:

- `POST /v1/runtime/web/lifecycle/pause` mit `{"runtime_instance":"..."}`. Nach einer linearisierbaren Fence blockiert dies neue Bootstrap-, Session-Inkarnations-, Ersatz- und Logical-Stream-Admission. Bestehende Carrier-Austauschvorgänge und Streams laufen weiter, exaktes Session-Replay bleibt verfügbar und Bridge-Ablehnung bleibt auf dem Decoy-Pfad.
- `POST /v1/runtime/web/lifecycle/drain` mit `{"runtime_instance":"...","timeout_secs":30}`. Die Antwort ist `202`; dieselbe Admission-Fence bleibt geschlossen, während asynchron auf Sitzungen, Streams und sessioneigene WebSockets gewartet wird. An der monotonen Deadline wird Close für alle verbleibenden aktiven Sitzungen signalisiert und bis zur bestätigten Null `force_closing` gemeldet. Natürlicher und erzwungener Abschluss bleiben bis zum Resume geschlossen. Ein zweiter gleichzeitiger Drain ergibt `409 web_lifecycle_in_progress`.
- `POST /v1/runtime/web/lifecycle/resume` mit `{"runtime_instance":"..."}`. Dies bricht einen aktiven Drain ab und öffnet ausschließlich die Operator-Admission. Wenn Forced Close bereits committed wurde, kann die alte Session-Cancellation nicht rückgängig gemacht werden. Config-, User-, Generation- und terminale Shutdown-Gates bleiben vorrangig.
- `POST /v1/runtime/web/sessions/close` mit genau einem Selektor: `{"kind":"refs","session_refs":[...]}`, `{"kind":"filter",...}` oder `{"kind":"all"}`. Exakte Referenzen sind auf 200 begrenzt, ein Filter darf nicht leer sein, nur eine Close-Operation darf laufen, und `all` wird abgelehnt, solange die effektive Ausgabe aktiviert ist. Die `202`-Antwort liefert `operation_id`; fragen Sie `GET /v1/runtime/web/operations/{operation_id}` ab. Die Operation scannt in Blöcken von 128 nur Sitzungen bis einschließlich ihres beim Start fixierten High-Water-Marks.
- `POST /v1/runtime/web/debug/clear` mit `{"runtime_instance":"..."}`. Die Antwort meldet gelöschte Datensätze, weiterhin von bereits gerenderten Snapshots gehaltene Bytes und die neue Epoche. Laufende Writer der alten Epoche können den Ring nicht erneut füllen.
- `POST /v1/runtime/web/carrier-learning/reset` mit derselben Body-Form. Der Endpunkt löscht gespeicherte prozesslokale Evidenz und erhöht die Learning-Epoche; bereits fixierte Versuchsketten und aktive Sitzungen bleiben unverändert.

Für ein deterministisches Close-all patchen Sie `{"web":{"enabled":false}}` mit aktiviertem Runtime-Reload, warten auf `runtime.manager.issuance_enabled = false`, senden den Selektor `all` mit derselben `runtime_instance` und fragen die Operation bis zu einem Endzustand ab. Das Deaktivieren von WEB stoppt neue Bootstrap-/Session-Ausgabe, schließt bestehende Sitzungen aber niemals implizit.

Der Operator-Lifecycle gilt nur für WEB und ändert weder globale Readiness und Liveness noch native TCP-/Unix-Listener, TLS-Fronting oder Fallback-Verhalten. Eine vor der Pause reservierte WebSocket-Lane ist bereits zugelassene logische Arbeit: Sie darf den Open-Vorgang abschließen und bleibt im Drain-Accounting enthalten. Lifecycle-Ablehnung verbraucht keine Rate-/Quota-Tokens und fügt dem Hot Path keinen Relay-Lock hinzu.

### Serverseitige WEB-Debug-Ansicht

Aktivieren Sie die begrenzte Erfassung in der zuständigen Konfigurationsdatei:

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

Öffnen Sie `http://127.0.0.1:9091/web-status` mit derselben Whitelist direkter Peers und demselben exakten `Authorization`-Header wie für die API. Ein abschließender Slash wird akzeptiert. Nur `GET` ist zulässig. Die Seite unterstützt die Filter `window_secs`, kanonische `ip`, numerische `session`, `user_agent` ohne Beachtung der Groß-/Kleinschreibung und `key`. Wiederholen Sie `group_by=ip`, `group_by=session`, `group_by=user_agent` oder `group_by=key`, um gruppierte Zusammenfassungen zu erstellen; `limit` ist auf `1..=1000` beschränkt. HTTP-Zeilen lassen sich vom Request bis zur Response zu Methode, Pfad, bereinigten Headern, Body-Metadaten oder -Bytes, Zeitpunkten, Frames und typisierten Lifecycle-Ereignissen einschließlich Carrier-Versuch, Commit, Healthy, gemeldetem Fehler, exaktem Close-Grund, Peer-Lücke und Übergängen des Vorgängers einer wiederhergestellten Sitzung aufklappen. Für WebSocket kommen der bereinigte Handshake `GET` → `101` sowie begrenzte Angaben pro Message zu Richtung, Message-Typ, Payload-/Body-Erfassung, Verarbeitungszeit, Verbindungs-/Lane-ID und geparsten inneren Frames hinzu. Rohe Subprotokolle und Session-Tokens werden nie gespeichert.

Der prozesseigene Ring übersteht den Austausch einer Runtime-Generation. Änderungen der Erfassungs-Policy löschen inkompatible gespeicherte Datensätze; reine Änderungen des Beobachtungsfensters tun dies nicht. Der Ring ist standardmäßig auf 65536 Datensätze und 64 MiB gespeicherte plus in Verarbeitung befindliche Daten begrenzt, die HTML-Response auf 8 MiB und die Gruppierung auf 1024 Gruppen; gleichzeitig dürfen höchstens zwei Response-Bodys Seiten-Permits halten. Ändern Sie `web.limits.debug_records_capacity` oder `web.limits.debug_bytes_global` nur zusammen mit einem Prozessneustart. Ein hot-reload-fähiger Präfix, der nur in eine gleichzeitig erhöhte neustartpflichtige Kapazität passt, wird bis zu diesem Neustart zurückgestellt.

`body_capture = "off"` lässt Bodys aus, `metadata` speichert Längen und Endzustände, `prefix` die konfigurierten Präfixe und `full` erkannte Carrier-Bodys bis `web.limits.max_body_bytes`. Gewöhnliche Decoy-Bodys bleiben auch in `full` auf `decoy_body_prefix_bytes` begrenzt. Queries und rohe Capabilities werden nie gespeichert; Werte von Credential-Headern werden ausgelassen; bekannte WEB-Capabilities und Bearer-Tokens werden aus erfassten Bodys entfernt; der angezeigte Schlüssel ist ein nicht geheimer, domänengetrennter Fingerprint. Die Zeitmessung endet beim Polling des Hyper-Bodys und behauptet weder einen Kernel-Flush noch eine TCP-Bestätigung.

Sideband-Berichte der generierten Bridge sind nur wirksam, wenn `enabled`, `capture_lifecycle` und `sideband` alle `true` sind. Die Policy ist hot-reload-fähig, aber nur neu ausgegebene Bridge-Seiten enthalten den Reporter. Jede Seite kann jedes der acht festen Ereignisse höchstens einmal melden: `runtime_started`, `status_posted`, `hello_received`, `boundary_timeout`, `hello_timeout`, `client_close_before_hello`, `document_unloaded_before_hello` und `runtime_error_before_hello`. Berichte sind exakte kanonische JSON-POSTs an `BASEapi/v1/diagnostic`, verwenden den Bootstrap-Bearer, ohne ihn zu verbrauchen, und nehmen nicht am Carrier-Framing teil. Fehlerhafte oder nicht authentifizierte Berichte folgen dem bereinigten Decoy-Pfad.

Nachdem ein Administrator oder Konfigurationssystem die TOML-Datei atomar aktualisiert hat, setzen Sie `TELEMT_API_AUTH` auf den exakten Wert von `auth_header` und starten Sie einen beobachtbaren Generations-Reload:

```bash
curl -sS -X POST http://127.0.0.1:9091/v1/system/reload \
  -H "Authorization: ${TELEMT_API_AUTH}" \
  -H 'Content-Type: application/json' \
  -d '{"mode":"drain","timeout_secs":30,"failure_policy":"rollback"}'

# Use data.reload_id from the response.
curl -sS http://127.0.0.1:9091/v1/system/reload/RELOAD_ID \
  -H "Authorization: ${TELEMT_API_AUTH}"
```

Der terminale Status `succeeded` bestätigt die Runtime-Aktivierung. Geänderte Carrier-, Kandidaten-, Deadline- oder Learning-Richtlinien werden von neu ausgegebenen Bridge-Sitzungen verwendet; bestehende Sitzungen und laufende Versuchsketten werden nicht migriert. Enthält `deferred_process_fields` den Wert `server.listeners`, `web.allow_wildcard_hosts` oder `web.limits`, ist die Datei gültig und gespeichert, diese Einstellungen erfordern aber weiterhin einen Telemt-Neustart.

Operationen für Access-Benutzer verwenden die vorhandenen Endpunkte, zum Beispiel:

```bash
curl -sS -X POST http://127.0.0.1:9091/v1/users/web-user/disable \
  -H "Authorization: ${TELEMT_API_AUTH}"

curl -sS -X POST http://127.0.0.1:9091/v1/users/web-user/rotate-secret \
  -H "Authorization: ${TELEMT_API_AUTH}" \
  -H 'Content-Type: application/json' \
  -d '{}'
```

Nach einer Secret-Rotation erstellt der Config-Watcher die WEB-Capabilities neu. Die Users-API liefert das Secret, aber keine `tg://webproxy`-URL. Erstellen Sie den Link mit dem konfigurierten Hostnamen und der `plain`- oder `dd`-Darstellung des Profils. Entfernen und aktivieren Sie vor dem Löschen eines Benutzers zuerst das WEB-Profil, das auf ihn verweist, damit die resultierende Konfiguration gültig bleibt.

Der vollständige Vertrag für Requests, Revisionen, Fehler und alle Benutzer-Endpunkte steht in der [Dokumentation der Control API](../Architecture/API/API.md).

## Bereitstellungsinvarianten

- Veröffentlichen Sie den unverschlüsselten HTTP-WEB-Listener niemals in einem nicht vertrauenswürdigen Netz. Erzwingen Sie diese Einschränkung auch bei einer Loopback-Bindung mit Host-Firewall-Regeln.
- Deaktivieren Sie am TLS-Terminator die Protokollierung von Request-Target und Authorization oder verwenden Sie ein geprüftes, redigiertes Format. Raw Queries enthalten Bridge-Capabilities und `Authorization` enthält Bootstrap- oder Session-Bearer-Zugangsdaten.
- Enthalten URI oder Header eine aktive Capability oder einen authentischen, vom aktuellen Prozess ausgegebenen Token, entspricht der Request aber nicht dem Carrier-Vertrag, weist Telemt ihn lokal ab. Solche Zugangsdaten werden nie an den Decoy weitergeleitet. Ein lediglich kanonisch aussehender gefälschter Wert bleibt gewöhnlicher Decoy-Datenverkehr.
- Verwenden Sie pro vhost eine stabile öffentliche Adresse. Wenn DNS mehrere Ingress-Adressen liefert, muss jede Bereitstellung die Adresse ihres externen Pfads verwenden.
- Bootstrap- und Session-Register sind prozesslokal. Ein Multi-Prozess- oder Multi-Host-Upstream-Pool benötigt Affinität für den vollständigen vhost: initialer und Recovery-Root-GET, Sitzungserstellung, Uplink, Downlink, WebSocket-Upgrade und DELETE. Ein einzelner Telemt-Prozess benötigt keine zusätzliche Affinität.
- Ein ungenutzter Bootstrap übersteht einen Konfigurations-Reload nur, wenn die exakte Profilidentität aktiv bleibt: Host, `public_addr`, Benutzer, Secret-Modus, Carrier-Kandidaten, Negotiation-Deadlines und Capability. Bereits erstellte Sitzungen behalten ihren unveränderlichen Carrier und ihre Profilidentität und bleiben lifecycle-bounded.
- Der Decoy gehört zum Anti-Probing-Vertrag. Prüfen Sie sein gewöhnliches 404-Verhalten und die Antwortzeiten über den öffentlichen TLS-Endpunkt, bevor Sie Links verteilen.

## Erstprüfung

1. Starten Sie das neu erstellte Telemt-Binary mit der WEB-Konfiguration und prüfen Sie, dass der private Listener gebunden ist.
2. Prüfen Sie über den öffentlichen TLS-Endpunkt, dass ein GET auf dem konfigurierten Basis-Root, der Alias ohne abschließenden Schrägstrich, ein unbekannter Pfad innerhalb dieser Basis und eine ungültige `bridge`-Query die beabsichtigte gewöhnliche Site oder den konfigurierten Decoy ohne synthetisierten Redirect zurückgeben. Prüfen Sie bei Prefix-only-Cohosting außerdem, dass der TLS-Terminator den Basispfad bytegenau beibehält.
3. Prüfen Sie, dass Telemt genau eine syntaktisch gültige `X-Forwarded-For`-Adresse und `Host: proxy.example.com` oder `Host: proxy.example.com:443` erhält.
4. Importieren Sie den ausgegebenen `tg://webproxy`-Link in den vorgesehenen Telegram-Desktop-Build und stellen Sie eine Proxy-Verbindung her.
5. Bestätigen Sie für `https-lanes`, dass die öffentliche Verbindung HTTP/2 ausgehandelt hat, und testen Sie mindestens zwei gleichzeitige logische Streams; der private Hop zu Telemt bleibt HTTP/1.1.
6. Bestätigen Sie für `websocket` eine `101`-Response, binären Relay-Datenverkehr und RFC-6455-Ping/Pong nach 25 Sekunden. Testen Sie für `websocket-lanes` mindestens zwei gleichzeitige Stream-Sockets und prüfen Sie, dass das Schließen oder Beschädigen einer Lane weder Geschwister noch die übergeordnete Sitzung schließt.
7. Testen Sie einen HTTP-Replay und eine Neuerstellung der Sitzung nach einer Scheduler-Lücke; halten Sie danach einen Long Poll länger als 25 Sekunden offen, um sicherzustellen, dass Frontend-Timeouts den Carrier nicht abbrechen.
8. Prüfen Sie Benutzer- und logische MTProxy-Verbindungslimits anhand der Logical-Stream-Zähler und nicht anhand der Zahl der HTTP-Verbindungen.
9. Prüfen Sie bei aktivierter Auto-Negotiation die konfigurierte Reihenfolge, das Replay exakt desselben Versuchs nach einer absichtlich verlorenen Response, das terminale Verhalten nach dem Commit sowie die Lifecycle-Zeilen `carrier_committed` und `carrier_healthy` in `/web-status`. Prüfen Sie, dass ein nativer Client ohne Metadaten den festen `carrier` ohne automatische Response-Header verwendet und explizite Capabilities unverändert bleiben.

## Fehlerbehebung

| Symptom | Prüfung |
| --- | --- |
| WEB-Konfiguration ist auf dem Datenträger gültig, aber das Listener-Verhalten hat sich nicht geändert | Prüfen Sie `deferred_process_fields`; Listener- und `web.allow_wildcard_hosts` / `[web.limits]`-Änderungen erfordern einen Neustart. |
| Carrier-Requests erreichen den Decoy | Prüfen Sie den exakten vhost, den Secret-Modus des Links, das CIDR des direkten Proxys und genau einen syntaktisch gültigen `X-Forwarded-For`-Wert. |
| Ein Link funktioniert nach einer Änderung von `base_path` nicht mehr | Importieren Sie den neu ausgegebenen Pfad-Link und prüfen Sie, dass das vollständige neue Präfix Telemt unverändert erreicht. Bestehende Sitzungen können sich nur über die neue exakte Basis wiederherstellen; alte Capabilities sind nicht wiederverwendbar. |
| `/telegram/web` leitet auf `/telegram/web/` um | Fügen Sie für den Pfad ohne Schrägstrich einen exakten Non-WEB-Handler hinzu. Nur der mit Schrägstrich abgeschlossene konfigurierte Teilbaum gehört zum WEB-Vertrag von Telemt. |
| Ein konkurrierender `https-lanes`-Downlink erreicht den Decoy mit `404` | Prüfen Sie, dass er mit `X-Down-Cursor: 0` beginnt, bewahren Sie `X-Lane-ID` und setzen Sie `lane_open_wait_secs` über den beobachteten Abstand zwischen Downlink und `OPEN`. Fortgeschrittene Cursor fehlender Lanes schlagen absichtlich fail-closed fehl. |
| Auto-Negotiation wechselt weiter, nachdem Daten bereits akzeptiert wurden | Das ist ungültig. Prüfen Sie das authentifizierte `X-Carrier-State`-Replay und das Carrier-Commit-Lifecycle-Ereignis; `committed` oder `healthy` ist terminal und erfordert eine neue Sitzung. |
| Long Polls werden nach einem festen Intervall getrennt | Setzen Sie Client-, Server-, Sende- und Lese-Timeouts von NGINX/HAProxy/Caddy über `web.timeouts.long_poll_secs`. |
| WebSocket-Upgrade erreicht statt `101` den Decoy | Bewahren Sie HTTP/1.1 `Connection: Upgrade`, `Upgrade: websocket`, das einzelne exakte `Sec-WebSocket-Protocol` und den kanonischen bodylosen Request an der konfigurierten Basis plus `/api/v1/ws`. Prüfen Sie außerdem Carrier-/Session-Kompatibilität und die Prozess-Verbindungsreserve. |
| Ein `websocket-lanes`-Stream wurde geschlossen, Geschwister bleiben aber verbunden | Dies ist die beabsichtigte Fehlergrenze. Prüfen Sie die Message-/Frame-Zeilen dieser Lane in `/web-status`; fehlerhafte oder lane-fremde Frames, Write-Timeouts und Backend-Close schließen nur die betroffene Lane. |
| `/web-status` ist leer | Prüfen Sie, dass `[web.debug].enabled = true` gesetzt ist, wenden Sie die Konfiguration an, wählen Sie ein Fenster innerhalb von `max_window_secs` und erzeugen Sie nach der Policy-Änderung neuen WEB-Datenverkehr. |
| `https-lanes` funktioniert, Streams blockieren sich aber weiterhin | Prüfen Sie die öffentliche HTTP/2-Aushandlung, die unveränderte Weitergabe von `X-Lane-ID` und genügend TLS-Terminator-Upstream-Verbindungen für parallele private HTTP/1.1-Polls. |
| Telegram Desktop lehnt den Link ab | Lassen Sie den Port weg und verwenden Sie einen gültigen FQDN, extern Port 443 sowie ausschließlich `plain` oder `dd`. |
| Ein Knoten funktioniert, ein Load-Balancing-Pool aber nur sporadisch | Konfigurieren Sie Affinität für den gesamten vhost; WEB-Zugangsdatenregister sind prozesslokal. |
