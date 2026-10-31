# Ping in der Proxyliste: RPC Ping/Pong und WEB-Latenz

[English](PROXY_PING.en.md) | [Русский](PROXY_PING.ru.md) | [Deutsch](PROXY_PING.de.md)

Die beobachteten **1000–1500 ms für WEB gegenüber 50–150 ms für Classic/DD/EE** können auf unterschiedlichen Messgrenzen beruhen. Bei der WEB-Prüfung unter Android ist der lokale Socket bereits bereit, bevor der entfernte WEB-Stream zwingend bereit ist. Der verbleibende Streamaufbau und die Übertragung können deshalb in den angezeigten Wert eingehen. Der Code schreibt keinen festen Zuschlag von einer Sekunde für jeden erfolgreichen WEB-Ping vor.

Diese Zahlen stammen aus Betreiberbeobachtungen und wurden für dieses Dokument nicht reproduziert. Die Quellcodeanalyse belegt Mechanismen, aber nicht die Ursache einer Verzögerung in einer bestimmten Installation.

## Clients und Messungen

Geprüft am **2026-10-31** anhand von DrKLO Android `3de37c8cfb039452be7398909461da6288babf15` und Telegram iOS `279f89e4d4f63f17227bf877dc3d8990f22ecd58`. Installierte Versionen und Forks können abweichen.

| Messung | Erfasster Bereich | Verhalten bei WEB |
| --- | --- | --- |
| Ping in der Android-Proxyliste | Verschlüsseltes MTProto `TL_ping` / `TL_pong` über den geprüften Proxy | Separater WEB-Testtransport, anschließend native Prüfung über einen lokalen Socket. |
| Ping in der iOS-Proxyliste | Erreichbarkeitsprüfung mit `req_pq` / `resPQ`; Messbeginn bei `connectionOpened` | `.web`-Einträge sind von der Ping-Prüfung ausgeschlossen; ein inaktiver WEB-Eintrag erscheint als nicht getestet. |
| ICMP-Ping | IP-Echo zum gewählten Host unter den jeweiligen ICMP-Routingregeln | Misst weder die Anwendungsweiterleitung noch das Telegram-DC. |
| WEB-Transport `FRAME_PING` / `FRAME_PONG` oder WebSocket-Keepalive | Erreichbarkeit des Transports bzw. der Sitzung | Nicht das in Android angezeigte MTProto-Ergebnis. |
| Telemt ME RPC Ping/Pong | Ein Writer-Pfad von Telemt zum ME einschließlich lokaler Warteschlange und Flush-Planung | Ohne Client, WebView und öffentliches TLS-Frontend. |

Quellen: [Android-Einstieg][android-entry], [native Anfragen][android-native], [iOS-Filter][ios-filter], [iOS-Prüfung][ios-probe], [iOS-Oberfläche][ios-ui]. Die Android-Formel für WEB-Ping lässt sich somit nicht auf den WEB-Eintrag im geprüften iOS übertragen.

Android zeigt das letzte Prüfergebnis ohne Median oder EMA an und überspringt eine erneute Prüfung, wenn die vorherige weniger als zwei Minuten zurückliegt. Auch ein verbundener Proxy kann diesen gespeicherten Wert anzeigen: Er ist keine laufende RTT-Messung der aktiven Sitzung. Die WEB-Prüfung erstellt einen eigenen Transport, statt den aktiven Anwendungstransport direkt wiederzuverwenden. Siehe [Aktualisierung der Proxyliste][android-ui] und [WEB-Transport][android-transport].

## Beginn und Ende der Android-Messung

Bei Classic/DD/EE erfolgt der native Bereitschafts-Callback nach dem entfernten TCP-Verbindungsaufbau und der erforderlichen Einrichtung des Proxytransports, einschließlich EE FakeTLS. Die Anfrageverarbeitung aktualisiert den Zeitstempel vor dem Senden bzw. erneuten Senden der Prüfung. Die übliche erfolgreiche Messung schließt diesen anfänglichen Transportaufbau daher aus, erfasst aber die anschließende Weiterleitung und den Rückweg. Siehe [Socket-Bereitschaft][android-socket] und [Anfrageverarbeitung][android-native].

Bei WEB liegen der Bridge-Start, das anfängliche Laden über HTTPS, HELLO/WELCOME und weitere **500 ms** Wartezeit vor `native_checkProxy`; diese Wartezeit wird nicht zum angezeigten Ping addiert. WELCOME bestätigt eine WEB-Sitzung, keinen bereiten Stream zum Telegram-DC. Anschließend verbindet sich die native Prüfung mit `127.0.0.1`. Dessen Bereitschaft wartet nicht auf den Abschluss des entfernten OPEN. Java-Accept/OPEN und die Aktualisierung des nativen Zeitstempels können in unterschiedlicher Reihenfolge erfolgen. Nur die innerhalb des Messintervalls noch ausstehende Arbeit trägt zum Ergebnis bei. Siehe [Prüfablauf][android-tester], [lokaler Socket und WELCOME][android-transport], [serverseitige Sitzungserstellung][session] und [Stream-Backend][backend].

Die Diagramme zeigen den üblichen erfolgreichen Ablauf, garantieren jedoch keine threadübergreifende Ereignisreihenfolge:

```mermaid
sequenceDiagram
    participant C as Android native checker
    participant P as Classic/DD/EE proxy
    participant D as Telegram DC
    C->>P: DNS / TCP / proxy transport setup
    Note over C,P: Remote transport ready, measurement timestamp refreshed
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
    Note over C,B: Local socket ready, measurement timestamp refreshed
    Note over B,T: OPEN may race with the native timestamp update
    C->>B: MTProxy header and encrypted TL_ping
    B->>T: OPEN / DATA over selected carrier
    T->>D: Stream setup and relay via Direct / ME
    D->>T: TL_pong
    T->>B: Downlink DATA
    B->>C: Local socket delivery
    Note over C: Display elapsed time from latest request timestamp
```

`TL_pong` beendet die Messung relativ zum letzten Anfragezeitstempel. Erzwungene Verarbeitung oder erneutes Senden können diesen zurücksetzen. Der angezeigte Wert entspricht daher nicht zwingend der gesamten Dauer eines fehlgeschlagenen oder wiederholten Versuchs. Die Prüfung verwendet einen [vorhandenen DC-Autorisierungsschlüssel][android-key]; ein vollständiger Austausch zur Erstellung eines neuen MTProto-Schlüssels gehört nicht obligatorisch zu jeder Prüfung.

## Einfluss von TLS

Die öffentliche TLS-Verbindung endet bei NGINX, HAProxy oder Caddy. Telemt empfängt unverschlüsseltes HTTP/1.1 am privaten Listener. Öffentliches HTTP/2 und internes HTTP/1.1 sind getrennte Verbindungen; ihre Protokollversionen müssen nicht übereinstimmen. EE FakeTLS ist ein MTProxy-Tarntransport, nicht die HTTPS-Verbindung des Browsers mit Zertifikatsprüfung. WEB transportiert plain/DD-MTProxy; EE ist kein WEB-Secret-Format. Siehe [WEB-Betriebsanleitung](WEB_PROXY.de.md).

Bei einer neuen Verbindung ohne Paketverlust benötigt der übliche TCP-Handshake ungefähr einen RTT zwischen Client und Frontend. Ein vollständiger TLS-1.3-Handshake fügt normalerweise einen RTT hinzu, ein vollständiger TLS-1.2-Handshake zwei. Das sind Schätzungen der Protokollrunden ohne DNS, Verarbeitung, Zertifikatsprüfung, Scheduling und erneute Übertragungen, kein gemessenes WEB-Latenzbudget. Sitzungswiederaufnahme kann den Ablauf verändern. Siehe [TLS 1.3][tls13] und [TLS 1.2][tls12].

Das anfängliche TLS für die Bridge liegt normalerweise vor der Android-Messung. Zusätzliche HTTP-Verbindungen oder ein WebSocket-Upgrade können noch innerhalb des Intervalls stattfinden; Verbindungswiederverwendung muss anhand eines Traces belegt werden. Persistente HTTPS-Verbindungen und bestehende WebSockets führen nicht für jeden Ping einen neuen TLS-Handshake aus. `cache: 'no-store'` steuert Caching, nicht die Wiederverwendung von TCP/TLS. Weder das Abschalten der Zertifikatsprüfung noch TLS 0-RTT ist zur Erklärung oder Diagnose erforderlich. Siehe [persistente HTTP-Verbindungen][http1] und [Bridge-Anfragen][request].

## Zusätzliche Arbeit bei WEB gegenüber nativem MTProxy

Die Darstellung trennt Arbeit vor dem Android-Timer von Arbeit, die in den angezeigten Wert eingehen kann. Als Basis dient Classic/DD über TCP. Bei EE gehört FakeTLS zum Aufbau des nativen Transports. Die Größe der Kästen und die Länge der Pfeile stellen keine Zeitdauer dar.

```mermaid
flowchart LR
    subgraph N["Natives MTProxy: Classic/DD"]
        direction TB
        N0["Vor der Messung<br/>DNS + TCP + nativer Transportaufbau"] --> N1["Entfernter Transport bereit<br/>Anfragezeitstempel aktualisiert"]
        N1 --> N2["MTProxy-Anfrage und Antwort<br/>Ausstehender Relay-Aufbau, Netzwerk, Warteschlangen, Telegram-DC"] --> N3["TL_pong empfangen<br/>Angezeigte Messung beendet"]
    end
    subgraph W["WEB: MTProxy in HTTPS oder WebSocket"]
        direction TB
        W0["Vor der Messung<br/>DNS + TCP + echtes TLS<br/>HTTP-Bridge + HELLO/WELCOME + 500 ms"] --> W1["Lokaler Socket bereit<br/>Anfragezeitstempel aktualisiert"]
        W1 --> W2["Zusätzliche Client-Arbeit<br/>Java / WebView / JavaScript-Warteschlangen<br/>Entferntes OPEN eventuell noch ausstehend"] --> W3["Uplink-Verarbeitung<br/>HTTP-Upload oder WebSocket-Frame<br/>Frontend-Verarbeitung und mögliche Pufferung"]
        W3 --> W4["Innere MTProxy-Anfrage und Antwort<br/>Ausstehender Relay-Aufbau, Netzwerk, Warteschlangen, Telegram-DC"] --> W5["Downlink-Verarbeitung<br/>HTTP-Poll oder WebSocket-Frame<br/>ACK/Commit-Freigabe und native Zustellwarteschlangen"]
        W5 --> W6["TL_pong empfangen<br/>Angezeigte Messung beendet"]
        X["Nur wenn eine weitere Verbindung nötig ist<br/>TCP + TLS, eventuell WebSocket-Upgrade<br/>Kein Handshake pro Ping bei Wiederverwendung"] -.-> W3
        X -.-> W5
        R["Nur bei Fehlern oder Überlastung<br/>Retries und Backoff<br/>Retry-After: 1 kann etwa eine Sekunde hinzufügen"] -.-> W3
        R -.-> W5
    end
    classDef preparation fill:#eeeeee,stroke:#666666,color:#111111
    classDef boundary fill:#dbeafe,stroke:#2563eb,color:#111111
    classDef shared fill:#dcfce7,stroke:#15803d,color:#111111
    classDef extra fill:#ffedd5,stroke:#c2410c,color:#111111
    class N0,W0 preparation
    class N1,N3,W1,W6 boundary
    class N2,W4 shared
    class W2,W3,W5,X,R extra
```

**Grau:** Arbeit vor der angezeigten Messung. **Blau:** Timer-Grenzen. **Grün:** MTProxy-Relay/DC-Arbeit in beiden Pfaden, deren tatsächliche Dauer abweichen kann. **Orange:** WEB-Transport- und Client-Arbeit innerhalb der Messung. **Gestrichelte Pfeile:** bedingter Verbindungsaufbau oder Retries, keine obligatorischen Phasen.

Bei Wiederverwendung des Carriers entfällt der bedingte TCP/TLS/Upgrade-Aufwand. Framing, HTTP- oder WebSocket-Verarbeitung und Client-Warteschlangen bleiben bestehen. HTTP kann Up- und Downlink überlappen, sodass nicht jede Anfrage zwingend einen ganzen RTT hinzufügt. Polling wird bei verfügbaren Daten geweckt, und Frontend-Pufferung hängt von der Installation ab. Paketverlust, Netzwerküberlastung und Upstream-Aufbau können auch natives MTProxy verzögern.

Die sichtbare Differenz kann somit verbleibenden WEB-Streamaufbau, zusätzliche Verbindungen, Transportverarbeitung und Scheduling sowie belegte Retries enthalten. Sie ist weder ein fester TLS-Zuschlag noch die arithmetische Summe aller Kästen. Der erste echte TLS-Handshake steht bewusst vor dem Android-Timer: Er beeinflusst die Gesamtdauer der Prüfung, normalerweise aber nicht den angezeigten Messwert. Da die Prüfung einen separaten Transport verwendet, garantiert eine aktive App-Verbindung auch keine warme Prüfung in der Proxyliste.

## Beispielhafte Zeitleiste mit ungefähren Dauern

**Ein Erklärungsmodell, kein Benchmark und kein erwarteter Latenzbereich.** Die Zahlen sollen das Zusammenspiel der Phasen zeigen. Sie rekonstruieren nicht die beobachteten 1000–1500 ms. Annahmen: DNS ist bereits zwischengespeichert, der RTT zwischen Client und Frontend beträgt 40 ms, die TCP-Verbindung ist neu, bei Bedarf erfolgt ein vollständiger TLS-1.3-Handshake, ein DC-Autorisierungsschlüssel ist vorhanden, und es gibt weder Paketverlust noch ein Zurücksetzen des nativen Anfragezeitstempels. Als Basis dient Classic/DD. Bei EE kommt der eigene FakeTLS-Aufbau vor dem nativen Timer hinzu.

In diesem Beispiel benötigt natives MTProxy 40 ms Vorbereitung für TCP. Die WEB-Vorbereitung dauert 750 ms: 50 ms Client-/Bridge-Start + 40 ms TCP + 40 ms TLS + 120 ms HTTP-Austausch für Bridge und Sitzung + 500 ms Wartezeit des Android-Checkers. Hier werden aufeinanderfolgende Dauern angenommen; reale Phasen können überlappen. Das anfängliche TLS und die 500 ms Wartezeit liegen außerhalb des angezeigten Pings.

Die Darstellung beginnt beim **letzten Anfragezeitstempel** der jeweiligen Prüfung, nicht beim App-Start oder ersten Verbindungsversuch. Die horizontale Achse zeigt Sekunden mit Millisekundengenauigkeit (0.200 = 200 ms). Die Balkenbreite ist proportional zur Dauer. Jeder Abschnitt ist ein separates Szenario; seine Phasen folgen aufeinander und laufen nicht parallel. Die anfängliche Vorbereitung liegt außerhalb der Darstellung.

```mermaid
%%{init: {"theme": "neutral", "gantt": {"leftPadding": 200, "rightPadding": 100, "barHeight": 24, "barGap": 8, "fontSize": 14, "sectionFontSize": 14}}}%%
gantt
    dateFormat x
    axisFormat %S.%L
    tickInterval 200millisecond
    todayMarker off
    title Angezeigter Ping - Beispielmodell
    accTitle: Angezeigter Ping - Beispielmodell
    accDescr: Sekunden seit Anfragezeitstempel, Beschriftungen in Millisekunden
    section Classic/DD - 100 ms
    R 100 ms :n_r, 0, 100ms
    section WEB ohne Fehler - 200 ms
    U 40 ms :w_u, 0, 40ms
    R 100 ms :w_r, after w_u, 100ms
    D 60 ms :w_d, after w_r, 60ms
    section WEB mit Retry - 1240 ms
    F 40 ms :crit, f_u, 0, 40ms
    Warten 1000 ms :crit, retry_wait, after f_u, 1000ms
    U 40 ms :retry_u, after retry_wait, 40ms
    R 100 ms :retry_r, after retry_u, 100ms
    D 60 ms :retry_d, after retry_r, 60ms
```

Dauer der einzelnen Phasen: `R` = 100 ms grundlegende MTProxy-Relay-/Netzwerk-/DC-Arbeit für Anfrage und Antwort. `U` = 40 ms zusätzliche WEB-Uplink-/OPEN-/Client-Arbeit. `D` = 60 ms zusätzliche WEB-Downlink-/Zustellarbeit. `F` = 40 ms für einen fehlgeschlagenen Upload-Versuch. `Warten` = 1000 ms Wartezeit gemäß `Retry-After: 1`. `U` und `D` sind beispielhafte Zusatzkosten gegenüber `R`, keine erneute Anrechnung des gesamten Netzwerk-RTT. Die ACK/Commit-Freigabe wird nur berücksichtigt, soweit sie die Zustellung tatsächlich verzögert.

| Szenario | Vor dem Ping-Timer | Angezeigter Ping | Gesamtdauer der Prüfung im Modell |
| --- | --- | --- | --- |
| Classic/DD | 40 ms | 100 ms | 140 ms |
| WEB ohne Fehler | 750 ms | 40 + 100 + 60 = 200 ms | 950 ms |
| WEB mit einem fehlgeschlagenen Upload und einer Retry-Pause | 750 ms | 40 + 1000 + 40 + 100 + 60 = 1240 ms | 1990 ms |

Eine weitere TCP- und TLS-1.3-Verbindung **innerhalb** der Messung könnte hier bei vollständig sequenziellem Ablauf ungefähr 80 ms hinzufügen: Aus 200 ms würden 280 ms. Bei Verbindungswiederverwendung entfällt dieser zusätzliche Handshake-Aufwand. Ein anfänglicher vollständiger TLS-1.2- statt TLS-1.3-Handshake verlängert unter diesen Annahmen die Vorbereitung um etwa 40 ms, nicht den angezeigten Ping. Die Beispiele lassen TLS-Verarbeitung, Sitzungswiederaufnahme und Paketverlust unberücksichtigt.

Die Zeile mit 1240 ms zeigt einen möglichen Mechanismus für einen Sekundenwert: einen durch HTTP-Traces belegten Retry. Sie beweist nicht, dass Retries die ursprüngliche Beobachtung verursacht haben. Ohne einen solchen Retry müssen andere tatsächlich gemessene Verzögerungen lokalisiert werden, etwa Warteschlangen, Frontend-Pufferung, Verbindungsaufbau oder Upstream-Arbeit. Timeouts dürfen nicht als Wartepausen eingesetzt und überlappende Phasen nicht ungeprüft in dieses sequenzielle Modell übertragen werden.

## HTTP, WebSocket und weitere Verzögerungen

| Faktor | Auswirkung und Beleg |
| --- | --- |
| HTTP-Uplink | Die generierte Bridge bietet `X-Telemt-Up-Window: 4` an; der Server akzeptiert 1–4, ohne Aushandlung gilt 1. Fenster 1 wartet vor dem nächsten Upload auf ein ACK; Fenster 4 erlaubt begrenzte Parallelität. Nicht jeder HTTP-Pfad arbeitet nach Stop-and-Wait. Siehe [Aushandlung][runtime] und [Sitzungshandler][session]. |
| Erster Downlink | `/down` kann gleichzeitig mit `/up` starten; es gibt keinen obligatorischen zusätzlichen sequenziellen ACK-RTT. Die erste Zustellung an den nativen Client wartet auf das erste gültige Upload-ACK/Commit. Frames werden schrittweise zugestellt. Siehe [Conveyor][conveyor] und [Downlink][downlink]. |
| Long Polling | `long_poll_secs=25` begrenzt das Warten ohne Daten. Verfügbare Daten wecken den Poll sofort. Lücken zwischen Polls oder belegte Browser-Verbindungsslots können die Zustellung dennoch verzögern. Siehe [serverseitiges Polling][poll]. |
| Gemeinsame Transportressourcen | `https` teilt eine Upload-Warteschlange; `https-lanes` trennt logische Lanes. WebSocket überträgt nach dem Upgrade Frames ohne POST pro Frame; `websocket-lanes` trennt Sockets. Netzwerk, Flow Control und WebView-Ressourcen bleiben gemeinsam genutzt. HTTP/2 multiplexiert Streams, beseitigt aber nicht alle Verzögerungen durch Überlastung und Flow Control. Siehe [HTTP/2][http2] und [Transportanleitung](WEB_PROXY.de.md). |
| Frontend-Pufferung | Pufferung von Anfragen/Antworten oder fehlende Streaming-/Upgrade-Unterstützung kann kleine Nachrichten verzögern. Mit dem bestehenden NGINX-Beispiel vergleichen; Routing, Authentifizierung und Limits beibehalten. |
| Client-Scheduling | Java-Accept/Read-Threads, UI-Dispatch, WebView/JavaScript und die Rückgabe an nativen Code erzeugen Warteschlangen. CPU-Last, mobiles Energiesparen und Netzwechsel können dies verstärken. |
| Weiterleitung und Netzwerk | Verbleibende Stream-Zulassung, innerer MTProxy-Handshake, Direct-Verbindungsaufbau oder ME-Registrierung, Telegram-Antwort, Paketverluste/Wiederholungen und Warteschlangen können beitragen. Eine bereite WEB-Sitzung belegt keinen bereiten Upstream. |
| Fehler und Wiederholungen | Telemt kann `503` mit `Retry-After: 1` zurückgeben. Die Bridge berücksichtigt dies; sonstiges Retry-Backoff beginnt bei 250 ms und verdoppelt sich bis 2000 ms zuzüglich bis zu ungefähr 25% Jitter, innerhalb des Retry-Budgets. Wiederholbare HTTP-Statuscodes umfassen 408/429/502/503/504. Ein Trace muss solche Ereignisse zeigen, bevor eine Sekundenstufe darauf zurückgeführt wird. Siehe [Antworten][response] und [Retry-Logik][request]. |

Fristen sind keine obligatorischen Pausen. Die Standardwerte von 10 s für Bridge-Anfragen, 90 s Retry-Budget, 30 s bis zum ersten Stream-Byte und 10 s für den Stream-Handshake dürfen nicht zum normalen Ping addiert werden. `carrier_probe_coalesce_ms=0` deaktiviert diese optionale Verzögerung zur Zusammenfassung von Probes. Carrier-Fallback-Fristen betreffen fehlgeschlagene Versuche, nicht jeden erfolgreichen Austausch. Siehe [Standardwerte](../../src/config/types/web/defaults.rs).

Vereinfacht umfasst eine WEB-Messung **verbleibenden Aufbau + Transport-/Netzwerkübertragung + Warteschlangen + Telegram-Antwort + Retry-Pausen innerhalb des Timers**. Die Phasen überlappen; alle Timeouts zu addieren oder jedem HTTP-Endpunkt einen eigenen RTT zuzuordnen wäre falsch. Bereite Carrier können Aufbaukosten reduzieren, die Android-Proxyprüfung verwendet jedoch weiterhin einen separaten Transport. WebSocket ist nicht grundsätzlich schneller; nur vom tatsächlichen Client unterstützte Carrier verwenden. Die aktuelle iOS-Kompatibilitätskonfiguration nutzt `https`.

## Diagnose unter Beibehaltung der Schutzmechanismen

1. Client/Build, Android-WebView-Version, Carrier, öffentlichen Endpunkt, IP-Familie, Netzwerk, Direct/ME-Route, DC und Last erfassen. Unter gleichen Bedingungen vergleichen. Den zwei Minuten lang gespeicherten Android-Wert beachten: Wiederholtes Ablesen liefert keine neuen Messungen.
2. Drei Experimente unterscheiden: neue Prüfung in der Proxyliste; neuer logischer Stream auf einem bereiten Carrier; Anwendungs-RPC in einer bestehenden MTProto-Sitzung. Die letzten beiden benötigen geeignete Client-Instrumentierung und werden nicht automatisch von der Proxyliste bereitgestellt. Einzelwerte und Verteilungen erfassen, statt einen kalten mit einem warmen Einzelwert zu vergleichen.
3. Das authentifizierte `GET /web-status` und vorhandene `[web.debug]`-Einstellungen mit `capture_timings=true`, `capture_frames=true`, `body_capture="metadata"` verwenden. Begrenzte Erfassung gemäß [WEB-Diagnoseanleitung](WEB_PROXY.de.md) aktivieren und danach den vorherigen Zustand wiederherstellen. Payloads, Capabilities und Secrets sind hierfür unnötig.
4. Sitzungserstellung, Carrier-Auswahl/Commit/Fehler, `stream_admitted`, `stream_first_byte`, `handshake_succeeded`, OPEN/DATA, HTTP-Statuscodes und Retries korrelieren. `relay_started` liegt vor der Upstream-Arbeit und ist kein DC-Bereitschaftszeitpunkt. `GET /v1/runtime/web/status` und `GET /v1/runtime/web/sessions` liefern Kapazitäts- und Warteschlangenkontext, keinen Ende-zu-Ende-RTT.
5. `request_body_us`, `response_ready_us` und `response_body_us` sind Zeitabstände seit Eintritt in den Service. Sie sind weder unabhängige, zu addierende Dauern noch Zeitpunkte eines Netzwerk-Flushs oder TCP-ACKs der Gegenstelle. Nur vorhandene und sinnvoll vergleichbare Werte gegenüberstellen. Siehe [Timing-Definitionen][timings].
6. Verbindungs-/TLS-/Anfragezeiten des Frontends und Client-Zeitstempel ergänzen, um Verzögerungen außerhalb von Telemt zu lokalisieren. Wiederverwendung von Verbindungen, ausgehandelte HTTP-Version, Pufferung und Upgrade prüfen. Sideband-Ereignisse zum Bridge-Start/HELLO ergeben keine vollständige Client-Zeitleiste. Für Vergleiche zwischen Hosts Uhren synchronisieren oder lokale Dauern verwenden.
7. Bei ME den vorhandenen Trace `ME RTT sample` (`rtt_ms`, `ema_ms`, `base_ms`, `degraded`) vergleichen. Der Zeitstempel liegt vor Writer-Warteschlange/Flush; die EMA besteht aus 80% vorherigem Wert und 20% neuer Messung. Keepalive-Scheduling vor diesem Zeitstempel ist ausgeschlossen. Ein niedriger ME-Wert bei hohem Android-Ping weist auf Arbeit außerhalb dieses ME-Messbereichs hin, benennt aber keine konkrete Ursache. Siehe [Writer][writer] und [Reader][reader].

Interpretationsbeispiele: Schnelle Telemt-Verarbeitung bei später Client-Zustellung lenkt die Untersuchung auf Frontend, Netzwerk und Client-Warteschlangen; `503` mit `Retry-After: 1` belegt eine Retry-Pause; lange Upstream-Arbeit erfordert eine Direct/ME-Untersuchung. Keines dieser Muster beweist allein, dass TLS-Kryptografie 1000–1500 ms verursacht. Kompatibilität, Zertifikatsprüfung, Zulassungslimits und Backpressure während der Untersuchung beibehalten.

## Grenzen der Belege

Dieses Dokument beschreibt geprüften Quellcode, keinen Ende-zu-Ende-Gerätebenchmark. Android-/iOS-Links verweisen auf die genannten festen Revisionen; Telemt-Links auf die begleitende Implementierung im Arbeitsverzeichnis einschließlich lokaler WEB-Änderungen. Daraus folgt keine Gleichheit aller veröffentlichten Pakete. Die Dokumentation ändert weder Client noch Server, Timeouts oder Sicherheitseinstellungen.

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
