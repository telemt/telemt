# Telemt auf der Kommandozeile

[English](CLI.en.md) · [Русский](CLI.ru.md) · [Deutsch](CLI.de.md) · [Dokumentation](README.de.md)

Dieses Handbuch beschreibt die CLI des vorliegenden Quellstands. Prüfen Sie die installierte Version mit `telemt --version` und `telemt --help`. Geben Sie zuerst die Optionen und zuletzt den Konfigurationspfad an. Ohne Pfad verwendet Telemt `config.toml` im Arbeitsverzeichnis.

## Prozess starten und verwalten

```bash
telemt run --log-level normal /etc/telemt/telemt.toml
```

`run` kann entfallen. Unter systemd oder in einem Container sollte der Prozess im Vordergrund laufen; Start, Stopp und Neustart übernimmt die Dienstverwaltung. Unter Unix unterstützt Telemt auch einen eigenen Daemon-Modus:

```bash
telemt start --pid-file /run/telemt/telemt.pid /etc/telemt/telemt.toml
telemt status --pid-file /run/telemt/telemt.pid
telemt reload --pid-file /run/telemt/telemt.pid
telemt stop --pid-file /run/telemt/telemt.pid
```

Verwenden Sie bei allen Befehlen dieselbe PID-Datei. Ihr Verzeichnis muss vorhanden sein und geeignete Eigentümerrechte haben. `status` prüft den dort verzeichneten Prozess, nicht die Betriebsbereitschaft des Proxys. `reload` sendet SIGHUP an die Konfigurationsüberwachung. Rückgabecode `0` bestätigt die Signalzustellung, nicht die Übernahme aller Einstellungen. Prüfen Sie das Protokoll und die [Regeln zur Konfigurationsübernahme](Config_params/CONFIG_PARAMS.de.md#konfigurationsänderungen-anwenden). Ein Generationswechsel über `POST /v1/system/reload` und ein Prozessneustart sind eigene Vorgänge.

`stop` sendet SIGTERM und wartet bis zu etwa zehn Sekunden auf das Entfernen der PID-Datei. Nach erfolgreicher Signalzustellung kann der Befehl `0` zurückgeben, obwohl der Prozess noch beendet wird. Prüfen Sie den Prozessstatus, wenn der nächste Schritt einen vollständig beendeten Prozess voraussetzt.

| Option | Bedeutung |
| --- | --- |
| `--daemon`, `-d` | Unix-Daemon-Modus; auch `start` aktiviert ihn. |
| `--foreground`, `-f` | Prozess im Vordergrund ausführen. |
| `--pid-file PATH` | Gemeinsame PID-Datei für Start, `status`, `reload` und `stop`. |
| `--run-as-user USER`, `--run-as-group GROUP` | Benutzer und Gruppe des Unix-Prozesses. |
| `--working-dir PATH` | Arbeitsverzeichnis des Unix-Prozesses. Ein absoluter Konfigurationspfad ist vorzuziehen. |
| `--strict-runtime-paths` | Strengere Prüfung der Laufzeitpfade; bei Start und Daemon-Steuerung einheitlich verwenden. |

## Funktionsprüfung

```bash
telemt healthcheck --mode liveness /etc/telemt/telemt.toml
telemt healthcheck --mode ready /etc/telemt/telemt.toml
```

`liveness` ist der Standardmodus und ruft `GET /v1/health` auf. `ready` ruft `GET /v1/health/ready` auf und verlangt `data.ready = true`. Beide erwarten HTTP `200` und `ok = true`; liveness verlangt zusätzlich `data.status = "ok"`.

Der Befehl liest API-Adresse und Autorisierungswert aus der angegebenen Konfiguration. Bind-Adressen für alle Schnittstellen werden über Loopback geprüft. Führen Sie den Befehl dort aus, wo die Adresse erreichbar und durch die API-Zugriffsliste zugelassen ist. Er öffnet keine MTProxy-Sitzung und prüft nicht den vollständigen Weg vom Client zu Telegram.

**Bei `server.api.enabled = false` endet der Befehl mit `0`, ohne eine Netzwerkanfrage zu senden.** Aktivieren Sie die API, bevor Sie das Ergebnis als Nachweis der Erreichbarkeit oder Bereitschaft verwenden. Rückgabecode `1` bedeutet einen Konfigurations- oder Prüffehler; ein ungültiger oder fehlender Wert für `--mode` ergibt `2`. Verbindungsaufbau, Lesen und Schreiben haben jeweils ein Zeitlimit von zwei Sekunden. Das ist keine gemeinsame Frist von zwei Sekunden für den gesamten Befehl.

## Protokollierung

| Option | Bedeutung |
| --- | --- |
| `--log-level LEVEL` | Stufe: `debug`, `verbose`, `normal` oder `silent`. |
| `--silent`, `-s` | Informationsmeldungen unterdrücken. |
| `--syslog` | Protokolle auf unterstützten Unix-Systemen an syslog senden. |
| `--log-file PATH` | In eine Datei schreiben. |
| `--log-file-daily PATH` | Dateiprotokollierung mit täglicher Rotation. |
| `--log-rotation MODE` | `never`, `minutely`, `hourly`, `daily` oder `weekly`. |
| `--log-max-size-bytes N` | Dateigröße als Schwelle für die Rotation. |
| `--log-max-files N` | Höchstzahl aufzubewahrender Dateien. |
| `--log-max-age-secs N` | Höchstalter aufzubewahrender Dateien in Sekunden. |

`RUST_LOG` hat Vorrang vor den Einstellungen der Protokollstufe. CLI-Optionen überschreiben die entsprechenden Konfigurationswerte. Pfade, Rotation und Aufbewahrung erklärt die [Referenz zur Protokollierung](Config_params/CONFIG_PARAMS.de.md#logging). Dateiausgabe und syslog schließen einander aus.

## Erstinstallation erzeugen

`--init` schreibt Konfigurations- und Dienstdateien und kann den Dienst starten. Es handelt sich um eine Installation, nicht um eine Konfigurationsprüfung; ein erneuter Aufruf kann vorhandene Dateien neu erzeugen. Prüfen und sichern Sie deshalb zuerst eine bestehende Installation.

```bash
telemt --init --port 443 --domain example.com --user alice --config-dir /etc/telemt --no-start
```

Übergeben Sie Optionswerte getrennt vom Optionsnamen, wie im Beispiel. Standardwerte sind Port `443`, Domain `www.google.com`, Benutzer `user` und Verzeichnis `/etc/telemt`. `--secret HEX` setzt ein Benutzergeheimnis aus 32 Hexadezimalzeichen; ohne diese Option wird eines erzeugt. `--no-start` verhindert den Dienststart, schreibt aber weiterhin die Installationsdateien. Diese Standardwerte unterscheiden sich von `install.sh`; die beiden Installationswege sind getrennt zu betrachten.

Zur API-Automatisierung dienen die englischen Referenzen für die [Control API](Architecture/API/API.md) und den [Python-Client mit CLI](Architecture/API/PYTHON_CLIENT.md). Das Python-Werkzeug ist vom hier beschriebenen Programm `telemt` unabhängig.
