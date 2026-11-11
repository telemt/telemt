# Telemt command-line guide

[English](CLI.en.md) · [Русский](CLI.ru.md) · [Deutsch](CLI.de.md) · [Documentation](README.en.md)

This guide describes the CLI in this checkout. Check `telemt --version` and `telemt --help` for the installed binary. Put options before the final configuration path; without a path, Telemt uses `config.toml` in the working directory.

## Run and manage a process

```bash
telemt run --log-level normal /etc/telemt/telemt.toml
```

`run` is optional. Under systemd or in a container, keep the process in the foreground and use the service manager to start, stop and restart it. On Unix, Telemt also supports its own daemon mode:

```bash
telemt start --pid-file /run/telemt/telemt.pid /etc/telemt/telemt.toml
telemt status --pid-file /run/telemt/telemt.pid
telemt reload --pid-file /run/telemt/telemt.pid
telemt stop --pid-file /run/telemt/telemt.pid
```

Use the same PID-file path for all commands and ensure its directory exists with appropriate ownership. `status` checks the process recorded in that file; it does not test proxy readiness. `reload` sends SIGHUP to the configuration watcher. Exit code `0` confirms signal delivery, not successful application of every setting. Check logs and the [configuration application rules](Config_params/CONFIG_PARAMS.en.md#applying-configuration-changes). A generation reload through `POST /v1/system/reload` and a process restart are separate operations.

`stop` sends SIGTERM and waits up to about ten seconds for PID-file cleanup. A successful signal can still return `0` while shutdown continues; check process status if subsequent work requires it to have exited.

| Option | Meaning |
| --- | --- |
| `--daemon`, `-d` | Enable Unix daemon mode; `start` also selects it. |
| `--foreground`, `-f` | Keep execution in the foreground. |
| `--pid-file PATH` | PID file shared with `status`, `reload` and `stop`. |
| `--run-as-user USER`, `--run-as-group GROUP` | Select the account and group for the Unix process. |
| `--working-dir PATH` | Working directory for the Unix process. Prefer an absolute configuration path. |
| `--strict-runtime-paths` | Apply stricter checks to runtime paths; use consistently for daemon control. |

## Health checks

```bash
telemt healthcheck --mode liveness /etc/telemt/telemt.toml
telemt healthcheck --mode ready /etc/telemt/telemt.toml
```

`liveness` is the default and probes `GET /v1/health`. `ready` probes `GET /v1/health/ready` and requires `data.ready = true`. Both require HTTP `200` and `ok = true`; liveness additionally requires `data.status = "ok"`.

The command reads the API address and authorization value from the supplied configuration. Wildcard listen addresses are probed through loopback. Run it where that address is reachable and permitted by the API whitelist. It does not open an MTProxy session or verify the complete client-to-Telegram path.

**If `server.api.enabled = false`, the command exits with `0` without a network probe.** Enable the API before treating this command as evidence of liveness or readiness. Exit code `1` means configuration/probe failure; invalid or missing `--mode` values return `2`. Connect, read and write operations have two-second timeouts; this is not a single two-second deadline for the whole command.

## Logging

| Option | Meaning |
| --- | --- |
| `--log-level LEVEL` | `debug`, `verbose`, `normal` or `silent`. |
| `--silent`, `-s` | Suppress informational logging. |
| `--syslog` | Send logs to syslog on supported Unix systems. |
| `--log-file PATH` | Write logs to a file. |
| `--log-file-daily PATH` | Enable file logging with daily rotation. |
| `--log-rotation MODE` | `never`, `minutely`, `hourly`, `daily` or `weekly`. |
| `--log-max-size-bytes N` | File size threshold for rotation. |
| `--log-max-files N` | Retained file count limit. |
| `--log-max-age-secs N` | Retained file age limit in seconds. |

`RUST_LOG` takes precedence over log-level settings. CLI logging options override their configuration counterparts. See [logging configuration](Config_params/CONFIG_PARAMS.en.md#logging) for path, rotation and retention semantics; file and syslog outputs are mutually exclusive.

## Generate an initial installation

`--init` writes configuration and service files and can start the service. It is an installation operation, not a configuration validator; running it again can regenerate existing files. Review and back up an existing installation first.

```bash
telemt --init --port 443 --domain example.com --user alice --config-dir /etc/telemt --no-start
```

Use separate option values as shown. Defaults are port `443`, domain `www.google.com`, user `user`, and directory `/etc/telemt`. `--secret HEX` supplies a 32-hex-digit user secret; omitting it generates one. `--no-start` prevents starting the service but still writes installation files. These defaults differ from those of `install.sh`; do not confuse the two installers.

For API automation, see the [Control API](Architecture/API/API.md) and [Python client and CLI](Architecture/API/PYTHON_CLIENT.md). The Python tool is separate from the `telemt` executable described here.
