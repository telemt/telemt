# Python Control API client and CLI

[tools/telemt_api.py](../../../tools/telemt_api.py) provides a Python 3.10+
standard-library client. No third-party package is required. Import
`TelemtAPI` from `tools.telemt_api` when running from the repository, or add the
`tools` directory to your Python import path and import from `telemt_api`.
The CLI parser lives in
[tools/telemt_api_cli.py](../../../tools/telemt_api_cli.py); keep both files
together when copying the tool.

```bash
python3 tools/telemt_api.py help
python3 tools/telemt_api.py --url http://127.0.0.1:9091 --auth 'Bearer synthetic-demo' capabilities --json-output
python3 tools/telemt_api.py config-state --sections general,access,web --json-output
```

The authorization value is exact, including any `Bearer ` prefix configured by
the operator. Global `--url`, `--auth`, `--timeout`, `--if-match`, and
`--json-output` may appear before or after a command. `--timeout` is the socket
timeout in seconds and defaults to 10; preflight can need a larger value because
its server work budget is 30 seconds. Authentication applies independently to
each request, including polling after a reload.

Default output retains human-readable user/create/delete output and prints
other payloads as JSON followed by revision/status metadata. `--json-output`
prints one JSON object containing `ok`, `data`, `revision`, and `http_status`.
`http_status` belongs to the client wrapper, not the server's JSON envelope.
The state endpoint can have `revision=null` while returning an effective
snapshot and a bounded desired-source error.

## Commands and methods

Existing statistics commands retain their names: `health`, `info`, `status`,
`init`, `limits`, `posture`, `whitelist`, `summary`, `zero`, `upstreams`,
`minimal`, `me-writers`, `dcs`, `me-pool`, `me-quality`, `upstream-quality`,
`nat-stun`, `me-selftest`, `connections`, and `events --limit N`.

| CLI | Python method | Contract |
| --- | --- | --- |
| `ready` | `health_ready()` | `200` ready or `503` readiness data; CLI exits 1 when not ready. |
| `capabilities` | `capabilities()` | Supported routes, feature gates and mutation availability. |
| `schema` | `config_schema()` | Types, defaults, sensitivity, exposure and apply policy. |
| `config` | `get_config()` | Desired editable config, including `web`; administratively sensitive. |
| `config-state [--sections general,web]` | `config_state(["general", "web"])` | Redacted desired/effective state and owner observations. |
| `validate --json FILE` | `validate_config(patch, ...)` | Candidate preparation without persistence/publication. |
| `config-patch --json FILE [--reload instant] [--wait]` | `patch_config(patch, ...)` | Exact sparse patch, optional reload policy, source/runtime preconditions. |
| `reload [--mode instant] [--wait]` | `reload(mode, ...)` | Submit generation reload; default failure policy is server-owned `keep_new`. |
| `reload-status ID` | `reload_status(id)` | Read one retained operation. |
| `reload-wait ID [--expected-revision REV]` | `wait_reload(id, ...)` | Poll to `succeeded`, `failed` or `rolled_back`. |
| `users`, `user NAME` | `list_users()`, `get_user(name)` | User/link responses can carry provisioning secrets. |
| `create NAME`, `patch NAME`, `delete NAME` | `create_user()`, `patch_user()`, `delete_user()` | Existing convenience methods and command names remain available. |
| `patch NAME --json FILE` or `--clear FIELD` | `patch_user_fields(name, fields)` | Exact omitted/null/value semantics. |
| `secret NAME [--secret HEX]` | `rotate_secret(name, ...)` | Implemented rotation endpoint, not a reserved route. |
| `enable NAME`, `disable NAME` | `enable_user()`, `disable_user()` | User admission controls with optional `If-Match`. |
| `reset-quota NAME` | `reset_user_quota()` | Durable quota reset; preserves the recurring boundary contract. |
| `quota` | `users_quota()` | Desired quota/period and effective recurring schedule/counters. |
| `active-ips` | `users_active_ips()` | Current per-user IP observations. |
| `tls-fingerprints [--limit N]` | `runtime_tls_fingerprints(limit)` | `1..1000`, subject to runtime-edge availability. |
| `web-status` | `web_status()` | Runtime identity, availability and operator lifecycle. |
| `web-sessions [FILTERS]` | `web_sessions(...)` | One bounded page; caller follows `next_cursor`. |
| `web-session REF` | `web_session(ref)` | Live `200` or retained closed `410` tombstone. |
| `web-close --runtime-instance INSTANCE --selector FILE [--wait]` | `web_close_sessions(instance, selector)` | Exact `refs`, nonempty `filter`, or `all` selector. |
| `web-operation ID`, `web-wait ID` | `web_operation(id)`, `wait_web_operation(id)` | Read/poll the process-scoped close operation. |
| `web-debug-clear --runtime-instance INSTANCE` | `web_debug_clear(instance)` | Clears retained debug records. |
| `web-learning-reset --runtime-instance INSTANCE` | `web_learning_reset(instance)` | Resets process-owned carrier learning. |
| `web-pause --runtime-instance INSTANCE` | `web_pause(instance)` | Stops admission of new WEB work. |
| `web-drain --runtime-instance INSTANCE --timeout-secs N [--wait]` | `web_drain(instance, seconds)` | Starts one bounded server drain, returns `202`. |
| `web-drain-wait ID --runtime-instance INSTANCE` | `wait_web_drain(instance, id)` | Polls the same drain through WEB status. |
| `web-resume --runtime-instance INSTANCE` | `web_resume(instance)` | Resumes operator admission subject to other policy gates. |
| `gen-secret` | `TelemtAPI.generate_secret()` | Generates a new 32-hex secret locally. |

The client covers all 51 JSON operations in the operation catalog. Open the
HTML `/web-status` viewer in a browser; it is not decoded as a JSON response.
Feature gates and missing runtime planes still return the server's documented
errors. Discovery availability is a snapshot, not a reservation.

## Sparse values and user updates

`create`/`patch` accept `--secret`, `--ad-tag`, `--max-conns`, `--expires`,
`--quota`, `--max-ips`, `--quota-period daily|weekly|monthly`, `--rate-up`,
`--rate-down`, and mutually exclusive `--enabled`/`--disabled`. Rate units are
bytes per second. A zero or false option is transmitted explicitly.

For backward compatibility, `patch_user(..., field=None)` continues to omit that
convenience argument. Use `patch_user_fields` or CLI JSON/`--clear` to transmit
null. The exact method does not alter the supplied dictionary:

```python
from tools.telemt_api import TelemtAPI

api = TelemtAPI("http://127.0.0.1:9091", auth_header="Bearer synthetic-demo")
api.patch_user_fields("alice", {
    "quota_period": None,
    "rate_limit_up_bps": 0,
    "enabled": False,
}, if_match="synthetic-source-revision")
```

For user fields, omission preserves the setting and null removes its override;
`enabled=null` restores the default enabled state. `secret=null` is ignored,
so the CLI excludes `secret` from `--clear`. Removing a quota or recurring period
still follows server validation and durable scheduling rules. `--json` cannot
be combined with field options/`--clear`; conflicting set/clear options fail
before any HTTP request.

```bash
python3 tools/telemt_api.py patch alice --quota 0 --disabled
python3 tools/telemt_api.py patch alice --clear quota_period --clear rate_limit_up_bps
printf '%s\n' '{"quota_period":null,"enabled":false}' | python3 tools/telemt_api.py patch alice --json -
```

Rotation returns the new raw credential, cancels owners tied to the old
credential identity and relies on asynchronous owner/watcher work for subsequent
publication. `UserInfo.in_runtime` only tests username membership. It does not
prove that a new credential or quota period has reached every consumer. Use
`config_state()` and `users_quota()` to inspect the corresponding evidence.

## Config preparation, ownership and reload

Config objects merge sparsely, arrays replace the complete array, and nested
object null members are ignored by the server. These semantics differ from
user PATCH nulls. In particular, `web.vhosts` is already editable and is replaced
as an array; fetch and retain the complete desired array before changing an entry.

`network.dns_overrides` accepts the same array replacement contract through
`validate_config`/`patch_config` and CLI JSON input. For example,
`{"network":{"dns_overrides":["upstream.example:443:192.0.2.10"]}}` replaces the
list, and `{"network":{"dns_overrides":[]}}` clears it. Other `network` fields
remain rejected. PATCH without a reload query leaves publication to the existing
watcher; it does not wait for the resolver update or move established connections.
See [DNS overrides](API.md#dns-overrides) for limits and source ownership.

State projections are inspection DTOs and must not be used as PATCH bodies.

`If-Match` fences the recursive desired-source revision. `If-Runtime-Match`
fences the active publication and is accepted by config preflight/PATCH only.
Both quoted and unquoted values are passed through unchanged. A patch must be
owned by one independently writable source; a cross-include edit can fail with
`409 config_patch_not_atomic`. The client preserves the server's error details
and does not split a rejected edit into partial commits.

```python
patch = {"general": {"log_level": "debug"}}
preview = api.validate_config(patch, reload="drain", timeout_secs=30,
                              failure_policy="rollback")
result = api.patch_config(
    patch,
    if_match=preview.data["base_revision"],
    if_runtime_match=preview.data["runtime"]["runtime_match"],
    reload="drain", timeout_secs=30, failure_policy="rollback",
)
accepted = result.data.get("reload")
if accepted:
    final = api.wait_reload(accepted["reload_id"],
                            expected_revision=accepted["config_revision"], timeout=60)
    if final.data["state"] != "succeeded":
        raise RuntimeError("Reload did not succeed")
```

`restart_required` is the legacy watcher classification;
`runtime_reload_required` describes differences requiring runtime activation;
`process_restart_required` identifies fields retained until process restart.
Do not reduce these flags to one generic restart action. A successful preflight
does not guarantee future binding, unchanged external resources, or consumer
convergence. `published_match` in state describes selected snapshot equality;
`subsystem_convergence` can remain `unknown`.

`--reload drain`/`--mode drain` requires `--timeout-secs 1..3600`; instant forbids
that option. `--failure-policy` is `keep_new` or `rollback`. Config preflight and
PATCH accept those query options; direct reload sends the corresponding JSON
body. Process-only patches can return no reload operation even with `--wait`.
For the CLI examples below, save the sparse config object as `patch.json` and
replace the synthetic preconditions with the tokens returned by preflight.

```bash
python3 tools/telemt_api.py --timeout 35 validate --json patch.json --json-output
python3 tools/telemt_api.py config-patch --json patch.json --if-match synthetic-source-revision --if-runtime-match synthetic-publication-token --reload drain --timeout-secs 30 --failure-policy rollback --wait
python3 tools/telemt_api.py reload --mode instant --wait --wait-timeout 60
```

Polling uses a monotonic budget (`--wait-timeout`, default 60) and a positive
interval (`--poll-interval`, default 0.25). Each request's socket timeout is capped
by the remaining budget; urllib's timeout is a socket wait limit, not a hard
end-to-end deadline against a peer that continuously streams bytes. Polling
only reads status. A timeout raises `TelemtAPIError(code="poll_timeout")` with
`last_response`, and does not cancel or resubmit the server operation. A normal
transport failure remains a transport error and is not retried automatically.

Library waiters return terminal `failed`, `rolled_back`, or `cancelled` data so
callers can inspect it. CLI wait/status commands exit 1 for those terminal
failures, 0 for a successful response/terminal result, and 2 for invalid local
input. Readiness false exits 1; a readable WEB tombstone exits 0. `202` without
`--wait` means the request was accepted, not that the operation completed.

Reload IDs are process-local. `expected_revision` detects a different source
target, but cannot distinguish all ID reuse after process restart with identical
source bytes. WEB identifiers already carry a process reference and are handled
as described below.

## WEB process references and bounded queries

Read `web_status().data["runtime"]["runtime_instance"]` and pass that exact
reference to WEB controls. Copy `session_ref`/`operation_id` unchanged from
server responses. The client never substitutes a fresh runtime reference after
`409 web_runtime_mismatch`; re-evaluate operator intent before submitting work
to a new process.

```python
status = api.web_status()
instance = status.data["runtime"]["runtime_instance"]
page = api.web_sessions(limit=25, user="alice")
refs = [row["session_ref"] for row in page.data["sessions"]]
if refs:
    close = api.web_close_sessions(instance, {"kind": "refs", "session_refs": refs})
    done = api.wait_web_operation(close.data["operation_id"])

drain = api.web_drain(instance, 30)
drain_id = drain.data["drain"]["operation_id"]
finished = api.wait_web_drain(instance, drain_id, timeout=60)
```

Enumeration defaults to 50 rows and accepts `limit=1..200`. `session_ref` is
mutually exclusive with `cursor`/`limit`. Filters are `ip`, `host`, `user`,
`user_agent_id`, `key_id`, `carrier`, and `state`; the
[API reference](API.md#web-session-enumeration) defines their exact formatting
and length limits. Query values are URL-encoded individually. The client does
not auto-page an unbounded session list. `refs` closes 1..200 unique references;
`filter` requires a non-null filter; `all` remains subject to the server's
issuance-disabled gate.

Every WEB POST sends exactly `Content-Type: application/json`, no query, and a
JSON object with the caller's process reference. The client caps these bodies
at 64 KiB; the configured server body limit can be lower. A close waiter stops
at `completed`, `cancelled`, or `failed`. A drain waiter reads WEB status until
the same drain is `completed` or `cancelled`, preserving `force_closing` as a
pending phase; a changed/missing process or drain fails with
`operation_mismatch`.

## Errors and credential exposure

`TelemtAPIError` exposes `code`, `http_status`, `request_id`, `details`, and an
optional `last_response` for polling diagnostics. JSON success envelopes with
HTTP `503` readiness or `410` tombstone are accepted only by those dedicated
methods. Other error envelopes raise, including feature-gate and stale-process
failures. CLI errors go to stderr with field details and request correlation.

For peers outside the API whitelist, `gray_action="drop"` closes without HTTP,
`"api"` returns structured `403 forbidden`, and `"200"` returns an empty
`200 OK`. An empty/non-JSON body raises `invalid_response`; it is never reported
as a successful mutation. Allowed peers still undergo authentication and
read-only checks.

Config GET, user lists, creation and rotation may reveal credentials or
credential-bearing links. Their library/CLI outputs retain the server contract;
`--json-output` does not redact them. Use the redacted state endpoint for
inspection where appropriate. All credentials and references in this guide
are synthetic examples.

Run the local mock HTTP and CLI contract suite from the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tools/tests -v
python3 tools/generate_api_openapi.py --check
```

These checks need no live proxy, Telegram connection or deployment credentials.
