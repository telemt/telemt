"""Argument parsing and output for the standard-library Control API client."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

if __package__:
    from .telemt_api import TelemtAPI, TelemtAPIError, USER_FIELDS, _positive_seconds
else:
    from telemt_api import TelemtAPI, TelemtAPIError, USER_FIELDS, _positive_seconds


READ_COMMANDS = {
    "health": "health", "ready": "health_ready", "capabilities": "capabilities",
    "schema": "config_schema", "config": "get_config", "info": "system_info",
    "status": "runtime_gates", "init": "runtime_initialization", "limits": "limits_effective",
    "posture": "security_posture", "whitelist": "security_whitelist", "summary": "stats_summary",
    "zero": "stats_zero_all", "upstreams": "stats_upstreams", "minimal": "stats_minimal_all",
    "me-writers": "stats_me_writers", "dcs": "stats_dcs", "me-pool": "runtime_me_pool_state",
    "me-quality": "runtime_me_quality", "upstream-quality": "runtime_upstream_quality",
    "nat-stun": "runtime_nat_stun", "me-selftest": "runtime_me_selftest",
    "connections": "runtime_connections_summary", "users": "list_users",
    "quota": "users_quota", "active-ips": "users_active_ips", "web-status": "web_status",
}
USER_OPTIONS = {
    "--secret": ("secret", str), "--ad-tag": ("user_ad_tag", str),
    "--max-conns": ("max_tcp_conns", int), "--expires": ("expiration_rfc3339", str),
    "--quota": ("data_quota_bytes", int), "--max-ips": ("max_unique_ips", int),
    "--quota-period": ("quota_period", str), "--rate-up": ("rate_limit_up_bps", int),
    "--rate-down": ("rate_limit_down_bps", int),
}


def _seconds(value):
    try:
        return _positive_seconds(float(value), "timeout/interval")
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def _poll_args(parser, optional=False):
    if optional:
        parser.add_argument("--wait", action="store_true", help="Poll this accepted operation to a terminal state")
    parser.add_argument("--wait-timeout", type=_seconds, default=60, help="Polling budget in seconds (default: 60)")
    parser.add_argument("--poll-interval", type=_seconds, default=0.25)


def _reload_args(parser, submission=False):
    parser.add_argument("--mode" if submission else "--reload", choices=("instant", "drain"),
                        default="instant" if submission else None)
    parser.add_argument("--timeout-secs", type=int, help="Server drain deadline, 1..3600; forbidden for instant")
    parser.add_argument("--failure-policy", choices=("keep_new", "rollback"))


def build_parser():
    # SUPPRESS lets common options appear before or after a command without a
    # subparser default overwriting a value already supplied to the root parser.
    common = argparse.ArgumentParser(add_help=False, argument_default=argparse.SUPPRESS)
    common.add_argument("-u", "--url", help="API base URL (default: http://127.0.0.1:9091)")
    common.add_argument("-a", "--auth", help="Exact Authorization header value")
    common.add_argument("-t", "--timeout", type=_seconds, help="Socket timeout in seconds (default: 10)")
    common.add_argument("--if-match", help="Optional source revision for mutations/preflight")
    common.add_argument("--json-output", action="store_true", help="Print one JSON envelope including http_status")
    parser = argparse.ArgumentParser(prog="telemt_api.py", parents=[common],
        description="Telemt Control API CLI. JSON input uses a file or '-' for stdin.",
        epilog="Config/user outputs may contain credentials. See docs/Architecture/API/PYTHON_CLIENT.md.")
    commands = parser.add_subparsers(dest="command")
    def command(name, **options):
        return commands.add_parser(name, parents=[common], **options)
    command("help", help="Show available commands")
    command("gen-secret", help="Generate a new 32-hex secret locally")
    for name, method in READ_COMMANDS.items():
        command(name, help=method.replace("_", " "))
    for name in ("events", "tls-fingerprints"):
        command(name).add_argument("--limit", type=int)
    command("config-state").add_argument("--sections", help="Comma-separated section names; omission selects all")
    for name in ("config-patch", "validate"):
        sub = command(name)
        sub.add_argument("--json", required=True, metavar="FILE", help="Sparse config object; '-' reads stdin")
        sub.add_argument("--if-runtime-match", help="Publication token from state or preflight")
        _reload_args(sub)
        if name == "config-patch":
            _poll_args(sub, optional=True)
    sub = command("reload")
    _reload_args(sub, submission=True)
    _poll_args(sub, optional=True)
    for name in ("reload-status", "reload-wait"):
        sub = command(name)
        sub.add_argument("reload_id", type=int)
        if name == "reload-wait":
            _poll_args(sub)
            sub.add_argument("--expected-revision", help="Accepted operation's config_revision")
    for name in ("user", "create", "patch", "delete", "secret", "enable", "disable", "reset-quota"):
        sub = command(name)
        sub.add_argument("username")
        if name in ("create", "patch"):
            for option, (field, kind) in USER_OPTIONS.items():
                sub.add_argument(option, dest=field, type=kind, default=argparse.SUPPRESS,
                                 **({"choices": ("daily", "weekly", "monthly")} if field == "quota_period" else {}))
            enabled = sub.add_mutually_exclusive_group()
            enabled.add_argument("--enabled", dest="enabled", action="store_const", const=True, default=argparse.SUPPRESS)
            enabled.add_argument("--disabled", dest="enabled", action="store_const", const=False, default=argparse.SUPPRESS)
        if name == "patch":
            sub.add_argument("--json", metavar="FILE", help="Exact sparse object; cannot be combined with field options")
            sub.add_argument("--clear", action="append", choices=sorted(USER_FIELDS - {"secret"}), default=[],
                             help="Send JSON null for one field (repeatable)")
        if name == "secret":
            sub.add_argument("--secret", help="32 hex characters; omission asks the server to generate a secret")
    sub = command("web-sessions")
    sub.add_argument("--limit", type=int)
    for name in ("cursor", "session-ref", "ip", "host", "user", "user-agent-id", "key-id", "carrier", "state"):
        sub.add_argument("--" + name)
    command("web-session").add_argument("session_ref")
    for name in ("web-operation", "web-wait", "web-drain-wait"):
        sub = command(name)
        sub.add_argument("operation_id")
        if name != "web-operation":
            _poll_args(sub)
        if name == "web-drain-wait":
            sub.add_argument("--runtime-instance", required=True)
    for name in ("web-close", "web-debug-clear", "web-learning-reset", "web-pause", "web-drain", "web-resume"):
        sub = command(name)
        sub.add_argument("--runtime-instance", required=True, help="Exact process reference copied from WEB status")
        if name == "web-close":
            sub.add_argument("--selector", required=True, metavar="FILE", help="refs/filter/all selector JSON, or '-' for stdin")
            _poll_args(sub, optional=True)
        if name == "web-drain":
            sub.add_argument("--timeout-secs", required=True, type=int)
            _poll_args(sub, optional=True)
    return parser


def _json_file(path):
    data = json.loads(sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("JSON input must be an object")
    return data


def _response_field(response, *keys):
    value = response.data
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            raise TelemtAPIError("Missing operation metadata", code="invalid_response", last_response=response)
        value = value[key]
    return value


def _wait_reload(api, response, accepted, options):
    if not isinstance(accepted, dict) or not isinstance(accepted.get("config_revision"), str) or isinstance(accepted.get("reload_id"), bool) or not isinstance(accepted.get("reload_id"), int):
        raise TelemtAPIError("Invalid accepted reload metadata", code="invalid_response", last_response=response)
    return api.wait_reload(accepted["reload_id"], expected_revision=accepted["config_revision"], **options)


def _dispatch(api, args):
    command = args.command
    revision = getattr(args, "if_match", None)
    wait_options = {"timeout": getattr(args, "wait_timeout", 60), "poll_interval": getattr(args, "poll_interval", 0.25)}
    if command in READ_COMMANDS:
        return getattr(api, READ_COMMANDS[command])()
    if command in ("events", "tls-fingerprints"):
        method = api.runtime_events_recent if command == "events" else api.runtime_tls_fingerprints
        return method(args.limit)
    if command == "config-state":
        return api.config_state(args.sections.split(",") if args.sections is not None else None)
    if command in ("config-patch", "validate"):
        method = api.patch_config if command == "config-patch" else api.validate_config
        response = method(_json_file(args.json), if_match=revision, if_runtime_match=args.if_runtime_match,
                          reload=args.reload, timeout_secs=args.timeout_secs, failure_policy=args.failure_policy)
        accepted = response.data.get("reload") if isinstance(response.data, dict) else None
        if getattr(args, "wait", False) and accepted:
            return _wait_reload(api, response, accepted, wait_options)
        if getattr(args, "wait", False) and response.http_status == 202:
            raise TelemtAPIError("Accepted config patch lacks reload metadata", code="invalid_response", last_response=response)
        return response
    if command == "reload":
        response = api.reload(args.mode, timeout_secs=args.timeout_secs, failure_policy=args.failure_policy, if_match=revision)
        if args.wait:
            return _wait_reload(api, response, response.data, wait_options)
        return response
    if command == "reload-status":
        return api.reload_status(args.reload_id)
    if command == "reload-wait":
        return api.wait_reload(args.reload_id, expected_revision=args.expected_revision, **wait_options)
    if command == "user":
        return api.get_user(args.username)
    if command in ("create", "patch"):
        fields = {key: value for key, value in vars(args).items() if key in USER_FIELDS}
        if command == "create":
            return api.create_user(args.username, if_match=revision, **fields)
        if args.json:
            if fields or args.clear:
                raise ValueError("--json cannot be combined with user field options or --clear")
            fields = _json_file(args.json)
        else:
            for name in args.clear:
                if name in fields:
                    raise ValueError("A field cannot be set and cleared together or cleared twice")
                fields[name] = None
        return api.patch_user_fields(args.username, fields, if_match=revision)
    if command in ("delete", "enable", "disable", "reset-quota", "secret"):
        method = {"delete": api.delete_user, "enable": api.enable_user, "disable": api.disable_user,
                  "reset-quota": api.reset_user_quota, "secret": api.rotate_secret}[command]
        return method(args.username, if_match=revision, **({"secret": args.secret} if command == "secret" else {}))
    if command == "web-sessions":
        return api.web_sessions(**{key: getattr(args, key) for key in
            ("limit", "cursor", "session_ref", "ip", "host", "user", "user_agent_id", "key_id", "carrier", "state")})
    if command == "web-session":
        return api.web_session(args.session_ref)
    if command == "web-operation":
        return api.web_operation(args.operation_id)
    if command == "web-wait":
        return api.wait_web_operation(args.operation_id, **wait_options)
    if command == "web-drain-wait":
        return api.wait_web_drain(args.runtime_instance, args.operation_id, **wait_options)
    if command == "web-close":
        response = api.web_close_sessions(args.runtime_instance, _json_file(args.selector))
        return api.wait_web_operation(_response_field(response, "operation_id"), **wait_options) if args.wait else response
    if command == "web-drain":
        response = api.web_drain(args.runtime_instance, args.timeout_secs)
        return api.wait_web_drain(args.runtime_instance, _response_field(response, "drain", "operation_id"), **wait_options) if args.wait else response
    method = {"web-debug-clear": api.web_debug_clear, "web-learning-reset": api.web_learning_reset,
              "web-pause": api.web_pause, "web-resume": api.web_resume}[command]
    return method(args.runtime_instance)


def _display(response, args):
    if getattr(args, "json_output", False):
        print(json.dumps(asdict(response), indent=2))
        return
    data = response.data
    if args.command == "users":
        if not data:
            print("No users configured.")
        else:
            fmt = "{:<24} {:>7}  {:>14}  {}"
            print(fmt.format("USERNAME", "CONNS", "OCTETS", "LINKS"))
            print("-" * 72)
            for user in data:
                links = user.get("links") or {}
                all_links = sum((links.get(kind) or [] for kind in ("classic", "secure", "tls")), [])
                print(fmt.format(user["username"], user.get("current_connections", 0), user.get("total_octets", 0), all_links[0] if all_links else "-"))
    elif args.command == "create":
        print(f"Created: {data.get('user', {}).get('username')}")
        print(f"Secret:  {data.get('secret')}")
        for kind, links in ((data.get("user") or {}).get("links") or {}).items():
            for link in links or []:
                print(f"Link ({kind}): {link}")
    elif args.command == "delete":
        print(f"Deleted: {data}")
    else:
        print(json.dumps(data, indent=2))
    if response.revision is not None:
        print(f"# revision: {response.revision}")
    if response.http_status != 200:
        print(f"# HTTP: {response.http_status}")


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in (None, "help"):
        parser.print_help()
        return 0
    if args.command == "gen-secret":
        print(TelemtAPI.generate_secret())
        return 0
    try:
        api = TelemtAPI(getattr(args, "url", "http://127.0.0.1:9091"),
                        auth_header=getattr(args, "auth", None), timeout=getattr(args, "timeout", 10))
        response = _dispatch(api, args)
        _display(response, args)
        if args.command == "ready":
            return 0 if response.http_status == 200 and _response_field(response, "ready") is True else 1
        data = response.data if isinstance(response.data, dict) else {}
        if data.get("state") in ("failed", "rolled_back", "cancelled"):
            return 1
        if args.command in ("web-drain", "web-drain-wait") and getattr(args, "wait", args.command == "web-drain-wait"):
            drain = (data.get("operator_lifecycle") or {}).get("drain") or {}
            return 1 if drain.get("state") == "cancelled" else 0
        return 0
    except TelemtAPIError as error:
        request = f" (request_id={error.request_id})" if error.request_id is not None else ""
        print(f"API error [{error.http_status}] {error.code}: {error}{request}", file=sys.stderr)
        if error.details:
            print(json.dumps(error.details), file=sys.stderr)
        return 1
    except (ValueError, OSError) as error:
        print(f"Input error: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
