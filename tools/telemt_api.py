"""
Telemt Control API Python Client
Full-coverage client for https://github.com/telemt/telemt

Usage:
    client = TelemtAPI("http://127.0.0.1:9091", auth_header="your-secret")
    client.health()
    client.create_user("alice", max_tcp_conns=10)
    client.patch_user("alice", data_quota_bytes=1_000_000_000)
    client.delete_user("alice")
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TelemtAPIError(Exception):
    """Raised when the API returns an error envelope or a transport error."""

    def __init__(self, message: str, code: str | None = None,
                 http_status: int | None = None, request_id: int | None = None):
        super().__init__(message)
        self.code = code
        self.http_status = http_status
        self.request_id = request_id

    def __repr__(self) -> str:
        return (f"TelemtAPIError(message={str(self)!r}, code={self.code!r}, "
                f"http_status={self.http_status}, request_id={self.request_id})")


# ---------------------------------------------------------------------------
# Response wrapper
# ---------------------------------------------------------------------------

@dataclass
class APIResponse:
    """Wraps a successful API response envelope."""
    ok: bool
    data: Any
    revision: str | None = None

    def __repr__(self) -> str:  # pragma: no cover
        return f"APIResponse(ok={self.ok}, revision={self.revision!r}, data={self.data!r})"


# ---------------------------------------------------------------------------
# Main client
# ---------------------------------------------------------------------------

class TelemtAPI:
    """
    HTTP client for the Telemt Control API.

    Parameters
    ----------
    base_url:
        Scheme + host + port, e.g. ``"http://127.0.0.1:9091"``.
        Trailing slash is stripped automatically.
    auth_header:
        Exact value for the ``Authorization`` header.
        Leave *None* when ``auth_header`` is not configured server-side.
    timeout:
        Socket timeout in seconds for every request (default 10).
    """

    def __init__(
            self,
            base_url: str = "http://127.0.0.1:9091",
            auth_header: str | None = None,
            timeout: int = 10,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth_header = auth_header
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Low-level HTTP helpers
    # ------------------------------------------------------------------

    def _headers(self, extra: dict | None = None) -> dict:
        h = {"Content-Type": "application/json; charset=utf-8",
             "Accept": "application/json"}
        if self.auth_header:
            h["Authorization"] = self.auth_header
        if extra:
            h.update(extra)
        return h

    def _request(
            self,
            method: str,
            path: str,
            body: dict | None = None,
            if_match: str | None = None,
            query: dict | None = None,
    ) -> APIResponse:
        url = self.base_url + path
        if query:
            qs = "&".join(f"{k}={v}" for k, v in query.items())
            url = f"{url}?{qs}"

        raw_body: bytes | None = None
        if body is not None:
            raw_body = json.dumps(body).encode()

        extra_headers: dict = {}
        if if_match is not None:
            extra_headers["If-Match"] = if_match

        req = Request(
            url,
            data=raw_body,
            headers=self._headers(extra_headers),
            method=method,
        )

        try:
            with urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read())
        except HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw)
            except Exception:
                raise TelemtAPIError(
                    str(exc), http_status=exc.code
                ) from exc
            err = payload.get("error", {})
            raise TelemtAPIError(
                err.get("message", str(exc)),
                code=err.get("code"),
                http_status=exc.code,
                request_id=payload.get("request_id"),
            ) from exc
        except URLError as exc:
            raise TelemtAPIError(str(exc)) from exc

        if not payload.get("ok"):
            err = payload.get("error", {})
            raise TelemtAPIError(
                err.get("message", "unknown error"),
                code=err.get("code"),
                request_id=payload.get("request_id"),
            )

        return APIResponse(
            ok=True,
            data=payload.get("data"),
            revision=payload.get("revision"),
        )

    def _get(self, path: str, query: dict | None = None) -> APIResponse:
        return self._request("GET", path, query=query)

    def _post(self, path: str, body: dict | None = None,
              if_match: str | None = None) -> APIResponse:
        return self._request("POST", path, body=body, if_match=if_match)

    def _patch(self, path: str, body: dict,
               if_match: str | None = None) -> APIResponse:
        return self._request("PATCH", path, body=body, if_match=if_match)

    def _delete(self, path: str, if_match: str | None = None) -> APIResponse:
        return self._request("DELETE", path, if_match=if_match)

    # ------------------------------------------------------------------
    # Health & system
    # ------------------------------------------------------------------

    def health(self) -> APIResponse:
        """GET /v1/health — liveness probe."""
        return self._get("/v1/health")

    def system_info(self) -> APIResponse:
        """GET /v1/system/info — binary version, uptime, config hash."""
        return self._get("/v1/system/info")

    # ------------------------------------------------------------------
    # Runtime gates & initialization
    # ------------------------------------------------------------------

    def runtime_gates(self) -> APIResponse:
        """GET /v1/runtime/gates — admission gates and startup progress."""
        return self._get("/v1/runtime/gates")

    def runtime_initialization(self) -> APIResponse:
        """GET /v1/runtime/initialization — detailed startup timeline."""
        return self._get("/v1/runtime/initialization")

    # ------------------------------------------------------------------
    # Limits & security
    # ------------------------------------------------------------------

    def limits_effective(self) -> APIResponse:
        """GET /v1/limits/effective — effective timeout/upstream/ME limits."""
        return self._get("/v1/limits/effective")

    def security_posture(self) -> APIResponse:
        """GET /v1/security/posture — API auth, telemetry, log-level summary."""
        return self._get("/v1/security/posture")

    def security_whitelist(self) -> APIResponse:
        """GET /v1/security/whitelist — current IP whitelist CIDRs."""
        return self._get("/v1/security/whitelist")

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats_summary(self) -> APIResponse:
        """GET /v1/stats/summary — uptime, connection totals, user count."""
        return self._get("/v1/stats/summary")

    def stats_zero_all(self) -> APIResponse:
        """GET /v1/stats/zero/all — zero-cost counters (core, upstream, ME, pool, desync)."""
        return self._get("/v1/stats/zero/all")

    def stats_upstreams(self) -> APIResponse:
        """GET /v1/stats/upstreams — upstream health + zero counters."""
        return self._get("/v1/stats/upstreams")

    def stats_minimal_all(self) -> APIResponse:
        """GET /v1/stats/minimal/all — ME writers + DC snapshot (requires minimal_runtime_enabled)."""
        return self._get("/v1/stats/minimal/all")

    def stats_me_writers(self) -> APIResponse:
        """GET /v1/stats/me-writers — per-writer ME status (requires minimal_runtime_enabled)."""
        return self._get("/v1/stats/me-writers")

    def stats_dcs(self) -> APIResponse:
        """GET /v1/stats/dcs — per-DC coverage and writer counts (requires minimal_runtime_enabled)."""
        return self._get("/v1/stats/dcs")

    # ------------------------------------------------------------------
    # Runtime deep-dive
    # ------------------------------------------------------------------

    def runtime_me_pool_state(self) -> APIResponse:
        """GET /v1/runtime/me_pool_state — ME pool generation/writer/refill snapshot."""
        return self._get("/v1/runtime/me_pool_state")

    def runtime_me_quality(self) -> APIResponse:
        """GET /v1/runtime/me_quality — ME KDF, route-drop, and per-DC RTT counters."""
        return self._get("/v1/runtime/me_quality")

    def runtime_upstream_quality(self) -> APIResponse:
        """GET /v1/runtime/upstream_quality — per-upstream health, latency, DC preferences."""
        return self._get("/v1/runtime/upstream_quality")

    def runtime_nat_stun(self) -> APIResponse:
        """GET /v1/runtime/nat_stun — NAT probe state, STUN servers, reflected IPs."""
        return self._get("/v1/runtime/nat_stun")

    def runtime_me_selftest(self) -> APIResponse:
        """GET /v1/runtime/me-selftest — KDF/timeskew/IP/PID/BND health state."""
        return self._get("/v1/runtime/me-selftest")

    def runtime_connections_summary(self) -> APIResponse:
        """GET /v1/runtime/connections/summary — live connection totals + top-N users (requires runtime_edge_enabled)."""
        return self._get("/v1/runtime/connections/summary")

    def runtime_events_recent(self, limit: int | None = None) -> APIResponse:
        """GET /v1/runtime/events/recent — recent ring-buffer events (requires runtime_edge_enabled).

        Parameters
        ----------
        limit:
            Optional cap on returned events (1–1000, server default 50).
        """
        query = {"limit": str(limit)} if limit is not None else None
        return self._get("/v1/runtime/events/recent", query=query)

    # ------------------------------------------------------------------
    # Users (read)
    # ------------------------------------------------------------------

    def list_users(self) -> APIResponse:
        """GET /v1/users — list all users with connection/traffic info."""
        return self._get("/v1/users")

    def get_user(self, username: str) -> APIResponse:
        """GET /v1/users/{username} — single user info."""
        return self._get(f"/v1/users/{_safe(username)}")

    # ------------------------------------------------------------------
    # Users (write)
    # ------------------------------------------------------------------

    def create_user(
            self,
            username: str,
            *,
            secret: str | None = None,
            user_ad_tag: str | None = None,
            max_tcp_conns: int | None = None,
            expiration_rfc3339: str | None = None,
            data_quota_bytes: int | None = None,
            max_unique_ips: int | None = None,
            if_match: str | None = None,
    ) -> APIResponse:
        """POST /v1/users — create a new user.

        Parameters
        ----------
        username:
            ``[A-Za-z0-9_.-]``, length 1–64.
        secret:
            Exactly 32 hex chars. Auto-generated if omitted.
        user_ad_tag:
            Exactly 32 hex chars.
        max_tcp_conns:
            Per-user concurrent TCP limit.
        expiration_rfc3339:
            RFC3339 expiration timestamp, e.g. ``"2025-12-31T23:59:59Z"``.
        data_quota_bytes:
            Per-user traffic quota in bytes.
        max_unique_ips:
            Per-user unique source IP limit.
        if_match:
            Optional ``If-Match`` revision for optimistic concurrency.
        """
        body: Dict[str, Any] = {"username": username}
        _opt(body, "secret", secret)
        _opt(body, "user_ad_tag", user_ad_tag)
        _opt(body, "max_tcp_conns", max_tcp_conns)
        _opt(body, "expiration_rfc3339", expiration_rfc3339)
        _opt(body, "data_quota_bytes", data_quota_bytes)
        _opt(body, "max_unique_ips", max_unique_ips)
        return self._post("/v1/users", body=body, if_match=if_match)

    def patch_user(
            self,
            username: str,
            *,
            secret: str | None = None,
            user_ad_tag: str | None = None,
            max_tcp_conns: int | None = None,
            expiration_rfc3339: str | None = None,
            data_quota_bytes: int | None = None,
            max_unique_ips: int | None = None,
            if_match: str | None = None,
    ) -> APIResponse:
        """PATCH /v1/users/{username} — partial update; only provided fields change.

        Parameters
        ----------
        username:
            Existing username to update.
        secret:
            New secret (32 hex chars).
        user_ad_tag:
            New ad tag (32 hex chars).
        max_tcp_conns:
            New TCP concurrency limit.
        expiration_rfc3339:
            New expiration timestamp.
        data_quota_bytes:
            New quota in bytes.
        max_unique_ips:
            New unique IP limit.
        if_match:
            Optional ``If-Match`` revision.
        """
        body: Dict[str, Any] = {}
        _opt(body, "secret", secret)
        _opt(body, "user_ad_tag", user_ad_tag)
        _opt(body, "max_tcp_conns", max_tcp_conns)
        _opt(body, "expiration_rfc3339", expiration_rfc3339)
        _opt(body, "data_quota_bytes", data_quota_bytes)
        _opt(body, "max_unique_ips", max_unique_ips)
        if not body:
            raise ValueError("patch_user: at least one field must be provided")
        return self._patch(f"/v1/users/{_safe(username)}", body=body,
                           if_match=if_match)

    def delete_user(
            self,
            username: str,
            *,
            if_match: str | None = None,
    ) -> APIResponse:
        """DELETE /v1/users/{username} — remove user; blocks deletion of last user.

        Parameters
        ----------
        if_match:
            Optional ``If-Match`` revision for optimistic concurrency.
        """
        return self._delete(f"/v1/users/{_safe(username)}", if_match=if_match)

    # NOTE: POST /v1/users/{username}/rotate-secret currently returns 404
    # in the route matcher (documented limitation). The method is provided
    # for completeness and future compatibility.
    def rotate_secret(
            self,
            username: str,
            *,
            secret: str | None = None,
            if_match: str | None = None,
    ) -> APIResponse:
        """POST /v1/users/{username}/rotate-secret — rotate user secret.

        .. warning::
            This endpoint currently returns ``404 not_found`` in all released
            versions (documented route matcher limitation). The method is
            included for future compatibility.

        Parameters
        ----------
        secret:
            New secret (32 hex chars). Auto-generated if omitted.
        """
        body: Dict[str, Any] = {}
        _opt(body, "secret", secret)
        return self._post(f"/v1/users/{_safe(username)}/rotate-secret",
                          body=body or None, if_match=if_match)

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    @staticmethod
    def generate_secret() -> str:
        """Generate a random 32-character hex secret suitable for user creation."""
        return secrets.token_hex(16)  # 16 bytes → 32 hex chars


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _safe(username: str) -> str:
    """Minimal guard: reject obvious path-injection attempts."""
    if "/" in username or "\\" in username:
        raise ValueError(f"Invalid username: {username!r}")
    return username


def _opt(d: dict, key: str, value: Any) -> None:
    """Add key to dict only when value is not None."""
    if value is not None:
        d[key] = value


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print(resp: APIResponse) -> None:
    print(json.dumps(resp.data, indent=2))
    if resp.revision:
        print(f"# revision: {resp.revision}", flush=True)


def _build_parser():
    import argparse

    p = argparse.ArgumentParser(
        prog="telemt_api.py",
        description="Telemt Control API CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
COMMANDS (read)
  health                          Liveness check
  info                            System info (version, uptime, config hash)
  status                          Runtime gates + startup progress
  init                            Runtime initialization timeline
  limits                          Effective limits (timeouts, upstream, ME)
  posture                         Security posture summary
  whitelist                       IP whitelist entries
  summary                         Stats summary (conns, uptime, users)
  zero                            Zero-cost counters (core/upstream/ME/pool/desync)
  upstreams                       Upstream health + zero counters
  minimal                         ME writers + DC snapshot  [minimal_runtime_enabled]
  me-writers                      Per-writer ME status      [minimal_runtime_enabled]
  dcs                             Per-DC coverage           [minimal_runtime_enabled]
  me-pool                         ME pool generation/writer/refill snapshot
  me-quality                      ME KDF, route-drops, per-DC RTT
  upstream-quality                Per-upstream health + latency
  nat-stun                        NAT probe state + STUN servers
  me-selftest                     KDF/timeskew/IP/PID/BND health
  connections                     Live connection totals + top-N  [runtime_edge_enabled]
  events [--limit N]              Recent ring-buffer events       [runtime_edge_enabled]

COMMANDS (users)
  users                           List all users
  user <username>                 Get single user
  create <username> [OPTIONS]     Create user
  patch  <username> [OPTIONS]     Partial update user
  delete <username>               Delete user
  secret <username> [--secret S]  Rotate secret (reserved; returns 404 in current release)
  gen-secret                      Print a random 32-hex secret and exit

USER OPTIONS (for create / patch)
  --secret S          32 hex chars
  --ad-tag S          32 hex chars (ad tag)
  --max-conns N       Max concurrent TCP connections
  --expires DATETIME  RFC3339 expiration (e.g. 2026-12-31T23:59:59Z)
  --quota N           Data quota in bytes
  --max-ips N         Max unique source IPs

EXAMPLES
  telemt_api.py health
  telemt_api.py -u http://10.0.0.1:9091 -a mysecret users
  telemt_api.py create alice --max-conns 5 --quota 10000000000
  telemt_api.py patch  alice --expires 2027-01-01T00:00:00Z
  telemt_api.py delete alice
  telemt_api.py events --limit 20
        """,
    )

    p.add_argument("-u", "--url", default="http://127.0.0.1:9091",
                   metavar="URL", help="API base URL (default: http://127.0.0.1:9091)")
    p.add_argument("-a", "--auth", default=None, metavar="TOKEN",
                   help="Authorization header value")
    p.add_argument("-t", "--timeout", type=int, default=10, metavar="SEC",
                   help="Request timeout in seconds (default: 10)")

    p.add_argument("command", nargs="?", default="help",
                   help="Command to run (see COMMANDS below)")
    p.add_argument("arg", nargs="?", default=None, metavar="USERNAME",
                   help="Username for user commands")

    # user create/patch fields
    p.add_argument("--secret", default=None)
    p.add_argument("--ad-tag", dest="ad_tag", default=None)
    p.add_argument("--max-conns", dest="max_conns", type=int, default=None)
    p.add_argument("--expires", default=None)
    p.add_argument("--quota", type=int, default=None)
    p.add_argument("--max-ips", dest="max_ips", type=int, default=None)

    # events
    p.add_argument("--limit", type=int, default=None,
                   help="Max events for `events` command")

    # optimistic concurrency
    p.add_argument("--if-match", dest="if_match", default=None,
                   metavar="REVISION", help="If-Match revision header")

    return p


if __name__ == "__main__":
    import sys

    parser = _build_parser()
    args = parser.parse_args()

    cmd = (args.command or "help").lower()

    if cmd in ("help", "--help"):
        parser.print_help()
        sys.exit(0)

    if cmd == "gen-secret":
        print(TelemtAPI.generate_secret())
        sys.exit(0)

    api = TelemtAPI(args.url, auth_header=args.auth, timeout=args.timeout)

    try:
        # -- read endpoints --------------------------------------------------
        if cmd == "health":
            _print(api.health())

        elif cmd == "info":
            _print(api.system_info())

        elif cmd == "status":
            _print(api.runtime_gates())

        elif cmd == "init":
            _print(api.runtime_initialization())

        elif cmd == "limits":
            _print(api.limits_effective())

        elif cmd == "posture":
            _print(api.security_posture())

        elif cmd == "whitelist":
            _print(api.security_whitelist())

        elif cmd == "summary":
            _print(api.stats_summary())

        elif cmd == "zero":
            _print(api.stats_zero_all())

        elif cmd == "upstreams":
            _print(api.stats_upstreams())

        elif cmd == "minimal":
            _print(api.stats_minimal_all())

        elif cmd == "me-writers":
            _print(api.stats_me_writers())

        elif cmd == "dcs":
            _print(api.stats_dcs())

        elif cmd == "me-pool":
            _print(api.runtime_me_pool_state())

        elif cmd == "me-quality":
            _print(api.runtime_me_quality())

        elif cmd == "upstream-quality":
            _print(api.runtime_upstream_quality())

        elif cmd == "nat-stun":
            _print(api.runtime_nat_stun())

        elif cmd == "me-selftest":
            _print(api.runtime_me_selftest())

        elif cmd == "connections":
            _print(api.runtime_connections_summary())

        elif cmd == "events":
            _print(api.runtime_events_recent(limit=args.limit))

        # -- user read -------------------------------------------------------
        elif cmd == "users":
            resp = api.list_users()
            users = resp.data or []
            if not users:
                print("No users configured.")
            else:
                fmt = "{:<24} {:>7}  {:>14}  {}"
                print(fmt.format("USERNAME", "CONNS", "OCTETS", "LINKS"))
                print("-" * 72)
                for u in users:
                    links = (u.get("links") or {})
                    all_links = (links.get("classic") or []) + \
                                (links.get("secure") or []) + \
                                (links.get("tls") or [])
                    link_str = all_links[0] if all_links else "-"
                    print(fmt.format(
                        u["username"],
                        u.get("current_connections", 0),
                        u.get("total_octets", 0),
                        link_str,
                    ))
            if resp.revision:
                print(f"# revision: {resp.revision}")

        elif cmd == "user":
            if not args.arg:
                parser.error("user command requires <username>")
            _print(api.get_user(args.arg))

        # -- user write ------------------------------------------------------
        elif cmd == "create":
            if not args.arg:
                parser.error("create command requires <username>")
            resp = api.create_user(
                args.arg,
                secret=args.secret,
                user_ad_tag=args.ad_tag,
                max_tcp_conns=args.max_conns,
                expiration_rfc3339=args.expires,
                data_quota_bytes=args.quota,
                max_unique_ips=args.max_ips,
                if_match=args.if_match,
            )
            d = resp.data or {}
            print(f"Created: {d.get('user', {}).get('username')}")
            print(f"Secret:  {d.get('secret')}")
            links = (d.get("user") or {}).get("links") or {}
            for kind, lst in links.items():
                for link in (lst or []):
                    print(f"Link ({kind}): {link}")
            if resp.revision:
                print(f"# revision: {resp.revision}")

        elif cmd == "patch":
            if not args.arg:
                parser.error("patch command requires <username>")
            if not any([args.secret, args.ad_tag, args.max_conns,
                        args.expires, args.quota, args.max_ips]):
                parser.error(
                    "patch requires at least one field (--secret, --max-conns, --expires, --quota, --max-ips, --ad-tag)")
            _print(api.patch_user(
                args.arg,
                secret=args.secret,
                user_ad_tag=args.ad_tag,
                max_tcp_conns=args.max_conns,
                expiration_rfc3339=args.expires,
                data_quota_bytes=args.quota,
                max_unique_ips=args.max_ips,
                if_match=args.if_match,
            ))

        elif cmd == "delete":
            if not args.arg:
                parser.error("delete command requires <username>")
            resp = api.delete_user(args.arg, if_match=args.if_match)
            print(f"Deleted: {resp.data}")
            if resp.revision:
                print(f"# revision: {resp.revision}")

        elif cmd == "secret":
            if not args.arg:
                parser.error("secret command requires <username>")
            _print(api.rotate_secret(args.arg, secret=args.secret,
                                     if_match=args.if_match))

        else:
            print(f"Unknown command: {cmd!r}\nRun with 'help' to see available commands.",
                  file=sys.stderr)
            sys.exit(1)

    except TelemtAPIError as exc:
        print(f"API error [{exc.http_status}] {exc.code}: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
