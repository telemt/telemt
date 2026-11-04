"""
Telemt Control API Python Client
Standard-library JSON client and CLI for Telemt's Control API.

Usage:
    client = TelemtAPI("http://127.0.0.1:9091", auth_header="your-secret")
    client.health()
    client.create_user("alice", max_tcp_conns=10)
    client.patch_user("alice", data_quota_bytes=1_000_000_000)
    client.delete_user("alice")
"""

from __future__ import annotations

import json
import math
import secrets
import time
from dataclasses import dataclass
from http.client import HTTPException
from typing import Any, Dict
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TelemtAPIError(Exception):
    """Raised when the API returns an error envelope or a transport error."""

    def __init__(self, message: str, code: str | None = None,
                 http_status: int | None = None, request_id: int | None = None,
                 details: list | None = None, last_response: APIResponse | None = None):
        super().__init__(message)
        self.code = code
        self.http_status = http_status
        self.request_id = request_id
        self.details = details or []
        self.last_response = last_response

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
    http_status: int = 200

    def __repr__(self) -> str:  # pragma: no cover
        return (f"APIResponse(ok={self.ok}, http_status={self.http_status}, "
                f"revision={self.revision!r}, data={self.data!r})")


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
            timeout: float = 10,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth_header = auth_header
        self.timeout = _positive_seconds(timeout, "timeout")

    # ------------------------------------------------------------------
    # Low-level HTTP helpers
    # ------------------------------------------------------------------

    def _headers(self, extra: dict | None = None) -> dict:
        # WEB controls require this exact media type without charset parameters.
        h = {"Content-Type": "application/json",
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
            *,
            if_runtime_match: str | None = None,
            success_statuses: tuple[int, ...] = (),
            timeout: float | None = None,
    ) -> APIResponse:
        url = self.base_url + path
        if query:
            qs = urlencode(query)
            url = f"{url}?{qs}"

        raw_body: bytes | None = None
        if body is not None:
            raw_body = json.dumps(body, allow_nan=False).encode("utf-8")
            if method == "POST" and path.startswith("/v1/runtime/web/") and len(raw_body) > 65536:
                raise ValueError("WEB control JSON exceeds 65536 bytes")

        extra_headers: dict = {}
        if if_match is not None:
            extra_headers["If-Match"] = if_match
        if if_runtime_match is not None:
            extra_headers["If-Runtime-Match"] = if_runtime_match

        req = Request(
            url,
            data=raw_body,
            headers=self._headers(extra_headers),
            method=method,
        )

        try:
            request_timeout = self.timeout if timeout is None else min(self.timeout, timeout)
            try:
                response = urlopen(req, timeout=request_timeout)
            except HTTPError as error:
                response = error
            with response:
                status, raw = response.status, response.read()
        except (URLError, OSError, HTTPException) as exc:
            raise TelemtAPIError(str(exc)) from exc

        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise TelemtAPIError("Expected a JSON API envelope (empty gray_action responses are not success)",
                                 code="invalid_response", http_status=status) from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("ok"), bool):
            raise TelemtAPIError("Invalid API envelope", code="invalid_response", http_status=status)
        if not payload["ok"]:
            err = payload.get("error", {})
            if not isinstance(err, dict):
                err = {}
            raise TelemtAPIError(
                err.get("message", "unknown error"),
                code=err.get("code"),
                http_status=status,
                request_id=payload.get("request_id"),
                details=err.get("details"),
            )
        if not (200 <= status < 300 or status in success_statuses) or "data" not in payload:
            raise TelemtAPIError("Unexpected API success response", code="invalid_response", http_status=status)

        return APIResponse(
            ok=True,
            data=payload.get("data"),
            revision=payload.get("revision"),
            http_status=status,
        )

    def _get(self, path: str, query: dict | None = None, **options) -> APIResponse:
        return self._request("GET", path, query=query, **options)

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

    def health_ready(self) -> APIResponse:
        """Return readiness data for both 200 and a documented 503 ok=true response."""
        return self._get("/v1/health/ready", success_statuses=(503,))

    def capabilities(self) -> APIResponse:
        return self._get("/v1/capabilities")

    def config_schema(self) -> APIResponse:
        return self._get("/v1/config/schema")

    def get_config(self) -> APIResponse:
        """Desired editable configuration; the legacy response can contain credentials."""
        return self._get("/v1/config")

    def config_state(self, sections: list[str] | None = None) -> APIResponse:
        """Redacted publication state, including partial results and nullable revision."""
        query = None
        if sections is not None:
            allowed = {"general", "network", "server", "timeouts", "censorship", "upstreams",
                       "dc_overrides", "web", "access", "logging", "root"}
            if isinstance(sections, str) or not sections or len(set(sections)) != len(sections) or not set(sections) <= allowed:
                raise ValueError("sections must contain unique known section names")
            query = {"sections": ",".join(sections)}
        return self._get("/v1/config/state", query)

    def patch_config(self, patch: dict, *, if_match: str | None = None,
                     if_runtime_match: str | None = None, reload: str | None = None,
                     timeout_secs: int | None = None, failure_policy: str | None = None) -> APIResponse:
        """Send a sparse patch unchanged; nested nulls keep the server's merge semantics."""
        _object(patch, "patch")
        return self._request("PATCH", "/v1/config", patch, if_match,
                             _reload_query(reload, timeout_secs, failure_policy),
                             if_runtime_match=if_runtime_match)

    def validate_config(self, patch: dict, *, if_match: str | None = None,
                        if_runtime_match: str | None = None, reload: str | None = None,
                        timeout_secs: int | None = None, failure_policy: str | None = None) -> APIResponse:
        """Prepare a candidate without committing; accepts the same inputs as PATCH."""
        _object(patch, "patch")
        return self._request("POST", "/v1/config/validate", patch, if_match,
                             _reload_query(reload, timeout_secs, failure_policy),
                             if_runtime_match=if_runtime_match)

    def reload(self, mode: str = "instant", *, timeout_secs: int | None = None,
               failure_policy: str | None = None, if_match: str | None = None) -> APIResponse:
        body = _reload_query(mode, timeout_secs, failure_policy)
        body["mode"] = body.pop("reload")
        return self._post("/v1/system/reload", body, if_match)

    def reload_status(self, reload_id: int) -> APIResponse:
        _bounded(reload_id, 0, 2**64 - 1, "reload_id")
        return self._get(f"/v1/system/reload/{reload_id}")

    def wait_reload(self, reload_id: int, *, timeout: float = 60, poll_interval: float = 0.25,
                    expected_revision: str | None = None) -> APIResponse:
        """Poll an accepted ID; failed/rolled_back are returned as terminal data."""
        _bounded(reload_id, 0, 2**64 - 1, "reload_id")
        def state(response):
            data = _object(response.data, "reload status")
            if data.get("reload_id") != reload_id or (expected_revision is not None and data.get("config_revision") != expected_revision):
                raise TelemtAPIError("Reload identity changed while polling", code="operation_mismatch", last_response=response)
            return data.get("state")
        return _poll(lambda remaining: self._get(f"/v1/system/reload/{reload_id}", timeout=remaining),
                     state, {"succeeded", "failed", "rolled_back"},
                     {"accepted", "preparing", "activating", "draining"}, timeout, poll_interval)

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
        if limit is not None:
            _bounded(limit, 1, 1000, "limit")
        query = {"limit": str(limit)} if limit is not None else None
        return self._get("/v1/runtime/events/recent", query=query)

    def runtime_tls_fingerprints(self, limit: int | None = None) -> APIResponse:
        if limit is not None:
            _bounded(limit, 1, 1000, "limit")
        return self._get("/v1/runtime/tls-fingerprints", {"limit": limit} if limit is not None else None)

    def users_quota(self) -> APIResponse:
        """Desired quota/period and effective recurring quota schedule are distinct."""
        return self._get("/v1/stats/users/quota")

    def users_active_ips(self) -> APIResponse:
        return self._get("/v1/stats/users/active-ips")

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
            quota_period: str | None = None,
            rate_limit_up_bps: int | None = None,
            rate_limit_down_bps: int | None = None,
            enabled: bool | None = None,
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
        quota_period:
            Optional UTC recurring period: daily, weekly or monthly.
        rate_limit_up_bps, rate_limit_down_bps:
            Per-user upload/download byte rates; zero values are transmitted.
        enabled:
            Optional admission flag; False is transmitted.
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
        _opt(body, "quota_period", quota_period)
        _opt(body, "rate_limit_up_bps", rate_limit_up_bps)
        _opt(body, "rate_limit_down_bps", rate_limit_down_bps)
        _opt(body, "enabled", enabled)
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
            quota_period: str | None = None,
            rate_limit_up_bps: int | None = None,
            rate_limit_down_bps: int | None = None,
            enabled: bool | None = None,
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
        quota_period, rate_limit_up_bps, rate_limit_down_bps, enabled:
            Recurring quota, byte rates and admission flag. None omits a field,
            preserving the legacy helper contract; use patch_user_fields to clear.
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
        _opt(body, "quota_period", quota_period)
        _opt(body, "rate_limit_up_bps", rate_limit_up_bps)
        _opt(body, "rate_limit_down_bps", rate_limit_down_bps)
        _opt(body, "enabled", enabled)
        return self.patch_user_fields(username, body, if_match=if_match)

    def patch_user_fields(self, username: str, fields: dict, *, if_match: str | None = None) -> APIResponse:
        """Exact sparse PATCH: omission preserves a field; explicit None sends JSON null.

        The older patch_user convenience method still omits None-valued arguments.
        Server-specific null semantics apply, including secret:null being ignored.
        """
        _object(fields, "fields")
        if not fields or not fields.keys() <= USER_FIELDS:
            raise ValueError("patch_user_fields requires at least one known user field")
        return self._patch(f"/v1/users/{_safe(username)}", fields, if_match)

    def enable_user(self, username: str, *, if_match: str | None = None) -> APIResponse:
        return self._post(f"/v1/users/{_safe(username)}/enable", if_match=if_match)

    def disable_user(self, username: str, *, if_match: str | None = None) -> APIResponse:
        return self._post(f"/v1/users/{_safe(username)}/disable", if_match=if_match)

    def reset_user_quota(self, username: str, *, if_match: str | None = None) -> APIResponse:
        return self._post(f"/v1/users/{_safe(username)}/reset-quota", if_match=if_match)

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

    def rotate_secret(
            self,
            username: str,
            *,
            secret: str | None = None,
            if_match: str | None = None,
    ) -> APIResponse:
        """POST /v1/users/{username}/rotate-secret — rotate user secret.

        Returns the new credential. Owners of the old identity are cancelled;
        watcher publication and existing-session retirement remain asynchronous.

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
    # WEB runtime: opaque references are always supplied by the caller.
    # ------------------------------------------------------------------

    def web_status(self) -> APIResponse:
        return self._get("/v1/runtime/web/status")

    def web_sessions(self, *, limit: int | None = None, cursor: str | None = None,
                     session_ref: str | None = None, ip: str | None = None,
                     host: str | None = None, user: str | None = None,
                     user_agent_id: str | None = None, key_id: str | None = None,
                     carrier: str | None = None, state: str | None = None) -> APIResponse:
        if limit is not None:
            _bounded(limit, 1, 200, "limit")
        if session_ref is not None and (cursor is not None or limit is not None):
            raise ValueError("session_ref cannot be combined with cursor or limit")
        query = {key: value for key, value in dict(limit=limit, cursor=cursor, session_ref=session_ref,
                 ip=ip, host=host, user=user, user_agent_id=user_agent_id, key_id=key_id,
                 carrier=carrier, state=state).items() if value is not None}
        return self._get("/v1/runtime/web/sessions", query)

    def web_session(self, session_ref: str) -> APIResponse:
        """A 410 ok=true tombstone is data, with http_status retained."""
        return self._get(f"/v1/runtime/web/sessions/{_safe(session_ref)}", success_statuses=(410,))

    def web_close_sessions(self, runtime_instance: str, selector: dict) -> APIResponse:
        _object(selector, "selector")
        kind = selector.get("kind")
        if kind == "refs":
            refs = selector.get("session_refs")
            if not isinstance(refs, list) or not all(isinstance(ref, str) for ref in refs) or not 1 <= len(refs) <= 200 or len(set(refs)) != len(refs) or set(selector) != {"kind", "session_refs"}:
                raise ValueError("refs selector requires 1..200 unique session references")
        elif kind == "all":
            if set(selector) != {"kind"}:
                raise ValueError("all selector accepts only kind")
        elif kind == "filter":
            allowed = {"kind", "session_ref", "ip", "host", "user", "user_agent_id", "key_id", "carrier", "state"}
            if not selector.keys() <= allowed or not any(value is not None for key, value in selector.items() if key != "kind"):
                raise ValueError("filter selector requires at least one known non-null filter")
        else:
            raise ValueError("selector.kind must be refs, filter or all")
        return self._post("/v1/runtime/web/sessions/close", {"runtime_instance": runtime_instance, "selector": selector})

    def web_operation(self, operation_id: str) -> APIResponse:
        return self._get(f"/v1/runtime/web/operations/{_safe(operation_id)}")

    def wait_web_operation(self, operation_id: str, *, timeout: float = 60, poll_interval: float = 0.25) -> APIResponse:
        path = f"/v1/runtime/web/operations/{_safe(operation_id)}"
        def state(response):
            data = _object(response.data, "WEB operation")
            if data.get("operation_id") != operation_id:
                raise TelemtAPIError("WEB operation identity changed", code="operation_mismatch", last_response=response)
            return data.get("state")
        return _poll(lambda remaining: self._get(path, timeout=remaining), state,
                     {"completed", "cancelled", "failed"}, {"queued", "running"}, timeout, poll_interval)

    def web_debug_clear(self, runtime_instance: str) -> APIResponse:
        return self._post("/v1/runtime/web/debug/clear", {"runtime_instance": runtime_instance})

    def web_learning_reset(self, runtime_instance: str) -> APIResponse:
        return self._post("/v1/runtime/web/carrier-learning/reset", {"runtime_instance": runtime_instance})

    def web_pause(self, runtime_instance: str) -> APIResponse:
        return self._post("/v1/runtime/web/lifecycle/pause", {"runtime_instance": runtime_instance})

    def web_drain(self, runtime_instance: str, timeout_secs: int) -> APIResponse:
        _bounded(timeout_secs, 1, 3600, "timeout_secs")
        return self._post("/v1/runtime/web/lifecycle/drain", {"runtime_instance": runtime_instance, "timeout_secs": timeout_secs})

    def web_resume(self, runtime_instance: str) -> APIResponse:
        return self._post("/v1/runtime/web/lifecycle/resume", {"runtime_instance": runtime_instance})

    def wait_web_drain(self, runtime_instance: str, operation_id: str, *,
                       timeout: float = 60, poll_interval: float = 0.25) -> APIResponse:
        """Poll the same drain through WEB status; never substitute a new process or drain."""
        def state(response):
            data = _object(response.data, "WEB status")
            runtime = data.get("runtime") or {}
            drain = (data.get("operator_lifecycle") or {}).get("drain") or {}
            if runtime.get("runtime_instance") != runtime_instance or drain.get("operation_id") != operation_id:
                raise TelemtAPIError("WEB process or drain identity changed", code="operation_mismatch", last_response=response)
            return drain.get("state")
        return _poll(lambda remaining: self._get("/v1/runtime/web/status", timeout=remaining), state,
                     {"completed", "cancelled"}, {"draining", "force_closing"}, timeout, poll_interval)

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

USER_FIELDS = {"secret", "user_ad_tag", "max_tcp_conns", "expiration_rfc3339", "data_quota_bytes",
               "quota_period", "rate_limit_up_bps", "rate_limit_down_bps", "max_unique_ips", "enabled"}


def _safe(value: str) -> str:
    """Keep one opaque path segment from becoming a path, query or fragment."""
    if not isinstance(value, str) or not value or value in (".", "..") or "/" in value or "\\" in value:
        raise ValueError("Expected one nonempty path segment")
    return quote(value, safe="")


def _opt(d: dict, key: str, value: Any) -> None:
    """Add key to dict only when value is not None."""
    if value is not None:
        d[key] = value


def _object(value, name):
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object")
    return value


def _bounded(value, minimum, maximum, name):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be within {minimum}..{maximum}")


def _positive_seconds(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a finite positive number of seconds")
    return value


def _reload_query(mode, timeout_secs, failure_policy):
    if mode is None:
        if timeout_secs is not None or failure_policy is not None:
            raise ValueError("timeout_secs and failure_policy require reload mode")
        return None
    if mode not in ("instant", "drain"):
        raise ValueError("reload mode must be instant or drain")
    if mode == "drain":
        _bounded(timeout_secs, 1, 3600, "timeout_secs")
    elif timeout_secs is not None:
        raise ValueError("instant reload forbids timeout_secs")
    if failure_policy is not None and failure_policy not in ("keep_new", "rollback"):
        raise ValueError("failure_policy must be keep_new or rollback")
    return {key: value for key, value in dict(reload=mode, timeout_secs=timeout_secs,
            failure_policy=failure_policy).items() if value is not None}


def _poll(fetch, state, terminal, pending, timeout, interval):
    deadline = time.monotonic() + _positive_seconds(timeout, "poll timeout")
    _positive_seconds(interval, "poll interval")
    last = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TelemtAPIError("Polling budget expired; the server operation was not cancelled",
                                 code="poll_timeout", last_response=last)
        last = fetch(remaining)
        if time.monotonic() >= deadline:
            raise TelemtAPIError("Polling budget expired; the server operation was not cancelled",
                                 code="poll_timeout", last_response=last)
        try:
            phase = state(last)
            known = phase in terminal or phase in pending
        except (ValueError, TypeError, AttributeError) as error:
            raise TelemtAPIError("Invalid operation response", code="invalid_response", last_response=last) from error
        if phase in terminal:
            return last
        if not known:
            raise TelemtAPIError("Unknown operation phase", code="invalid_response", last_response=last)
        time.sleep(min(interval, max(0, deadline - time.monotonic())))


def main(argv=None):
    if __package__:
        from .telemt_api_cli import main as cli_main
    else:
        from telemt_api_cli import main as cli_main
    return cli_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
