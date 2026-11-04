import json
import re
import unittest
from http.client import RemoteDisconnected
from pathlib import Path
from urllib.error import URLError
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from tools.telemt_api import TelemtAPI, TelemtAPIError, USER_FIELDS
from http_fixture import MockAPI


INSTANCE = "0123456789abcdef0123456789abcdef"
SESSION = f"ws1.{INSTANCE}.0000000000000001"
OPERATION = f"wo1.{INSTANCE}.0000000000000001"


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.peer = MockAPI().__enter__()
        self.addCleanup(self.peer.__exit__, None, None, None)
        self.api = TelemtAPI(self.peer.url, auth_header="Bearer synthetic-test", timeout=2)

    def test_all_json_operations_match_the_rust_catalog(self):
        reads = {
            "health": "health", "health_ready": "health_ready", "capabilities": "capabilities",
            "config_schema": "config_schema", "system_info": "system_info", "runtime_gates": "runtime_gates",
            "runtime_initialization": "runtime_initialization", "limits_effective": "limits_effective",
            "security_posture": "security_posture", "security_whitelist": "security_whitelist",
            "stats_summary": "stats_summary", "stats_zero_all": "stats_zero_all", "stats_upstreams": "stats_upstreams",
            "stats_minimal_all": "stats_minimal_all", "stats_me_writers": "stats_me_writers", "stats_dcs": "stats_dcs",
            "runtime_me_pool_state": "runtime_me_pool_state", "runtime_me_quality": "runtime_me_quality",
            "runtime_upstream_quality": "runtime_upstream_quality", "runtime_nat_stun": "runtime_nat_stun",
            "runtime_me_selftest": "runtime_me_selftest", "runtime_connections_summary": "runtime_connections_summary",
            "runtime_events_recent": "runtime_events_recent", "runtime_tls_fingerprints": "runtime_tls_fingerprints",
            "web_status": "web_status", "web_sessions": "web_sessions", "users_active_ips": "users_active_ips",
            "users_quota": "users_quota", "config_get": "get_config", "config_state": "config_state", "users_list": "list_users",
        }
        calls = {key: (method, (), {}, None) for key, method in reads.items()}
        calls.update({
            "web_session": ("web_session", (SESSION,), {}, None),
            "web_sessions_close": ("web_close_sessions", (INSTANCE, {"kind": "refs", "session_refs": [SESSION]}), {}, {"runtime_instance": INSTANCE, "selector": {"kind": "refs", "session_refs": [SESSION]}}),
            "web_operation": ("web_operation", (OPERATION,), {}, None),
            **{key: (method, (INSTANCE,), {}, {"runtime_instance": INSTANCE}) for key, method in
               [("web_debug_clear", "web_debug_clear"), ("web_learning_reset", "web_learning_reset"),
                ("web_pause", "web_pause"), ("web_resume", "web_resume")]},
            "web_drain": ("web_drain", (INSTANCE, 30), {}, {"runtime_instance": INSTANCE, "timeout_secs": 30}),
            "config_validate": ("validate_config", ({"general": {"log_level": "debug"}},), {}, {"general": {"log_level": "debug"}}),
            "config_patch": ("patch_config", ({"web": {"enabled": False}},), {}, {"web": {"enabled": False}}),
            "reload": ("reload", (), {}, {"mode": "instant"}),
            "reload_status": ("reload_status", (7,), {}, None),
            "users_create": ("create_user", ("alice",), {}, {"username": "alice"}),
            "users_get": ("get_user", ("alice",), {}, None),
            "users_patch": ("patch_user", ("alice",), {"enabled": False}, {"enabled": False}),
            "users_delete": ("delete_user", ("alice",), {}, None),
            "users_rotate_secret": ("rotate_secret", ("alice",), {}, None),
            "users_enable": ("enable_user", ("alice",), {}, None),
            "users_disable": ("disable_user", ("alice",), {}, None),
            "users_reset_quota": ("reset_user_quota", ("alice",), {}, None),
        })
        root = Path(__file__).resolve().parents[2]
        catalog = json.loads((root / "src/api/discovery/operations.json").read_text())
        self.assertEqual(set(calls), {row["id"] for row in catalog} - {"web_status_html"})
        for operation in catalog:
            if operation["id"] == "web_status_html":
                continue  # The HTML viewer is opened in a browser, not decoded as JSON.
            with self.subTest(operation=operation["id"]):
                method, args, options, body = calls[operation["id"]]
                status = operation["success"][0]
                self.peer.reply({"fixture": operation["id"]}, status)
                response = getattr(self.api, method)(*args, **options)
                request = self.peer.requests[-1]
                self.assertEqual(request["method"], operation["method"])
                self.assertEqual(request["path"], operation["path"].format(username="alice", id=7, session_ref=SESSION, operation_id=OPERATION))
                self.assertEqual(request["body"], body)
                self.assertEqual(request["headers"]["authorization"], ["Bearer synthetic-test"])
                self.assertEqual(request["headers"]["content-type"], ["application/json"])
                self.assertEqual(response.http_status, status)
                self.assertEqual(response.revision, "source-revision")

    def test_exact_user_fields_match_the_versioned_request_contract(self):
        root = Path(__file__).resolve().parents[2]
        artifact = json.loads((root / "docs/Architecture/API/openapi-v1.json").read_text())
        self.assertEqual(USER_FIELDS, set(artifact["components"]["schemas"]["PatchUserRequest"]["properties"]))

    def test_config_sparse_body_queries_and_both_preconditions_are_unchanged(self):
        body = {"general": {"ad_tag": None, "me_keepalive_enabled": False}, "upstreams": []}
        for method in (self.api.validate_config, self.api.patch_config):
            self.peer.reply({"reload": {"reload_id": 7}}, 202 if method == self.api.patch_config else 200)
            method(body, if_match='"source"', if_runtime_match='"process:1:2"', reload="drain", timeout_secs=30, failure_policy="rollback")
            request = self.peer.requests[-1]
            self.assertEqual(request["body"], body)
            self.assertEqual(parse_qs(urlsplit(request["path"]).query), {"reload": ["drain"], "timeout_secs": ["30"], "failure_policy": ["rollback"]})
            self.assertEqual(request["headers"]["if-match"], ['"source"'])
            self.assertEqual(request["headers"]["if-runtime-match"], ['"process:1:2"'])

    def test_null_false_zero_and_legacy_none_omission(self):
        self.peer.reply({})
        fields = {"data_quota_bytes": None, "quota_period": None, "rate_limit_up_bps": 0, "enabled": False}
        self.api.patch_user_fields("alice", fields, if_match="rev")
        self.assertEqual(self.peer.requests[-1]["body"], fields)
        self.peer.reply({})
        self.api.patch_user("alice", max_tcp_conns=None, data_quota_bytes=0, enabled=False, rate_limit_down_bps=0)
        self.assertEqual(self.peer.requests[-1]["body"], {"data_quota_bytes": 0, "enabled": False, "rate_limit_down_bps": 0})
        self.peer.reply({})
        self.api.create_user("alice", enabled=False, quota_period="weekly", rate_limit_up_bps=0, rate_limit_down_bps=12)
        self.assertEqual(self.peer.requests[-1]["body"], {"username": "alice", "enabled": False, "quota_period": "weekly", "rate_limit_up_bps": 0, "rate_limit_down_bps": 12})

    def test_rotation_controls_preserve_revision_and_real_http_status(self):
        for method in (self.api.enable_user, self.api.disable_user, self.api.reset_user_quota, self.api.delete_user, self.api.rotate_secret):
            self.peer.reply({"in_runtime": False}, 202)
            response = method("alice", if_match="source-rev")
            self.assertEqual(response.http_status, 202)
            self.assertEqual(self.peer.requests[-1]["headers"]["if-match"], ["source-rev"])
        self.peer.reply({"secret": "0" * 32})
        self.api.rotate_secret("alice", secret="0" * 32)
        self.assertEqual(self.peer.requests[-1]["body"], {"secret": "0" * 32})

    def test_ready_503_and_web_410_are_data_only_on_the_documented_routes(self):
        for status, method, args, data in [(503, self.api.health_ready, (), {"ready": False}),
                                          (410, self.api.web_session, (SESSION,), {"state": "closed", "reason": "timeout"})]:
            self.peer.reply(data, status)
            response = method(*args)
            self.assertEqual(response.data, data)
            self.assertEqual(response.http_status, status)
            self.peer.reply(data, status)
            with self.assertRaises(TelemtAPIError):
                self.api.health()
        self.peer.raw(b'{"ok":false,"error":{"code":"web_snapshot_busy","message":"busy"}}', 503)
        with self.assertRaises(TelemtAPIError) as raised:
            self.api.health_ready()
        self.assertEqual(raised.exception.code, "web_snapshot_busy")

    def test_error_envelope_retains_details_and_request_id(self):
        details = [{"path": "web.debug", "code": "effective_config_invalid", "message": "retained capacity"}]
        self.peer.raw(json.dumps({"ok": False, "error": {"code": "bad_request", "message": "invalid", "details": details}, "request_id": 42}).encode(), 400)
        with self.assertRaises(TelemtAPIError) as raised:
            self.api.validate_config({})
        error = raised.exception
        self.assertEqual((error.http_status, error.code, error.request_id, error.details), (400, "bad_request", 42, details))
        self.assertEqual(len(self.peer.requests), 1)

    def test_gray_and_malformed_responses_are_structured_errors_without_raw_contents(self):
        for raw in (b"", b"<html>private-source-excerpt</html>", b"[]", b'{"ok":"true"}', b'{"ok":true}'):
            self.peer.raw(raw)
            with self.assertRaises(TelemtAPIError) as raised:
                self.api.health()
            self.assertEqual(raised.exception.code, "invalid_response")
            self.assertEqual(raised.exception.http_status, 200)
            self.assertNotIn("private-source-excerpt", str(raised.exception))

    def test_transport_failure_never_resubmits_a_mutation(self):
        for failure in (URLError("unreachable"), TimeoutError("socket timed out"),
                        RemoteDisconnected("connection closed after submission")):
            with self.subTest(failure=type(failure).__name__), patch("tools.telemt_api.urlopen", side_effect=failure) as request:
                with self.assertRaises(TelemtAPIError) as raised:
                    self.api.reload()
                self.assertIs(raised.exception.__cause__, failure)
                self.assertEqual(request.call_count, 1)
                self.assertEqual(request.call_args.args[0].get_method(), "POST")
        self.assertEqual(self.peer.requests, [])

    def test_documented_python_examples_run_against_the_http_contract(self):
        root = Path(__file__).resolve().parents[2]
        guide = (root / "docs/Architecture/API/PYTHON_CLIENT.md").read_text()
        examples = re.findall(r"^```python\n(.*?)^```", guide, re.M | re.S)
        self.assertEqual(len(examples), 3)
        self.peer.reply({"username": "alice"})
        self.peer.reply({"base_revision": "source", "runtime": {"runtime_match": "publication"}})
        self.peer.reply({"reload": {"reload_id": 7, "config_revision": "target"}}, 202)
        self.peer.reply({"reload_id": 7, "config_revision": "target", "state": "succeeded"})
        self.peer.reply({"runtime": {"runtime_instance": INSTANCE}})
        self.peer.reply({"sessions": [{"session_ref": SESSION}]})
        self.peer.reply({"operation_id": OPERATION}, 202)
        self.peer.reply({"operation_id": OPERATION, "state": "completed"})
        self.peer.reply({"drain": {"operation_id": "wd1.synthetic"}}, 202)
        self.peer.reply({"runtime": {"runtime_instance": INSTANCE}, "operator_lifecycle": {
            "drain": {"operation_id": "wd1.synthetic", "state": "completed"}}})
        namespace = {}
        with patch("tools.telemt_api.TelemtAPI", return_value=self.api):
            for example in examples:
                exec(compile(example, "PYTHON_CLIENT.md", "exec"), namespace)
        self.assertEqual(len(self.peer.requests), 10)
        self.assertEqual(len(self.peer.responses), 0)
        self.assertEqual(self.peer.requests[0]["body"]["quota_period"], None)
        self.assertEqual(self.peer.requests[2]["headers"]["if-runtime-match"], ["publication"])
        self.assertEqual(self.peer.requests[6]["body"]["runtime_instance"], INSTANCE)
        self.assertEqual(self.peer.requests[6]["body"]["selector"]["session_refs"], [SESSION])

    def test_query_and_path_values_cannot_inject_parameters(self):
        self.peer.reply({})
        self.api.web_sessions(user="alice&limit=200", host="a+b.example", ip="::1", cursor=SESSION, limit=1)
        self.assertEqual(parse_qs(urlsplit(self.peer.requests[-1]["path"]).query),
                         {"user": ["alice&limit=200"], "host": ["a+b.example"], "ip": ["::1"], "cursor": [SESSION], "limit": ["1"]})
        self.peer.reply({})
        self.api.get_user("alice?admin=true#fragment")
        self.assertEqual(self.peer.requests[-1]["path"], "/v1/users/alice%3Fadmin%3Dtrue%23fragment")

    def test_state_scopes_nullable_revision_and_unknown_convergence_are_preserved(self):
        data = {"desired_status": "unreadable", "subsystem_convergence": "unknown", "effective": {"fields": []}}
        self.peer.reply(data, revision=None)
        response = self.api.config_state(["web", "access"])
        self.assertIsNone(response.revision)
        self.assertEqual(response.data, data)
        self.assertEqual(parse_qs(urlsplit(self.peer.requests[-1]["path"]).query), {"sections": ["web,access"]})

    def test_invalid_bounds_and_combinations_send_nothing(self):
        cases = [lambda: self.api.reload("instant", timeout_secs=1), lambda: self.api.reload("drain"),
                 lambda: self.api.reload("drain", timeout_secs=3601), lambda: self.api.reload(failure_policy="retry"),
                 lambda: self.api.patch_config({}, timeout_secs=2), lambda: self.api.patch_config([]),
                 lambda: self.api.web_sessions(limit=201), lambda: self.api.web_sessions(session_ref=SESSION, limit=1),
                 lambda: self.api.runtime_tls_fingerprints(0), lambda: self.api.runtime_events_recent(True),
                 lambda: self.api.web_drain(INSTANCE, 0), lambda: self.api.web_close_sessions(INSTANCE, {"kind": "filter"}),
                 lambda: self.api.web_close_sessions(INSTANCE, {"kind": "refs", "session_refs": [SESSION] * 2}),
                 lambda: self.api.web_close_sessions(INSTANCE, {"kind": "all", "user": "alice"}),
                 lambda: self.api.web_close_sessions(INSTANCE, {"kind": "filter", "host": "x" * 70000}),
                 lambda: self.api.config_state([]), lambda: self.api.config_state(["web", "web"]),
                 lambda: self.api.get_user("../alice"), lambda: self.api.patch_user_fields("alice", {"typo": 1})]
        for call in cases:
            with self.subTest(call=call), self.assertRaises(ValueError):
                call()
        self.assertEqual(self.peer.requests, [])

    def test_polling_reaches_every_reload_and_web_terminal_state_without_mutation(self):
        for terminal in ("succeeded", "failed", "rolled_back"):
            for phase in ("accepted", "preparing", "activating", "draining", terminal):
                self.peer.reply({"reload_id": 7, "config_revision": "target", "state": phase})
            response = self.api.wait_reload(7, expected_revision="target", poll_interval=0.001)
            self.assertEqual(response.data["state"], terminal)
        for terminal in ("completed", "cancelled", "failed"):
            for phase in ("queued", "running", terminal):
                self.peer.reply({"operation_id": OPERATION, "state": phase})
            response = self.api.wait_web_operation(OPERATION, poll_interval=0.001)
            self.assertEqual(response.data["state"], terminal)
        self.assertTrue(all(request["method"] == "GET" for request in self.peer.requests))

    def test_drain_polling_preserves_process_and_operation_identity(self):
        for phase in ("draining", "force_closing", "completed"):
            self.peer.reply({"runtime": {"runtime_instance": INSTANCE}, "operator_lifecycle": {"drain": {"operation_id": "wd1.synthetic", "state": phase}}})
        response = self.api.wait_web_drain(INSTANCE, "wd1.synthetic", poll_interval=0.001)
        self.assertEqual(response.data["operator_lifecycle"]["drain"]["state"], "completed")
        self.peer.reply({"runtime": {"runtime_instance": "f" * 32}, "operator_lifecycle": {"drain": {"operation_id": "wd1.synthetic", "state": "completed"}}})
        with self.assertRaises(TelemtAPIError) as raised:
            self.api.wait_web_drain(INSTANCE, "wd1.synthetic")
        self.assertEqual(raised.exception.code, "operation_mismatch")

    def test_polling_rejects_reused_reload_ids_and_unknown_or_malformed_status(self):
        for data, code in [({"reload_id": 7, "config_revision": "different", "state": "succeeded"}, "operation_mismatch"),
                           ({"reload_id": 7, "config_revision": "target", "state": "invented"}, "invalid_response"),
                           (None, "invalid_response")]:
            self.peer.reply(data)
            with self.assertRaises(TelemtAPIError) as raised:
                self.api.wait_reload(7, expected_revision="target")
            self.assertEqual(raised.exception.code, code)

    def test_poll_budget_caps_each_request_and_keeps_last_response(self):
        clock = [0.0]
        def sleep(seconds):
            clock[0] += seconds
        for _ in range(2):
            self.peer.reply({"reload_id": 7, "state": "preparing"})
        with patch("tools.telemt_api.time.monotonic", side_effect=lambda: clock[0]), patch("tools.telemt_api.time.sleep", side_effect=sleep), patch("tools.telemt_api.urlopen", wraps=__import__("urllib.request", fromlist=["urlopen"]).urlopen) as request:
            with self.assertRaises(TelemtAPIError) as raised:
                self.api.wait_reload(7, timeout=0.5, poll_interval=0.3)
            self.assertEqual(raised.exception.code, "poll_timeout")
            self.assertEqual(raised.exception.last_response.data["state"], "preparing")
            self.assertEqual([call.kwargs["timeout"] for call in request.call_args_list], [0.5, 0.2])
        self.assertEqual(len(self.peer.requests), 2)


if __name__ == "__main__":
    unittest.main()
