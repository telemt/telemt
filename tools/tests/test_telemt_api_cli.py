import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from tools.telemt_api_cli import main
from http_fixture import MockAPI


INSTANCE = "0123456789abcdef0123456789abcdef"
SESSION = f"ws1.{INSTANCE}.0000000000000001"
OPERATION = f"wo1.{INSTANCE}.0000000000000001"


class CLITests(unittest.TestCase):
    def setUp(self):
        self.peer = MockAPI().__enter__()
        self.addCleanup(self.peer.__exit__, None, None, None)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def run_cli(self, arguments, stdin=""):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors), patch("sys.stdin", io.StringIO(stdin)):
            try:
                code = main(["--url", self.peer.url, "--auth", "Bearer synthetic-test", "--json-output", *arguments])
            except SystemExit as error:
                code = error.code
        return code, output.getvalue(), errors.getvalue()

    def json_file(self, value):
        path = Path(self.directory.name) / "request.json"
        path.write_text(json.dumps(value))
        return str(path)

    def test_user_patch_sends_explicit_zero_false_and_null(self):
        self.peer.reply({"username": "alice", "enabled": False}, 202)
        result = self.run_cli(["patch", "alice", "--quota", "0", "--disabled", "--clear", "quota_period",
                               "--rate-up", "0", "--rate-down", "10", "--if-match", "source"])
        self.assertEqual(result[0], 0, result[2])
        self.assertEqual(json.loads(result[1])["http_status"], 202)
        self.assertEqual(self.peer.requests[-1]["body"], {"data_quota_bytes": 0, "enabled": False, "quota_period": None,
                                                        "rate_limit_up_bps": 0, "rate_limit_down_bps": 10})
        self.assertEqual(self.peer.requests[-1]["headers"]["if-match"], ["source"])

    def test_patch_exact_json_from_stdin_and_ambiguous_inputs_are_rejected(self):
        body = {"expiration_rfc3339": None, "enabled": False}
        self.peer.reply({})
        self.assertEqual(self.run_cli(["patch", "alice", "--json", "-"], json.dumps(body))[0], 0)
        self.assertEqual(self.peer.requests[-1]["body"], body)
        for arguments in (["patch", "alice", "--json", "-", "--quota", "1"],
                          ["patch", "alice", "--quota", "0", "--clear", "data_quota_bytes"],
                          ["patch", "alice", "--clear", "quota_period", "--clear", "quota_period"],
                          ["patch", "alice"], ["config-patch", "--json", "-"],
                          ["web-close", "--selector", "-"], ["reload", "--wait", "--wait-timeout", "0"]):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.run_cli(arguments, "[]")[0], 2)
        self.assertEqual(len(self.peer.requests), 1)

    def test_config_validation_and_commit_preserve_headers_and_policy(self):
        body = {"general": {"me_keepalive_enabled": False}, "web": {"vhosts": []}}
        path = self.json_file(body)
        for command in ("validate", "config-patch"):
            self.peer.reply({"valid": True, "reload": None})
            result = self.run_cli([command, "--json", path, "--if-match", '"rev"', "--if-runtime-match", "opaque",
                                   "--reload", "drain", "--timeout-secs", "12", "--failure-policy", "rollback"])
            self.assertEqual(result[0], 0, result[2])
            request = self.peer.requests[-1]
            self.assertEqual(request["body"], body)
            self.assertEqual(request["headers"]["if-match"], ['"rev"'])
            self.assertEqual(request["headers"]["if-runtime-match"], ["opaque"])
            self.assertEqual(parse_qs(urlsplit(request["path"]).query), {"reload": ["drain"], "timeout_secs": ["12"], "failure_policy": ["rollback"]})

    def test_reload_waits_for_terminal_state_and_reports_failure(self):
        self.peer.reply({"reload_id": 7, "config_revision": "target", "state": "accepted"}, 202)
        self.peer.reply({"reload_id": 7, "config_revision": "target", "state": "draining"})
        self.peer.reply({"reload_id": 7, "config_revision": "target", "state": "rolled_back", "error": "synthetic failure"})
        result = self.run_cli(["reload", "--mode", "drain", "--timeout-secs", "10", "--failure-policy", "rollback", "--wait", "--poll-interval", "0.001"])
        self.assertEqual(result[0], 1, result[2])
        self.assertEqual(json.loads(result[1])["data"]["state"], "rolled_back")
        self.assertEqual([request["method"] for request in self.peer.requests], ["POST", "GET", "GET"])
        self.assertEqual(self.peer.requests[0]["body"], {"mode": "drain", "timeout_secs": 10, "failure_policy": "rollback"})

    def test_config_wait_only_polls_an_operation_actually_accepted(self):
        self.peer.reply({"reload": {"reload_id": 9, "config_revision": "target"}}, 202)
        self.peer.reply({"reload_id": 9, "config_revision": "target", "state": "succeeded"})
        result = self.run_cli(["config-patch", "--json", "-", "--reload", "instant", "--wait"], '{}')
        self.assertEqual(result[0], 0, result[2])
        self.assertEqual([request["path"] for request in self.peer.requests], ["/v1/config?reload=instant", "/v1/system/reload/9"])
        self.peer.reply({"process_restart_required": True})
        self.assertEqual(self.run_cli(["config-patch", "--json", "-", "--wait"], '{}')[0], 0)
        self.assertEqual(len(self.peer.requests), 3)

    def test_web_controls_use_exact_media_type_and_caller_process_reference(self):
        cases = [("web-debug-clear", [], "/debug/clear"), ("web-learning-reset", [], "/carrier-learning/reset"),
                 ("web-pause", [], "/lifecycle/pause"), ("web-resume", [], "/lifecycle/resume"),
                 ("web-drain", ["--timeout-secs", "30"], "/lifecycle/drain"),
                 ("web-close", ["--selector", "-"], "/sessions/close")]
        for command, options, suffix in cases:
            self.peer.reply({"state": "accepted"}, 202 if command in ("web-drain", "web-close") else 200)
            result = self.run_cli([command, "--runtime-instance", INSTANCE, *options], '{"kind":"refs","session_refs":["' + SESSION + '"]}')
            self.assertEqual(result[0], 0, result[2])
            request = self.peer.requests[-1]
            self.assertEqual(request["headers"]["content-type"], ["application/json"])
            self.assertEqual(request["path"], "/v1/runtime/web" + suffix)
            self.assertEqual(request["body"]["runtime_instance"], INSTANCE)

    def test_web_close_wait_and_cancelled_drain_wait(self):
        self.peer.reply({"operation_id": OPERATION, "state": "queued"}, 202)
        self.peer.reply({"operation_id": OPERATION, "state": "completed"})
        result = self.run_cli(["web-close", "--runtime-instance", INSTANCE, "--selector", "-", "--wait"], '{"kind":"all"}')
        self.assertEqual(result[0], 0, result[2])
        self.assertEqual(self.peer.requests[-1]["path"], "/v1/runtime/web/operations/" + OPERATION)
        self.peer.reply({"drain": {"operation_id": "wd1.synthetic", "state": "draining"}}, 202)
        self.peer.reply({"runtime": {"runtime_instance": INSTANCE}, "operator_lifecycle": {"drain": {"operation_id": "wd1.synthetic", "state": "cancelled"}}})
        result = self.run_cli(["web-drain", "--runtime-instance", INSTANCE, "--timeout-secs", "10", "--wait"])
        self.assertEqual(result[0], 1, result[2])
        self.assertEqual(self.peer.requests[-1]["path"], "/v1/runtime/web/status")

    def test_readiness_503_is_failure_but_retained_tombstone_is_readable(self):
        self.peer.reply({"ready": False, "reason": "admission_closed"}, 503)
        code, output, errors = self.run_cli(["ready"])
        self.assertEqual(code, 1, errors)
        self.assertEqual(json.loads(output)["http_status"], 503)
        self.peer.reply({"state": "closed", "reason": "timeout"}, 410)
        code, output, errors = self.run_cli(["web-session", SESSION])
        self.assertEqual(code, 0, errors)
        self.assertEqual(json.loads(output)["http_status"], 410)

    def test_error_details_are_visible_and_transport_does_not_retry_mutations(self):
        self.peer.raw(b'{"ok":false,"error":{"code":"runtime_conflict","message":"stale","details":[{"path":"$","code":"runtime_conflict","message":"retry preview"}]},"request_id":9}', 409)
        code, output, errors = self.run_cli(["config-patch", "--json", "-"], '{}')
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertIn("runtime_conflict", errors)
        self.assertIn("retry preview", errors)
        self.assertIn("request_id=9", errors)
        self.assertEqual(len(self.peer.requests), 1)

    def test_missing_accepted_metadata_does_not_trigger_a_new_mutation(self):
        for args, stdin in [(["reload", "--wait"], ""),
                            (["config-patch", "--json", "-", "--wait"], '{}'),
                            (["web-close", "--runtime-instance", INSTANCE, "--selector", "-", "--wait"], '{"kind":"all"}'),
                            (["web-drain", "--runtime-instance", INSTANCE, "--timeout-secs", "10", "--wait"], "")]:
            self.peer.reply({}, 202)
            code, _, errors = self.run_cli(args, stdin)
            self.assertEqual(code, 1, errors)
            self.assertIn("invalid_response", errors)
        self.assertEqual(len(self.peer.requests), 4)

    def test_new_read_commands_send_their_documented_query_scope(self):
        for args, path, query in [(["capabilities"], "/v1/capabilities", {}),
                                 (["schema"], "/v1/config/schema", {}),
                                 (["config"], "/v1/config", {}),
                                 (["config-state", "--sections", "web,access"], "/v1/config/state", {"sections": ["web,access"]}),
                                 (["quota"], "/v1/stats/users/quota", {}),
                                 (["active-ips"], "/v1/stats/users/active-ips", {}),
                                 (["tls-fingerprints", "--limit", "1"], "/v1/runtime/tls-fingerprints", {"limit": ["1"]}),
                                 (["web-sessions", "--limit", "1", "--user", "a&b"], "/v1/runtime/web/sessions", {"limit": ["1"], "user": ["a&b"]}),
                                 (["web-operation", OPERATION], "/v1/runtime/web/operations/" + OPERATION, {}),
                                 (["reload-status", "7"], "/v1/system/reload/7", {})]:
            self.peer.reply({})
            result = self.run_cli(args)
            self.assertEqual(result[0], 0, result[2])
            request = self.peer.requests[-1]
            self.assertEqual(request["method"], "GET")
            self.assertEqual(urlsplit(request["path"]).path, path)
            self.assertEqual(parse_qs(urlsplit(request["path"]).query), query)

    def test_global_options_work_on_either_side_of_the_command(self):
        self.peer.reply({"status": "ok"})
        self.assertEqual(self.run_cli(["health", "--url", self.peer.url, "--auth", "Bearer later", "--timeout", "0.5"])[0], 0)
        self.assertEqual(self.peer.requests[-1]["headers"]["authorization"], ["Bearer later"])
        self.peer.reply({"status": "ok"})
        self.assertEqual(self.run_cli(["health"])[0], 0)
        self.assertEqual(self.peer.requests[-1]["headers"]["authorization"], ["Bearer synthetic-test"])

    def test_old_command_names_and_actual_script_and_module_entrypoints(self):
        for invocation in ([sys.executable, "tools/telemt_api.py"], [sys.executable, "-m", "tools.telemt_api"]):
            self.peer.reply({"status": "ok"})
            result = subprocess.run([*invocation, "health", "--url", self.peer.url, "--json-output"],
                                    capture_output=True, text=True, timeout=5,
                                    cwd=Path(__file__).resolve().parents[2], env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["data"], {"status": "ok"})
        for command, options, expected in [("create", ["alice", "--quota-period", "daily", "--disabled"], "/v1/users"),
                                            ("secret", ["alice"], "/v1/users/alice/rotate-secret"),
                                            ("enable", ["alice"], "/v1/users/alice/enable"),
                                            ("disable", ["alice"], "/v1/users/alice/disable"),
                                            ("reset-quota", ["alice"], "/v1/users/alice/reset-quota")]:
            self.peer.reply({"user": {"username": "alice"}})
            self.assertEqual(self.run_cli([command, *options])[0], 0)
            self.assertEqual(self.peer.requests[-1]["path"], expected)


if __name__ == "__main__":
    unittest.main()
