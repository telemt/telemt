"""Local scripted HTTP peer for wire-contract tests; no live Telemt is required."""

import json
import threading
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class MockAPI:
    def __init__(self):
        self.requests = []
        self.responses = deque()
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def handle_request(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                fixture.requests.append({"method": self.command, "path": self.path,
                    "headers": {key.lower(): self.headers.get_all(key) for key in self.headers},
                    "body": json.loads(raw) if raw else None, "raw": raw})
                if fixture.responses:
                    status, body, media_type = fixture.responses.popleft()
                else:
                    status, body, media_type = 500, b'{"ok":false,"error":{"code":"unscripted","message":"Unexpected request"}}', "application/json"
                self.send_response(status)
                self.send_header("Content-Type", media_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_PATCH = do_DELETE = handle_request

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def reply(self, data=None, status=200, revision="source-revision"):
        self.raw(json.dumps({"ok": True, "data": data, "revision": revision}).encode(), status)

    def raw(self, body, status=200, media_type="application/json"):
        self.responses.append((status, body, media_type))
