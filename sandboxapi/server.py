"""The API: sandbox-api as an actual HTTP service (stdlib only).

POST /detonate  {"name": ..., "kind": ..., "content": ...} -> threat report JSON
POST /triage    same body -> triage row only
GET  /health    -> {"status": "ok", "executed": false}
GET  /samples   -> the synthetic sample set (names + kinds)

Run it:  python main.py serve 8771
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import chamber, report, samples


def make_handler():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _json(self, code: int, obj: dict):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/health":
                self._json(200, {"status": "ok", "executed": False, "network_calls": 0})
            elif self.path == "/samples":
                self._json(200, {"samples": [
                    {"name": s["name"], "kind": s["kind"]} for s in samples.SAMPLES]})
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                self._json(400, {"error": "invalid JSON"})
                return
            if self.path == "/detonate":
                self._json(200, report.build_report(payload))
            elif self.path == "/triage":
                self._json(200, chamber.triage(payload))
            else:
                self._json(404, {"error": "not found"})

    return Handler


def serve(port: int = 8771) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler())
    return server
