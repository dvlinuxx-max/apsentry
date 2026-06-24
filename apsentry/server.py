"""Built-in dashboard: a threaded HTTP server exposing a JSON API and the UI."""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from .baseline import Baseline
from .models import AccessPoint
from .monitor import Monitor
from .state import MonitorState

_UI_DIR = os.path.join(os.path.dirname(__file__), "ui")
_STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}


def _make_handler(monitor: Monitor, state: MonitorState, baseline: Baseline):
    class Handler(BaseHTTPRequestHandler):
        server_version = "apsentry"

        def log_message(self, *args):
            pass

        def _json(self, obj, code: int = 200):
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _static(self, fname: str, ctype: str):
            path = os.path.join(_UI_DIR, fname)
            try:
                with open(path, "rb") as f:
                    body = f.read()
            except OSError:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if not length:
                return {}
            try:
                return json.loads(self.rfile.read(length).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return {}

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path in _STATIC:
                return self._static(*_STATIC[path])
            if path == "/api/state":
                return self._json(state.snapshot())
            if path == "/api/scan":
                monitor.run_once()
                return self._json(state.snapshot())
            if path == "/api/export":
                return self._json([a.to_dict() for a in state.aps.values()])
            self.send_error(404)

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            data = self._read_json()
            if path == "/api/baseline/learn":
                for ap in state.aps.values():
                    baseline.add(ap)
                baseline.save()
                return self._json({"ok": True, "trusted": len(baseline)})
            if path == "/api/baseline/add":
                bssid = (data.get("bssid") or "").lower()
                ap = state.aps.get(bssid)
                if ap:
                    baseline.add(ap)
                    baseline.save()
                    return self._json({"ok": True, "trusted": len(baseline)})
                return self._json({"ok": False, "error": "unknown bssid"}, 404)
            if path == "/api/baseline/remove":
                bssid = (data.get("bssid") or "").lower()
                ok = baseline.remove(bssid)
                baseline.save()
                return self._json({"ok": ok, "trusted": len(baseline)})
            if path == "/api/baseline/clear":
                baseline.entries.clear()
                baseline.save()
                return self._json({"ok": True, "trusted": 0})
            self.send_error(404)

    return Handler


def run_server(monitor: Monitor, state: MonitorState, baseline: Baseline,
               host: str = "127.0.0.1", port: int = 8787) -> None:
    monitor.run_once()           # populate before first paint
    monitor.start_background()
    httpd = ThreadingHTTPServer((host, port), _make_handler(monitor, state, baseline))
    print(f"apsentry dashboard: http://{host}:{port}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()
        httpd.shutdown()
