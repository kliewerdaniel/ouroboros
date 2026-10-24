"""Expose /metrics and /health over HTTP using only the stdlib.

    OUROBOROS_METRICS_PORT=9102 python3 -m lab.metrics_server

Scrape with:  curl -s localhost:9102/metrics
"""
from __future__ import annotations

import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from defense.metrics import Metrics

DEFAULT_PORT = 9102


class Handler(BaseHTTPRequestHandler):
    metrics: Metrics = Metrics()
    server_version = "ouroboros-metrics/1.0"

    def _send(self, code: int, body: str, ctype: str) -> None:
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        path = self.path.split("?")[0]
        if path == "/metrics":
            self._send(200, self.metrics.render(), "text/plain; version=0.0.4; charset=utf-8")
        elif path == "/health":
            self._send(200, '{"status":"ok"}\n', "application/json")
        else:
            self._send(404, "not found\n", "text/plain; charset=utf-8")

    def log_message(self, fmt: str, *args) -> None:  # quieter logs
        pass


def seed_from_replay(metrics: Metrics) -> None:
    """Populate metrics by running the dry-run replay pipeline in-process."""
    import os as _os
    out_dir = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "out")
    _os.makedirs(out_dir, exist_ok=True)
    audit_path = _os.path.join(out_dir, "audit.jsonl")
    if _os.path.exists(audit_path):
        _os.remove(audit_path)

    from lab.simulator import SCRIPT, build
    guard = build(metrics, out_dir)
    for item in SCRIPT:
        guard.execute(item["action"], item["payload"],
                      lambda p, *a, **k: (_ for _ in ()).throw(AssertionError(p)),
                      step=int(item["step"]))
        metrics.observe("token_spend", int(item["tokens"]))


def serve(port: int = DEFAULT_PORT, seed: bool = False) -> None:
    if seed:
        seed_from_replay(Handler.metrics)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"metrics on http://127.0.0.1:{port}/metrics  (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Ouroboros metrics endpoint")
    ap.add_argument("--port", type=int, default=int(os.getenv("OUROBOROS_METRICS_PORT", DEFAULT_PORT)))
    ap.add_argument("--seed", action="store_true",
                    help="populate by running the dry-run replay before serving")
    args = ap.parse_args()
    serve(args.port, seed=args.seed)
