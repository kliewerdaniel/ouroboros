"""The metrics endpoint, verified over real HTTP in-process."""
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from defense.metrics import Metrics
from lab.metrics_server import Handler, seed_from_replay


@pytest.fixture()
def base_url():
    Handler.metrics = Metrics()
    seed_from_replay(Handler.metrics)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def _get(url):
    try:
        r = urllib.request.urlopen(url, timeout=5)
        return r.status, r.headers.get("Content-Type"), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type"), e.read().decode()


def test_health_endpoint(base_url):
    code, ctype, body = _get(base_url + "/health")
    assert code == 200 and "json" in ctype and "ok" in body


def test_metrics_endpoint_serves_real_series(base_url):
    code, ctype, body = _get(base_url + "/metrics")
    assert code == 200
    assert ctype.startswith("text/plain; version=0.0.4")
    assert 'ouroboros_actions_denied_total{action="shell",reason="detection verdict high"} 1' in body
    assert 'ouroboros_detection_findings_total{marker="M04",severity="critical"} 1' in body
    assert "ouroboros_token_spend_count 6" in body


def test_metrics_content_type_is_scrapeable(base_url):
    _, ctype, _ = _get(base_url + "/metrics")
    assert ctype == "text/plain; version=0.0.4; charset=utf-8"


def test_unknown_path_is_404(base_url):
    code, _, _ = _get(base_url + "/nope")
    assert code == 404


def test_metrics_endpoint_reports_no_execution(base_url):
    """The seeded replay is dry-run, so nothing was executed."""
    _, _, body = _get(base_url + "/metrics")
    assert 'ouroboros_execution_errors_total' not in body
