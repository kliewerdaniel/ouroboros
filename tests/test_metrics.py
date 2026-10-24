"""Metrics: exposition format, label cardinality, no duplicate registration."""
from defense.metrics import Metrics, PROM_AVAILABLE


def test_render_is_prometheus_text_format():
    m = Metrics()
    m.inc_allowed("shell")
    m.inc_denied("shell", "detection verdict high")
    m.observe_finding("M01", "high")
    text = m.render()
    assert 'ouroboros_actions_allowed_total{action="shell"} 1' in text
    assert 'ouroboros_actions_denied_total{action="shell",reason="detection verdict high"} 1' in text
    assert 'ouroboros_detection_findings_total{marker="M01",severity="high"} 1' in text
    assert "# TYPE ouroboros_actions_allowed_total counter" in text


def test_multiple_label_values_do_not_duplicate_series():
    """Two actions must not build two Counters with the same name."""
    m = Metrics()
    for a in ("shell", "network", "shell", "recon"):
        m.inc_allowed(a)
    assert m.render().count("# TYPE ouroboros_actions_allowed_total counter") == 1


def test_two_metrics_instances_do_not_collide():
    a, b = Metrics(), Metrics()
    a.inc_allowed("shell")
    b.inc_allowed("shell")
    assert 'ouroboros_actions_allowed_total{action="shell"} 1' in a.render()
    assert 'ouroboros_actions_allowed_total{action="shell"} 1' in b.render()


def test_repeated_increments_accumulate():
    m = Metrics()
    for _ in range(3):
        m.inc_allowed("shell")
    assert 'ouroboros_actions_allowed_total{action="shell"} 3' in m.render()


def test_histogram_and_gauge_exposed():
    m = Metrics()
    m.observe("token_spend", 120)
    m.observe("token_spend", 96)
    m.set_gauge("audit_entries", 2)
    text = m.render()
    assert "ouroboros_token_spend_count 2" in text
    assert "ouroboros_token_spend_sum 216.0" in text
    assert "ouroboros_audit_entries 2.0" in text


def test_no_payload_in_labels():
    """Payloads must never become label values -- unbounded cardinality."""
    m = Metrics()
    m.inc("actions_denied_total", {"action": "shell", "reason": "x"})
    assert "payload" not in m.render()


def test_prometheus_availability_is_reported():
    assert isinstance(PROM_AVAILABLE, bool)
