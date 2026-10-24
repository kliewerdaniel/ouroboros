"""End-to-end dry-run replay: the pipeline produces a verified audit trail."""
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_simulator_runs_and_verifies():
    r = subprocess.run([sys.executable, "-m", "lab.simulator"],
                       cwd=REPO, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "verify=OK" in r.stdout
    assert "denied=2" in r.stdout


def test_simulator_writes_artifacts():
    subprocess.run([sys.executable, "-m", "lab.simulator"], cwd=REPO, capture_output=True)
    out = os.path.join(REPO, "lab", "out")
    assert os.path.exists(os.path.join(out, "audit.jsonl"))
    assert os.path.exists(os.path.join(out, "memory.json"))


def test_simulator_is_dry_run():
    """No network or shell action may be performed by the replay."""
    src = open(os.path.join(REPO, "lab", "simulator.py")).read()
    assert "dry_run=True" in src
    assert "subprocess" not in src.split("SCRIPT:")[0]  # no executor wired in
