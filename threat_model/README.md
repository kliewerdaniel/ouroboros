# threat_model/ -- NON-OPERATIONAL SPECIMEN

These modules are a **threat-model specimen**, retained to document what the
Ouroboros architecture describes. They are NOT part of the operational package.

- No `__init__.py` is provided, so nothing here is importable as a package.
- Nothing in `defense/`, `lab/`, or `authz.py` imports from this directory.
- `parasite/parasite.py` as written performs unauthenticated network calls and
  `subprocess.run(shell=True)` on model output. It is the *failure mode* the
  defensive layer exists to prevent. It is not a tool and is not runnable code
  in the supported sense.

The runnable, verifiable artifact is the defensive layer:

    python3 -m lab.simulator     # dry-run replay, audited, nothing executed
    python3 -m pytest -q         # 30 tests over gate/detection/policy/audit

Do not wire anything in this directory into a real system.
