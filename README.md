# Ouroboros — Recursive Intelligence Parasite: Threat Model & Defensive Harness

A working implementation of the threat model from
[Operation Ouroboros: The Recursive Intelligence Parasite](https://www.danielkliewer.com/blog/2026-10-23-operation-ouroboros-recursive-intelligence-parasite).

The premise: LLMjacking turns an exposed inference endpoint into a control plane.
Ouroboros asks what happens when an adversary chains the documented components —
exposed endpoints, tool-enabled agents, poisoned retrieval, over-privileged cloud
identities — into one persistent, distributed system.

**This repository is the defensive answer to that question.** It models the
attacker's architecture and implements the boundary that stops it.

## The core claim

The failure in the threat model is not that a model is intelligent. It is that
**there is no authorization boundary between what a model decides and what the
system does.** A loop that pipes model output into `subprocess.run(shell=True)`
is not an AI problem; it is an ordinary missing-authorization-boundary problem
with a novel source of input.

Every layer below exists to insert that boundary.

## Architecture

```
       UNTRUSTED INPUTS
  model output, retrieved docs, tool results
                 |
                 v
       +-------------------+
       |   Authz Gate      |   fail-closed: deny unless explicitly authorized
       +-------------------+
                 |
                 v
       +-------------------+
       |   Detectors       |   injection markers, spend/step/entropy anomalies
       +-------------------+
                 |
                 v
       +-------------------+
       |   Policy Engine   |   classify, score, allow / audit / deny
       +-------------------+
                 |
           permitted only
                 |
                 v
       +-------------------+
       |   Audit Log       |   hash-chained, tamper-evident, append-only
       +-------------------+
                 |
                 v
       +-------------------+
       |   Memory          |   node state, survives restart
       +-------------------+
```

### Layer 1 — `authz.py` (fail-closed gate)

Nothing runs unless authorization is explicit **and** currently valid.
Defaults are deny:

| Env var | Default | Meaning |
|---|---|---|
| `OUROBOROS_AUTHORIZED` | `0` (deny) | master switch; absent means nothing runs |
| `OUROBOROS_DRY_RUN` | `1` | actions are logged, never performed |
| `OUROBOROS_ALLOW_HOSTS` | empty | target allowlist (host or CIDR); empty = deny all |
| `OUROBOROS_MAX_STEPS` | `0` | step budget; `0` means any step is an anomaly |

The allowlist is enforced on resolved hosts, so `evil.127.0.0.1.attacker.test`
does not pass a `127.0.0.1` allow entry. Non-`http(s)` schemes (`file://`,
`gopher://`) are refused, as is any payload that is not a URL at all.

### Layer 2 — `defense/detectors.py`

Two jobs, both measured:

- **Injection detection** over an EICAR-style marker table
  (`fixtures/injection_corpus.py`). A marker is suppressed when it appears in
  *attributed context* — quoted or discussed rather than issued. This is what
  keeps prose like *"'ignore all previous instructions' is a common phrase in
  security research"* from tripping the detector while the imperative form still
  fires. Substring matching alone cannot make that distinction.
- **Resource anomaly detection** — the signals that actually reveal a hijack:
  - `step_budget_anomaly` — a long-running loop is the captured agent's signature
    (100,000 steps, no human approval). Crossing 80% of budget is an alert.
  - `token_spend_anomaly` — the victim's loss is a compute bill. Uses **median
    absolute deviation**, not mean/stdev: a single spike inflates both, so a
    naive z-score scores the spike itself as only mildly unusual and misses it
    (z=2.45 vs the 826 MAD gives). See
    `test_outlier_masks_itself_under_naive_zscore`.
  - `target_entropy_anomaly` — a parasite fans out to thousands of addresses;
    a flat target distribution is the tell.

### Layer 3 — `defense/policy_engine.py`

Classifies each proposed action and rules on it. **Deny is driven by detection,
not by a trivially strict policy** — a permissive policy
(`allow_shell=True, allow_network=True`) still refuses an action whose payload
trips detection at or above `deny_on_verdict`. Unknown actions are denied.

### Layer 4 — `defense/audit.py`

Append-only, hash-chained. Each entry embeds the previous entry's SHA-256, so
editing a past entry, deleting one, or inserting one all break verification.
This is the "independent logs" requirement: the agent can append, but cannot
rewrite history without detection. `verify()` localizes the first break.

### Layer 5 — `defense/retrieval_integrity.py`

RAG poisoning works by altering retrieved ground truth. Two checkable defenses:
canary chunks (known plaintext that must be present and unmodified at read
time) and per-chunk SHA-256 hashes (any content edit invalidates the hash, so
poisoning is detectable even without a canary hit).

## Run it

```bash
python3 -m lab.simulator    # dry-run replay: gate -> detect -> policy -> audit
python3 -m pytest -q         # 33 tests
```

`lab/simulator.py` replays a scripted "brain" through the whole pipeline and
performs **nothing** — no network call, no shell command. It exists to prove the
layers fire and to produce the audit trail. Output on the committed corpus:

```
 #  action   detect    policy   gate      reason
 0  recon    clean     allow    allow
 1  network  clean     allow    allow
 2  shell    clean     allow    allow
 3  shell    high      DENY     allow     detection verdict high
 4  network  critical  DENY     DENY      detection verdict critical; payload is not a URL
 5  shell    clean     allow    allow
allowed=4  denied=2
audit: 6 entries, verify=OK
retrieval: OK (3 chunks, 0 problems)
```

Artifacts land in `lab/out/` (`audit.jsonl`, `memory.json`).

## Test coverage

| Area | Tests |
|---|---|
| `test_authz.py` | default-deny, dry-run default, allowlist scope + suffix-spoof rejection, scheme refusal, non-URL payload, step budget, `require()` raising |
| `test_detectors.py` | every attack fixture flagged, zero benign false positives, attributed-marker suppression, step-budget threshold, MAD spike detection, outlier-masking regression, entropy on flat vs concentrated targets |
| `test_policy.py` | unknown action denied, shell gate, injection overrides permissive policy, read-only allowed, oversize payload |
| `test_audit.py` | chain verifies, append preserves chain, edited entry breaks chain, deleted entry breaks chain |
| `test_retrieval.py` | clean store verifies, hash detects edit, missing canary flagged, snapshot stable |
| `test_simulator.py` | replay runs and verifies, artifacts written, replay is provably dry-run |

Run: `python3 -m pytest -q` → **33 passed**.

## `threat_model/` — non-operational specimen

`threat_model/` holds the *attacker's* modules (`parasite/`, `payloads/`,
`hive/`, `scanners/`, `collector.py`) as a documentation specimen of the
architecture under analysis. They are **not** part of the operational package:
no `__init__.py`, imported by nothing, and `parasite/parasite.py` as written is
the failure mode the defensive layer prevents. Do not wire them into a system.

## References

1. Symantec research, reported by Help Net Security — *Hackers hijack exposed AI
   models to launch cyberattacks at victims' expense*, Oct 23 2026.
2. Pillar Security — *Operation Bizarre Bazaar: first attributed LLMjacking
   campaign with commercial marketplace monetization*, Jan 2026.
3. MITRE ATLAS — adversarial techniques against AI systems.
4. OWASP — *Top 10 for Agentic Applications*.
