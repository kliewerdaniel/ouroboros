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
                 |
                 v
  +---------------------------+   InferenceGuard: the boundary, wired in
  | gate -> detect -> policy  |   dry-run never reaches the executable
  | -> audit -> metrics       |   /metrics over real HTTP
  +---------------------------+
```

The last box is the deployment shape: `defense/middleware.py` wraps any callable
so nothing runs without passing the pipeline, and `defense/metrics.py` exposes
the decisions for scraping.

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

### Layer 6 — `defense/middleware.py` (the boundary, wired in)

`InferenceGuard.execute(action, payload, fn, step=...)` is the deployment form.
It decides, then either refuses or calls `fn`. The property to assert on is
`Outcome.executed`: in dry-run (the default) it is `False` and `fn` is never
reached. There is no code path to `fn` that skips the gate or the policy engine.

`@guarded("shell", guard)` is the decorator form.

The step budget gates **every** action, not just the ones that fall through to
`step_ok` — see the defect list below.

### Layer 7 — `defense/metrics.py` (observability)

Prometheus exposition with a stdlib-only fallback. The in-memory dicts are
always the source of truth, so `/metrics` works with zero dependencies; when
`prometheus_client` is installed the same increments are mirrored into its
objects, so a scrape and the renderer agree.

Labels stay low-cardinality — `action`, `reason`, `marker`, `severity`. Payloads
are never labels; they would be unbounded cardinality.

`lab/metrics_server.py` serves `/metrics` and `/health` on `127.0.0.1` using only
the stdlib:

```bash
python3 -m lab.metrics_server --seed --port 9102
curl -s localhost:9102/metrics | grep -v '^#'
```

### Layer 8 — `defense/rate_limit.py` (the last check before execution)

Token bucket, per key (`shell`, `inference:tenant-a`, `network:10.0.0.0/8`). Checked
immediately before execution, so an over-budget caller is refused without ever
reaching `fn`.

Two properties matter more than the algorithm:

- **Misconfiguration must not open the gate.** `rate<=0` or `capacity<=0` is a
  DENY, not "unlimited" — a fat-fingered config gets a shut door, not an
  unbounded loop.
- **Denial is attributable.** The decision carries `remaining` and `retry_after`.

### Layer 9 — `defense/inference.py` (the boundary on a live call)

`InferenceEndpoint` speaks real HTTP — Ollama `/api/generate` or OpenAI-compatible
`/v1/chat/completions`. `GuardedInference.respond(prompt)` puts the guard in front
of it, so a prompt is only sent if it passes gate, detection, policy and rate
limiting, and **the model's response is scanned on the way back in**.

```python
endpoint = InferenceEndpoint("http://127.0.0.1:11434/api/generate", model="qwen3:4b")
gi = GuardedInference(endpoint, guard)
out = gi.respond("Reply with exactly: OUROBOROS-LIVE-OK")
```

Verified against a live local Ollama: dry-run and denied prompts made **0** HTTP
calls; the live path returned the model's text. Run it:

```bash
python3 -m lab.live_check     # skips cleanly if no endpoint is answering
```

### Layer 10 — Witness anchoring (the truncation defense)

Hash chaining proves the chain is **internally consistent** — which a
truncated-and-re-derived chain also is. That is a real gap, not a theoretical
one:

```
after truncation: 4 entries, head=444211f106fc1c3d
  plain verify:    ok=True   <-- chain is internally consistent
  witness verify:  ok=False
                   reason=anchored head 7e090780e84e not in chain -- log truncated or replaced
```

The fix is to publish the head to a sink the node cannot rewrite.
`verify_with_witness(w)` compares the anchored head against the chain; if it is
no longer reachable, entries were removed. `InferenceGuard` anchors automatically
when given a witness.

`FileWitness` is same-host (defends against accidental loss, not a compromised
box). `CallbackWitness` ships the head to WORM storage or a ledger — that is the
deployment that actually defeats a compromised node.

### Layer 11 — Signed entries (a different threat)

`SignedAuditLog` adds an HMAC the verifier recomputes. This does **not** replace
the witness — it covers a different attacker: one who can tamper with the file
but does not hold the signing key. If the key lives on the node, a compromised
node can re-sign; pair the two.

Demonstrated: an attacker who edits an early entry *and* rebuilds the hash chain
defeats the hash layer entirely (`AuditLog.verify()` passes). Only the signature
still fails.

### Layer 12 — `defense/vector_guard.py` (integrity over a real store)

SQLite-backed chunk store where every chunk carries `SHA-256(source, text)`,
verified on read. A tampered chunk **raises** rather than being returned, and
canary chunks must be present and unmodified.

The tamper tests write with raw SQL, bypassing the wrapper — because that is the
attack, and it is why verification cannot live only in the wrapper.

## Run it

```bash
python3 -m lab.simulator              # dry-run replay: gate -> detect -> policy -> audit -> metrics
python3 -m pytest -q                   # 55 tests
python3 -m lab.metrics_server --seed   # /metrics + /health on 127.0.0.1:9102
python3 -m lab.live_check              # live inference through the guard (skips if no endpoint)
```

Runs on the Python standard library alone. `prometheus_client` is optional.

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
| `test_middleware.py` | dry-run never invokes the executable, deny paths, `on_deny="raise"`, execution only when dry-run off, step budget blocks execution, decorator form, every decision audited, null-audit default, deny metric carries the real cause |
| `test_metrics.py` | exposition format, TYPE once per family, no duplicate series across label values or instances, accumulation, gauge/histogram, no payload in labels |
| `test_metrics_server.py` | `/health` 200 JSON, `/metrics` 200 with scrape content-type and real series, unknown path 404, seeded replay reports no execution |
| `test_rate_limit.py` | capacity then deny, independent per-key budgets, refill over time, misconfiguration fails closed, retry_after, concurrent access admits exactly capacity |
| `test_inference.py` | dry-run makes zero HTTP calls, denied prompt makes zero calls, live path returns model text, response scanned on the way back, scanning can be disabled, string format coerced, missing url rejected, OpenAI format parses, rate limit blocks the call |
| `test_audit_witness.py` | truncated re-derived chain passes plain verify (the gap), witness catches it, anchored chain accepted, no-anchor is not a failure, witness-unavailable reported, file witness roundtrip, signature rejects re-derived chain without the key, wrong key, unsigned entry, signed log survives reopen |
| `test_vector_guard.py` | roundtrip, clean store verifies, raw-SQL tamper detected on read and by verify, search raises, clean search, missing canary, canary modification, snapshot hash-bound, hash covers source and text, context manager, persistence across connections |
| `test_simulator.py` | replay runs and verifies, artifacts written, replay is provably dry-run |

Run: `python3 -m pytest -q` → **95 passed**.

## Defects the tests caught

Worth recording, because each one is a real failure mode rather than a nitpick:

1. **Step budget bypassed for shell and network actions.** `execute` computed
   `step_ok` then overwrote `gate_ok` with `authorize_command()` /
   `authorize_target()`, neither of which consults the budget. A shell command at
   step 100,000 with `max_steps=1` was permitted *and executed* — exactly the
   unbounded-loop signature from the Symantec report. Now folded into the final
   conjunction.
2. **Deny metric mislabelled.** On denial the metric recorded `ruling.reason`,
   which reads `"shell permitted"` when the gate is what refused. An operator
   would read it as the opposite of what happened. Now records the real cause.
3. **`setdefault(k, Histogram(...))` double-registered.** `setdefault` evaluates
   its default eagerly, so a duplicate series was built on every call. Now
   check-then-create, with a per-instance registry so two `Metrics` objects in
   one process do not collide.
4. **Counter per label value.** `_inc` keyed prometheus objects by label-value
   tuple, so each new `action=` built a second `Counter` with the same name.
   Counters are now created once per metric name; `.labels()` selects the child.
5. **`# TYPE` emitted per series.** Invalid Prometheus text format — HELP/TYPE
   must appear once per metric family.
6. **Injection false positive.** Substring matching flagged prose *about*
   instructions. Attributed-context suppression fixes it (see Layer 2).
7. **Outlier masking in spend detection.** Mean/stdev scored the spike's own
   z-score as 2.45, under threshold. Switched to MAD (z=826).
8. **Inference wire format silently mismatched.** `generate` compared
   `self.fmt is InferenceFormat.OLLAMA`; passing the bare string `"ollama"` made
   that `False`, so it sent an Ollama-shaped body to an OpenAI-shaped parser.
   Caught by the live check against real Ollama, not by reading. Now coerced in
   `__post_init__`, and the annotation admits `InferenceFormat | str`.
9. **Redundant deny reasons.** `authorize_command` and `authorize_step` both
   emit "not authorized", so one refusal read as two causes. Deduplicated while
   preserving order.
10. **The audit log's truncation gap** (design, not a bug): hash chaining cannot
    detect a log that was shortened and re-derived, because the result is still
    internally consistent. Closed by witness anchoring — the head is published
    to a sink the node cannot rewrite, so a shorter replacement chain is
    detectable. Demonstrated in `tests/test_audit_witness.py`.
11. **Signature layer is not a substitute for the witness.** `SignedAuditLog`
    stops an attacker without the key, but a node holding the key can re-sign.
    The two cover different threats and belong together.

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
