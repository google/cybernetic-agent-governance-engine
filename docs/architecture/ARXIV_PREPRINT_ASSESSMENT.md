# CAGE arxiv Preprint Assessment
## Can you write an arxiv preprint on CAGE?

> **Short answer:** Yes — and you have unusually strong raw material. But three blockers must be resolved before submission.

---

## What CAGE has that is genuinely paper-quality

### 1. A machine-verified safety invariant with a counterexample

[`proof/model.py`](../../proof/model.py) exhaustively enumerates **19 reachable states** via BFS and proves:

```
NoDirectBind == (phase = EXECUTED) ⟹ (resolvedAllow = TRUE)
```

The ungated variant produces a concrete counterexample (`phase=EXECUTED, resolvedAllow=False, seal_present=False`). This is not a test — it is a proof over the full state space. Documented in [`docs/technical-report/10-FORMAL-VERIFICATION.md`](../technical-report/10-FORMAL-VERIFICATION.md) §Step 7.

### 2. Formal mathematical foundations already written

[`docs/technical-report/10-FORMAL-VERIFICATION.md`](../technical-report/10-FORMAL-VERIFICATION.md) contains:
- Hybrid automaton `H = (Q, X, Init, f, Dom, E, G, R)` with guard condition `G_actuate` as a LaTeX formula
- Discrete-time CBF invariance theorem with inductive proof sketch (Ames et al. IEEE TAC 2017)
- FiscalLimitGuard race-condition proof: `∀t: S(t) = Σ r_i ≤ L`
- KMS non-repudiation proof chain
- AARM 11-vector neutralization table with logical invariants per vector

### 3. A novel compiler contribution

The STPA-to-Policy compiler ([`src/gateway/governance/stpa_compiler.py`](../../src/gateway/governance/stpa_compiler.py)) eliminates the "Natural Language Tax" between design-time hazard analysis and runtime enforcement. No published paper does this for the STPA → OPA Rego + NeMo Colang + LangGraph Saga pipeline simultaneously. This is the primary novel contribution.

### 4. A novel four-state decision primitive

The ALLOW | DENY | MANUAL_REVIEW | DEFER extension with the Confidence-Starvation Boundary (0.70/0.95) and the three-phase PARK→HYDRATE→REPLAY flow ([`src/gateway/governance/defer_queue.py`](../../src/gateway/governance/defer_queue.py)) is a concrete contribution beyond the standard tri-state policy engine.

### 5. Measured evidence on a live system

1,281 tests on a live GKE cluster, KMS HSM signing in production, 10/11 AARM vectors neutralized with a live conformance API (`GET /v1/aarm/conformance-report`). The paper at arxiv:2606.12320 explicitly says *"a full-system evaluation against a live agent benchmark is the invited next step"* — CAGE is that next step.

---

## Blockers — must resolve before submission

### BLOCKER 1 (Critical): Google LLC copyright vs. "not an officially supported Google product"

Every source file carries `# Copyright 2026 Google LLC` but [`README.md`](../../README.md) states:

> "This is not an officially supported Google product."

For an arxiv preprint you must resolve the institutional affiliation:
- **If personal work:** Change copyright headers; use personal/university affiliation on the paper
- **If Google work:** Requires Google's internal publication approval process (go/pub-approval or equivalent)

This is a legal question. Do not submit until it is resolved.

### BLOCKER 2 (Critical): `proof/model.py` attribution

[`docs/technical-report/10-FORMAL-VERIFICATION.md`](../technical-report/10-FORMAL-VERIFICATION.md) line 287 states:

> "The NoDirectBind TLA+ specification and foundational BFS state-space enumerator were adapted from the open-source implementation by LalaSkye (Apache 2.0). Source: https://github.com/LalaSkye/no-direct-bind"

Before submitting:
1. Verify the repo exists and the license is actually Apache 2.0
2. Confirm what specifically was adapted vs. what is original CAGE work
3. Include proper attribution in the paper's Related Work section
4. If the adaptation is substantial, consider whether co-authorship is appropriate

### BLOCKER 3 (Important): CBF ground truth is self-reported (POAM-023)

The paper would claim formal financial safety guarantees via the CBF, but [`README.md`](../../README.md) explicitly states:

> "The CBF currently reads from Redis state... `AnchorageGrpcLedgerProvider` is tracked as POAM-023 (target: 2026-09-08)."

A reviewer will immediately ask: if the cash balance is self-reported by the agent's own Redis instance, the CBF invariant is only as strong as the Redis write path. You must either:
- Implement `AnchorageGrpcLedgerProvider` before submitting, **or**
- Scope the paper's claims to "the CBF invariant holds given a trusted balance oracle" and treat external reconciliation as explicit future work

---

## Things that weaken the paper (fix if possible)

### The DoWhy causal model falls back to synthetic data on cold-start

[`docs/governance/CAUSAL_AND_CBF_GOVERNANCE.md`](../governance/CAUSAL_AND_CBF_GOVERNANCE.md) states the `MockTelemetryProvider` (deterministic seed=42) activates when fewer than 50 live samples are available. A paper claiming causal world-model validation needs results from the live `LangfuseTelemetryProvider` path. Run a benchmark with ≥50 live samples and report those numbers.

### Adjudication latency is unmeasured

The paper at arxiv:2606.12320 claims single-digit microseconds. You should measure and report CAGE's actual p50/p95/p99 latency for the full 7-tier pipeline on the GKE cluster. "Low-millisecond" is not a publishable claim; "p50=4.2ms, p99=18ms on GKE n2-standard-4" is. The `asyncio.gather` parallelisation is a real contribution — measure it.

### Test count includes skipped tests

The README reports "1,281 passed / 32 skipped / 0 failed." A paper should report only the passing count and explain what the 32 skipped tests cover (EU_ECB region-specific + CI-only latency budget tests).

---

## Recommended paper framing

The strongest angle is **not** "here is another governance framework" — that space is crowded. The strongest angle is:

> **"From Hazard Analysis to Runtime Enforcement: A Compiler-Driven Approach to Agentic AI Governance with Formal Safety Guarantees"**

This positions the STPA compiler as the primary contribution, with the formal proofs as the evaluation. It directly responds to the open problem stated in arxiv:2606.12320.

### Suggested section structure

| § | Title | Primary source |
|---|-------|----------------|
| 1 | Introduction — The Natural Language Tax | [`README.md`](../../README.md) §"The CAGE Product Offering" |
| 2 | Problem Statement — Composite Principals and Workflow-Internal Risk | [`docs/security/STPA_ANALYSIS.md`](../security/STPA_ANALYSIS.md) |
| 3 | Architecture — Seven-Tier Symbolic Governor | [`docs/governance/NEURO_SYMBOLIC_GOVERNANCE.md`](../governance/NEURO_SYMBOLIC_GOVERNANCE.md) |
| 4 | The STPA-to-Policy Compiler | [`src/gateway/governance/stpa_compiler.py`](../../src/gateway/governance/stpa_compiler.py) |
| 5 | Formal Safety Properties | [`docs/technical-report/10-FORMAL-VERIFICATION.md`](../technical-report/10-FORMAL-VERIFICATION.md) |
| 6 | The Four-State Decision Primitive | [`src/gateway/governance/defer_queue.py`](../../src/gateway/governance/defer_queue.py) |
| 7 | Evaluation — Live GKE Cluster Results | Test results + `proof/model.py` output |
| 8 | Related Work | arxiv:2606.12320; OPA; NeMo; STPA literature; CBF literature |
| 9 | Limitations and Future Work | POAM-023; delegation chain; µs latency gap |

---

## Target venues

| Venue | Fit | Notes |
|---|---|---|
| **arxiv cs.CR + cs.AI** (cross-list) | ✅ Strong | Establish priority first; free; immediate |
| **IEEE S&P 2027** | 🟡 Possible | Needs POAM-023 closed |
| **USENIX Security 2027** | 🟡 Possible | Strong on formal proofs; weak on CBF ground truth |
| **ACM CCS 2027** | 🟡 Possible | Same as USENIX |
| **SOSP / EuroSys 2027** | 🟡 Possible | Systems angle; compiler contribution fits |

**Recommendation:** Submit to arxiv (cs.CR + cs.AI cross-list) to establish priority, then revise for a conference submission after closing POAM-023 and collecting latency measurements.

---

## Relationship to arxiv:2606.12320

The paper at arxiv:2606.12320 explicitly states:

> "A full-system evaluation against a live agent benchmark is the invited next step."

CAGE is a direct empirical response to that invitation. The recommended framing is to cite 2606.12320 as the reference architecture and position CAGE as:
1. An independent convergent implementation that validates the paper's core claims
2. A production system that extends the paper with the STPA compiler, four-state primitive, and multi-jurisdiction compliance profiles
3. An empirical evaluation that the paper explicitly called for

This is a stronger position than competing with the paper — it is building on it.

---

*Assessment produced 2026-07-25 against CAGE v0.1.0.*
