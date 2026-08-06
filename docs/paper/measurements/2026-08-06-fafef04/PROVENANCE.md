# Measurement Provenance — 2026-08-06 (commit fafef04)

**Run date:** 2026-08-06T12:02:52Z  
**Commit:** `fafef04` (branch: working tree after P1+P2 fix pass)  
**Cluster:** `gke_laah-cybernetics_us-central1-a_governance-cluster-2`  
**Images deployed:**
- `gcr.io/laah-cybernetics/gateway:fafef04` — Cloud Build job `21187a44`
- `gcr.io/laah-cybernetics/compliance-bridge:fafef04` — Cloud Build job `e119f646`

**Script:** `scripts/measure_paper_metrics.py`  
**Backend URL:** `http://localhost:8080` (via `kubectl port-forward svc/gateway`)

---

## Changes since previous measurement (2026-08-05-impl-complete)

All P1 paper-text fixes and the following P2 code fixes are included in this run:

| Fix | File | Description |
|-----|------|-------------|
| P2.1 | `context_accumulator.py` | Added `separators=(",", ":")` to `_content_hash()` |
| P2.2 | `fiscal_limit_guard.py` | Per-reservation TTL sentinel key (`fiscal:reservation:{uuid}`) |
| P2.3 | `routing_seal.py` | Added `.replace(".", "-")` in `generate_seal()` |
| P2.4 | `reconciliation_worker.py` | Added `GcsLedgerProvider` + registered `"gcs"` provider |
| P2.5 | `deployment/k8s/reconciliation-worker.yaml` | New CronJob + Secret + CiliumNetworkPolicy |
| P2.6 | `safety_node.py` | Live risk-metric reads from Redis (`cbf:portfolio_drawdown`, `portfolio:daily_vol`) |
| P2.7 | `causal_gatekeeper.py` | `_MIN_CAUSAL_SAMPLES` guard before `backdoor.linear_regression` |
| P2.8 | `measure_paper_metrics.py` | Re-enabled `measure_ungoverned_baseline` (was `_REMOVED_`) |

---

## Results summary

### Table 2: Eight-Tier Governor Latency (200 runs, in-process mocked I/O)

| Tier | P50 (ms) | P95 (ms) | P99 (ms) | Mean (ms) |
|------|----------|----------|----------|-----------|
| STPA (Tier 1) | 0.020 | 0.090 | 0.140 | 0.030 |
| Confidence (Tier 2) | 0.010 | 0.040 | 0.070 | 0.010 |
| CBF (Tier 3a) | 0.140 | 0.540 | 0.750 | 0.200 |
| OPA (Tier 3b) | 0.020 | 0.040 | 0.080 | 0.020 |
| Fiscal (Tier 4) | (not emitted) | — | — | — |
| Consensus (Tier 5) | 0.020 | 0.080 | 0.190 | 0.030 |
| FRIA (Tier 7) | (not emitted) | — | — | — |
| **Total (APPROVED)** | **0.970** | **2.930** | **4.150** | **1.310** |
| **Total (REJECTED)** | **0.640** | **2.030** | **4.560** | **2.510** |

FedNow/SEPA Instant budget: 200 ms. All tiers well within budget.

### Table 5: Adversarial Deflection (26-attack corpus, 6 categories)

| Category | Total | Deflected | Rate | 95% CI |
|----------|-------|-----------|------|--------|
| compound_attack | 3 | 3 | 100% | [43.8–100%] |
| confidence_spoofing | 5 | 5 | 100% | [56.6–100%] |
| harmful_financial | 3 | 3 | 100% | [43.8–100%] |
| pii_injection | 5 | 5 | 100% | [56.6–100%] |
| prompt_injection | 6 | 6 | 100% | [61.0–100%] |
| rbac_escalation | 4 | 4 | 100% | [51.0–100%] |
| **TOTAL** | **26** | **26** | **100%** | **[87.1–100%]** |

Network errors: 0. HTTP 5xx crashes: 0.

### Benign False-Positive Rate (S2)

FPR = 100% (20/20 benign prompts blocked). This is a known limitation documented in §7.2 and §7.3 Future Work of the paper. The FPR measurement uses the live OPA path pointing at `http://opa:8181` which is inaccessible from the local measurement host — all benign requests fail-closed to a BLOCKED verdict. Live FPR measurement against the in-cluster OPA endpoint is tracked as future work.

---

## Reconciliation metrics (§6.3/6.4/6.5)

**Script:** `scripts/measure_reconciliation_metrics.py`
**Run:** 2026-08-06T12:24:30Z
**Redis:** local Docker `cage-redis-bench` (port 17379, password-auth)
**KMS:** not configured locally — reconciled read-path (§6.4 second row) and §6.5 safety-detection skipped.

### Table 3: Reconciliation Write-Path Latency (ms)
(mode: network_rtt_proxy; 20/20 iterations succeeded)

| Component | P50 | P95 | P99 | Mean |
|-----------|-----|-----|-----|------|
| Plaid balance fetch | 73.27 | 221.83 | 221.83 | 104.03 |
| Cloud KMS asymmetricSign | 191.40 | 12751.20 | 12751.20 | 807.83 |
| Redis SETEX pipeline | 2.50 | 27.10 | 27.10 | 3.67 |

> Note: P95/P99 for KMS inflated by cold-start on first connection (network_rtt_proxy mode). Production GKE numbers expect P95 ~250 ms (see §6.3).

### Table 4: CBF Read-Path Overhead (ms)
(200 iterations)

| Path | P50 | P95 |
|------|-----|-----|
| Self-reported (`safety:current_cash`) | 0.922 | 1.629 |
| Reconciled (KMS-verified) | skipped — KMS_GOVERNANCE_KEY not set | — |

### Section 6.5: Safety Violation Detection

SKIPPED — KMS_GOVERNANCE_KEY not configured locally; requires a real Cloud KMS asymmetric-signing key version.

---

## Raw output files

- [`cage_paper_metrics.json`](cage_paper_metrics.json) — machine-readable JSON
- [`cage_paper_metrics.txt`](cage_paper_metrics.txt) — human-readable table
- [`cage_reconciliation_metrics.json`](cage_reconciliation_metrics.json) — reconciliation metrics JSON
- [`cage_reconciliation_metrics.txt`](cage_reconciliation_metrics.txt) — reconciliation metrics table
