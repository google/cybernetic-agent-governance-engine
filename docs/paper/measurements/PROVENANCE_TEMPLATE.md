# Measurement Provenance

> Copy this file into `docs/paper/measurements/<YYYY-MM-DD>-<short-sha>/PROVENANCE.md`
> and fill in every field. Fields marked **[REQUIRED]** must be completed before
> Step F (paper patch) may proceed. Fields marked [optional] may be left blank
> if not applicable.

---

## Run identity

| Field | Value |
|---|---|
| Commit SHA (full) | <!-- e.g. a1b2c3d4e5f6... --> |
| Short SHA | <!-- e.g. a1b2c3d --> |
| Branch | <!-- e.g. docs/paper-metrics-2026-08-01 --> |
| Measurement date (UTC) | <!-- e.g. 2026-08-01T14:32:00Z --> |
| Operator | <!-- GitHub username or name --> |

---

## Cluster / environment

| Field | Value |
|---|---|
| Target | <!-- e.g. GKE governance-cluster-2, us-central1-a --> |
| Node type | <!-- e.g. e2-standard-4 --> |
| Kubernetes version | <!-- e.g. v1.35.6-gke.1127000 --> |
| GCP project | <!-- e.g. laah-cybernetics --> |
| `CAGE_ENV` | <!-- development / test --> |

---

## Step A — Proof / deterministic verifications

| Variant | Reachable states | Invariant | Notes |
|---|---|---|---|
| `gated_transitions()` | <!-- 21 expected --> | <!-- holds --> | |
| `concurrent_tier_transitions()` | <!-- 24 expected --> | <!-- holds --> | |
| `ungated_transitions()` (Gap 1) | <!-- 19 expected --> | <!-- violated --> | |
| `no_seal_govern_transitions()` (Gap 2) | <!-- 19 expected --> | <!-- violated --> | |
| `cbf_fail_open_transitions()` (Gap 3) | <!-- 20 expected --> | <!-- holds structurally --> | |
| `dowhy_absent_transitions()` (Gap 4) | <!-- 20 expected --> | <!-- holds structurally --> | |

`pytest tests/test_no_direct_bind_proof.py` result: <!-- PASSED / FAILED -->

STPA freshness check result: <!-- PASSED / FAILED -->

---

## Step B — Latency / deflection / FPR

### Latency

| Field | Value |
|---|---|
| Mode | <!-- mocked / unmocked --> |
| `LATENCY_RUNS` (`n`) | <!-- e.g. 200 --> |
| `BACKEND_URL` | <!-- e.g. http://localhost:18080 --> |
| `UNMOCKED` | <!-- 0 / 1 --> |
| `CAGE_NORMATIVE_PROVIDER` | <!-- e.g. langfuse / static / (unset) --> |
| FRIA span emitted? | <!-- yes / no (span not emitted) --> |
| C6 consistency warnings? | <!-- none / list warnings --> |

### Adversarial deflection

| Field | Value |
|---|---|
| Dataset file | <!-- e.g. tests/red_team/adversarial_dataset.json --> |
| Dataset SHA-256 | <!-- sha256sum output --> |
| Total payloads (`n`) | <!-- e.g. 21 --> |
| Overall deflection rate | <!-- e.g. 100.0% --> |
| Errors (network) | <!-- e.g. 0 --> |

### Benign FPR

| Field | Value |
|---|---|
| Dataset file | <!-- e.g. tests/red_team/benign_dataset.json --> |
| Dataset SHA-256 | <!-- sha256sum output --> |
| Total payloads (`n`) | <!-- e.g. 20 --> |
| False positive rate | <!-- e.g. 0.0% --> |
| Errors (network) | <!-- e.g. 0 --> |

---

## Step C — Reconciliation / CBF

| Component | Mode | Notes |
|---|---|---|
| Plaid fetch | <!-- live_authenticated / network_rtt_proxy --> | |
| KMS signing | <!-- measured / SKIPPED — KMS_GOVERNANCE_KEY not set --> | |
| Redis SETEX | <!-- measured / SKIPPED — Redis unreachable --> | |
| `N_ITERATIONS` | <!-- e.g. 20 --> | |
| `N_ITERATIONS_FAST` (CBF read) | <!-- e.g. 200 --> | |

---

## Step E — Human evaluation gate results

**[REQUIRED]** Complete before proceeding to Step F.

| Gate | Result | Notes |
|---|---|---|
| E1 — No C6 warnings | <!-- PASS / FAIL --> | |
| E2 — FRIA span emitted | <!-- PASS / FAIL / N/A --> | |
| E3 — KMS mode not SKIPPED | <!-- PASS / FAIL / advisory --> | |
| E4 — Plaid mode live_authenticated | <!-- PASS / FAIL / advisory --> | |
| E5 — `n` matches paper caption | <!-- PASS / FAIL --> | |
| E6 — Deflection denominator matches dataset | <!-- PASS / FAIL --> | |
| E7 — No undisclosed skips | <!-- PASS / FAIL --> | |
| E8 — Proof counts match pinned values | <!-- PASS / FAIL --> | |

**Overall gate result:** <!-- PASS / FAIL -->

**Operator sign-off:** <!-- name, date -->

> If any gate FAILS, do not proceed to Step F. Re-run the affected step and
> archive a new provenance directory.

---

## Skipped components and required caption disclosures

<!-- List every SKIPPED component and the exact caption text that must appear
     in the paper to disclose the skip. Leave blank if nothing was skipped. -->

| Component | Skip reason | Required caption disclosure |
|---|---|---|
| | | |

---

## Archived files

| File | SHA-256 |
|---|---|
| `cage_paper_metrics.json` | <!-- sha256sum output --> |
| `cage_paper_metrics.txt` | <!-- sha256sum output --> |
| `cage_reconciliation_metrics.json` | <!-- sha256sum output --> |
| `cage_reconciliation_metrics.txt` | <!-- sha256sum output --> |

---

## Patch applied

| Field | Value |
|---|---|
| `_patch_paper.py` replacement block date | <!-- e.g. 2026-08-01 --> |
| `[MISS]` count after patch | <!-- must be 0 --> |
| Blast-radius files updated | <!-- list files, or "N/A — state counts unchanged" --> |
| `REVISION_TRACKER.md` row added | <!-- yes / no --> |
