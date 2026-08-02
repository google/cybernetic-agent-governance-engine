# CAGE Paper — Measurement Runbook

**Authoritative procedure for regenerating every number in `CAGE_ARXIV.MD`.**

> **Non-negotiables (read before touching any figure):**
> - Every number in §4.4 and §6 must trace to a committed artefact in
>   `docs/paper/measurements/`.
> - Never hand-edit a figure directly in `CAGE_ARXIV.MD`.
> - Never fabricate a value for a skipped component — record
>   `SKIPPED — <reason>` in `PROVENANCE.md` instead (matching the honesty
>   convention already in `scripts/measure_reconciliation_metrics.py`).
> - The workflow is **two-stage**: archive first (Step D), evaluate second
>   (Step E). Only after Step E passes does the paper get patched (Step F).
>   A measurement run that fails Step E must be re-run, not promoted.

---

## Change → re-measurement trigger matrix

| Files changed | Re-run |
|---|---|
| `proof/model.py`, `src/gateway/governance/symbolic_governor.py`, any tier module | Step A (proof) + Step B (latency) |
| `src/gateway/governance/cbf.py`, `src/compliance_bridge/reconciliation_worker.py` | Step C (reconciliation/CBF) |
| `tests/red_team/adversarial_dataset.json`, `tests/red_team/benign_dataset.json` | Step B (deflection + FPR) |
| `config/governance_thresholds.json` | Step B (latency) + Step C (CBF) |
| `scripts/measure_paper_metrics.py` | Step B |
| `scripts/measure_reconciliation_metrics.py` | Step C |
| `scripts/_patch_paper.py` | Step F (verify `[MISS]` count is zero) |
| `docs/technical-report/07-*`, `docs/technical-report/10-*`, `docs/architecture/ARCHITECTURE.md` | Step A blast-radius check (see `REVISION_TRACKER.md`) |

---

## Prerequisites

### 1. Python environment

```bash
uv sync --all-groups --all-extras
```

### 2. Port-forwards (required for Steps B deflection/FPR and Step C)

In a separate terminal, keep running:

```bash
bash scripts/port_forward_dev.sh
```

### 3. Required environment variables

| Variable | Required for | Notes |
|---|---|---|
| `CAGE_ENV` | All steps | Set to `development` |
| `BACKEND_URL` | Step B (deflection/FPR) | Default: `http://localhost:18080` |
| `LATENCY_RUNS` | Step B (latency) | Default: `200`; use `≥200` for paper |
| `KMS_GOVERNANCE_KEY` | Step C (KMS signing) | Full resource path; if unset, KMS section is skipped |
| `REDIS_HOST` / `REDIS_PORT` | Step C (CBF read-path) | Default: `localhost` / `16379` |
| `UNMOCKED` | Step B | Set to `1` for live GKE backend; omit for mocked-I/O |

> **Secret hygiene:** Never paste secret values into this runbook, into a
> results file, or into any committed file. Store secrets in
> `terraform.auto.tfvars` (gitignored) and reference them via
> `secretKeyRef` in Kubernetes manifests. Mask any credential-shaped value
> before logging (`value[:4] + "****"`).

---

## Step A — Deterministic verifications (no cluster needed)

These produce the reachable-state counts for §4.4 and Appendix A. They are
deterministic: the same code always produces the same counts.

```bash
# 1. Run the formal proof enumerator
CAGE_ENV=development uv run python proof/model.py

# 2. Run the pinned proof assertions (18 tests)
CAGE_ENV=development uv run pytest tests/test_no_direct_bind_proof.py -v

# 3. Verify STPA freshness
CAGE_ENV=development uv run python scripts/check_stpa_freshness.py

# 4. Lint and type-check
uv run ruff check src/ scripts/ proof/
uv run mypy src/

# 5. Full verification suite
CAGE_ENV=development uv run python scripts/verify_all.py
```

**Expected state counts** (pinned by `tests/test_no_direct_bind_proof.py`):

| Variant | States | Invariant |
|---|---|---|
| `gated_transitions()` (canonical) | 21 | holds |
| `concurrent_tier_transitions()` (CBF ∥ OPA) | 24 | holds |
| `ungated_transitions()` (Gap 1) | 19 | violated — counterexample produced |
| `no_seal_govern_transitions()` (Gap 2) | 19 | violated |
| `cbf_fail_open_transitions()` (Gap 3) | 20 | holds structurally |
| `dowhy_absent_transitions()` (Gap 4) | 20 | holds structurally |

If any count differs, **stop**. Do not proceed to Step D. Fix `proof/model.py`
and update the blast-radius files listed in `REVISION_TRACKER.md` before
continuing.

---

## Step B — Latency, deflection, FPR

### B1 — Mocked-I/O latency (default; no cluster needed)

Isolates pure governance-logic CPU cost from network jitter. Required for
Table 2 in §6.2.

```bash
CAGE_ENV=development \
LATENCY_RUNS=200 \
  uv run python scripts/measure_paper_metrics.py
```

**Required disclosure sentence** (must appear in §6.2 caption):
> "Latency measured in mocked-I/O mode (Redis, OPA HTTP, and consensus RPC
> replaced with zero-latency AsyncMocks) to isolate pure governance-logic CPU
> cost. End-to-end latency in a deployed system will be dominated by network
> round-trips."

### B2 — Unmocked mode (live GKE backend; optional)

Requires port-forwards active and `BACKEND_URL` pointing at the live gateway.

```bash
CAGE_ENV=development \
UNMOCKED=1 \
BACKEND_URL=http://localhost:18080 \
  uv run python scripts/measure_paper_metrics.py
```

**Required disclosure sentence** (must appear in any table using unmocked data):
> "Latency measured against the live GKE governance stack via port-forward
> (`UNMOCKED=1`). Results include network round-trips to Redis, OPA HTTP, and
> consensus RPC."

### Outputs

Both modes write to:
- `/tmp/cage_paper_metrics.json` — machine-readable
- `/tmp/cage_paper_metrics.txt` — human-readable table summary

---

## Step C — Reconciliation / CBF

Produces `T_reconcile`, CBF read-path Δt, and the safety-violation case for
Tables 3 & 4 and §6.3–6.5.

```bash
export KMS_GOVERNANCE_KEY="projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/1"
export REDIS_HOST=localhost
export REDIS_PORT=16379
export CAGE_ENV=development

uv run python scripts/measure_reconciliation_metrics.py
```

**Mode labels** (must appear in table captions):

| Component | Live mode label | Fallback label |
|---|---|---|
| Plaid fetch | `live_authenticated` | `network_rtt_proxy` |
| KMS signing | measured | `SKIPPED — KMS_GOVERNANCE_KEY not set` |
| Redis SETEX | measured | `SKIPPED — Redis unreachable` |

If a component is skipped, the caption **must** state which component was
skipped and why. Never promote a run where KMS was skipped as a complete
reconciliation measurement.

### Outputs

- `/tmp/cage_reconciliation_metrics.json` — machine-readable
- `/tmp/cage_reconciliation_metrics.txt` — human-readable table summary

---

## Step D — Archive with provenance

Run immediately after Steps A–C complete, before evaluating the results.
This creates a durable, committed record of the raw outputs. It does **not**
touch `CAGE_ARXIV.MD`.

```bash
bash scripts/archive_paper_evidence.sh
```

This script:
1. Reads `/tmp/cage_paper_metrics.json` and `/tmp/cage_reconciliation_metrics.json`.
2. Creates `docs/paper/measurements/<YYYY-MM-DD>-<short-sha>/`.
3. Copies the JSON and TXT files into that directory.
4. Writes `PROVENANCE.md` from `docs/paper/measurements/PROVENANCE_TEMPLATE.md`,
   substituting commit SHA, branch, and timestamp.

The resulting directory must be committed alongside any paper patch (Step F).

---

## Step E — Human evaluation gate (mandatory before patching the paper)

**This step is not automated.** Open the archived `PROVENANCE.md` and the
`.txt` summary files and verify every applicable gate below. A run that fails
any gate must be **re-run**, not promoted.

### Gate checklist

| # | Gate | Pass condition | Failure cause |
|---|---|---|---|
| E1 | C6 consistency | No `⚠️ WARNING` lines in `cage_paper_metrics.txt` | OS scheduler jitter; run again on a quiet machine |
| E2 | FRIA span emitted | `FRIA (Tier 7)` row is **not** `span not emitted` | `CAGE_NORMATIVE_PROVIDER` was unset; set it and re-run |
| E3 | KMS mode | `kms_sign` is **not** `SKIPPED` | `KMS_GOVERNANCE_KEY` not configured; configure and re-run |
| E4 | Plaid mode | `plaid_fetch_mode` is `live_authenticated` | No Plaid credentials; acceptable only if §6.3 caption discloses `network_rtt_proxy` |
| E5 | `n` matches caption | `latency_runs` in JSON matches the value in the paper caption | `LATENCY_RUNS` env var was overridden |
| E6 | Deflection denominator | `deflection.total` matches `len(payloads)` in `adversarial_dataset.json` | Dataset was modified between runs |
| E7 | No skipped components without disclosure | Every `SKIPPED` entry in `PROVENANCE.md` has a corresponding caption note planned | Incomplete run promoted silently |
| E8 | Proof counts match pinned values | State counts in `cage_paper_metrics.json` match the table in Step A | `proof/model.py` was modified without updating the blast-radius files |

> **Gates E3 and E4 are advisory for §6.3 only.** If KMS or Plaid was
> unavailable, the run may still be promoted for §6.2 (latency) and §6.6
> (deflection/FPR) provided the caption for §6.3 discloses the skip.

Sign off by adding your name and the gate results to `PROVENANCE.md` before
proceeding to Step F.

---

## Step F — Patch the paper

Only run this step after Step E passes.

### F1 — Add a replacement block to `_patch_paper.py`

Append a new tuple to the `replacements` list in
[`scripts/_patch_paper.py`](../../scripts/_patch_paper.py). **Never mutate a
historical block** — append only. Each block must include a comment with the
date and the short SHA of the measurement run that produced the numbers.

Example:
```python
# ── 2026-08-01 (sha: abc1234) — Table 2 latency update ──────────────────
("Old table text here",
 "New table text here"),
```

### F2 — Run the patcher and verify zero misses

```bash
uv run python scripts/_patch_paper.py
```

The script exits non-zero if any `[MISS]` line is printed (i.e., a search
string was not found in `CAGE_ARXIV.MD`). Zero `[MISS]` lines is required
before proceeding.

### F3 — Propagate through the blast-radius file list

If the state counts changed (Step A produced different numbers), update all
four blast-radius files listed in `REVISION_TRACKER.md`:

- `docs/technical-report/07-SECURITY-INFRASTRUCTURE.md`
- `docs/technical-report/10-FORMAL-VERIFICATION.md`
- `docs/architecture/ARCHITECTURE.md`
- `CAGE_ARXIV.MD` (already patched by F2)

### F4 — Add a row to `REVISION_TRACKER.md`

Record: finding ID (if applicable), commit SHA, measurement date, which
components were live vs. skipped, and the gate results from Step E.

---

## Step G — Commit & PR

### Commit message format

```
docs(docs): update §6 measurement tables — <short description>
```

For code changes that triggered the re-measurement:

```
feat(governance): <description>
test(tests): update proof assertions for <change>
```

### Branch naming

```
docs/paper-metrics-<YYYY-MM-DD>
```

### Shared-module cross-region impact

If `src/gateway/governance/` or `config/thresholds/` was touched as part of
the change that triggered re-measurement, the PR description **must** include:

1. Impact on US_FED posture (NIST SP 800-53)
2. Impact on EU_ECB posture (GDPR / EU AI Act / DORA)
3. Impact on APAC_MAS posture (MAS FEAT / MAS Notice 655 / MAS TRM)
4. `CAGE_DEPLOYMENT_REGION` guard placement for any new data path

### Merge strategy

Squash merge only. Confirm the pre-filled commit message matches the PR title
and follows Conventional Commits format before merging.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `FRIA (Tier 7)` shows `span not emitted` | `CAGE_NORMATIVE_PROVIDER` not set | `export CAGE_NORMATIVE_PROVIDER=langfuse` before re-running Step B |
| Deflection block empty / all errors | Backend unreachable | Verify port-forwards are active: `bash scripts/port_forward_dev.sh` |
| `KMS permission denied` | IAM role missing | Grant `cloudkms.cryptoKeyVersions.useToSign` to the caller's service account |
| C6 warning fires (`tier P95 > total P95`) | OS scheduler jitter on a loaded machine | Re-run on a quiet machine; do not promote the run |
| `[MISS]` lines in `_patch_paper.py` output | Search string no longer present in `CAGE_ARXIV.MD` | The paper text was already updated; remove or update the stale replacement block |
| `pytest tests/test_no_direct_bind_proof.py` fails | `proof/model.py` state counts changed | Update the proof and all blast-radius files before proceeding |
| Redis connection refused | Port-forward not active or wrong port | `kubectl port-forward svc/redis 16379:6379 -n governance-stack` |
