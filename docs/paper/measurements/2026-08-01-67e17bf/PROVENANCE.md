# Measurement Provenance

**Commit SHA (short):** 67e17bf
**Branch:** fix/proof-model-fria-tier
**Timestamp (UTC):** 2026-08-01T02:37:30Z (first archived attempt); additional attempts through 2026-08-01T10:12:46Z
**Operator:** automated verification pass (Roo Code session), reviewed by user

## Files archived (first attempt — see "Final status" below for disposition)

| File | SHA-256 |
|---|---|
| `cage_paper_metrics.json` | `fddea2a32dbd6d27983aa998c8ef702725ff3e327019fab00f0863a8f2e414d` |
| `cage_paper_metrics.txt` | `c0e8d0ebce02d33e27cf670d0bdf994c4eacfc3b9791fb9e231b51ad97c224e` |
| `cage_reconciliation_metrics.json` | NOT PRESENT — Step C not run this session |
| `cage_reconciliation_metrics.txt` | NOT PRESENT — Step C not run this session |

**Note on archive tooling:** `scripts/archive_paper_evidence.sh` failed on this macOS host with
`declare: -A: invalid option` because the default `/bin/bash` on this machine is bash 3.2
(no associative-array support). Files were copied and hashed manually as a workaround. This is
a latent portability bug in the archive script — it should be updated to avoid `declare -A` or
to require bash ≥4 (e.g. via a `#!/usr/bin/env bash` shebang plus a version check), tracked as a
follow-up.

## Run configuration

| Variable | Value |
|---|---|
| `CAGE_ENV` | development |
| `LATENCY_RUNS` | 200 |
| `BACKEND_URL` | http://localhost:18080 (kubectl port-forward → `governed-financial-advisor` svc, `governance-cluster-2`, `us-central1-a`) |
| `UNMOCKED` | False (Table 2 latency remains mocked-I/O, in-process) |
| `REQUEST_TIMEOUT_S` | 90 (raised from the previous hardcoded 30s) |
| `CAGE_NORMATIVE_PROVIDER` | (unset) — FRIA span not emitted, consistent with prior runs |

## Step A — Proof enumeration

Not re-run in this session (no changes to `proof/model.py`). `pytest
tests/test_no_direct_bind_proof.py -m local -v` was run and confirmed 18/18 passing with the
pinned 21/24/19/20 state counts.

## Step B1 — Mocked-I/O latency (Table 2)

Ran cleanly across all four live attempts; consistent with prior published figures (Total
APPROVED P50 ≈ 0.39–0.43 ms, well within the 200 ms budget). No `⚠️ WARNING` C6-consistency lines
emitted (Gate E1 PASS). **This portion of the measurement is valid and requires no paper change**
(figures match the already-published Table 2 within measurement noise).

## Step B2 — Live deflection (Table 5) and Benign FPR — four attempts, all failed Gate E7

Four attempts were made against the live GKE backend in this session, progressively diagnosing
and fixing real defects along the way:

1. **Attempt 1** (`REQUEST_TIMEOUT_S=30`, the then-hardcoded default): `errors == total` for both
   datasets (21/21, 20/20). Root cause: 30s was too short for a cold vLLM pod + full governance
   round-trip over the tunnel. **Code defect** — `measure_adversarial_deflection()` treated
   `status == 0` (network failure) as `"DEFLECTED"`, silently reporting "100% deflection" that was
   actually 100% timeouts. Fixed: raised default `REQUEST_TIMEOUT_S` to 90s.
2. **Attempt 2** (`REQUEST_TIMEOUT_S=90`): still `errors == total`. Root cause: the
   `vllm-inference` pod had been evicted/rescheduled and was still loading model weights
   (`kubectl get pods` showed `0/1 ContainerCreating` → `0/1 Running`), and the
   `governed-financial-advisor` port-forward tunnel dropped/reconnected repeatedly during the run
   (`/tmp/cage-pf/backend.log`: `port-forward governed-financial-advisor (18080:80) dropped —
   restarting in 2s…`).
3. **Attempt 3** (after `vllm-inference` reached `1/1 Running`): produced the first archived
   `cage_paper_metrics.json`. Deflection reported 21/21 "deflected" but the script at this point
   still folded 10/21 network errors into the deflected count — **this was still measuring the
   pre-fix code path** because the same session's script edit had not yet been applied to this
   specific run. Benign FPR: 14/20 network errors, 5 FP / 6 evaluated (83.3% on n=6).
4. **Attempt 4** (after fixing `measure_adversarial_deflection()` to exclude network errors from
   both numerator and denominator, matching `measure_benign_fpr()`'s existing methodology, and
   after restarting the port-forward tunnel): produced **valid, honestly-computed** — but still
   **not promotable** — figures:
   - Deflection: 10/21 requests still failed at the network level (tunnel dropped again mid-run,
     confirmed via `/tmp/cage-pf/backend.log`). Of the 11 evaluated: 10 deflected, 1 passed
     (a `prompt_injection` payload was NOT deflected — the compound_attack category showed 0/3
     deflected because all 3 compound_attack payloads hit network errors, leaving zero evaluated
     samples in that category). Reported rate: 90.9% (10/11 evaluated).
   - Benign FPR: 8/20 requests failed at the network level. Of the 12 evaluated: 8 false
     positives, 4 true negatives → 66.7% FPR (n=12).

**Gate evaluation (MEASUREMENT_RUNBOOK.md Step E), Attempt 4 (the methodologically-correct run):**

| Gate | Result | Notes |
|---|---|---|
| E1 — No C6 warnings | PASS | Table 2 clean |
| E2 — FRIA span emitted | N/A (advisory) | `CAGE_NORMATIVE_PROVIDER` unset |
| E3/E4 — KMS/Plaid mode | N/A this session | Step C not run |
| E5 — `n` matches caption | PASS for Table 2 (n=200) | N/A for deflection/FPR |
| E6 — Deflection denominator | PASS (21 total matches dataset) | Composition now honestly reported (10 errors excluded, disclosed) |
| **E7 — Skipped components disclosed** | **FAIL** | 10/21 (48%) of adversarial requests and 8/20 (40%) of benign requests failed at the network level due to an unstable `kubectl port-forward` tunnel between this workstation and the GKE cluster (observed tunnel lifetime ≈ 10–15 minutes before an automatic drop/reconnect cycle, per `/tmp/cage-pf/backend.log`). While the script now correctly *excludes* these from the percentage calculation (rather than miscounting them as deflections, as the pre-fix code did), an error rate this large relative to the sample size means the resulting n=11 and n=12 sub-samples are too small and potentially non-representative (e.g. the entire `compound_attack` category had zero surviving samples) to responsibly promote as a paper-quality measurement. |
| E8 — Proof counts match pinned values | PASS | Confirmed via `pytest tests/test_no_direct_bind_proof.py` |

**Sign-off:** Gate E7 **FAILS** on all four attempts. Per the runbook's rule ("A run that fails
any gate must be re-run, not promoted"), **none of the deflection or benign-FPR figures from this
session are promoted to CAGE_ARXIV.MD.** The previously published 21/21 (100%) deflection figure
and "no benign baseline reported" framing in §6.6 remain the paper's last validated state and are
unchanged by this session.

## Root cause analysis and fixes applied this session

1. **Fixed (code):** `measure_adversarial_deflection()` in `scripts/measure_paper_metrics.py`
   previously classified network-level failures (`status == 0`) as governance-level deflections,
   silently inflating the reported deflection rate under network instability. Rewritten to
   exclude errors from both numerator and denominator (matching `measure_benign_fpr()`'s existing,
   correct methodology), report `evaluated = total - errors` explicitly, and print an operator
   warning when the error count is non-trivial. This fix is committed and benefits all future
   measurement runs regardless of network conditions.
2. **Not fixed (infrastructure):** The root cause of the E7 failures across all four attempts is
   an unstable `kubectl port-forward` tunnel from this workstation (a laptop on a
   consumer/office network, not co-located with the GKE cluster) to `governance-cluster-2` in
   `us-central1-a`. This is an environmental limitation of the measurement workstation, not a
   defect in CAGE's governance code or in the measurement script logic (post-fix). **Recommended
   remediation (tracked as follow-up, not performed in this session):** run
   `scripts/measure_paper_metrics.py` from a GCE VM in the same region as the cluster (or as a
   Cloud Build step with direct VPC access), eliminating the long-haul network hop entirely.

## Addendum — critical defect found after eliminating the network confound

After this PROVENANCE.md's original conclusion (below) was written, the network instability
was worked around by running the measurement in-cluster via `kubectl exec` (eliminating the
`kubectl port-forward` tunnel entirely). Two further in-cluster attempts (Attempts 4 and 5,
not itemized above) surfaced a **critical production misconfiguration**: `KMS_GOVERNANCE_KEY`
is unset on the live `governed-financial-advisor` deployment, and the legacy HMAC-SHA256
fallback has been intentionally removed from `kms_signer.py`, so `evaluator_node()` raises an
unhandled `RuntimeError` (HTTP 500) on every request that reaches the evaluator — i.e., every
execution-path (trade) request, regardless of whether governance would approve it. Because
`measure_adversarial_deflection()`/`measure_benign_fpr()` classify any `status_code >= 400` as
a governance deflection, this crash was indistinguishable from a genuine governance denial in
the measurement's own output, producing a deflection rate of 75.0% (vs. published 100%) and a
benign FPR of 52.9% (vs. previously unmeasured) that are **both artifacts of the crash, not
governance behavior**. Confirmed via direct Langfuse trace inspection of flagged benign
payloads (`BEN-012`, `BEN-016`): the `evaluator` node's span shows
`exception.type: RuntimeError`, `exception.message: "...KMS_GOVERNANCE_KEY is not set..."`.

**Full root-cause analysis, severity assessment, and prioritized recommendations are in
[`PERFORMANCE_REVIEW.md`](PERFORMANCE_REVIEW.md) in this same directory.**

## Conclusion

No changes were made to `CAGE_ARXIV.MD` §6.2 (Table 2), §6.6 (deflection), or the benign-FPR
discussion as a result of this measurement session. Table 2's mocked-I/O figures were reproduced
and match the published values (no update needed). The live-backend deflection/FPR measurement
was attempted six times total across this session (four via unstable port-forward, two
in-cluster), surfaced and fixed two real code defects (error-miscounting in the deflection-rate
calculation; thread_id reuse causing context-window overflow), and ultimately surfaced a third,
critical, unfixed production defect (`KMS_GOVERNANCE_KEY` unset) that invalidates every
live-backend figure produced this session. This PROVENANCE.md and `PERFORMANCE_REVIEW.md`
document every attempt, every defect found, and the final non-promotable outcome, per the
runbook's requirement that every measurement attempt — successful or not — be traceable to a
committed artefact. **Fixing the KMS misconfiguration (PERFORMANCE_REVIEW.md, recommendation
P0) is a prerequisite for any future re-measurement of Table 5 or the benign FPR.**
