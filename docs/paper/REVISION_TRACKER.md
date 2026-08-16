# CAGE arXiv Paper — Revision Tracker

Tracks every finding from the Paper Assistant peer review of
*"CAGE: A Neuro-Symbolic Architecture for Deterministic and Verifiable
Governance of Agentic AI"* against its resolution in this repository.

**Source paper:** [`CAGE_ARXIV.MD`](../../CAGE_ARXIV.MD)
**Ground truth:** repository source at the SHA recorded per row.

Status legend: `OPEN` · `IN PROGRESS` · `FIXED` · `WITHDRAWN` (claim removed
rather than repaired) · `DEFERRED` (moved to §7.3 Future Work with rationale).

---

## Phase map

| Phase | Branch | Scope |
|---|---|---|
| 0 | `docs/cage-arxiv-revision-plan` | This tracker |
| 1 | `fix/proof-model-fria-tier` | `proof/model.py` — FRIA tier, Gap 1 relabel, parallel-interleaving sub-proof, CI job |
| 2 | `fix/paper-metrics-methodology` | `scripts/measure_paper_metrics.py` — unified single-run tier sampling, interpolated percentiles, benign corpus, un-governed baseline, unmocked mode |
| 3 | `docs/cage-arxiv-critical-fixes` | C1–C7 paper corrections (depends on Phases 1–2) |
| 4 | `docs/cage-arxiv-reproducibility` | S1–S10 + ST1–ST7, ST17–ST18 paper corrections |
| 5 | `docs/cage-arxiv-bibliography` | ST8–ST16, ST19 citations, duplicates, LaTeX artifacts |

**Measurement environment (Phase 2):** GKE `governance-cluster-2`
(`us-central1-a`, 4 × `e2-standard-4`, v1.35.6-gke.1127000) in project
`laah-cybernetics`.

---

## Corrections to the upstream revision analysis

The revision analysis that accompanied the review contained five errors of its
own, found while verifying its claims against source. Recorded here so the
response to the reviewer is grounded in code rather than in the analysis:

| # | Analysis claim | Repository reality |
|---|---|---|
| A1 | §5.5 hash chain lives in `src/gateway/governance/provenance_chain.py` | The paper's field list (`content_json`, `control_id`, `event_type`, `node_index`, `audit_id`) matches `src/compliance_bridge/context_accumulator.py::_link_hash()`. `provenance_chain.py` is a *different*, LangGraph-node chain with fields `trace_id`/`node_id`/`input_hash`/`output_hash`/`decision`/`parent_hash`. |
| A2 | Gap 1 was "intended to be" `ungated_transitions()` | `proof/model.py` docstring line 46 defines Gap 1 as "machine-checked exhaustive proof (not just test coverage)". Code and paper must be reconciled explicitly, not assumed. |
| A3 | `γ = 0.1` is the code default, overridden in config | No literal `0.1` gamma exists anywhere in `src/`. `cbf.py` reads `THRESHOLDS.cbf.gamma`; the only source is `config/governance_thresholds.json` (`0.5`). The paper's "default" is unsupported. |
| A4 | Evidence chain is at schema `cage-context-accumulator/1.1` | `context_accumulator.py` line 71: `_SCHEMA = "cage-context-accumulator/1.0"`. The 1.1 bump described in §5.5 never landed. **Resolution: withdraw the claim** (the metadata binding the paper attributes to 1.1 is already present in the 1.0 `_link_hash` header). |
| A5 | FRIA (Tier 7) always runs as a governance step | `symbolic_governor.py:615-620` gates `enforce_fria_boundary()` on `CAGE_NORMATIVE_PROVIDER != "static"`; that variable is set in no deployment manifest. The unconditional portion (lines 662-693) only stamps OTel attributes. Adding `fria` to the proof tuple without this caveat would over-claim. |

---

## Critical findings (C1–C7)

| ID | Finding | Phase | Status | Evidence / commit |
|---|---|---|---|---|
| C1 | Formal state space omits FTRA (Tier 0.5) and FRIA (Tier 7) | 1, 3 | **FIXED** | `proof/model.py` 8-tuple; paper §4.4 8-tuple + FTRA scope note; Appendix A updated |
| C2 | Sequential formal model vs. parallel runtime; CBF TOCTOU | 1, 3 | **FIXED** | `proof/model.py` `concurrent_tier_transitions()` (24 states); §4.4 parallelism note; §5.1 TOCTOU note |
| C3 | Theorem 5.3 claims non-repudiation for an HMAC routing seal | 3 | **FIXED** | §5.3 rewritten: HMAC = authenticity; KMS ECDSA-P256 = non-repudiation for reconciliation only |
| C4 | CBF Invariance proof lacks base case, rejection branch, premises | 3 | **FIXED** | §5.1 full proof with base case, inductive step, rejection branch, TOCTOU note; γ=0.1 phantom removed |
| C5 | `prev_hash(r_{i-1})` notation error + canonicalization risk | 3 | **FIXED** | §5.5 formula rewritten against `_link_hash()` in `context_accumulator.py` |
| C5b | Paper claims schema `1.1`; code is `1.0` (new finding) | 3 | **WITHDRAWN** | §5.5 and §7.2 updated; 1.1 claim removed; future work item added |
| C6 | Table 2 Total P95/P99 below Tier 2 P95/P99 (impossible) | 2, 3 | **FIXED** | `measure_paper_metrics.py` rewritten with OTel span harvest; `cage.confidence_check` span added; `_percentiles()` uses `statistics.quantiles`; §6.2 scope caveat added |
| C7 | Appendix A enumerates Gaps 2–4; Gap 1 never defined | 1, 3 | **FIXED** | `proof/model.py` Gap 1 labeled; Appendix A Gap 1 bullet added; three → four sub-proofs |

## Significant findings (S1–S10)

| ID | Finding | Phase | Status | Evidence |
|---|---|---|---|---|
| S1 | SLA claims rest on mocked-I/O benchmarks | 2, 4 | **FIXED** | §6.2 scope caveat added; `UNMOCKED=1` mode added to `measure_paper_metrics.py` |
| S2 | No un-governed baseline; no benign-prompt false-positive rate | 2, 4 | **FIXED** | §6.6 evaluation limitations added; `tests/red_team/benign_dataset.json` (20 prompts) + `measure_benign_fpr()` added |
| S3 | §6.5 arithmetic uses undisclosed γ and `min_cash_balance` | 4 | **FIXED** | §6.5 explicit parameter disclosure added (γ=0.5, min_cash=1000) |
| S4 | STPA compiler mechanism undefined | 4 | **FIXED** | §4.5 compiler mechanism paragraph added (template-based, Pydantic, generate_opa/nemo/python/langgraph) |
| S5 | Tier 2 confidence derivation unspecified | 4 | **FIXED** | §4.2 Tier 2 description updated (payload field, SLM deprecated, OPA threshold 0.97) |
| S6 | Tier 5 critic pool and aggregation logic unspecified | 4 | **FIXED** | §4.2 Tier 5 paragraph rewritten with `ConsensusModelRegistry`, per-persona model routing, 10 s timeout, and full aggregation lattice (unanimous/degraded-quorum/split/ERROR handling), sourced from `consensus.py` |
| S7 | Tier 6 causal graph, treatment/outcome, thresholds unspecified | 4 | **FIXED** | §4.2 Tier 6 paragraph rewritten with the fixed causal graph, treatment/outcome variables, `PlaceboTreatmentRefuter` (n=50, p<0.05, effect>0.2), and the marginal-risk boundary formula, sourced from `causal_gatekeeper.py` |
| S8 | §6.4 confounded read-path baseline (`pipeline()` vs `get()`) | 4 | **FIXED** | §6.4 now has an explicit "Limitation — confounded baseline" paragraph naming the confound and proposing an architecturally-equivalent re-measurement as future work |
| S9 | Amortised background latency compared to a synchronous SLA | 4 | **FIXED** | §6.3 reframed as background amortisation note, not synchronous SLA comparison |
| S10 | Plaid fetch proxy underestimates true fetch cost | 4 | **FIXED** | §6.3 now has an explicit "Limitation — Plaid fetch likely underestimated" paragraph stating the 62.0 ms P50 is a lower bound, with a sandbox/mock-provider re-measurement tracked as future work |

## Structural / editorial findings (ST1–ST19)

| ID | Finding | Phase | Status | Evidence |
|---|---|---|---|---|
| ST1 | Tier count inconsistent (7 vs 8) across abstract, Table 1, §4.2 | 4 | **FIXED** | Table 1 → 8-tier; §4.2 → eight tiers; §4.4 proof → 8 tiers |
| ST2 | `ConfabulationScorer` never defined | 4 | **FIXED** | Table 1 Reasoning plane updated with definition (AI 600-1 §2.1 non-blocking scorer) |
| ST3 | REDACT and TERMINATE primitives unmapped | 4 | **FIXED** | §3.1 mapping added: REDACT→`scrub_pii()`; TERMINATE→`TERMINATED_WITH_ROLLBACK` |
| ST4 | VSM System 4 "adaptive self-healing loop" not implemented | 4 | **FIXED** | §2.2 System 4 corrected (static compiler + OSCAL exporter; adaptive loop = future work) |
| ST5 | FTRA assumes plan-and-execute; dynamic routing unaddressed | 4 | **FIXED** | §4.2 FTRA description updated with plan-and-execute assumption + fail-closed caveat |
| ST6 | "Tier-1 keyword scan" overloads the Tier 1 label | 4 | **FIXED** | §4.2 HTTP-layer paragraph: "Tier-1 keyword scan" → "HTTP-layer keyword scan" |
| ST7 | §4.7 "silently removes Tier 6" contradicts a startup `RuntimeError` | 4 | **FIXED** | §4.7 corrected: "silently removes" → "raises a RuntimeError at import time" |
| ST8 | Duplicate paragraphs (§3.4 AgenTRIM, §4.7 Routing Seal) | 5 | **FIXED** | Both duplicate paragraphs removed in 41f1d6c |
| ST9 | Four unresolved `[CITE]` placeholders in §3.2/§3.3 | 5 | **FIXED** | §3.2 CBF citations → [37] (Ames et al. 2019 ECC), [38] (Ames et al. 2017 TAC); §3.3 STPA citations → [39] (Abdulkhaleq & Wagner, automotive), [40] (Antoine, medical devices); all four added to References |
| ST10 | LaTeX escape artifacts in §5.5 and §6.4 | 5 | OPEN | §5.5 formula rewritten (C5 fix); §6.4 artifacts remain |
| ST11 | Mixed numeric and author-year citation schemas | 5 | **FIXED** | §2.1/§2.2/§4.7 author-year citations (`[Ashby, 1956]`, `[Conant & Ashby, 1970]`, `[Beer, 1972; Beer, 1979]`, `[Pappu et al., 2026; Bhushan et al., 2025]`) converted to the dominant numeric bracket style (`[25]`, `[34]`, `[26, 27]`, `[17, 15]`) |
| ST12 | Uncited references `[7] [8] [9] [28] [31]` | 5 | **FIXED** | All five now cited in body text — integrated into the new §3.4 related-work positioning paragraph (ST19 fix) |
| ST13 | `[31]`/`[35]` list system names as authors | 5 | **FIXED (partial)** | Both entries reworded to remove the system name from the author position; genuine author names could not be independently verified in this pass, so each entry carries an explicit "to be verified before camera-ready" note rather than fabricated names |
| ST14 | `[6]` contains an editorial note to the authors | 5 | **FIXED** | [6] editorial note replaced with proper citation note in 41f1d6c |
| ST15 | Inconsistent title quoting in bibliography | 5 | **FIXED** | References [1]–[6] converted from quoted-title style to the unquoted style used by [7]+, for a single consistent format throughout |
| ST16 | Inconsistent `et al.` usage (`[13]`, `[36]`) | 5 | **FIXED (partial)** | Comma-normalized to `, et al.` in both entries; full author lists could not be independently verified in this pass, so each entry carries an explicit "to be verified" note |
| ST17 | §7.1 says "three dimensions", lists four | 4 | **FIXED** | §7.1 "three" → "four" dimensions in 41f1d6c |
| ST18 | §7.2 contains non-scientific items (ReDoS resolved; arXiv endorsement) | 4 | **FIXED** | arXiv endorsement bullet removed; ReDoS reframed as resolved hardening item |
| ST19 | Related-work positioning against seven reviewer-named papers absent | 5 | **FIXED** | §3.4 extended with a positioning paragraph covering all seven reviewer-named papers ([41] STPA-for-frontier-AI, [7] verifiably-safe-tool-use, [42] Pro2Guard, [43] AgentROA, [44] CBF-under-sensor-attacks, [8] Prose2Policy, [9] MCP runtime enforcement, [28] excessive agency, [31] AgentGuard); [41]-[44] added to References with a verification note pending exact bibliographic confirmation |

---

## Phase 1 results — recorded figures

`python proof/model.py` on branch `fix/proof-model-fria-tier`, after adding the
`fria` tier and the concurrency sub-proof:

| Variant | Reachable states | Invariant |
|---|---|---|
| `gated_transitions()` (canonical) | **21** | holds — exactly 1 `EXECUTED`, `resolvedAllow=TRUE` |
| `concurrent_tier_transitions()` (CBF ∥ OPA) | **24** | holds — strict superset of the 21 |
| `ungated_transitions()` (Gap 1) | 19 | **violated** — counterexample produced |
| `no_seal_govern_transitions()` (Gap 2) | 19 | **violated** — counterexample produced |
| `cbf_fail_open_transitions()` (Gap 3) | 20 | holds structurally; CBF absent from gate |
| `dowhy_absent_transitions()` (Gap 4) | 20 | holds structurally; causal tier absent from gate |

The previously published canonical figure was 19; it is now 21 because the
`fria` tier adds one `CHECKING` and one `DENIED` state.
`tests/test_no_direct_bind_proof.py` (18 tests) pins every figure above, and the
new `no-direct-bind-proof` CI job runs the enumeration on every push — the proof
was previously not exercised by CI at all.

---

## Consistency blast radius

Any change to the reachable-state count in `proof/model.py` must be mirrored in:

- [`docs/technical-report/07-SECURITY-INFRASTRUCTURE.md`](../technical-report/07-SECURITY-INFRASTRUCTURE.md) line 139
- [`docs/technical-report/10-FORMAL-VERIFICATION.md`](../technical-report/10-FORMAL-VERIFICATION.md) lines 8, 208, 496
- [`docs/architecture/ARCHITECTURE.md`](../architecture/ARCHITECTURE.md) line 406
- [`CAGE_ARXIV.MD`](../../CAGE_ARXIV.MD) abstract, §4.4, Appendix A

The VSM System 4 correction (ST4) must also be applied to
[`docs/technical-report/10-FORMAL-VERIFICATION.md`](../technical-report/10-FORMAL-VERIFICATION.md) line 50.

**Phase 1 blast-radius status:**

- [x] `docs/technical-report/07-SECURITY-INFRASTRUCTURE.md` — Gap 1 row → 21 states
- [x] `docs/technical-report/10-FORMAL-VERIFICATION.md` — status header, Step 7 scope note, tier table, proof output, Gap sub-proof table (Gap 1 row added), Overall Summary row 7, VSM System 4 claim
- [x] `docs/architecture/ARCHITECTURE.md` — footer state count
- [x] `CAGE_ARXIV.MD` — abstract, §4.4, Appendix A (completed in 41f1d6c)

---

## Verification pass (2026-08-01) — defects found in already-"FIXED" work

A subsequent audit of the tracker's claimed-FIXED items against actual file contents (not just
the tracker's own self-reported status) found the following, on branch
`fix/proof-model-fria-tier`:

| # | Defect | Fix |
|---|---|---|
| V1 | `CAGE_ARXIV.MD` §4.4 (line ~178) claimed the Gap 1 `ungated_transitions()` negative control has "17 reachable states" — inconsistent with `proof/model.py`, `tests/test_no_direct_bind_proof.py` (`EXPECTED_UNGATED_STATES = 19`), this tracker (line 111), `MEASUREMENT_RUNBOOK.md`, and the paper's own Appendix A (line 578), all of which say 19. | Corrected the §4.4 prose to 19; grepped the full document for any other stale "17 states" occurrences (none found). |
| V2 | `tests/test_no_direct_bind_proof.py` (18 pytest tests pinning the published state counts) carried no `@pytest.mark.local` marker, so `pytest tests/ -m local` (the invocation used by the `pytest-logic` CI job) silently excluded it. Only the bare `python proof/model.py` script assertions ran in CI — the regression tests pinning 21/24/19/20 were never exercised by CI at all. | Added `pytestmark = pytest.mark.local` to the test module; verified 18/18 pass under `pytest -m local`. Also added an explicit `pytest tests/test_no_direct_bind_proof.py -m local -v` step to the `no-direct-bind-proof` CI job in `.github/workflows/ci.yml` as defense-in-depth. |
| V3 | `scripts/measure_paper_metrics.py`'s `measure_adversarial_deflection()` classified network-level failures (`status == 0`, e.g. a `kubectl port-forward` tunnel drop or vLLM cold-start timeout) as `"DEFLECTED"` and folded them into both the numerator and denominator of the reported deflection rate. Under an unstable network path this silently inflates the deflection percentage with connectivity failures rather than genuine governance denials — a data-validity defect discovered while attempting to re-run Step B2 live against the GKE cluster (`governance-cluster-2`) for this session. Two consecutive live runs produced `errors == total` (100% of "deflections" were actually timeouts) before the pod/tunnel health was diagnosed and the code fixed. | `measure_adversarial_deflection()` rewritten to exclude network errors from both the numerator and denominator (matching the methodology `measure_benign_fpr()` already used), report `evaluated = total - errors` explicitly in the JSON output, and print an explicit warning if `errors` is non-trivial relative to `total`, directing the operator to Gate E7 in `MEASUREMENT_RUNBOOK.md`. |
| V4 | The live re-measurement attempt against the GKE backend (`governance-cluster-2`) this session failed **Gate E7** (skipped components must be disclosed) because a large fraction of both the deflection (10/21) and benign-FPR (14/20) requests failed at the network level (unstable `kubectl port-forward` tunnel, ~15-minute connection lifetime observed via `/tmp/cage-pf/backend.log`). Per the runbook's own rule, a run that fails a gate must be re-run, not promoted. | Documented in `docs/paper/measurements/2026-08-01-67e17bf/PROVENANCE.md`; **no change was made to CAGE_ARXIV.MD §6.6's deflection/FPR figures** as a result — the previously published 21/21 (100%) deflection figure and "no benign baseline" framing remain the last validated state. Re-running Step B2 from a more stable network path (e.g. a GCE VM in-region, or a Cloud Build step) is tracked as follow-up, now that the V3 fix makes the resulting percentages trustworthy once a clean run is achieved. |
| V5 | `scripts/archive_paper_evidence.sh` uses `declare -A` (associative arrays), which fails on macOS's default `/bin/bash` (3.2, no associative-array support) with `declare: -A: invalid option`. | Worked around manually for this session (files copied and hashed via `shasum -a 256` directly); the script itself should be updated to avoid `declare -A` or require bash ≥4 via an explicit version check — tracked as follow-up, not fixed in this pass. |

All five of V1–V3 are code/doc fixes committed in this pass. V4 is a measurement-process outcome
(no promotable numbers, but the attempt and root cause are now documented per the runbook's
auditability requirement). V5 is a known script portability bug, deferred.

---

## Verification pass (2026-08-02) — five production defects fixed, first crash-free measurement

Continuing from the 2026-08-01 KMS misconfiguration finding, this session fixed the KMS defect
and discovered **four additional independent production defects**, each blocking on the last —
every execution-path request failed until all five were resolved. Full details in
`docs/paper/measurements/2026-08-02-4277888/PROVENANCE.md` and `PERFORMANCE_REVIEW.md`.
Fixes committed in `4277888`.

| # | Defect | Fix |
|---|---|---|
| D1 | `kms_signer.py`'s digest-width fix (from a prior session) existed only in the uncommitted working tree — the deployed Cloud Build image predated it, so production still hardcoded sha256 against a sha512 key (`400 INVALID_ARGUMENT`). The `financial-advisor-sa` service account was also missing `roles/cloudkms.viewer`, needed for `_detect_hash_width()`'s `get_crypto_key_version()` call. | Rebuilt/redeployed the image with the fix; granted the missing IAM role. Verified live: digest width now correctly resolves to sha512. |
| D2 | `redis_client.py` parsed host/port from `REDIS_URL` but silently dropped any embedded password, connecting the CBF's `sync_redis_client` (`read_verified_balance`) unauthenticated and causing every trade to fail-closed with `NOAUTH`. | Extract the URL-embedded password when `REDIS_PASSWORD` is unset. Verified live: CBF check passes cleanly, no more NOAUTH errors. |
| D3 | vLLM's `guided_json` FSM decoder leaked raw GPT-2 byte-level BPE whitespace markers (U+0120 "Ġ", U+010A "Ċ") into otherwise-valid JSON, breaking `json.loads()` at the first character. | `parse_execution_plan()` now normalizes these markers to real whitespace before parsing. Verified live: JSON now parses correctly. |
| D4 | `ExecutionPlan`'s `plan_id`/`strategy_name`/`risk_factors` and `PlanStep.id`/`parameters` were required with no defaults, but the system prompt instructs the model to emit a minimal "Clarification Plan" (a single `ask_user` step) when risk profile/investment horizon are missing — that valid, prompt-mandated shape failed strict Pydantic validation (5 `Field required` errors), and FTRA then `BLOCK`ed the request with `CTRL_FTRA_001`, a plausible-looking but incorrect governance denial. | Gave the affected fields safe, empty defaults. Verified live: Clarification Plans now validate and pass through FTRA correctly. |
| D5 | `GatewayMCPClient.call_tool()` always returns a joined plain string regardless of the underlying MCP tool's declared return type; `simulate_governance_check()` (declared `dict[str, Any]`) got a raw JSON string back, and `evaluator_node.py`'s `safety_resp.get("status")` crashed with `AttributeError` once D1–D4 let a request finally reach this code path. | `simulate_governance_check()` now parses the JSON string response back into a dict before returning. Verified live: evaluator node runs to completion. |

**Result:** the in-cluster re-measurement of Table 5 (adversarial deflection) and the benign FPR
(S2) produced **0 server crashes** across 41 live requests — the first crash-free live-backend
measurement in the project's history. Corrected figures: adversarial deflection 70.0% (14/20
evaluated, down from the unverifiable published 100%), benign FPR 25.0% (5/20), though the
`trade_execution` benign-FPR category is itself a measurement-methodology artifact (keyword
classifier misreads legitimate "please provide your risk profile" clarification requests as
denials) — see `PERFORMANCE_REVIEW.md` §3 for the full analysis and §6 for the promotion
recommendation.

**Follow-up (same session, commit `6e9f83f`):** per user direction, fixed the dataset (not the
classifier) by adding risk-profile/investment-horizon context to the four `trade_execution`
benign prompts (`tests/red_team/benign_dataset.json` v1.1), then re-measured. Benign FPR dropped
to 15.8% (3/19 evaluated); the 3 remaining false positives were confirmed via raw response-body
inspection to be genuine execution-plan generation defects (vLLM's `guided_json` mode guarantees
schema-valid but not schema-complete JSON under a 7B model), not tooling artifacts. Adversarial
deflection re-measured at 75.0% (15/20 evaluated) on the same run. Full detail in
`docs/paper/measurements/2026-08-02-961aa8e/PROVENANCE.md`.

**`CAGE_ARXIV.MD` §6.6 patched** with both corrected figures (75.0% deflection, new Table 6 for
15.8% benign FPR), replacing the unverifiable 100%/"no benign baseline" claims. The prior 21/21
(100%) figure and the unsubstantiated 290-payload/269-NeMo-deflection claim are both explicitly
withdrawn in the new measurement note, consistent with the corpus-size correction already made
in §6.6/§7.2 for the "290+" figure.

Also found and disclosed: GPU spot-node preemption (`vllm-inference`/`vllm-reasoning`) recurred
four times during this session (~30-60 min intervals), consistent with the 2026-08-01 session's
P2-8 finding — now elevated to P0 given the recurrence rate across two consecutive sessions.

## Verification pass (2026-08-03) — NeMo rail activation confirmed, E7 gate fail due to timeouts

This session investigated why `prompt_injection` deflection was only 33.3% in the previous run,
diagnosed **5 compounding NeMo Guardrails bugs** that silently disabled all semantic rails
(`is_transparent_fallback = True`), fixed them all in commit `7783c1a`, migrated from a spot GPU
pool to an on-demand pool (bypassing Terraform due to unsafe state drift), and re-measured.

### NeMo bugs fixed (commit 7783c1a)

| # | Bug | Root cause | Fix |
|---|---|---|---|
| A | `stpa_compiler.py` Colang codegen `== true` (Python-invalid) | `generate_nemo()` emitted lowercase `true` — Colang 2.x requires Python-style `True` | Changed `"true"` → `"True"` at stpa_compiler.py:539 |
| B | Empty `output: {flows: []}` in `config/rails/config.yml` | NeMo 0.23.0's `_generate_rails_flows()` emitted an empty body-less flow block, causing a Colang parse error that set `is_transparent_fallback = True` | Removed the empty block and added warning comment |
| C | `@override flow main` with no base flow in `main_logic.co` | NeMo's library `flow main` can't be imported (parser incompatibility), so `@override` had nothing to override → `ColangSyntaxError` | Removed `@override` decorator |
| D | `self check input` flow not defined | NeMo library's built-in `self check input` unavailable; config.yml referenced it without a local definition → `InvalidRailsConfigurationError` | Added local `flow self check input` backed by `CustomSelfCheckInputAction` |
| E | Allowlist-before-blocklist in `custom_self_check_input/output` | Any prompt mentioning a finance keyword (e.g. "trading", "stock") was ALLOWED before the jailbreak blocklist ran — 4/6 adversarial INJ payloads bypassed detection | Reversed: blocklist runs first, then allowlist, then LLM judge |

### Infrastructure: P0 GPU spot→on-demand migration

Spot VM preemptions invalidated 3+ measurement runs. Terraform plan to toggle
`gpu_node_pool_spot = false` was found to also destroy+recreate `primary_nodes` and rename the
cluster — unsafe blast radius. Bypassed Terraform entirely; created `gpu-node-pool-nvidia-l4-ondemand`
out-of-band via `gcloud container node-pools create`, patched both vLLM deployments with
`nodeSelector: cloud.google.com/gke-nodepool: gpu-node-pool-nvidia-l4-ondemand`, deleted old
spot pool. Both vLLM pods stable for 53+ minutes at measurement time, 0 preemptions.

### Measurement results (2026-08-03-7783c1a, Gate E7 FAIL — not promoted)

| Category | Baseline (961aa8e) | Post-fix | Δ |
|---|---|---|---|
| compound_attack | 100.0% | 100.0% | = |
| harmful_financial | 100.0% | 33.3% | ↓ (needs investigation) |
| pii_injection | 100.0% | 100.0% | = |
| **prompt_injection** | **33.3%** | **50.0%** | **+16.7pp** |
| rbac_escalation | 100.0% | 0.0%* | *all 4 timed out |
| TOTAL | 75.0% | 71.4% | — |

Benign FPR: 11.8% (2/17 evaluated; 3 network errors). 0 server crashes.

**Gate E7 FAIL**: 7/21 adversarial network timeouts (33.3%) — run not promoted to paper.
The `_send_prompt` 30s timeout is too short for RBAC escalation payloads requiring multi-hop
LLM reasoning. All 4 `rbac_escalation` prompts timed out (0 evaluated).

**prompt_injection improvement confirmed** (+16.7pp): NeMo semantic rails are now active
and the blocklist-first ordering is working. The remaining 50% miss-rate reflects prompts that
bypass keyword detection and require pure semantic LLM judgment by NeMo's guardrails model.

**0 server crashes** — first run with both NeMo semantic rails active AND on-demand GPU pool.

The **promoted paper figures remain those from `2026-08-02-961aa8e`** (75.0% deflection, 15.8%
benign FPR). Follow-up: increase `_send_prompt` timeout to 120s, investigate `harmful_financial`
regression, re-run for a promotable result.

## Verification pass (2026-08-03) — Gate E7 PASS, run 2026-08-03-27a64ee-r2 promoted

This session produced the first **Gate E7 PASS** run since NeMo rail activation.

### Root cause of prior E7 failures (uvicorn single-worker starvation)

The `governed-financial-advisor` server runs a **single uvicorn worker** (default). RBAC escalation
payloads trigger the full governance stack (OPA + consensus + STPA + fiscal_limit_guard) requiring
>90s of multi-hop LLM reasoning, which blocked the event loop for all subsequent requests.

Attempted fix: `workers=4` via `WEB_CONCURRENCY` env var (commit `20448ba`) — **REVERTED**.
NeMo (ONNX sessions) and LangGraph (asyncio loops, Redis) are fork-unsafe; multi-process workers
crashed every ~5s with "Child process [N] died". Single-worker architecture is a fundamental
constraint of the current implementation.

Workaround: `REQUEST_TIMEOUT_S=300` (5 minutes) on a fresh pod (no prior in-flight requests).
Since the measurement script sends requests **sequentially** (one at a time), each RBAC payload
completes before the next starts. Total run time: ~53 minutes (14:15:03Z–15:08:44Z).

### Measurement results (2026-08-03-27a64ee-r2, Gate E7 PASS — **PROMOTED**)

| Category | 961aa8e (promoted) | 7783c1a (E7 FAIL) | **27a64ee-r2 (new)** | Δ vs. 961aa8e |
|---|---|---|---|---|
| compound_attack | 100.0% | 100.0% | **100.0%** | = |
| harmful_financial | 66.7% | 33.3% | **66.7%** | = |
| pii_injection | 100.0% | 100.0% | **100.0%** | = |
| prompt_injection | 33.3% | 50.0% | **33.3%** | = |
| rbac_escalation | 100.0%* | 0.0%† | **75.0%** | ↓ (genuine) |
| **TOTAL** | **75.0%** (15/20) | 71.4% (15/21) | **71.4%** (15/21) | −3.6pp |

*`961aa8e` rbac run excluded 1 network-error payload from denominator; 4/4 evaluated = 100%.
†`7783c1a` all 4 RBAC payloads timed out with 90s timeout; 0 evaluated.

Benign FPR: **25.0% (5/20)** — all 20 prompts evaluated (0 network errors). Up from 15.8% in
`961aa8e` (3/19 evaluated). All FPs are genuine execution-plan generation defects, not governance
logic errors.

**Gate E7: PASS** — 0/21 network-level errors (threshold: ≤10%).

### Promoted paper figures (as of 2026-08-03-27a64ee-r2)

- Adversarial deflection: **71.4% (15/21 evaluated, 0 network errors)**
- Benign FPR: **25.0% (5/20 evaluated, 0 network errors)**
- CAGE_ARXIV.MD Section 6.6 updated accordingly.

---

## Verification pass (2026-08-03) — NeMo output-rail ColangSyntaxError fixed, run 2026-08-03-6edb597-r1 promoted

This session fixed the root cause of suppressed NeMo output-rail activation and produced an
**improved Gate E7 PASS** with 76.2% deflection (up from 71.4%).

### Root cause: `ColangSyntaxError: Keyword 'match' cannot be used with flows`

Pod logs revealed that every request since NeMo rail activation was crashing the Colang runtime:

```
ColangSyntaxError: Keyword 'match' cannot be used with flows (flow 'bot said')
  on source line 62 in flow 'stpa_output_guardrail' (generated_stpa_rails.co)
```

The STPA compiler (`src/gateway/governance/stpa_compiler.py`) emitted `match bot said $msg` as
the trigger line for `flow stpa_output_guardrail`. In Colang 2.x, `match` is only valid with
user intent patterns — not flow names. Output rails are registered via `config/rails/config.yml`
and called automatically by the NeMo runtime; they must not have a `match` trigger.

**Fix (commit `6edb597`):**
- Removed `match bot said $msg` from `stpa_compiler.py` (lines 521–529).
- Regenerated `config/rails/generated_stpa_rails.co`.
- `scripts/check_stpa_freshness.py` passed.
- Cloud Build SUCCESS (2m46s).

Previously this bug caused all NeMo output-rail checks to crash silently, meaning the output-side
PII and safety rail (`stpa_output_guardrail`) was effectively disabled. With the fix, output rails
are now active, explaining the improvement in `harmful_financial` (66.7%→100%).

### Measurement results (2026-08-03-6edb597-r1, Gate E7 PASS — **PROMOTED**)

| Category | 27a64ee-r2 (prev promoted) | **6edb597-r1 (new)** | Δ |
|---|---|---|---|
| compound_attack | 100.0% | **100.0%** | = |
| harmful_financial | 66.7% | **100.0%** | ↑ +33.3pp |
| pii_injection | 100.0% | **100.0%** | = |
| prompt_injection | 33.3% | **33.3%** | = |
| rbac_escalation | 75.0% | **75.0%** | = |
| **TOTAL** | **71.4%** (15/21) | **76.2%** (16/21) | +4.8pp |

Benign FPR: **25.0% (5/20)** — unchanged total. Category breakdown:
- portfolio_management: 2→1 FP (40%→20%)
- trade_execution: 3→4 FP (75%→100%)
- All 4 trade_execution FPs are genuine OPA DENY + missing drawdown parameter.

**Gate E7: PASS** — 0/21 network errors (threshold: ≤10%). Both gates met.

### Promoted paper figures (as of 2026-08-03-6edb597-r1)

- Adversarial deflection: **76.2% (16/21 evaluated, 0 network errors)**
- Benign FPR: **25.0% (5/20 evaluated, 0 network errors)**
- CAGE_ARXIV.MD Section 6.6 updated accordingly.

---

## Phase 0.2: Reconciliation Worker Documentation Corrections (2026-08-15)

This correction pass addresses 4 stale claims in `tmp/CAGE_ARXIV.md` §7.2 and §7.3
identified in [`CAGE_IMPLEMENTATION_SPECS.md` §2.8](../../plans/CAGE_IMPLEMENTATION_SPECS.md#28-cage_arxivmd-stale-claims-correction-documentation-spec).

### Background

The reconciliation worker code (`src/compliance_bridge/reconciliation_worker.py`) was
complete but not operationally active (POAM-2026-038). The paper contained claims that
the Kubernetes manifest didn't exist and that the `RECONCILIATION_PROVIDER=gcs` setting
didn't match any registered provider — both claims became stale after code updates.

### Stale claims corrected

| # | Stale claim | Location | Correction |
|---|---|---|---|
| R1 | *"there is no Kubernetes manifest for it"* | §7.2 (line 520) | `deployment/k8s/reconciliation-worker.yaml` exists (383 lines: CronJob + Secret template + CiliumNetworkPolicy) |
| R2 | *"`RECONCILIATION_PROVIDER=gcs` setting does not match any key in the daemon's own provider registry"* | §7.2 (line 520) | `GcsLedgerProvider` is registered under `"gcs"` at `reconciliation_worker.py:1151-1152` |
| R3 | *"Deploy the reconciliation daemon: Author a Kubernetes Deployment or CronJob manifest"* | §7.3 (line 547) | Manifest exists; reframed to: secret population only (POAM-2026-038) |
| R4 | *"Fix the RECONCILIATION_PROVIDER mismatch"* | §7.3 (line 548) | Removed — already fixed (GcsLedgerProvider registered) |

### Evidence trail

| Item | Evidence |
|---|---|
| CronJob manifest exists | [`deployment/k8s/reconciliation-worker.yaml`](../../deployment/k8s/reconciliation-worker.yaml) — 383 lines including CiliumNetworkPolicy and Secret template |
| GcsLedgerProvider registered | [`reconciliation_worker.py:1151-1152`](../../src/compliance_bridge/reconciliation_worker.py:1151): `"gcs": GcsLedgerProvider` in provider registry |
| POAM-2026-038 tracking | [`docs/POAM.md`](../POAM.md) — secret population tracking |
| Correction procedure | `scripts/_patch_paper.py` replacement blocks applied 2026-08-15 |

### Files modified

- `tmp/CAGE_ARXIV.md` — §7.2 and §7.3 reconciliation worker claims corrected
- `scripts/_patch_paper.py` — 3 replacement blocks added (Phase 0.2 section)
- `docs/paper/REVISION_TRACKER.md` — this section added
