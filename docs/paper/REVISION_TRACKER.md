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
| S6 | Tier 5 critic pool and aggregation logic unspecified | 4 | OPEN | `consensus.py` — heterogeneous registry, 10 s timeout, degraded-quorum lattice |
| S7 | Tier 6 causal graph, treatment/outcome, thresholds unspecified | 4 | OPEN | `causal_gatekeeper.py` — `market_volatility → trade_amount → risk_score`, placebo refuter n=50 |
| S8 | §6.4 confounded read-path baseline (`pipeline()` vs `get()`) | 4 | OPEN | §6.4 already concedes this; needs framing as a limitation |
| S9 | Amortised background latency compared to a synchronous SLA | 4 | **FIXED** | §6.3 reframed as background amortisation note, not synchronous SLA comparison |
| S10 | Plaid fetch proxy underestimates true fetch cost | 4 | OPEN | §6.3 methodology note |

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
| ST9 | Four unresolved `[CITE]` placeholders in §3.2/§3.3 | 5 | OPEN | Lines 83, 87 — need CBF/STPA prior-work citations |
| ST10 | LaTeX escape artifacts in §5.5 and §6.4 | 5 | OPEN | §5.5 formula rewritten (C5 fix); §6.4 artifacts remain |
| ST11 | Mixed numeric and author-year citation schemas | 5 | OPEN | Throughout |
| ST12 | Uncited references `[7] [8] [9] [28] [31]` | 5 | OPEN | References section |
| ST13 | `[31]`/`[35]` list system names as authors | 5 | OPEN | References |
| ST14 | `[6]` contains an editorial note to the authors | 5 | **FIXED** | [6] editorial note replaced with proper citation note in 41f1d6c |
| ST15 | Inconsistent title quoting in bibliography | 5 | OPEN | `[1]`–`[4]` vs `[7]`+ |
| ST16 | Inconsistent `et al.` usage (`[13]`, `[36]`) | 5 | OPEN | References |
| ST17 | §7.1 says "three dimensions", lists four | 4 | **FIXED** | §7.1 "three" → "four" dimensions in 41f1d6c |
| ST18 | §7.2 contains non-scientific items (ReDoS resolved; arXiv endorsement) | 4 | **FIXED** | arXiv endorsement bullet removed; ReDoS reframed as resolved hardening item |
| ST19 | Related-work positioning against seven reviewer-named papers absent | 5 | OPEN | §3.4 — [7] and [31] already in bibliography; need positioning text |

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
