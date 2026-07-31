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
| C1 | Formal state space omits FTRA (Tier 0.5) and FRIA (Tier 7) | 1, 3 | **Phase 1 FIXED** (paper pending) | `proof/model.py` `TIERS`; `symbolic_governor.py:606-693`; `graph.py` FTRA wiring |
| C2 | Sequential formal model vs. parallel runtime; CBF TOCTOU | 1, 3 | **Phase 1 FIXED** (paper pending) | `symbolic_governor.py:324` `asyncio.gather`; `cbf.py:330-350` read-only `verify_action()` |
| C3 | Theorem 5.3 claims non-repudiation for an HMAC routing seal | 3 | OPEN | `routing_seal.py` HMAC-SHA256 + `GOVERNANCE_SALT`; KMS confined to reconciliation/evidence paths |
| C4 | CBF Invariance proof lacks base case, rejection branch, premises | 3 | OPEN | `cbf.py:394` condition; `cbf.setup()` seeds `100000.0`; `min_cash_balance=1000` |
| C5 | `prev_hash(r_{i-1})` notation error + canonicalization risk | 3 | OPEN | `context_accumulator.py:85-112` `_link_hash()` |
| C5b | Paper claims schema `1.1`; code is `1.0` (new finding) | 3 | OPEN → WITHDRAW | `context_accumulator.py:71` |
| C6 | Table 2 Total P95/P99 below Tier 2 P95/P99 (impossible) | 2, 3 | OPEN | `measure_paper_metrics.py` — `_sample_confidence_tier` and `_sample_cbf_opa_tier` are duplicate `_run_checks()` calls with identical params; Total measured via `govern()` |
| C7 | Appendix A enumerates Gaps 2–4; Gap 1 never defined | 1, 3 | **Phase 1 FIXED** (paper pending) | `proof/model.py` docstring lines 45-49 |

## Significant findings (S1–S10)

| ID | Finding | Phase | Status | Evidence |
|---|---|---|---|---|
| S1 | SLA claims rest on mocked-I/O benchmarks | 2, 4 | OPEN | §6.2 methodology statement |
| S2 | No un-governed baseline; no benign-prompt false-positive rate | 2, 4 | OPEN | `tests/red_team/adversarial_dataset.json` (21 payloads, 5 categories) |
| S3 | §6.5 arithmetic uses undisclosed γ and `min_cash_balance` | 4 | OPEN | `config/governance_thresholds.json`: `gamma=0.5`, `min_cash_balance=1000.0` |
| S4 | STPA compiler mechanism undefined | 4 | OPEN | `stpa_compiler.py` — Pydantic `ControlStructureModel` + `generate_opa/nemo/python/langgraph/agp/terminal_registry/registry_manifest` |
| S5 | Tier 2 confidence derivation unspecified | 4 | OPEN | `symbolic_governor.py:242`; `deployment/system_authz.rego:16,20` (`slm_available == false` → 0.97) |
| S6 | Tier 5 critic pool and aggregation logic unspecified | 4 | OPEN | `consensus.py` — heterogeneous registry, 10 s timeout, degraded-quorum lattice |
| S7 | Tier 6 causal graph, treatment/outcome, thresholds unspecified | 4 | OPEN | `causal_gatekeeper.py` — `market_volatility → trade_amount → risk_score`, placebo refuter n=50 |
| S8 | §6.4 confounded read-path baseline (`pipeline()` vs `get()`) | 4 | OPEN | §6.4 already concedes this; needs framing as a limitation |
| S9 | Amortised background latency compared to a synchronous SLA | 4 | OPEN | §6.3 final paragraph |
| S10 | Plaid fetch proxy underestimates true fetch cost | 4 | OPEN | §6.3 methodology note |

## Structural / editorial findings (ST1–ST19)

| ID | Finding | Phase | Status | Evidence |
|---|---|---|---|---|
| ST1 | Tier count inconsistent (7 vs 8) across abstract, Table 1, §4.2 | 4 | OPEN | Table 1 "7-tier"; §4.2 "seven tiers" then enumerates eight |
| ST2 | `ConfabulationScorer` never defined | 4 | OPEN | `confabulation_scorer.py` — AI 600-1 §2.1 Langfuse scorer, non-blocking |
| ST3 | REDACT and TERMINATE primitives unmapped | 4 | OPEN | `inference_proxy.py` — `scrub_pii()` (REDACT); `dge_action: TERMINATED_WITH_ROLLBACK` (TERMINATE) |
| ST4 | VSM System 4 "adaptive self-healing loop" not implemented | 4 | **Docs FIXED** (paper pending) | No adaptive policy loop in `src/`; same claim repeated in `docs/technical-report/10-FORMAL-VERIFICATION.md:50` |
| ST5 | FTRA assumes plan-and-execute; dynamic routing unaddressed | 4 | OPEN | `ftra/graph_analyzer.py` — linear chain, optional `depends_on`, fail-closed default |
| ST6 | "Tier-1 keyword scan" overloads the Tier 1 label | 4 | OPEN | §4.2 HTTP-layer paragraph |
| ST7 | §4.7 "silently removes Tier 6" contradicts a startup `RuntimeError` | 4 | OPEN | §4.7 fail-safe assertions paragraph |
| ST8 | Duplicate paragraphs (§3.4 AgenTRIM, §4.7 Routing Seal) | 5 | OPEN | Lines 99-101, 215-216 |
| ST9 | Four unresolved `[CITE]` placeholders in §3.2/§3.3 | 5 | OPEN | Lines 83, 87 |
| ST10 | LaTeX escape artifacts in §5.5 and §6.4 | 5 | OPEN | Lines 266-272, 345-351 |
| ST11 | Mixed numeric and author-year citation schemas | 5 | OPEN | Throughout |
| ST12 | Uncited references `[7] [8] [9] [28] [31]` | 5 | OPEN | References section |
| ST13 | `[31]`/`[35]` list system names as authors | 5 | OPEN | References |
| ST14 | `[6]` contains an editorial note to the authors | 5 | OPEN | References |
| ST15 | Inconsistent title quoting in bibliography | 5 | OPEN | `[1]`–`[4]` vs `[7]`+ |
| ST16 | Inconsistent `et al.` usage (`[13]`, `[36]`) | 5 | OPEN | References |
| ST17 | §7.1 says "three dimensions", lists four | 4 | OPEN | Line 405 |
| ST18 | §7.2 contains non-scientific items (ReDoS resolved; arXiv endorsement) | 4 | OPEN | Lines 427, 433 |
| ST19 | Related-work positioning against seven reviewer-named papers absent | 5 | OPEN | §3.4 |

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
- [ ] `CAGE_ARXIV.MD` — abstract, §4.4, Appendix A (deferred to Phase 3)
