#!/usr/bin/env python3
"""Patch CAGE_ARXIV.MD with all Phase 3/4/5 corrections.

Run: uv run python3 scripts/_patch_paper.py

Exit codes:
    0 — all replacements applied successfully (zero [MISS] lines)
    1 — one or more search strings were not found in CAGE_ARXIV.MD

A non-zero exit means the paper text has already been updated (or the
replacement block is stale).  Fix or remove the stale block before
committing.  Never suppress this exit code — it is the machine-enforceable
complement to the human evaluation gate in Step E of the measurement runbook
(docs/paper/MEASUREMENT_RUNBOOK.md).
"""
import sys
from pathlib import Path

paper = Path("CAGE_ARXIV.MD")
text = paper.read_text()

replacements = [
    # ── C1/C7: state counts ──────────────────────────────────────────────────
    ("BFS visits 19 reachable states",
     "BFS visits 21 reachable states"),
    ("holds in all 19 reachable states",
     "holds in all 21 reachable states"),
    (r"|S| \= 19",
     r"|S| = 21"),
    ("where |S| = 19",
     "where |S| = 21"),
    # ── C1: 7-tuple → 8-tuple in §4.4 definition ────────────────────────────
    ("`tier_results` is a 7-tuple recording each governance tier "
     "(`stpa, confidence, cbf, opa, fiscal, consensus, causal`) as `PENDING | PASS | FAIL`",
     "`tier_results` is an 8-tuple recording each governance tier within "
     "`_run_checks()` (`stpa, confidence, cbf, opa, fiscal, consensus, causal, fria`) "
     "as `PENDING | PASS | FAIL`. Tier 0.5 (FTRA) is not included in this tuple "
     "because it executes at the LangGraph graph level before `_run_checks()` is "
     "invoked; its verdict (`CLEAR | HITL_REQUIRED | BLOCKED`) is recorded separately "
     "in the LangGraph state"),
    # ── C1: Appendix A 7-tuple ───────────────────────────────────────────────
    ("tier_results ∈ {PENDING, PASS, FAIL}^7  "
     "(one per governance tier: stpa, confidence, cbf, opa, fiscal, consensus, causal)",
     "tier_results ∈ {PENDING, PASS, FAIL}^8  "
     "(one per governance tier within _run_checks(): "
     "stpa, confidence, cbf, opa, fiscal, consensus, causal, fria)"),
    # ── C1: §4.4 proof: 7 tiers → 8 tiers ──────────────────────────────────
    ("from `CHECKING`, each of the 7 tiers resolves to `PASS` or `FAIL` in sequence; "
     "any `FAIL` moves immediately to `DENIED` (fail-closed); "
     "once all 7 tiers have resolved to `PASS`",
     "from `CHECKING`, each of the 8 tiers within `_run_checks()` resolves to "
     "`PASS` or `FAIL` in sequence; any `FAIL` moves immediately to `DENIED` "
     "(fail-closed); once all 8 tiers have resolved to `PASS`"),
    # ── ST1: Table 1 Reasoning plane ─────────────────────────────────────────
    ("SymbolicGovernor (7-tier pipeline) \\+ ConfabulationScorer",
     "SymbolicGovernor (8-tier pipeline) + ConfabulationScorer"),
    # ── ST1: §4.2 opening sentence ───────────────────────────────────────────
    ("The governor evaluates every action through seven tiers in sequence:",
     "The governor evaluates every agent action through eight tiers in sequence "
     "(Tiers 1–7 within `_run_checks()`, plus Tier 0.5 at the LangGraph graph level):"),
    # ── C7: Appendix A three → four gap-specific sub-proofs ─────────────────
    ("`proof/model.py` additionally verifies three gap-specific sub-proofs",
     "`proof/model.py` additionally verifies four gap-specific sub-proofs"),
    # ── C7: Add Gap 1 bullet before Gap 2 in Appendix A ─────────────────────
    ("- **Gap 2 (`govern()` without seal)**:",
     "- **Gap 1 (no routing seal on approval)**: `ungated_transitions()` models "
     "the pre-fix code path in which `govern()` transitions directly from `CHECKING` "
     "to `EXECUTED` once all tiers pass, without requiring a routing seal. This variant "
     "reaches 19 reachable states and produces the explicit counterexample "
     "`(phase=EXECUTED, resolvedAllow=FALSE, seal_present=FALSE)` — a direct violation "
     "of the NoDirectBind invariant. This confirms that the seal-issuance step in "
     "`gated_transitions()` is load-bearing: removing it structurally (not merely "
     "skipping one tier's evaluation) produces a genuine, minimal counterexample.\n"
     "- **Gap 2 (`govern()` without seal)**:"),
    # ── C7: Gap 2 state count 17 → 19 ───────────────────────────────────────
    ("This variant reaches 17 states and produces the counterexample",
     "This variant reaches 19 states and produces the counterexample"),
    # ── C7: Gap 3/4 state counts 18 → 20 ────────────────────────────────────
    ("The structural invariant still holds (18 reachable states)",
     "The structural invariant still holds (20 reachable states)"),
    ("the structural invariant holds (18 reachable states)",
     "the structural invariant holds (20 reachable states)"),
    # ── C7: ungated negative control 17 → 19 ────────────────────────────────
    ("produces a genuine, minimal counterexample (17 reachable states",
     "produces a genuine, minimal counterexample (19 reachable states"),
    # ── ST17: §7.1 three → four dimensions ──────────────────────────────────
    ("extends it in three dimensions:",
     "extends it in four dimensions:"),
    # ── C2: Add parallelism note to §4.4 ────────────────────────────────────
    ("The state `(phase=EXECUTED, resolvedAllow=FALSE)` is unreachable under "
     "`gated_transitions()`. ∎",
     "The state `(phase=EXECUTED, resolvedAllow=FALSE)` is unreachable under "
     "`gated_transitions()`. ∎\n\n"
     "**Parallelism note:** The formal model treats tier evaluation as sequential "
     "for the purpose of the NoDirectBind invariant — the invariant concerns "
     "reachability of the `EXECUTED` state, not the order in which tiers evaluate. "
     "In the runtime implementation, Tier 3 (CBF + OPA) evaluates concurrently via "
     "`asyncio.gather()` (`symbolic_governor.py:324`); the invariant holds because "
     "both results are collected before any transition to `SEAL_ISSUED` is permitted. "
     "`proof/model.py`'s `concurrent_tier_transitions()` sub-proof explores both "
     "CBF/OPA interleavings (24 reachable states, a strict superset of the 21-state "
     "sequential model) and confirms the invariant holds under every ordering."),
    # ── C3: Theorem 5.3 rewrite ──────────────────────────────────────────────
    ("### 5.3 Cloud KMS Non-Repudiation\n\n"
     "**Theorem**: Every governance decision is non-repudiably attested by a Cloud KMS "
     "asymmetric signature that cannot be forged without access to the HSM-backed private key.\n\n"
     "**Proof**: Cloud KMS uses FIPS 140-2 Level 3 HSMs. The private key never leaves the HSM. "
     "The signature is produced by `asymmetricSign` over the SHA-256 hash of the governance "
     "decision payload. Forgery requires either breaking ECDSA-P256 or compromising the HSM — "
     "both computationally infeasible under standard cryptographic assumptions. ∎",
     "### 5.3 Routing Seal Authenticity and Reconciliation Non-Repudiation\n\n"
     "**Theorem (Routing Seal Authenticity):** Every governance approval is attested by an "
     "ephemeral HMAC-SHA256 routing seal that cannot be forged without access to the "
     "`GOVERNANCE_SALT` secret.\n\n"
     "**Proof (routing seal):** The routing seal is generated by `generate_seal()` in "
     "`routing_seal.py` as `HMAC-SHA256(GOVERNANCE_SALT, expire_hex || action_slug || "
     "canonical_payload)`. HMAC-SHA256 is existentially unforgeable under chosen-message "
     "attack (EUF-CMA) when the key is secret. The seal provides *authenticity* — any party "
     "holding `GOVERNANCE_SALT` can verify it — but not *non-repudiation*, since the key is "
     "shared between the gateway (issuer) and the actuator (verifier). The 30-second TTL "
     "prevents replay attacks. ∎\n\n"
     "**Theorem (Reconciliation Non-Repudiation):** Every reconciliation balance payload is "
     "non-repudiably attested by a Cloud KMS ECDSA-P256 asymmetric signature.\n\n"
     "**Proof (reconciliation attestation):** The reconciliation daemon signs balance payloads "
     "with Cloud KMS ECDSA-P256 (`asymmetricSign`). Cloud KMS uses FIPS 140-2 Level 3 HSMs; "
     "the private key never leaves the HSM. This signature provides non-repudiation: only the "
     "KMS key holder can produce a valid signature, and any party with the public key can verify "
     "it. The CBF verifies this signature before trusting the reconciled balance (§4.3).\n\n"
     "**Scope clarification:** The routing seal (HMAC) attests governance *approval* on the "
     "synchronous request path (Table 2, sub-ms latency). The KMS signature (ECDSA-P256) "
     "attests balance *provenance* on the background reconciliation path (Table 3, 108.3 ms "
     "P50). These are distinct mechanisms on distinct paths; the KMS latency does not appear "
     "in Table 2. ∎"),
    # ── C4: CBF proof rewrite ────────────────────────────────────────────────
    ("**Proof sketch**: By definition of `verify_action`, if the result is \"SAFE\" then "
     "`h(S(t+1)) ≥ (1 − γ) · h(S(t))`. Since `γ ∈ (0, 1)` and `h(S(t)) ≥ 0`, we have "
     "`h(S(t+1)) ≥ 0`. By induction, `h(S(t)) ≥ 0` for all `t ≥ 0`. ∎",
     "**Proof:**\n\n"
     "*Base case (t = 0):* The system is initialized with `cash_balance(0) = 100,000` and "
     "`min_cash_balance` from `THRESHOLDS.cbf.min_cash_balance` (default: 1,000 per "
     "`config/governance_thresholds.json`). The operator is responsible for ensuring "
     "`h(S(0)) ≥ 0` at deployment; the CBF `setup()` method bootstraps this value.\n\n"
     "*Inductive step:* Assume `h(S(t)) ≥ 0`. By definition of `verify_action()` in "
     "`cbf.py`, the action is blocked if and only if `h(S(t+1)) < (1 − γ) · h(S(t))` "
     "or `h(S(t+1)) < 0`. Therefore, if `verify_action()` returns `\"SAFE\"`, both "
     "conditions hold: `h(S(t+1)) ≥ (1 − γ) · h(S(t))` and `h(S(t+1)) ≥ 0`. Since "
     "`γ ∈ (0, 1)` and `h(S(t)) ≥ 0`, we have `h(S(t+1)) ≥ 0`. By induction, "
     "`h(S(t)) ≥ 0` for all `t ≥ 0`. ∎\n\n"
     "*Rejection branch:* If `verify_action()` returns a violation string, the action is "
     "blocked before execution; `S(t+1) = S(t)` and `h(S(t+1)) = h(S(t)) ≥ 0`.\n\n"
     "**Premises and limitations:** This theorem assumes (1) `h(S(0)) ≥ 0` at "
     "initialization; (2) the reconciliation daemon provides a valid KMS-signed balance "
     "(§4.3, §5.4) — if the daemon is absent, the CBF raises `CBFStateUnverifiedError` "
     "in production (fail-closed); (3) `verify_action()` and trade execution are atomic — "
     "this is not currently guaranteed (see §5.2 TOCTOU note and §7.2).\n\n"
     "**TOCTOU limitation:** `verify_action()` is read-only; `atomic_verify_and_commit()` "
     "is implemented in `cbf.py` but is not yet wired into the live request-handling "
     "pipeline. Under concurrent agent execution, two agents can both pass the CBF check "
     "against the same pre-action balance and jointly overdraw. The FiscalLimitGuard's "
     "atomic reservation (§5.2) mitigates this at the daily-cap level but not at the "
     "per-trade CBF level. Wiring `atomic_verify_and_commit()` into the serving path is "
     "tracked as future work (§7.3)."),
    # ── C4: §4.3 γ default correction ───────────────────────────────────────
    ("where `γ = 0.1` (default). An action is safe if and only if the post-action balance "
     "satisfies this condition.",
     "where `γ` is configurable via `THRESHOLDS.cbf.gamma` in "
     "`config/governance_thresholds.json` (default: 0.5 in the reference configuration). "
     "An action is safe if and only if the post-action balance satisfies this condition."),
    # ── C5: §5.5 hash formula correction ────────────────────────────────────
    ("record\\_hash(r\\_i) \\= SHA-256(\n\n"
     "    prev\\_hash(r\\_{i-1}) ‖ content\\_json(r\\_i) ‖ control\\_id(r\\_i)\n\n"
     "    ‖ event\\_type(r\\_i) ‖ node\\_index(r\\_i) ‖ audit\\_id(r\\_i)\n\n"
     ")",
     "record_hash(r_i) = SHA-256(\n\n"
     "    JSON_sorted({\n"
     '        "schema":      _SCHEMA,\n'
     '        "node_index":  r_i.node_index,\n'
     '        "audit_id":    r_i.audit_id,\n'
     '        "control_id":  r_i.control_id,\n'
     '        "event_type":  r_i.event_type\n'
     "    }) || json.dumps(r_i.payload, sort_keys=True)\n\n"
     ")\n\n"
     "where `JSON_sorted` denotes `json.dumps(..., sort_keys=True, "
     'separators=(",", ":"))` and `||` denotes UTF-8 string concatenation. '
     "The `prev_hash` field of `r_i` stores `record_hash(r_{i-1})` (or the "
     "sentinel `\"GENESIS\"` for i=0), so any modification to `r_{i-1}` changes "
     "`record_hash(r_{i-1})`, which changes `r_i.prev_hash`, which changes "
     "`record_hash(r_i)`, propagating invalidation forward through the chain. "
     "Key-sorted JSON serialization provides canonical encoding, preventing "
     "field-reordering attacks. This formula matches `_link_hash()` in "
     "`src/compliance_bridge/context_accumulator.py`."),
    # ── C5b: withdraw schema 1.1 claim ──────────────────────────────────────
    ("a schema version bump to `cage-context-accumulator/1.1` with version-dispatched "
     "verification preserves backward compatibility.",
     "The current implementation uses schema `cage-context-accumulator/1.0` "
     "(`context_accumulator.py:71`). A schema version bump to `1.1` with "
     "version-dispatched verification to support both old and new artifacts in the "
     "same WORM archive is tracked as future work (§7.3)."),
    # ── C5b: §7.2 schema versioning limitation ───────────────────────────────
    ("**Evidence chain schema versioning**: The `record_hash` binding change (§5.5) is "
     "not backward-compatible. NDJSON artifacts produced before the "
     "`cage-context-accumulator/1.1` schema bump will not re-verify under the new hash "
     "function. Deployments with WORM archive requirements must coordinate a schema "
     "migration or accept that pre-migration artifacts are verified only against the v1.0 "
     "hash function.",
     "**Evidence chain schema versioning**: The `record_hash` binding change (§5.5) is "
     "not backward-compatible. NDJSON artifacts produced before this change will not "
     "re-verify under the new hash function. The current schema is "
     "`cage-context-accumulator/1.0`; a `1.1` bump with version-dispatched verification "
     "is tracked as future work (§7.3). Deployments with WORM archive requirements must "
     "coordinate a schema migration or accept that pre-migration artifacts are verified "
     "only against the v1.0 hash function."),
    # ── ST4: VSM System 4 correction ─────────────────────────────────────────
    ("- **System 4 (Intelligence/Adaptation)**: Sustained by the adaptive self-healing "
     "feedback loop that dynamically adjusts policy variables based on environment feedback.",
     "- **System 4 (Intelligence/Adaptation)**: Represented by the STPA compiler and "
     "OSCAL exporter, which translate environmental hazard analysis into updated policy "
     "artifacts. A fully adaptive, self-healing policy-adjustment loop is tracked as "
     "future work (§7.3); the current implementation uses statically compiled policies "
     "regenerated on each CI run."),
    # ── ST7: §4.7 fail-safe contradiction fix ────────────────────────────────
    ("this silently removes the causal gatekeeper (Tier 6\\) from the pipeline. "
     "These checks run before the gateway begins accepting traffic, ensuring the service "
     "fails fast rather than surfacing gaps on the first live request.",
     "this raises a `RuntimeError` at import time, preventing the service from starting "
     "at all. These checks run before the gateway begins accepting traffic, ensuring the "
     "service fails fast rather than surfacing gaps on the first live request. "
     "(Note: the phrase 'silently removes' in an earlier draft was a contradiction — "
     "a `RuntimeError` at startup is not silent; the service halts before accepting "
     "any traffic.)"),
    # ── ST18: remove arXiv endorsement bullet ────────────────────────────────
    ("\n**Endorsement requirement**: arxiv requires endorsement from an established "
     "researcher for first-time submitters to cs.CR or cs.AI. This is a non-technical "
     "blocker that must be resolved before submission.\n",
     "\n"),
    # ── ST18: relocate ReDoS to implementation note ──────────────────────────
    # (leave in place but reframe as historical hardening, not ongoing limitation)
    ("**ReDoS in PII scrubbing**: Prior to this work, the email PII pattern in "
     "`PIISanitizer` and `scrub_pii` used unbounded quantifiers, causing quadratic "
     "backtracking on adversarial no-TLD inputs. A crafted 128 KB body could stall the "
     "async event loop for seconds on the unauthenticated `POST /v1/chat/completions` "
     "path. Bounding the local part to `{1,64}` and the domain to `{1,255}` (RFC 5321 "
     "maxima) makes the scan linear while preserving matching behaviour for all valid "
     "addresses.",
     "**PII scrubbing hardening (resolved)**: An earlier version of the email PII "
     "pattern in `PIISanitizer` and `scrub_pii` used unbounded quantifiers, causing "
     "quadratic backtracking on adversarial no-TLD inputs. This was remediated by "
     "bounding the local part to `{1,64}` and the domain to `{1,255}` (RFC 5321 maxima), "
     "making the scan linear while preserving matching behaviour for all valid addresses. "
     "This is a resolved historical hardening item, not an ongoing limitation."),
    # ── ST6: HTTP-layer Tier-1 label disambiguation ───────────────────────────
    ("The inference proxy enforces input governance — Tier-1 keyword scan,",
     "The inference proxy enforces input governance — HTTP-layer keyword scan,"),
    # ── ST2: ConfabulationScorer definition ──────────────────────────────────
    ("SymbolicGovernor (8-tier pipeline) + ConfabulationScorer",
     "SymbolicGovernor (8-tier pipeline) + ConfabulationScorer (a non-blocking "
     "AI 600-1 §2.1 scorer that evaluates response faithfulness via Langfuse "
     "and emits a `confabulation_score` OTel attribute; it does not gate execution)"),
    # ── ST3: REDACT/TERMINATE mapping ────────────────────────────────────────
    ("CAGE implements all six primitives and satisfies all four invariants.",
     "CAGE implements all six primitives and satisfies all four invariants. "
     "BLOCK and DEFER map to the governor's DENY and HITL escalation paths. "
     "REDACT maps to `inference_proxy.py`'s `scrub_pii()` function, which "
     "masks PII before the payload reaches the agent. TERMINATE maps to the "
     "`dge_action: TERMINATED_WITH_ROLLBACK` verdict emitted by the governor "
     "when a saga compensating action is triggered. AUDIT and ESCALATE map to "
     "the NDJSON audit chain and the `DeferQueue` HITL path respectively."),
    # ── S3: §6.5 parameter disclosure ───────────────────────────────────────
    ("A subsequent `execute_trade` request for $10,000 produced two different verdicts "
     "depending on which balance the CBF consulted:",
     "The experiment used the following CBF parameters from "
     "`config/governance_thresholds.json`: `min_cash_balance = $1,000`, `γ = 0.5`. "
     "With these parameters: `h(current) = $8,000 − $1,000 = $7,000`; "
     "`h(next) = $8,000 − $10,000 − $1,000 = −$3,000`; "
     "`threshold = (1 − 0.5) × $7,000 = $3,500`. "
     "Since `h(next) = −$3,000 < threshold = $3,500`, the action is blocked. "
     "A subsequent `execute_trade` request for $10,000 produced two different verdicts "
     "depending on which balance the CBF consulted:"),
    # ── S1: §6.2 scope caveat ────────────────────────────────────────────────
    ("All tiers complete well within the 200 ms FedNow/SEPA Instant budget.",
     "All tiers complete well within the 200 ms FedNow/SEPA Instant budget.\n\n"
     "**Scope of Table 2:** These measurements isolate pure governance-logic CPU cost "
     "by mocking all I/O-bound dependencies. They establish that the *computational* "
     "overhead of the governance pipeline is negligible relative to the 200 ms SLA. "
     "End-to-end latency in a deployed system will be dominated by network round-trips "
     "to Redis (~1–3 ms in-cluster), OPA HTTP (~2–5 ms in-cluster), and consensus RPC "
     "(variable). A full end-to-end benchmark against the live GKE cluster is tracked "
     "as future work (§7.3). The 200 ms SLA claim should be read as: 'the governance "
     "logic itself does not consume a material fraction of the SLA budget,' not as "
     "'the full governed request completes in sub-ms time.'"),
    # ── S2: §6.6 baseline caveat ─────────────────────────────────────────────
    ("This security was achieved without sacrificing performance: the total governance "
     "pipeline operates within the 200 ms soft SLA target, demonstrating that robust, "
     "multi-layered cybernetic governance and zero-trust verification can be deployed in "
     "production without introducing significant performance overhead to real-time "
     "financial systems.",
     "This security was achieved without sacrificing performance: the total governance "
     "pipeline operates within the 200 ms soft SLA target, demonstrating that robust, "
     "multi-layered cybernetic governance and zero-trust verification can be deployed in "
     "production without introducing significant performance overhead to real-time "
     "financial systems.\n\n"
     "**Evaluation limitations:** We do not report an un-governed baseline (the same 21 "
     "payloads against the LLM without CAGE) or a benign prompt evaluation (false "
     "positive rate). Without a baseline, the 100% deflection rate cannot be attributed "
     "specifically to CAGE's governance pipeline vs. the underlying model's native safety "
     "tuning. Without a benign evaluation, the false positive rate of the pipeline is "
     "unknown. A benign dataset (`tests/red_team/benign_dataset.json`, 20 prompts) and "
     "an un-governed baseline mode have been added to `scripts/measure_paper_metrics.py` "
     "for future measurement runs; results are tracked as future work (§7.3)."),
    # ── S9: amortised latency framing ────────────────────────────────────────
    ("Amortised per-request overhead: `T_reconcile / (poll_interval_s × request_rate_hz)`. "
     "Using the P50 total (~172 ms) at 60 s polling and 10 req/s, amortised overhead ≈ "
     "0.29 ms/request — still negligible relative to the 200 ms governance budget, even "
     "before accounting for in-cluster KMS latency improvements.",
     "**Background amortisation note:** The reconciliation daemon operates on a decoupled "
     "60-second polling loop; its execution duration dictates data freshness but does not "
     "sequentially block the synchronous gateway pipeline. The calculation "
     "`T_reconcile / (poll_interval_s × request_rate_hz)` = 172 ms / (60 s × 10 req/s) "
     "≈ 0.29 ms/request expresses the *background* write-path cost amortised across "
     "requests — it is not a per-request synchronous overhead and should not be compared "
     "directly to the 200 ms synchronous governance SLA. The practical conclusion is that "
     "the reconciliation daemon's background polling cost is negligible relative to the "
     "request rate, not that each request incurs 0.29 ms of reconciliation overhead."),
    # ── S4: STPA compiler mechanism ──────────────────────────────────────────
    ("The compiler eliminates the manual translation step that introduces policy drift "
     "between the hazard model and the enforcement code.",
     "The compiler is a deterministic, template-based code generator (no LLM involvement). "
     "It ingests `config/stpa_control_structure.yaml`, validates it against a Pydantic "
     "schema (`ControlStructureModel`), and generates artifacts via per-target template "
     "functions: `generate_opa()` emits Rego rules by mapping each UCA's `condition` "
     "(operator, parameter, threshold) to a Rego predicate; `generate_nemo()` emits "
     "Colang 2.x flow definitions from `nemo_rail` fields; `generate_python()` emits a "
     "`GeneratedSTPAValidator` class with one check method per UCA; `generate_langgraph()` "
     "emits Write-Ahead Log forward nodes and idempotent compensating nodes from "
     "`langgraph_saga` fields. The compiler is invoked as "
     "`python -m src.gateway.governance.stpa_compiler compile`.\n\n"
     "The compiler eliminates the manual translation step that introduces policy drift "
     "between the hazard model and the enforcement code."),
    # ── S5: Tier 2 confidence derivation ─────────────────────────────────────
    ("**Tier 2 — Confidence Scoring**: Evaluates the agent's confidence in the action. "
     "Actions below the threshold (default: 0.95) are escalated to HITL.",
     "**Tier 2 — Confidence Scoring**: Evaluates the agent's confidence in the action. "
     "The confidence score is a field in the action payload (`params[\"confidence\"]`), "
     "expected to be set by the agent's reasoning layer before submitting the action for "
     "governance. The SLM sidecar that previously computed an independent confidence score "
     "has been deprecated to reduce latency; the OPA policy (`system_authz.rego`) enforces "
     "a higher threshold (0.97 vs. 0.95) when the `slm_available: false` sentinel is "
     "present. Actions below the threshold (default: 0.95) are escalated to HITL."),
    # ── ST5: FTRA dynamic routing caveat ─────────────────────────────────────
    ("This pre-execution gate catches unsafe trajectories before any tool call is made.",
     "This pre-execution gate catches unsafe trajectories before any tool call is made. "
     "**Architectural assumption:** FTRA assumes a plan-and-execute agent architecture "
     "where a complete multi-step trajectory is formulated prior to any execution. "
     "For agent architectures that dynamically or reactively resolve future tool calls "
     "based on intermediate environment observations, FTRA operates on the plan available "
     "at commencement time and applies a fail-closed default (`BLOCKED`) when the plan "
     "is incomplete or absent."),
    # ── ST8: Remove duplicate AgenTRIM paragraph ─────────────────────────────
    ("**AgenTRIM** \\[2026\\] similarly addresses tool misuse in LLM agents, while "
     "adversarial evaluation studies \\[Deng et al., 2025\\] confirm the attack surface "
     "that CAGE's deflection pipeline targets.\n\n"
     "**AgenTRIM** \\[35\\] similarly addresses tool misuse in LLM agents, while "
     "adversarial evaluation studies \\[36\\] confirm the attack surface that CAGE's "
     "deflection pipeline targets.",
     "**AgenTRIM** \\[35\\] similarly addresses tool misuse in LLM agents, while "
     "adversarial evaluation studies \\[36\\] confirm the attack surface that CAGE's "
     "deflection pipeline targets."),
    # ── ST8: Remove duplicate Routing Seal paragraph ─────────────────────────
    ("**Runtime Routing Seal**: Once all checks inside `_run_checks()` return zero "
     "violations, `routing_seal.py` generates an ephemeral symmetric routing token "
     "formatted as `<expire_ts_hex>.<action_slug>.<hmac_hex>` using HMAC-SHA256 keyed "
     "by a high-entropy `GOVERNANCE_SALT`. The seal lifetime is 30 seconds (configurable "
     "via `GOVERNANCE_SEAL_TTL_S`). The `require_cleared_seal` decorator provides strict "
     "enforcement: it calls `verify_seal()` and raises a `SymbolicGovernorViolation` "
     "before the wrapped callable is invoked, making it impossible for callers to silently "
     "ignore a failed verification. This design directly eliminates the Confused Deputy "
     "class of attacks catalogued in AARM-V3 \\[23, 24\\].  \n"
     "**Runtime Routing Seal**: Once all checks inside `_run_checks()` return zero "
     "violations, `routing_seal.py` generates an ephemeral symmetric routing token "
     "formatted as `<expire_ts_hex>.<action_slug>.<hmac_hex>` using HMAC-SHA256 keyed "
     "by a high-entropy `GOVERNANCE_SALT`. The seal lifetime is 30 seconds (configurable "
     "via `GOVERNANCE_SEAL_TTL_S`). The `require_cleared_seal` decorator provides strict "
     "enforcement: it calls `verify_seal()` and raises a `SymbolicGovernorViolation` "
     "before the wrapped callable is invoked, making it impossible for callers to silently "
     "ignore a failed verification. This design directly eliminates the Confused Deputy "
     "class of attacks catalogued in AARM-V3 \\[Errico, 2026; Cloud Security Alliance, "
     "2026\\].",
     "**Runtime Routing Seal**: Once all checks inside `_run_checks()` return zero "
     "violations, `routing_seal.py` generates an ephemeral symmetric routing token "
     "formatted as `<expire_ts_hex>.<action_slug>.<hmac_hex>` using HMAC-SHA256 keyed "
     "by a high-entropy `GOVERNANCE_SALT`. The seal lifetime is 30 seconds (configurable "
     "via `GOVERNANCE_SEAL_TTL_S`). The `require_cleared_seal` decorator provides strict "
     "enforcement: it calls `verify_seal()` and raises a `SymbolicGovernorViolation` "
     "before the wrapped callable is invoked, making it impossible for callers to silently "
     "ignore a failed verification. This design directly eliminates the Confused Deputy "
     "class of attacks catalogued in AARM-V3 \\[23, 24\\]."),
    # ── ST14: Fix [6] editorial note ─────────────────────────────────────────
    ("\\[6\\] Federal Reserve. \"Supervisory Guidance on Model Risk Management.\" "
     "SR 11-7, 2011\\. \\[Note: SR 26-2 is the successor guidance — verify citation "
     "when published.\\]",
     "\\[6\\] Federal Reserve. \"Supervisory Guidance on Model Risk Management.\" "
     "SR 11-7, 2011\\. (SR 26-2 is the anticipated successor guidance; cite SR 11-7 "
     "until SR 26-2 is formally published.)"),
]

count_total = 0
miss_count = 0
for old, new in replacements:
    count = text.count(old)
    if count:
        text = text.replace(old, new)
        count_total += count
        print(f"  [{count}x] {old[:70].strip()!r}")
    else:
        print(f"  [MISS] {old[:70].strip()!r}")
        miss_count += 1

paper.write_text(text)
print(f"\nDone. {count_total} substitutions applied, {miss_count} missed.")

if miss_count:
    print(
        f"\nERROR: {miss_count} replacement block(s) did not match any text in "
        f"{paper}.\n"
        "The paper text may have already been updated, or the replacement block\n"
        "is stale. Fix or remove the stale block before committing.\n"
        "See docs/paper/MEASUREMENT_RUNBOOK.md Step F for guidance."
    )
    sys.exit(1)
