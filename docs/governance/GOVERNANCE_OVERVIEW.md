# Cybernetic Governance of Agentic AI

**Last Updated:** 2026-09-07 | **System Version:** v3.0.1

> **Jurisdiction separation principle:** **ISO/IEC 42001:2023** is the **sole universal governance baseline** — every control, pipeline step, and audit artifact in this document applies to all deployment regions (`US_FED`, `EU_ECB`, `APAC_MAS`). All other regulatory frameworks are **additive, jurisdiction-specific layers** activated exclusively by the `CAGE_DEPLOYMENT_REGION` environment variable:
> - **US_FED only:** SR 26-2 (Federal Reserve), NIST AI 600-1, NIST SP 800-53, NIST AI RMF
> - **EU_ECB only:** EU AI Act, GDPR Art. 22, DORA
> - **APAC_MAS only:** MAS FEAT Principles, MAS Notice 655, MAS TRM
>
> Controls marked *(All Regions)* are ISO 42001 obligations. Controls marked with a specific region are additive obligations for that jurisdiction only.

> **Release Note (v3.0.1):** This document reflects the v3.0.1 stable release. Key changes in v3.0.1:
> - **Lua-Atomic CBF Check & Commit (CR-3):** `ControlBarrierFunction.atomic_verify_and_commit()` collapses barrier checks and balance commits into a single atomic Redis Lua execution, eliminating TOCTOU race conditions.
> - **Strictly Human-Gated NeMo Refinement (CR-2):** Autonomous auto-apply branch removed; all refinements require human review via `POST /v1/nemo/propose-refinement` and `POST /v1/nemo/approve-refinement/{proposal_id}`.
> - **Evidence Stream Schema Consolidation (CR-1):** Canonical `1.1` schema enforcing 6-field `record_hash` cryptographic binding.
> - **Centralized Threshold Governance:** Numeric thresholds centralized under `config/thresholds/<REGION>_BASELINE.json` accessed via typed accessor functions.
> - **Operational External Reconciliation (POAM-023 / POAM-2026-038 CLOSED):** GCS WORM ledger + Cloud KMS signing + 300s TTL in Redis.
> - **NARROW Primitive:** Bounded partial-authority execution on re-verified clamped parameters.
> - **Seams Contracts Extraction:** Zero-kernel-import boundaries isolating `NormativeProvider`, `AttestationProvider`, and `ExecutionActuator` in `src/gateway/governance/seams/`.

> - **External Hold Generalization:** `DeferReason.EXTERNAL_HOLD` replaces legacy vendor-specific `FLOWSIGNAL_ESCALATION` routing.

> - **Full RefusalReceipt v3:** Complete `RefusalReceipt` v3 serialization into the evidence stream.

> - **Attestation Failure Attributability:** First-class `provider_name` logging and `fetch_error` attribution, along with Ed25519 CER signature verification.

> - **In-Kernel ConsequenceToken & ContentAddress:** Cryptographically secure references decoupled from storage mechanisms.

This document describes the **Cybernetic Governance** framework that transforms the Financial Advisor agent from a probabilistic LLM application into a deterministic, engineering-controlled system. For the full architectural detail, see [`ARCHITECTURE.md`](../architecture/ARCHITECTURE.md).

## 1. Theoretical Framework: Hybrid Reasoning Architecture & STPA

We utilize a **Hybrid Reasoning Architecture** to solve the "Recursive Paradox" of agent safety (High Variety vs. Low Safety). This architecture combines **deterministic workflow control** (LangGraph) with **LLM-powered reasoning** (native LangChain Runnables).

We also employ **Systems-Theoretic Process Analysis (STPA)** to identify and mitigate Unsafe Control Actions (UCAs). See [`docs/security/STPA_ANALYSIS.md`](../security/STPA_ANALYSIS.md) for the detailed hazard analysis.

- **Variety Attenuation:** Ashby's Law ($V_R \ge V_A$) is used to constrain the agent's infinite action space ($V_A$) into a manageable set of states verified by the governance stack ($V_R$).
- **Explicit Routing (LangGraph):** Unlike standard "tool-use" agents that probabilistically choose tools, the **Supervisor Agent** (implemented in **LangGraph**) uses a deterministic `StateGraph` to transition between states. This forms the "hard logic" cage around the probabilistic "soft logic" of the LLM.

### 2. The Dynamic Risk-Adaptive Stack

The architecture enforces "Defense in Depth" through a **8-tier `SymbolicGovernor` pipeline** (`Tier 0.5` through `Tier 6`, executed in two phases via `run_pipeline()` in `src/gateway/governance/governor/pipeline.py`) backed by supporting infrastructure layers and the broader **15 security & governance control points** wrapping the entire system.

> **See also:** [`docs/governance/NEURO_SYMBOLIC_GOVERNANCE.md`](NEURO_SYMBOLIC_GOVERNANCE.md) for the full neuro-symbolic architecture detail.

#### Pre-Pipeline: NeMo Guardrails (Layer 0)

**Goal:** Input/Output safety, topical control, and **PII filtering**.

NeMo Guardrails runs **before** the governor pipeline is invoked. It is integrated into the gateway process (not a standalone sidecar service). The `nemo-service` pod in the `governance-stack` namespace hosts the standalone Colang runtime for external callers, but the production inference path uses the in-process singleton in `src/integrations/nemo/manager.py`. NeMo delegates all LLM inference to the vLLM endpoint via the `vllm_llama` engine in `config/rails/config.yml`.

- **PII Filtering:** **Microsoft Presidio** (15 entity types) detects and masks PII in both user input and agent output. Spacy `en_core_web_sm` provides entity recognition.
- **Implementation:** `src/integrations/nemo/manager.py` & `config/rails/`
- **No governance context injection:** NeMo input rails do not run STPA/CBF checks or receive their results. The former `pre_check()` context injection was removed (#261) because no Colang flow consumed it; all governance checks run once, in the governor pipeline.
- **Observability (ISO 42001):** A custom `NeMoOTelCallback` intercepts every guardrail intervention and emits an OpenTelemetry span with `langfuse.trace.metadata.guardrail.outcome` and `langfuse.trace.metadata.iso.control_id="A.6.2.8"`.

#### The 8-Tier Two-Phase Governance Pipeline (`SymbolicGovernor` / `run_pipeline()`)

The `SymbolicGovernor` in `src/gateway/governance/governor/governor.py` (orchestrated by `run_pipeline()` in `src/gateway/governance/governor/pipeline.py`) is the central enforcement engine. Tier labels follow the authoritative `TIER_LABELS` mapping in `proof/model.py` (`Tier 0.5` through `Tier 6`). Execution is split into **Phase 1** (sequential read-only validation stages) and **Phase 2** (sequential mutating commit stages with LIFO rollback via `ReservationScope`), where Phase 2 **commits** only if all Phase 1 stages produce zero violations (non-`HARD` findings run it as a side-effect-free preview instead; see [Two-Phase Pipeline Execution](#two-phase-pipeline-execution-phase-1-read-only--phase-2-mutating-commitrollback)):

| Tier | Phase | Name | Implementation | Notes |
|------|-------|------|---------------|-------|
| **Tier 0.5** | Phase 1 (Read-Only) | FTRA Action Classification & Reachability | `FtraStage.run()` (`src/gateway/governance/governor/stages/ftra.py`, `src/gateway/governance/ftra/`) | Validates semantic tool parameters and classifies actions (`IRREVERSIBLE_TERMINAL`, `REVERSIBLE`, `READ_ONLY`) against the signed terminal registry; complements the pre-execution graph gate (`create_ftra_node()`). |
| **Tier 1** | Phase 1 (Read-Only) | STPA UCA Constraint Check | `StpaStage.run()` (`src/gateway/governance/governor/stages/stpa.py`, `src/gateway/governance/stpa_validator.py`) | Evaluates ontology-defined Unsafe Control Actions (`src/cage_finance/stpa/uca_rules.py`). Every finding is `HARD`: a UCA is never routable to a human, so `StpaStage` promotes any non-`HARD` kind a validator returns. |
| **Tier 3b** | Phase 1 (Read-Only) | OPA Policy Evaluation | `OpaStage.run()` / `OPAClient.evaluate_policy()` (`src/gateway/governance/governor/stages/opa.py`, `src/gateway/core/policy.py`) | Evaluates declarative Rego policy (`src/cage_finance/opa/trade_governance.rego`, `deployment/system_authz.rego`) prior to any state mutation and records `opa_verdict` on `StageContext`. |
| **Tier 2** | Phase 1 (Read-Only) | Agentic Confidence Gate | `ConfidenceStage.run()` (`src/gateway/governance/governor/stages/confidence.py`) | Checks self-reported confidence against `get_agent_confidence_threshold()` (default 0.95; `EU_ECB` elevates to 0.97). Runs after `stpa` and `opa`, so it is reached only over a clean STPA check and a decided OPA verdict (both refuse with `HARD` otherwise). |
| **Tier 5** | Phase 1 (Read-Only) | Multi-Agent Consensus | `ConsensusGate.check_consensus()` (`src/gateway/governance/consensus/engine.py`, `src/cage_finance/tiers/consensus_tier.py`) | For trades exceeding $10,000 USD: two concurrent LLM critics ("Risk Manager" and "Compliance Officer") must reach unanimity. 10-second per-critic timeout (`CONSENSUS_CRITIC_TIMEOUT_S`, default `10.0`s). Any dissent or error escalates. Degraded-quorum routing: `ERROR + APPROVE → ESCALATE` (HITL) is explicitly handled. |
| **Tier 6** | Phase 1 (Read-Only) | DoWhy Causal Gatekeeper | `causal_safety_check()` (`src/gateway/governance/causal/gatekeeper.py`, `src/cage_finance/tiers/causal_tier.py`) | Constructs a `CausalModel` (market_volatility → trade_amount → risk_score), estimates causal effect via backdoor linear regression, then applies a **Placebo Treatment Refuter** (50 simulations, p < 0.05). Dispatched via `asyncio.to_thread`. Fail-safe: blocks on any exception or missing live telemetry in production. Redis connection errors are fail-closed (raise `RuntimeError`); absent keys return `None` (first-boot safe). |
| **Tier 3a** | Phase 2 (Mutating) | Control Barrier Function | `ControlBarrierFunction.atomic_verify_and_commit()` (`src/gateway/governance/safety/cbf_engine.py`, `src/cage_finance/tiers/cbf_tier.py`) | Redis-backed cash balance invariant. Uses Lua atomic check+commit. Reads KMS-signed reconciled balance (POAM-023 / POAM-2026-038) when available. Each commit ledgers its debit by `debit_id` (`cbf:debits` HASH + `cbf:debits:total`, inside the Lua script) and nets the running total from the reconciled snapshot to prevent intra-window double-spend; the reconciler settles debits only up to the custodian's signed `settled_through` ([ADR-010](../adr/ADR-010-settlement-aware-debit-ledger.md)). Previews (`verify_action()`) read the same total but never debit. Commits in Phase 2 only after all Phase 1 stages pass with zero violations. |
| **Tier 4** | Phase 2 (Mutating) | Fiscal Limit Pre-Reservation | `FiscalLimitGuard.reserve()` (`src/cage_finance/safety/fiscal_limit_guard.py`, `src/cage_finance/tiers/fiscal_tier.py`) | Atomically reserves the requested USD amount against the daily cap in Redis (Lua script, read-write) in Phase 2 after all read-only tiers pass. The reservation is confirmed only after the trade executes (`SymbolicGovernor.settle(seal, executed=True)`), released by `ReservationScope` (LIFO) if a subsequent mutating stage fails or no routing seal is issued, and reclaimed after its TTL if never settled (ADR-009). |

**Routing Seal v2 timing & evidence binding:** The KMS-backed routing seal (`generate_seal_with_evidence()` in `src/gateway/governance/routing_seal.py`) is issued **only after all pipeline tiers complete successfully**. The seal utilizes a 4-tuple format `<expire_hex>.<action_slug>.<record_hash_hex>.<hmac_hex>` where the SHA-256 `record_hash` of the durable evidence item is folded directly into the HMAC input. In production (`CAGE_REQUIRE_EVIDENCE_BINDING=true`), actuators strictly reject un-bound or tampered seals.

**6 Governance Runtime Decision Primitives (`SymbolicGovernor.validate_action()`):**
1. `ALLOW` — all checks passed; issues cryptographic routing seal v2.
2. `DENY` — hard safety invariant violated; returns `SymbolicGovernorViolation` without seal.
3. `REQUIRE_APPROVAL` — triggers HITL approval workflow; state checkpointed to Redis.
4. `DEFER` — low confidence or incomplete data; context parked in `DeferQueue` (`db=1`, `noeviction`) for asynchronous data injection.
5. `NARROW` — policy violation with partial-authority option; clamps execution parameters to safe bounds.

**HITL (Human-in-the-Loop):** Handled by `src/gateway/governance/defer_queue.py`, triggered by pipeline decisions (e.g., `MANUAL_REVIEW` from OPA or confidence starvation). LangGraph's `interrupt_before=["governed_trader"]` enforces a physical pause before every trade execution; after human approval, `execute_trade_action(deferred_id=...)` consumes the approved token once and `revalidate_post_hitl()` re-runs OPA (Tier 3b) and the CBF (Tier 3a) and Fiscal (Tier 4) mutating tiers under `Profile.POST_HITL` in the gateway before actuation, rolling back committed tiers LIFO on failure.

**Startup guards:** `src/gateway/governance/governor/posture.py` and `src/gateway/governance/governor/bootstrap.py` run startup assertions that raise `RuntimeError` if:
- `dowhy` is not installed in production (Tier 6 would be silently absent)
- KMS readiness probe fails (`KMSGovernanceSigner.validate_ready()`)
- Redis readiness probe fails
- `RECONCILIATION_PROVIDER=stub` with `CAGE_ENV=production` (CAGE-SEC-007)
- Default `GOVERNANCE_SALT` is detected in production (`assert_custom_salt_in_production()`)

#### Supporting Infrastructure (Not Pipeline Steps)

The following components are essential infrastructure but are **not** numbered governance pipeline steps:

| Component | Role | Notes |
|-----------|------|-------|
| **Redis Session Persistence** | Stateful sessions on stateless compute | `AsyncRedisSaver` checkpoints graph state after each node transition; `MemorySaver` fallback emits OTel alert. |
| **Pydantic Schema Validation** | Structural integrity at the request boundary | Strict Pydantic v2 models validate every tool call before it reaches the pipeline. UUID v4, ticker regex `^[A-Z]{1,5}$`, and `trader_role` enforced here. |
| **KMS Routing Seal v2** | Cryptographic authorization between agent nodes | Issued after full pipeline approval (see above). GCP KMS asymmetric signing (primary); HMAC-SHA256 fallback with `record_hash` binding for dev/CI. Implementation: `src/gateway/governance/routing_seal.py` |
| **Synchronous Replication Barrier** | Distributed multi-agent state consistency | Redis `WAIT` synchronization in `src/gateway/governance/safety/cbf_engine.py` with automatic fail-closed rollback (`rollback_state()`) on replica lag timeout in production. |

**OPA RBAC thresholds** (enforced in Tier 3b):

| Role     | ALLOW up to | MANUAL_REVIEW         | DENY         |
| -------- | ----------- | --------------------- | ------------ |
| `junior` | $5,000      | $5,001 – $10,000      | > $10,000    |
| `senior` | $500,000    | $500,001 – $1,000,000 | > $1,000,000 |

- **Canonical policy:** `src/cage_finance/opa/trade_governance.rego` (package `trade.governance`).
- **System authorization:** `deployment/system_authz.rego` — enforces SR 26-2 §IV.B `confidence_sufficient ≥ 0.95` for agentic trade execution (OPA is sole enforcer; Python check is a fast-fail pre-check only).
- **Infrastructure:** OPA runs as a standalone service in the `default` namespace; the gateway calls it via the `OPAClient` with a `CircuitBreaker` (5 failures → 30s open-circuit; DENY-on-open).

---

## Symbolic Governor Pipeline

> **Sources:** [`src/gateway/governance/governor/governor.py`](../../src/gateway/governance/governor/governor.py), [`src/gateway/governance/governor/pipeline.py`](../../src/gateway/governance/governor/pipeline.py), [`proof/model.py`](../../proof/model.py)

`SymbolicGovernor` and `run_pipeline()` implement a strict **8-tier, two-phase governance pipeline** (`TIER_LABELS` in `proof/model.py`: `Tier 0.5` through `Tier 6`). Every tool execution request must pass all applicable Phase 1 read-only stages with zero violations before Phase 2 mutating stages commit, and all Phase 2 stages must commit cleanly before a routing seal is issued.

### 8-Tier Pipeline (`proof/model.py` Tier Labels)

| Tier | Stage ID | Phase | Name | Key Invariant / Action | Source Module |
|------|----------|-------|------|------------------------|---------------|
| **Tier 0.5** | `ftra` | Phase 1 | FTRA reachability & boundary check | `FtraStage.run()` / `IrreversibilityClassifier` + `PlanGraphAnalyzer` classify action irreversibility and graph reachability | `src/gateway/governance/governor/stages/ftra.py`, `src/gateway/governance/ftra/` |
| **Tier 1** | `stpa` | Phase 1 | STPA/STAMP UCA validation | `StpaStage.run()` / `STPAValidator.validate()` checks Unsafe Control Actions defined in the ontology | `src/gateway/governance/governor/stages/stpa.py`, `src/gateway/governance/stpa_validator.py` |
| **Tier 2** | `confidence` | Phase 1 | Agent confidence | Checks self-reported confidence against `get_agent_confidence_threshold()` (default 0.95) | `src/gateway/governance/governor/stages/confidence.py` |
| **Tier 3a** | `cbf` | Phase 2 | Control Barrier Function | `atomic_verify_and_commit()` — Lua atomic Redis check+commit; reads KMS-signed reconciled balance (POAM-023); commits in Phase 2 only after Phase 1 produces zero violations | `src/gateway/governance/safety/cbf_engine.py`, `src/cage_finance/tiers/cbf_tier.py` |
| **Tier 3b** | `opa` | Phase 1 | OPA policy evaluation | `OpaStage.run()` / `OPAClient.evaluate_policy()` evaluates Rego policy in Phase 1 prior to any state mutation | `src/gateway/governance/governor/stages/opa.py`, `src/cage_finance/opa/trade_governance.rego`, `deployment/system_authz.rego` |
| **Tier 4** | `fiscal` | Phase 2 | Fiscal Limit Pre-Reservation | `FiscalLimitGuard.reserve()` atomically reserves the daily fiscal cap in Redis (Lua script, read-write) in Phase 2. `FiscalLimitGuard.release()` returns it via `ReservationScope` if a downstream stage fails; `FiscalLimitGuard.confirm()` makes it permanent once the trade executes; an unsettled reservation is reclaimed after its TTL. | `src/cage_finance/safety/fiscal_limit_guard.py`, `src/cage_finance/tiers/fiscal_tier.py` |
| **Tier 5** | `consensus` | Phase 1 | Consensus (high-value trades) | Unanimous multi-critic gate; threshold $10,000 USD (US_FED); 10-second per-critic timeout (`CONSENSUS_CRITIC_TIMEOUT_S`, default `10.0`s). Degraded-quorum routing: `ERROR + APPROVE → ESCALATE` (HITL) is explicitly handled. | `src/gateway/governance/consensus/engine.py`, `src/cage_finance/tiers/consensus_tier.py` |
| **Tier 6** | `causal` | Phase 1 | Causal gatekeeper | DoWhy `CausalModel` + Placebo Treatment Refuter (50 sims, p < 0.05, \|eff\| > 0.2); `asyncio.to_thread` dispatch. Redis connection errors are fail-closed (raise `RuntimeError`); absent keys return `None` (first-boot safe). | `src/gateway/governance/causal/gatekeeper.py`, `src/cage_finance/tiers/causal_tier.py` |

> **Note:** PII sanitization (`src/gateway/governance/pii_sanitizer.py`) and confabulation scoring (`src/gateway/governance/confabulation_scorer.py`) are **not** sequential stages of `run_pipeline()`. PII sanitization runs inside `src/gateway/governance/uca_logger.py` immediately before a UCA audit record is written to the WORM ledger. Confabulation scoring is a standalone Langfuse observability metric computed independently of the governance decision path.

### NoDirectBind Invariant

The **NoDirectBind invariant** is the foundational safety property of the pipeline:

> *No output produced by an LLM may be bound directly to an executable action (trade, API call, state mutation) without first passing through the full `SymbolicGovernor` pipeline.*

This invariant is enforced structurally: `validate_action()` is the single choke point through which every tool execution request must pass. The caller must present a trusted Linkerd mTLS workload identity to reach it at all (`WorkloadIdentityMiddleware`, `src/gateway/server/workload_identity.py`), and the downstream actuator verifies the governor's routing seal (`verify_seal()`) before it fires. A routing seal is issued **only** after all tiers complete successfully.

### Two-Phase Pipeline Execution (`Phase 1` Read-Only → `Phase 2` Mutating Commit/Rollback)

In `src/gateway/governance/governor/pipeline.py`, `run_pipeline()` separates read-only validation stages from state-mutating reservation stages:

1. **Phase 1 — Sequential Read-Only Validation:** Executes `ftra` (Tier 0.5) → `stpa` (Tier 1) → `opa` (Tier 3b) → `confidence` (Tier 2) → Phase-1 domain tiers (`consensus` Tier 5, `causal` Tier 6) → jurisdiction tiers (`fria`, `EU_ECB` only; see [FRIA Tier](#fria-tier--eu_ecb-only-phase-1-after-causal)). Because every STPA finding and every undecided OPA verdict is `HARD`, `confidence` only ever runs over a clean STPA check and a decided OPA verdict. Evaluation stops immediately at the first `ViolationKind.HARD` violation.
2. **Phase 2 — Gated by `phase2_mode(profile, phase1_kinds)`:**
   - **SKIP** if Phase 1 produced any `HARD` finding: the request is refused and no barrier is consulted.
   - **PREVIEW** if Phase 1 produced any other finding (e.g. an OPA `MANUAL_REVIEW` that parks the trade for a human, or a `NARROWABLE` finding), or under `Profile.DRY_RUN` (`SymbolicGovernor.verify()` / `validate_action()`): `_preview_mutating()` calls each mutating stage's side-effect-free `preview()` and never `commit()`. It continues past non-`HARD` findings and stops at the first `HARD` one. The result is recorded as `PipelineResult.barrier_preview` (`PASS` / `FAIL`) plus `preview_violations`, surfaced in the verdict meta and in the DeferToken `opa_input_snapshot` so the reviewer sees every barrier breach before approving. A `HARD` preview finding (e.g. a CBF or dose barrier) denies before any human is asked.
   - **COMMIT** only when Phase 1 is clean under `Profile.FULL` or `Profile.POST_HITL`: mutating tiers (`cbf` Tier 3a → `fiscal` Tier 4 → any plugin barrier) commit sequentially through a per-request `ReservationScope` (`src/gateway/governance/governor/reservation.py`). If any Phase 2 stage emits a violation or the scope exits without sealing, `ReservationScope.rollback()` undoes all prior commits in reverse (LIFO) order.

   If a committing `govern()` run fails only on `NARROWABLE` findings and narrowing is enabled, `SymbolicGovernor._sealed_narrow()` re-runs the full sealed pipeline on the clamped parameters and, inside the same `ReservationScope`, writes a single-use `narrow:receipt:<seal>` (`src/gateway/governance/narrow_receipt.py`) that the domain tool consumes. If the clamped parameters still breach, or the receipt cannot be written, the commits roll back and the request is denied.

### FRIA Tier — EU_ECB only (phase 1, after `causal`)

The EU AI Act Art. 27 Fundamental Rights Impact Assessment is the `fria` tier ([`FriaTier`](../../src/gateway/governance/jurisdiction/eu_ai_act/fria_tier.py), phase 1, order 7). It is not a domain tier and not part of the universal 8-tier table above: `assemble_governor()` ([`governor/assembly.py`](../../src/gateway/governance/governor/assembly.py)) resolves a `JurisdictionContribution` from `ControlRegistry().active_region` via the `JURISDICTIONS` table ([`jurisdiction/registry.py`](../../src/gateway/governance/jurisdiction/registry.py)). `US_FED` and `APAC_MAS` contribute nothing; `EU_ECB` contributes the `fria` tier, which then runs right after `causal`. Jurisdiction tiers must be phase 1, so `fria` never re-runs under POST_HITL; `proof/model.py` covers it in the `JURISDICTION_TIERS` sub-proof. It claims every action by default. Model confidence plays no part in it.

| Condition | Violation | Outcome |
|-----------|-----------|---------|
| No current FRIA artefact for the action (or system-wide `"*"`) under `CTRL_FRIA_006.assessments` — missing, unparseable, timezone-naive, future-dated, or older than `fria.fria_reassessment_interval_days` (365, `config/thresholds/EU_ECB_BASELINE.json`; Art. 27(2)) | HARD `FRIA_ASSESSMENT_STALE` | DENY; no provider call |
| `NormativeProvider.validate_fria()` times out (`CAGE_NORMATIVE_GATE_TIMEOUT_SECONDS`, default 5 s), raises, or returns `error` | HARD `FRIA_PROVIDER_UNAVAILABLE` | DENY |
| Provider admits | — | pass |
| Provider refuses with a finding carrying `needs_human_review: true` | HITL `FRIA_EXTERNAL_HOLD` | REQUIRE_APPROVAL `DeferToken` parked |
| Provider refuses otherwise | HARD `FRIA_REJECTED` | DENY |

`assert_production_posture()` ([`governor/posture.py`](../../src/gateway/governance/governor/posture.py)) runs a `jurisdiction_requirements` check: an enforcing `EU_ECB` posture refuses to start when the `NormativeProvider` is the stub (which admits every assessment).

---

## Mathematical Governance Invariants

The following formal conditions are evaluated at runtime. A violation of any invariant causes the pipeline to halt and the request to be denied.

### Control Barrier Function (CBF) — Tier 3a

**Barrier function:** `h(x) = cash_balance − min_cash_balance`

**Discrete-time CBF condition** (must hold at every time step):

```
h(S(t+1)) ≥ (1−γ) · h(S(t))
```

where γ = 0.5 (from `config/governance_thresholds.json` → `cbf.gamma`), `min_cash_balance` = $1,000 USD. If `h(S(t)) ≥ 0` and the condition holds for all t, then `h(S(t)) ≥ 0` for all t ≥ 0 — the cash balance never falls below `min_cash_balance`.

> **Implementation note (intra-window double-spend prevention, [ADR-010](../adr/ADR-010-settlement-aware-debit-ledger.md)):** `verify_action()` is a pure, side-effect-free preview (`admits(balance, cost)`); it never debits anything. Intra-window double-spend protection lives in Redis: the commit path (`atomic_verify_and_commit()`, called by `commit_barrier`) nets `cbf:debits:total` from the reconciled scalar inside its Lua script and ledgers the admitted debit under its `debit_id`; `rollback_barrier` retires exactly that id; the reconciliation daemon settles debits with `settle_debits_sync()` only up to the signed `settled_through` minus a clock-skew margin ([`debit_ledger.py`](../../src/gateway/governance/safety/debit_ledger.py)).

> **Source:** [`src/gateway/governance/safety/cbf_engine.py`](../../src/gateway/governance/safety/cbf_engine.py)

### Confabulation Risk Score — Langfuse Observability Metric (not a pipeline tier)

```
risk_score = 1.0 − confidence
```

**Decision rule:** `is_confabulation_blocked(confidence)` returns `True` when `confidence < CONFIDENCE_THRESHOLD` (default 0.95). This is a standalone Langfuse score payload builder (`score_confabulation()`), not a step invoked from `SymbolicGovernor`.

> **Source:** [`src/gateway/governance/confabulation_scorer.py`](../../src/gateway/governance/confabulation_scorer.py)

### Causal Marginal Risk Boundary — Tier 6

The causal gatekeeper blocks a trade when the estimated marginal effect of `trade_amount` on `risk_score` pushes the predicted risk above the safety boundary:

```
(0.5 + estimate.value × amount) > 0.95  →  LOCK (trade blocked)
```

Additionally, the Placebo Treatment Refuter (50 simulations) must confirm the world-model is trustworthy: if the placebo still detects a significant effect (p < 0.05 **or** |effect| > 0.2), the model is deemed unreliable and the trade is blocked.

> **Source:** [`src/gateway/governance/causal/gatekeeper.py`](../../src/gateway/governance/causal/gatekeeper.py)

### Confidence Band — Tier 2 (every region)

`ConfidenceStage` evaluates the agent's self-reported confidence against `get_agent_confidence_threshold()` (`confidence.agent_threshold`) and `get_confidence_defer_floor()` (`confidence.defer_floor`):

```
score ≥ 0.95              →  pass
0.70 ≤ score < 0.95       →  HITL violation        (REQUIRE_APPROVAL)
score < 0.70              →  DEFERRABLE violation  (DEFER)
```

FTRA applies the same floor: an irreversible terminal with confidence ≥ `defer_floor` is `HITL_REQUIRED`, below it `BLOCKED`. This band is jurisdiction-neutral and is not a Fundamental Rights Impact Assessment (see [FRIA Tier](#fria-tier--eu_ecb-only-phase-1-after-causal)).

> **Source:** [`src/gateway/governance/governor/stages/confidence.py`](../../src/gateway/governance/governor/stages/confidence.py), [`src/gateway/governance/schemas/thresholds.py`](../../src/gateway/governance/schemas/thresholds.py)

---

## STPA Unsafe Control Actions

> **Source:** [`src/gateway/governance/ontology.py`](../../src/gateway/governance/ontology.py)

The STPA (Systems-Theoretic Process Analysis) ontology defines Unsafe Control Actions (UCAs) as formal inequalities. The `STPAValidator` (`src/gateway/governance/stpa_validator.py`) evaluates these constraints on every request; any violation halts the pipeline at Tier 1.

### Financial UCAs (FIN-*)

| UCA ID | Inequality Condition | Hazard Description |
|--------|---------------------|--------------------|
| **FIN-1** | `trade_value > position_limit` | Trade value exceeds the authorised position limit — unsafe control action |
| **FIN-2** | `portfolio_concentration > 0.25` | Single-asset concentration exceeds 25% of portfolio — unsafe control action |

### General UCAs (UCA-*)

| UCA ID | Inequality Condition | Hazard Description |
|--------|---------------------|--------------------|
| **UCA-2** | `risk_score > 0.8` (missing action) | Required risk-mitigation action is absent when risk score exceeds 0.8 |
| **UCA-5** | `drawdown > stpa.uca5_drawdown_threshold_pct` (4.5%) | Drawdown exceeds permitted percentage — STPA Violation |
| **UCA-6** | `order_size > uca6_max_order_volume_fraction × daily_vol` (1%) | Order size exceeds the permitted fraction of daily volume — STPA Violation |
| **UCA-7** | `market_volatility > threshold` | Action taken during excessive market volatility — timing unsafe control action |

STPA thresholds are sourced from `config/governance_thresholds.json` → `stpa.*` and validated by Pydantic at startup.

### Regional Control Maps

The ontology defines three regional control maps activated by `CAGE_DEPLOYMENT_REGION`:

| Region | Activated By | Additive Obligations |
|--------|-------------|----------------------|
| **US_FED** | `CAGE_DEPLOYMENT_REGION=US_FED` | NIST SP 800-53, SR 26-2 §IV, NIST AI RMF |
| **EU_ECB** | `CAGE_DEPLOYMENT_REGION=EU_ECB` | EU AI Act Art. 27, GDPR Art. 22, DORA Art. 12 |
| **APAC_MAS** | `CAGE_DEPLOYMENT_REGION=APAC_MAS` | MAS FEAT Principles, MAS Notice 655, MAS TRM §4.2 |

All UCAs above are evaluated in **all regions** as part of the ISO 42001 universal baseline. Regional control maps add jurisdiction-specific thresholds and reporting obligations on top of the universal UCA set.

---

## Decoupled Governance Abstraction (Multi-Region Productization)

All hardcoded regulatory citation strings (`SR 26-2 §IV.B`, `ISO 42001 §A.5.2`, etc.) have been removed from Python business logic. The system now uses a multi-region two-layer abstraction layer that dynamically adapts depending on the `CAGE_DEPLOYMENT_REGION` environment variable (`US_FED`, `EU_ECB`, `APAC_MAS`):

| Layer | Location | Purpose |
|---|---|---|
| **Stable Control IDs** | `src/gateway/governance/constants.py` — `GovernanceControl` enum | Internal IDs (`CTRL_AGT_001`…) that never change regardless of which frameworks or regions are active |
| **Regulatory Registry** | `config/compliance/{REGION}_BASELINE.json` *(fallback to legacy `config/control_mappings.json`)* | Single source of truth mapping `CTRL_*` IDs to external frameworks in a region-specific baseline profile — no Python changes required |
| **OSCAL Framework Router** | `config/oscal/framework_mappings/*.json` — loaded by `FrameworkRouter` in `oscal_ssp_exporter.py` | UCA-to-control cross-walk tables for NIST SP 800-53, ISO 42001, EU AI Act, and MAS FEAT — adding a new jurisdiction is a JSON-only operation |

### GovernanceControl → Framework Mapping

| Control ID | Internal ID | Primary Framework | Scope | Governing Module / Active Regions |
|---|---|---|---|---|
| `CTRL_AGT_001` | THR-CONF-001 | ISO 42001 §A.5.2 | Agentic | `src/gateway/governance/governor/stages/confidence.py` — Tier 2 confidence check *(All Regions)* |
| `CTRL_WAL_002` | THR-WAL-002 | ISO 42001 §A.8.4 | Agentic | `src/cage_finance/stpa/saga_nodes.py` — WAL SAGA *(All Regions)* · DORA Art. 12 addendum *(EU_ECB only)* |
| `CTRL_TEL_003` | THR-TEL-003 | ISO 42001 §A.9.4 | Agentic | `src/gateway/governance/telemetry_provider.py`, `src/gateway/governance/causal/gatekeeper.py` *(All Regions)* |
| `CTRL_MRM_004` | THR-MRM-004 | SR 26-2 §IV — Model Risk Management | Traditional ML | `src/gateway/governance/safety/cbf_engine.py` (`ControlBarrierFunction`), `src/gateway/governance/causal/gatekeeper.py` — **US_FED only**; ISO 42001 §A.9.4 is the universal equivalent |
| `CTRL_OPA_005` | THR-OPA-005 | ISO 42001 §A.6.1 | Agentic | `src/gateway/governance/governor/stages/opa.py` — Tier 3b OPA policy check *(All Regions)* |
| `CTRL_FRIA_006` | THR-FRIA-006 | EU AI Act Art. 27 | Agentic | `src/gateway/governance/jurisdiction/eu_ai_act/fria_tier.py` (`FriaTier`), contributed via `src/gateway/governance/jurisdiction/registry.py` — phase-1 `fria` tier after `causal` — **EU_ECB only** |
| `CTRL_TQP_007` | THR-TQP-007 | ISO 42001 Annex A.4 | Agentic | `src/gateway/governance/token_quota_proxy.py` — per-session token + step-count quota enforcement *(All Regions)* |
| `CTRL_DFR_008` | THR-DFR-008 | CSA AARM-V7 / ISO 42001 §A.8.4 | AARM Primitive | `src/gateway/governance/defer_queue.py` — DEFER State Machine *(All Regions)* |
| `CTRL_FTRA_001` | — | ISO 42001 §A.9.4 | Agentic | `src/gateway/governance/ftra/node_factory.py`, `src/gateway/governance/governor/stages/ftra.py` — Tier 0.5 reachability gate *(All Regions)* |

Legacy citations (e.g. `SR 26-2 §IV.B`) are preserved as `legacy_citation` fields inside baseline profiles so SIEM consumers retain backward-compatible alert matching.

### ControlRegistry API & Multi-Region Execution

The `ControlRegistry` is a thread-safe, lock-guaranteed singleton that loads regulatory definitions dynamically at startup:

1. **Activation Pattern:**
   ```bash
   export CAGE_DEPLOYMENT_REGION=EU_ECB  # Options: US_FED (default), EU_ECB, APAC_MAS
   ```
2. **Properties and Methods:**
   - `registry.active_region`: Returns the active region identifier string (`"US_FED"`, `"EU_ECB"`, `"APAC_MAS"`, or `"LEGACY"`).
   - `registry.active_hash`: SHA-256 hash of the currently loaded baseline profile JSON (used for policy version pinning in `validate_action()`).
   - `registry.get_mapping_safe(control)`: Returns `None` instead of raising `KeyError` if a control is absent from the active region's baseline, enabling graceful handling of region-specific controls like `CTRL_FRIA_006`.
   - `ControlRegistry.reconfigure(region)`: Triggers atomic runtime reloading of the baseline profile. Thread-safe: the new instance is loaded outside the lock, then swapped atomically inside a single lock acquisition.

---

## SR 26-2 Compliance — US_FED Only (`CAGE_DEPLOYMENT_REGION=US_FED`)

> **Scope:** The Federal Reserve's SR 26-2 (April 17, 2026) applies **exclusively** to `CAGE_DEPLOYMENT_REGION=US_FED` deployments. EU_ECB and APAC_MAS deployments satisfy equivalent obligations via ISO 42001 and their respective jurisdiction-specific frameworks. No SR 26-2 obligation is imposed on non-US_FED deployments.

The Federal Reserve's SR 26-2 explicitly scopes generative and agentic AI systems *outside* SR 11-7's prescriptive framework, directing institutions to apply rigorous internal risk controls. CAGE addresses all four SR 26-2 examination dimensions:

| SR 26-2 Dimension | CAGE Implementation | Source File |
|---|---|---|
| **Agentic Bounding** | Confidence threshold — `CTRL_AGT_001` (ISO 42001 §A.5.2) | `src/gateway/governance/governor/stages/confidence.py`, `config/control_mappings.json` |
| **Non-Determinism Containment** | WAL + LIFO rollback SAGA — `CTRL_WAL_002` (ISO 42001 §A.8.4) | `src/cage_finance/stpa/saga_nodes.py` |
| **World-Model Validation** | DoWhy `CausalGatekeeper` Phase 2 — `CTRL_TEL_003` (ISO 42001 §A.9.4) on live Langfuse telemetry | `src/gateway/governance/causal/gatekeeper.py`, `src/gateway/governance/telemetry_provider.py` |
| **Traditional MRM (non-agentic)** | CBF formula + DoWhy coefficient validation — `CTRL_MRM_004` (SR 26-2 §IV, US_FED only) | `src/gateway/governance/safety/cbf_engine.py`, `src/gateway/governance/causal/gatekeeper.py` (Phase 1) |

### Four Governance Gap Closures

These were the four original SR 26-2 examination gaps; all are now closed and decoupled from hardcoded regulatory strings via the `GovernanceControl` registry:

| Gap | Closure | Files |
|---|---|---|
| Gap 1 (Live Telemetry) | `LangfuseTelemetryProvider` + `CTRL_TEL_003` OTel spans | `src/gateway/governance/telemetry_provider.py`, `src/gateway/governance/causal/gatekeeper.py` |
| Gap 2 (WAL Atomicity) | MCP tool WAL nodes + `CTRL_WAL_002` annotations | `src/cage_finance/stpa/saga_nodes.py` (compiled via `src/gateway/governance/stpa_compiler.py`) |
| Gap 3 (Terminology) | All audit logs now lead with `[CTRL_*]` IDs; `legacy_citation` in regional profile for SIEM back-compat | `src/gateway/governance/governor/governor.py`, `src/gateway/governance/safety/cbf_engine.py`, `config/compliance/*_BASELINE.json` |
| Gap 4 (Scope) | `config/agent_scope.yaml` retains authoritative SR 26-2 scope block; `CTRL_*` IDs added as stable aliases | `config/agent_scope.yaml` |

## 3. Tiered Observability: The Cost of Transparency

The architecture implements a **Risk-Based Tiered Strategy** balancing operational visibility against cost.

| Tier     | Destination              | Content                  | Sampling Logic                | Purpose                       |
| -------- | ------------------------ | ------------------------ | ----------------------------- | ----------------------------- |
| **Hot**  | OpenTelemetry → Langfuse | Governance spans (100%)  | 100% for governance decisions | Audit evidence, compliance    |
| **Hot**  | OpenTelemetry → Langfuse | General inference spans  | 1% sampling (RA-001)          | Operational health            |
| **Cold** | GCS artifact bucket      | OSCAL Assessment Results | Per Lula 6h CronJob run       | Regulatory compliance records |

**Dual Langfuse projects:**

- **Application project** — inference latency, token counts, model quality metrics
- **Compliance project** — governance verdicts, OPA results, ISO 42001 control evidence

## 4. Implementation Details

### The Deterministic Router (LangGraph)

The canonical agent graph is assembled by `create_graph(redis_url)` in `src/governed_financial_advisor/graph/graph.py`. The graph compiles with:

- **10 nodes:** `nemo_guardrail → thinker_node → doer_node → data_analyst / execution_analyst → evaluator → safety_check → governed_trader → explainer → nemo_output_rail`
- **`interrupt_before=["governed_trader"]`** — mandatory HITL pause before any trade execution
- **`AsyncRedisSaver`** — durable checkpoint persistence; `MemorySaver` fallback emits ERROR log + OTel alert span

All agent transitions are explicitly managed by routing functions (`route_supervisor`, `route_after_evaluator`, `route_after_safety`). Agents return structured state fields; the graph decides the next node deterministically based on those fields.

### Governance Enforcement Path

The gateway-side `validate_action()` / `verify_seal()` pair is the single choke point that intercepts all tool executions:

1. Validates Pydantic schema (infrastructure boundary — not a pipeline step).
2. Optionally verifies `policy_version_id` against `ControlRegistry.active_hash` to detect substrate policy drift.
3. Invokes the full `SymbolicGovernor` two-phase pipeline (`run_pipeline()` in `src/gateway/governance/governor/pipeline.py`): Phase 1 read-only stages — FTRA (Tier 0.5) → STPA (Tier 1) → OPA (Tier 3b) → Confidence (Tier 2) → Consensus (Tier 5) → Causal Gatekeeper (Tier 6) — followed by Phase 2 mutating stages — CBF (Tier 3a) → Fiscal Limit Pre-Reservation (Tier 4) — committed on zero violations, previewed read-only on non-`HARD` findings, and skipped on a `HARD` finding.
4. Issues the governor's KMS-signed routing seal (`src/gateway/governance/routing_seal.py`; HMAC fallback in dev/test only) only after all tiers pass.
5. The downstream actuator calls `verify_seal()` before firing — the wrapped action is never invoked if the seal is missing, expired, or tampered.
6. Wraps execution in ISO 42001-stamped OpenTelemetry spans.

## 5. Local Development

### Prerequisites

- [Open Policy Agent (OPA)](https://www.openpolicyagent.org/docs/latest/#running-opa) installed
- Python ≥ 3.11; `uv` or `pip`

### Running the Stack

1. **Start OPA Server:**
   ```bash
   opa run -s deployment/system_authz.rego --addr :8181
   ```
2. **Install dependencies:**
   ```bash
   uv sync --all-groups --all-extras
   ```
3. **Run Tests:**
   ```bash
   pytest tests/ -v --timeout=60
   ```

## 6. Deployment (Sovereign vLLM on GKE)

The architecture is designed for **Google Kubernetes Engine (GKE)** using the **Sovereign vLLM** pattern — all LLM inference runs within the cluster boundary; no requests are sent to external LLM APIs.

- **Infrastructure:** GKE Standard Cluster with NVIDIA L4 GPU Spot node pools.
- **Reasoning Node:** vLLM serving `DeepSeek-R1-Distill-Llama-8B` (AWQ 4-bit, 32K context, `gpu_memory_utilization=0.9`).
- **Fast Node:** vLLM serving `Meta-Llama-3.1-8B-Instruct` (standard precision, Spot instances).
- **Governance:** OPA in `default` namespace; NeMo Guardrails in `governance-stack` namespace; both accessed over intra-cluster DNS.
- **Communication:** Intra-cluster HTTP/REST and gRPC.

For detailed deployment instructions, see **[DEPLOYMENT_RULES.md](../operations/DEPLOYMENT_RULES.md)** and **[ARCHITECTURE.md](../architecture/ARCHITECTURE.md)**.

---

## 7. v2.1.0 Governance Additions

### FTRA Commencement Reachability Gate (Tier 0.5)

The **Forward-Looking Trajectory Reachability Analyzer (FTRA, `CTRL_FTRA_001`, Tier 0.5)** (`src/gateway/governance/ftra/` and `src/gateway/governance/governor/stages/ftra.py`) operates both as an in-graph **Pre-Execution Boundary Gate** — a dedicated LangGraph node inserted between `evaluator` and `safety_check` that analyzes a proposed multi-step `ExecutionPlan` *before any step runs* to determine whether an irreversible terminal action (e.g. `execute_trade`, `write_db`) is reachable from step 0 — and as **Tier 0.5** (`FtraStage`) at the start of `run_pipeline()` for every per-tool-call request.

> **Note:** FTRA (`ftra`, Tier 0.5) is included in the `TIERS` state tuple in [`proof/model.py`](../../proof/model.py) for the 8-tier `NoDirectBind` BFS verification.

- **`src/gateway/governance/ftra/classifier.py`** — `IrreversibilityClassifier` classifies each plan-step action name (via `config/ftra/terminal_registry.json`) as `IRREVERSIBLE_TERMINAL`, `REVERSIBLE`, or `READ_ONLY`; fail-closed for unregistered actions
- **`src/gateway/governance/ftra/graph_analyzer.py`** — `PlanGraphAnalyzer` builds a NetworkX `DiGraph` over `ExecutionPlan.steps` and runs DFS from step 0 to compute the reachable terminals and critical path
- **`src/gateway/governance/ftra/models.py`** — `TerminalClassification`, `FTRAVerdict` (`CLEAR` \| `HITL_REQUIRED` \| `BLOCKED`), `ReachabilityResult` data models
- **`src/gateway/governance/ftra/node_factory.py`** — `create_ftra_node()` / `route_after_ftra()` — LangGraph node factory and conditional-edge routing, wired into `src/governed_financial_advisor/graph/graph.py`
- **`src/gateway/governance/governor/stages/ftra.py`** — `FtraStage` — Tier 0.5 in-pipeline boundary stage enforcing semantic input validation and irreversibility classification

**Decision semantics:** `CLEAR` proceeds to the OPA `safety_check` node. `HITL_REQUIRED` (irreversible terminal reachable, confidence ≥ 0.70) parks the thread in DeferQueue `db=1` with `DeferReason.FTRA_IRREVERSIBLE_TERMINAL` pending human clearance. `BLOCKED` (confidence < 0.70) routes to `explainer`, halting the plan before any further LLM inference.

### NeMo Guardrails — Full Integration (`src/integrations/nemo/`)

The NeMo integration is now a complete subsystem with the following components:

| Module | Purpose |
|--------|---------|
| [`src/integrations/nemo/manager.py`](../../src/integrations/nemo/manager.py) | In-process NeMo singleton; delegates LLM inference to vLLM via `vllm_llama` engine |
| [`src/integrations/nemo/actions.py`](../../src/integrations/nemo/actions.py) | Custom Colang actions: STPA check, CBF check, OPA check — injected via context to avoid re-entrant loops |
| [`src/integrations/nemo/server.py`](../../src/integrations/nemo/server.py) | Standalone Colang runtime for external callers (`nemo-service` pod) |
| [`src/integrations/nemo/vllm_client.py`](../../src/integrations/nemo/vllm_client.py) | Async vLLM client used by NeMo actions for LLM inference |
| [`src/integrations/nemo/colang/cbrn_rails.co`](../../src/integrations/nemo/colang/cbrn_rails.co) | CBRN (Chemical, Biological, Radiological, Nuclear) content rails — US_FED only; Cat-M change requiring AO pre-approval |

### NIST AI 600-1 Compliance Gates (Phases 0–3)

All four phases of the NIST AI 600-1 implementation are now complete. The following Lula validation manifests are active or stub-ready in `compliance/lula/`:

| Phase | Control | Manifest | Status |
|-------|---------|----------|--------|
| Phase 0 | §2.6 CBRN / Harmful Content | `lula-validation-ai600-cbrn.yaml` | 🔶 Stub (Cat-M: AO pre-approval required) |
| Phase 1 | §2.1 Confabulation | `lula-validation-ai600-confabulation.yaml` | 🔶 Stub (requires Langfuse metric) |
| Phase 2 | §2.2 Data Privacy | `lula-validation-ai600-data-privacy.yaml` | ✅ Active |
| Phase 2 | §2.3 Prompt Injection | `lula-validation-ai600-prompt-injection.yaml` | 🔶 Stub |
| Phase 3 | §2.5 Human-AI Configuration | `lula-validation-ai600-human-ai-config.yaml` | ✅ Active |

### Three-Region Compliance Matrix

CAGE v3.0.1 ships separate OSCAL SSPs and Lula manifests for each deployment region:

| Region | OSCAL SSP | Lula Manifests |
|--------|-----------|----------------|
| **US_FED** | [`compliance/oscal/system-security-plan.yaml`](../../compliance/oscal/system-security-plan.yaml) | SP 800-53 + NIST AI 600-1 manifests |
| **EU_ECB** | [`compliance/oscal/system-security-plan-eu-ecb.yaml`](../../compliance/oscal/system-security-plan-eu-ecb.yaml) | EU AI Act / GDPR / DORA manifests |
| **APAC_MAS** | [`compliance/oscal/system-security-plan-apac-mas.yaml`](../../compliance/oscal/system-security-plan-apac-mas.yaml) | MAS FEAT / Notice 655 / TRM manifests |

Region selection is controlled exclusively by `CAGE_DEPLOYMENT_REGION`. No code changes are required to switch regions.

### AARM 11-Vector Threat Ledger

The AARM conformance engine (`src/compliance_bridge/aarm_mapper.py` + `aarm_report_generator.py`) provides:

- A static, version-pinned ledger mapping all 11 CSA AARM vectors to specific CAGE control points
- `GET /v1/aarm/conformance-report` — returns per-vector `NEUTRALIZED | PARTIAL | EXPOSED` verdicts with optional vLLM narrative enrichment
- Auto-serialization of the report to GCS/S3 on every Lula audit run
- `GovernanceControl.CTRL_AARM_009` maps to this subsystem in the `ControlRegistry`

See [`compliance/lula/lula-validation-aarm-vectors.yaml`](../../compliance/lula/lula-validation-aarm-vectors.yaml) for the Lula validation manifest.
