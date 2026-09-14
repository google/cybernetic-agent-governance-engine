# CAGE Technical Report — Architecture Gap Analysis (TR-01 → TR-06)

| Field | Value |
|---|---|
| **Scope** | [`docs/technical-report/README.md`](../docs/technical-report/README.md), [`01-SYSTEM-OVERVIEW.md`](../docs/technical-report/01-SYSTEM-OVERVIEW.md) → [`06-COMPLIANCE-STANDARDS.md`](../docs/technical-report/06-COMPLIANCE-STANDARDS.md) |
| **Compared against** | `src/` tree at HEAD, `proof/model.py`, `pyproject.toml`, `config/`, `compliance/lula/`, `AGENTS.md` |
| **Type** | Analysis only — no edits made |
| **Codebase version** | `pyproject.toml` `version = "3.0.0"` |

---

## 0. Executive Summary

The technical report series was written against a **pre-v3.0.0-refactor mental model** of CAGE: a monolithic `SymbolicGovernor` with hardcoded, numbered, finance-flavoured tiers living entirely in `src/gateway/governance/`. The code has since moved to a **kernel + registered domain-tier plugin** architecture, and the reports have not followed.

Five systemic gaps dominate. Everything else in this document is a specialization of one of them:

| # | Systemic gap | Impact |
|---|---|---|
| **G1** | **Tier model is stale.** TRs describe a fixed, kernel-owned tier ladder ("Tier 2 = CBF", "Tier 5 = Consensus"). The kernel now owns *no* domain tiers; they are registered by plugins via [`GovernanceTierPlugin`](../src/gateway/governance/contracts.py:218) with `(phase, order)` properties and executed by `_run_domain_tiers()`. | High — the central architectural claim of TR-02/TR-05 is structurally wrong |
| **G2** | **Deprecated module paths persist.** TRs still link to `cbf.py`, `causal_gatekeeper.py`, `fiscal_limit_guard.py`, `compliance_bridge/reconciliation_worker.py`, `safety_params.json`, `governance/policy/trade_governance.rego`. None of these files exist. | High — broken links; contradicts AGENTS.md canonical namespaces |
| **G3** | **Whole kernel subsystems are undocumented.** ~20 Layer-1 modules (consequence gateway, token quota proxy, governance envelope, decisions, null components, evidence cold-store/residency, JCS canonicalizer, plugin loader, attestation aggregator, singletons) appear in no TR. | High — the reports understate the system |
| **G4** | **Layer/plugin architecture is asserted but not specified.** TR-01 states domain-agnosticism as a claim; no TR documents the plugin contract, the entry-point mechanism, `install_domain_components()`, the invariant protocol, or the four-layer split from AGENTS.md. | High — the primary v3 architectural achievement is undocumented |
| **G5** | **Quantitative claims drift.** Test counts, provider counts, node counts, `AgentState` field counts, Lula counts, and decision-primitive counts disagree with code and with each other across documents. | Medium — undermines credibility of the whole series |

---

## 1. Ground Truth: What the Code Actually Looks Like

### 1.1 Layer 1 — Kernel (`src/gateway/`)

Subpackages under [`src/gateway/governance/`](../src/gateway/governance/):

| Subpackage | Modules |
|---|---|
| `causal/` | `gatekeeper.py` |
| `consensus/` | `engine.py` |
| `evidence/` | `stream.py`, `cold_store.py`, `null_cold_store.py`, `factory.py`, `residency.py` |
| `ftra/` | `models.py`, `classifier.py`, `graph_analyzer.py`, `node_factory.py`, `bounding_contract.py` |
| `ingress/` | 8 adapters (AAIF, ACS, OSCAL, Lula, AGP, policy translator, AGW, agent registry) |
| `langgraph_harness/` | `nemo_node_factory.py`, `opa_node_factory.py`, `types.py` |
| `nemo/` | `manager.py`, `actions.py`, `action_registry.py`, `server.py`, `vllm_client.py`, `prompt_fetcher.py`, `colang/cbrn_rails.co` |
| `reconciliation/` | `daemon.py` |
| `safety/` | `cbf_engine.py`, `resource_guard.py` |
| `schemas/` | `thresholds.py` |

Flat kernel modules: `symbolic_governor.py`, `contracts.py`, `decisions.py`, `types.py`, `constants.py`, `singletons.py`, `plugin_loader.py`, `null_components.py`, `iso_control.py`, `jcs_canonicalizer.py`, `governance_envelope.py`, `consequence_gateway.py`, `consequence_token.py`, `consequence_authority_store.py`, `token_quota_proxy.py`, `pause_primitive.py`, `defer_queue.py`, `attestation_aggregator.py`, `attestation_provider.py`, `normative_provider.py`, `telemetry_provider.py`, `kms_signer.py`, `jwks.py`, `routing_seal.py`, `provenance_chain.py`, `execution_actuator.py`, `hitl_escalator.py`, `background_tasks.py`, `env_posture.py`, `http_client_factory.py`, `authorization_claim_detector.py`, `confidence_claim_detector.py`, `confabulation_scorer.py`, `prompt_injection_detector.py`, `pii_sanitizer.py`, `text_filter.py`, `ontology.py`, `uca_logger.py`, `generated_stpa_validator.py`, `generated_saga_nodes.py`, `stpa_compiler.py`, `oscal_ssp_exporter.py`.

### 1.2 Layer 2 — Domain plugins

**Finance** ([`src/cage_finance/plugin.py`](../src/cage_finance/plugin.py)) registers **five** tiers:

| Tier name | Phase | Order | Module |
|---|---|---|---|
| `bounding` | 1 | 2 | [`tiers/bounding_tier.py`](../src/cage_finance/tiers/bounding_tier.py) |
| `cbf` | 2 | 3 | [`tiers/cbf_tier.py`](../src/cage_finance/tiers/cbf_tier.py) |
| `fiscal` | 2 | 4 | [`tiers/fiscal_tier.py`](../src/cage_finance/tiers/fiscal_tier.py) |
| `consensus` | 1 | 5 | [`tiers/consensus_tier.py`](../src/cage_finance/tiers/consensus_tier.py) |
| `causal` | 1 | 6 | [`tiers/causal_tier.py`](../src/cage_finance/tiers/causal_tier.py) |

It also owns `opa/trade_governance.rego`, `models/trade_order.py`, `rails/`, `safety/bounding/`, `tools/` (`execute_trade_action`, `check_market_status`, `get_market_sentiment`, `bounded_execution`, `market_service`), `invariants.py` (`CashBarrier`, `finance_cost_resolver`), and three regional compliance overlays.

**Healthcare** ([`src/cage_healthcare/plugin.py`](../src/cage_healthcare/plugin.py)) registers **two** tiers — `dose_barrier` (phase 2, order 3) and `clinical_consensus` (phase 1, order 5) — plus `SerumConcentrationBarrier`, `HealthcareRailProvider`, `ClinicalToolProvider`, and `opa/dosing_governance.rego`.

### 1.3 Layer 3 — Integrations

[`src/integrations/`](../src/integrations/) contains `provider_01`, `provider_02`, `provider_03`, `provider_05`, `provider_06`, plus **`actuator_01/`**, **`storage_gcs/`**, **`storage_s3/`**. **`provider_04/` does not exist.**

### 1.4 Formal model

[`proof/model.py`](../proof/model.py:128) `TIERS = ("ftra", "stpa", "confidence", "cbf", "opa", "fiscal", "consensus", "causal", "fria")` — nine entries, with `ftra` explicitly at Tier 0.5 and `fria` labelled Tier 7 in-comment. [`tests/test_tier_registry_formal_parity.py`](../tests/test_tier_registry_formal_parity.py:149) pins this tuple.

---

## 2. G2 — Deprecated / Non-Existent Path References (Cross-Cutting)

Every row below is a link or code reference in TR-01…TR-06 that points at a file that **does not exist at HEAD**. These are the highest-confidence, lowest-ambiguity fixes.

| Referenced path | Occurrences | Canonical path (per [`AGENTS.md`](../AGENTS.md)) |
|---|---|---|
| `src/gateway/governance/cbf.py` | [TR-02 §11.1](../docs/technical-report/02-ARCHITECTURE.md:686), [TR-05 §4](../docs/technical-report/05-AI-GOVERNANCE-POLICY-ENGINE.md:153) | `src/gateway/governance/safety/cbf_engine.py` |
| `src/gateway/governance/causal_gatekeeper.py` | [TR-02 §11.2](../docs/technical-report/02-ARCHITECTURE.md:710), TR-09 ×3 | `src/gateway/governance/causal/gatekeeper.py` |
| `src/gateway/governance/fiscal_limit_guard.py` | [TR-02 §6.2](../docs/technical-report/02-ARCHITECTURE.md:400), [TR-05 §8.2](../docs/technical-report/05-AI-GOVERNANCE-POLICY-ENGINE.md:520) | `src/gateway/governance/safety/resource_guard.py` (`FiscalLimitGuard`) |
| `src/compliance_bridge/reconciliation_worker.py` | [TR-05 §9](../docs/technical-report/05-AI-GOVERNANCE-POLICY-ENGINE.md:565) | `src/gateway/governance/reconciliation/daemon.py` |
| `src/gateway/governance/safety_params.json` | [TR-02 §12.3](../docs/technical-report/02-ARCHITECTURE.md:834) | `config/safety_params.json` |
| `src/governed_financial_advisor/governance/policy/trade_governance.rego` | [TR-05 §5](../docs/technical-report/05-AI-GOVERNANCE-POLICY-ENGINE.md:220), [TR-05 §5](../docs/technical-report/05-AI-GOVERNANCE-POLICY-ENGINE.md:297), [TR-06 §3.2](../docs/technical-report/06-COMPLIANCE-STANDARDS.md:124), [TR-04 §1](../docs/technical-report/04-AGENT-SYSTEM.md:16) | `src/cage_finance/opa/trade_governance.rego` (Layer 2) and `config/opa/trade_policy.rego` |
| `src/governed_financial_advisor/graph/governance/trade_policy.rego` | [TR-05 §5](../docs/technical-report/05-AI-GOVERNANCE-POLICY-ENGINE.md:222) — link text and link target already disagree | `config/opa/trade_policy.rego` |
| `src/integrations/provider_04/` | [TR-03 §5](../docs/technical-report/03-TECHNOLOGY-STACK.md:169), TR-07 §…, README | **Package does not exist** — remove or re-scope |
| `src/agentsight-ui/gateway_protos/gateway.proto` | [TR-03 §1](../docs/technical-report/03-TECHNOLOGY-STACK.md:24) | `src/gateway/protos/gateway.proto` |
| `src/gateway/governance/routing_seal.py` linked to `src/governed_financial_advisor/utils/routing_seal.py` | [TR-01 §9.3](../docs/technical-report/01-SYSTEM-OVERVIEW.md:296) | Mismatched label/target — both files exist but the link is wrong |
| `config/rails/definitions.co`, `config/rails/main_logic.co` | [TR-03 §1](../docs/technical-report/03-TECHNOLOGY-STACK.md:21), [TR-05 §6](../docs/technical-report/05-AI-GOVERNANCE-POLICY-ENGINE.md:305) | These exist, but the *kernel* rails now live at `src/gateway/governance/nemo/colang/` and domain rails at `src/cage_{domain}/rails/` — the layer split needs stating |

**Also verify:** [`AGENTS.md`](../AGENTS.md) itself names `src.gateway.governance.reconciliation.worker` as canonical, but the module on disk is `reconciliation/daemon.py`. Flag as an AGENTS.md/code divergence to resolve alongside the TR updates.

---

## 3. G1 — The Tier Model Is Structurally Stale

### 3.1 What the TRs say

TR-01 §9.1, TR-02 §6.1, TR-04 §13.2, and TR-05 §2 all present the same picture: a **fixed, kernel-owned ladder** with numbers baked into `SymbolicGovernor._run_checks()`:

> Tier 0 STPA → Tier 1 Confidence → Tier 2 CBF → Tier 2b/4 OPA → Tier 3 Fiscal → Tier 5 Consensus → Tier 6 Causal → Tier 6b FRIA

TR-05 §2 additionally attributes tier implementations to kernel classes: "Tier 2 | `ControlBarrierFunction` in `cbf_engine.py`", "Tier 5 | `ConsensusEngine` in `consensus/engine.py`".

### 3.2 What the code does

[`SymbolicGovernor._run_checks()`](../src/gateway/governance/symbolic_governor.py:1217) executes, in order:

1. **FTRA boundary gate** — `_ftra_boundary_check()`, kernel-owned, **mandatory, no disable flag** (`cage.ftra_boundary_gate` span)
2. **STPA** — `self.stpa_validator.validate()` (kernel)
3. **`_run_domain_tiers(phase=1)`** — *all registered plugin tiers with `phase == 1`*, sorted by `(phase, order, tier_name)`
4. Confidence pre-check + POAM-TIER2-001 structural-corroboration heuristic (kernel)
5. OPA evaluation (kernel, `self.opa_client`)
6. **`_run_domain_tiers(phase=2)`** — mutating plugin tiers, with **LIFO `_rollback_committed()`** on failure

Key consequences the TRs miss entirely:

| Reality | Documented? |
|---|---|
| CBF, Fiscal, Consensus, Causal are **Layer 2 plugin tiers**, not kernel tiers | ❌ No |
| Tier ordering comes from a plugin-supplied `order` property, not from source order | ❌ No |
| `_is_governed_action()` gates the whole domain-tier loop — if **no tier claims the action**, no domain tier runs at all | ❌ No |
| With `CAGE_ACTIVE_PLUGINS=""`, [`null_components.py`](../src/gateway/governance/null_components.py) supplies fail-closed `NullSafetyFilter` etc. | ❌ No |
| Phase-2 failure triggers LIFO `rollback()` across previously committed tiers | Partially — TR-02 §6.2 describes a "LangGraph Saga Engine", not the tier rollback |
| Violations are structured [`Violation`](../src/gateway/governance/contracts.py:191) dataclasses (`tier`, `code`, `message`, `recoverable`, `needs_human_review`), not strings | ❌ No |
| Refusals emit [`RefusalReceipt`](../src/gateway/governance/contracts.py:58) schema v3 with a 5-part proof chain and `tier_failures` tuple | ❌ No |
| A `bounding` tier (order 2) exists in finance and has **no TR coverage at all** | ❌ No |

### 3.3 Tier-numbering collisions across documents

The series contradicts itself on tier numbers, and none of the schemes match `proof/model.py`:

| Component | TR-01 §9.1 | TR-02 §6.1 | TR-05 §2 | `proof/model.py` |
|---|---|---|---|---|
| FTRA | "pre-pipeline" (0.5) | "pre-pipeline" | not in tier table | index 0, "Tier 0.5" |
| STPA | 0 | 0 | 0 | "Tier 1" |
| Confidence | 1 | 1 | 1 | "Tier 2" |
| CBF | 2a (Phase 2) | 2a (Phase 2) | 2 | "Tier 3a" |
| OPA | 2b (Phase 1) | 2b (Phase 1) | 4 | "Tier 3b" |
| Fiscal | 3 (Phase 2) | 3 (Phase 2) | 3 | "Tier 4" |
| Consensus | 5 | 5 | 5 | 5 |
| Causal | 6 | 6 | 6 | 6 |
| FRIA | 6b | 6b | 6b | "Tier 7" |

**Recommendation:** adopt a single canonical scheme, and make `proof/model.py` `TIERS` the normative source (it is already pinned by a test). Replace the "8-tier pipeline" phrase — which appears ~15 times and means different things in different documents — with an explicit "kernel gates + N registered domain tiers" formulation.

### 3.4 The "Tier 7 is intentionally skipped" note is now wrong

[TR-05 §2](../docs/technical-report/05-AI-GOVERNANCE-POLICY-ENGINE.md:85) states "Tier 7 is intentionally skipped — there is no standalone Tier 7." `proof/model.py` labels `fria` as **Tier 7**. This note must be reconciled or removed.

---

## 4. G4 — The Layer Architecture Is Asserted, Never Specified

[`AGENTS.md`](../AGENTS.md) defines a four-layer model (Kernel / Domain Plugins / Integrations & Rails / Reference App) with an enforced import boundary (Gate G3, [`scripts/check_import_boundaries.py`](../scripts/check_import_boundaries.py)). **No technical report document contains this table.** TR-01 §1.2 gestures at it in prose ("Kernel owns mechanism, Plugins own nomenclature, Configuration owns jurisdiction") but never names the layers, the enforcement gate, or the contracts.

Undocumented plugin-architecture surface that should exist in TR-02 (structure) and TR-05 (governance semantics):

| Mechanism | Source | Why it matters |
|---|---|---|
| [`CagePlugin`](../src/gateway/governance/contracts.py:284) protocol, `CAGE_PLUGIN_API_VERSION = "1.0"`, `validate_plugin()` fail-closed major-version check | `contracts.py` | The extension contract adopters must implement |
| [`GovernanceTierPlugin`](../src/gateway/governance/contracts.py:218) — `tier_name` / `phase` / `order` / `claims_action` / `evaluate` / `commit` / `rollback` | `contracts.py` | The actual tier model |
| [`InvariantModel`](../src/gateway/governance/contracts.py:342) — declarative affine barrier (`invariant_id`, `state_key`, `threshold_key`, `gamma`); **non-affine barriers are a kernel RFC, not a plugin extension** | `contracts.py` | The precise, load-bearing limit of domain extensibility. Completely absent from TR-05 §4, which still presents CBF as finance-specific cash logic |
| [`DomainToolProvider`](../src/gateway/governance/contracts.py:401) | `contracts.py` | How domain MCP tools reach the tool server |
| [`discover_plugins()`](../src/gateway/governance/plugin_loader.py:67) + `CAGE_ACTIVE_PLUGINS` tri-state semantics (unset = all, `""` = none, CSV = allowlist) | `plugin_loader.py` | TR-01 §4 mentions `CAGE_ACTIVE_PLUGINS=""` once, with no mechanism description |
| `install_domain_components(safety_filter_impl, consensus_engine_impl, resource_guard)` | [`singletons.py`](../src/gateway/governance/singletons.py) | How plugins inject implementations into kernel singletons |
| `register_overlay_dir()` for per-plugin `<REGION>_OVERLAY.json` | [`constants.py`](../src/gateway/governance/constants.py) | The domain × jurisdiction composition mechanism TR-06 §1 claims but does not explain |
| `register_rail_provider()` / [`nemo/action_registry.py`](../src/gateway/governance/nemo/action_registry.py) | kernel | How healthcare contributes `CheckContraindicationAction` |
| `register_background_task()` | [`background_tasks.py`](../src/gateway/governance/background_tasks.py) | Plugin-supplied background workers |
| [`null_components.py`](../src/gateway/governance/null_components.py) — `NullSafetyFilter` and peers, fail-closed bare-kernel mode | kernel | The proof that the kernel runs with zero domains |

### 4.1 Entry-point registration is inconsistent with the docs and with tests

[`pyproject.toml`](../pyproject.toml:284) declares **only** the finance entry point:

```toml
[project.entry-points."cage.plugins"]
finance = "cage_finance.plugin:FinanceCagePlugin"
```

But [`tests/test_code_audit_remediation.py`](../tests/test_code_audit_remediation.py:249) asserts *both* `finance` and `healthcare` entry points are present. And TR-01 §1 / README claim finance and healthcare are "**equal-standing** case studies, neither privileged nor required."

**Finding:** the equal-standing claim is not currently true at the packaging layer. Either the entry point is missing from `pyproject.toml` (a code bug the docs update should not paper over) or the docs overstate parity. This needs resolution before TR-01 is edited.

### 4.2 TR-01 cites a test file that does not exist

[TR-01 §1.2](../docs/technical-report/01-SYSTEM-OVERVIEW.md:41) names `tests/test_domain_independence.py` as "the standing proof". No such file exists. The nearest actual coverage is [`tests/test_healthcare_plugin.py`](../tests/test_healthcare_plugin.py) (which *does* contain the no-Lua / no-KMS / line-count assertions TR-01 describes), plus [`tests/test_tier_registry_contract.py`](../tests/test_tier_registry_contract.py), [`tests/test_tier_registry_formal_parity.py`](../tests/test_tier_registry_formal_parity.py), [`tests/test_import_boundaries.py`](../tests/test_import_boundaries.py), and [`tests/test_capability_dispatch_coverage.py`](../tests/test_capability_dispatch_coverage.py). Retarget the citation.

---

## 5. G3 — Kernel Subsystems Present in Code, Absent from TR-01…TR-06

A targeted search of TR-01…TR-06 for each of these module names returns **zero hits**. Each represents a real governance capability the report series does not describe.

| Kernel module | Capability | Suggested home |
|---|---|---|
| [`decisions.py`](../src/gateway/governance/decisions.py:81) — `GovernanceDecision` enum + `DeferResponse` / `NarrowResponse` / `PauseResponse` Pydantic models | The canonical decision vocabulary and its HTTP serialization | TR-05 (new §on decision primitives); TR-02 §5.2 (endpoint contracts) |
| [`consequence_gateway.py`](../src/gateway/governance/consequence_gateway.py:82) — `ConsequenceGateway`, "vendor-agnostic post-FRIA consequence boundary" | An entire enforcement boundary downstream of FRIA | TR-02 §5 and TR-05 |
| [`consequence_token.py`](../src/gateway/governance/consequence_token.py:125) — short-TTL single-use JWS carrying FlowSignal authority decisions | A second cryptographic authority artifact alongside the routing seal | TR-05 §9; TR-07 |
| `consequence_authority_store.py` | Authority persistence for the above | TR-05 §9 |
| [`token_quota_proxy.py`](../src/gateway/governance/token_quota_proxy.py:194) — `TokenQuotaProxy` inline circuit breaker, per-session token quotas | Has **two active Lula manifests** (`tqp007`, `iso001-token-quota`) yet no TR text | TR-05 + TR-06 §7 |
| [`governance_envelope.py`](../src/gateway/governance/governance_envelope.py:232) — `GovernanceEnvelope` + `GovernanceEnvelopeBuilder` | The signed envelope format vendors map to/from | TR-02 §5; TR-06 §14b |
| [`pause_primitive.py`](../src/gateway/governance/pause_primitive.py) | PAUSE runtime implementation (TRs name PAUSE as a primitive but never describe its machinery) | TR-05 |
| [`null_components.py`](../src/gateway/governance/null_components.py:47) — `NullSafetyFilter` et al. | Bare-kernel fail-closed defaults | TR-01 §1.2; TR-02 |
| [`evidence/cold_store.py`](../src/gateway/governance/evidence/cold_store.py) + `null_cold_store.py` + `factory.py` | Pluggable durable evidence sinks (GCS / S3 via `src/integrations/storage_*`) | TR-06 §14b |
| [`evidence/residency.py`](../src/gateway/governance/evidence/residency.py) + [`config/compliance/residency.json`](../config/compliance/residency.json) | Data-residency enforcement — directly relevant to TR-06's sovereignty claims | TR-06 §1, §15 |
| [`jcs_canonicalizer.py`](../src/gateway/governance/jcs_canonicalizer.py) | RFC 8785 JCS — TR-02 §11.6 mentions `jcs_canonicalize_plan()` but never the module or its role in `RefusalReceipt` hashing | TR-02 §11.6 |
| [`attestation_aggregator.py`](../src/gateway/governance/attestation_aggregator.py:46) + `attestation_provider.py` | Multi-provider attestation aggregation (the seam Providers 02/05 plug into) | TR-02 §1; TR-03 §5 |
| [`iso_control.py`](../src/gateway/governance/iso_control.py) | TR-05 §11 covers `stamp_iso_control()`, but AGENTS.md flags the **`ISO_CONTROL_MAP` relocation from `compliance_bridge/types.py` to the kernel** as a canonical-namespace change — undocumented as a change | TR-05 §11; TR-06 |
| [`env_posture.py`](../src/gateway/governance/env_posture.py) | Environment posture resolution | TR-06 §1 |
| [`jwks.py`](../src/gateway/governance/jwks.py) | JWKS publication for asymmetric seal verification — TR-01 §8.2 claims "v3 routing seal in asymmetric JWT format" but no TR explains key distribution | TR-07 (and cross-ref from TR-05 §9) |
| [`authorization_claim_detector.py`](../src/gateway/governance/authorization_claim_detector.py), [`confidence_claim_detector.py`](../src/gateway/governance/confidence_claim_detector.py) | Claim-detection defences | TR-05 §12 (AI 600-1 module table) |
| [`execution_actuator.py`](../src/gateway/governance/execution_actuator.py) | The kernel actuator that verifies seals before firing | TR-02 §5; TR-04 §13.1 |
| [`singletons.py`](../src/gateway/governance/singletons.py) | Domain-component installation | TR-02 §6 |
| [`ftra/bounding_contract.py`](../src/gateway/governance/ftra/bounding_contract.py) + [`src/cage_finance/safety/bounding/`](../src/cage_finance/safety/bounding/) + [`config/opa/bounding_contracts.rego`](../config/opa/bounding_contracts.rego) | The **entire bounding-contract subsystem and its order-2 governance tier** | TR-05 (new section) |

### 5.1 Layer 3 integrations that are undocumented

| Package | Role | TR coverage |
|---|---|---|
| [`src/integrations/actuator_01/`](../src/integrations/actuator_01/) — `client.py`, `envelope_builder.py`, `signatures.py` | Actuator-side vendor adapter | ❌ None (TR-03 §5 lists providers only) |
| [`src/integrations/storage_gcs/cold_store.py`](../src/integrations/storage_gcs/cold_store.py) | GCS cold-store backend | ❌ None |
| [`src/integrations/storage_s3/cold_store.py`](../src/integrations/storage_s3/cold_store.py) | S3/MinIO cold-store backend | ❌ None (TR-03 §8 mentions `STORAGE_BACKEND` but not these packages) |

### 5.2 Compliance Bridge modules undocumented in TR-06

TR-06 covers `audit_workflow.py`, `oscal_parser.py`, `oscal_exporter.py`, `sla_monitor.py`, `eval_dataset.py`, `types.py`, `context_accumulator.py`, `aarm_mapper.py`, `aarm_report_generator.py`. It does **not** cover: [`clickhouse_sink.py`](../src/compliance_bridge/clickhouse_sink.py), [`cmek_guard.py`](../src/compliance_bridge/cmek_guard.py), [`kms_batch_signer.py`](../src/compliance_bridge/kms_batch_signer.py) (TR-06 §6 describes KMS batch signing in prose without naming the module), [`governance_webhook.py`](../src/compliance_bridge/governance_webhook.py), [`lula_scheduler.py`](../src/compliance_bridge/lula_scheduler.py), [`auth.py`](../src/compliance_bridge/auth.py), [`metrics.py`](../src/compliance_bridge/metrics.py), [`storage.py`](../src/compliance_bridge/storage.py).

---

## 6. FTRA (Tier 0.5) — Documented, but Only Half of It

FTRA is the best-covered v3 addition: TR-04 §5a and TR-05 §12-ish both describe `classifier.py`, `graph_analyzer.py`, `node_factory.py`, `models.py`, the `CLEAR`/`HITL_REQUIRED`/`BLOCKED` verdicts, and the removed `ftra_reachability.py` scaffold. Remaining gaps:

| Gap | Detail |
|---|---|
| **Two FTRA enforcement points, one documented** | TRs describe only the in-graph `ftra_node` (between `evaluator` and `safety_check`). The code *also* runs a mandatory kernel-side [`_ftra_boundary_check()`](../src/gateway/governance/symbolic_governor.py:1088) at the very top of `_run_checks()`, with explicit **bypass detection** (`detect_bypass=True`, `bypassed_ftra_node` flag) to catch direct HTTP hits on `/governance/validate-action` or ext_authz. This is an R-03 mitigation and a load-bearing security control. |
| **`FtraBoundaryResult` undocumented** | [`models.py`](../src/gateway/governance/ftra/models.py:263) — `requires_hitl`, `irreversibility_score`, `classification`, `terminal_match`, `bypassed_ftra_node`. |
| **Taxonomy incomplete in docs** | TR-04 §5a lists three classes (`IRREVERSIBLE_TERMINAL`, `REVERSIBLE`, `READ_ONLY`). The code defines **four**, including [`EXTERNALLY_REVERSIBLE`](../src/gateway/governance/ftra/models.py:48) with score 0.8 and `requires_hitl=True`. AGENTS.md names the canonical set as `REVERSIBLE` / `IRREVERSIBLE` / `EXTERNALLY_REVERSIBLE` per OWASP AISVS C9 — reconcile all three vocabularies. |
| **Irreversibility scoring absent** | The 1.0 / 0.8 / 0.5 / 0.0 score map is nowhere in the TRs. |
| **`ParseResult` / `ParseFailureClass` absent** | Defensive plan-parsing failure taxonomy (BUG-FTRA-SCHEMA-001, BUG-FTRA-JSON-001) — governs how malformed LLM output is handled at the gate. |
| **Registry-integrity claim unverified in docs** | AGENTS.md states registries "must be signed using KMS/JCS canonicalization." No TR describes signing of [`config/ftra/terminal_registry.json`](../config/ftra/terminal_registry.json). Confirm whether this is implemented before documenting it. |
| **Bounding contracts** | [`ftra/bounding_contract.py`](../src/gateway/governance/ftra/bounding_contract.py) (`BoundingContractConfig`, `BoundingContractEnforcer`) sits inside the FTRA package and backs the finance `bounding` tier. Zero TR coverage. |
| **Lula manifest exists** | [`compliance/lula/lula-validation-ftra.yaml`](../compliance/lula/lula-validation-ftra.yaml) is ✅ Active for CTRL_FTRA_001 — TR-06 §7's 15-row excerpt omits it. |

---

## 7. Per-Document Findings

### 7.1 `README.md` (series index)

| Claim | Reality | Action |
|---|---|---|
| Status: "3,925 collected / 3,446 passed, 0 failed, 96 skipped" | TR-01 §5 says "2,841 passed, 0 failed, 67 skipped"; TR-09 says the same; AGENTS.md records "2553 passed, 51 skipped, 1 failed" (2026-08-10) | Pick one measurement with provenance; propagate |
| "Date 2026-08-22" / "v3.0.0 stable tagged 2026-08-28" | Status line also says "(v3.0.0 stable, 2026-09-06)" | Internally inconsistent dating |
| "Vendor Integrations: 6 (`provider_01` through `provider_06`)" | 5 providers exist (no `provider_04`), plus `actuator_01`, `storage_gcs`, `storage_s3` | Correct the count and taxonomy |
| "Governance Tiers: 7 + tier 6b" | 2 kernel gates + N plugin tiers (5 finance / 2 healthcare); formal model lists 9 | Restate per §3 |
| "Decision Primitives: 6" | [`GovernanceDecision`](../src/gateway/governance/decisions.py:81) docstring says "canonical **five**-state vocabulary" but defines **six** members (`ALLOW`, `DENY`, `PAUSE`, `NARROW`, `REQUIRE_APPROVAL`, `DEFER`) | 6 is right; the code docstring is the error — note it |
| "AgentState Fields: 25" | 33 fields in [`state.py`](../src/governed_financial_advisor/graph/state.py) (adds `ftra_status`, `ftra_result`, `ftra_defer_id`, `narrow_status`, `narrowed_params`, `pause_resume_token`, `pause_reason`, plus `confidence`) | Recount |
| "Agent Nodes: 10 (LangGraph StateGraph)" | 12 nodes registered in [`graph.py`](../src/governed_financial_advisor/graph/graph.py:113) — adds `ftra_node` and `defer_node` | Recount |
| "Lula Validation Manifests: 30 (6 Active, 24 Stub)" | 31 manifests on disk + `assessment-results.yaml`; [`compliance/lula/README.md`](../compliance/lula/README.md:76) tallies 7 Active (6 ALL + 1 US_FED) / 24 Stub | TR-06 §7 says "31 (plus 1 draft)" — README says 30. Reconcile |
| Formalism table: CBF, causal, resource_guard paths | ✅ Correct (already uses `safety/cbf_engine.py`, `causal/gatekeeper.py`, `safety/resource_guard.py`) | Keep — use as the model for fixing TR-02/TR-05 |
| "Domain Coupling: None — kernel is domain-agnostic" | Broadly true, but [`ontology.py`](../src/gateway/governance/ontology.py) (`TradingKnowledgeGraph`, FIN-1/FIN-2) and `generated_stpa_validator.py` still live in the kernel with finance semantics | Qualify the claim, or note it as a known residual coupling |

### 7.2 `01-SYSTEM-OVERVIEW.md`

**Accurate and worth preserving:** §1 domain-agnostic framing, §1.2 three-way ownership split, §2.1 finance↔healthcare enforcement-point mapping table (the single best artifact in the series), §8.1–8.4 formal guarantees, §8.2 NoDirectBind.

| Issue | Detail |
|---|---|
| Status line vs README | "2,841 passed / 67 skipped / 75.40%" contradicts README's "3,446 passed / 96 skipped" |
| §1.2 test citation | `tests/test_domain_independence.py` does not exist (see §4.2) |
| §2.1 table row "Governed action: `execute_trade`" | Actual registered MCP tool is `execute_trade_action` ([`tool_provider.py`](../src/cage_finance/tools/tool_provider.py:193)); `execute_trade` is the governance action key. Distinguish them |
| §2.1 "Critic panel: Risk Manager, Compliance Officer" | Now configured via [`src/cage_finance/config/critics.yaml`](../src/cage_finance/config/critics.yaml) / `src/cage_healthcare/config/critics.yaml` — mention the config seam |
| §4 cap. 1 sub-agent list | Lists "market data analyst, risk analyst, execution analyst, explainer, evaluator, supervisor" — omits `governed_trader`, `financial_advisor`, `data_analyst` naming inconsistency vs TR-04 §2 |
| §4 cap. 2 "8-tier … 7 in-pipeline tiers 0–6" | Stale per §3 |
| §5 "v3.0.0 stable release was tagged on 2026-08-28" | Not verifiable from repo state; also conflicts with README's 2026-09-06 status stamp |
| §5.2 findings table | Omits POAM-023 / POAM-2026-038 (reported closed in TR-05/TR-06) and the FTRA/TQP controls |
| §6.1 external dependencies | Omits ClickHouse (used by [`clickhouse_sink.py`](../src/compliance_bridge/clickhouse_sink.py)) as a distinct dependency; only mentions it parenthetically as a Langfuse backend |
| §8.1 "cash balance never falls below `min_cash_balance`" | Now a *domain instantiation* of the generic `InvariantModel` affine barrier. Restate generically, then give cash as the finance example |
| §8.3 FRIA table | Says thresholds are enforced in `symbolic_governor.py`; TR-05 §2 says `normative_provider.py`; both are partly true (constants in the former, `enforce_fria_boundary()` in the latter) — state precisely |
| §8.4 "deterministic sorted-key JSON serialization" | Superseded — [`compute_hash()`](../src/gateway/governance/provenance_chain.py) now uses RFC 8785 JCS. TR-02 §11.6 already says this; §8.4 contradicts it |
| §9.1 | Contains a **duplicated/orphaned heading**: a `| Tier | Name | Mathematical Invariant |` table header with no rows, immediately followed by a second `### 9.1 Two-Phase Eight-Tier Pipeline Summary`. Structural defect |
| §9.3 Routing Seal | Describes the **3-tuple v1 format** `<expire_ts_hex>.<action_slug>.<hmac_hex>`, while §4 and TR-02 §11.7 describe the **4-tuple v2** with `record_hash_hex`, and TR-05 describes **v3 JWT**. Three formats in one series |
| §9.3 link | Label `src/gateway/governance/routing_seal.py`, target `src/governed_financial_advisor/utils/routing_seal.py` |

### 7.3 `02-ARCHITECTURE.md`

| Issue | Detail |
|---|---|
| §1 "five major subsystems" then a **six-row table** | Off-by-one in the prose |
| §2 Mermaid diagram | Shows `SymbolicGovernor` → CBF / Consensus as direct kernel children. Post-refactor these are plugin-registered tiers. Diagram needs redrawing around the tier registry |
| §2 diagram | Shows `vLLM Fast → Qwen/Qwen2.5-1.5B-Instruct`, but §5.4 and TR-03 §3 say `Meta-Llama-3.1-8B-Instruct` for the fast node. Contradiction within the same document |
| §2 diagram | "FastMCP Tool Server — 7 tools" vs §5.3 prose "exposes six tools" vs the actual split: 3 kernel tools ([`mcp_tool_server.py`](../src/gateway/server/mcp_tool_server.py): `simulate_governance_check`, `trigger_safety_intervention`, `verify_content_safety`) + 3 finance plugin tools (`execute_trade_action`, `check_market_status`, `get_market_sentiment`) + healthcare `dose_order`. The tool set is now **plugin-dependent**, which is the real story |
| §2 "Langfuse SaaS / Dual-project OTLP" | TR-01 §6.1 and TR-03 §8 say **self-hosted v3**. §8.2 of this same document also says "Langfuse SaaS". Contradiction |
| §2 "Inference Proxy 5-tier pipeline" under a "Hybrid Gateway" that also has an "8-tier pipeline" | Two unrelated things both called "tiers" — needs disambiguating terminology |
| §3.1/§3.2 "registers ten nodes" | 12 nodes; `ftra_node` and `defer_node` missing from the inventory table and both Mermaid diagrams |
| §3.3 routing functions | Omits `route_after_ftra()` and the defer routing edge |
| §3.4 AgentState "25 fields" | 33 (see §7.1) |
| §5.1 mount topology | Correct, but omits that `/tools/execute` enforcement lives in [`governance_middleware.py`](../src/gateway/server/governance_middleware.py) *and* that [`agent_gateway_adapter.py`](../src/gateway/server/agent_gateway_adapter.py) exposes a second (ext_authz) entry point subject to the same FTRA boundary gate |
| §5.2 | "enforces the X-CAGE-Routing-Seal **HMAC** header" — production is KMS-signed JWT (v3); HMAC is the dev fallback |
| §6 heading "Symbolic Governor 8-Tier Pipeline" + §6.1 tier table | Stale per §3; the table attributes plugin tiers to kernel modules |
| §6.2 "FiscalLimitGuard (`src/gateway/governance/fiscal_limit_guard.py`)" | Dead path; class now in `safety/resource_guard.py`, wrapped by `src/cage_finance/tiers/fiscal_tier.py` |
| §6.3 regional profiles | Does not mention per-plugin `<REGION>_OVERLAY.json` or `register_overlay_dir()` — the domain × jurisdiction composition mechanism |
| §9.2 dual-project Langfuse | Accurate; but omits the compliance-pipeline port split (3000 app / 3001 compliance) that AGENTS.md treats as architectural |
| §10 §10.1 "no human in the low-latency path" | Directly contradicts the §10 v3.0.0 CR-2 note *four lines above*, which says refinement "strictly requires human approval". Fix the ASCII diagram and the summary sentence |
| §11.1 / §11.2 source paths | `cbf.py`, `causal_gatekeeper.py` — dead |
| §11.1 "`verify_action()` is read-only; the actual debit is performed by `FiscalLimitGuard`" | Contradicts §6.1/§11.x elsewhere: the debit is performed by `atomic_verify_and_commit()` in the Lua hop. Stale v2 text |
| §11.1 "Redis atomic implementation uses WATCH/MULTI/EXEC with `_MAX_RETRIES = 5`" | CBF now uses a Lua script (`LUA_ATOMIC_CBF`) plus replica `WAIT` and fence epoch; WATCH/MULTI/EXEC is the ResourceGuard pattern. The two are conflated |
| §12 STPA UCA-5 | "`order_size > 0.1 × daily_volume`" here vs "drawdown > 4.5%" in TR-01 §Formalism and TR-05 §3. UCA-5 has two different definitions across the series |
| §12.3 | `src/gateway/governance/safety_params.json` → `config/safety_params.json` |

### 7.4 `03-TECHNOLOGY-STACK.md`

| Issue | Detail |
|---|---|
| §1 proto path | `src/agentsight-ui/gateway_protos/gateway.proto` → `src/gateway/protos/gateway.proto`; also omits the vendored Envoy protos under [`src/gateway/protos/envoy/`](../src/gateway/protos/envoy/) that back the ext_authz boundary |
| §1 Colang locations | Lists only `config/rails/*`; omits kernel rails [`src/gateway/governance/nemo/colang/cbrn_rails.co`](../src/gateway/governance/nemo/colang/cbrn_rails.co) and plugin rails `src/cage_{domain}/rails/` |
| §1 Rego locations | Lists `trade.governance`, `system.authz`, `deployment/system_authz.rego`; omits `src/cage_finance/opa/trade_governance.rego`, `src/cage_healthcare/opa/dosing_governance.rego`, `config/opa/bounding_contracts.rego`, `config/opa/agent_catalog.rego`, `config/opa/generated_stpa_policy.rego` |
| §2 "FastMCP — 6 registered tools" | Plugin-dependent (see §7.3) |
| §4 Presidio "**10 entity types**" | TR-01 §4, TR-03 §2, TR-05 §6, and README all say **15**. Internal contradiction within TR-03 itself |
| §5 Provider table | Lists `provider_04` (does not exist); omits `actuator_01`, `storage_gcs`, `storage_s3` |
| §5 | Does not mention the `NormativeProvider` / `AttestationProvider` / `EnvelopeMapper` protocol split, the UDS sidecar pattern, or [`tests/test_normative_provider_conformance.py`](../tests/) — all mandated by AGENTS.md's adapter standard |
| Missing: plugin/packaging | No entry for the `cage.plugins` entry-point group, `uv_build` `module-root = "src"`, or the `[project.optional-dependencies] finance` extra |
| Missing libraries | `networkx` (FTRA graph analysis), `dowhy` (Tier 6 — mentioned in prose only), `pyjwt`/`jwcrypto` for the v3 JWT seal and ConsequenceToken JWS, `clickhouse` client |
| §7 "`infra/modules/` (16 shared modules)" | Verify against [`infra/modules/`](../infra/modules/) at edit time |
| §9 sampling / §10 tooling | OSCAL version stated as v1.0.4 here, but TR-02 §2 ingress table and TR-06 §1 say v1.1.2. Reconcile artifact-schema vs assessment-semantics versions consistently |

### 7.5 `04-AGENT-SYSTEM.md`

| Issue | Detail |
|---|---|
| §2 agent inventory | 9 agents listed; graph registers 12 nodes. `ftra_node` and `defer_node` are governance nodes, not agents — but the document's own §4 says "Ten named nodes are registered" |
| §3 "TypedDict has **25 fields**" | 33 |
| §3 | Omits `ftra_status`, `ftra_result`, `ftra_defer_id`, `narrow_status`, `narrowed_params`, `pause_resume_token`, `pause_reason`, `confidence` — i.e. every field added by the NARROW/PAUSE/FTRA work that §5a of the same document describes |
| §4 Mermaid | Missing `ftra_node` between `evaluator` and `safety_check`, and `defer_node` entirely |
| §5a DEFER "four states" | Superseded — [`GovernanceDecision`](../src/gateway/governance/decisions.py:81) is a six-member enum. §5a still frames DEFER as an extension of a tri-state model |
| §5a | No mention of `narrow_status` / `pause_resume_token` state plumbing despite NARROW/PAUSE being first-class |
| §5a FTRA | See §6 — missing boundary check, `EXTERNALLY_REVERSIBLE`, scoring, `ParseResult` |
| §8 EvaluatorAgent "five async MCP tools" | Two of the five (`check_market_status`, `get_market_sentiment`) are **finance-plugin** tools; `evaluate_policy` is an internal helper (`_evaluate_policy_internal`), not a registered `@mcp.tool()`. Verify the list against [`mcp_tool_server.py`](../src/gateway/server/mcp_tool_server.py) and [`tool_provider.py`](../src/cage_finance/tools/tool_provider.py) |
| §10 red team paths | Cites both `tests/red_team/` and `tests/red_teaming/`; AGENTS.md uses `tests/red_team/`. Verify which exists |
| §11 PolicyTranspiler | Lives at `src/governed_financial_advisor/governance/transpiler.py` (Layer 4). Given it generates *kernel-adjacent* Rego and NeMo stubs, note the layer placement explicitly — it is a plausible boundary concern |
| §13 | "All agent tool calls are mediated by `symbolic_governor.py`" — true, but the section never mentions that the FTRA boundary gate is the *first* thing `_run_checks()` does, nor `execution_actuator.py` |
| §1 header | "OPA policy evaluation (`src/governed_financial_advisor/governance/policy/trade_governance.rego`)" — dead path |

### 7.6 `05-AI-GOVERNANCE-POLICY-ENGINE.md`

This is the document most damaged by the refactor — its central §2 tier table is the primary artifact of G1.

| Issue | Detail |
|---|---|
| §2 tier table | Attributes CBF / Fiscal / Consensus / Causal to kernel modules as fixed numbered tiers. All four are now Layer-2 plugin tiers. **Rewrite required, not patchable** |
| §2 | Omits the `bounding` tier (finance, order 2) and both healthcare tiers |
| §2 note | "Tier 7 is intentionally skipped" contradicts `proof/model.py` |
| §2 | No mention of `phase`/`order`, `claims_action()`, `_is_governed_action()` short-circuit, or LIFO `_rollback_committed()` |
| §2 "Tier 2 CBF … Active Regions: `US_FED`, `APAC_MAS`" | Claims CBF is *suppressed in EU_ECB*. Verify — this is a strong claim with no visible code support in `cbf_tier.py`/`cbf_engine.py`; if untrue it is a material compliance misstatement |
| §3 "enforces **9** UCAs (UCA-1 … UCA-9)" then a **6-row table** (SC-1, FIN-1, FIN-2, UCA-5, UCA-6, UCA-7) | Count/table mismatch |
| §3 FIN-1/FIN-2 definitions | "FIN-1 Portfolio Fraction Exceeded (`qty/portfolio ≤ 0.1`)" and "FIN-2 Latency SLA Breach" here; TR-01 Formalism and TR-02 §12.1 define FIN-1 as `trade_value > position_limit` and FIN-2 as `portfolio_concentration > 0.25`. **Direct contradiction across documents** |
| §3 | Does not address that STPA UCA definitions for a *finance* domain still live in the kernel (`ontology.py`, `generated_stpa_validator.py`) while [`config/stpa/domains/finance/trade_hazards.yaml`](../config/stpa/domains/finance/trade_hazards.yaml) exists as the domain-split config. The STPA layer split is half-done and undocumented |
| §4 | `cbf.py` dead path; presents CBF as cash-specific rather than as `InvariantModel`-parameterized |
| §4 code sample | Shows a WATCH/MULTI/EXEC Python snippet as "the atomic CBF enforcement pattern". Production is a Lua script. Replace or clearly label as historical |
| §4 | Missing: fence epoch (`safety:fence_epoch`), replica `WAIT`, sequence replay defence (`reconciliation:sequence:*`, R-04), `_CBF_STRICT_MODE` fail-closed behaviour, local-debit accounting — all in [`cbf_engine.py`](../src/gateway/governance/safety/cbf_engine.py) and all named in the v3.0.0 header note of this very document |
| §5 OPA | Both rego path references are dead/mismatched; the role matrix (junior/senior) should be identified as **finance-plugin policy**, not kernel policy |
| §6 NeMo | Does not mention `action_registry.py` / `register_rail_provider()` — the mechanism by which plugins contribute rails |
| §7 Consensus | Critic personas are now config-driven (`src/cage_{domain}/config/critics.yaml`); document the seam |
| §7.3 priority ladder row 1 | "ALL critics `ERROR` → `APPROVE` (fail-open)" — **directly contradicts** TR-02 §11.4, TR-04 §13.3, and TR-01 §9.2, which all state unanimous ERROR → ESCALATE (fail-closed, DoS prevention). This is a safety-semantics contradiction and should be resolved against [`consensus/engine.py`](../src/gateway/governance/consensus/engine.py) before publication |
| §8.2 | `fiscal_limit_guard.py` dead path |
| §9 | Reconciliation worker path dead (`compliance_bridge/reconciliation_worker.py` → `gateway/governance/reconciliation/daemon.py`). Note also that [`kms_batch_signer.py`](../src/compliance_bridge/kms_batch_signer.py:44) contains a stale in-code reference to `config/compliance/reconciliation_worker.py`, as does [`normative_provider.py`](../src/gateway/governance/normative_provider.py:45) — code comments to fix alongside |
| §9 | No coverage of `ConsequenceToken` JWS or `jwks.py` despite describing the signing architecture |
| §10 "22 tracked thresholds" | Verify against [`config/governance_thresholds.json`](../config/governance_thresholds.json); also omits [`config/thresholds/token_quota.yaml`](../config/thresholds/token_quota.yaml) |
| §11 ISO control stamping | Should note the `ISO_CONTROL_MAP` move into the kernel (AGENTS.md canonical-namespace change) |
| §12 AI 600-1 module table | Good; extend with `authorization_claim_detector.py` and `confidence_claim_detector.py` |
| Missing sections | Decision primitives (`decisions.py`), NARROW parameter clamping (`_compute_narrowed_params()`), PAUSE (`pause_primitive.py`), `RefusalReceipt`/`PauseReceipt` proof chains, `TokenQuotaProxy`, `ConsequenceGateway`, bounding contracts, `GovernanceEnvelope` |

### 7.7 `06-COMPLIANCE-STANDARDS.md`

Structurally the healthiest of the six — most content is framework mapping that the refactor did not invalidate.

| Issue | Detail |
|---|---|
| §5.1 Clause 8 row | "8-tier governance pipeline (FTRA + Tiers 0–6 + 6b): STPA → confidence → CBF → **SLM (deprecated)** → OPA → consensus → causal → FRIA" — carries a deprecated tier in the canonical clause mapping. Rewrite per §3 |
| §3.2 AC row | Dead rego path |
| §7 "31-manifest inventory (plus 1 draft)" | [`compliance/lula/README.md`](../compliance/lula/README.md) tallies differently and the series README says 30. Reconcile the three |
| §7 15-row excerpt | Omits the ✅ **Active** manifests `lula-validation-ftra.yaml`, `lula-validation-tqp007.yaml`, `lula-validation-iso001-token-quota.yaml`, `lula-validation-flowsignal.yaml`. An excerpt that omits four of the seven active gates is misleading |
| §7 three-region table | Claims per-region manifest **directories** (`compliance/lula/us_fed/`, `eu_ecb/`, `apac_mas/`). No such directories exist — manifests are flat with a `Region Scope` column in the README. **Factually wrong** |
| §7 | No mention of [`compliance/lula/.stub-baseline`](../compliance/lula/.stub-baseline) or [`scripts/check_lula_stub_count.py`](../scripts/check_lula_stub_count.py), which enforce the stub-count gate in CI |
| §6 OSCAL inventory | Lists 6 artifacts; [`compliance/lula/README.md`](../compliance/lula/README.md:93) references per-region SSPs (`system-security-plan-eu-ecb.yaml`, `-apac-mas.yaml`) absent from this table |
| §14b AARM table | Paths are **correct and current** (`safety/cbf_engine.py`, `causal/gatekeeper.py`, `safety/resource_guard.py`) — use as the reference style |
| §14b V1 row | Points at `src/governed_financial_advisor/graph/nodes/` for the context accumulator, while §5.2 points at `src/compliance_bridge/context_accumulator.py`. Inconsistent |
| §14b evidence stream | Covers `evidence/stream.py`; omits `evidence/cold_store.py`, `evidence/residency.py`, `evidence/factory.py`, and the `storage_gcs`/`storage_s3` backends |
| Missing: residency | [`config/compliance/residency.json`](../config/compliance/residency.json) + `evidence/residency.py` implement data-residency enforcement — highly material to §1's sovereignty framing, entirely absent |
| Missing: domain overlays | §1 asserts domain × jurisdiction composition; never shows that overlays live in `src/cage_{domain}/config/compliance/<REGION>_OVERLAY.json` and are wired by `register_overlay_dir()` |
| Missing: CI compliance gates | No mention of `check_apac_mas_posture.py`, `check_eu_ecb_posture.py`, `check_domain_literals.py`, `check_telemetry_literals.py`, `check_import_boundaries.py`, `check_poam_lula_divergence.py`, `check_policy_drift.py`, `check_stpa_freshness.py` — the automated enforcement layer behind the compliance claims |
| §12 "22 governance thresholds" | Same verification need as TR-05 §10 |
| §10 SAR / §11 RAR | Operational-tracking content that sits awkwardly against the AGENTS.md documentation standard ("no internal operational tracking"; "illustrative patterns only"). Consider adding a Reference Architecture Note |

---

## 8. Cross-Document Contradiction Register

These are cases where two or more TR documents assert incompatible facts. Each must be resolved to a single answer before editing, because fixing one document in isolation will not converge.

| # | Contradiction | Documents | Resolution source |
|---|---|---|---|
| C1 | Consensus unanimous-ERROR → `APPROVE` (fail-open) vs `ESCALATE` (fail-closed) | TR-05 §7.3 vs TR-01 §9.2, TR-02 §11.4, TR-04 §13.3 | [`consensus/engine.py`](../src/gateway/governance/consensus/engine.py) |
| C2 | FIN-1 / FIN-2 definitions | TR-05 §3 vs TR-01 Formalism, TR-02 §12.1 | [`ontology.py`](../src/gateway/governance/ontology.py), [`config/stpa/`](../config/stpa/) |
| C3 | UCA-5 = drawdown 4.5% vs order_size > 10% daily volume | TR-05 §3, TR-01 vs TR-02 §12.2 | `generated_stpa_validator.py` |
| C4 | Routing seal: 3-tuple v1 / 4-tuple v2 / JWT v3 | TR-01 §9.3 vs TR-01 §4 + TR-02 §11.7 vs TR-05 §9 | [`routing_seal.py`](../src/gateway/governance/routing_seal.py) |
| C5 | Presidio entity types: 10 vs 15 | TR-03 §4 vs TR-01 §4, TR-03 §2, TR-05 §6 | [`config/rails/config.yml`](../config/rails/config.yml) |
| C6 | Fast-node model: Qwen2.5-1.5B vs Llama-3.1-8B | TR-02 §2 + §5.4 vs TR-03 §3, TR-04 §2 | deployment templates |
| C7 | Langfuse SaaS vs self-hosted v3 | TR-02 §2 + §8.2 vs TR-01 §6.1, TR-03 §8 | [`deployment/k8s/langfuse-web.yaml`](../deployment/k8s/langfuse-web.yaml) |
| C8 | Cybernetic loop "no human in the low-latency path" vs "strictly human-gated refinement" | TR-02 §10 vs TR-02 §10 CR-2 note, TR-05 overview | [`server.py`](../src/governed_financial_advisor/server.py) |
| C9 | MCP tool count: 7 vs 6 vs plugin-dependent | TR-02 §2 vs TR-02 §5.3, TR-03 §2 | `mcp_tool_server.py` + plugin `tool_provider.py` |
| C10 | Test totals: 3,446 / 2,841 / 2,553 | README + TR-02/03/04 vs TR-01 + TR-09 vs AGENTS.md | fresh `make test-coverage` run |
| C11 | Lula manifest count: 30 vs 31 vs 32-on-disk; 6 vs 7 Active | README vs TR-06 §7 vs `compliance/lula/README.md` | `compliance/lula/` + `.stub-baseline` |
| C12 | Provenance hash: sorted-key JSON vs RFC 8785 JCS | TR-01 §8.4 vs TR-02 §11.6 | [`provenance_chain.py`](../src/gateway/governance/provenance_chain.py) |
| C13 | OSCAL version: v1.0.4 vs v1.1.2 | TR-03 §10/§11, TR-06 §6 vs TR-02 §2, TR-06 §1 | `compliance/oscal/` |
| C14 | FRIA enforcement location: `symbolic_governor.py` vs `normative_provider.py` | TR-01 §8.3, TR-02 §6.1 vs TR-05 §2, TR-04 §13.4 | both — state the split precisely |
| C15 | Healthcare "equal standing" vs finance-only entry point | TR-01 §1, README vs [`pyproject.toml`](../pyproject.toml:284) | resolve in code first |

---

## 9. Recommended Remediation Sequence

Ordered so that each step de-risks the next. Steps 0–2 are prerequisites: editing prose before the underlying facts are settled will produce a second round of drift.

**Step 0 — Resolve code-side ambiguities (not documentation work).**
- Decide whether the healthcare `cage.plugins` entry point belongs in [`pyproject.toml`](../pyproject.toml:284) (C15).
- Reconcile `reconciliation/daemon.py` vs the `reconciliation.worker` name in [`AGENTS.md`](../AGENTS.md).
- Fix the `GovernanceDecision` docstring ("five-state" → six members).
- Fix stale in-code path comments in [`kms_batch_signer.py`](../src/compliance_bridge/kms_batch_signer.py:44) and [`normative_provider.py`](../src/gateway/governance/normative_provider.py:45).

**Step 1 — Establish a single source of truth for the tier model.**
Adopt `proof/model.py` `TIERS` as normative. Write one canonical description of the pipeline — kernel gates (FTRA boundary, STPA, confidence, OPA) plus registered domain tiers ordered by `(phase, order)` — and reuse it verbatim in TR-01 §9, TR-02 §6, TR-04 §13, TR-05 §2. Retire the ambiguous phrase "8-tier pipeline".

**Step 2 — Settle the contradiction register (§8).**
Resolve C1–C15 against code, one answer each, recorded in a small decision table. C1 (consensus fail-open vs fail-closed) is safety-critical and should be verified first.

**Step 3 — Mechanical path corrections (§2).**
Low-risk, high-value: fix every dead path and mismatched link. Can proceed in parallel with Steps 1–2.

**Step 4 — Recount every quantitative claim.**
Nodes (12), AgentState fields (33), providers (5 + 3 non-provider packages), decision primitives (6), Lula manifests, thresholds, tests. Run [`make test-coverage`](../Makefile) once and cite that single run with provenance across all documents.

**Step 5 — Add the missing architectural spine.**
New TR-02 section: the four-layer model, Gate G3 import boundary, the plugin contracts (`CagePlugin`, `GovernanceTierPlugin`, `InvariantModel`, `DomainToolProvider`), `discover_plugins()` / `CAGE_ACTIVE_PLUGINS`, `install_domain_components()`, `register_overlay_dir()`, `null_components.py` bare-kernel mode. Cross-reference [`docs/guides/PLUGIN_DEVELOPMENT.md`](../docs/guides/PLUGIN_DEVELOPMENT.md) and [`docs/architecture/EXTENSIBILITY_ARCHITECTURE.md`](../docs/architecture/EXTENSIBILITY_ARCHITECTURE.md) rather than duplicating them.

**Step 6 — Rewrite TR-05 §2–§4.**
The tier table, the CBF section (generic `InvariantModel` barrier + finance instantiation + Lua/fence-epoch/WAIT/replay-defence mechanics), and the STPA section. This is a rewrite, not an edit pass.

**Step 7 — Document the missing kernel subsystems (§5).**
Add sections for decisions/NARROW/PAUSE, `ConsequenceGateway` + `ConsequenceToken` + `jwks.py`, `TokenQuotaProxy`, `GovernanceEnvelope`, bounding contracts, evidence cold-store + residency, `RefusalReceipt`/`PauseReceipt` proof chains, and the Layer-3 `actuator_01` / `storage_*` packages.

**Step 8 — Extend the FTRA coverage (§6).**
Add the kernel boundary gate and bypass detection, the four-class taxonomy with scores, `FtraBoundaryResult`, `ParseResult`, and the bounding-contract link.

**Step 9 — TR-06 corrections.**
Remove the non-existent per-region Lula directories, refresh the manifest excerpt to include all active gates, add residency + domain overlays + CI compliance gates, and update the ISO 42001 Clause 8 row.

**Step 10 — Consistency sweep.**
Re-run a search for each dead path from §2 and each contradiction from §8 to confirm convergence, and align every document's Status/Date header block.

---

## 10. Suggested Documentation-Level Additions

Two things the series would benefit from that do not exist in any form today:

1. **A layer-boundary diagram** in TR-02 showing Layer 1 ↔ 2 ↔ 3 ↔ 4 with the permitted import directions and the Gate G3 arrow — this single diagram would carry most of the v3 architectural story.
2. **A "what changed in v3.0.0" appendix** cross-referencing [`docs/BREAKING_CHANGES_v3.md`](../docs/BREAKING_CHANGES_v3.md), listing the module relocations (§2 table), the tier-model change, and the domain-plugin extraction — so readers of the v2-era text can orient themselves.

Per the AGENTS.md documentation standard, both should be written as illustrative reference-architecture material, and all long-form edits should be applied in small chunks rather than monolithic rewrites.
