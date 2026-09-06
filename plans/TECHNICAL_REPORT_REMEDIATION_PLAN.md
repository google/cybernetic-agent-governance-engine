# CAGE Technical Report Remediation Plan (v3.0.0 Architecture Alignment)

| Metadata | Value |
|---|---|
| **Authoritative Baseline** | `src/` tree at HEAD, `proof/model.py`, `config/`, `AGENTS.md` |
| **Target Scope** | [`docs/technical-report/`](../docs/technical-report/) (TR-01 → TR-10, `README.md`), [`pyproject.toml`](../pyproject.toml), [`AGENTS.md`](../AGENTS.md) |
| **Tracking Analysis** | [`plans/TECHNICAL_REPORT_GAP_ANALYSIS.md`](TECHNICAL_REPORT_GAP_ANALYSIS.md) |
| **Branch** | `docs/sync-tech-report-code` |
| **Date** | 2026-09-06 |
| **Version** | 3.0.0 |

---

## 1. Executive Summary & Context

An extensive initial refactoring pass on branch `docs/sync-tech-report-code` (modifying 17 files, +1,064 / -197 lines) resolved several critical documentation issues:
- **G2 Dead Paths**: Replaced 11 deprecated module paths (`cbf.py`, `causal_gatekeeper.py`, `fiscal_limit_guard.py`, `provider_04`, etc.) with canonical v3 paths.
- **G4 Plugin Architecture Spine**: Added §14 to TR-02 covering the Three-Layer Split, Gate G3 import boundary, plugin registration, and bare-kernel null components.
- **G3 Major Subsystems**: Added Token Quota Proxy (§18), Consequence Gateway & Tokens (§19), PAUSE primitive (§20), Bounding Contracts (§21), and Extension Protocols (§22) to TR-05; added Cold Storage & Residency (§17) to TR-06; updated Layer 3 integration adapters in TR-03.
- **FTRA Boundary Gate**: Documented the kernel-side `_ftra_boundary_check()` and 4-class irreversibility taxonomy in TR-05 §2.1.

However, **the technical reports remain only ~55% aligned with HEAD**. Significant architectural discrepancies, cross-document contradictions, quantitative table mismatches, and code-side packaging oversights remain.

This remediation plan defines the exact execution sequence to close all remaining gaps (G1, G3, G4, G5, C1–C15, Steps 0–10).

---

## 2. Phase 1: Code-Side & Packaging Prerequisites (Step 0)

Before editing prose, resolve 4 code-side inconsistencies that otherwise perpetuate documentation drift.

### 1.1 Register Healthcare Plugin in `pyproject.toml` (C15, §4.1)
- **Problem**: TR-01 §1 claims finance and healthcare have equal standing. TR-02 §14.4 asserts both are registered under `[project.entry-points."cage.domain_plugins"]`. However, [`pyproject.toml:284`](../pyproject.toml:284) only registers `finance` under `cage.plugins`.
- **Action**: Update `pyproject.toml` entry points to declare both plugins:
  ```toml
  [project.entry-points."cage.plugins"]
  finance = "cage_finance.plugin:FinanceCagePlugin"
  healthcare = "cage_healthcare.plugin:HealthcareCagePlugin"
  ```
- **Validation**: Confirm with `uv run pytest tests/test_code_audit_remediation.py -k test_plugin_entry_points`.

### 1.2 Reconcile `AGENTS.md` Canonical Path for Reconciliation Worker
- **Problem**: [`AGENTS.md:352, 444`](../AGENTS.md#L352) cites `src.gateway.governance.reconciliation.worker`, but the physical file is [`src/gateway/governance/reconciliation/daemon.py`](../src/gateway/governance/reconciliation/daemon.py).
- **Action**: Update `AGENTS.md` lines 352 and 444 to reference `reconciliation.daemon`.

### 1.3 Correct `GovernanceDecision` Docstring Count
- **Problem**: [`src/gateway/governance/decisions.py:82`](../src/gateway/governance/decisions.py#L82) states "five-state governance decision vocabulary", but defines six members (`ALLOW`, `DENY`, `PAUSE`, `NARROW`, `REQUIRE_APPROVAL`, `DEFER`).
- **Action**: Update the docstring to read "Canonical six-state governance decision vocabulary".

### 1.4 Clean Stale Path Comments in Compliance Modules
- **Problem**: Code comments cite deleted path `config/compliance/reconciliation_worker.py`.
- **Action**: Update comments in [`src/compliance_bridge/kms_batch_signer.py:44`](../src/compliance_bridge/kms_batch_signer.py#L44) and [`src/gateway/governance/normative_provider.py:45`](../src/gateway/governance/normative_provider.py#L45) to point to `src/gateway/governance/reconciliation/daemon.py`.

---

## 3. Phase 2: Resolve Critical Safety Contradiction C1 (Consensus Fail Semantics)

- **Ground Truth**: [`src/gateway/governance/consensus/engine.py:425, 441-450`](../src/gateway/governance/consensus/engine.py#L425):
  ```python
  if all(v == "ERROR" for v in votes):
      # Unanimous ERROR must escalate, not approve — a DoS attack causing
      # both backends to error would otherwise bypass the consensus gate.
      status = "ESCALATE"
  ```
- **The Defect**: [TR-05 §7.3 (table line 535, callout line 543) and §20 (line 1276)](../docs/technical-report/05-AI-GOVERNANCE-POLICY-ENGINE.md#L535) state:
  *"ALL critics return ERROR → APPROVE (fail-open)"*. This is a safety-critical documentation bug.
- **Action**:
  1. Rewrite TR-05 §7.3 priority ladder row 1:
     `ALL critics return ERROR → ESCALATE (fail-closed; DoS bypass prevention)`.
  2. Rewrite the TR-05 §7.3 callout: explain that unanimous critic error triggers human escalation (`GovernanceError` / `ESCALATE`) to prevent an adversary from triggering a consensus bypass by exhausting GPU inference capacity.
  3. Align TR-05 §20 (line 1276) to match.
  4. Cross-check TR-01 §9.2, TR-02 §11.4, and TR-04 §13.3 to confirm uniform fail-closed documentation.

---

## 4. Phase 3: Synchronize Tier Model Architecture Across All TRs (G1 & Step 1)

Adopt [`proof/model.py:128`](../proof/model.py#L128) `TIERS = ("ftra", "stpa", "confidence", "cbf", "opa", "fiscal", "consensus", "causal", "fria")` as the single source of truth across the series. Retire the ambiguous phrase "8-tier pipeline".

### 4.1 TR-02 §6.1 Tier Table & Pipeline Diagram
- **Problem**: TR-02 §6.1 still presents a monolithic kernel ladder ("Tier 0 STPA → Tier 1 Confidence → Tier 2b OPA → Tier 5 Consensus → Tier 6 Causal → Tier 6b FRIA → Tier 2a CBF → Tier 3 Fiscal") and attributes CBF, Fiscal, Consensus, and Causal directly to kernel classes.
- **Action**:
  1. Update TR-02 §6.1 table to reflect the Kernel Gates + Registered Domain Tiers structure already established in TR-01 §9.1 and TR-05 §2.
  2. Update the Mermaid diagram in TR-02 §2: show `SymbolicGovernor` dispatching to `_run_domain_tiers(phase=1)` and `_run_domain_tiers(phase=2)` via the plugin registry rather than calling CBF/Consensus as direct kernel dependencies.

### 4.2 Reconcile Internal Contradictions in TR-05 (C2, C3)
- **Problem**: TR-05 contradicts itself between §3 and §12:
  - Line 229 defines FIN-1 as `qty / portfolio ≤ 0.1` and FIN-2 as `latency ≤ 200ms`.
  - Line 1292 defines FIN-1 as `trade_value > position_limit` and FIN-2 as `portfolio_concentration > 0.25`.
  - Line 231 defines UCA-5 as `drawdown > 4.5%`, while line 1294 defines UCA-5 as `order_size > 0.1 × daily_volume`.
- **Action**:
  - Authoritative definitions live in [`src/gateway/governance/ontology.py`](../src/gateway/governance/ontology.py) and `GeneratedSTPAValidator`:
    - `FIN-1`: `trade_value > position_limit` (`stpa.max_sell_portfolio_fraction = 0.10`).
    - `FIN-2`: `portfolio_concentration > 0.25` (`TradingKnowledgeGraph` concentration limit).
    - `UCA-5`: `drawdown > 4.5%` (`stpa.uca5_drawdown_threshold_pct = 4.5`).
    - `UCA-6`: `order_size > fraction × daily_vol` (1% US / 0.5% EU / 0.8% APAC).
  - Unify the definitions in TR-05 §3 and TR-05 §12.
  - Explain the STPA layer split: core validator and ontology in kernel, domain trade hazards in [`config/stpa/domains/finance/trade_hazards.yaml`](../config/stpa/domains/finance/trade_hazards.yaml).

### 4.3 Update TR-04 §13 (Agent System Governance Pipeline)
- Replace references to kernel CBF/Consensus with domain plugin tier execution via `SymbolicGovernor`.
- Document `execution_actuator.py` enforcing routing seal verification prior to MCP execution.

### 4.4 Update TR-06 §5.1 (ISO 42001 Clause 8 Mapping)
- Remove the deprecated phrase: *"8-tier governance pipeline (FTRA + Tiers 0–6 + 6b): STPA → confidence → CBF → SLM (deprecated) → OPA → consensus → causal → FRIA"*.
- Replace with: *"Two-phase governance pipeline comprising kernel boundary gates (FTRA 0.5, STPA 1, Confidence 2, OPA 3b, FRIA 7) and domain-registered tiers (Bounding, CBF, Fiscal, Consensus, Causal) with LIFO rollback."*

---

## 5. Phase 4: Synchronize Quantitative Data, Tables, and Manifest Inventories (G5 & Step 4)

### 5.1 Harmonize Test Statistics (C10)
- **Problem**: Divergence across documents:
  - `3,925 collected / 3,446 passing, 0 failed, 96 skipped` (README line 71, TR-04, TR-10).
  - `2,841 passing, 0 failed, 67 skipped` (TR-01 line 133, TR-09 line 1073, README line 32).
  - `2,553 passed, 51 skipped, 1 failed` (historical in AGENTS.md).
- **Action**: Standardize on the verified comprehensive test run across all documents: **3,925 tests collected / 3,446 local unit passed, 0 failed, 96 skipped (v3.0.0 stable)**. Update README line 32, TR-01 §5, and TR-09 §11.

### 5.2 Synchronize `AgentState` Fields (33 Fields)
- **Problem**: TR-04 §3 prose was updated to state 33 fields, but the table following it lists only 25 fields. TR-02 §3.4 line 187 still says "25 fields" and lists 25 fields.
- **Action**: Add the 8 missing governance fields to the tables in both TR-02 §3.4 and TR-04 §3:
  - `ftra_status`: Reachability verdict (`CLEAR`, `HITL_REQUIRED`, `BLOCKED`)
  - `ftra_result`: Serialized `FtraBoundaryResult`
  - `ftra_defer_id`: UUID for parked requests in `DeferQueue`
  - `narrow_status`: Narrowing state enum (`NONE`, `APPLIED`, `REJECTED`)
  - `narrowed_params`: Clamped trade parameter dictionary
  - `pause_resume_token`: Resumption token for paused executions
  - `pause_reason`: Reason code for PAUSE primitive
  - `confidence`: Calibrated model confidence score

### 5.3 Synchronize Graph Node Inventory (12 Nodes)
- **Problem**: TR-04 §4 documents 12 nodes, but TR-02 §3.1 still states "registers ten nodes", and TR-02 Mermaid diagrams omit `ftra_node` and `defer_node`.
- **Action**: Update TR-02 §3.1 to 12 nodes and update both Mermaid flowcharts in TR-02 to include `ftra_node` (between `evaluator` and `safety_check`) and `defer_node`.

### 5.4 Reconcile Presidio PII Entity Count (10 Entities) (C5)
- **Ground Truth**: [`config/rails/config.yml:51-60`](../config/rails/config.yml#L51-L60) configures exactly 10 entities (`PERSON`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD`, `US_SSN`, `US_BANK_NUMBER`, `IBAN_CODE`, `IP_ADDRESS`, `DATE_TIME`, `LOCATION`).
- **Action**: Update README line 30, TR-01 §4 line 119, TR-05 line 428, and TR-10 line 102 from "15 entity types" to "**10 entity types**".

### 5.5 Reconcile Fast Inference Model (C6)
- **Ground Truth**: [`03-TECHNOLOGY-STACK.md:46`](../docs/technical-report/03-TECHNOLOGY-STACK.md#L46) states Fast Node is `Meta-Llama-3.1-8B-Instruct`. `Qwen/Qwen2.5-1.5B-Instruct` is marked NOT CURRENTLY DEPLOYED.
- **Action**: Update TR-02 §2 line 56, TR-02 §5.4 line 323, and TR-08 §2 line 43 to replace `Qwen/Qwen2.5-1.5B-Instruct` with `Meta-Llama-3.1-8B-Instruct`.

### 5.6 Reconcile Langfuse Deployment Architecture (C7)
- **Ground Truth**: Self-hosted v3 on GKE with ClickHouse + MinIO (`deployment/k8s/langfuse-web.yaml`).
- **Action**: In TR-02 §2 line 64, §8.2 line 475, and TR-07 lines 59, 66, 416, replace "Langfuse SaaS" with "Langfuse (self-hosted v3 on GKE)".

### 5.7 Fix Lula Manifest Inventory & Remove Non-Existent Directories (C11)
- **Problem**: TR-06 §7 lines 344–346 claim per-region directories (`compliance/lula/us_fed/`, `eu_ecb/`, `apac_mas/`). All manifests are actually stored flat in `compliance/lula/`. Furthermore, the 15-manifest excerpt omits active manifests.
- **Action**:
  1. Remove references to fictitious per-region subdirectories in TR-06 §7.
  2. Add active manifests to the TR-06 manifest table: `lula-validation-ftra.yaml`, `lula-validation-tqp007.yaml`, `lula-validation-iso001-token-quota.yaml`, `lula-validation-flowsignal.yaml`.
  3. Document the [`.stub-baseline`](../compliance/lula/.stub-baseline) CI gate enforced by [`scripts/check_lula_stub_count.py`](../scripts/check_lula_stub_count.py).

### 5.8 Reconcile Routing Seal Formats Across Documents (C4)
- **Action**: Update TR-01 §9.3 to describe the canonical v3 asymmetric JWT format with KMS HSM signing and 4-tuple HMAC dev fallback, matching TR-06 §16.4, TR-07 §9.0, and TR-10 §9.

### 5.9 Fix Provenance Chain Serialization (C12)
- **Action**: In TR-01 §8.4, replace "deterministic sorted-key JSON serialization" with "RFC 8785 JSON Canonicalization Scheme (JCS)" implemented via [`src/gateway/governance/jcs_canonicalizer.py`](../src/gateway/governance/jcs_canonicalizer.py).

### 5.10 Reconcile Cybernetic Loop Human Gating (C8)
- **Action**: In TR-02 §10 lines 580 and 586, update the diagram and prose: replace `POST /v1/nemo/apply-refinement` and "no human in the low-latency path" with the mandatory human approval gate `POST /v1/nemo/approve-refinement/{proposal_id}` (CR-2 compliance).

### 5.11 Correct Test Citation in TR-01 §1.2
- **Action**: Replace reference to non-existent `tests/test_domain_independence.py` with the standing proof suite: [`tests/test_healthcare_plugin.py`](../tests/test_healthcare_plugin.py), [`tests/test_tier_registry_contract.py`](../tests/test_tier_registry_contract.py), and [`tests/test_import_boundaries.py`](../tests/test_import_boundaries.py).

---

## 6. Phase 5: Document Remaining Kernel Subsystems & Compliance Bridge Modules (G3 & Step 7)

Add targeted documentation for kernel modules that currently have zero representation in the report series:

| Module | Role | Location to Document |
|---|---|---|
| [`decisions.py`](../src/gateway/governance/decisions.py) | `GovernanceDecision` enum + `DeferResponse`, `NarrowResponse`, `PauseResponse` Pydantic models | TR-05 (decision serialization); TR-02 §5.2 (endpoint response schemas) |
| [`governance_envelope.py`](../src/gateway/governance/governance_envelope.py) | `GovernanceEnvelope` + `GovernanceEnvelopeBuilder` wire format | TR-02 §5; TR-06 §14b |
| [`jwks.py`](../src/gateway/governance/jwks.py) | JWKS endpoint (`/.well-known/jwks.json`) for asymmetric seal public keys | TR-07 §9.0; TR-02 §5.1 |
| [`authorization_claim_detector.py`](../src/gateway/governance/authorization_claim_detector.py), [`confidence_claim_detector.py`](../src/gateway/governance/confidence_claim_detector.py) | Claim-detection defense modules | TR-05 §12 (AI 600-1 table) |
| [`execution_actuator.py`](../src/gateway/governance/execution_actuator.py) | Kernel actuator enforcing seal verification before execution | TR-02 §5.3; TR-04 §13.1 |
| [`src/compliance_bridge/clickhouse_sink.py`](../src/compliance_bridge/clickhouse_sink.py), `cmek_guard.py` | Compliance Bridge telemetry persistence & CMEK key validation | TR-06 §14b |
| [`ftra/models.py`](../src/gateway/governance/ftra/models.py) (`ParseResult`, `ParseFailureClass`) | Defensive plan parsing and LLM schema validation failure handling | TR-04 §5a; TR-05 §2.1 |

---

## 7. Phase 6: Consistency Sweep & Verification (Step 10)

1. **Dead Link & Path Verification**:
   - Run ripgrep for all deprecated paths (`cbf.py`, `causal_gatekeeper.py`, `fiscal_limit_guard.py`, `provider_04`, `safety_params.json`). Zero occurrences must be found across `docs/technical-report/`.
2. **Import Boundary Gate**:
   - Run `uv run python scripts/check_import_boundaries.py --verbose` to ensure no illegal upward imports exist in code.
3. **Formal Parity Check**:
   - Run `uv run pytest tests/test_tier_registry_formal_parity.py -v` to ensure the tier registry matches `proof/model.py`.
4. **Header Block Synchronization**:
   - Verify every document in `docs/technical-report/` has a consistent header block (Date: 2026-09-06, Version: 3.0.0, Test count: 3,925 collected / 3,446 passing, 0 failed, 96 skipped).
5. **Commit & Branch Hygiene**:
   - Confirm branch `docs/sync-tech-report-code` meets Conventional Commits standards before squashing into `main`.

---

## 8. File Modification Checklist

| Document | Target Updates |
|---|---|
| [`pyproject.toml`](../pyproject.toml) | Add `healthcare = "cage_healthcare.plugin:HealthcareCagePlugin"` entry point |
| [`AGENTS.md`](../AGENTS.md) | Update canonical path to `reconciliation.daemon` (lines 352, 444) |
| [`src/gateway/governance/decisions.py`](../src/gateway/governance/decisions.py) | Update docstring count to 6 members |
| [`src/compliance_bridge/kms_batch_signer.py`](../src/compliance_bridge/kms_batch_signer.py) | Clean stale comment |
| [`src/gateway/governance/normative_provider.py`](../src/gateway/governance/normative_provider.py) | Clean stale comment |
| [`README.md`](../README.md) | Update Presidio to 10 entities; test counts to 3,446; align architecture overview |
| [`docs/technical-report/README.md`](../docs/technical-report/README.md) | Align test counts (line 32), Lula count (line 29), Presidio count (line 30) |
| [`docs/technical-report/01-SYSTEM-OVERVIEW.md`](../docs/technical-report/01-SYSTEM-OVERVIEW.md) | Update test citation (§1.2); Presidio to 10 (§4); JCS serialization (§8.4); seal to v3 JWT (§9.3) |
| [`docs/technical-report/02-ARCHITECTURE.md`](../docs/technical-report/02-ARCHITECTURE.md) | Redraw diagrams with 12 nodes & plugin tiers (§2); 12 nodes (§3.1); 33 state fields (§3.4); Fast model Llama-3.1 (§2, §5.4); self-hosted Langfuse (§2, §8.2); rewrite §6.1 tier table; human approval in loop (§10) |
| [`docs/technical-report/04-AGENT-SYSTEM.md`](../docs/technical-report/04-AGENT-SYSTEM.md) | Expand 25-field table to all 33 fields (§3); document `execution_actuator.py` (§13) |
| [`docs/technical-report/05-AI-GOVERNANCE-POLICY-ENGINE.md`](../docs/technical-report/05-AI-GOVERNANCE-POLICY-ENGINE.md) | Unify FIN-1/FIN-2/UCA-5 definitions (§3 vs §12); fix consensus fail-closed ESCALATE (§7.3, §20); Presidio to 10 (§6); document `decisions.py` models & claim detectors |
| [`docs/technical-report/06-COMPLIANCE-STANDARDS.md`](../docs/technical-report/06-COMPLIANCE-STANDARDS.md) | Update ISO 42001 Clause 8 tier description (§5.1); remove fake regional directories (§7); add active manifests (`ftra`, `tqp007`, `iso001-token-quota`, `flowsignal`) to table (§7); document `.stub-baseline` gate |
| [`docs/technical-report/07-SECURITY-INFRASTRUCTURE.md`](../docs/technical-report/07-SECURITY-INFRASTRUCTURE.md) | Update Langfuse SaaS to self-hosted v3; document JWKS endpoint (§9.0) |
| [`docs/technical-report/09-OPERATIONAL-RUNBOOK.md`](../docs/technical-report/09-OPERATIONAL-RUNBOOK.md) | Align test statistics (line 1073) |
| [`docs/technical-report/10-FORMAL-VERIFICATION.md`](../docs/technical-report/10-FORMAL-VERIFICATION.md) | Update Presidio to 10 entities (line 102) |

