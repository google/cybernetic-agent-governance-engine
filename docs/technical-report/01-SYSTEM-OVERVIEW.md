# 01 — System Overview

| Field                | Value                                                                                                         |
| -------------------- | ------------------------------------------------------------------------------------------------------------- |
| **Document Version** | 3.0                                                                                                           |
| **Date**             | 2026-08-22                                                                                                    |
| **Classification**   | INTERNAL                                                                                                      |
| **Document Series**  | CAGE Technical Report                                                                                         |
| **Status**           | ACTIVE — v3.0.0 stable (GKE deployment verified; 2,553 passed, 1 failed, 51 skipped; live GKE integration confirmed per [`AGENTS.md`](../../AGENTS.md)) |
| **Reference**        | [`compliance/boundary/AUTHORIZATION_BOUNDARY.md`](../../compliance/boundary/AUTHORIZATION_BOUNDARY.md) |

---

## 1. System Identity

The **Cybernetic Agent Governance Engine (CAGE)** v3.0.0 is a production-grade, **domain-agnostic** multi-agent AI governance framework. Its kernel provides universal runtime safety mechanisms — Control Barrier Functions, consensus arbitration, causal reasoning, forward-reachability boundary analysis, pipeline orchestration, and tamper-evident evidence sealing — that operate on abstract action primitives and encode no domain knowledge.

Two things sit outside that kernel and are supplied as **configuration rather than core requirements**:

| Concern | Mechanism | Shipped instances | Extensible? |
|---|---|---|---|
| **Domain semantics** | Optional `cage.plugins` entry-point packages, gated by `CAGE_ACTIVE_PLUGINS` | Finance ([`src/cage_finance/`](../../src/cage_finance/)) and healthcare ([`src/cage_healthcare/`](../../src/cage_healthcare/)) — **equal-standing case studies**, neither privileged nor required | Yes — `src/cage_<domain>/` for manufacturing, logistics, energy, critical infrastructure, clinical operations, or any other vertical |
| **Jurisdictional compliance** | Region profiles selected by `CAGE_DEPLOYMENT_REGION` over a universal ISO 42001 baseline | `US_FED`, `EU_ECB`, `APAC_MAS`, `LOCAL` | Yes — config-only, no Python changes |

CAGE runs on any conformant Kubernetes 1.24+ cluster (GKE is the reference deployment target).

### 1.1 Core Problem Solved

Any operator deploying high-reliability agentic AI faces the same structural gap: an LLM-based agent can trigger consequential, difficult-to-reverse writes to authoritative state stores — ledgers, clinical order systems, control-plane APIs, actuator endpoints — through opaque inference calls with no enforceable policy boundary, no tamper-evident audit trail, and no mechanism for human override once a workflow is in motion. Most AI systems treat compliance as a post-hoc concern: a layer of documentation applied after the system is built.

CAGE inverts this model. Every governance control is a first-class citizen inside the agent graph and inference pipeline. Compliance is not checked; it is enforced at the point of inference, producing both governed outputs and cryptographically attributable audit evidence in real time.

The intensity of the regulatory environment varies by domain and jurisdiction, but the *enforcement mechanism* does not. The mathematical invariant `h(x) ≥ 0` does not know what `x` means — only that the boundary must not be crossed. That indifference is what makes the substrate reusable across domains.

### 1.2 Extensibility Model

1. **Kernel owns mechanism.** Everything under [`src/gateway/`](../../src/gateway/): the atomic Redis Lua barrier hop, fence-epoch logic, KMS signature verification, quota reservation, the consensus algorithm, causal refutation, LIFO rollback ordering, evidence emission.
2. **Plugins own nomenclature and parameters.** Which actions a domain claims, which scalar its barrier watches, which threshold key holds the floor, which critics vote, which tools exist.
3. **Configuration owns jurisdiction.** Regional thresholds (`config/thresholds/`), control profiles (`config/compliance/`), policy bundles (`config/opa/`), and Lula assertions (`compliance/lula/`).

[`tests/test_bare_kernel_portability.py`](../../tests/test_bare_kernel_portability.py) and [`tests/test_cage_plugin_validation.py`](../../tests/test_cage_plugin_validation.py) provide the standing proof: they verify that Layer 1 boots cleanly without loading proprietary cloud vendor SDKs and that plugin contracts enforce domain isolation. Companion tests in [`tests/test_healthcare_plugin.py`](../../tests/test_healthcare_plugin.py) assert the healthcare package contains zero Lua scripts and zero KMS imports — it cannot fork the atomicity or signing paths. Authoring guide: [`DOMAIN_PLUGIN_ARCHITECTURE.md`](../architecture/DOMAIN_PLUGIN_ARCHITECTURE.md) §10.

---

## 2. Case Study: Regulatory Constraints in the Finance Example Domain

> **Scope note:** this section is a **worked case study of the finance example domain under the `US_FED` posture**, not a statement of CAGE's core requirements. The constraints below arrive from the finance plugin's threshold profile and the selected region profile. A healthcare deployment substitutes an entirely different constraint set — dosing ceilings, contraindication screening, HIPAA retention, clinician attestation — through the identical enforcement points, with no kernel change. §2.1 shows the mapping.

CAGE's inference pipeline enforces the following hard constraints when the finance example plugin is active under a US financial-services posture:

| Constraint                                                           | Regulatory Source                | Enforcement Point                                        |
| -------------------------------------------------------------------- | -------------------------------- | -------------------------------------------------------- |
| Maximum transaction latency: **200 ms**                              | Real-time interbank rail infrastructure requirement (FedNow / SEPA Instant) — required to support synchronous, inline AML and fraud-screening pipelines | Gateway — transaction commit blocked if latency exceeded |
| Identity verification required for transactions **> $1,000 USD**     | ISO-20022 (Section 1)            | Gateway / OPA policy                                     |
| OFAC sanctions screening for **all international transfers**         | ISO-20022 (Section 1)            | NeMo Guardrails + OPA                                    |
| PII **must not** persist in session history beyond **24 hours**      | SEC Reg S-P / GLBA (Section 2)   | Redis session TTL + NeMo PII masking                     |
| Audit logs retained for **7 years**                                  | FINRA Rule 4511 / SEC Rule 17a-4 | GCS artifact bucket + Compliance Bridge                  |
| All access to account data requires **a valid signed session token** | ISO-20022 (Section 2)            | Gateway authentication middleware                        |

These constraints are not aspirational. They are encoded as machine-enforceable policy in OPA Rego, NeMo Guardrails Colang rails, and the CAGE gateway middleware stack.

### 2.1 The Same Enforcement Points, a Different Domain

The table below maps each enforcement point to its finance-domain and healthcare-domain instantiation. The **Enforcement mechanism** column is kernel-owned and identical in both columns to its left — this is the domain-agnosticism claim stated concretely.

| Enforcement point | Finance example domain | Healthcare example domain | Enforcement mechanism (kernel, unchanged) |
|---|---|---|---|
| Barrier scalar | Cash balance floor (`CashBarrier`) | Serum concentration ceiling (`SerumConcentrationBarrier`) | Affine CBF evaluated in the atomic Redis Lua hop |
| Governed action | `execute_trade` | `dose_order` | Capability dispatch + FTRA irreversibility classification |
| Resource ceiling | Fiscal pre-reservation of budget tokens | Cumulative dose pre-reservation | `LeaseLedger` + `FiscalLimitStage` (generic budget tokens) |
| Critic panel | Risk Manager, Compliance Officer | Clinical reviewer personas | Heterogeneous multi-model `ConsensusEngine` |
| Policy bundle | `trade_governance.rego` | `dosing_governance.rego` | OPA client with fail-closed circuit breaker |
| Escalation | HITL approval above a value threshold | HITL approval above a clinical-risk threshold | LangGraph interrupt + mandatory hashed rationale |
| Evidence | Trade decision record | Order decision record | SHA-256 hash-chained accumulator + KMS routing seal |

An adopter domain — manufacturing tolerance limits, logistics capacity, grid dispatch headroom — populates the same seven rows with its own nouns and inherits the right-hand column unchanged.

---

## 3. System Stakeholders and Roles

CAGE follows the NIST SP 800-37 Rev. 2 role taxonomy. The table below summarizes each organizational role and its primary accountability domain. All incumbent positions are designated **TBD** as of 2026-03-06 pending ATO approval.

> **Note:** A standalone `docs/ROLES_AND_RESPONSIBILITIES.md` with a full RACI matrix and named incumbents was removed during a documentation-scope cleanup (2026-07) — CAGE is a reference architecture, not an operating organization, and a fictional roles document with placeholder `[TBD]` incumbents provided no engineering value. Adopters deploying CAGE in a real regulated environment should author their own RACI matrix naming real AO/ISSO/System Owner incumbents before pursuing an authorization package.

| Role                                    | Abbreviation | Primary Accountability                                                    |
| --------------------------------------- | ------------ | ------------------------------------------------------------------------- |
| **Authorizing Official**                | AO           | ATO decision; formal risk acceptance on behalf of the organization        |
| **Information System Security Officer** | ISSO         | Security posture ownership; POA&M tracking; SSP maintenance               |
| **System Owner**                        | SO           | Mission alignment; system lifecycle; change control authority             |
| **Common Control Provider (GCP/GKE)**   | CCP          | Platform-level inherited controls via GCP FedRAMP authorization           |
| **System Administrator**                | SA           | Kubernetes operations; secret rotation; patch management                  |
| **AI Model Operator**                   | AMO          | vLLM management; model versioning; governance tuning; SR 11-7 compliance  |
| **Compliance Engineer**                 | CE           | Lula automation; OSCAL artifact generation; ISO 42001 evidence production |

> **Note:** The Common Control Provider role is filled by Google Cloud Platform. All other roles have TBD incumbents. Personnel assignments are a prerequisite for ATO.

---

## 4. Primary Capabilities

> **v3.0.0 additions:** Full first-class runtime execution for 6 governance primitives (`ALLOW`, `DENY`, `REQUIRE_APPROVAL`, `DEFER`, `NARROW`, `PAUSE`), HMAC Routing Seal v2 (`<expire_hex>.<action_slug>.<record_hash_hex>.<hmac_hex>`) with SHA-256 evidence record hash binding, Lua-atomic Control Barrier Functions (`atomic_verify_and_commit()`) with synchronous replica `WAIT` verification and fail-closed state rollback, monotonic fence epoch (`safety:fence_epoch`), evidence stream blocking precondition checks, 57/66-state formal reachability models, Distributed CBF formal verification ($N \in \{2, 3, 4\}$ agents), and external attestation layers (Provider 05 3-axiom, Provider 04, Provider 03).


CAGE provides eight integrated capabilities. **Capabilities 2 and 4–8 are domain-neutral substrate functions** available regardless of which plugin — if any — is loaded. Capability 1 is a reference application belonging to the finance example domain, and capability 3 is the domain-neutral escalation primitive it exercises.

1. **Reference Applications for the Example Domains** *(plugin layer — optional)* — Two case studies demonstrate the substrate under load, and they carry **equal weight**:
   - **Finance case study.** The Governed Financial Advisor (`src/governed_financial_advisor/`) is a multi-agent reference application comprising specialist sub-agents (market data analyst, risk analyst, execution analyst, explainer, evaluator, supervisor) orchestrated by a LangGraph `StateGraph` (`src/governed_financial_advisor/graph/graph.py`). It pairs with the [`src/cage_finance/`](../../src/cage_finance/) plugin.
   - **Healthcare case study.** The [`src/cage_healthcare/`](../../src/cage_healthcare/) plugin contributes a dose-barrier tier, a clinical consensus tier, `dose_order` tooling, and `dosing_governance.rego`. It exists specifically to falsify the "this is really a finance product" claim by construction — it names things and implements no mechanism.

   Neither case study is required. `CAGE_ACTIVE_PLUGINS=""` runs the substrate with no domain loaded. In both cases, agent orchestration is governed end-to-end via the 8-tier pipeline (FTRA + 7 in-pipeline tiers); no agent action bypasses the policy engine. The FTRA Commencement Reachability Gate (`src/gateway/governance/ftra/`) enforces that every graph instance contains a reachable HITL approval path before any LLM inference begins — a check that inspects graph topology, not domain semantics.

2. **Real-Time Neuro-Symbolic Governance & 6 Decision Primitives** — An 8-tier policy enforcement architecture (FTRA pre-pipeline boundary gate at Tier 0.5, plus 7 in-pipeline tiers 0–6, plus adaptive Tier 6b FRIA gate) applied at inference time. Evaluates actions against 6 first-class runtime primitives (`ALLOW`, `DENY`, `REQUIRE_APPROVAL`, `DEFER`, `NARROW`, `PAUSE`). Each tier (STPA/UCA validation, agentic confidence check, Control Barrier Function with synchronous `WAIT` replication barrier and fail-closed rollback, OPA Rego authorization, multi-agent consensus, causal gatekeeper, and external normative validation) intercepts every request before and after the LLM call. The SLM sidecar has been deprecated and replaced by a permanent `slm_available=false` sentinel. Governance is synchronous — not advisory.

3. **Human-in-the-Loop Approval Escalation** *(domain-neutral)* — Any action a plugin classifies as high-risk is routed to a mandatory HITL approval node before execution — a trade recommendation in the finance case study, a dose order in the healthcare case study, or any adopter-defined consequential write. The gate itself is action-agnostic: it triggers on the risk verdict, not on the action's meaning. The approval workflow is logged with full provenance and linked to the originating inference trace.

4. **Continuous Compliance Evidence Generation** — The Compliance Bridge service produces OSCAL component definitions, control implementation statements, and ISO 42001 evidence artifacts as a continuous byproduct of system operation. Evidence is archived to GCS for 7-year audit retention. OSCAL assessment state semantics follow NIST SP 800-53A §3.2 — four states: `PASS`, `FAIL`, `NOT_APPLICABLE`, and `ERROR` (scanner failure — distinct from `NOT_APPLICABLE`).

5. **Privacy-Preserving PII Detection and Masking** — Microsoft Presidio and NVIDIA NeMo Guardrails jointly detect and mask 10 PII entity types in both inbound prompts and outbound model responses. Masked data is subject to the 24-hour session retention limit enforced by Redis TTL policies. NeMo Guardrails (`src/gateway/governance/nemo/`) additionally enforces CBRN keyword rails (`colang/cbrn_rails.co`) under `US_FED` jurisdiction (NIST AI 600-1 §2.6). The LangGraph harness (`src/gateway/governance/langgraph_harness/`) wraps both NeMo and OPA as typed governance nodes composable into any StateGraph pipeline.

6. **Red Team Adversarial Testing Harness** — A built-in evaluation harness with 290+ adversarial payloads tests governance robustness against prompt injection, jailbreak attempts, and governance bypass patterns. Red team results feed directly into the POA&M remediation cycle.

7. **Real-Time Audit Observability** — OpenTelemetry traces are emitted per inference request and forwarded to Langfuse via native OTLP (standalone OTel Collector deprecated 2026-05-31). An AgentSight eBPF DaemonSet provides kernel-level system call telemetry. The AgentSight UI (`src/agentsight-ui/`) is a React/TypeScript real-time governance dashboard (`src/agentsight-ui/src/KernelDashboard.tsx`) that surfaces governance verdicts, agent state transitions, and anomaly signals — including a live `max_slippage_pct` slider (0–10%, persisted via `POST /api/governance/thresholds`), per-item ΔP price-drift badges (green/yellow/red with pulse animation), and HITL TTL countdown timers for pending approvals.

8. **Configurable Multi-Jurisdiction Compliance Engine** *(configuration layer)* — Dynamic loading of regional compliance profiles (`config/compliance/`), governance thresholds (`config/thresholds/`), and OSCAL framework routing tables (`config/oscal/framework_mappings/`) via the `CAGE_DEPLOYMENT_REGION` environment variable. **ISO 42001 is the universal baseline active in every posture; the jurisdictional frameworks below are additive, configurable extensions that gate regional deployment posture only.** Four postures ship: `LOCAL` (universal baseline only — the development default), `US_FED` (NIST SP 800-53, NIST AI 600-1, AI RMF, SR 26-2, FINRA/SEC), `EU_ECB` (EU AI Act, DORA, GDPR Art. 22, EBA/GL/2023/02, with mandatory Fundamental Rights Impact Assessment and SR 26-2 telemetry suppression), and `APAC_MAS` (MAS FEAT Principles, MAS TRM Guidelines, MAS Notice 655). The compliance matrix includes separate Lula validation manifests and a pytest parametrize matrix covering all jurisdictions. The Phase A ingress adapters (`src/gateway/governance/ingress/`) normalize AAIF, ACS, OSCAL, and Lula schemas into the `ControlRegistry` format; the Phase B AGW adapter (`agw_adapter.py` + `agent_gateway_adapter.py`) exposes an Envoy ext_authz gRPC boundary. The CAGE-003 Agent Registry (`agent_registry_adapter.py`) maintains a SPIFFE trust-domain catalog of all authorized agents.

   **Adding a jurisdiction is a config-only operation requiring no Python code changes:** create `config/thresholds/<REGION>_BASELINE.json` and `config/compliance/<REGION>_BASELINE.json` against the existing schema, register region Rego under `config/opa/` and Lula assertions under `compliance/lula/`, ship a `<REGION>_OVERLAY.json` inside each active domain plugin, then set `CAGE_DEPLOYMENT_REGION=<REGION>`. Domain plugins and jurisdictional postures compose independently — any plugin runs under any posture.

---

## 5. Current Compliance Posture (NIST RMF Readiness)

CAGE is in active NIST RMF implementation. As of the assessment date, the system has not been recommended for ATO. The overall risk posture is classified **HIGH**. The v3.0.0 stable release was tagged on 2026-08-28. Both application images were built via Cloud Build and deployed to GKE cluster `governance-cluster-2`, namespace `governance-stack`. The test suite reports **3,446 passed, 0 failed, 96 skipped** (3,925 collected) with statement coverage across all three regional compliance postures.

### 5.1 Control Family Readiness

| Control Family                       | Readiness | Domain                   |
| ------------------------------------ | --------- | ------------------------ |
| AC — Access Control                  | 19%       | Identity & authorization |
| AU — Audit & Accountability          | 54%       | Logging & evidence       |
| CA — Security Assessment             | 19%       | Authorization package    |
| CM — Configuration Management        | 32%       | IaC & baseline           |
| IA — Identification & Authentication | 15%       | Credential management    |
| IR — Incident Response               | 28%       | Response procedures      |
| RA — Risk Assessment                 | 15%       | Threat modeling          |
| SC — System & Comms Protection       | 33%       | Encryption & isolation   |
| SI — System & Information Integrity  | 42%       | Scanning & integrity     |
| **Overall**                          | **24%**   |                          |

### 5.2 Critical Open Findings

| Finding                                                    | Status       |
| ---------------------------------------------------------- | ------------ |
| No intra-cluster mTLS between governance pipeline services | **RESOLVED** (POAM-007 — Linkerd mTLS + Cilium L7 deployed 2026-05-17) |
| System Security Plan (SSP) not yet drafted                 | **Open** (POAM-015) |
| FIPS 199 categorization document unsigned                  | **Open** (POAM-009 — In Progress) |
| HMAC routing seal bypass (FIND-010)                        | **RESOLVED** (`CAGE_ROUTING_SEAL_SECRET` enforced via K8s secret + `RuntimeError` fail-closed guard) |
| Langfuse compliance credentials fail silently when absent  | **Open** (POAM-018) |
| Terraform dual-project fallback defeats telemetry isolation | **Open** (POAM-019) |

The most significant systemic gap is the absence of an SSP (POAM-015). No ATO recommendation can be issued until the SSP, FIPS 199 categorization signature, and remaining critical findings are resolved. See [`docs/POAM.md`](../POAM.md) for the full Plan of Action and Milestones.

---

## 6. System Authorization Boundary

The CAGE authorization boundary encompasses all components deployed within the `governance-stack` Kubernetes namespace on the designated GKE cluster. The boundary extends to GCP managed services (Cloud SQL PostgreSQL, Google Cloud Storage) provisioned exclusively for CAGE, as well as the Terraform infrastructure-as-code and GitHub Actions CI/CD pipeline used to provision and deploy CAGE components.

Full boundary definition, component inventory, and data flow risk assessments are documented in `compliance/boundary/AUTHORIZATION_BOUNDARY.md`.

### 6.1 External Dependencies

The following external systems exchange data with CAGE across the authorization boundary. Each marked with _ISA Required_ requires a formal Interconnection Security Agreement before production data may be transmitted.

| External System            | Interface              | ISA Required     | Notes                                                   |
| -------------------------- | ---------------------- | ---------------- | ------------------------------------------------------- |
| **GCP Secret Manager**     | N/A                    | N/A — Removed    | **Removed (ADR):** Secrets now delivered exclusively via Kubernetes `Secret` objects provisioned by Terraform; no runtime GCP Secret Manager dependency |
| **GCS Artifact Bucket**    | GCP API (HTTPS)        | No — GCP FedRAMP | OSCAL/audit evidence archive; 7-year retention          |
| **MinIO** (model weights)  | HTTPS/REST             | Evaluate         | Self-hosted object store for vLLM model weights         |
| **Langfuse** (self-hosted v3) | HTTPS/REST (OTel OTLP) | **Yes**       | Self-hosted v3 with ClickHouse + MinIO; standalone OTel Collector deprecated 2026-05-31; inference traces; potential PII in spans; DPA required if SaaS used |
| **yfinance / Market Data** | HTTPS/REST             | **Yes**          | Financial instrument prices; API key auth               |
| **OFAC SDN List**          | HTTPS/REST             | No               | Read-only sanctions reference; no CAGE data transmitted |

> **Risk Note:** Langfuse is self-hosted v3 (ClickHouse + MinIO backend) within the GKE boundary. PII may be present in OTel trace payloads. The standalone OpenTelemetry Collector was deprecated 2026-05-31; services now export OTLP directly to Langfuse's integrated ingestion endpoint.

---

## 7. Document Series Navigation

This document is the first in the CAGE Technical Report series. Each document addresses a distinct architectural or compliance domain.

| Document                            | Title                             |
| ----------------------------------- | --------------------------------- |
| `01-SYSTEM-OVERVIEW.md`             | This document                     |
| `02-ARCHITECTURE.md`                | System Architecture               |
| `03-TECHNOLOGY-STACK.md`            | Technology Stack                  |
| `04-AGENT-SYSTEM.md`                | Multi-Agent System Design         |
| `05-AI-GOVERNANCE-POLICY-ENGINE.md` | AI Governance & Policy Engine     |
| `06-COMPLIANCE-STANDARDS.md`        | Compliance & Regulatory Standards |
| `07-SECURITY-INFRASTRUCTURE.md`     | Security Infrastructure           |
| `08-DEPLOYMENT-INFRASTRUCTURE.md`   | Deployment & Infrastructure       |
| `09-OPERATIONAL-RUNBOOK.md`         | Operational Runbook               |
| `10-FORMAL-VERIFICATION.md`         | Formal Verification & Completeness Proof |

---

## 8. Formal Safety Guarantees

CAGE's governance kernel provides four classes of formal safety guarantee, each grounded in a mathematical invariant enforced at runtime.

### 8.1 Control Barrier Function Invariance

The cash-balance safety property is expressed as a **discrete-time Control Barrier Function (CBF)** invariant. Let the barrier function be:

```
h(x) = cash_balance − min_cash_balance
```

The safe set is `S = {x ∈ ℝⁿ : h(x) ≥ 0}`. The CBF condition:

```
h(S(t+1)) ≥ (1 − γ) · h(S(t))     γ ∈ (0, 1), γ = 0.5 (default)
```

guarantees `h(S(t)) ≥ 0` for all `t` — i.e., the cash balance never falls below `min_cash_balance = $1,000 USD` — provided the invariant holds at `t = 0`. Implemented in [`src/gateway/governance/safety/cbf_engine.py`](../../src/gateway/governance/safety/cbf_engine.py) using Lua-atomic check-and-commit (`atomic_verify_and_commit()`) with synchronous replica `WAIT` verification.

### 8.2 NoDirectBind Invariant

All agent tool calls must pass through `validate_action()` — the single choke point for tool execution — and present a valid v3 routing seal (`X-CAGE-Routing-Seal`) in asymmetric JWT format (signed by Cloud KMS HSM, with dev/test HMAC fallback) verified via `verify_seal()` before the downstream actuator fires. Direct binding from an agent to an actuator — bypassing the governance pipeline — is structurally prohibited. This invariant is enforced at the framework level: no code path exists from agent intent to trade execution that does not traverse `SymbolicGovernor._run_checks()`. There is no `@governed_tool` decorator in the codebase.

### 8.3 FRIA Zone Classification

Every governed action is classified into one of three Fundamental Rights Impact Assessment (FRIA) zones based on the agent's confidence score:

| Zone | Threshold | Enforcement |
|------|-----------|-------------|
| `ALLOW` | confidence ≥ 0.95 | Async attestation; non-blocking |
| `DEFER` | 0.70 ≤ confidence < 0.95 | Synchronous blocking gate; context parked in Redis `db=1` (4-hour TTL) |
| `DENY` | confidence < 0.70 | Hard denial; confidence-starvation boundary |

The FRIA zone thresholds (`FRIA_ZONE_ALLOW = 0.95`, `FRIA_ZONE_DEFER = 0.70`) are sourced from `config/thresholds/*.json` (and `config/governance_thresholds.json`) and enforced in [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py).

### 8.4 Provenance Hash Chain Integrity

Every governance decision is recorded in a SHA-256 hash chain. Each `ProvenanceRecord` carries:

```
record_hash_n = SHA-256(parent_hash_{n-1} || jcs_canonicalize_plan(record_n))
```

The chain uses **deterministic RFC 8785 JSON Canonicalization Scheme (JCS)** serialization via [`src/gateway/governance/jcs_canonicalizer.py`](../../src/gateway/governance/jcs_canonicalizer.py) to guarantee cross-language deterministic byte representation without float serialization drift. Construction is O(n) in the number of governance nodes. `verify_chain_integrity()` validates the full chain on demand. Records are KMS-signed and written to the GCS WORM bucket under `provenance/<date>/<trace_id>.json`. Implemented in [`src/gateway/governance/provenance_chain.py`](../../src/gateway/governance/provenance_chain.py).

---

## 9. Governance Architecture

### 9.1 Plugin-Registered Tier Pipeline (v3.0.0 Architecture)

> **v3.0.0 architecture note:** The tier model has migrated from a fixed, kernel-owned tier ladder to a **plugin-registered tier system**. Domain plugins (finance, healthcare) register their governance tiers via [`GovernanceTierPlugin`](../../src/gateway/governance/contracts.py:218) protocol at startup. Tier numbering follows [`proof/model.py`](../../proof/model.py:128) `TIERS` tuple: `("ftra", "stpa", "confidence", "cbf", "opa", "fiscal", "consensus", "causal", "fria")`.

The `SymbolicGovernor` in [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py:1217) executes the governance pipeline in two phases. The pipeline is **fail-closed**: any tier raising a validation error halts execution and returns `BLOCKED`.

| Tier | Name | Owner | Description | Enforcement Mechanism |
| ---- | ---- | ----- | ----------- | --------------------- |
| **0.5** | FTRA Boundary | Kernel | Action irreversibility classification & bypass detection (R-03) | [`_ftra_boundary_check()`](../../src/gateway/governance/symbolic_governor.py:1088) |
| **1** | STPA UCA Validation | Kernel | Unsafe control action check | [`GeneratedSTPAValidator.validate()`](../../src/gateway/governance/generated_stpa_validator.py) |
| **2** | Confidence Pre-check | Kernel | Agent confidence threshold | Inline logic in `_run_checks()` |
| **—** | **Domain Tiers Phase 1 (read-only)** | **Plugin** | Registered tiers with `phase == 1`, sorted by `(phase, order)` | [`_run_domain_tiers()`](../../src/gateway/governance/symbolic_governor.py:944) |
| **3b** | OPA Policy | Kernel | Rego policy evaluation | [`OPAClient.evaluate_policy()`](../../src/gateway/core/policy.py) |
| **—** | **Domain Tiers Phase 2 (mutating)** | **Plugin** | Registered tiers with `phase == 2`, LIFO rollback on failure | [`_run_domain_tiers()`](../../src/gateway/governance/symbolic_governor.py:944) + [`_rollback_committed()`](../../src/gateway/governance/symbolic_governor.py:909) |
| **7** | FRIA Gate | Kernel | External normative provider (confidence-mapped) | [`enforce_fria_boundary()`](../../src/gateway/governance/normative_provider.py) |

**Finance plugin tiers** (registered by [`FinanceCagePlugin`](../../src/cage_finance/plugin.py:107)):
- Order 2 (phase 1): Bounding contracts (instrument/venue/counterparty allowlisting)
- Order 3 (phase 2): CBF (cash barrier via Lua atomic script)
- Order 4 (phase 2): Fiscal limit pre-reservation
- Order 5 (phase 1): Multi-agent consensus
- Order 6 (phase 1): Causal gatekeeper (DoWhy placebo refutation)

**Healthcare plugin tiers** (registered by [`CageHealthcarePlugin`](../../src/cage_healthcare/plugin.py)):
- Order 3 (phase 2): Dose barrier (serum concentration CBF)
- Order 5 (phase 1): Clinical consensus

> **Zero Budget Leakage:** Phase 2 state mutations execute only after all Phase 1 validation tiers emit `ALLOW`. Rejections in Phase 1 prevent any ledger mutation or spending cap consumption.

### 9.2 Key Mathematical Invariants

**FTRA (Tier 0.5):** Kernel-side [`_ftra_boundary_check()`](../../src/gateway/governance/symbolic_governor.py:1088) classifies action irreversibility into four classes (`IRREVERSIBLE_TERMINAL` score 1.0, `EXTERNALLY_REVERSIBLE` score 0.8, `REVERSIBLE` score 0.5, `READ_ONLY` score 0.0) with bypass detection (R-03 mitigation).

**CBF (Tier 3a, domain plugin):** `h(S(t+1)) ≥ (1−γ)·h(S(t))` ensures cash balance never falls below `min_cash_balance`, executed via single-hop Redis Lua atomic script. Registered by finance domain plugin via [`InvariantModel`](../../src/gateway/governance/contracts.py:342) protocol with [`CashBarrier`](../../src/cage_finance/invariants.py) instantiation.

**Confabulation (Langfuse metric, not a tier):** `risk_score = 1.0 − confidence` maps agent confidence directly to a risk score. A confidence of 0.95 yields `risk_score = 0.05` — the maximum tolerated confabulation risk.

**Causal (Tier 6, domain plugin):** Enforces a non-positive slope guard ($\beta \le 0 \implies \text{BLOCK}$) and bounded marginal risk scoring: $\text{risk\_score} = \min(1.0, 0.5 + \beta \times \text{amount}) \le 0.95$. The PlaceboTreatmentRefuter runs 50 simulations; a statistically significant placebo effect (p < 0.05 or |effect| > 0.2) indicates poisoned model assumptions.

**Consensus (Tier 5, domain plugin):** Boolean consensus logic — unanimous `APPROVE` → pass; unanimous `REJECT` → block; split vote or any `ESCALATE` → human escalation; unanimous `ERROR` → escalate (fail-closed, DoS bypass prevention).

### 9.3 Routing Seal

On approval, the governor returns a short-lived routing seal token. In v3, the routing seal is an **asymmetric JWT with evidence binding** signed by Cloud KMS HSM (with HMAC-SHA256 fallback in local/offline environments):

```
JWT Header:  {"alg": "RS256", "typ": "JWT", "kid": "<kms-key-version>"}
JWT Payload: {"sub": "<action_slug>", "params_hash": "<sha256>", "record_hash": "<evidence_hash>", "exp": <ts+30s>}
```

30-second TTL; the `record_hash` cryptographically binds the actuation clearance to a specific evidence record in the compliance audit stream. Downstream execution actuators ([`src/gateway/governance/execution_actuator.py`](../../src/gateway/governance/execution_actuator.py)) verify the seal against the JWKS endpoint before firing — ensuring execution cannot proceed by ignoring governance verdicts. See [`src/gateway/governance/routing_seal.py`](../../src/gateway/governance/routing_seal.py).

---

