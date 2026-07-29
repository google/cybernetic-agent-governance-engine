# CAGE Compliance & Governance Posture Framework
**CAGE Version:** v2.1.0
**Last Evaluated:** 2026-06-15

---

## ⚖️ The Dual-Responsibility Compliance Model

> **CRITICAL CONTEXT FOR AUDITORS:** CAGE provides the built-in technical enforcement controls, automated runtime guardrails, and programmatic evidence generation required to prove compliance. It does **not** automatically grant organizational or certified compliance. Full certification requires institutional audits, independent assessments, and formal administrative authorization.

> **Jurisdictional Architecture:** CAGE deploys to three regions controlled by `CAGE_DEPLOYMENT_REGION`. **ISO 42001** is the **universal baseline** active in all regions. NIST SP 800-53, EU AI Act/GDPR/DORA, and MAS FEAT are **jurisdictional extensions** active only in their respective regions. See [`docs/JURISDICTIONAL_SEPARATION_ANALYSIS.md`](docs/compliance/cross-region/JURISDICTIONAL_SEPARATION_ANALYSIS.md) for the full architectural rationale.

> **Deployment Targets:** The `gcp-gke` deployment target (`infra/targets/gcp-gke/`) is an optional GCP-specific configuration. The `agnostic` deployment target (`infra/targets/agnostic/`) deploys to any Kubernetes 1.24+ cluster without GCP dependencies.

---

## 1. Regulatory Perimeter & Framework Mapping

The Cybernetic Agent Governance Engine (CAGE) splits its internal control framework based on the operational nature of the component being evaluated. Traditional statistical calculations follow strict banking model guidelines, while autonomous LLM workflows are managed under infrastructure and operational resilience standards.

### 1.1 Universal Controls (ISO 42001 — All Deployments)

> **Scope: Universal — applies to ALL `CAGE_DEPLOYMENT_REGION` values (US_FED, EU_ECB, APAC_MAS)**

| System Layer | Component / Routine | Governing Framework | CAGE Control ID | Technical Artifact |
| --- | --- | --- | --- | --- |
| **Autonomous Engine** | LLM Routers & Execution Trust Thresholds | **ISO/IEC 42001 §A.5.2** (AI Management System) | `CTRL_AGT_001` | `src/gateway/governance/symbolic_governor.py` |
| **Autonomous Engine** | LangGraph SAGA WAL Router + Atomic Rollback Patterns | **ISO/IEC 42001 §A.8.4** | `CTRL_WAL_002` | `src/gateway/governance/generated_saga_nodes.py` |
| **Autonomous Engine** | DoWhy Live Telemetry Placebo Simulation (50-run loop) | **ISO/IEC 42001 §A.9.4** | `CTRL_TEL_003` | `src/gateway/governance/causal_gatekeeper.py` |
| **AARM Primitives** | Cryptographic Hash-Chained Context Accumulator | **CSA AARM-V1** · **ISO/IEC 42001 §A.5.3** | `CTRL_CTX_007` | `src/compliance_bridge/context_accumulator.py` |
| **AARM Primitives** | DEFER State Machine (Confidence-Starvation Boundary) | **CSA AARM-V7** · **ISO/IEC 42001 §A.8.4** | `CTRL_DFR_008` | `src/gateway/governance/defer_queue.py` |
| **AARM Primitives** | 11-Vector AARM Threat Conformance Report | **CSA AARM v1.0** | `CTRL_AARM_009` | `src/compliance_bridge/aarm_mapper.py` |
| **Security Gates** | Open Policy Agent (OPA) Guardrail & Constraints | **ISO/IEC 42001 §A.6.1** (Enterprise Policy) | `CTRL_OPA_005` | `src/gateway/governance/symbolic_governor.py` |

### 1.2 US_FED Only Controls (NIST SP 800-53 / AI 600-1)

> **Scope: US_FED only — applies when `CAGE_DEPLOYMENT_REGION=US_FED`**

| System Layer | Component / Routine | Governing Framework | CAGE Control ID | Technical Artifact |
| --- | --- | --- | --- | --- |
| **Statistical Code** | Control Barrier Function ($h(x)$ formula & $\gamma$ decay) | **SR 26-2 §IV.B** (Model Risk Management) | `CTRL_MRM_004` | `src/gateway/governance/cbf.py` |
| **Statistical Code** | DoWhy Causal Inference Model Graph & Regression Coefficients | **SR 26-2 §IV.B** (Model Risk Management) | `CTRL_MRM_004` | `src/gateway/governance/causal_gatekeeper.py` |
| **Infrastructure** | GKE Clusters, Workload Identity, Pod Networking | **NIST RMF (SP 800-37)** · **FedRAMP HIGH** | *Out of Code Scope* | `infra/modules/gcp_gke_cluster/` |

> **Note:** SR 26-2 has no legal force outside the US Federal Reserve system. The `EU_ECB_BASELINE.json` and `APAC_MAS_BASELINE.json` profiles suppress SR 26-2 telemetry via the `_NO_LEGAL_FORCE_MARKER` sentinel (see `.roo/rules` §12.4).

### 1.3 EU_ECB Only Controls (EU AI Act / GDPR / DORA)

> **Scope: EU_ECB only — applies when `CAGE_DEPLOYMENT_REGION=EU_ECB`**

| System Layer | Component / Routine | Governing Framework | CAGE Control ID | Technical Artifact |
| --- | --- | --- | --- | --- |
| **Autonomous Engine** | Step 7 Fundamental Rights Impact Assessment (FRIA) Attestation | **EU AI Act Art. 29a** | `CTRL_FRIA_006` | `src/gateway/governance/symbolic_governor.py` |
| **Autonomous Engine** | LangGraph SAGA WAL Router (DORA operational resilience) | **DORA Article 12** | `CTRL_WAL_002` | `src/gateway/governance/generated_saga_nodes.py` |
| **Autonomous Engine** | DoWhy Live Telemetry (DORA ICT continuity) | **DORA Article 10** | `CTRL_TEL_003` | `src/gateway/governance/causal_gatekeeper.py` |

### 1.4 APAC_MAS Only Controls (MAS FEAT / MAS Notice 655 / MAS TRM)

> **Scope: APAC_MAS only — applies when `CAGE_DEPLOYMENT_REGION=APAC_MAS`**

| System Layer | Component / Routine | Governing Framework | CAGE Control ID | Technical Artifact |
| --- | --- | --- | --- | --- |
| **Statistical Code** | Control Barrier Function (MAS FEAT fairness boundary) | **MAS FEAT Principles** | `CTRL_MRM_004` | `src/gateway/governance/cbf.py` |
| **Statistical Code** | DoWhy Causal Inference (MAS FEAT accountability) | **MAS FEAT Principles** | `CTRL_MRM_004` | `src/gateway/governance/causal_gatekeeper.py` |

### 1.5 Summary Mapping for Examiners

| System Layer | Component / Routine | Governing Framework | CAGE Control ID | Technical Artifact | Active Regions |
| --- | --- | --- | --- | --- | --- |
| **Statistical Code** | Control Barrier Function ($h(x)$ formula & $\gamma$ decay) | **SR 26-2 §IV.B** <br> (Model Risk Management) | `CTRL_MRM_004` | `src/gateway/governance/cbf.py` | `US_FED`, `APAC_MAS` *(suppressed in EU_ECB)* |
| **Statistical Code** | DoWhy Causal Inference Model Graph & Regression Coefficients | **SR 26-2 §IV.B** <br> (Model Risk Management) | `CTRL_MRM_004` | `src/gateway/governance/causal_gatekeeper.py` | `US_FED`, `APAC_MAS` *(suppressed in EU_ECB)* |
| **Autonomous Engine** | LLM Routers & Execution Trust Thresholds | **ISO/IEC 42001 §A.5.2** <br> (AI Management System) | `CTRL_AGT_001` | `src/gateway/governance/symbolic_governor.py` | *All Regions* |
| **Autonomous Engine** | LangGraph SAGA WAL Router + Atomic Rollback Patterns | **ISO/IEC 42001 §A.8.4** <br> **DORA Article 12** | `CTRL_WAL_002` | `src/gateway/governance/generated_saga_nodes.py` | *All Regions* |
| **Autonomous Engine** | DoWhy Live Telemetry Placebo Simulation (50-run loop) | **ISO/IEC 42001 §A.9.4** <br> **DORA Article 10** | `CTRL_TEL_003` | `src/gateway/governance/causal_gatekeeper.py` | *All Regions* |
| **Autonomous Engine** | Step 7 Fundamental Rights Impact Assessment (FRIA) Attestation | **EU AI Act Art. 29a** | `CTRL_FRIA_006` | `src/gateway/governance/symbolic_governor.py` | `EU_ECB` only |
| **AARM Primitives** | Cryptographic Hash-Chained Context Accumulator | **CSA AARM-V1** <br> **ISO/IEC 42001 §A.5.3** | `CTRL_CTX_007` | `src/compliance_bridge/context_accumulator.py` | *All Regions* |
| **AARM Primitives** | DEFER State Machine (Confidence-Starvation Boundary) | **CSA AARM-V7** <br> **ISO/IEC 42001 §A.8.4** | `CTRL_DFR_008` | `src/gateway/governance/defer_queue.py` | *All Regions* |
| **AARM Primitives** | 11-Vector AARM Threat Conformance Report | **CSA AARM v1.0** | `CTRL_AARM_009` | `src/compliance_bridge/aarm_mapper.py` | *All Regions* |
| **Security Gates** | Open Policy Agent (OPA) Guardrail & Constraints | **ISO/IEC 42001 §A.6.1** <br> (Enterprise Policy) | `CTRL_OPA_005` | `src/gateway/governance/symbolic_governor.py` | *All Regions* |
| **AI Safety (US_FED)** | Confabulation / Hallucination Rate Enforcement | **NIST AI 600-1 §2.1** | `CTRL_AGT_001` | `src/gateway/governance/confabulation_scorer.py` | `US_FED` only |
| **AI Safety (US_FED)** | PII Sanitization & Data Privacy Audit Logging | **NIST AI 600-1 §2.2** | `CTRL_PII_010` | `src/gateway/governance/pii_sanitizer.py` | `US_FED` only |
| **AI Safety (US_FED)** | Prompt Injection Detection & CausalGatekeeper WAL Integrity | **NIST AI 600-1 §2.3** | `CTRL_WAL_002` | `src/gateway/governance/prompt_injection_detector.py` | `US_FED` only |
| **AI Safety (US_FED)** | Human-AI Configuration / HITL Escalation (DEFER Queue) | **NIST AI 600-1 §2.5** | `CTRL_DFR_008` | `src/gateway/governance/hitl_escalator.py` | `US_FED` only |
| **AI Safety (US_FED)** | CBRN Content Filtering (NeMo Guardrails) | **NIST AI 600-1 §2.6 / §2.12** | `CTRL_CBRN_011` | `src/gateway/governance/nemo/colang/cbrn_rails.co` | `US_FED` only *(Cat-M: AO pre-approval required)* |
| **Infrastructure** | GKE Clusters, Workload Identity, Pod Networking | **NIST RMF (SP 800-37)** <br> **FedRAMP HIGH** | *Out of Code Scope* | `infra/modules/gcp_gke_cluster/` | *Optional — GCP-specific deployment target (`infra/targets/gcp-gke/`); not required for `agnostic` target deployments* |

---

## 2. Mathematical Safety Invariants

The following formal invariants are implemented directly in source code and enforced at runtime on every governance evaluation. Full derivations are in [`docs/technical-report/10-FORMAL-VERIFICATION.md`](docs/technical-report/10-FORMAL-VERIFICATION.md) and [`docs/governance/CAUSAL_AND_CBF_GOVERNANCE.md`](docs/governance/CAUSAL_AND_CBF_GOVERNANCE.md).

### 2.1 Control Barrier Function (CBF)

**Source:** [`src/gateway/governance/cbf.py`](src/gateway/governance/cbf.py) · **Control:** `CTRL_MRM_004`

The safe set is `S = {x ∈ ℝⁿ : h(x) ≥ 0}` where the barrier function is:

```
h(x) = cash_balance − min_cash_balance
```

The discrete-time CBF condition enforced at every governance tick:

```
h(S(t+1)) ≥ (1−γ) · h(S(t)),   γ ∈ (0,1)
```

This guarantees the cash balance never drops below the minimum threshold in a single step. The decay factor `γ` bounds the maximum permissible drawdown per evaluation cycle. CBF currently reads from Redis state; external reconciliation via `AnchorageGrpcLedgerProvider` is FUTURE STATE (POAM-023, target 2026-09-08).

### 2.2 Confabulation Risk Formula

**Source:** [`src/gateway/governance/confabulation_scorer.py`](src/gateway/governance/confabulation_scorer.py) · **Control:** `CTRL_AGT_001`

```
risk_score = 1.0 − confidence
```

| Score Range | Action |
|-------------|--------|
| ≥ 0.95 (`FRIA_ZONE_ALLOW`) | Async attestation — 0 ms overhead |
| [0.70, 0.95) (`FRIA_ZONE_DEFER`) | Synchronous blocking gate via DEFER queue |
| < 0.70 | Local hard deny — no external call |

### 2.3 Causal Marginal Risk Boundary

**Source:** [`src/gateway/governance/causal_gatekeeper.py`](src/gateway/governance/causal_gatekeeper.py) · **Control:** `CTRL_TEL_003`

A trade action is blocked when:

```
(0.5 + estimate.value × amount) > 0.95
```

The `PlaceboTreatmentRefuter` runs **50 simulations**; the causal effect is considered spurious (action blocked) when **p ≥ 0.05** or **|effect| ≤ 0.2**.

### 2.4 FRIA Zone Thresholds

**Source:** [`src/gateway/governance/symbolic_governor.py`](src/gateway/governance/symbolic_governor.py) · **Control:** `CTRL_FRIA_006`

| Constant | Value | Semantic |
|----------|-------|----------|
| `FRIA_ZONE_ALLOW` | `0.95` | Confidence floor for immediate async pass |
| `FRIA_ZONE_DEFER` | `0.70` | Confidence floor for DEFER queue entry |

Scores below `FRIA_ZONE_DEFER` trigger a local hard deny without invoking the external normative provider.

### 2.5 Fiscal Limit Guard Parameters

**Source:** [`src/gateway/governance/fiscal_limit_guard.py`](src/gateway/governance/fiscal_limit_guard.py) · **Control:** `CTRL_MRM_004`

| Parameter | Value |
|-----------|-------|
| Daily cap | **$500,000** |
| Rolling window | **86,400 s** (24 h) |
| Contention strategy | Exponential backoff |
| Redis failure mode | Fail-closed (blocks request) |

### 2.6 Provenance Hash Chain Integrity

**Source:** [`src/gateway/governance/provenance_chain.py`](src/gateway/governance/provenance_chain.py) · **Control:** `CTRL_CTX_007`

SHA-256 hash chain with O(n) construction:

```
record_hash[n] = SHA-256(record_hash[n-1] ‖ content_json[n])
```

Any mutation of node `k` invalidates all hashes for nodes `k … n`, making tampering detectable at O(1) per node during verification.

### 2.7 Routing Seal Integrity

**Source:** [`src/gateway/governance/routing_seal.py`](src/gateway/governance/routing_seal.py) · **Control:** `CTRL_MRM_004`

HMAC-SHA256 token format:

```
<expire_ts_hex>.<action_slug>.<hmac_hex>
```

TTL: **30 seconds**. Unsigned or expired requests return HTTP 403.

---

## 3. STPA Unsafe Control Actions (UCAs)

**Source:** [`src/gateway/governance/ontology.py`](src/gateway/governance/ontology.py), [`config/stpa_control_structure.yaml`](config/stpa_control_structure.yaml)

The STPA-to-Policy Compiler (`src/gateway/governance/stpa_compiler.py`) ingests the declarative YAML control structure and auto-generates OPA Rego policies, NeMo Colang rails, Python validator classes, and LangGraph Saga compensating sub-graphs from the following UCA definitions:

| UCA ID | Condition | Generated Enforcement Artifact |
|--------|-----------|-------------------------------|
| **FIN-1** | `trade_value > position_limit` | OPA Rego rule + `GeneratedSTPAValidator` |
| **FIN-2** | `portfolio_concentration > 0.25` | OPA Rego rule + `GeneratedSTPAValidator` |
| **UCA-5** | `order_size > 0.1 × daily_volume` | Saga compensating node + HITL escalation |
| **UCA-6** | `order_size > fraction × daily_vol` | Saga compensating node + HITL escalation |

Full STPA hazard analysis (UCAs 1–9, Saga pattern, FiscalLimitGuard): [`docs/security/STPA_ANALYSIS.md`](docs/security/STPA_ANALYSIS.md)

---

## 4. In-Depth Control Implementations

### A. SR 26-2 Model Risk Management Partitioning
*   **Status:** Strictly Scoped & Partitioned.
*   **Mechanism:** Traditional, deterministic safety formulas and back-testable statistical structures (the causal regression kernel) are isolated under `CTRL_MRM_004`. CAGE intentionally decouples these from fluid agent workflows, fulfilling the Federal Reserve mandate to apply targeted, rigorous mathematical validation to traditional predictive blocks while shielding them from non-deterministic LLM variance. The discrete-time CBF condition `h(S(t+1)) ≥ (1−γ)·h(S(t))` (see §2.1 above) is the primary mathematical invariant validated under this control.
*   **Companion Documentation:** For details on mathematical CBF equations and regression validation, see [docs/CAUSAL_AND_CBF_GOVERNANCE.md](docs/governance/CAUSAL_AND_CBF_GOVERNANCE.md) and [docs/STPA_ANALYSIS.md](docs/security/STPA_ANALYSIS.md).

### B. ISO/IEC 42001 & DORA (Digital Operational Resilience Act)
*   **Status:** Technical Controls Implemented & Observable.
*   **Mechanism:**
    *   **Transaction Atomicity (DORA Art. 12):** The LangGraph SAGA Write-Ahead Log (WAL) pattern isolates tool calls and model actions, guaranteeing LIFO (Last-In, First-Out) rollbacks during system or execution faults to prevent partial "ghost states" in ledger positions.
    *   **Continuous Telemetry Validation (DORA Art. 10):** Real-time Langfuse OpenTelemetry spans are piped through the placebo refuter at runtime to verify that the agent's world-model matches execution reality, rather than drifting on synthetic variables.
    *   **Tamper-Proof Audit Logging:** All decisions and system exceptions generate a cryptographically hash-chained SHA-256 ledger (`cage-intent/1.0`) to satisfy strict non-repudiation and lifecycle logging policies.
*   **Companion Documentation:** 
    *   For detail on the STPA control structure compiling to OPA/NeMo/Saga, see [docs/STPA_ANALYSIS.md](docs/security/STPA_ANALYSIS.md).
    *   For detailed symbolic governor and hybrid logic flow, see README_GOVERNANCE.md and [docs/NEURO_SYMBOLIC_GOVERNANCE.md](docs/governance/NEURO_SYMBOLIC_GOVERNANCE.md).

### C. European Union AI Act, GDPR, and EBA Hard Law Baseline (EU_ECB Profile)
*   **Status:** Technical Controls Mapped & Telemetry Attested.
*   **Mechanism:**
    *   **Fundamental Rights Impact Assessment (EU AI Act Art. 29a):** In `EU_ECB` region, the `symbolic_governor` executes a Step 7 FRIA attestation control (`CTRL_FRIA_006`), injecting pre-market assessment metadata as attributes on live OTel telemetry spans. This guarantees live tracing logs provide proof of pre-market compliance under DORA Art. 10 / 12 auditing guidelines.
    *   **Prohibition on Fully Automated Decisions (GDPR Art. 22):** The `EU_ECB` profile automatically scales down maximum trade and confidence thresholds and forces human-in-the-loop validation for any decision carrying legal or significant effect, preventing illegal automated processing.
    *   **SR 26-2 Telemetry Suppression:** CAGE dynamically suppresses US Fed SR 26-2 telemetry when executing under the `EU_ECB` profile using a data-driven sentinel mechanism. The `EU_ECB_BASELINE.json` encodes `CTRL_MRM_004`'s `legacy_citation` as `"SR 26-2 §IV (US Federal Reserve — no legal force in EU jurisdiction)"`. The `causal_gatekeeper` reads this marker at runtime and emits `primary_framework` (the EBA citation) on OTel spans instead. Adding a new region requires only a JSON profile update — no Python changes.
    *   **EBA Guidelines Mapping:** Integrates governance metrics directly with internal audit processes per EBA/GL/2023/02 guidelines.

### D. Singapore MAS FEAT Principles Baseline (APAC_MAS Profile)
*   **Status:** Technical Controls Mapped & Enforced.
*   **Mechanism:**
    *   **Fairness, Ethics, Accountability, Transparency (FEAT):** Restricts the agent's parameters to MAS FEAT boundaries, dynamically loading `config/thresholds/APAC_MAS_BASELINE.json` to enforce strict operational limits (e.g., SLA latency floor: `175ms`, Consensus: `$8,500`). Ensures full algorithmic accountability and trace transparency in the compliance project trace database.

### E. NIST RMF & FedRAMP HIGH
*   **Status:** **PARTIAL** (Technical Hardening Complete, Administrative ATO Pending).
*   **Mechanism:**
    *   **Zero-Trust Network Hardening:** Deploys Linkerd SPIFFE/SVID mTLS for cryptographic workload validation (**POAM-007 / IA-3**, closed 2026-05-17) and Cilium Layer 7 network policies for default-deny egress lockdown (**POAM-011 / SC-8**, Open). Both controls are technically active in the `governance-stack` Kubernetes namespace; POAM-011 (SC-8) and POAM-012 (SC-12) remain Open pending formal assessment closure.
    *   **Programmatic Evidence:** The automated script `oscal_ssp_exporter.py` automatically compiles these exact control configurations and implementation narratives into the authoritative 1,330-line Open Security Controls Assessment Language (OSCAL) document on every build pipeline run. OSCAL artifacts are persisted to GCS using the native GCS SDK (boto3 S3-compat fallback) at schema version **OSCAL v1.0.4**.
    *   **KMS Batch Signing for Audit Evidence:** All OSCAL findings and AARM conformance reports are asymmetrically signed via Google Cloud KMS HSM (`src/gateway/governance/kms_signer.py`) before GCS persistence. The private key never leaves the HSM; Cloud Audit Logs provide external, immutable attestation of every signing operation. This constitutes the audit evidence chain for FedRAMP HIGH AU-9 and AU-10.
    *   **⚠️ Gaps to Authorization:** The CAGE software runtime does not inherently possess an official **Authority to Operate (ATO)**. To close this loop, the parent organization must deploy independent assessors to complete RMF Step 5 (Assess) and Step 6 (Authorize), as well as remediate the remaining 11 open infrastructure POA&M infrastructure tickets.
*   **Companion Documentation:** For infrastructure configurations, Linkerd policy files, and security posture tracking, see [docs/SECURITY_STATUS.md](docs/security/SECURITY_STATUS.md) and [docs/POAM.md](docs/compliance/cross-region/POAM.md).

### F. Lula Automated Compliance Validation (20 Manifests — 4 Active, 16 Stub)
*   **Status:** Partially Automated.
*   **Mechanism:** Lula automates OSCAL Assessment Result generation on a 6-hour CronJob schedule (`deployment/k8s/lula-cron.yaml`). There are **20 validation manifests** in `compliance/lula/` — 4 are production-ready and Active; 16 are Stubs that require cluster-specific namespace/resource name configuration before activation. See [`compliance/lula/README.md`](compliance/lula/README.md) for the full status table and activation instructions.

    **✅ Active (4):**
    *   `lula-validation-a52.yaml` (ISO 42001 A.5.2, **ALL regions**) — Social impact assessment; NeMo Guardrails toxicity blocking ≥ 99%
    *   `lula-validation-a53.yaml` (ISO 42001 A.5.3, **ALL regions**) — Logging and monitoring; Langfuse safety rate ≥ 98%
    *   `lula-validation-a92.yaml` (ISO 42001 A.9.2, **ALL regions**) — Data transfer to suppliers; Presidio PII leak rate = 0%
    *   `lula-validation-sc4.yaml` (NIST SP 800-53 SC-4, **US_FED only**) — Fiscal limits and RBAC; OPA ConfigMap label present in `governance-stack` namespace

    **🔶 Stub (11)** — NIST SP 800-53 / CSA AARM; logic complete, requires cluster-specific configuration:
    *   `lula-validation-aarm-vectors.yaml` (CSA AARM v1.0, **ALL regions**) — 11-vector AI agent threat model coverage
    *   `lula-validation-ac2.yaml` (NIST SP 800-53 AC-2) — Account management / service account lifecycle
    *   `lula-validation-ac3.yaml` (NIST SP 800-53 AC-3) — Access enforcement / OPA RBAC
    *   `lula-validation-au12.yaml` (NIST SP 800-53 AU-12) — Langfuse OTLP ingestion availability (standalone OTel Collector deprecated 2026-05-31; validation needs update)
    *   `lula-validation-cm6.yaml` (NIST SP 800-53 CM-6) — Configuration settings enforcement
    *   `lula-validation-ia3.yaml` (NIST SP 800-53 IA-3) — Device identification / Linkerd mTLS SPIFFE identity
    *   `lula-validation-ia5.yaml` (NIST SP 800-53 IA-5) — Authenticator management / KMS HSM key lifecycle
    *   `lula-validation-ir6.yaml` (NIST SP 800-53 IR-6) — Incident reporting
    *   `lula-validation-ra5.yaml` (NIST SP 800-53 RA-5) — Vulnerability scanning (pip-audit / Trivy CI)
    *   `lula-validation-sc8.yaml` (NIST SP 800-53 SC-8) — Transmission confidentiality / TLS enforcement
    *   `lula-validation-si2.yaml` (NIST SP 800-53 SI-2) — Flaw remediation / CVE patching (pip-audit CI)

    **🔶 Stub (5)** — NIST AI 600-1 (**US_FED only**); Phase 0 scaffolding added 2026-06-15; require Langfuse metric availability and cluster-specific configuration before activation (see [`docs/compliance/us_fed/AI_600_1_IMPLEMENTATION_PLAN.md`](docs/compliance/us_fed/AI_600_1_IMPLEMENTATION_PLAN.md)):
    *   `lula-validation-ai600-confabulation.yaml` (AI 600-1 §2.1, controls: SI-10, AU-3, POAM AI600-001) — Confabulation / hallucination detection; asserts `confabulation_rate < 0.02` over 24 h window via `confabulation_scorer.py`
    *   `lula-validation-ai600-data-privacy.yaml` (AI 600-1 §2.2, controls: SI-19, SC-28, POAM AI600-002) — Data privacy / PII sanitization; asserts PII audit log retention ≥ 90 days and Presidio score threshold ≥ 0.5
    *   `lula-validation-ai600-prompt-injection.yaml` (AI 600-1 §2.3, controls: SI-3, SI-10, CA-8, POAM AI600-003) — Prompt injection detection; asserts injection detector ConfigMap present and deflection score ≥ 4
    *   `lula-validation-ai600-human-ai-config.yaml` (AI 600-1 §2.5, controls: AC-5, AU-3, CA-7, POAM AI600-005) — Human-AI configuration / HITL escalation; asserts DEFER queue SLA ≤ 4 h for CRITICAL escalations and HITL audit trail present
    *   `lula-validation-ai600-cbrn.yaml` (AI 600-1 §2.6 / §2.12, controls: SA-12, SR-3, SI-7, POAM AI600-007) — CBRN content filtering; asserts CBRN keyword list ≥ 10 terms enabled and NeMo CBRN rail deployed. **⚠️ Cat-M: requires AO pre-approval before cluster activation.**

### G. NIST AI 600-1 Generative AI Risk Management (US_FED Profile)
*   **Status:** Phase 0 Scaffolding Complete (2026-06-15). Full assertions target Phase 2–3 per [`docs/compliance/us_fed/AI_600_1_IMPLEMENTATION_PLAN.md`](docs/compliance/us_fed/AI_600_1_IMPLEMENTATION_PLAN.md).
*   **Jurisdiction:** `US_FED` only (`CAGE_DEPLOYMENT_REGION=US_FED`). NIST AI 600-1 controls are **not** applied to `EU_ECB` or `APAC_MAS` deployments.
*   **Mechanism:** NIST AI 600-1 ("Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile") defines risk controls specific to generative AI systems. CAGE implements the following AI 600-1 risk domains as runtime controls, each backed by a Lula validation stub:

    | AI 600-1 Section | Risk Domain | CAGE Implementation | Lula Manifest | POAM |
    | --- | --- | --- | --- | --- |
    | §2.1 | Confabulation / Hallucination | `confabulation_scorer.py` — confidence gate ≥ 0.95; provenance signing via AgentSight | `lula-validation-ai600-confabulation.yaml` | AI600-001 |
    | §2.2 | Data Privacy / PII | `pii_sanitizer.py` (Presidio) — PII scrubbed before LLM; CMEK-encrypted audit log | `lula-validation-ai600-data-privacy.yaml` | AI600-002 |
    | §2.3 | Prompt Injection | `prompt_injection_detector.py` + `causal_gatekeeper.py` WAL integrity | `lula-validation-ai600-prompt-injection.yaml` | AI600-003 |
    | §2.5 | Human-AI Configuration | `hitl_escalator.py` + `defer_queue.py` — DEFER SLA ≤ 4 h; consensus threshold $10,000 | `lula-validation-ai600-human-ai-config.yaml` | AI600-005 |
    | §2.6 / §2.12 | CBRN & Value Chain | NeMo `cbrn_rails.co` — Tier-1 keyword list; NeMo CBRN rail deployed | `lula-validation-ai600-cbrn.yaml` | AI600-007 |

*   **Companion Documentation:**
    *   [`docs/compliance/us_fed/AI_600_1_IMPLEMENTATION_PLAN.md`](docs/compliance/us_fed/AI_600_1_IMPLEMENTATION_PLAN.md) — phased implementation plan (Phase 0–3, Weeks 1–52)
    *   [`docs/compliance/us_fed/NIST_AI_600_1_US_FED_ANALYSIS.md`](docs/compliance/us_fed/NIST_AI_600_1_US_FED_ANALYSIS.md) — gap analysis and control mapping
    *   [`compliance/lula/README.md`](compliance/lula/README.md) — full Lula validation status table including AI 600-1 stubs

### H. Continuous Audit Event Loop & Compliance Bridge API (v2.0.0)
*   **Status:** Implemented & Active.
*   **Mechanism:** In CAGE v2.0.0, the Compliance Bridge service (`src/compliance_bridge/main.py`) acts as the central hub for automated compliance scoring and threat ledger reporting. It exposes fourteen REST endpoints:
    1.  `GET /health` — Kubernetes liveness probe.
    2.  `GET /v1/controls` — Discovery endpoint; returns the full registry of supported ISO 42001 / NIST controls.
    3.  `GET /v1/metrics/summary` — Aggregate compliance posture across all supported controls in a single response.
    4.  `GET /v1/oscal/assessment-results` — Exports current compliance posture as an OSCAL 1.1.2 Assessment Results document.
    5.  `GET /v1/audit/status/{audit_id}` — Polls the status of a previously submitted audit.
    6.  `GET /v1/metrics/{control_id}` — Returns compliance metrics for a specific control ID (queried by Lula).
    7.  `POST /v1/audit/ingest` — Accepts OSCAL Assessment Result YAML from the Lula CronJob, parses, persists to GCS, and ingests into Langfuse.
    8.  `GET /v1/aarm/conformance-report` — Generates a live 11-vector CSA AARM conformance report with optional vLLM narrative enrichment (Semaphore-controlled rate limit of 3 concurrent calls).
    9.  `GET /v1/defer/pending` — Lists all pending context-starved execution contexts parked in Redis `db=1` (AARM-V7).
    10. `POST /v1/defer/{defer_id}/inject` — Resolves deferred tokens by injecting supplementary context data.
    11. `POST /v1/defer/{defer_id}/escalate` — Escalates deferred tokens to `MANUAL_REVIEW` after TTL expiry (4 hours).
    12. `GET /v1/prompts/{name}` — Proxy endpoint; fetches Langfuse prompts by name via HTTP.
    13. `GET /v1/telemetry/history` — Fetches paginated historical compliance telemetry from the Langfuse compliance project.
    14. `GET /v1/events/stream` — SSE governance event stream consumed by the AgentSight UI KernelDashboard.

### I. Dependency Security — `diskcache` CVE-2025-69872 Remediation
*   **Status:** Remediated in v2.0.0.
*   **Mechanism:** **CVE-2025-69872 in `diskcache`** (transitive dependency via `outlines`; `outlines` removed to eliminate the dependency) — a pickle deserialization RCE vulnerability in the `diskcache` package, which was a transitive dependency pulled in by `outlines`. The `outlines` package was removed from all CAGE service dependencies to eliminate `diskcache` from the dependency tree. Structured-output generation previously provided by `outlines` is now handled via vLLM's native JSON-mode API. No CAGE service imports `outlines` or `diskcache` at runtime. The removal is enforced by `pip-audit` and Trivy scans in `.github/workflows/security-scan.yml` (POAM-010 closed). Regulated-environment deployers should verify their own dependency trees do not re-introduce `outlines` via transitive dependencies.
*   **Compliance Mapping:** NIST SP 800-53 SI-2 (Flaw Remediation); ISO/IEC 42001 §A.9.3 (Supplier Relationships).

---

## 5. Automated Posture Enforcement (CI/CD Guardrails)

To guarantee that compliance claims never drift from physical codebase state, permanent regression tests are established in `tests/test_governance_architecture.py` and `tests/test_framework_router.py`.

The **architecture guardrail** (`test_governance_architecture.py`) scans all business logic files on every pull request to enforce:
1.  **Zero Citation Leakage:** Prevents literal strings like `"SR 26-2"`, `"SR 11-7"`, or `"ISO 42001"` from being hardcoded into executable files.
2.  **Authoritative Translation:** Restricts all runtime regulatory definitions to the `config/compliance/*_BASELINE.json` regional profiles loaded by `ControlRegistry`.
3.  **Active Control Verification:** Ensures every control code defined in the system registry has a physical, verified invocation point in the gateway's execution paths.
4.  **Regional Profile Parity:** Ensures every `CTRL_*` key across all three regional profiles has a corresponding `GovernanceControl` enum member.

The **FrameworkRouter test matrix** (`test_framework_router.py`, ~40 tests) locks down the v2.0.0 Crown Jewel Decoupling:
1.  **JSON schema integrity** for all four OSCAL routing files (`NIST`, `ISO42001`, `EU_AI_ACT`, `MAS_FEAT`).
2.  **Cache identity** — `FrameworkRouter.get()` returns identical instance; no double-load on repeated calls.
3.  **Cache isolation** — loading NIST does not pollute the EU_AI_ACT cache entry.
4.  **UCA coverage** — UCA-1 through UCA-9 map ≥1 control per framework.
5.  **No orphaned control IDs** — every referenced control ID has a description entry.
6.  **Narrative rendering** — `format_narrative()` produces fully rendered prose with no stray `{placeholder}` tokens.
7.  **Deduplication** — `all_controls()` returns no duplicate control IDs (OSCAL idempotency guarantee).
8.  **Sentinel suppression** — `_NO_LEGAL_FORCE_MARKER` correctly routes US_FED → legacy citation, EU_ECB/APAC_MAS → `primary_framework` citation.

---

## 📚 Complete Compliance Reference Map

To help you navigate the full regulatory documentation suite:

*   **Executive Overview:** [docs/CAGE_ONE_PAGER.md](docs/project/CAGE_ONE_PAGER.md) — 1-page overview of the business case and architecture.
*   **Detailed Governance Architecture:** README_GOVERNANCE.md — Walkthrough of the 15-tier SymbolicGovernor and the decoupled abstraction layer.
*   **System Architecture Spec:** [ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md) — System-wide component structure, database schemas, and request-response pathways.
*   **Security Posture & Milestones:** [docs/SECURITY_STATUS.md](docs/security/SECURITY_STATUS.md) and [docs/POAM.md](docs/compliance/cross-region/POAM.md) — Precise POAM checklists and NIST RMF coverage tracking.
*   **STPA & Hazard Analysis:** [docs/STPA_ANALYSIS.md](docs/security/STPA_ANALYSIS.md) — Breakdown of UCAs 1-9 and the STPA-to-Policy compiler specification.
*   **Causal & CBF Design:** [docs/CAUSAL_AND_CBF_GOVERNANCE.md](docs/governance/CAUSAL_AND_CBF_GOVERNANCE.md) — DoWhy regression kernel placebo refuter and discrete-time CBF mathematics.
*   **Full Technical Report Series:** [docs/technical-report/README.md](docs/technical-report/README.md) — 10-document technical report series detailing individual domains.
