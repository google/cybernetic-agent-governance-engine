# 06 — Compliance & Regulatory Standards

> **v2.1.0 additions**: Three-region compliance matrix with separate Lula manifests per jurisdiction (EU_ECB, APAC_MAS, US_FED) and a pytest parametrize matrix covering all three. NIST AI 600-1 Compliance Gates phases 0–3 all implemented. AARM Profile Mapper (`src/compliance_bridge/aarm_mapper.py`) with 11-vector threat ledger. Evidence Chain Metadata Binding (`src/compliance_bridge/evidence_stream.py`). CBF External Reconciliation Worker (`src/compliance_bridge/reconciliation_worker.py`) — POAM-023 closed. Region-Aware K8s Templates (`deployment/k8s/*.yaml.tpl`). Langfuse Native OTLP (standalone OTel Collector deprecated 2026-05-31).


---

| Field              | Value      |
| ------------------ | ---------- |
| **Version**        | 2.2        |
| **Date**           | 2026-06-03 |
| **Classification** | INTERNAL   |
| **Document**       | CAGE-TR-06 |

---

## 1. Regulatory Framework Overview

The Cybernetic Governance Engine (CAGE) simultaneously targets federal cybersecurity, international standards, and regional financial AI rules. Using its dynamic regional profile system (`CAGE_DEPLOYMENT_REGION`), CAGE can shift its compliance posture seamlessly between the United States (`US_FED`), European Union (`EU_ECB`), and Singapore (`APAC_MAS`) jurisdictions.

### Summary of Targeted Frameworks

| Standard                      | Authority       | Scope in CAGE / Active Region Mappings |
| ----------------------------- | --------------- | -------------------------------------------- |
| **NIST SP 800-53 Rev 5**      | NIST            | HIGH baseline; primary US cyber framework *(US_FED)* |
| **NIST SP 800-37 Rev 2 (RMF)**| NIST            | 7-step authorization process *(US_FED)* |
| **FIPS 199**                  | NIST            | Security categorization *(US_FED)* |
| **FIPS 140-2/3**              | NIST            | Cryptographic standards *(All Regions)* |
| **ISO/IEC 42001:2023**        | ISO             | AI Management System *(All Regions)* |
| **OSCAL v1.0.4 / 1.1.2**     | NIST            | Machine-readable compliance artifacts *(All Regions)*. Artifact schema: OSCAL v1.0.4. Runtime assessment state semantics: aligned to NIST SP 800-53A §3.2 four-state model (OSCAL 1.1.2 — includes `ERROR` state alongside `satisfied`, `not-satisfied`, `not-applicable`). |
| **ISO-20022**                 | ISO             | Banking/payments standard *(All Regions)* |
| **FINRA Rule 4511**           | FINRA           | 7-year records retention *(US_FED)* |
| **SEC Rule 17a-4**            | SEC             | Electronic records *(US_FED)* |
| **SEC Reg S-P**               | SEC             | Privacy of consumer financial information *(US_FED)* |
| **GLBA**                      | Federal         | Financial privacy *(US_FED)* |
| **SR 11-7**                   | Federal Reserve | Model Risk Management (non-agentic components) *(US_FED)* |
| **SR 26-2**                   | Federal Reserve | Agentic AI Risk Management *(US_FED; suppressed in EU_ECB)* |
| **EU AI Act** (Reg. 2024/1689)| European Union  | High-Risk AI obligations, Art. 6, 9, 10, 12, 14, 17, 29a, 61, Annex III §5(b) *(EU_ECB)* |
| **DORA**                      | European Union  | Digital Operational Resilience Act, Art. 10, 11, 12 *(EU_ECB)* |
| **GDPR Article 22**           | European Union  | Automated individual decision-making constraints *(EU_ECB)* |
| **EBA Guidelines** (2023/02)  | EBA / ECB       | Internal governance for financial institutions *(EU_ECB)* |
| **MAS FEAT Principles**       | Singapore MAS   | Fairness, Ethics, Accountability, Transparency *(APAC_MAS)* |
| **CSA AARM v1.0**             | Cloud Security Alliance | Autonomous Agent Risk Management — 11 threat vectors *(All Regions)* |

No single compliance program covers all frameworks. CAGE's architecture is designed so that a single evidence artifact (e.g., an OpenTelemetry trace with HMAC seal and regional baseline stamps) simultaneously satisfies NIST AU controls, ISO 42001 A.5.3 documentation, and regional electronic record mandates.

---

## 2. FIPS 199 Security Categorization

**Source:** [`compliance/categorization/FIPS199_CATEGORIZATION.md`](../../compliance/categorization/FIPS199_CATEGORIZATION.md)

CAGE is categorized under FIPS 199 using the high-water mark rule across three security objectives per information type:

| Security Objective        | Categorization |
| ------------------------- | -------------- |
| Confidentiality           | Moderate       |
| Integrity                 | **High**       |
| Availability              | Moderate       |
| **Overall System Impact** | **HIGH**       |

The Integrity objective dominates and elevates the overall system impact to HIGH, which triggers the full NIST SP 800-53 Rev 5 HIGH baseline (approximately 350+ controls) as the applicable control set.

The Privacy Impact Assessment ([`compliance/pia/PRIVACY_IMPACT_ASSESSMENT.md`](../../compliance/pia/PRIVACY_IMPACT_ASSESSMENT.md)) applies a stricter categorization of C=High / I=High / A=High, reflecting the sensitivity of PII processed in LLM prompts and the reputational impact of data exposure in a financial AI context.

> **Finding FIND-007:** The FIPS 199 categorization document is currently unsigned by the Authorizing Official. Status: **In-Progress**. Tracked in POAM-009. This is a Critical finding blocking ATO.

---

## 3. NIST SP 800-53 Rev 5 Control Coverage

> **⚠️ US_FED ONLY — Regional Scoping Notice:** NIST SP 800-53 Rev 5 is a **US_FED deployment requirement only**. It does **not** apply to `EU_ECB` or `APAC_MAS` deployments. EU_ECB stable releases are gated on EU AI Act (Reg. 2024/1689) compliance. APAC_MAS stable releases are gated on MAS FEAT compliance. See §14 (Compliance Posture Summary) and §15.2 (Supported Jurisdictions) for the full regional breakdown.

> **NIST SP 800-53 gates apply to US_FED deployments only.** EU_ECB stable releases are gated on EU AI Act compliance. APAC_MAS stable releases are gated on MAS FEAT compliance.

**Sources:** [`docs/NIST_RMF_CHUNK1_CURRENT_STATE.md`](../compliance/us_fed/NIST_RMF_CHUNK1_CURRENT_STATE.md) through [`docs/NIST_RMF_CHUNK5_MONITOR_ROADMAP.md`](../compliance/us_fed/NIST_RMF_CHUNK5_MONITOR_ROADMAP.md)

### 3.1 Overall Readiness

**24% overall readiness** — 113 controls sampled across all applicable families; 24 fully implemented, 23 partially implemented, 66 gaps identified.

### 3.2 Control Family Coverage

| Control Family                       | Coverage | Key Implementations                                                                                                 |
| ------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------- |
| AC (Access Control)                  | 19%      | OPA Rego RBAC (`src/governed_financial_advisor/governance/policy/trade_governance.rego`); no MFA deployed                                                            |
| AU (Audit & Accountability)          | 54%      | OTel traces; Langfuse; 7-year retention pipeline                                                                    |
| CA (Security Assessment)             | 19%      | Lula 6h CronJob; SAR target 2026Q1                                                                                  |
| CM (Configuration Management)        | 32%      | `config/governance_thresholds.json`; Terraform IaC                                                                         |
| IA (Identification & Authentication) | 15%      | HMAC routing seals; no MFA; no account management procedures                                                        |
| IR (Incident Response)               | 28%      | `GovernanceEventBus`; IR-6 reporting implemented (see [`docs/POAM.md`](../POAM.md)); full IRP authorship is an adopter responsibility for real deployments |
| RA (Risk Assessment)                 | 15%      | [`compliance/rar/RISK_ASSESSMENT_REPORT.md`](../../compliance/rar/RISK_ASSESSMENT_REPORT.md); Lula automated checks |
| SC (System & Communications)         | 33%      | `NetworkPolicy` enforcement; **Linkerd mTLS (FIND-011 resolved)**              |
| SI (System & Information Integrity)  | 42%      | Presidio PII detection; NeMo guardrails; Aho-Corasick scanning                                                      |

The AU (Audit & Accountability) family is the strongest at 54%, driven by the mature OpenTelemetry and Langfuse observability stack. The IA (Identification & Authentication) family at 15% represents the most critical gap — absence of MFA and formal account management procedures directly imposes a HIGH risk finding.

---

## 4. NIST RMF 7-Step Readiness

**Sources:** [`docs/NIST_RMF_CHUNK2_PREPARE_CATEGORIZE.md`](../compliance/us_fed/NIST_RMF_CHUNK2_PREPARE_CATEGORIZE.md) through [`docs/NIST_RMF_CHUNK4_ASSESS_AUTHORIZE.md`](../compliance/us_fed/NIST_RMF_CHUNK4_ASSESS_AUTHORIZE.md)

### 4.1 Step-by-Step Scores

| RMF Step                 | Score  | Status      | Key Gaps                                          |
| ------------------------ | ------ | ----------- | ------------------------------------------------- |
| 1–2 Prepare / Categorize | 28/100 | In Progress | No SSP; FIPS 199 unsigned; system roles TBD       |
| 3–4 Select / Implement   | 29/100 | In Progress | No MFA; mock trace source                         |
| 5–6 Assess / Authorize   | 22/100 | Not Started | Authorization package 24% complete; no ATO letter |
| 7 Monitor                | 18/100 | In Progress | ISCM strategy document pending; no SIEM integration |

No ATO (Authorization to Operate) has been granted. The security assessor determined overall risk as HIGH and does not recommend full ATO at this time. An Interim ATO (IATO) may be possible if the remaining Critical finding (FIND-007) is remediated first.

### 4.2 ATO Progression Roadmap

**Source:** [`docs/NIST_RMF_CHUNK5_MONITOR_ROADMAP.md`](../compliance/us_fed/NIST_RMF_CHUNK5_MONITOR_ROADMAP.md)

The phased roadmap targets continuous ATO posture over a 52-week horizon:

```
Phase 0  Weeks  1– 2  →  +38%  Authorization foundation
                           SSP draft, FIPS 199 sign-off, system role assignment

Phase 1  Weeks  2– 6  →  +45%  Quick wins
                           MFA deployment, intra-cluster mTLS, SBOM automation

Phase 2  Weeks  6–16  →  +59%  Core hardening
                           Audit pipeline production, vuln scanning, IRP activation

Phase 3  Weeks 16–52  →  +77%  Architectural uplift
                           Federated identity, SIEM integration, continuous ATO
```

---

## 5. ISO/IEC 42001:2023 AI Management System Compliance

**Sources:** [`docs/ISO_42001_COMPLIANCE.md`](../compliance/universal/ISO_42001_COMPLIANCE.md), [`docs/SYSTEM_DESCRIPTION_ISO_42001.md`](../compliance/universal/SYSTEM_DESCRIPTION_ISO_42001.md)

### 5.1 Clause Mapping

| Clause                     | Title                    | CAGE Implementation                            |
| -------------------------- | ------------------------ | ---------------------------------------------- |
| 6 — Planning               | Risk-based AI planning   | `execution_analyst` risk-based plan generation |
| 8 — Operation              | Runtime AI controls      | `symbolic_governor` 7-tier symbolic governor pipeline (Tiers 0–6 + Tier 6b adaptive FRIA gate): STPA UCA validation → agentic confidence → CBF → SLM (deprecated) → OPA → consensus → causal gatekeeper → FRIA |
| 9 — Performance Evaluation | Monitoring & measurement | `EvaluatorAuditor` (`src/governed_financial_advisor/agents/evaluator/`) + Lula 6h CronJob |
| 10 — Improvement           | Continual improvement    | HITL interrupt + POAM tracking                 |

### 5.2 Annex A Control Mapping

| Annex A Control | Title                      | CAGE Implementation                           |
| --------------- | -------------------------- | --------------------------------------------- |
| A.5.2           | Social Impact Assessment   | NeMo `nemo_output_rail` guardrail             |
| A.5.3           | Documentation & Monitoring | OTel trace stamping; **SHA-256 hash-chained Context Accumulator** (`src/compliance_bridge/context_accumulator.py`) — AARM-V1 Memory Poisoning neutralization |
| A.8.4           | AI System Operation Controls | HITL + Saga WAL; **DEFER State Machine** (`src/gateway/governance/defer_queue.py`) — Confidence-Starvation Boundary 0.70, AARM-V7 Context Window Overflow neutralization |
| A.9.2           | Data Privacy & PII         | Presidio + NeMo (`nemo_input_scan`)           |
| SC-4            | Fiscal Controls / RBAC     | OPA Rego (`opa_policy_check`)                 |

### 5.3 Continuous Audit Evidence Loop

The system implements an automated evidence pipeline satisfying ISO 42001 Clause 9 continuous evaluation requirements:

```
Lula CronJob (6h)
  → OSCAL Assessment Results (YAML)
    → POST /v1/audit/ingest (Compliance Bridge)
      → run_audit_workflow (6-step pipeline, upgraded in CAGE v0.1.0)
        ├── Step 1:  Artifact persistence
        ├── Step 2:  OSCAL parse (OscalFinding extraction)
        │            OscalResult: PASS | FAIL | NOT_APPLICABLE | ERROR
        │            (see §5.5 for ERROR state semantics)
        ├── Step 2b: ContextAccumulator SHA-256 hash chain (AARM-V1)
        ├── Step 3:  Langfuse trace flush + compliance scores
        │            ERROR findings score 0.0 (same as FAIL — never masked as PASS)
        ├── Step 4:  SSE event publish (AUDIT_FINDING, CONTEXT_CHAIN_SEALED)
        │            GOVERNANCE_VIOLATION fired for FAIL **and** ERROR on CRITICAL_CONTROLS
        ├── Step 5:  Critical alert routing (Slack / PagerDuty)
        │            Triggered by result ∈ {FAIL, ERROR} on {A.9.2, SC-4, A.8.4}
        └── Step 6:  AARM Conformance Report (11-vector NEUTRALIZED/PARTIAL/EXPOSED)
               GCS/S3: context_chain.ndjson + aarm_conformance.json
```

This loop produces time-stamped OSCAL Assessment Result artifacts that serve as machine-readable evidence for both ISO 42001 and NIST SP 800-53 assessment records.

### 5.5 OSCAL Assessment State Semantics (NIST SP 800-53A §3.2)

> **Change introduced in CAGE v2.2.0 (2026-06-01).** Prior versions incorrectly mapped scanner failures to `NOT_APPLICABLE`. This section documents the corrected four-state model and its regulatory basis.

The [`OscalResult`](../../src/compliance_bridge/types.py) type in the Compliance Bridge defines four mutually exclusive assessment states, aligned with NIST SP 800-53A §3.2 assessment attribute vocabulary:

| State            | OSCAL `status.state` | Langfuse Score | Triggers Alert | Regulatory Meaning |
| ---------------- | -------------------- | -------------- | -------------- | ------------------- |
| `PASS`           | `satisfied`          | `1.0`          | No             | Assessment objective met — evidence satisfies the control requirement |
| `FAIL`           | `not-satisfied`      | `0.0`          | Yes (if critical) | Assessment objective not met — evidence explicitly fails the control |
| `NOT_APPLICABLE` | `not-applicable`     | _(no score)_   | No             | Control does not apply to this system component type (e.g. a wireless control on a wired-only system) |
| `ERROR`          | `error`              | `0.0`          | Yes (if critical) | Control applies but the scanner/collector failed to gather evidence ("fetch failed", timeout, unrecognised OSCAL state) |

#### Why ERROR ≠ NOT_APPLICABLE

The distinction is critical for audit integrity:

- **NOT_APPLICABLE** is a deliberate, documented scoping decision. It means the control was reviewed and determined to be out of scope for this specific system component. It must be justified in the SSP and approved by the Authorizing Official.
- **ERROR** is an operational failure. The control is in scope, but the evidence collection mechanism broke. The control may be violated — we simply cannot confirm it.

Masking an `ERROR` as `NOT_APPLICABLE` would:
1. Hide a potential security blind spot from auditors and the Authorizing Official
2. Prevent the critical-alert pipeline from firing on controls like SC-4 (Fiscal Limits) or A.9.2 (PII masking)
3. Violate NIST SP 800-53A §3.2, which requires evaluation errors to be flagged as **Incomplete/Unknown** — never as Not Applicable

#### Implementation Points

| Component | Behaviour |
| --------- | --------- |
| [`_map_state()`](../../src/compliance_bridge/oscal_parser.py) | Unrecognised OSCAL `status.state` values → `ERROR` (with warning log). Explicit `"not-applicable"` / `"na"` → `NOT_APPLICABLE`. |
| [`_finding_to_state()`](../../src/compliance_bridge/oscal_exporter.py) | `ERROR` findings emit OSCAL state `"error"`, not `"not-applicable"`. |
| [`findings_from_metrics_dict()`](../../src/compliance_bridge/oscal_exporter.py) | Langfuse fetch failures (`{"error": "..."}`) emit an `ERROR` `OscalFinding` with a descriptive `remarks` field. They are **not silently dropped**. |
| [`_step4_alert_on_critical_fail()`](../../src/compliance_bridge/audit_workflow.py) | Critical-control filter matches `result ∈ {FAIL, ERROR}`. A scanner failure on SC-4, A.9.2, or A.8.4 triggers the same Slack/PagerDuty alert as an explicit FAIL. |
| [`_ingest_sync()`](../../src/compliance_bridge/audit_workflow.py) | `ERROR` findings score `0.0` in Langfuse — identical to FAIL. They are never scored as `1.0` (PASS). |

### 5.4 Compliance Bridge API Endpoints (v0.1.0-rc.1)

CAGE v0.1.0 adds four new REST endpoints to the Compliance Bridge (`src/compliance_bridge/main.py`):

| Endpoint | Method | Description |
| -------- | ------ | ----------- |
| `/v1/aarm/conformance-report` | `GET` | Returns the AARM 11-vector conformance report card (JSON/YAML). Supports optional vLLM narrative enrichment (11 concurrent calls, `asyncio.Semaphore(3)` rate cap). |
| `/v1/defer/pending` | `GET` | Lists all currently parked DEFER queue tokens with their `DeferReason`, `confidence_score`, and TTL remaining. |
| `/v1/defer/{id}/inject` | `POST` | Resolves a deferred token via automated data injection — body carries supplementary context data. Token status transitions to `INJECTED`. |
| `/v1/defer/{id}/escalate` | `POST` | Manually escalates a deferred token to `MANUAL_REVIEW`. Token status transitions to `ESCALATED`. |

These complement the existing `POST /v1/audit/ingest` and `GET /v1/events/stream` (SSE) endpoints.

---

## 6. OSCAL Artifact Inventory

**Source:** [`compliance/oscal/`](../../compliance/oscal/)

CAGE maintains its compliance artifacts in OSCAL v1.0.4 format to enable machine-readable, interoperable security documentation. The current artifact inventory is:

| File                                                                                              | Type                                | Status                             |
| ------------------------------------------------------------------------------------------------- | ----------------------------------- | ---------------------------------- |
| [`compliance/oscal/component-definition.yaml`](../../compliance/oscal/component-definition.yaml)                   | Component Definition (OSCAL v1.0.4) | 3 components, 4 controls defined   |
| [`compliance/oscal/system-security-plan.yaml`](../../compliance/oscal/system-security-plan.yaml)                   | System Security Plan                | **Stub — Critical gap (POAM-015)** |
| [`compliance/oscal/sp800-53-component-definition.yaml`](../../compliance/oscal/sp800-53-component-definition.yaml) | SP 800-53 Component Definition      | Present                            |
| [`compliance/oscal/sp800053-profile.yaml`](../../compliance/oscal/sp800053-profile.yaml)                           | SP 800-53 Profile                   | Present                            |
| [`compliance/oscal/common-controls-catalog.yaml`](../../compliance/oscal/common-controls-catalog.yaml)             | Common Controls Catalog             | Present                            |
| [`compliance/oscal/information-type-registry.yaml`](../../compliance/oscal/information-type-registry.yaml)         | Information Type Registry           | Present                            |

> **SSP Gap (FIND-013 / POAM-015):** No complete System Security Plan exists. The [`compliance/oscal/system-security-plan.yaml`](../../compliance/oscal/system-security-plan.yaml) file is a stub with placeholder content. Severity: **HIGH**. Status: **Open**. A complete SSP is a prerequisite for ATO submission.

### OSCAL Artifact Persistence and KMS Batch Signing

OSCAL Assessment Result artifacts are persisted to GCS using the native `google-cloud-storage>=2.0.0` SDK (primary) with `boto3>=1.35.0` S3-compatible fallback. Each artifact batch is signed using **Cloud KMS HSM-backed asymmetric signing** before persistence, providing tamper-evident audit evidence:

- **Signing**: RSA-PKCS1-4096-SHA256 via `KMSSigner` — private key never leaves the HSM
- **Verification**: Sub-millisecond local RSA verification using embedded public key PEM
- **Audit trail**: Google Cloud Audit Logs provide an immutable record of every signing operation
- **Compliance**: Satisfies FINRA Rule 4511 tamper-evident records requirement and ISO 42001 §A.7.5 records integrity

### Automated Multi-Jurisdiction SSP Exporter
To accelerate compliance authoring across different jurisdictions, CAGE includes an automated compliance narrative compiler: [`src/gateway/governance/oscal_ssp_exporter.py`](../../src/gateway/governance/oscal_ssp_exporter.py). 

This tool dynamically compiles STPA hazards (UCAs) and control implementations into OSCAL System Security Plans. It provides a `--framework` CLI parameter to dynamically generate the control cross-walk narrative targeted at different international authorities:
- **EU AI Act:** `python -m src.gateway.governance.oscal_ssp_exporter export --framework EU_AI_ACT`
- **Singapore MAS FEAT:** `python -m src.gateway.governance.oscal_ssp_exporter export --framework MAS_FEAT`
- **ISO/IEC 42001:** `python -m src.gateway.governance.oscal_ssp_exporter export --framework ISO42001`
- **NIST SP 800-53 (Default):** `python -m src.gateway.governance.oscal_ssp_exporter export --framework NIST`

---

## 7. Lula Validation Manifests

### Three-Region Compliance Matrix (v2.1.0)

CAGE v2.1.0 ships separate Lula validation manifests for each of the three regulatory jurisdictions. The manifests are parametrized in CI via a pytest matrix that runs all three regions in parallel:

| Jurisdiction | Lula Manifest Directory | Threshold Config | OSCAL Framework |
|---|---|---|---|
| `US_FED` | `compliance/lula/us_fed/` | `config/thresholds/US_FED_BASELINE.json` | NIST SP 800-53 Rev 5 |
| `EU_ECB` | `compliance/lula/eu_ecb/` | `config/thresholds/EU_ECB_BASELINE.json` | EU AI Act + DORA |
| `APAC_MAS` | `compliance/lula/apac_mas/` | `config/thresholds/APAC_MAS_BASELINE.json` | MAS FEAT + TRM |

Each manifest set covers the same control families but with jurisdiction-specific thresholds, telemetry suppression rules (EU_ECB/APAC_MAS suppress SR 26-2 telemetry per the "no legal force" sentinel), and OSCAL framework routing.


**Source:** [`compliance/lula/`](../../compliance/lula/)

Lula automates OSCAL Assessment Result generation on a 6-hour CronJob schedule ([`deployment/k8s/lula-cron.yaml`](../../deployment/k8s/lula-cron.yaml)). RBAC permissions are defined in [`deployment/k8s/lula-rbac.yaml`](../../deployment/k8s/lula-rbac.yaml).

**15 manifests listed below (4 Active, 11 Stub)** — this table covers the original US_FED and universal controls. For the complete 21-manifest inventory including EU_ECB, APAC_MAS, and NIST AI 600-1 stubs, see [`compliance/lula/README.md`](../../compliance/lula/README.md).

| Manifest                                                                                         | Control         | Kubernetes Check                                                                 |
| ------------------------------------------------------------------------------------------------ | --------------- | -------------------------------------------------------------------------------- |
| [`compliance/lula/lula-validation-a52.yaml`](../../compliance/lula/lula-validation-a52.yaml)     | ISO 42001 A.5.2 | Social impact assessment ConfigMap                                               |
| [`compliance/lula/lula-validation-a53.yaml`](../../compliance/lula/lula-validation-a53.yaml)     | ISO 42001 A.5.3 | Documentation/logging config                                                     |
| [`compliance/lula/lula-validation-a92.yaml`](../../compliance/lula/lula-validation-a92.yaml)     | ISO 42001 A.9.2 | PII detection Deployment                                                         |
| [`compliance/lula/lula-validation-sc4.yaml`](../../compliance/lula/lula-validation-sc4.yaml)     | SP 800-53 SC-4  | Information in shared resources                                                  |
| [`compliance/lula/lula-validation-au12.yaml`](../../compliance/lula/lula-validation-au12.yaml)   | SP 800-53 AU-12 | Langfuse OTLP ingestion availability (direct; OTel Collector deprecated 2026-05-31) |
| [`compliance/lula/lula-validation-ac2.yaml`](../../compliance/lula/lula-validation-ac2.yaml)     | SP 800-53 AC-2  | Account management / service account lifecycle                                   |
| [`compliance/lula/lula-validation-ac3.yaml`](../../compliance/lula/lula-validation-ac3.yaml)     | SP 800-53 AC-3  | Access enforcement / OPA RBAC                                                    |
| [`compliance/lula/lula-validation-ra5.yaml`](../../compliance/lula/lula-validation-ra5.yaml)     | SP 800-53 RA-5  | Vulnerability scanning (pip-audit / Trivy CI)                                    |
| [`compliance/lula/lula-validation-cm6.yaml`](../../compliance/lula/lula-validation-cm6.yaml)     | SP 800-53 CM-6  | Configuration settings enforcement                                               |
| [`compliance/lula/lula-validation-ir6.yaml`](../../compliance/lula/lula-validation-ir6.yaml)     | SP 800-53 IR-6  | Incident reporting                                                               |
| [`compliance/lula/lula-validation-ia3.yaml`](../../compliance/lula/lula-validation-ia3.yaml)     | SP 800-53 IA-3  | Device identification / Linkerd mTLS SPIFFE identity                             |
| [`compliance/lula/lula-validation-ia5.yaml`](../../compliance/lula/lula-validation-ia5.yaml)     | SP 800-53 IA-5  | Authenticator management / KMS HSM key lifecycle                                 |
| [`compliance/lula/lula-validation-sc8.yaml`](../../compliance/lula/lula-validation-sc8.yaml)     | SP 800-53 SC-8  | Transmission confidentiality / TLS enforcement                                   |
| [`compliance/lula/lula-validation-si2.yaml`](../../compliance/lula/lula-validation-si2.yaml)     | SP 800-53 SI-2  | Flaw remediation / CVE patching (pip-audit CI)                                   |
| [`compliance/lula/lula-validation-aarm-vectors.yaml`](../../compliance/lula/lula-validation-aarm-vectors.yaml) | CSA AARM v1.0 | 11-vector AI agent threat model coverage                              |

---

## 8. Information System Continuous Monitoring (ISCM) Strategy

**Source:** [`compliance/continuous-monitoring/ISCM_STRATEGY.md`](../../compliance/continuous-monitoring/ISCM_STRATEGY.md)

### 8.1 Two-Tier Monitoring Architecture

CAGE implements a two-tier ISCM strategy balancing compliance cycle frequency with real-time operational visibility:

**Tier 1 — Compliance Cycle (6-hour frequency):**

- Lula CronJob generates OSCAL Assessment Results
- Compliance Bridge ingests results via `POST /v1/audit/ingest`
- `run_audit_workflow` scores compliance posture
- Langfuse records compliance scores as evaluation traces
- SSE alerts surface open findings to operators

**Tier 2 — Operational Real-Time (60-second frequency):**

- SC-4 OPA policy watch with continuous enforcement
- Continuous OTel span streaming from all agent nodes
- AgentSight eBPF DaemonSet capturing kernel-level agent activity

### 8.2 Evidence Age Tracking

The `ComplianceMetrics` model in [`src/compliance_bridge/types.py`](../../src/compliance_bridge/types.py) includes an `evidence_age_seconds` field that tracks the staleness of each compliance assertion. A 6-hour startup grace period is enforced before the system raises evidence-age alerts, allowing the first Lula cycle to complete after deployment.

---

## 9. Privacy Impact Assessment

**Source:** [`compliance/pia/PRIVACY_IMPACT_ASSESSMENT.md`](../../compliance/pia/PRIVACY_IMPACT_ASSESSMENT.md)

The PIA identified eight privacy risks (PR-1 through PR-8) associated with LLM-based financial AI processing:

| Risk ID | Risk                      | Residual Risk | Control                             |
| ------- | ------------------------- | ------------- | ----------------------------------- |
| PR-1    | PII in LLM prompts        | MODERATE      | NeMo input scan; Presidio masking   |
| PR-2    | Audit log over-retention  | LOW           | 90-day raw AI logs; 7-year redacted |
| PR-3    | Unauthorized data access  | LOW           | OPA RBAC; NetworkPolicy             |
| PR-4    | Market data linkage       | LOW           | Pseudonymization                    |
| PR-5    | Third-party data exposure | LOW           | `yfinance` read-only; ISA agreement |
| PR-6    | Intra-cluster plaintext   | LOW           | **FIND-011 resolved**; Linkerd mTLS deployed |
| PR-7    | Session token exposure    | LOW           | ≤8-hour token lifetime              |
| PR-8    | Residual data in models   | LOW           | vLLM stateless inference            |

PR-1 remains at MODERATE residual risk pending MFA deployment. PR-6 has been reduced to LOW following Linkerd mTLS deployment (POAM-007 closed 2026-05-17).

### 9.1 Data Retention Schedule

| Data Category                  | Retention Period      | Regulatory Driver                 |
| ------------------------------ | --------------------- | --------------------------------- |
| Audit logs                     | 7 years               | FINRA Rule 4511; SEC Rule 17a-4   |
| AI interaction logs (raw)      | 90 days               | Operational; privacy minimization |
| AI interaction logs (redacted) | 7 years               | FINRA Rule 4511                   |
| Session tokens                 | ≤ 8 hours             | SEC Reg S-P; GLBA                 |
| PII in prompts                 | 24-hour session limit | GLBA; SEC Reg S-P                 |

---

## 10. Security Assessment Report (SAR-CAGE-2026Q1)

**Source:** [`compliance/sar/SAR_2026Q1.md`](../../compliance/sar/SAR_2026Q1.md)

**Overall Risk Determination: HIGH**

The security assessor does NOT recommend ATO at this time. An Interim ATO (IATO) is possible only if the remaining Critical finding (FIND-007) is resolved prior to submission. The finding register is:

| Finding ID | Description                          | Severity | Status       | POAM            |
| ---------- | ------------------------------------ | -------- | ------------ | --------------- |
| FIND-010   | HMAC routing seal bypass             | Critical | **RESOLVED** | POAM-012 Closed |
| FIND-011   | No intra-cluster mTLS                | Critical | **RESOLVED** | POAM-007 Closed |
| FIND-007   | FIPS 199 categorization unsigned     | Critical | In-Progress  | POAM-009        |
| FIND-001   | No account management procedures     | High     | Open         | —               |
| FIND-003   | Mock audit traces in production path | High     | Open         | POAM-003        |
| FIND-006   | No Incident Response Plan (IRP)      | High     | Open         | —               |
| FIND-008   | No vulnerability scanning            | High     | **RESOLVED** | POAM-010 Closed |
| FIND-013   | No complete System Security Plan     | High     | Open         | POAM-015        |
| FIND-014   | No ATO authorization letter          | High     | Open         | POAM-005        |

FIND-010 and FIND-011 are resolved Critical findings: HMAC seal integrity was hardened (FIND-010), and intra-cluster mTLS was deployed via Linkerd with Cilium L7 egress lockdown (FIND-011). FIND-008 (vulnerability scanning) is resolved via the `security-scan.yml` CI pipeline implementing pip-audit, Trivy, Grype, and CycloneDX SBOM generation.

### CVE-2025-69872 Remediation (`outlines` Package Removal)

The `outlines` Python package was removed from all CAGE images following the discovery of **CVE-2025-69872** (critical severity). Structured output enforcement is now handled natively by vLLM's FSM (Finite State Machine) guided decoding, which provides equivalent `ExecutionPlan` schema compliance without the vulnerable dependency.

| Attribute | Value |
| --------- | ----- |
| **CVE** | CVE-2025-69872 |
| **Severity** | Critical |
| **Affected Package** | `outlines` |
| **Remediation** | Package removed; vLLM FSM guided decoding used instead |
| **NIST Control** | SI-2 (Flaw Remediation) |
| **Lula Validation** | `compliance/lula/lula-validation-si2.yaml` — flaw remediation CronJob |
| **Status** | **RESOLVED** |

---

## 11. Risk Assessment

**Source:** [`compliance/rar/RISK_ASSESSMENT_REPORT.md`](../../compliance/rar/RISK_ASSESSMENT_REPORT.md)

CAGE's current overall risk posture is assessed as **HIGH** based on four compounding risk drivers:

1. **Missing Authentication Controls:** No multi-factor authentication is deployed. Operator accounts rely on single-factor credentials. No formal account management procedures exist (FIND-001). This directly fails SP 800-53 IA-2, IA-4, and IA-12.

2. ~~**No Intra-Cluster Transport Encryption:**~~ **RESOLVED.** Linkerd mTLS proxy injection is active in the `governance-stack` namespace, encrypting all service-to-service traffic. POAM-007 closed 2026-05-17.

3. **Incomplete Authorization Package:** The authorization package stands at 24% completion. Without a complete SSP, POA&M, and signed FIPS 199, the Authorizing Official cannot make an informed risk-based authorization decision.

4. ~~**eBPF Monitoring Console-Only:**~~ **RESOLVED.** The AgentSight eBPF DaemonSet exporter has been updated to `"remote"` mode, exporting to `http://agentsight-dashboard:8080` for centralized collection.

---

## 12. Governance Threshold Traceability

**Source:** [`compliance/risk_acceptance/THRESHOLD_TRACEABILITY_MATRIX.md`](../../compliance/risk_acceptance/THRESHOLD_TRACEABILITY_MATRIX.md)

All 22 governance thresholds defined in [`config/governance_thresholds.json`](../../config/governance_thresholds.json) are formally traced to specific regulatory controls in the Threshold Traceability Matrix. Four thresholds carry formal documented risk acceptances:

| ID     | Accepted Risk                         | Rationale                                                             | Regulatory Linkage |
| ------ | ------------------------------------- | --------------------------------------------------------------------- | ------------------ |
| RA-001 | 1% OTel sampling rate                 | Compensated by 100% governance event logging                          | AU-12              |
| RA-002 | $10k single-agent consensus threshold | Amounts below threshold acceptable without multi-agent consensus      | SR 26-2 §IV.B Agentic MRM |
| RA-003 | Daily SBOM generation vs. per-build   | `deployment/k8s/sbom-cronjob.yaml` daily automation accepted as compensating control | CM-3, SA-12        |
| RA-004 | Single OPA node + circuit breaker     | 5-failure circuit breaker enforces DENY-on-open posture               | SC-4, AC-3         |

Each risk acceptance was reviewed and signed by the system owner and is referenced directly in the OSCAL Component Definition.

---

## 13. Software Bill of Materials (SBOM)

**Sources:** [`compliance/sbom/README.md`](../../compliance/sbom/README.md); [`scripts/generate_sbom.py`](../../scripts/generate_sbom.py)

CAGE produces a Software Bill of Materials to satisfy supply chain risk management requirements under SP 800-53 SA-12 and SR 26-2 model inventory obligations.

| Attribute         | Value                                                                                 |
| ----------------- | ------------------------------------------------------------------------------------- |
| Generation script | [`scripts/generate_sbom.py`](../../scripts/generate_sbom.py)                          |
| Automation        | `deployment/k8s/sbom-cronjob.yaml` — daily scheduled generation                                      |
| Format            | SPDX / CycloneDX (see [`compliance/sbom/README.md`](../../compliance/sbom/README.md)) |
| Risk acceptance   | RA-003 — daily generation accepted vs. per-build (documented)                         |

The daily generation cadence was accepted under RA-003 as a compensating control. Per-build SBOM generation remains the target state and is tracked in the POAM roadmap as a Phase 1 quick-win item.

---

## 14. Compliance Posture Summary

The table below consolidates the current compliance posture across all targeted frameworks:

| Framework                   | Posture                               | Active Region(s) | Blocking Gap                                |
| --------------------------- | ------------------------------------- | ---------------- | ------------------------------------------- |
| NIST SP 800-53 Rev 5 (HIGH) | 24% implemented                       | `US_FED`         | No MFA, no SSP                              |
| NIST RMF (Steps 1–7)        | 28–22/100 per step                    | `US_FED`         | No ATO; authorization package incomplete    |
| FIPS 199                    | Categorized; unsigned                 | `US_FED`         | FIND-007 / POAM-009                         |
| FIPS 140-2/3                | HMAC-SHA256 implemented               | All Regions      | FIPS-validated module validation pending    |
| ISO/IEC 42001:2023          | Clauses 6, 8, 9, 10 mapped            | All Regions      | Evidence artifacts incomplete for Clause 9  |
| OSCAL v1.0.4                | Artifacts present; SSP stub           | All Regions      | FIND-013 / POAM-015                         |
| FINRA Rule 4511             | 7-year retention pipeline implemented | `US_FED`         | Audit log production pipeline not validated |
| SEC Rule 17a-4              | Electronic records design complete    | `US_FED`         | WORM storage not yet enforced               |
| SEC Reg S-P                 | PII controls implemented              | `US_FED`         | PR-1, PR-6 at MODERATE residual             |
| GLBA                        | Privacy controls partial              | `US_FED`         | ~~mTLS gap (PR-6)~~ **Resolved**             |
| SR 26-2                     | Agentic model risk — 4 gaps closed    | `US_FED`         | All four gaps closed                        |
| EU AI Act (Reg. 2024/1689)  | High-Risk AI controls mapped (6 CTRLs)| `EU_ECB`         | FRIA attestation logging only; no EU AI Office registration |
| DORA (Reg. 2022/2554)       | ICT resilience controls mapped        | `EU_ECB`         | Full DORA compliance testing pending        |
| GDPR Article 22             | Automated decision-making constraints | `EU_ECB`         | DPIA integration pending                    |
| EBA Guidelines (2023/02)    | Internal model governance mapped      | `EU_ECB`         | ECB SSM TRIM validation pending             |
| MAS FEAT Principles         | FEAT controls mapped (5 CTRLs)        | `APAC_MAS`       | Fairness Impact Assessment quantitative metrics pending |
| MAS TRM Guidelines          | TRM §6.3/6.4 AI controls mapped      | `APAC_MAS`       | MAS Notice 655 audit certification pending  |
| ISO-20022                   | Transaction message format; 200 ms latency is an operational infrastructure requirement of real-time interbank rails (FedNow / SEPA Instant), not an ISO-20022 mandate | All Regions      | SLA validation testing not complete         |
| CSA AARM v1.0               | 11 threat vectors assessed            | All Regions      | 4 vectors at PARTIAL status                 |

---

## 14b. AARM Profile Mapper and Evidence Chain (v2.1.0)

### AARM Profile Mapper (`src/compliance_bridge/aarm_mapper.py`)

The AARM Profile Mapper translates CAGE governance decisions into the 11-vector AARM (AI Assurance and Risk Management) threat ledger format. Each vector maps to a specific CAGE control:

| AARM Vector | CAGE Control | Implementation |
|---|---|---|
| V1 — Context Accumulation | AARM-V1 context accumulator | `src/governed_financial_advisor/graph/nodes/` |
| V2 — Confabulation Risk | Confabulation scorer | `src/gateway/governance/confabulation_scorer.py` |
| V3 — Prompt Injection | Prompt injection detector | `src/gateway/governance/prompt_injection_detector.py` |
| V4 — PII Leakage | PII sanitizer | `src/gateway/governance/pii_sanitizer.py` |
| V5 — CBRN Exposure | NeMo CBRN rail | `src/gateway/governance/nemo/colang/cbrn_rails.co` |
| V6 — Fiscal Limit Breach | FiscalLimitGuard + CBF | `src/gateway/governance/fiscal_limit_guard.py` |
| V7 — Confidence Starvation | DEFER state machine | `src/gateway/governance/defer_queue.py` |
| V8 — Causal Boundary Violation | DoWhy causal gatekeeper | `src/gateway/governance/causal_gatekeeper.py` |
| V9 — Consensus Failure | ConsensusModelRegistry | `src/gateway/governance/consensus.py` |
| V10 — HITL SLA Breach | HITL escalator + DeferQueue TTL | `src/gateway/governance/hitl_escalator.py` |
| V11 — Provenance Chain Break | Provenance chain | `src/gateway/governance/provenance_chain.py` |

The AARM report generator (`src/compliance_bridge/aarm_report_generator.py`) produces AARM-format compliance reports from the 11-vector ledger for submission to regulatory reviewers.

### Evidence Chain Metadata Binding (`src/compliance_bridge/evidence_stream.py`)

The evidence stream module binds governance decision metadata to OSCAL evidence artifacts at the point of creation. Each evidence record includes:

- `thread_id` — LangGraph thread identifier (links evidence to the originating inference trace)
- `control_id` — NIST SP 800-53 / ISO 42001 control identifier
- `decision` — `PASS` | `FAIL` | `NOT_APPLICABLE` | `ERROR`
- `governance_signature` — KMS-signed (production) or HMAC-SHA256 (dev/CI)
- `deployment_region` — `US_FED` | `EU_ECB` | `APAC_MAS`
- `langfuse_trace_id` — OTLP trace ID for cross-referencing in Langfuse

Evidence records are streamed to the OSCAL exporter (`src/compliance_bridge/oscal_exporter.py`) and archived to the GCS WORM bucket for 7-year retention.

---

## 15. Multi-Jurisdiction Compliance Engine

CAGE v0.1.0 introduced a **multi-jurisdiction compliance engine** that allows the system to seamlessly shift its entire regulatory compliance posture between United States, European Union, and Singapore regulatory environments without any code changes. This section documents the architecture, configuration, and operational behavior of the multi-jurisdiction system.

### 15.1 Activation Mechanism

The active jurisdiction is determined by a single environment variable:

```
CAGE_DEPLOYMENT_REGION=US_FED | EU_ECB | APAC_MAS
```

Setting this variable at boot time triggers cascading configuration changes across three independent subsystems:

| Subsystem | Configuration Source | Effect |
| --------- | -------------------- | ------ |
| **Compliance Control Profiles** | [`config/compliance/{REGION}_BASELINE.json`](../../config/compliance/) | Activates region-specific regulatory control mappings (primary framework, co-frameworks, legacy citations) for all 5–6 CAGE governance controls |
| **Governance Thresholds** | [`config/thresholds/{REGION}_BASELINE.json`](../../config/thresholds/) | Loads region-calibrated numeric thresholds (confidence, drawdown, consensus, latency, portfolio limits, FRIA parameters) |
| **OSCAL Framework Routing** | [`config/oscal/framework_mappings/*.json`](../../config/oscal/framework_mappings/) | Routes UCA-to-control cross-walk narratives to the correct international standard for SSP generation |

### 15.2 Supported Jurisdictions

#### United States (`US_FED`)

| Attribute | Value |
| --------- | ----- |
| **Primary Prudential Authority** | Federal Reserve / OCC / FDIC (Joint Agency) |
| **Primary AI Framework** | SR 26-2 (Model Risk Management for Agentic AI) |
| **Legacy MRM Framework** | SR 11-7 (superseded by SR 26-2 for agentic components) |
| **Cyber Baseline** | NIST SP 800-53 Rev 5 HIGH |
| **Financial Privacy** | SEC Reg S-P, GLBA, FINRA Rule 4511 |
| **Compliance Profile** | [`config/compliance/US_FED_BASELINE.json`](../../config/compliance/US_FED_BASELINE.json) (5 controls) |
| **Threshold Profile** | [`config/thresholds/US_FED_BASELINE.json`](../../config/thresholds/US_FED_BASELINE.json) |
| **Key Differentiator** | SR 26-2 Footnote 3 novelty exclusion — agentic AI is explicitly excluded from traditional MRM scope; governed under ISO 42001 |

#### European Union (`EU_ECB`)

| Attribute | Value |
| --------- | ----- |
| **Primary Prudential Authority** | European Central Bank (SSM) / EBA / EU AI Office |
| **Primary AI Framework** | EU AI Act (Regulation (EU) 2024/1689) — High-Risk AI System per Art. 6 + Annex III §5(b) |
| **Additional Frameworks** | DORA (Arts. 5, 10, 11, 12), GDPR (Arts. 5, 22, 35), EBA/GL/2023/02, BCBS 239 |
| **Compliance Profile** | [`config/compliance/EU_ECB_BASELINE.json`](../../config/compliance/EU_ECB_BASELINE.json) (6 controls — includes `CTRL_FRIA_006`) |
| **Threshold Profile** | [`config/thresholds/EU_ECB_BASELINE.json`](../../config/thresholds/EU_ECB_BASELINE.json) |
| **Key Differentiators** | (1) Mandatory Step 8 Fundamental Rights Impact Assessment (Art. 29a); (2) SR 26-2 telemetry suppression; (3) Stricter thresholds across all governance tiers; (4) Additional Tier 1 keywords (`GDPR OVERRIDE`, `IGNORE FAIRNESS CHECKS`, `BYPASS FRIA`) |

#### Singapore / APAC (`APAC_MAS`)

| Attribute | Value |
| --------- | ----- |
| **Primary Prudential Authority** | Monetary Authority of Singapore (MAS) |
| **Primary AI Framework** | MAS FEAT Principles (Fairness, Ethics, Accountability, Transparency) |
| **Additional Frameworks** | MAS Notice 655, MAS TRM Guidelines (§6.3, §6.4), MAS ENRM Guidelines |
| **Compliance Profile** | [`config/compliance/APAC_MAS_BASELINE.json`](../../config/compliance/APAC_MAS_BASELINE.json) (5 controls) |
| **Threshold Profile** | [`config/thresholds/APAC_MAS_BASELINE.json`](../../config/thresholds/APAC_MAS_BASELINE.json) |
| **Key Differentiator** | MAS FEAT Fairness Principle F2 requires quantitative fairness metrics (demographic parity, equalized odds) — mapped to DoWhy causal gatekeeper validation |

### 15.3 Region-Specific Threshold Calibration

Governance thresholds are calibrated independently per jurisdiction to reflect local regulatory expectations. Key threshold differences:

| Threshold | `US_FED` | `EU_ECB` | `APAC_MAS` | Regulatory Rationale |
| --------- | -------- | -------- | ---------- | -------------------- |
| Min. Agentic Confidence | 0.95 | **0.97** | 0.95 | EU AI Act Art. 9 mandates stricter risk management for High-Risk AI |
| Drawdown Limit | 5% | **4%** | 5% | EBA stress-test adverse scenario (EBA/GL/2018/02) |
| UCA-5 Drawdown Threshold | 4.5% | **3.5%** | 4.5% | 1% more conservative cushion for EBA Pillar 2 Requirement triggers |
| Max Order Volume Fraction | 1% | **0.5%** | 1% | MiFID II market integrity / MAR Art. 12 slippage controls |
| Max Portfolio Sell Fraction | 10% | **8%** | 10% | ESMA MiFID II best execution requirements |
| Max Latency (ms) | 200 | **150** | 200 | DORA Art. 10 operational resilience — ECB SSM lower tolerance |
| Consensus Threshold (USD) | $10,000 | **$7,500** | $5,000 | GDPR Art. 22 automated decision-making; MAS FEAT A1 human oversight |
| CBF Gamma (decay) | 0.5 | **0.6** | 0.5 | CRD VI / EBA SREP capital buffer maintenance |
| FRIA Enabled | No | **Yes** | No | EU AI Act Art. 29a — no US/SG equivalent |

### 15.4 ControlRegistry Architecture

The **`ControlRegistry`** class ([`src/gateway/governance/constants.py`](../../src/gateway/governance/constants.py)) is the runtime component that loads and serves regional compliance profiles:

- **Dynamic Loading:** At startup, reads `CAGE_DEPLOYMENT_REGION` and loads the corresponding `config/compliance/{REGION}_BASELINE.json`
- **Thread-Safe Access:** Provides `get_mapping(control_id)` and `get_mapping_safe(control_id)` methods for safe access to region-specific control metadata
- **Graceful Degradation:** `get_mapping_safe()` returns `None` for controls that don't exist in the active region (e.g., `CTRL_FRIA_006` is only present in `EU_ECB`), preventing `KeyError` exceptions in non-EU deployments
- **Active Region Attribute:** Exposes `active_region` for span tagging and audit attribution

### 15.5 SR 26-2 Telemetry Suppression

When CAGE operates under the `EU_ECB` profile, US-specific regulatory citations must not appear in audit telemetry. This is implemented via a **data-driven sentinel mechanism** in the Causal Gatekeeper ([`src/gateway/governance/causal_gatekeeper.py`](../../src/gateway/governance/causal_gatekeeper.py)):

1. Each regional profile's `CTRL_MRM_004` entry includes a `legacy_citation` field
2. The EU profile encodes: `"SR 26-2 §IV (US Federal Reserve — no legal force in EU jurisdiction)"`
3. At runtime, the gatekeeper checks for the `"no legal force"` sentinel marker
4. When detected, it emits `primary_framework` (the jurisdiction-correct citation, e.g., `EBA/GL/2023/02`) on OTel spans instead of the US-specific SR 26-2 string
5. The APAC profile similarly flags its SR 26-2 legacy citation as having no legal force in Singapore

This mechanism is fully data-driven — adding a new region that suppresses SR 26-2 requires only a JSON profile update with the sentinel marker. No Python changes are needed.

### 15.6 EU-Specific: Fundamental Rights Impact Assessment (Step 8)

The `EU_ECB` profile activates an additional governance step — **Step 8: FRIA Attestation** — that executes after the 7 fail-closed governance tiers (0–6). This step:

- Is triggered only when `CAGE_DEPLOYMENT_REGION=EU_ECB`
- Reads `CTRL_FRIA_006` from the EU compliance profile (Art. 29a attestation)
- Stamps FRIA compliance attestation as OpenTelemetry span attributes
- Records protected characteristics assessment (gender, race, ethnicity, age, disability, nationality, religion)
- Enforces demographic parity and equalized odds thresholds (5% tolerance per EBA/GL/2020/06)
- Is **non-blocking** (attestation stamp, not a fail-closed gate) — this is why it is designated "Step 8" rather than "Tier 7"
- Requires periodic reassessment (365-day interval per Art. 29a)

### 15.7 OSCAL Framework Router

> **Implementation Status:** The Multi-jurisdiction SSP Router described in this section has been **fully implemented** in [`src/gateway/governance/oscal_ssp_exporter.py`](../../src/gateway/governance/oscal_ssp_exporter.py) (previously described as "designed but not implemented"). The `FrameworkRouter` class and its CLI export interface are production-ready as of CAGE v2.2.0.

The **`FrameworkRouter`** class ([`src/gateway/governance/oscal_ssp_exporter.py`](../../src/gateway/governance/oscal_ssp_exporter.py)) enables automated SSP generation targeted at different international authorities. It loads external JSON routing tables from `config/oscal/framework_mappings/` and maps STPA Unsafe Control Actions (UCAs) to jurisdiction-specific control identifiers:

| Framework ID | JSON Routing Table | Target Authority |
| ------------ | ------------------ | ---------------- |
| `NIST` | [`NIST_SP800_53.json`](../../config/oscal/framework_mappings/NIST_SP800_53.json) | NIST / FedRAMP (US) |
| `ISO42001` | [`ISO_42001.json`](../../config/oscal/framework_mappings/ISO_42001.json) | ISO (Global) |
| `EU_AI_ACT` | [`EU_AI_ACT.json`](../../config/oscal/framework_mappings/EU_AI_ACT.json) | EU AI Office / EBA |
| `MAS_FEAT` | [`MAS_FEAT.json`](../../config/oscal/framework_mappings/MAS_FEAT.json) | MAS (Singapore) |

Usage:
```bash
# Generate EU AI Act SSP narrative
python -m src.gateway.governance.oscal_ssp_exporter export --framework EU_AI_ACT

# Generate MAS FEAT SSP narrative
python -m src.gateway.governance.oscal_ssp_exporter export --framework MAS_FEAT
```

Adding a new jurisdiction requires only a new JSON file in the mappings directory and a one-line entry in `_FRAMEWORK_FILE_MAP` — zero changes to the SSP generation logic.

### 15.8 Extensibility: Adding a New Jurisdiction

To add a new regulatory jurisdiction (e.g., `UK_FCA` for the UK Financial Conduct Authority), the following config-only steps are required:

| Step | File to Create/Modify | Purpose |
| ---- | --------------------- | ------- |
| 1 | `config/compliance/{REGION}_BASELINE.json` | Define 5–6 control mappings with primary_framework, co_frameworks, legacy_citation, scope |
| 2 | `config/thresholds/{REGION}_BASELINE.json` | Calibrate numeric governance thresholds to local regulatory expectations |
| 3 | `config/oscal/framework_mappings/{FRAMEWORK}.json` | Create UCA-to-control routing table for OSCAL SSP generation |
| 4 | `_FRAMEWORK_FILE_MAP` in `oscal_ssp_exporter.py` | Register the new framework ID (one line) |

**No Python code changes are required** for steps 1–3. The `ControlRegistry`, `SymbolicGovernor`, `CausalGatekeeper`, and `FrameworkRouter` all dynamically load regional configuration from these JSON files at runtime.

---

## 16. Mathematical Safety Controls

This section formalises the mathematical safety invariants that underpin CAGE's compliance posture. All constants are sourced from [`config/governance_thresholds.json`](../../config/governance_thresholds.json) and the named constants in the respective source modules.

### 16.1 Control Barrier Function (CBF) — ISO 42001 A.8.4

**Source:** [`src/gateway/governance/cbf.py`](../../src/gateway/governance/cbf.py)

The Control Barrier Function enforces the core financial safety invariant using control theory formalism. The safe set `S` and barrier function `h` are defined as:

```
Safe set:        S = {x ∈ ℝⁿ : h(x) ≥ 0}
Barrier function: h(x) = cash_balance − min_cash_balance
```

The discrete-time CBF condition that must hold at every governance step is:

```
h(S(t+1)) ≥ (1−γ) · h(S(t))     where γ ∈ (0,1)
```

| Parameter | Value | Source |
| --------- | ----- | ------ |
| `min_cash_balance` | `1000.0` | `cbf.min_cash_balance` in `governance_thresholds.json` |
| `γ` (decay rate) | `0.5` (US_FED/APAC_MAS), `0.6` (EU_ECB) | `cbf.gamma` — region-calibrated |

The CBF is enforced atomically via Redis `WATCH/MULTI/EXEC` (5 retries on contention). A violation of `h(x) ≥ 0` raises `GovernanceError` immediately (fail-closed). The CBF is re-evaluated at execution time by `post_hitl_revalidate_node` using the fresh live price to prevent TOCTOU exploits.

**ISO 42001 mapping:** A.8.4 (AI System Operation Controls — runtime safety invariant enforcement).

### 16.2 FRIA Zone Thresholds

The Adaptive FRIA Gate (Tier 6b) maps model confidence to three decision zones. These constants are defined in [`src/gateway/governance/symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py):

| Constant | Value | Zone | Compliance Mapping |
| -------- | ----- | ---- | ------------------ |
| `FRIA_ZONE_ALLOW` | `0.95` | `confidence ≥ 0.95` → autonomous clearance | ISO 42001 A.8.4; EU AI Act Art. 29a (EU_ECB) |
| `FRIA_ZONE_DEFER` | `0.70` | `0.70 ≤ confidence < 0.95` → synchronous FRIA gate | CSA AARM V7; ISO 42001 A.8.4 |
| *(implicit deny)* | `< 0.70` | `confidence < 0.70` → Confidence-Starvation Boundary | ISO 42001 A.8.4; CSA AARM V7 |

### 16.3 Fiscal Limit Guard — ISO 42001 A.8.4 / SC-4

**Source:** [`src/gateway/governance/fiscal_limit_guard.py`](../../src/gateway/governance/fiscal_limit_guard.py)

The `FiscalLimitGuard` enforces a hard daily spending cap to prevent race conditions where parallel agent threads collectively exceed the authorized limit:

| Parameter | Value | Notes |
| --------- | ----- | ----- |
| Daily cap | **$500,000 USD** | Configurable via `FISCAL_DAILY_CAP_USD` env var |
| Cap storage | Integer cents | Prevents floating-point precision errors |
| Window | **86,400 seconds** | Rolling 24-hour window |
| Retry strategy | Exponential backoff: `_RETRY_BASE_MS × 2^attempt` | Redis `WATCH/MULTI/EXEC` contention handling |
| Reservation TTL | 300 seconds | Reclaims limits from crashed nodes automatically |

Headroom is pre-reserved in Redis *after* concurrent CBF+OPA validation (closing the TOCTOU race). Unused limits are returned via `release(token)` on Saga rollback. If Redis is unavailable, the trade is blocked (fail-closed).

**ISO 42001 mapping:** A.8.4 (AI System Operation Controls); **[US_FED only]** NIST SP 800-53 SC-4 (Information in Shared Resources).

### 16.4 HMAC-SHA256 Routing Seal

**Source:** [`src/gateway/governance/routing_seal.py`](../../src/gateway/governance/routing_seal.py)

Every approved governance decision is sealed with an HMAC-SHA256 routing seal before execution is permitted. The seal format is:

```
<expire_ts_hex>.<action_slug>.<hmac_hex>
```

| Field | Description |
| ----- | ----------- |
| `expire_ts_hex` | Hex-encoded Unix timestamp of seal expiry |
| `action_slug` | URL-safe slug identifying the governed action |
| `hmac_hex` | HMAC-SHA256 hex digest over `expire_ts_hex.action_slug` |

| Parameter | Value | Notes |
| --------- | ----- | ----- |
| TTL | **30 seconds** | Seals expire 30s after issuance; prevents replay attacks |
| Algorithm | HMAC-SHA256 | FIPS-approved; constant-time `hmac.compare_digest` for verification |
| Secret | `CAGE_ROUTING_SEAL_SECRET` | Kubernetes `Secret` object; ≥ 64 characters required in production |

The seal is verified by [`src/gateway/server/governance_middleware.py`](../../src/gateway/server/governance_middleware.py) before any trade execution. A missing, expired, or invalid seal returns HTTP 401 (fail-closed). This satisfies the `NoDirectBind` invariant: there is no code path from `CHECKING` to `EXECUTED` that bypasses `SEAL_ISSUED`.

**ISO 42001 mapping:** A.7.5 (Records Integrity — cryptographic seal on every governance approval).

### 16.5 7-Tier Symbolic Governor Pipeline Reference

The full mathematical pipeline is documented in [Document 05 — AI Governance & Policy Engine](./05-AI-GOVERNANCE-POLICY-ENGINE.md) §16. The pipeline enforces the following invariant chain in strict sequential order:

```
STPA UCAs (Tier 0)
  → Confidence ≥ threshold (Tier 1)
    → h(S(t+1)) ≥ (1−γ)·h(S(t)) [CBF] (Tier 2)
      → OPA Rego ALLOW (Tier 4)  ← concurrent with Tier 2 via asyncio.gather
        → Consensus (amount ≤ threshold OR unanimous APPROVE) (Tier 5)
          → (0.5 + estimate.value × amount) ≤ 0.95 [Causal] (Tier 6)
            → FRIA zone check (Tier 6b)
              → SEAL_ISSUED → EXECUTED
```

All tiers are fail-closed. A violation at any tier raises `GovernanceError` and prevents execution. The routing seal (§16.4) is issued only after all tiers pass, satisfying the `NoDirectBind` formal invariant verified in `proof/model.py`.

---

_Document ends. Next: [`07-SECURITY-INFRASTRUCTURE.md`](./07-SECURITY-INFRASTRUCTURE.md)_
