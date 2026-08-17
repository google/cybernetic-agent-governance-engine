# NIST RMF Steps 1–2 Gap Analysis & Refactoring Recommendations

## Cybernetic Governance Engine (CAGE) — Chunk 2 of 5

> **Scope:** NIST RMF Steps 1 (Prepare) and 2 (Categorize)
> **Produced:** 2026-06-01
> **System Version:** CAGE v2.0.0
> **Prerequisite:** `docs/NIST_RMF_CHUNK1_CURRENT_STATE.md` (inventory baseline)
> **Standards Referenced:** NIST SP 800-37 Rev. 2, FIPS 199, NIST SP 800-60 Vol. I & II, NIST SP 800-53 Rev. 5, SR 26-2 (Federal Reserve, April 17, 2026), CSA AARM v1.0

---

## Table of Contents

1. [Step 1 — Prepare: Organization-Level Preparation](#1-step-1--prepare-organization-level-preparation)
2. [Step 1 — Prepare: System-Level Preparation](#2-step-1--prepare-system-level-preparation)
3. [Step 1 — Prepare: Common Control Identification](#3-step-1--prepare-common-control-identification)
4. [Step 2 — Categorize: Information System Categorization](#4-step-2--categorize-information-system-categorization)
5. [Step 2 — Categorize: Information Type Identification](#5-step-2--categorize-information-type-identification)
6. [Step 2 — Categorize: Security Categorization in OSCAL](#6-step-2--categorize-security-categorization-in-oscal)
7. [Priority Matrix](#7-priority-matrix)
8. [Step 1–2 Readiness Score](#8-step-12-readiness-score)

---

## 1. Step 1 — Prepare: Organization-Level Preparation

_(NIST SP 800-37 §2.1 — establishing organizational roles, accountability structures, and documented authorization context before system-level work begins)_

### Current State

- **`docs/SYSTEM_DESCRIPTION_ISO_42001.md`** (all 66 lines) is a conceptual academic document mapping Stafford Beer's Viable System Model to ISO/IEC 42001 clauses. It identifies system components (Planner, Evaluator, Executor) and their ISO clause mappings but contains no authorization boundary statement, no designated Authorizing Official (AO), no Information System Security Officer (ISSO), and no System Owner role assignment. It is a governance philosophy document, not an NIST SP 800-37–compliant System Security Plan.

- **`docs/CAGE_ONE_PAGER.md`** (lines 8–16) references SR 11-7, ISO 42001, and SOC 2 Type II as regulatory drivers and identifies target audiences as "Engineering leads, compliance reviewers, AI governance evaluators" — but this is an engineering status document, not a formal authorization package. No AO, ISSO, or System Owner are named. Open issues R-06 and R-25 are tracked but there is no formal Plan of Action and Milestones (POA&M) artifact tied to RMF. **v2.0.0 addition:** SR 26-2 (Federal Reserve, April 17, 2026) is now the primary agentic AI governance framework for CAGE, superseding SR 11-7 for agentic AI use cases. CSA AARM v1.0 provides the 11-vector threat framework.

- **`docs/GOVERNANCE_CROSSWALK.md`** maps 7 governance requirements to engineering artifacts and Lula validation manifests, with a `role-id: provider` stub visible in `compliance/oscal/component-definition.yaml` (line 41). No roles matrix defining human accountability (who holds the AO authority, who is the ISSO, who is the System Owner) exists anywhere in the repository.

### Gaps Identified

1. **No System Security Plan (SSP):** There is no NIST SP 800-37–structured SSP document. The existing `docs/SYSTEM_DESCRIPTION_ISO_42001.md` covers governance philosophy but not SP 800-18 SSP content (system name, unique identifier, system categorization, operational status, authorization boundary, information types, environment of operation, interconnections, laws and regulations, control implementation descriptions).
2. **No Roles and Responsibilities Matrix:** No document designates an Authorizing Official (AO), Information System Security Officer (ISSO), System Owner, Common Control Provider (CCP), or Security Control Assessor (SCA). The OSCAL file's `role-id: provider` is a placeholder, not an organizational role assignment.
3. **No Authorization Boundary Statement:** No document formally declares what is inside versus outside the CAGE authorization boundary — e.g., whether the GKE cluster, MinIO, Langfuse self-hosted, and the external OFAC screening service are in-boundary or inherited.
4. **No POA&M Artifact:** Open issues (R-06 streaming gap, R-25 version cap) are tracked in `docs/CAGE_ONE_PAGER.md` as inline text. There is no machine-readable POA&M tied to control weaknesses.
5. **No Mission/Business Process Alignment Document:** NIST SP 800-37 §2.1 requires mapping system functions to organizational mission. No such document links CAGE's financial advisory function to a parent organization's risk tolerance or mission objectives.

### Refactoring Recommendations

1. **Create `docs/SYSTEM_SECURITY_PLAN.md`** following NIST SP 800-18 section structure: system identification, system categorization (link to FIPS 199 results from Area 4), authorization boundary narrative, information types table, system environment, interconnection table, laws and regulations table, and per-control implementation summaries. This is the foundational document for the entire RMF authorization package.
2. **Create `docs/ROLES_AND_RESPONSIBILITIES.md`** — a table with columns: Role (AO / ISSO / System Owner / CCP / SCA) | Name/Position | Organization | Responsibilities | Contact. Even if the project is open-source and roles are notional, this artifact must exist for any authorization package. Update `compliance/oscal/component-definition.yaml` `responsible-roles` entries to reference these named roles.
3. **Create `docs/AUTHORIZATION_BOUNDARY.md`** — a narrative + diagram (Mermaid or draw.io export) that declares the precise boundary: what is in-scope (CAGE gateway, financial advisor graph, compliance bridge, OPA, NeMo, Redis, Lula CronJob), what is inherited from the cloud platform (GKE node security, VPC network controls, GCS encryption-at-rest), and what is external (Langfuse, broker APIs, OFAC screening).
4. **Create `compliance/poam/poam.yaml`** — an OSCAL-formatted Plan of Action and Milestones tracking R-06, R-25, and the gaps identified in this and Chunk 1. Reference each item with a `finding-id`, `deadline`, `responsible-party`, and `remediation-plan`.
5. **Add a `docs/MISSION_BUSINESS_PROCESS.md`** aligning CAGE to its organizational mission (regulated financial AI advisory), risk tolerance level, and key stakeholders — satisfying NIST SP 800-37 §2.1 task P-2.

---

## 2. Step 1 — Prepare: System-Level Preparation

_(NIST SP 800-37 §2.2 — defining the system boundary, identifying stakeholders, registering the system, and documenting external dependencies)_

### Current State

- **`ARCHITECTURE.md`** (lines 1–100+, Mermaid component map) provides the most detailed boundary context in the codebase. It identifies 8 logical subsystems: governed-financial-advisor, gateway, compliance-bridge, green-stack-pipeline, agentsight-ui, and infrastructure services (Redis, OPA, NeMo, vLLM×2, Langfuse, MinIO/GCS, Lula, KFP). Data flows are shown in the Mermaid diagram via protocol labels (REST+SSE, gRPC, MCP SSE, HTTP, boto3, OTel). **v2.0.0:** Standalone OTel Collector **deprecated 2026-05-31**; OTLP traces now go directly to Langfuse's integrated ingestion endpoint at `http://langfuse-web:3000/api/public/otel/v1/traces`. AgentSight UI (React/Vite) with eBPF kernel observability added as a new subsystem.

- **`config/settings.py`** (lines 21–102) inventories external service endpoints through environment variables: `VLLM_BASE_URL`, `VLLM_REASONING_API_BASE`, `VLLM_FAST_API_BASE`, `OPA_URL`, `GATEWAY_URL`, `REDIS_URL`, `SANDBOX_URL`, `LANGCHAIN_PROJECT`, `GOOGLE_CLOUD_PROJECT`. The `REQUIRED_ENV_VARS` list (lines 70–76) enforces startup validation of critical endpoints. However, this is a runtime configuration file — not a formal dependency register with vendor, version, data classification, or risk tier.

- **`src/governed_financial_advisor/infrastructure/config_manager.py`** (lines 23–92) implements a cloud-agnostic `ConfigManager` that resolves all configuration from environment variables, with K8s Secret injection documented in comments. No formal data flow diagram or trust zone map exists; the ARCHITECTURE.md Mermaid diagram serves this purpose implicitly but does not label trust boundaries, data classification, or encryption state of each connection.

### Gaps Identified

1. **No Formal System Boundary Document:** `ARCHITECTURE.md` is an engineering reference, not a formal system boundary declaration. It does not label which components are within the authorization boundary vs. inherited from the platform, nor does it specify which flows cross trust boundaries.
2. **No External Dependency Register:** The 10 external services implied by `config/settings.py` (vLLM×2, OPA, NeMo, Redis, Langfuse with integrated OTLP, MinIO/GCS, KFP, Lula, SANDBOX_URL) are not catalogued with: vendor/owner, current version, data types exchanged, interface protocol, encryption-in-transit status, and risk tier classification. (Standalone OTel Collector removed from dependency list — deprecated 2026-05-31.) **v2.0.0 additions:** TrustLayers (External Normative Provider), AnchorageGrpcLedgerProvider (externally reconciled CBF), `google-adk>=1.28.1` (advisor extras) should be added to the register.
3. **No Formal Data Flow Diagram with Trust Zones:** The Mermaid diagram in `ARCHITECTURE.md` shows connectivity but does not demarcate trust zones (internet-facing, DMZ, governance zone, inference zone, storage zone) or label encryption state, data classification, or authentication mechanisms per flow.
4. **`SANDBOX_URL` Undefined:** `config/settings.py` line 55 references `SANDBOX_URL` without any documentation of what this service is, who operates it, what data it receives, or whether it is in-boundary or external.
5. **No Interconnection Security Agreement (ISA):** For each external service that receives PII or financial transaction data (Langfuse self-hosted, broker APIs implied by `execute_trade_action`), an ISA or Memorandum of Understanding (MOU) should be documented.

### Refactoring Recommendations

1. **Create `docs/SYSTEM_BOUNDARY_DIAGRAM.md`** — a formal trust zone diagram (Mermaid preferred for version control) with four labeled zones: (a) External/Internet, (b) Ingress/DMZ (NGINX Inference Gateway, agentsight-ui), (c) Governance Zone (CAGE gateway, OPA, NeMo, Redis, compliance bridge), (d) Inference Zone (vLLM×2 pools). Each cross-zone connection must be labeled with protocol, port, encryption status (TLS/mTLS), and authentication mechanism.
2. **Create `docs/EXTERNAL_DEPENDENCY_REGISTER.md`** — a table with columns: Service Name | Vendor | Version | In-Boundary? | Data Types Exchanged | Protocol | Encryption | Auth Method | Risk Tier. Populate immediately with the 11+ services identified in `config/settings.py` and `ARCHITECTURE.md`.
3. **Document `SANDBOX_URL`** — add a docstring or inline comment to `config/settings.py` line 55 and a corresponding row in the External Dependency Register. If this is a broker sandbox, it likely receives financial transaction data and requires formal interconnection documentation.
4. **Create `docs/INTERCONNECTION_AGREEMENTS/` directory** — add stub ISA templates for Langfuse (telemetry/PII traces), broker APIs (financial transaction data), and OFAC screening service (financial identifiers). Even if the service is self-hosted, document the data exchange agreement.
5. **Annotate `ARCHITECTURE.md` Mermaid diagram** — add trust zone `subgraph` boundaries, encryption labels (e.g., `TLS 1.3`), and data classification labels (`PII`, `FIN-DATA`, `AUDIT`) to each cross-zone edge.

---

## 3. Step 1 — Prepare: Common Control Identification

_(NIST SP 800-37 §2.3 — identifying controls that are inherited from the platform or enterprise, vs. system-specific controls that the system itself implements)_

### Current State

- **`compliance/oscal/component-definition.yaml`** (all 163 lines) defines 3 software components — TypeScript Governance Gateway (A.5.2, A.5.3), OPA Policy Engine (SC-4), and NeMo Guardrails + Presidio (A.9.2). Every `implemented-requirements` entry uses `role-id: provider` (line 41), meaning all 4 controls are claimed as system-provided. There are **no `inherited` control designations** and no Common Control Provider (CCP) entries anywhere in the file.

- The `responsible-roles` section uses only a single generic `role-id: provider` — there is no distinction between controls the CAGE system itself provides and controls inherited from the GKE platform (e.g., physical security, network segmentation via `deployment/k8s/network-policy.yaml`, node OS hardening, GCS encryption-at-rest).

- The OSCAL `component-definition` structure chosen (OSCAL 1.0.4) supports the `control-implementation` → `implemented-requirements` → `by-components` → `implementation-status` field which could carry `status: inherited | planned | implemented | partial`, but this field is absent from all 4 implemented requirements.

### Gaps Identified

1. **No Inherited Control Designations:** GKE provides at least 15+ NIST SP 800-53 controls by inheritance: physical and environmental protection (PE family), media protection (MP), contingency planning platform-layer (CP), supply chain risk management at hardware level (SR), and node-level OS hardening (SI-3, SI-6). None of these are referenced in the OSCAL file.
2. **No Common Control Provider (CCP) Entry:** There is no `back-matter` entry or separate OSCAL component referencing GKE/Google Cloud as a CCP with an associated Shared Responsibility Matrix or FedRAMP authorization package.
3. **No `implementation-status` Field:** The OSCAL 1.0.4 schema supports `by-components` entries with `implementation-status` (implemented / partial / planned / not-applicable). All 4 implemented requirements omit this field, making compliance status opaque to automated tools.
4. **No NIST SP 800-53 Control Mapping:** All 4 controls reference ISO 42001 source (`https://www.iso.org/standard/81230.html`). There are no parallel `implemented-requirements` entries mapping to NIST SP 800-53 Rev. 5 control identifiers (AC-2, AU-2, SI-10, etc.), which is required for a NIST RMF authorization package.
5. **Only 4 of ~110 Applicable Controls Addressed:** For a Moderate-impact financial AI system (see Area 4), NIST SP 800-53 Moderate baseline includes ~110 controls. The current OSCAL file covers 4, leaving 106+ unaddressed in any machine-readable artifact.

### Refactoring Recommendations

1. **Add a GKE Common Control Provider component** to `compliance/oscal/component-definition.yaml` — a new `components` entry with `type: service` and `title: GKE/Google Cloud Platform (Common Controls)`, listing inherited PE, MP, CP, and SR controls. Reference Google Cloud's FedRAMP authorization (P-ATO) as a `back-matter` resource.
2. **Add `implementation-status` to all existing `implemented-requirements`** — for each of A.5.2, A.5.3, A.9.2, SC-4, add a `by-components` block with `implementation-status: {state: implemented}` and a `remarks` field citing the specific code artifact.
3. **Create a parallel NIST SP 800-53 mapping** — add a second `control-implementations` block per component with `source: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"` and map each ISO 42001 control to its nearest SP 800-53 equivalent: A.5.2 → SI-10/SI-15, A.5.3 → AU-2/AU-12, A.9.2 → AC-4/SC-8, SC-4 → AC-3/AC-6.
4. **Create `compliance/oscal/common-controls-catalog.yaml`** — an OSCAL catalog or profile identifying which SP 800-53 controls are fully inherited from GKE, which are hybrid (GKE provides infrastructure, CAGE provides application-layer), and which are system-specific to CAGE.
5. **Extend `compliance/oscal/component-definition.yaml` `responsible-roles`** — add role definitions for `system-owner`, `isso`, `authorizing-official`, `common-control-provider` to match the roles matrix recommended in Area 1.

---

## 4. Step 2 — Categorize: Information System Categorization

_(FIPS 199 / NIST SP 800-60 — formally determining Confidentiality, Integrity, and Availability impact levels for the information system)_

### Current State

- **`docs/banking_regs.md`** (all 18 lines) references ISO-20022 compliance for fund transfers including OFAC sanctions screening, PII retention limits (24-hour session history), session token authentication, and a 200ms latency SLA. The document's existence confirms that CAGE processes financial transaction data subject to US banking regulation — a strong indicator of Moderate-to-High categorization — but it contains no explicit FIPS 199 impact level statement.

- **`docs/CAGE_ONE_PAGER.md`** (lines 8–9) explicitly references three regulatory frameworks: SR 11-7 (Federal Reserve model risk management for high-risk AI), ISO/IEC 42001 (AI management system), and SOC 2 Type II. SR 11-7 applies to model risk in bank holding companies — a Moderate-to-High designation context. The document also references adversarial attack classes RBAC-002 (excessive permissions) and PII-004 (data leakage), confirming sensitivity of data in scope.

- **`config/governance_thresholds.json`** (lines 32–34) sets a `consensus.threshold_usd: 10000.0`, triggering human-in-the-loop for trades above $10k. The `confidence.min_trade_confidence: 0.95` (line 27) reflects an SR 11-7 model performance requirement. These operational thresholds implicitly reflect a Moderate/High Integrity and Availability posture (trading errors must be contained; system availability required for time-sensitive market operations), but no formal categorization document references these thresholds.

### Gaps Identified

1. **No FIPS 199 Categorization Table:** There is no document in the repository containing the formal FIPS 199 security categorization table with Confidentiality (C), Integrity (I), and Availability (A) impact levels (Low/Moderate/High) and the resulting overall system categorization.
2. **No SP 800-60 Mapping:** There is no mapping of the system's information types to the SP 800-60 Volume II taxonomy (e.g., Financial Management — Budget Formulation, Financial Management — Financial Reporting, Privacy — Individually Identifiable Information) with provisional impact levels.
3. **Implicit High-Impact Indicators Not Formalized:** The combination of SR 11-7 compliance, OFAC screening, PII handling (16 entity types in `config/rails/config.yml`), and $10k+ trade execution strongly suggests a Moderate-High Integrity and Moderate Confidentiality impact, but this analysis has never been formally documented or approved by an AO.
4. **No Availability SLA Documentation:** `docs/banking_regs.md` Section 3 mandates no transaction above 200ms latency, and `config/governance_thresholds.json` enforces `stpa.max_latency_ms: 200.0`, but there is no formal Availability impact level statement or Recovery Time Objective (RTO)/Recovery Point Objective (RPO) documented anywhere.
5. **No Annual Review Process:** FIPS 199 categorizations must be reviewed when the system changes significantly. There is no documented review trigger or cadence.

### Refactoring Recommendations

1. **Create `docs/FIPS_199_CATEGORIZATION.md`** — a formal categorization document containing: system name and unique identifier, information types catalogued (from Area 5), a FIPS 199 impact table (C/I/A × Low/Moderate/High with justification per type), the overall system categorization (high-water mark), and AO approval signature block. Recommended baseline based on evidence: Confidentiality=Moderate (PII, financial account data), Integrity=High (trade execution errors are irreversible), Availability=Moderate (200ms SLA, market hours dependency).
2. **Create `docs/SP800-60_INFORMATION_TYPES.md`** — map each information type to SP 800-60 Vol. II identifiers with provisional C/I/A impact levels before applying organization-specific adjustments.
3. **Add categorization metadata to `compliance/oscal/component-definition.yaml`** — reference the FIPS 199 result in the OSCAL `metadata.remarks` field as a machine-readable pointer until a full OSCAL SSP is created (see Area 6).
4. **Document the 200ms latency SLA as an Availability requirement** in the SSP (Area 1 recommendation) and link it to the FIPS 199 Availability impact level. Add a corresponding `AvailabilityRequirement` entry to a future `docs/CONTINGENCY_PLAN.md`.
5. **Establish an Annual Categorization Review** — add a GitHub Actions workflow or Lula CronJob hook that generates a review reminder issue when 365 days have passed since the last `docs/FIPS_199_CATEGORIZATION.md` commit.

---

## 5. Step 2 — Categorize: Information Type Identification

_(NIST SP 800-60 Vol. II — cataloguing all information types processed, stored, or transmitted, with sensitivity levels)_

### Current State

- **`config/rails/config.yml`** (lines 35–71) contains the most explicit information-type inventory in the codebase. The NeMo Guardrails `sensitive_data_detection` configuration lists **15 PII entity types** applied to both input and output rails: `EMAIL_ADDRESS`, `PHONE_NUMBER`, `PERSON`, `CREDIT_CARD`, `US_SSN`, `LOCATION`, `DATE_TIME`, `NRP`, `CRYPTO`, `US_ITIN`, `US_PASSPORT`, `US_BANK_NUMBER`, `US_DRIVER_LICENSE`, `IBAN_CODE`, `IP_ADDRESS`. This is a technically enforced PII taxonomy, not a formally catalogued information type register.

- **`src/gateway/governance/nemo/manager.py`** (lines 58–68) implements a `SafeAnalyzer` patching Presidio's `AnalyzerEngine` to enforce the same 15-entity set at detection time, with a `score_threshold=0.3` sensitivity floor. This confirms runtime enforcement of PII detection but does not constitute a formal information type catalog with SP 800-60 identifiers or data owner assignments.

- **`config/governance_thresholds.json`** defines financial thresholds (`cbf.min_cash_balance`, `drawdown.limit`, `consensus.threshold_usd`, `confidence.min_trade_confidence`) that implicitly characterize financial transaction data as high-sensitivity (irreversible, regulated), but no formal data classification or sensitivity label is attached to the financial information types the system processes.

### Gaps Identified

1. **No Formal SP 800-60 Information Type Catalog:** The 15 PII entity types in `config/rails/config.yml` are detection targets, not SP 800-60 information type definitions. There is no document mapping the system's data to SP 800-60 Vol. II taxonomy entries with provisional base impact levels.
2. **Financial Transaction Data Not Formally Typed:** The system executes trades (up to $500k for senior roles per `compliance/oscal/component-definition.yaml` line 100), stores portfolio state, and receives market data — but none of these financial information types are catalogued with sensitivity levels, data owners, or retention requirements.
3. **AI Model Outputs Not Classified:** The system generates trade recommendations, risk scores, and governance verdicts (APPROVED/REJECTED). These AI-generated outputs are not classified as an information type, yet they drive consequential financial decisions. Under SR 11-7, model outputs have specific validation and audit requirements.
4. **Audit Logs Not Formally Typed:** The system emits OTel spans tagged with ISO 42001 control IDs to Langfuse. Audit logs are an information type with specific NIST SP 800-53 AU control requirements and retention periods — but no audit log retention policy or classification exists.
5. **No Data Owner Assignments:** Each information type requires a designated data owner responsible for its classification and handling. No such assignments exist.
6. **No Data Retention Schedule:** `docs/banking_regs.md` Section 2.1 mandates PII retention ≤24 hours in session history, but no broader data retention schedule covers audit logs, trade records, model outputs, or governance verdicts.

### Refactoring Recommendations

1. **Create `docs/SP800-60_INFORMATION_TYPES.md`** with a table: Information Type | SP 800-60 ID | Description | Data Owner | Confidentiality Impact | Integrity Impact | Availability Impact | Retention Period | Regulatory Driver. Include at minimum: (a) PII — C=Moderate, I=Moderate, A=Low; (b) Financial Transaction Data — C=Moderate, I=High, A=Moderate; (c) AI Model Outputs/Trade Recommendations — C=Low, I=High, A=Moderate; (d) Audit Logs/Governance Verdicts — C=Low, I=High, A=Moderate; (e) Market Data — C=Low, I=Moderate, A=High; (f) Authentication Credentials — C=High, I=High, A=Moderate.
2. **Promote `config/rails/config.yml` PII entity list** to the information type catalog as the authoritative PII sub-type list, cross-referencing it from `docs/SP800-60_INFORMATION_TYPES.md` so the technical enforcement config and the policy catalog remain in sync.
3. **Create `docs/DATA_RETENTION_POLICY.md`** — define retention periods for each information type, citing the regulatory driver (ISO-20022 24h PII limit from `docs/banking_regs.md`, SR 11-7 model documentation requirements, SOC 2 Type II audit log retention).
4. **Add data classification labels to `config/governance_thresholds.json` `_comment` fields** — annotate each threshold section with the information type and impact level it governs (e.g., `consensus.threshold_usd` governs Financial Transaction Data — Integrity=High).
5. **Add an AI Model Output information type handling procedure** — create `docs/MODEL_OUTPUT_HANDLING.md` specifying that governance verdicts (APPROVED/REJECTED) are Integrity=High artifacts, must be HMAC-sealed (already implemented via `GOVERNANCE_SALT`), must be retained for SR 11-7 model audit purposes, and must be explainable (already implemented via the Explainer node).

---

## 6. Step 2 — Categorize: Security Categorization in OSCAL

_(Recording the FIPS 199 categorization result in a machine-readable OSCAL artifact, enabling automated compliance tooling to consume and validate it)_

### Current State

- **`compliance/oscal/component-definition.yaml`** (all 163 lines, OSCAL version 1.0.4) contains **no `security-impact-level` element** anywhere in the file. The `metadata` block (lines 12–20) includes `title`, `version`, `oscal-version`, `last-modified`, and `remarks`, but no categorization metadata. The `back-matter` block (lines 149–162) references three external resources (ISO 42001 standard, Lula tool, OSCAL spec) but no FIPS 199 document or SP 800-60 mapping.

- The current OSCAL artifact is a **Component Definition** (`component-definition:`), which is the correct OSCAL document type for cataloguing component-level control implementations. However, the NIST RMF-required categorization metadata belongs in an **OSCAL System Security Plan (SSP)** document — specifically in the `system-characteristics` → `security-impact-level` element. No OSCAL SSP document exists in the `compliance/oscal/` directory.

- The existing 4 implemented controls all reference the ISO 42001 source URL. No OSCAL `import-profile` or `baseline` element references NIST SP 800-53 Rev. 5 Moderate baseline, which would be the expected starting point for a financial AI system of this categorization.

### Gaps Identified

1. **No OSCAL SSP Document:** The repository contains only `compliance/oscal/component-definition.yaml`. NIST RMF authorization requires an OSCAL SSP (`system-security-plan`) containing: `system-characteristics` (with `security-impact-level`, `system-status`, `authorization-boundary`), `system-implementation` (users, components, inventory-items, leveraged-authorizations), and `control-implementation` (per-control satisfaction statements mapped to SP 800-53).
2. **No `security-impact-level` Element:** The OSCAL 1.0.4 schema defines `security-impact-level` with sub-elements `security-objective-confidentiality`, `security-objective-integrity`, `security-objective-availability` (each accepting `fips-199-low | fips-199-moderate | fips-199-high`). This element is absent from all existing OSCAL files.
3. **No OSCAL `import-profile` for SP 800-53 Moderate Baseline:** Without a profile import, automated tools cannot determine which SP 800-53 controls apply to this system. The OSCAL component definition is self-contained with no baseline reference.
4. **No Leveraged Authorizations:** An OSCAL SSP should list `leveraged-authorizations` for cloud platform controls inherited from GKE/Google Cloud (FedRAMP P-ATO), enabling auditors to trace inherited control coverage automatically.
5. **Lula Validation Scope Limited to 4 Controls:** The Lula CronJob (`deployment/k8s/lula-cron.yaml`) validates only A.5.2, A.5.3, A.9.2, and SC-4. An OSCAL SSP linked to the SP 800-53 Moderate baseline would identify 100+ controls requiring validation, enabling expansion of the Lula test suite systematically.

### Refactoring Recommendations

1. **Create `compliance/oscal/system-security-plan.yaml`** — an OSCAL 1.0.4 SSP document with the following minimum structure:
   ```yaml
   system-security-plan:
     metadata:
       title: "CAGE System Security Plan"
       oscal-version: "1.0.4"
     import-profile:
       href: "https://csrc.nist.gov/OSCAL/profiles/nist-800-53-rev5-moderate-baseline"
     system-characteristics:
       system-name: "Cybernetic Agent Governance Engine (CAGE)"
       security-impact-level:
         security-objective-confidentiality: fips-199-moderate
         security-objective-integrity: fips-199-high
         security-objective-availability: fips-199-moderate
     system-implementation:
       leveraged-authorizations:
         - title: "Google Cloud Platform (FedRAMP P-ATO)"
     control-implementation:
       implemented-requirements: [] # populate per Area 3 recommendation
   ```
2. **Add `security-impact-level` to the existing `compliance/oscal/component-definition.yaml` `metadata.remarks`** as a stopgap human-readable reference until the full SSP is created: `remarks: "Pending FIPS 199 formal categorization — provisional: C=Moderate, I=High, A=Moderate"`.
3. **Link the SSP to the component definition** — add an `import-component-definition` reference in the OSCAL SSP pointing to `compliance/oscal/component-definition.yaml`, so the 4 existing implemented requirements flow into the SSP's control implementation section.
4. **Extend the Lula CronJob manifest** (`deployment/k8s/lula-cron.yaml`) to also validate against the new OSCAL SSP, using `lula validate --input compliance/oscal/system-security-plan.yaml` so the categorization metadata is included in the automated audit scope.
5. **Create `compliance/oscal/profiles/cage-moderate-tailored.yaml`** — an OSCAL profile that imports the SP 800-53 Rev. 5 Moderate baseline and applies CAGE-specific tailoring (scoping out PE controls fully inherited from GKE, adding AI-specific overlays for SR 11-7 and ISO 42001 controls).

---

## 7. Priority Matrix

| #   | Recommendation                                                                                    | NIST Control Family    | Effort | Impact | Priority |
| --- | ------------------------------------------------------------------------------------------------- | ---------------------- | ------ | ------ | -------- |
| 1   | Create OSCAL SSP with `security-impact-level` (`compliance/oscal/system-security-plan.yaml`)      | CA-2, CA-5, CA-6, RA-2 | M      | H      | **P1**   |
| 2   | Create formal FIPS 199 categorization document (`docs/FIPS_199_CATEGORIZATION.md`)                | RA-2                   | S      | H      | **P1**   |
| 3   | Create SP 800-60 information type catalog (`docs/SP800-60_INFORMATION_TYPES.md`)                  | RA-2, PM-7             | S      | H      | **P1**   |
| 4   | Create Roles and Responsibilities matrix (`docs/ROLES_AND_RESPONSIBILITIES.md`)                   | PM-2, AC-1, CA-1       | S      | H      | **P1**   |
| 5   | Create System Security Plan (`docs/SYSTEM_SECURITY_PLAN.md`)                                      | CA-6, PL-2             | L      | H      | **P1**   |
| 6   | Add NIST SP 800-53 control mappings to OSCAL component definition                                 | CA-2, PL-8             | M      | H      | **P2**   |
| 7   | Add GKE Common Control Provider entry to OSCAL (`inherited` controls)                             | CA-3, SA-9             | M      | H      | **P2**   |
| 8   | Create Authorization Boundary document with trust zone diagram (`docs/AUTHORIZATION_BOUNDARY.md`) | PL-2, SA-17            | M      | M      | **P2**   |
| 9   | Create External Dependency Register (`docs/EXTERNAL_DEPENDENCY_REGISTER.md`)                      | SA-9, SA-12            | S      | M      | **P2**   |
| 10  | Document `SANDBOX_URL` service and add to dependency register                                     | SA-9                   | S      | M      | **P2**   |
| 11  | Create OSCAL tailored profile for SP 800-53 Moderate baseline (`compliance/oscal/profiles/`)      | PL-7, PL-10            | M      | M      | **P2**   |
| 12  | Add `implementation-status` fields to all existing OSCAL `implemented-requirements`               | CA-2                   | S      | M      | **P2**   |
| 13  | Create AI Model Output handling procedure (`docs/MODEL_OUTPUT_HANDLING.md`)                       | SI-12, SR 11-7         | S      | M      | **P2**   |
| 14  | Create Data Retention Policy (`docs/DATA_RETENTION_POLICY.md`)                                    | SI-12, AU-11           | S      | M      | **P2**   |
| 15  | Create POA&M artifact (`compliance/poam/poam.yaml`)                                               | CA-5                   | M      | M      | **P2**   |
| 16  | Create Interconnection Security Agreements (`docs/INTERCONNECTION_AGREEMENTS/`)                   | CA-3, SA-9             | M      | L      | **P3**   |
| 17  | Annotate ARCHITECTURE.md Mermaid diagram with trust zones and encryption labels                   | SA-17                  | S      | M      | **P3**   |
| 18  | Create Mission/Business Process alignment document (`docs/MISSION_BUSINESS_PROCESS.md`)           | PM-7, PM-11            | S      | L      | **P3**   |
| 19  | Add annual categorization review GitHub Actions trigger                                           | RA-3                   | S      | L      | **P3**   |
| 20  | Extend Lula CronJob to validate OSCAL SSP (not just component definition)                         | CA-7                   | S      | M      | **P3**   |

**Effort Key:** S = Small (days), M = Medium (1–3 weeks), L = Large (3+ weeks)
**Impact Key:** H = High (blocks authorization), M = Medium (significant gap), L = Low (enhancement)

---

## 8. Step 1–2 Readiness Score

### Score: **28 / 100**

### Justification

The CAGE codebase demonstrates exceptional _technical_ governance maturity — an 8-tier governance pipeline (FTRA + 7 in-pipeline tiers), Presidio PII masking across 16 entity types, Cloud KMS HSM-backed asymmetric signing, automated Lula OSCAL auditing across 15 manifests, and OTel-stamped ISO 42001 evidence — but this technical strength does not translate into RMF Steps 1–2 readiness, which are fundamentally _documentation and authorization_ steps. The score of 28% reflects the following distribution:

**What exists (contributing ~28 points):** The `ARCHITECTURE.md` Mermaid diagram provides a credible starting point for a system boundary narrative (+8). The `config/rails/config.yml` 16-entity PII detection list provides a detailed, technically enforced basis for an information type catalog (+5). The `compliance/oscal/component-definition.yaml` establishes machine-readable implemented requirements and a valid OSCAL framework to extend (+5). The `docs/GOVERNANCE_CROSSWALK.md` provides a partial control-to-artifact traceability matrix (+5). References scattered across `docs/project/CAGE_ONE_PAGER.md` and `docs/compliance/` to SR 26-2 (Federal Reserve, April 17, 2026), SR 11-7, ISO/IEC 42001:2023, CSA AARM v1.0, and SOC 2 Type II establish regulatory context sufficient to justify a Moderate-High FIPS 199 categorization (+5). (Note: no standalone `docs/banking_regs.md` exists in this repository — a consolidated banking-regulations reference document remains a gap.)

**What is missing (the 72-point gap):** There is no System Security Plan, no FIPS 199 categorization table, no SP 800-60 information type catalog, no Roles and Responsibilities matrix, no Authorization Boundary document, no OSCAL SSP with `security-impact-level`, no Common Control Provider entries, no POA&M, no data retention policy, and no NIST SP 800-53 control mappings. Every one of these artifacts is a mandatory prerequisite for RMF Step 3 (Select controls) — without them, the control selection baseline cannot be formally established, and the system cannot proceed toward an Authority to Operate (ATO).

**v2.0.0 context:** SR 26-2 (Federal Reserve, April 17, 2026) is now the primary agentic AI governance framework, adding specific requirements for agentic AI systems in financial services that must be reflected in the SSP and FIPS 199 categorization. CSA AARM v1.0 provides an 11-vector threat framework that should be incorporated into the SP 800-60 information type catalog and risk assessment.

**Top 3 Priority Recommendations to close the gap:**

1. **Create `compliance/oscal/system-security-plan.yaml`** with `security-impact-level: C=Moderate / I=High / A=Moderate` — this single artifact unblocks automated tooling and establishes the formal categorization result.
2. **Create `docs/FIPS_199_CATEGORIZATION.md`** with the formal FIPS 199 impact table and AO sign-off block — the human-readable companion to the OSCAL SSP.
3. **Create `docs/ROLES_AND_RESPONSIBILITIES.md`** — without named AO/ISSO/System Owner, no artifact in the authorization package has formal accountability, making the entire package non-submittable for authorization review.

---

_End of Chunk 2 — NIST RMF Steps 1 (Prepare) and 2 (Categorize). Updated 2026-06-01 for CAGE v2.0.0._
_Chunk 3 will cover Step 3 (Select) — NIST SP 800-53 control baseline selection, tailoring, and parameter assignments._
