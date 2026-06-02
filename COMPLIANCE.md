# CAGE Compliance & Governance Posture Framework
**CAGE Version:** 2.0.0 (CSA AARM Conformance Release)  
**Last Evaluated:** 2026-05-24  

---

## ⚖️ The Dual-Responsibility Compliance Model

> **CRITICAL CONTEXT FOR AUDITORS:** CAGE provides the built-in technical enforcement controls, automated runtime guardrails, and programmatic evidence generation required to prove compliance. It does **not** automatically grant organizational or certified compliance. Full certification requires institutional audits, independent assessments, and formal administrative authorization.

---

## 1. Regulatory Perimeter & Framework Mapping

The Cybernetic Agent Governance Engine (CAGE) splits its internal control framework based on the operational nature of the component being evaluated. Traditional statistical calculations follow strict banking model guidelines, while autonomous LLM workflows are managed under infrastructure and operational resilience standards.

### Summary Mapping for Examiners

| System Layer | Component / Routine | Governing Framework | CAGE Control ID | Technical Artifact | Active Regions |
| --- | --- | --- | --- | --- | --- |
| **Statistical Code** | Control Barrier Function ($h(x)$ formula & $\gamma$ decay) | **SR 26-2 §IV.B** <br> (Model Risk Management) | `CTRL_MRM_004` | `src/gateway/governance/safety.py` | `US_FED`, `APAC_MAS` *(suppressed in EU_ECB)* |
| **Statistical Code** | DoWhy Causal Inference Model Graph & Regression Coefficients | **SR 26-2 §IV.B** <br> (Model Risk Management) | `CTRL_MRM_004` | `src/gateway/governance/causal_gatekeeper.py` | `US_FED`, `APAC_MAS` *(suppressed in EU_ECB)* |
| **Autonomous Engine** | LLM Routers & Execution Trust Thresholds | **ISO/IEC 42001 §A.5.2** <br> (AI Management System) | `CTRL_AGT_001` | `src/gateway/governance/symbolic_governor.py` | *All Regions* |
| **Autonomous Engine** | LangGraph SAGA WAL Router + Atomic Rollback Patterns | **ISO/IEC 42001 §A.8.4** <br> **DORA Article 12** | `CTRL_WAL_002` | `src/gateway/governance/generated_saga_nodes.py` | *All Regions* |
| **Autonomous Engine** | DoWhy Live Telemetry Placebo Simulation (50-run loop) | **ISO/IEC 42001 §A.9.4** <br> **DORA Article 10** | `CTRL_TEL_003` | `src/gateway/governance/causal_gatekeeper.py` | *All Regions* |
| **Autonomous Engine** | Step 7 Fundamental Rights Impact Assessment (FRIA) Attestation | **EU AI Act Art. 29a** | `CTRL_FRIA_006` | `src/gateway/governance/symbolic_governor.py` | `EU_ECB` only |
| **AARM Primitives** | Cryptographic Hash-Chained Context Accumulator | **CSA AARM-V1** <br> **ISO/IEC 42001 §A.5.3** | `CTRL_CTX_007` | `src/compliance_bridge/context_accumulator.py` | *All Regions* |
| **AARM Primitives** | DEFER State Machine (Confidence-Starvation Boundary) | **CSA AARM-V7** <br> **ISO/IEC 42001 §A.8.4** | `CTRL_DFR_008` | `src/gateway/governance/defer_queue.py` | *All Regions* |
| **AARM Primitives** | 11-Vector AARM Threat Conformance Report | **CSA AARM v1.0** | `CTRL_AARM_009` | `src/compliance_bridge/aarm_mapper.py` | *All Regions* |
| **Security Gates** | Open Policy Agent (OPA) Guardrail & Constraints | **ISO/IEC 42001 §A.6.1** <br> (Enterprise Policy) | `CTRL_OPA_005` | `src/gateway/governance/symbolic_governor.py` | *All Regions* |
| **Infrastructure** | GKE Clusters, Workload Identity, Pod Networking | **NIST RMF (SP 800-37)** <br> **FedRAMP HIGH** | *Out of Code Scope* | `infra/modules/gcp_gke_cluster/` | *All Regions* |

---

## 2. In-Depth Control Implementations

### A. SR 26-2 Model Risk Management Partitioning
*   **Status:** Strictly Scoped & Partitioned.
*   **Mechanism:** Traditional, deterministic safety formulas and back-testable statistical structures (the causal regression kernel) are isolated under `CTRL_MRM_004`. CAGE intentionally decouples these from fluid agent workflows, fulfilling the Federal Reserve mandate to apply targeted, rigorous mathematical validation to traditional predictive blocks while shielding them from non-deterministic LLM variance.
*   **Companion Documentation:** For details on mathematical CBF equations and regression validation, see [docs/CAUSAL_AND_CBF_GOVERNANCE.md](docs/CAUSAL_AND_CBF_GOVERNANCE.md) and [docs/STPA_ANALYSIS.md](docs/STPA_ANALYSIS.md).

### B. ISO/IEC 42001 & DORA (Digital Operational Resilience Act)
*   **Status:** Technical Controls Implemented & Observable.
*   **Mechanism:**
    *   **Transaction Atomicity (DORA Art. 12):** The LangGraph SAGA Write-Ahead Log (WAL) pattern isolates tool calls and model actions, guaranteeing LIFO (Last-In, First-Out) rollbacks during system or execution faults to prevent partial "ghost states" in ledger positions.
    *   **Continuous Telemetry Validation (DORA Art. 10):** Real-time Langfuse OpenTelemetry spans are piped through the placebo refuter at runtime to verify that the agent's world-model matches execution reality, rather than drifting on synthetic variables.
    *   **Tamper-Proof Audit Logging:** All decisions and system exceptions generate a cryptographically hash-chained SHA-256 ledger (`cage-intent/1.0`) to satisfy strict non-repudiation and lifecycle logging policies.
*   **Companion Documentation:** 
    *   For detail on the STPA control structure compiling to OPA/NeMo/Saga, see [docs/STPA_ANALYSIS.md](docs/STPA_ANALYSIS.md).
    *   For detailed symbolic governor and hybrid logic flow, see [README_GOVERNANCE.md](README_GOVERNANCE.md) and [docs/NEURO_SYMBOLIC_GOVERNANCE.md](docs/NEURO_SYMBOLIC_GOVERNANCE.md).

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
    *   **Fairness, Ethics, Accountability, Transparency (FEAT):** Restricts the agent's parameters to MAS FEAT boundaries, dynamically loading `config/thresholds/APAC_MAS_BASELINE.json` to enforce strict operational limits (e.g., SLA latency floor: `100ms`, Consensus: `$5,000`). Ensures full algorithmic accountability and trace transparency in the compliance project trace database.

### E. NIST RMF & FedRAMP HIGH
*   **Status:** **PARTIAL** (Technical Hardening Complete, Administrative ATO Pending).
*   **Mechanism:**
    *   **Zero-Trust Network Hardening:** Deploys Linkerd SPIFFE/SVID mTLS for cryptographic workload validation (**POAM-007 / IA-3**) and Cilium Layer 7 network policies for default-deny egress lockdown (**POAM-011 / SC-8**).
    *   **Programmatic Evidence:** The automated script `oscal_ssp_exporter.py` automatically compiles these exact control configurations and implementation narratives into the authoritative 1,151-line Open Security Controls Assessment Language (OSCAL) document on every build pipeline run.
    *   **⚠️ Gaps to Authorization:** The CAGE software runtime does not inherently possess an official **Authority to Operate (ATO)**. To close this loop, the parent organization must deploy independent assessors to complete RMF Step 5 (Assess) and Step 6 (Authorize), as well as remediate the remaining 11 open infrastructure POA&M infrastructure tickets.
*   **Companion Documentation:** For infrastructure configurations, Linkerd policy files, and security posture tracking, see [docs/SECURITY_STATUS.md](docs/SECURITY_STATUS.md) and [docs/POAM.md](docs/POAM.md).

### F. Lula Automated Compliance Validation (15 Manifests)
*   **Status:** 100% Automated.
*   **Mechanism:** Lula automates OSCAL Assessment Result generation on a 6-hour CronJob schedule (`deployment/k8s/lula-cron.yaml`). Each of the 15 validation manifests in `compliance/lula/` performs a Kubernetes-native resource check and maps it to a specific OSCAL control ID:
    *   `lula-validation-a52.yaml` (ISO 42001 A.5.2) — Social impact assessment ConfigMap
    *   `lula-validation-a53.yaml` (ISO 42001 A.5.3) — Documentation/logging config
    *   `lula-validation-a92.yaml` (ISO 42001 A.9.2) — PII detection Deployment
    *   `lula-validation-ac2.yaml` (NIST SP 800-53 AC-2) — Account management resources
    *   `lula-validation-ac3.yaml` (NIST SP 800-53 AC-3) — Access enforcement policy
    *   `lula-validation-cm6.yaml` (NIST SP 800-53 CM-6) — Configuration settings ConfigMap
    *   `lula-validation-ia3.yaml` (NIST SP 800-53 IA-3) — Device identification config
    *   `lula-validation-ia5.yaml` (NIST SP 800-53 IA-5) — Authenticator management
    *   `lula-validation-ir6.yaml` (NIST SP 800-53 IR-6) — Incident reporting resources
    *   `lula-validation-ra5.yaml` (NIST SP 800-53 RA-5) — `security-scanner-cronjob` existence check
    *   `lula-validation-sc4.yaml` (NIST SP 800-53 SC-4) — Information in shared resources
    *   `lula-validation-sc8.yaml` (NIST SP 800-53 SC-8) — Transmission confidentiality
    *   `lula-validation-si2.yaml` (NIST SP 800-53 SI-2) — Flaw remediation CronJob
    *   `lula-validation-au12.yaml` (NIST SP 800-53 AU-12) — Langfuse OTLP ingestion availability (standalone OTel Collector deprecated 2026-05-31; validation stub needs update to check Langfuse worker readiness)
    *   `lula-validation-aarm-vectors.yaml` (CSA AARM v1.0) — OPA Rego vectors checking

### G. Continuous Audit Event Loop & Compliance Bridge API (v2.0.0)
*   **Status:** Implemented & Active.
*   **Mechanism:** In CAGE v2.0.0, the Compliance Bridge service (`src/compliance_bridge/main.py`) acts as the central hub for automated compliance scoring and threat ledger reporting. It exposes four key REST endpoints:
    *   `GET /v1/aarm/conformance-report` — Generates a live 11-vector CSA AARM conformance report with optional vLLM narrative enrichment (Semaphore-controlled rate limit of 3 concurrent calls).
    *   `GET /v1/defer/pending` — Lists all pending context-starved execution contexts parked in Redis `db=1` (AARM-V7).
    *   `POST /v1/defer/{id}/inject` — Resolves deferred tokens by injecting supplementary context data.
    *   `POST /v1/defer/{id}/escalate` — Escalates deferred tokens to `MANUAL_REVIEW` after TTL expiry (4 hours).

---

## 3. Automated Posture Enforcement (CI/CD Guardrails)

To guarantee that compliance claims never drift from physical codebase state, permanent regression tests are established in `tests/test_governance_architecture.py` and `tests/test_framework_router.py`.

The **architecture guardrail** (`test_governance_architecture.py`) scans all business logic files on every pull request to enforce:
1.  **Zero Citation Leakage:** Prevents literal strings like `"SR 26-2"`, `"SR 11-7"`, or `"ISO 42001"` from being hardcoded into executable files.
2.  **Authoritative Translation:** Restricts all runtime regulatory definitions to the `config/compliance/*_BASELINE.json` regional profiles loaded by `ControlRegistry`.
3.  **Active Control Verification:** Ensures every control code defined in the system registry has a physical, verified invocation point in the gateway's execution paths.
4.  **Regional Profile Parity:** Ensures every `CTRL_*` key across all three regional profiles has a corresponding `GovernanceControl` enum member.

The **FrameworkRouter test matrix** (`test_framework_router.py`, 41 tests) locks down the v2.0.0 Crown Jewel Decoupling:
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

*   **Executive Overview:** [docs/CAGE_ONE_PAGER.md](docs/CAGE_ONE_PAGER.md) — 1-page overview of the business case and architecture.
*   **Detailed Governance Architecture:** [README_GOVERNANCE.md](README_GOVERNANCE.md) — Walkthrough of the 15-tier SymbolicGovernor and the decoupled abstraction layer.
*   **System Architecture Spec:** [ARCHITECTURE.md](ARCHITECTURE.md) — System-wide component structure, database schemas, and request-response pathways.
*   **Security Posture & Milestones:** [docs/SECURITY_STATUS.md](docs/SECURITY_STATUS.md) and [docs/POAM.md](docs/POAM.md) — Precise POAM checklists and NIST RMF coverage tracking.
*   **STPA & Hazard Analysis:** [docs/STPA_ANALYSIS.md](docs/STPA_ANALYSIS.md) — Breakdown of UCAs 1-9 and the STPA-to-Policy compiler specification.
*   **Causal & CBF Design:** [docs/CAUSAL_AND_CBF_GOVERNANCE.md](docs/CAUSAL_AND_CBF_GOVERNANCE.md) — DoWhy regression kernel placebo refuter and discrete-time CBF mathematics.
*   **Full Technical Report Series:** [docs/technical-report/README.md](docs/technical-report/README.md) — 10-document technical report series detailing individual domains.
