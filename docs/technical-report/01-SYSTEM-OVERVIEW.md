# 01 — System Overview

| Field                | Value                                                                                                         |
| -------------------- | ------------------------------------------------------------------------------------------------------------- |
| **Document Version** | 2.0                                                                                                           |
| **Date**             | 2026-06-03                                                                                                    |
| **Classification**   | INTERNAL                                                                                                      |
| **Document Series**  | CAGE Technical Report                                                                                         |
| **Status**           | ACTIVE — v0.1.0 stable (GO — 2026-06-08; GKE deployment verified 2026-06-03)                                |
| **Reference**        | `docs/ROLES_AND_RESPONSIBILITIES.md`, `docs/banking_regs.md`, `compliance/boundary/AUTHORIZATION_BOUNDARY.md` |

---

## 1. System Identity

The **Cybernetic Agent Governance Engine (CAGE)** v0.1.0 is a production-grade, multi-agent AI governance framework purpose-built for regulated financial advising. CAGE runs on Google Kubernetes Engine (GKE) and is designed from the ground up to satisfy the overlapping — and often conflicting — compliance obligations facing AI systems deployed in financial services contexts.

### 1.1 Core Problem Solved

Financial services AI operates at the intersection of multiple, simultaneously binding regulatory regimes: FINRA, SEC Regulation S-P, the Gramm-Leach-Bliley Act (GLBA), ISO-20022 transaction standards, the NIST SP 800-53 Rev 5 HIGH security baseline, and the emerging AI-specific standard ISO/IEC 42001:2023. Most AI systems treat compliance as a post-hoc concern — a layer of documentation applied after a system is built.

CAGE inverts this model. Every governance control — from a sanctions screening rule to a NIST audit log requirement — is implemented as a first-class citizen inside the agent graph and inference pipeline. Compliance is not checked; it is enforced at the point of inference, producing both governed outputs and cryptographically attributable audit evidence in real time.

---

## 2. Key Regulatory Constraints

CAGE's inference pipeline enforces the following hard constraints derived from applicable regulations and codified in `docs/banking_regs.md`:

| Constraint                                                           | Regulatory Source                | Enforcement Point                                        |
| -------------------------------------------------------------------- | -------------------------------- | -------------------------------------------------------- |
| Maximum transaction latency: **200 ms**                              | ISO-20022 (Section 3)            | Gateway — transaction commit blocked if latency exceeded |
| Identity verification required for transactions **> $1,000 USD**     | ISO-20022 (Section 1)            | Gateway / OPA policy                                     |
| OFAC sanctions screening for **all international transfers**         | ISO-20022 (Section 1)            | NeMo Guardrails + OPA                                    |
| PII **must not** persist in session history beyond **24 hours**      | SEC Reg S-P / GLBA (Section 2)   | Redis session TTL + NeMo PII masking                     |
| Audit logs retained for **7 years**                                  | FINRA Rule 4511 / SEC Rule 17a-4 | GCS artifact bucket + Compliance Bridge                  |
| All access to account data requires **a valid signed session token** | ISO-20022 (Section 2)            | Gateway authentication middleware                        |

These constraints are not aspirational. They are encoded as machine-enforceable policy in OPA Rego, NeMo Guardrails Colang rails, and the CAGE gateway middleware stack.

---

## 3. System Stakeholders and Roles

CAGE follows the NIST SP 800-37 Rev. 2 role taxonomy. The table below summarizes each organizational role and its primary accountability domain. All incumbent positions are designated **TBD** as of 2026-03-06 pending ATO approval. Full role definitions, RACI matrix, and required qualifications are maintained in `docs/ROLES_AND_RESPONSIBILITIES.md`.

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

CAGE provides eight integrated capabilities that together constitute a full-stack governed AI financial advisor:

1. **Autonomous AI Financial Advising** — A multi-agent LangGraph pipeline comprising specialist sub-agents (market data analyst, risk analyst, execution analyst, supervisor) that collaboratively generate investment analysis and trade recommendations. Agent orchestration is governed end-to-end; no agent action bypasses the policy engine.

2. **Real-Time Neuro-Symbolic Governance** — A 7-tier policy enforcement architecture (tiers 0–6, plus adaptive Tier 6b FRIA gate) applied at inference time. Each tier (STPA/UCA validation, agentic confidence check, Control Barrier Function, OPA Rego authorization, multi-agent consensus, causal gatekeeper, and external normative validation) intercepts every request before and after the LLM call. The SLM sidecar (formerly Tier 3) has been deprecated and replaced by a permanent `slm_available=false` sentinel to optimize latency. Governance is synchronous — not advisory.

3. **Human-in-the-Loop Trade Approval** — High-risk trade recommendations are routed to a mandatory HITL approval node before execution. The approval workflow is logged with full provenance and linked to the originating inference trace.

4. **Continuous Compliance Evidence Generation** — The Compliance Bridge service produces OSCAL component definitions, control implementation statements, and ISO 42001 evidence artifacts as a continuous byproduct of system operation. Evidence is archived to GCS for 7-year audit retention. OSCAL assessment state semantics follow NIST SP 800-53A §3.2 — four states: `PASS`, `FAIL`, `NOT_APPLICABLE`, and `ERROR` (scanner failure — distinct from `NOT_APPLICABLE`).

5. **Privacy-Preserving PII Detection and Masking** — Microsoft Presidio and NVIDIA NeMo Guardrails jointly detect and mask 15 PII entity types in both inbound prompts and outbound model responses. Masked data is subject to the 24-hour session retention limit enforced by Redis TTL policies.

6. **Red Team Adversarial Testing Harness** — A built-in evaluation harness with 290+ adversarial payloads tests governance robustness against prompt injection, jailbreak attempts, and governance bypass patterns. Red team results feed directly into the POA&M remediation cycle.

7. **Real-Time Audit Observability** — OpenTelemetry traces are emitted per inference request and forwarded to Langfuse. An AgentSight eBPF DaemonSet provides kernel-level system call telemetry. The KernelDashboard UI (AgentSight Phase 1, v0.1.0-rc.1) surfaces real-time governance verdicts, agent state transitions, and anomaly signals for operators — including a live `max_slippage_pct` slider (0–10%, persisted via `POST /api/governance/thresholds`), per-item ΔP price-drift badges (green/yellow/red with pulse animation), and HITL TTL countdown timers for pending approvals.

8. **Multi-Jurisdiction Compliance Engine** — Dynamic loading of regional compliance profiles (`config/compliance/`), governance thresholds (`config/thresholds/`), and OSCAL framework routing tables (`config/oscal/framework_mappings/`) via the `CAGE_DEPLOYMENT_REGION` environment variable. Supports three regulatory jurisdictions — `US_FED` (NIST SP 800-53, SR 26-2, FINRA/SEC), `EU_ECB` (EU AI Act, DORA, GDPR Art. 22, EBA/GL/2023/02, with mandatory Fundamental Rights Impact Assessment and SR 26-2 telemetry suppression), and `APAC_MAS` (MAS FEAT Principles, MAS TRM Guidelines, MAS Notice 655). Adding a new jurisdiction is a config-only operation requiring no Python code changes.

---

## 5. Current Compliance Posture (NIST RMF Readiness)

CAGE is in active NIST RMF implementation. As of the assessment date, the system has not been recommended for ATO. The overall risk posture is classified **HIGH**. The v0.1.0 stable release was tagged on 2026-06-08 (GO — branch `rc-v0.1.0`, tag `v0.1.0`). Both application images were built via Cloud Build and deployed to GKE cluster `gke_YOUR_GCP_PROJECT_ID_us-central1-a_cage-dev`, namespace `governance-stack`, on 2026-06-03. The full test suite now reports **844 passed, 0 failed, 24 skipped** (2026-06-03 GKE cycle).

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

The most significant systemic gap is the absence of an SSP (POAM-015). No ATO recommendation can be issued until the SSP, FIPS 199 categorization signature, and remaining critical findings are resolved. See [`docs/POAM.md`](../compliance/cross-region/POAM.md) for the full Plan of Action and Milestones.

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

