# Security Assessment Plan (SAP)

**System:** Cybernetic AI Governance Engine (CAGE) — Governed Financial Advisor
**Document Number:** SAP-CAGE-2026-001
**Reference:** NIST SP 800-53A Rev. 5; NIST SP 800-37 Rev. 2; NIST SP 800-53 Rev. 5
**Version:** 1.0 (Draft)
**Date:** 2026-03-06
**Classification:** UNCLASSIFIED
**Status:** DRAFT — Pending AO Approval

| Field                           | Value                                                                                                                                       |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| System Name                     | Cybernetic AI Governance Engine (CAGE)                                                                                                      |
| System Abbreviation             | CAGE                                                                                                                                        |
| ISSO                            | [ISSO NAME — TBD]                                                                                                                           |
| Authorizing Official (AO)       | [AO NAME — TBD]                                                                                                                             |
| Security Control Assessor (SCA) | [SCA NAME — TBD]                                                                                                                            |
| Assessment Period               | 2026-04-01 through 2026-05-23                                                                                                               |
| Related Documents               | `docs/POAM.md`, `compliance/sar/SAR_2026Q1.md`, `compliance/categorization/FIPS199_CATEGORIZATION.md`, `docs/ROLES_AND_RESPONSIBILITIES.md` |

---

## 1. Introduction and Purpose

### 1.1 Purpose

This Security Assessment Plan (SAP) establishes the scope, objectives, methods, schedule, and rules of engagement for the independent security control assessment of the Cybernetic AI Governance Engine (CAGE). The assessment is conducted in accordance with:

- **NIST SP 800-53A Rev. 5** — Assessing Security and Privacy Controls in Information Systems and Organizations
- **NIST SP 800-37 Rev. 2** — Risk Management Framework for Information Systems and Organizations
- **NIST SP 800-53 Rev. 5** — Security and Privacy Controls for Information Systems and Organizations

The assessment is a prerequisite to the Authorization to Operate (ATO) decision for the CAGE system (see POAM-005, POAM-015). The findings produced by this assessment will be documented in the Security Assessment Report (SAR) at `compliance/sar/SAR_2026Q1.md` and will inform the POA&M (`docs/POAM.md`) remediation priorities.

### 1.2 Regulatory Context

CAGE operates in the financial services sector and is subject to the following regulatory requirements that inform the assessment:

| Regulation            | Relevance to Assessment                                       |
| --------------------- | ------------------------------------------------------------- |
| SEC Rule 17a-4        | Requires non-rewriteable audit log preservation (AU-9, AU-11) |
| FINRA Rule 4511       | Electronic records storage; audit trail integrity             |
| SEC Reg S-P           | Safeguarding customer PII (IA-5, SC-28, MP-5)                 |
| SR 11-7 (Fed Reserve) | Model risk management validation requirements                 |
| ISO/IEC 42001:2023    | AI management system audit trail requirements                 |
| NIST AI RMF 1.0       | AI-specific risk management alignment                         |

### 1.3 Assessment Authority

The CAGE System Owner has authorized this assessment per NIST SP 800-37 Rev. 2 CA-2. The assessment team is independent of the system development and operations team and reports directly to the Authorizing Official (AO).

---

## 2. Assessment Scope

### 2.1 System Authorization Boundary

The assessment scope is bounded by the CAGE authorization boundary as defined in `compliance/boundary/AUTHORIZATION_BOUNDARY.md`. The following components are within the assessment scope:

| Component                   | Type                        | Location                          | Assessment Priority |
| --------------------------- | --------------------------- | --------------------------------- | ------------------- |
| CAGE Gateway                | FastAPI/gRPC Application    | GKE Namespace: `governance-stack` | Critical            |
| NeMo Guardrails Server      | AI Safety Layer             | GKE Namespace: `governance-stack` | Critical            |
| OPA Policy Engine           | Authorization Engine        | GKE Namespace: `governance-stack` | Critical            |
| LangGraph Financial Advisor | AI Agent Orchestrator       | GKE Namespace: `governance-stack` | Critical            |
| AgentSight eBPF Sidecar     | eBPF Monitoring Agent       | GKE Namespace: `governance-stack` | High                |
| Compliance Bridge           | Audit/OSCAL Service         | GKE Namespace: `governance-stack` | High                |
| Redis Cache                 | In-memory Data Store        | GKE Namespace: `governance-stack` | High                |
| Cloud SQL PostgreSQL        | Relational Database         | GCP Managed Service               | High                |
| GCS Buckets (OSCAL/Audit)   | Object Storage              | GCP Managed Service               | Moderate            |
| GKE Network Policies        | Kubernetes Network Control  | GKE Namespace: `governance-stack` | Critical            |
| Terraform IaC               | Infrastructure as Code      | `infra/targets/gcp-gke/`          | High                |
| GitHub Actions CI/CD        | Build & Deployment Pipeline | GitHub Cloud                      | High                |

### 2.2 Components Out of Scope

The following components are provided by Google Cloud Platform (GCP) as a Common Control Provider (CCP) and are assessed via GCP's FedRAMP authorization. These controls are inherited by CAGE:

- GKE control plane physical and hypervisor security
- GCP data center physical security and environmental controls
- GCP network infrastructure backbone
- Google-managed encryption-at-rest for Cloud SQL and GCS (unless CMEK is assessed)
- GCP Identity and Access Management (IAM) platform infrastructure

### 2.3 Information Types in Scope

Per `compliance/categorization/FIPS199_CATEGORIZATION.md`, all five information types are in scope:

- IT-001: Financial Trade Execution Data (C=Moderate, I=High, A=Moderate)
- IT-002: AI Model Inference Outputs (C=Moderate, I=High, A=Moderate)
- IT-003: Audit and Accountability Records (C=Low, I=High, A=Moderate)
- IT-004: PII / Individual Financial Records (C=High, I=High, A=Low)
- IT-005: Governance Policy Configurations (C=Moderate, I=High, A=High)

**Overall System Security Category:** HIGH (C=High, I=High, A=High per FIPS 199)

---

## 3. Assessment Objectives and Control Selection

### 3.1 Control Baseline

The NIST SP 800-53 Rev. 5 **HIGH** impact baseline applies to CAGE per the FIPS 199 categorization. The full HIGH baseline contains approximately 421 controls and control enhancements. This initial assessment focuses on the priority controls identified through gap analysis (see `docs/POAM.md`).

### 3.2 Priority Control Selection Rationale

The following 13 controls are prioritized for assessment based on:

1. Open POA&M items identifying specific weaknesses
2. FIPS 199 HIGH impact on one or more security objectives
3. AI/ML-specific risk factors unique to the CAGE architecture
4. Regulatory drivers (SEC, FINRA, SR 11-7)

| Control ID | Control Name                               | Priority Rationale                         | POAM Reference |
| ---------- | ------------------------------------------ | ------------------------------------------ | -------------- |
| AC-2       | Account Management                         | No documented procedures; HIGH risk        | POAM-001       |
| AC-3       | Access Enforcement                         | HMAC seal bypass identified; CRITICAL risk | POAM-012       |
| AU-2       | Event Logging                              | Audit log coverage completeness            | —              |
| AU-12      | Audit Record Generation                    | Mock trace generator identified            | POAM-003       |
| IA-3       | Device Identification and Authentication   | No intra-cluster mTLS                      | POAM-007       |
| IA-5       | Authenticator Management                   | No secret rotation schedule                | POAM-014       |
| RA-5       | Vulnerability Monitoring and Scanning      | No CI/CD scanning                          | POAM-010       |
| SC-8       | Transmission Confidentiality and Integrity | No TLS validation test                     | POAM-011       |
| SI-2       | Flaw Remediation                           | Unpinned dependencies                      | POAM-013       |
| CM-6       | Configuration Settings                     | CIS benchmark compliance                   | —              |
| CM-8       | System Component Inventory                 | No SBOM                                    | POAM-006       |
| IR-1       | Incident Response Policy and Procedures    | No IRP document                            | POAM-008       |
| IR-6       | Incident Reporting                         | No reporting procedures                    | POAM-008       |

### 3.3 Additional Controls for Spot-Check Assessment

In addition to the 13 priority controls, the assessment team will perform spot-check evaluation of:

- AU-9 (Protection of Audit Information)
- CA-7 (Continuous Monitoring) — per `compliance/continuous-monitoring/ISCM_STRATEGY.md`
- SA-11 (Developer Testing and Evaluation) — red team testing per `tests/red_team/`
- PM-7 (Enterprise Architecture) — AI governance pipeline architecture

---

## 4. Assessment Team

### 4.1 Team Composition

Per `docs/ROLES_AND_RESPONSIBILITIES.md`, the following roles are defined for the assessment:

| Role                                      | Incumbent            | Responsibilities                                                          |
| ----------------------------------------- | -------------------- | ------------------------------------------------------------------------- |
| Security Control Assessor (Lead)          | [SCA NAME — TBD]     | Lead all assessment activities; produce SAR; brief AO                     |
| Technical Assessor — Cloud/Infrastructure | [TBD]                | Assess GKE, Terraform, network controls; review POAM-002, POAM-007        |
| Technical Assessor — Application Security | [TBD]                | Assess gateway, API controls, authentication; review POAM-012, POAM-013   |
| Technical Assessor — AI/ML Security       | [TBD]                | Assess NeMo Guardrails, OPA, LangGraph; AI-specific threat scenarios      |
| Technical Assessor — DevSecOps/CI         | [TBD]                | Assess GitHub Actions pipeline, SBOM, scanning; review POAM-006, POAM-010 |
| ISSO (Liaison, Non-assessor)              | [ISSO NAME — TBD]    | Coordinate access, provide documentation, answer assessor questions       |
| System Owner (Liaison, Non-assessor)      | [SYSTEM OWNER — TBD] | Authorize access; receive findings briefing                               |

### 4.2 Independence Requirements

Per NIST SP 800-53A Rev. 5, the Security Control Assessor (SCA) must be independent from the system development and operations personnel. Assessment team members must:

- Have no involvement in CAGE system development, configuration, or operation
- Have no reporting relationship to the System Owner that would impair objectivity
- Disclose and resolve any conflicts of interest prior to assessment initiation

### 4.3 Assessor Qualifications

Assessment team members must hold relevant qualifications including one or more of:

- Certified Information Systems Security Professional (CISSP)
- Certified Information Security Manager (CISM)
- GIAC Security Expert (GSE) or relevant GIAC specializations
- Certified Ethical Hacker (CEH) for penetration testing activities
- Experience with NIST SP 800-53A assessment procedures
- Experience with AI/ML security assessments (AI-specific assessor requirement)

---

## 5. Assessment Methods

Per NIST SP 800-53A Rev. 5, three assessment methods are employed:

### 5.1 Examination

**Definition:** Reviewing, inspecting, observing, studying, or analyzing assessment objects (specifications, mechanisms, activities) to facilitate assessor understanding and produce evidence.

**Evidence Sources for Examination:**

- System Security Plan (`compliance/ssp/SYSTEM_SECURITY_PLAN_OUTLINE.md`) and control implementation statements
- FIPS 199 Categorization (`compliance/categorization/FIPS199_CATEGORIZATION.md`)
- OSCAL Component Definitions (`compliance/oscal/component-definition.yaml`)
- Terraform IaC configurations (`deployment/terraform/`)
- Kubernetes manifests (`deployment/k8s/`)
- Network Policy specifications (`deployment/k8s/network-policy.yaml`, `network-policy-hardening.yaml`)
- GitHub Actions workflows (`.github/workflows/`)
- OPA Rego policies (`src/governed_financial_advisor/governance/policy/`)
- NeMo Guardrails Colang configurations
- Lula compliance validation specs (`compliance/lula/`)
- Audit log samples from Langfuse
- POA&M (`docs/POAM.md`) and existing remediation evidence

### 5.2 Interview

**Definition:** Conducting discussions with individuals or groups within an organization to facilitate assessor understanding, achieve clarification, and identify potential issues.

**Interview Subjects:**

- ISSO: Overall security posture, POA&M status, monitoring procedures
- System Administrator: Configuration management, patching, account management
- AI Model Operator: Governance policy management, model risk management, incident handling
- Compliance Engineer: OSCAL/Lula pipeline, SBOM status, vulnerability scan process
- Development Lead: Dependency management, CI/CD security controls, HMAC seal implementation
- Cloud/Platform Engineer: GKE configuration, IAM bindings, network policy enforcement

### 5.3 Test

**Definition:** Executing assessment objects (mechanisms, activities) under specified conditions to compare actual with expected behavior.

**Testing Activities:**

- Execute Lula compliance validation suite (`compliance/lula/`)
- Run automated control tests (`make test` / `pytest tests/`)
- Verify TLS enforcement on gateway endpoints (gRPC and REST)
- Attempt HMAC seal bypass scenarios to validate POAM-012 remediation
- Execute red-team adversarial prompt injection tests (`tests/red_team/`)
- Run `pip-audit` and Trivy container scanning against current images
- Validate OPA policy enforcement via test cases
- Verify NetworkPolicy default-deny posture via `kubectl` inspection
- Test mTLS absence (confirm POAM-007 finding)
- Validate AgentSight eBPF monitoring alerts

---

## 6. Assessment Schedule

The assessment is planned over **8 weeks** from 2026-04-01 through 2026-05-23.

### 6.1 Assessment Milestones

| Week       | Dates                   | Activities                                                                                               | Deliverable                                                     |
| ---------- | ----------------------- | -------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| **Week 1** | 2026-04-01 – 2026-04-04 | Kickoff meeting; review SSP, FIPS 199, POA&M; set up assessment environment; finalize interview schedule | Kickoff meeting minutes; assessment environment confirmation    |
| **Week 2** | 2026-04-07 – 2026-04-11 | Examine IaC, Kubernetes manifests, network policies; interview ISSO and System Admin                     | Week 2 field notes; CM and SC control preliminary findings      |
| **Week 3** | 2026-04-14 – 2026-04-18 | Examine OPA/NeMo configurations; interview AI Model Operator; assess IA-3, IA-5, AC-3                    | Week 3 field notes; IA and AC control preliminary findings      |
| **Week 4** | 2026-04-21 – 2026-04-25 | Technical testing: Lula validation, TLS tests, HMAC bypass tests, red-team adversarial tests             | Technical test results; AU and IR preliminary findings          |
| **Week 5** | 2026-04-28 – 2026-05-02 | Examine CI/CD pipeline; run container scanning and pip-audit; interview Compliance Engineer              | DevSecOps control findings; RA-5, SI-2, CM-8 assessment         |
| **Week 6** | 2026-05-05 – 2026-05-09 | Draft findings consolidation; preliminary risk determinations; internal assessor review                  | Draft findings list with risk ratings                           |
| **Week 7** | 2026-05-12 – 2026-05-16 | Present preliminary findings to ISSO and System Owner; allow factual accuracy review                     | Preliminary findings briefing; system owner factual corrections |
| **Week 8** | 2026-05-19 – 2026-05-23 | Finalize SAR; incorporate factual corrections; assessor certification; deliver to AO                     | **Final SAR (`compliance/sar/SAR_2026Q1.md`) delivered to AO**  |

### 6.2 Key Milestones

| Milestone                     | Target Date |
| ----------------------------- | ----------- |
| Assessment Kickoff            | 2026-04-01  |
| Technical Testing Complete    | 2026-05-02  |
| Preliminary Findings Briefing | 2026-05-12  |
| Final SAR Delivered           | 2026-05-23  |
| ATO Decision Target           | 2026-06-30  |

---

## 7. Rules of Engagement

### 7.1 Authorization

All assessment activities are authorized in writing by the System Owner and AO prior to commencement. Testing activities that involve active exploitation (penetration testing, red-team exercises) require a signed Rules of Engagement (ROE) document approved by the System Owner.

### 7.2 Testing Constraints

- **Production System:** No destructive testing in the production GKE namespace. Testing shall be conducted in a designated assessment environment that mirrors production configuration
- **Data Handling:** Assessors shall not retain, copy, or transmit PII or financial data encountered during the assessment. Any inadvertent access to PII shall be immediately reported to the ISSO
- **Denial of Service:** Load-based tests and denial-of-service scenarios are prohibited without explicit System Owner authorization and shall only be performed in isolated environments
- **Third-Party Systems:** Testing shall not extend to Langfuse (SaaS), vLLM/Vertex AI (Google Cloud managed), or other external systems outside the CAGE authorization boundary
- **Notification:** The ISSO shall be notified at least 24 hours before any active technical testing (penetration testing, red-team exercises)

### 7.3 Evidence Handling

- All assessment evidence (screenshots, log samples, test outputs) shall be stored in a secure, access-controlled location
- Evidence shall be labeled with the control ID, assessment date, and assessor name
- Evidence containing PII shall be redacted before inclusion in the SAR
- Evidence shall be retained for a minimum of 3 years following the ATO decision

### 7.4 Communications

- **Primary Contact (ISSO):** [ISSO NAME — TBD] — all routine assessment coordination
- **Escalation Contact (System Owner):** [SYSTEM OWNER — TBD] — issues affecting assessment scope or timeline
- **AO Briefing:** Preliminary findings briefing scheduled for Week 7; final SAR delivery in Week 8

### 7.5 Stop Conditions

The assessment shall be suspended and the AO immediately notified if:

- A Critical vulnerability is discovered that poses immediate operational risk
- Evidence of active exploitation or unauthorized access is identified
- Assessment activities cause unintended disruption to production systems
- A conflict of interest is identified involving an assessment team member

---

## 8. Reporting Requirements

### 8.1 Security Assessment Report (SAR)

The primary output of this assessment is the Security Assessment Report (SAR), located at `compliance/sar/SAR_2026Q1.md`. The SAR shall include:

- Executive summary of overall risk posture
- Assessment scope and methodology
- Summary of findings (all open POA&M items plus new findings)
- Detailed findings with descriptions, evidence, risk levels, and recommendations
- Residual risk summary
- Assessor certification

### 8.2 Interim Communications

- **Weekly status emails** from the SCA to the ISSO summarizing activities and any emerging issues
- **Stop-condition notifications** per Section 7.5 above
- **Preliminary findings briefing** (Week 7) to ISSO and System Owner

### 8.3 Finding Severity Definitions

| Severity          | Definition                                                                                  | CVSS Range (Reference) |
| ----------------- | ------------------------------------------------------------------------------------------- | ---------------------- |
| **Critical**      | Exploitation would result in catastrophic impact to C, I, or A; immediate action required   | 9.0–10.0               |
| **High**          | Exploitation would result in severe impact; remediation required before ATO                 | 7.0–8.9                |
| **Moderate**      | Exploitation would result in significant impact; remediation required within 90 days of ATO | 4.0–6.9                |
| **Low**           | Exploitation would result in limited impact; remediation recommended within 180 days        | 0.1–3.9                |
| **Informational** | No direct exploitability; best-practice recommendation                                      | N/A                    |

### 8.4 Finding Status Definitions

| Status            | Definition                                                                  |
| ----------------- | --------------------------------------------------------------------------- |
| **Open**          | Finding confirmed; no remediation in place                                  |
| **In Progress**   | Remediation actions underway; not yet verified complete                     |
| **Resolved**      | Remediation implemented and verified by assessor                            |
| **Risk Accepted** | AO has formally accepted the residual risk; no further remediation required |

---

## 9. Appendix A: Control Assessment Checklist

The following table defines the assessment method, depth, coverage, and evidence sources for all 13 priority controls. Assessment methods use SP 800-53A terminology: **E** = Examine, **I** = Interview, **T** = Test.

| #   | Control ID | Control Name                               | Methods | Depth         | Coverage       | Primary Evidence Sources                                                                                                                                                         | Notes                                 |
| --- | ---------- | ------------------------------------------ | ------- | ------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| 1   | AC-2       | Account Management                         | E, I    | Comprehensive | Representative | IAM Terraform bindings; GKE RBAC manifests; ISSO interview on provisioning process; service account inventory                                                                    | POAM-001: No documented procedures    |
| 2   | AC-3       | Access Enforcement                         | E, I, T | Comprehensive | Representative | OPA policy tests; HMAC seal configuration; governance middleware code review; bypass test scenarios                                                                              | POAM-012: Bypass when env var unset   |
| 3   | AU-2       | Event Logging                              | E, I    | Basic         | Representative | Langfuse configuration; OpenTelemetry span definitions; interview ISSO on log coverage                                                                                           | Verify coverage across all components |
| 4   | AU-12      | Audit Record Generation                    | E, I, T | Comprehensive | Representative | `scripts/automated_auditor.py` code review; Langfuse trace samples; OTel endpoint config; Lula validation (`compliance/lula/lula-validation-au12.yaml`)                          | POAM-003: Mock trace generator        |
| 5   | IA-3       | Device Identification and Authentication   | E, I, T | Comprehensive | Representative | Inter-service HMAC configuration; `deployment/k8s/` service mesh absence; Istio/cert-manager assessment; mTLS test                                                               | POAM-007: No intra-cluster mTLS       |
| 6   | IA-5       | Authenticator Management                   | E, I    | Comprehensive | Representative | Kubernetes secrets configuration; GCP Secret Manager usage; `CAGE_ROUTING_SEAL_SECRET` rotation policy; ISSO interview                                                           | POAM-014: No rotation schedule        |
| 7   | RA-5       | Vulnerability Monitoring and Scanning      | E, I, T | Comprehensive | Representative | GitHub Actions workflow (`.github/workflows/security-scan.yml`); Trivy execution; pip-audit results; Lula validation (`compliance/lula/lula-validation-ra5.yaml`)                | POAM-010: No CI/CD scanning           |
| 8   | SC-8       | Transmission Confidentiality and Integrity | E, I, T | Comprehensive | Representative | TLS configuration on gRPC/REST endpoints; `tests/test_gateway_connectivity.py`; certificate validity; network policy review                                                      | POAM-011: No TLS assertion in tests   |
| 9   | SI-2       | Flaw Remediation                           | E, I, T | Comprehensive | Representative | `pyproject.toml` and `requirements.txt` version constraints; pip-audit results; Trivy CVE report; patching SLA documentation                                                     | POAM-013: Unpinned dependencies       |
| 10  | CM-6       | Configuration Settings                     | E, I, T | Basic         | Representative | CIS Kubernetes Benchmark compliance; Lula validation (`compliance/lula/lula-validation-cm6.yaml`); security context configuration (`deployment/k8s/security-context-patch.yaml`) | Verify hardened security contexts     |
| 11  | CM-8       | System Component Inventory                 | E, I    | Comprehensive | Representative | SBOM generation status; container image inventory; dependency manifest completeness; DevSecOps interview                                                                         | POAM-006: No SBOM                     |
| 12  | IR-1       | Incident Response Policy and Procedures    | E, I    | Comprehensive | Comprehensive  | IRP document existence and completeness; interview ISSO on incident handling; notification procedures                                                                            | POAM-008: No IRP document             |
| 13  | IR-6       | Incident Reporting                         | E, I    | Comprehensive | Comprehensive  | Incident reporting procedures; external notification timelines; regulatory reporting requirements (SEC Reg S-P)                                                                  | POAM-008: No IRP                      |

---

## 10. Approval and Signatures

This Security Assessment Plan has been reviewed and approved by the following parties.

### System Owner Approval

I approve this Security Assessment Plan and authorize the assessment team to conduct the activities described herein within the defined scope and rules of engagement.

| Field        | Value                                      |
| ------------ | ------------------------------------------ |
| Name         | [SIGNATURE REQUIRED — PENDING AO APPROVAL] |
| Title        | System Owner                               |
| Organization | [TBD]                                      |
| Date         | [TBD]                                      |

### ISSO Concurrence

I concur with the assessment scope, schedule, and rules of engagement defined in this plan.

| Field        | Value                                      |
| ------------ | ------------------------------------------ |
| Name         | [SIGNATURE REQUIRED — PENDING AO APPROVAL] |
| Title        | Information System Security Officer        |
| Organization | [TBD]                                      |
| Date         | [TBD]                                      |

### Authorizing Official Acknowledgment

I acknowledge receipt of this Security Assessment Plan and authorize the commencement of assessment activities.

| Field        | Value                                      |
| ------------ | ------------------------------------------ |
| Name         | [SIGNATURE REQUIRED — PENDING AO APPROVAL] |
| Title        | Authorizing Official                       |
| Organization | [TBD]                                      |
| Date         | [TBD]                                      |

---

