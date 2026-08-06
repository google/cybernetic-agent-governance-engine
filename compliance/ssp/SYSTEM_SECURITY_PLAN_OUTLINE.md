# System Security Plan (SSP) — Outline and Scaffold

**System:** Cybernetic AI Governance Engine (CAGE) — Governed Financial Advisor  
**Reference:** NIST SP 800-18 Rev. 1 — Guide for Developing Security Plans for Federal Information Systems  
**NIST SP 800-53 Rev. 5 Baseline:** HIGH Impact  
**Version:** 0.1 (Stub — Pending ISSO Population)  
**Date:** 2026-03-06  
**Status:** STUB — Each section contains placeholder text for ISSO completion

> **⚠ NOTE TO ISSO:** This document is a scaffold. Each section contains a description of what is required. Replace all placeholder text with actual system-specific content. Target completion date: 2026-06-30 (see POAM-015).

---

## Section 1 — System Identification

_This section provides the basic identifying information for the information system. Include the system name, acronym, system identifier assigned by the organization, and any federal identifiers (e.g., FISMA unique identifier). Document the system boundary narrative — what is included in and excluded from the authorization boundary. Cross-reference the system description in the architecture documentation._

| Field                  | Value                                                                                                                                                                |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| System Name            | Cybernetic AI Governance Engine (CAGE) — Governed Financial Advisor                                                                                                  |
| System Acronym         | CAGE                                                                                                                                                                 |
| System Identifier      | [ASSIGN — e.g., CAGE-2026-001]                                                                                                                                       |
| System Version         | [CURRENT VERSION — TBD]                                                                                                                                              |
| Authorization Boundary | [DESCRIBE BOUNDARY — include GKE cluster, Cloud SQL, GCS, external LLM API dependencies, Langfuse, Redis. Exclude: end-user devices, external market data providers] |
| System Environment     | Google Kubernetes Engine (GKE) on Google Cloud Platform (GCP), region [TBD]                                                                                          |
| Deployment Model       | Cloud-hosted (GCP), containerized microservices                                                                                                                      |

**Authorization Boundary Narrative:**

[ISSO to provide 1–2 paragraphs describing exactly what hardware, software, data, and communications are within the authorization boundary. Reference `ARCHITECTURE.md` and `docs/GATEWAY_ARCHITECTURE.md` for system topology. Explicitly state what is inherited from GCP/GKE (Common Control Provider) and what is system-specific.]

---

## Section 2 — System Categorization

_This section documents the security impact level for the information system as determined through the FIPS 199 process. Do not re-derive the categorization here; instead, cross-reference the formal categorization document and summarize the result._

**Cross-reference:** [`compliance/categorization/FIPS199_CATEGORIZATION.md`](../../compliance/categorization/FIPS199_CATEGORIZATION.md)

**Overall Security Category (per FIPS 199):**

```
SC_CAGE = {(confidentiality, HIGH), (integrity, HIGH), (availability, HIGH)}
```

**Applicable Baseline:** NIST SP 800-53 Rev. 5 **HIGH** impact baseline

[ISSO to summarize the rationale from the FIPS 199 document in 2–3 sentences, noting the primary drivers (PII confidentiality = HIGH; financial/AI output integrity = HIGH; governance policy availability = HIGH).]

---

## Section 3 — System Owner

_Provide the name, title, organization, address, phone, and email address of the person who owns the information system. The System Owner is responsible for the overall procurement, development, integration, modification, operation, maintenance, and disposal of the system._

| Field        | Value                     |
| ------------ | ------------------------- |
| Name         | [SYSTEM OWNER NAME — TBD] |
| Title        | [TITLE — TBD]             |
| Organization | [ORGANIZATION — TBD]      |
| Address      | [ADDRESS — TBD]           |
| Phone        | [PHONE — TBD]             |
| Email        | [EMAIL — TBD]             |

**Signature:** ****************\_**************** **Date:** ******\_******

---

## Section 4 — Authorizing Official

_Provide the name, title, organization, and contact information for the Authorizing Official (AO) responsible for issuing the Authorization to Operate (ATO). The AO is the senior official who bears ultimate responsibility for the risk decision._

| Field        | Value                |
| ------------ | -------------------- |
| Name         | [AO NAME — TBD]      |
| Title        | [TITLE — TBD]        |
| Organization | [ORGANIZATION — TBD] |
| Address      | [ADDRESS — TBD]      |
| Phone        | [PHONE — TBD]        |
| Email        | [EMAIL — TBD]        |

**Signature:** ****************\_**************** **Date:** ******\_******

---

## Section 5 — Other Designated Contacts

_List other individuals who have security roles and responsibilities for this system. Typically includes the ISSO, Deputy ISSO (if applicable), and any other designated contacts the AO or System Owner should be able to reach._

| Role                 | Name              | Organization | Phone   | Email   |
| -------------------- | ----------------- | ------------ | ------- | ------- |
| ISSO                 | [ISSO NAME — TBD] | [ORG]        | [PHONE] | [EMAIL] |
| Compliance Engineer  | [NAME — TBD]      | [ORG]        | [PHONE] | [EMAIL] |
| AI Model Operator    | [NAME — TBD]      | [ORG]        | [PHONE] | [EMAIL] |
| System Administrator | [NAME — TBD]      | [ORG]        | [PHONE] | [EMAIL] |

[Add rows for all individuals with a security role for this deployment.]

---

## Section 6 — Assignment of Security Responsibility

_Document who is designated as the Information System Security Officer (ISSO) or equivalent. Include a signed acknowledgement from the ISSO accepting security responsibility. Reference the full Roles and Responsibilities document for complete role definitions._

[A real deployment maintains its own Roles and Responsibilities document as a cross-reference here.]

The following individual has been designated as the ISSO for the CAGE system and accepts responsibility for coordinating and overseeing all security activities:

| Field            | Value             |
| ---------------- | ----------------- |
| ISSO Name        | [ISSO NAME — TBD] |
| Designation Date | [DATE — TBD]      |

**ISSO Acknowledgement Signature:** ****************\_**************** **Date:** ******\_******

---

## Section 7 — System Operational Status

_Indicate the operational status of the system. Select the appropriate status and document any planned changes._

**Current Status:** ☐ Operational ☐ Under Development ☑ **Major Modification** (Undergoing NIST RMF authorization for the first time)

[ISSO to describe the current development/deployment state: which components are in production, which are in development, and any planned major changes that could affect the authorization boundary within the next 12 months.]

---

## Section 8 — Information System Type

_Classify the information system type. Indicate whether it is a Major Application, General Support System, or Minor Application._

**System Type:** ☑ **Major Application** — CAGE provides AI-governed financial advisory functions with security implications for financial data and PII, requiring its own authorization.

[ISSO to provide 2–3 sentences explaining why CAGE qualifies as a Major Application rather than a General Support System, referencing its financial advisory mission, PII processing, and regulatory obligations.]

---

## Section 9 — General System Description / Purpose

_Describe the system's purpose, mission, and functions in plain language. This section should be understandable by a non-technical reader. Include the primary business functions the system supports, the user population, and the key technical capabilities._

[ISSO to write a 3–5 paragraph description of the CAGE system, drawing from `README.md`, `FUNCTIONAL_SPEC.md`, and `ARCHITECTURE.md`. Cover: (1) mission — AI-governed financial advisory; (2) multi-agent LLM orchestration via LangGraph; (3) governance enforcement via OPA Rego + NeMo Guardrails Colang; (4) PII detection and redaction; (5) ISO 42001 audit trail generation; (6) OFAC screening. Describe the intended user population and operational environment.]

---

## Section 10 — System Environment and Special Considerations

_Describe the technical environment in which the system operates. Include hardware, software, network topology, and any special security considerations such as high-risk environments, mobile code, public access, or AI/ML components._

**Infrastructure:** Google Kubernetes Engine (GKE) on Google Cloud Platform (GCP)

**Special Considerations:**

1. **AI/ML Components:** CAGE uses Large Language Models (LLMs) from third-party providers (OpenAI, Anthropic, Google). LLM inference introduces non-deterministic outputs and adversarial manipulation risks not present in traditional systems. Refer to NIST AI RMF 1.0 and SR 11-7 for applicable AI risk management requirements.

2. **External LLM API Dependencies:** AI inference is performed by external cloud-hosted LLM providers. Data sent to these providers must be pre-processed by NeMo Guardrails PII detection to prevent PII egress. This external dependency is out-of-boundary but represents a significant third-party risk.

3. **Financial Regulatory Environment:** System operates subject to SEC Rule 17a-4 (records retention), FINRA 4511 (books and records), and OFAC sanctions screening requirements. These regulatory obligations impose additional controls beyond the NIST SP 800-53 HIGH baseline.

[ISSO to complete this section with specific GKE cluster configuration details, network topology (referencing `docs/GATEWAY_ARCHITECTURE.md`), and any additional special considerations identified during security categorization.]

---

## Section 11 — System Interconnections / Information Sharing

_List all external systems and services that the CAGE system connects to or shares information with. For each interconnection, document the data exchanged, the communication method, and the security controls protecting the connection._

| Interconnection ID | External System                     | Data Exchanged                      | Direction      | Protocol/Port | Security Controls                 | Agreement Type         |
| ------------------ | ----------------------------------- | ----------------------------------- | -------------- | ------------- | --------------------------------- | ---------------------- |
| IC-001             | OpenAI / Anthropic / Google LLM API | AI inference requests/responses     | Outbound       | HTTPS/443     | TLS 1.3, PII redaction pre-egress | [MOU/ISA — TBD]        |
| IC-002             | OFAC Sanctions Screening API        | Trade recommendation screening data | Outbound       | HTTPS/443     | TLS 1.3                           | [Agreement type — TBD] |
| IC-003             | Langfuse (self-hosted or SaaS)      | OTel traces, audit records          | Outbound       | HTTPS/443     | TLS 1.3, API key auth             | [Agreement type — TBD] |
| IC-004             | Market Data Provider                | Real-time market prices/data        | Inbound        | HTTPS/443     | TLS 1.3                           | [Agreement type — TBD] |
| IC-005             | GCP Cloud Audit Logs                | Infrastructure audit events         | Internal (GCP) | GCP internal  | GCP-managed                       | GCP Terms of Service   |

[ISSO to complete with specific API endpoints, finalize agreement types, and document any Interconnection Security Agreements (ISAs) required per NIST SP 800-47.]

---

## Section 12 — Laws, Regulations, and Policies Applicable

_List all laws, regulations, policies, standards, and guidance documents applicable to this information system and its data._

| Category                   | Document                             | Applicability                                     |
| -------------------------- | ------------------------------------ | ------------------------------------------------- |
| Federal Security Standards | FIPS 140-2 / 140-3                   | Cryptographic module requirements                 |
| Federal Security Standards | FIPS 199                             | Security categorization                           |
| NIST Guidance              | NIST SP 800-53 Rev. 5                | Security and privacy control baseline (HIGH)      |
| NIST Guidance              | NIST SP 800-37 Rev. 2                | Risk Management Framework process                 |
| NIST Guidance              | NIST SP 800-60 Vol. I & II           | Information type categorization                   |
| NIST Guidance              | NIST SP 800-61 Rev. 2                | Incident response                                 |
| NIST Guidance              | NIST SP 800-171                      | CUI protection (if applicable)                    |
| NIST Guidance              | NIST AI RMF 1.0                      | AI risk management                                |
| Financial Regulation       | SEC Rule 17a-4                       | Electronic records preservation (6 years)         |
| Financial Regulation       | FINRA Rule 4511                      | Books and records requirements                    |
| Financial Regulation       | SEC Reg S-P                          | Customer PII safeguarding and breach notification |
| Financial Regulation       | OFAC Regulations                     | Sanctions screening for all transactions          |
| Federal Reserve Guidance   | SR 11-7                              | Model risk management for AI/ML                   |
| International Standard     | ISO/IEC 42001:2023                   | AI Management System                              |
| International Standard     | ISO/IEC 27001:2022                   | Information security management (reference)       |
| Organizational Policy      | [ORGANIZATION SECURITY POLICY — TBD] | Organizational security requirements              |

---

## Section 13 — Minimum Security Controls

_This section references the applicable security controls from NIST SP 800-53 Rev. 5 HIGH impact baseline. Full control implementation statements are maintained as machine-readable OSCAL data._

**Applicable Baseline:** NIST SP 800-53 Rev. 5 HIGH impact baseline (325+ controls)

**OSCAL Control Implementation Data:**  
Full control implementation statements are (or will be) maintained in machine-readable OSCAL format at:

- [`compliance/oscal/component-definition.yaml`](../../compliance/oscal/component-definition.yaml) _(to be created — see POAM-015)_
- Automated compliance validation: Lula specification files in `compliance/oscal/` _(to be created)_

**Control Selection Notes:**

- All NIST SP 800-53 Rev. 5 HIGH baseline controls apply
- AI-specific control enhancements (e.g., SR family for supply chain, PM family for program management) are included
- Privacy controls (PT family) apply due to PII processing (see IT-004)
- Controls inherited from GCP/GKE Common Control Provider are designated as INHERITED in the OSCAL component definition

[ISSO: Do not attempt to document all control implementation statements in this markdown file. Use the OSCAL format in `compliance/oscal/` for machine-readable control statements that can be processed by Lula for automated compliance checking. Use Appendix A of this document for a summary view of the highest-priority controls.]

---

## Section 14 — Information System Security Plan Completion Date

**Target SSP Completion Date:** 2026-06-30 _(see POAM-015)_

**Planned Review Frequency:** Annually, or within 30 days of a significant change to the system

| Milestone                                    | Target Date | Status      |
| -------------------------------------------- | ----------- | ----------- |
| SSP Outline / Scaffold (this document)       | 2026-03-06  | ✅ Complete |
| Section 9–12 narrative completion            | 2026-04-30  | ⬜ Pending  |
| OSCAL component definition creation          | 2026-05-15  | ⬜ Pending  |
| All HIGH baseline control statements drafted | 2026-06-15  | ⬜ Pending  |
| System Owner and AO review                   | 2026-06-20  | ⬜ Pending  |
| Final SSP approved                           | 2026-06-30  | ⬜ Pending  |

---

## Section 15 — Information System Security Plan Approval

_The following signatures indicate approval of this System Security Plan._

### System Owner

I approve this System Security Plan and commit to implementing the described security controls.

| Field     | Value                              |
| --------- | ---------------------------------- |
| Name      | ****************\_**************** |
| Title     | System Owner                       |
| Signature | ****************\_**************** |
| Date      | ****************\_**************** |

### ISSO

I certify that this System Security Plan accurately represents the security posture of the CAGE system.

| Field     | Value                               |
| --------- | ----------------------------------- |
| Name      | ****************\_****************  |
| Title     | Information System Security Officer |
| Signature | ****************\_****************  |
| Date      | ****************\_****************  |

### Authorizing Official

I approve this System Security Plan as part of the authorization package for the CAGE system.

| Field     | Value                              |
| --------- | ---------------------------------- |
| Name      | ****************\_**************** |
| Title     | Authorizing Official               |
| Signature | ****************\_**************** |
| Date      | ****************\_**************** |

---

## Appendix A — Control Implementation Summary Table (Priority Controls)

_This table provides a high-level summary of implementation status for the highest-priority controls. Detailed implementation statements are maintained in OSCAL format._

| #   | Control ID | Control Name                                             | Implementation Status | Origin    | Notes                                                  |
| --- | ---------- | -------------------------------------------------------- | --------------------- | --------- | ------------------------------------------------------ |
| 1   | AC-2       | Account Management                                       | ⬜ Planned            | System    | See POAM-001: no formal procedures exist               |
| 2   | AC-6       | Least Privilege                                          | ⬜ Planned            | System    | See POAM-002: IAM bindings need remediation            |
| 3   | AU-2       | Event Logging                                            | 🔶 Partial            | System    | OTel spans configured; mock traces issue (POAM-003)    |
| 4   | AU-12      | Audit Record Generation                                  | 🔶 Partial            | System    | See POAM-003: synthetic traces in auditor.py           |
| 5   | CA-5       | Plan of Action and Milestones                            | 🔶 In Progress        | System    | This POA&M document (POAM-004)                         |
| 6   | CA-6       | Authorization                                            | ⬜ Planned            | System    | No ATO exists (POAM-005)                               |
| 7   | CA-7       | Continuous Monitoring                                    | 🔶 Partial            | System    | Langfuse monitoring active; formal process TBD         |
| 8   | CM-8       | System Component Inventory                               | ⬜ Planned            | System    | No SBOM (POAM-006)                                     |
| 9   | IA-3       | Device Identification and Authentication                 | ⬜ Planned            | System    | No mTLS (POAM-007)                                     |
| 10  | IR-1       | Incident Response Policy                                 | ⬜ Planned            | System    | No IRP document (POAM-008)                             |
| 11  | PL-2       | System Security Plan                                     | 🔶 In Progress        | System    | This document (POAM-015)                               |
| 12  | RA-2       | Security Categorization                                  | 🔶 In Progress        | System    | FIPS 199 doc created; awaiting AO signature (POAM-009) |
| 13  | RA-5       | Vulnerability Monitoring and Scanning                    | ⬜ Planned            | System    | No CI vulnerability scanning (POAM-010)                |
| 14  | SC-8       | Transmission Confidentiality and Integrity               | 🔶 Partial            | Hybrid    | TLS configured; no automated validation (POAM-011)     |
| 15  | SC-12      | Cryptographic Key Establishment and Management           | 🔶 Partial            | System    | HMAC routing seal; bypass risk (POAM-012)              |
| 16  | SC-28      | Protection of Information at Rest                        | 🔶 Partial            | Inherited | GCP default encryption; CMEK not validated (POAM-014)  |
| 17  | SI-2       | Flaw Remediation                                         | ⬜ Planned            | System    | Dependencies unpinned (POAM-013)                       |
| 18  | SI-3       | Malware Protection                                       | ✅ Inherited          | Inherited | GCP Cloud Security Command Center                      |
| 19  | SI-10      | Information Input Validation                             | ✅ Implemented        | System    | NeMo Guardrails Colang rails enforce input validation  |
| 20  | PT-2       | Authority to Process Personally Identifiable Information | 🔶 Partial            | System    | PII detection implemented; formal PIA TBD              |

**Legend:**

- ✅ Implemented — Control is fully implemented and operating effectively
- 🔶 Partial — Control is partially implemented; gaps documented in POA&M
- ⬜ Planned — Control implementation is planned; not yet started
- Inherited — Control is fully inherited from GCP/GKE Common Control Provider
- Hybrid — Control is partially inherited; system-specific implementation required

---

## Appendix B — Related Documents

_The following documents constitute the NIST RMF authorization package and related compliance artifacts for the CAGE system._

### Authorization Package Documents

| Document                              | Location                                                                                             | Status                       |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------- | ---------------------------- |
| FIPS 199 Security Categorization      | [`compliance/categorization/FIPS199_CATEGORIZATION.md`](../categorization/FIPS199_CATEGORIZATION.md) | Draft — Pending AO Signature |
| System Security Plan (this document)  | [`compliance/ssp/SYSTEM_SECURITY_PLAN_OUTLINE.md`](SYSTEM_SECURITY_PLAN_OUTLINE.md)                  | Stub — Pending Completion    |
| Plan of Action and Milestones         | [`docs/POAM.md`](../../docs/POAM.md)                                                                                                                                 | Active (23 items)            |
| Roles and Responsibilities            | [Adopter-authored — not included in this reference architecture]                     | N/A                        |
| Information Type Registry             | [`compliance/oscal/information-type-registry.yaml`](../oscal/information-type-registry.yaml)         | Complete (v1.0)              |
| Security Assessment Report (SAR)      | TBD — to be created post-assessment                                                                  | Not Started                  |
| Authorization to Operate (ATO) Letter | TBD — issued by AO upon authorization                                                                | Not Started                  |

### NIST RMF Analysis Documents

| Document               | Location                                                                                         | Description                                               |
| ---------------------- | ------------------------------------------------------------------------------------------------ | --------------------------------------------------------- |
| Current State Analysis | [`docs/NIST_RMF_CHUNK1_CURRENT_STATE.md`](../../docs/compliance/us_fed/NIST_RMF_CHUNK1_CURRENT_STATE.md)           | Initial system security posture assessment                |
| Prepare & Categorize   | [`docs/NIST_RMF_CHUNK2_PREPARE_CATEGORIZE.md`](../../docs/compliance/us_fed/NIST_RMF_CHUNK2_PREPARE_CATEGORIZE.md) | RMF Prepare and Categorize step analysis                  |
| Select & Implement     | [`docs/NIST_RMF_CHUNK3_SELECT_IMPLEMENT.md`](../../docs/compliance/us_fed/NIST_RMF_CHUNK3_SELECT_IMPLEMENT.md)     | Control selection and implementation analysis             |
| Assess & Authorize     | [`docs/NIST_RMF_CHUNK4_ASSESS_AUTHORIZE.md`](../../docs/compliance/us_fed/NIST_RMF_CHUNK4_ASSESS_AUTHORIZE.md)     | Assessment and authorization readiness analysis           |
| Monitor & Roadmap      | [`docs/NIST_RMF_CHUNK5_MONITOR_ROADMAP.md`](../../docs/compliance/us_fed/NIST_RMF_CHUNK5_MONITOR_ROADMAP.md)       | Continuous monitoring strategy and implementation roadmap |

### Architecture and Design Documents

| Document             | Location                                                             | Description                                    |
| -------------------- | -------------------------------------------------------------------- | ---------------------------------------------- |
| System Architecture  | [`ARCHITECTURE.md`](../../docs/architecture/ARCHITECTURE.md)                           | High-level system architecture                 |
| Gateway Architecture | [`docs/GATEWAY_ARCHITECTURE.md`](../../docs/architecture/GATEWAY_ARCHITECTURE.md) | Inference gateway design                       |
| Governance Crosswalk | [`docs/GOVERNANCE_CROSSWALK.md`](../../docs/compliance/cross-region/GOVERNANCE_CROSSWALK.md) | Control crosswalk to governance implementation |
| ISO 42001 Compliance | [`docs/ISO_42001_COMPLIANCE.md`](../../docs/compliance/universal/ISO_42001_COMPLIANCE.md) | ISO 42001 AI management system compliance      |

### OSCAL Artifacts

| Artifact                     | Location                                                               | Description                                                | Status    |
| ---------------------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------- | --------- |
| Component Definition         | `compliance/oscal/component-definition.yaml`                          | OSCAL machine-readable control implementation statements (ISO 42001 AIMS) | ✅ Exists |
| System Security Plan — US_FED | `compliance/oscal/system-security-plan.yaml`                         | OSCAL SSP — NIST SP 800-53 Rev 5 HIGH + NIST AI 600-1     | ✅ Exists |
| System Security Plan — EU_ECB | `compliance/oscal/system-security-plan-eu-ecb.yaml`                  | OSCAL SSP — EU AI Act / GDPR Art. 22 / DORA               | ✅ Exists |
| System Security Plan — APAC_MAS | `compliance/oscal/system-security-plan-apac-mas.yaml`              | OSCAL SSP — MAS FEAT / MAS Notice 655 / MAS TRM §6.3      | ✅ Exists |
| Assessment Results           | `compliance/lula/assessment-results.yaml`                             | OSCAL assessment results (Lula-generated)                  | ✅ Exists |
| Assessment Plan              | `compliance/oscal/assessment-plan.yaml`                               | OSCAL assessment plan                                      | ⬜ Pending |
| POA&M (OSCAL)                | `compliance/oscal/plan-of-action-milestones.yaml`                     | OSCAL POA&M representation                                 | ⬜ Pending |
| Lula Specifications          | `compliance/lula/lula-validation-*.yaml`                              | Automated control validation specifications (29 manifests) | ✅ Exists |

---

_This document is a controlled artifact. All changes require ISSO review. Significant changes require AO notification._  
_Next scheduled review: 2026-06-30 (SSP completion milestone) or upon significant system change._
