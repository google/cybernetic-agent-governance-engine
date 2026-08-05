# FIPS 199 / NIST SP 800-60 Security Categorization

**Document Control**

| Field                                      | Value                                                               |
| ------------------------------------------ | ------------------------------------------------------------------- |
| System Name                                | Cybernetic AI Governance Engine (CAGE) — Governed Financial Advisor |
| System Abbreviation                        | CAGE                                                                |
| System Owner                               | [SYSTEM OWNER NAME — TBD]                                           |
| Information System Security Officer (ISSO) | [ISSO NAME — TBD]                                                   |
| Authorizing Official (AO)                  | [AO NAME — TBD]                                                     |
| Document Date                              | 2026-03-06                                                          |
| Version                                    | 1.0 (Draft)                                                         |
| Classification                             | UNCLASSIFIED                                                        |
| Status                                     | DRAFT — Pending AO Signature                                        |

---

## 1. Purpose

This Security Categorization document establishes the security category for the Cybernetic AI Governance Engine (CAGE) in accordance with:

- **FIPS 199** — Standards for Security Categorization of Federal Information and Information Systems
- **NIST SP 800-60 Vol. I & II** — Guide for Mapping Types of Information and Information Systems to Security Categories
- **NIST SP 800-37 Rev. 2** — Risk Management Framework for Information Systems and Organizations

The security category determined herein drives the selection of security controls from the NIST SP 800-53 Rev. 5 control catalog and informs the Authorization to Operate (ATO) decision.

---

## 2. System Description

The Cybernetic AI Governance Engine (CAGE) is an AI-native financial advisory platform that:

- Orchestrates multi-agent LLM workflows for investment analysis and trade recommendations
- Enforces governance policies via OPA (Open Policy Agent) Rego rules and NeMo Guardrails Colang definitions
- Applies STPA (Systems-Theoretic Process Analysis) validation to AI decision paths
- Detects and redacts PII in real time using NeMo Guardrails Presidio (15 entity types)
- Produces ISO 42001-compliant audit trails via OpenTelemetry spans stored in Langfuse
- Screens trade recommendations against OFAC sanctions lists
- Exposes a gRPC/REST hybrid gateway for downstream consumption

The system operates on Google Kubernetes Engine (GKE) and ingests market data, executes AI inference via LLM providers, and surfaces governed financial recommendations to end users.

---

## 3. Information Types and Impact Levels

Information types are classified per **NIST SP 800-60 Volume II**. Impact levels (Low / Moderate / High) reflect potential adverse effects on organizational operations, assets, or individuals.

| IT ID  | Information Type Name              | SP 800-60 Identifier | Confidentiality | Integrity | Availability | PII? |
| ------ | ---------------------------------- | -------------------- | --------------- | --------- | ------------ | ---- |
| IT-001 | Financial Trade Execution Data     | C.2.8.12             | **Moderate**    | **High**  | **Moderate** | No   |
| IT-002 | AI Model Inference Outputs         | D.14.1               | **Moderate**    | **High**  | **Moderate** | No   |
| IT-003 | Audit and Accountability Records   | D.16.1               | **Low**         | **High**  | **Moderate** | No   |
| IT-004 | PII / Individual Financial Records | D.2.2                | **High**        | **High**  | **Low**      | Yes  |
| IT-005 | Governance Policy Configurations   | C.3.5.1              | **Moderate**    | **High**  | **High**     | No   |

### 3.1 Information Type Justifications

#### IT-001 — Financial Trade Execution Data (C.2.8.12)

- **Confidentiality = Moderate:** Unauthorized disclosure of trade data could enable front-running or market manipulation, causing significant financial harm, but does not rise to catastrophic national-security-level harm.
- **Integrity = High:** Unauthorized modification of trade orders, positions, or AI-generated recommendations could result in severe financial loss, regulatory violations (SEC Rule 17a-4, FINRA 4511), and reputational damage.
- **Availability = Moderate:** Temporary unavailability causes operational disruption and financial impact but is recoverable; markets have known trading windows.

#### IT-002 — AI Model Inference Outputs (D.14.1)

- **Confidentiality = Moderate:** Governance verdicts and risk scores contain proprietary methodology; disclosure causes competitive harm but not catastrophic harm.
- **Integrity = High:** Tampered AI outputs could bypass governance controls and cause compliant-looking but harmful financial recommendations to be executed. Violates SR 11-7 model risk management requirements.
- **Availability = Moderate:** System degrades gracefully via fail-safe governance blocks; temporary unavailability is operationally impactful but recoverable.

#### IT-003 — Audit and Accountability Records (D.16.1)

- **Confidentiality = Low:** Audit logs are by design shareable for regulatory examination; they do not contain sensitive content beyond operational metadata.
- **Integrity = High:** Tampered audit records undermine the ISO 42001 evidence chain, obstruct regulatory examination (SEC Rule 17a-4, FINRA 4511), and constitute a regulatory violation.
- **Availability = Moderate:** Loss of audit trails impairs post-incident analysis but does not immediately halt operations.

#### IT-004 — PII / Individual Financial Records (D.2.2)

- **Confidentiality = High:** Unauthorized disclosure of investor PII (names, financial data, investment profiles) causes severe privacy harm, triggers SEC Reg S-P / FINRA notification obligations, and constitutes a reportable breach.
- **Integrity = High:** Corrupted PII records could cause incorrect financial decisions, regulatory non-compliance, and legal liability.
- **Availability = Low:** PII records are not time-critical for system operation; limited availability impact.

#### IT-005 — Governance Policy Configurations (C.3.5.1)

- **Confidentiality = Moderate:** Exposure of Rego policies and Colang rail definitions reveals proprietary governance logic and could assist adversarial bypass attempts.
- **Integrity = High:** Tampered governance policies could silently disable safety controls, allowing prohibited trade actions or PII exfiltration to proceed undetected.
- **Availability = High:** Governance policies must be continuously available; their unavailability causes the system to fail-safe (blocking all AI inference), which is operationally unacceptable during trading hours.

---

## 4. Overall System Security Category

Per **FIPS 199 §3**, the system security category is determined by taking the high-water mark across all information types for each security objective:

```
SC_CAGE = {
  (confidentiality, HIGH),    ← driven by IT-004 PII (C=High)
  (integrity, HIGH),          ← driven by IT-001, IT-002, IT-003, IT-004, IT-005 (I=High)
  (availability, HIGH)        ← driven by IT-005 Governance Policy Configs (A=High)
}
```

> **Overall System Security Category: HIGH**

### 4.1 FIPS 199 Formula

```
SC_system = {(confidentiality, impact), (integrity, impact), (availability, impact)}

Where impact = MAX(impact_level across all information types for that objective)

SC_CAGE = {(confidentiality, HIGH), (integrity, HIGH), (availability, HIGH)}
```

**Resulting Baseline:** NIST SP 800-53 Rev. 5 **HIGH** impact baseline applies. This requires implementation and assessment of all HIGH baseline controls.

---

## 5. Applicable Regulatory Drivers

| Regulation / Guidance         | Applicability to CAGE                                                                                                                          |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| **SEC Rule 17a-4**            | Requires preservation of electronic records (trade data, audit logs) in non-rewriteable, non-erasable format for 6 years                       |
| **FINRA Rule 4511**           | Requires preservation of books and records; governs electronic storage media requirements                                                      |
| **OFAC Sanctions Screening**  | All trade recommendations must be screened against OFAC SDN list; blocking violations is mandatory                                             |
| **SEC Reg S-P**               | Requires safeguarding of nonpublic customer financial information (PII); breach notification obligations                                       |
| **FINRA**                     | General broker-dealer conduct rules apply to AI-generated recommendations                                                                      |
| **SR 11-7 (Federal Reserve)** | Model Risk Management guidance applies to AI/ML models used in financial decisions; requires validation, documentation, and ongoing monitoring |
| **ISO/IEC 42001:2023**        | AI Management System standard; CAGE implements ISO 42001 audit trail requirements                                                              |
| **NIST SP 800-53 Rev. 5**     | Security and Privacy Controls baseline — HIGH impact selected                                                                                  |
| **NIST AI RMF 1.0**           | AI Risk Management Framework — informs AI-specific control selection                                                                           |

---

## 6. Special Factors and Considerations

### 6.1 AI-Specific Risk Factors

CAGE presents novel security categorization challenges due to its AI-native architecture:

- **Model Output Integrity:** LLM outputs are non-deterministic; integrity controls must address prompt injection, hallucination, and adversarial manipulation
- **Governance Bypass Risk:** The `CAGE_ROUTING_SEAL_SECRET` bypass mechanism (POAM-012) represents a critical integrity risk that elevates the effective integrity impact
- **Multi-Agent Trust:** Agent-to-agent communication is protected by both HMAC routing seal and Linkerd mTLS (POAM-007 Closed 2026-05-17 via `deployment/k8s/linkerd-mtls-policy.yaml`), providing defense-in-depth for intra-cluster inter-service integrity

### 6.2 PII Processing Scope

CAGE processes PII through NeMo Guardrails Presidio detection covering 15 entity types including names, financial account numbers, tax identifiers, and investment profile data. This triggers **High** confidentiality impact per D.2.2.

### 6.3 Critical Infrastructure Consideration

Financial advisory systems serving retail investors may be considered part of the Financial Services critical infrastructure sector. This does not change the FIPS 199 category but informs resilience planning.

---

## 7. Signature Blocks

This Security Categorization document requires signatures from the System Owner and the Authorizing Official before it becomes effective.

### 7.1 System Owner Concurrence

I concur with the security categorization of the Cybernetic AI Governance Engine (CAGE) as described in this document.

| Field        | Value                              |
| ------------ | ---------------------------------- |
| Name         | ****************\_**************** |
| Title        | System Owner                       |
| Organization | ****************\_**************** |
| Signature    | ****************\_**************** |
| Date         | ****************\_**************** |

### 7.2 ISSO Concurrence

I have reviewed this security categorization and confirm it accurately reflects the information types and impact levels for the CAGE system.

| Field        | Value                               |
| ------------ | ----------------------------------- |
| Name         | ****************\_****************  |
| Title        | Information System Security Officer |
| Organization | ****************\_****************  |
| Signature    | ****************\_****************  |
| Date         | ****************\_****************  |

### 7.3 Authorizing Official Approval

I approve the security categorization of the Cybernetic AI Governance Engine (CAGE) as **HIGH** impact. This categorization shall govern the selection of security controls and the conduct of the authorization process.

| Field        | Value                              |
| ------------ | ---------------------------------- |
| Name         | ****************\_**************** |
| Title        | Authorizing Official               |
| Organization | ****************\_**************** |
| Signature    | ****************\_**************** |
| Date         | ****************\_**************** |

---

## 8. Document History

| Version   | Date       | Author | Description                                                      |
| --------- | ---------- | ------ | ---------------------------------------------------------------- |
| 1.0 Draft | 2026-03-06 | [ISSO] | Initial draft created as part of NIST RMF Phase 0 implementation |

---

_This document is controlled. Unauthorized modification invalidates the security categorization and requires AO re-approval._
