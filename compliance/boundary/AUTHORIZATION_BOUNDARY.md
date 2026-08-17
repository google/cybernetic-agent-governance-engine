# Authorization Boundary Document

**System:** Cybernetic AI Governance Engine (CAGE) — Governed Financial Advisor
**Document Number:** BOUNDARY-CAGE-2026-001
**Reference:** NIST SP 800-37 Rev. 2; NIST SP 800-53 Rev. 5; FIPS 199
**Version:** 1.0 (Draft)
**Date:** 2026-03-06
**Classification:** UNCLASSIFIED
**Status:** DRAFT — Pending AO Approval

| Field                     | Value                                                                                                                                                                 |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| System Name               | Cybernetic AI Governance Engine (CAGE)                                                                                                                                |
| System Abbreviation       | CAGE                                                                                                                                                                  |
| System Owner              | [SYSTEM OWNER NAME — TBD]                                                                                                                                             |
| ISSO                      | [ISSO NAME — TBD]                                                                                                                                                     |
| Authorizing Official (AO) | [AO NAME — TBD]                                                                                                                                                       |
| Cloud Platform            | Google Kubernetes Engine (GKE) on Google Cloud Platform (GCP)                                                                                                         |
| Deployment Namespace      | `governance-stack`                                                                                                                                                                                    |
| Related Documents         | `compliance/categorization/FIPS199_CATEGORIZATION.md`, `compliance/rar/RISK_ASSESSMENT_REPORT.md`, `compliance/sar/SAR_2026Q1.md`, `docs/SECURITY_ASSESSMENT_PLAN.md` |

---

## 1. Purpose and Scope

### 1.1 Purpose

This Authorization Boundary Document defines the logical and technical boundary of the Cybernetic AI Governance Engine (CAGE) information system for purposes of security authorization under NIST SP 800-37 Rev. 2. The authorization boundary:

1. Identifies all system components that are subject to the CAGE security authorization
2. Identifies external systems and interconnections that exchange data with CAGE
3. Defines data flows across the boundary
4. Identifies security controls that are inherited from the Common Control Provider (GCP/GKE)
5. Provides a visual representation of the system boundary

The authorization boundary governs the scope of the Security Assessment Plan (`docs/SECURITY_ASSESSMENT_PLAN.md`), the Security Assessment Report (`compliance/sar/SAR_2026Q1.md`), and the System Security Plan (SSP).

### 1.2 Scope

The CAGE authorization boundary encompasses all hardware, software, firmware, data, people, procedures, and facilities that compose the CAGE system and are under the direct management authority of the CAGE System Owner. The boundary is instantiated within the Google Cloud Platform (GCP) project under the CAGE-designated GKE cluster and namespace (`governance-stack`).

---

## 2. System Authorization Boundary Definition

### 2.1 Boundary Statement

The CAGE authorization boundary encompasses all components deployed within the `governance-stack` Kubernetes namespace on the designated GKE cluster, including all associated GCP managed services (Cloud SQL PostgreSQL, Google Cloud Storage) provisioned exclusively for the CAGE system. The boundary also includes the infrastructure-as-code (Terraform) and CI/CD pipeline (GitHub Actions) used to provision and deploy CAGE components.

### 2.2 Boundary Criteria

A component is **within** the CAGE authorization boundary if:

- It is deployed in the `governance-stack` GKE namespace under CAGE System Owner control
- It is a GCP managed service (Cloud SQL, GCS) provisioned exclusively for CAGE
- It processes, transmits, or stores one or more of the five CAGE information types (IT-001 through IT-005)
- It is managed via CAGE Terraform infrastructure code (`infra/`)

A component is **outside** the CAGE authorization boundary if:

- It is a GCP/GKE platform control inherited from Google's FedRAMP authorization
- It is a shared SaaS service accessed via API (Langfuse, Vertex AI)
- It is not under the management authority of the CAGE System Owner

### 2.3 Impact Level

The CAGE system is categorized as **HIGH** impact per FIPS 199 (C=High, I=High, A=High). See `compliance/categorization/FIPS199_CATEGORIZATION.md` for full categorization.

---

## 3. Components Within Boundary

The following table enumerates all components within the CAGE authorization boundary:

| Component ID | Component Name              | Type                          | Location                              | Function                                                                                             | Data Types Processed           | POAM Issues                     |
| ------------ | --------------------------- | ----------------------------- | ------------------------------------- | ---------------------------------------------------------------------------------------------------- | ------------------------------ | ------------------------------- |
| COMP-001     | CAGE Gateway                | FastAPI/gRPC Application      | GKE `governance-stack` namespace             | Primary API gateway; routes requests through 8-tier governance pipeline (FTRA + 7 in-pipeline tiers); enforces HMAC routing seals | IT-001, IT-002, IT-004, IT-005 | POAM-012 (resolved)             |
| COMP-002     | NeMo Guardrails (in-process) | AI Safety Module             | GKE `governance-stack` namespace (integrated into gateway process) | Input/output safety filtering; PII detection (15 entity types); Colang rail enforcement | IT-001, IT-002, IT-004         | —                               |
| COMP-003     | OPA Policy Engine           | Authorization Engine          | GKE `governance-stack` namespace             | Rego-based RBAC; governance policy enforcement; trade authorization decisions                        | IT-001, IT-002, IT-005         | POAM-002 (IAM), POAM-001 (AC-2) |
| COMP-004     | LangGraph Financial Advisor | AI Agent Orchestrator         | GKE `governance-stack` namespace             | Multi-agent LLM orchestration for investment analysis and trade recommendations                      | IT-001, IT-002, IT-004         | —                               |
| COMP-005     | AgentSight eBPF Sidecar     | eBPF Monitoring Agent         | GKE `governance-stack` namespace (DaemonSet) | Kernel-level system call monitoring; anomaly detection; security event collection                    | IT-002, IT-003                 | —                               |
| COMP-006     | Compliance Bridge           | Audit/OSCAL Service           | GKE `governance-stack` namespace             | OSCAL artifact generation; ISO 42001 evidence stamping; SSE compliance event streaming               | IT-003, IT-005                 | POAM-003 (mock traces)          |
| COMP-007     | Redis Cache                 | In-Memory Data Store          | GKE `governance-stack` namespace             | Session state caching; governance decision caching; rate limiting state                              | IT-001, IT-002                 | —                               |
| COMP-008     | Cloud SQL PostgreSQL        | Relational Database           | GCP Managed Service (us-central1)     | Persistent storage for Langfuse trace data; application state                                        | IT-003, IT-004                 | POAM-014 (SC-28, CMEK)          |
| COMP-009     | GCS Buckets (OSCAL/Audit)   | Object Storage                | GCP Managed Service (us-central1)     | OSCAL artifact storage; audit evidence archive; model artifacts                                      | IT-003, IT-005                 | POAM-014 (SC-28, CMEK)          |
| COMP-010     | KernelDashboard UI          | Web Frontend                  | GKE `governance-stack` namespace             | Operator dashboard for AgentSight eBPF monitoring visualization                                      | IT-003                         | —                               |
| COMP-011     | Terraform IaC               | Infrastructure as Code        | GitHub Repository + GCP State         | Reproducible infrastructure provisioning; IAM binding definitions; network configuration             | IT-005 (configuration)         | POAM-002 (broad IAM)            |
| COMP-012     | GitHub Actions CI/CD        | Build and Deployment Pipeline | GitHub Cloud                          | Automated build, test, and deployment pipeline for CAGE services                                     | IT-005 (configuration)         | POAM-010 (no scanning)          |

---

## 4. External Systems and Interconnections

The following external systems exchange data with CAGE across the authorization boundary. Each interconnection is subject to data sharing agreements and/or Interconnection Security Agreements (ISA) as required.

| Ext ID  | External System                  | Interface Type         | Data Exchanged                                                         | Auth Method                             | ISA Required           | Notes                                                                                      |
| ------- | -------------------------------- | ---------------------- | ---------------------------------------------------------------------- | --------------------------------------- | ---------------------- | ------------------------------------------------------------------------------------------ |
| EXT-001 | Langfuse (SaaS)                  | HTTPS/REST (OTel OTLP) | Inference traces; audit spans; performance metrics (IT-003)            | API Key (LANGFUSE_SECRET_KEY)           | **Yes — ISA Required** | PII may be present in traces; requires data processing agreement; no CMEK on Langfuse side |
| EXT-002 | vLLM / Vertex AI (Google)        | HTTPS/REST or gRPC     | AI inference requests/responses; model outputs (IT-002)                | GCP Workload Identity / API Key         | **Yes — ISA Required** | AI model outputs may include PII echoed from input; output governed by NeMo Guardrails     |
| EXT-003 | Google Cloud APIs (GCP platform) | HTTPS (GCP API)        | Resource management; IAM; Cloud Trace; Secret Manager; Cloud SQL proxy | GCP Service Account / Workload Identity | No (GCP FedRAMP)       | Inherited controls; GCP FedRAMP authorization covers platform-level controls               |
| EXT-004 | GKE Control Plane                | Kubernetes API (HTTPS) | Kubernetes API calls; pod scheduling; config management (IT-005)       | GCP IAM + Kubernetes RBAC               | No (GCP FedRAMP)       | GKE control plane is GCP-managed; authentication via kubeconfig + WLI                      |
| EXT-005 | OFAC SDN List (Treasury.gov)     | HTTPS/REST             | Sanctions screening data (reference data only)                         | None (public API)                       | No                     | Read-only reference data; no CAGE data sent to OFAC API                                    |
| EXT-006 | Market Data Provider             | HTTPS/REST             | Market prices; financial instrument data (IT-001)                      | API Key                                 | **Yes — ISA Required** | Financial data ingested for trade recommendation context                                   |

### 4.1 Interconnection Risk Notes

- **EXT-001 (Langfuse):** Highest-risk interconnection due to potential PII in OTel traces. Langfuse is a SaaS service outside the GCP FedRAMP boundary. A formal ISA and data processing agreement (DPA) are required before PII is transmitted. Langfuse self-hosted deployment on GKE should be evaluated to bring traces within boundary.
- **EXT-002 (vLLM/Vertex AI):** AI inference requests may contain investor context including PII. NeMo Guardrails PII redaction must be verified to operate before data reaches external LLM endpoints.
- **EXT-006 (Market Data):** Financial market data is ingested; no CAGE financial data is transmitted outbound. ISA required for data quality and availability SLA documentation.

---

## 5. Data Flows

### 5.1 Primary Data Flows Across the Authorization Boundary

**Inbound Flows (External → CAGE):**

1. **User/Client → CAGE Gateway (gRPC/REST):** Financial advisory requests from authorized clients. Data types: IT-001 (trade intent), IT-004 (investor profile/PII). Authentication: TLS + application-level auth token.

2. **Market Data Provider → CAGE Gateway:** Financial instrument prices and market context. Data type: IT-001. Authentication: API key over HTTPS.

3. **GKE Control Plane → CAGE Components:** Kubernetes lifecycle events, config updates, secret delivery. Data type: IT-005 (governance configurations). Authentication: GCP IAM + RBAC.

**Outbound Flows (CAGE → External):**

4. **CAGE Gateway → vLLM/Vertex AI:** LLM inference requests after NeMo PII scrubbing. Data type: IT-002 (sanitized prompts). Authentication: GCP Workload Identity.

5. **Compliance Bridge → Langfuse:** OpenTelemetry trace spans containing governance verdicts and (scrubbed) inference context. Data type: IT-003 (audit records). Authentication: API key over HTTPS. **ISA required.**

6. **CAGE → GCS Buckets:** OSCAL artifacts, audit evidence, compliance reports. Data type: IT-003, IT-005. Authentication: GCP Service Account (Workload Identity).

**Internal Flows (Within Boundary):**

7. **Gateway → NeMo Guardrails → OPA → LangGraph:** 5-tier governance pipeline processing. All HMAC-sealed inter-service calls protected by Linkerd mTLS (POAM-007 Closed 2026-05-17). Data types: IT-001, IT-002, IT-004, IT-005. Authentication: HMAC routing seal + Linkerd mTLS (SPIFFE/X.509).

8. **Gateway → Redis Cache:** Session state and governance decision caching. Data types: IT-001, IT-002. No external network traversal.

9. **All Components → AgentSight eBPF:** Kernel-level system call telemetry captured by eBPF DaemonSet. Data type: IT-003 (observability). No network crossing; eBPF operates at kernel layer.

### 5.2 Data Flow Risk Assessment

The highest-risk data flows are:

- **Flow 4 (to vLLM/Vertex AI):** PII leakage risk if NeMo Guardrails fails to scrub input. Mitigated by NeMo Guardrails but requires validation.
- **Flow 5 (to Langfuse):** Audit traces may contain PII echoed from inference context. Requires Langfuse DPA and trace PII scrubbing validation.
- **Flow 7 (internal governance pipeline):** Linkerd mTLS (POAM-007 Closed 2026-05-17) provides mutual authentication via SPIFFE/X.509 certificates for all intra-cluster governance pipeline traffic. HMAC routing seal remains as an application-layer defense-in-depth control.

---

## 6. Inherited Controls from Cloud Provider

The following security controls are inherited from Google Cloud Platform's FedRAMP authorization. CAGE does not independently implement these controls but relies on GCP's authorization for assurance.

| Control Family                                        | Inherited Control Areas                                                                      | GCP Documentation Reference                           |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| **Physical Protection (PE)**                          | Data center physical security; environmental controls; access control to physical facilities | Google Cloud Security Whitepaper; GCP FedRAMP Package |
| **Media Protection (MP-5, MP-6)**                     | Physical media sanitization and disposal; protection of media in transport                   | GCP Data Deletion Whitepaper                          |
| **System and Communications Protection (SC-12)**      | Cryptographic key management for Google-managed encryption                                   | GCP Key Management documentation                      |
| **Maintenance (MA)**                                  | Hardware maintenance; diagnostic port control; remote maintenance controls                   | GCP Transparency Reports                              |
| **Personnel Security (PS)**                           | Google employee background screening; personnel security procedures                          | Google Cloud Security Whitepaper                      |
| **Audit and Accountability (AU) — Platform**          | GCP Cloud Audit Logs (Admin Activity, Data Access, System Event, Policy Denied)              | Cloud Audit Logs documentation                        |
| **Configuration Management (CM) — Platform**          | GKE node OS hardening; container runtime (containerd) security                               | GKE Security Overview                                 |
| **Contingency Planning (CP) — Platform**              | GCP regional redundancy; Cloud SQL automated backups; GCS geo-redundancy                     | GCP SLA documentation                                 |
| **Identification and Authentication (IA) — Platform** | GCP Identity Platform; IAM authentication infrastructure                                     | Cloud IAM documentation                               |

### 6.1 Inherited Control Limitations

The following GCP controls are provided but require CAGE-specific configuration to be effective:

- **SC-28 (Encryption at Rest):** GCP provides encryption at rest by default with Google-managed keys. CAGE-specific action: configure Customer-Managed Encryption Keys (CMEK) for Cloud SQL and GCS buckets. Status: pending (POAM-014).
- **IA-2 (Identification and Authentication):** GCP IAM provides the authentication infrastructure, but CAGE must configure appropriate IAM roles. Current status: overly broad (POAM-002).
- **AU-2/AU-3 (Audit Logging):** Cloud Audit Logs are enabled at platform level. CAGE must ensure application-level audit events are captured and forwarded (POAM-003).

---

## 7. Authorization Boundary Diagram

The following ASCII diagram depicts the CAGE authorization boundary, key components, and external interconnections.

```
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║                    CAGE AUTHORIZATION BOUNDARY                                        ║
║                    GKE Cluster | Namespace: governance-stack | GCP: us-central1      ║
║                                                                                       ║
║  ┌─────────────────────────────────────────────────────────────────────────────────┐  ║
║  │                       GKE governance-stack Namespace                            │  ║
║  │                                                                                 │  ║
║  │  ┌─────────────┐    ┌─────────────────────────────────────────────────────┐     │  ║
║  │  │  COMP-010   │    │         5-TIER GOVERNANCE PIPELINE                  │     │  ║
║  │  │ KernelDash  │    │                                                     │     │  ║
║  │  │     UI      │    │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │     │  ║
║  │  └──────┬──────┘    │  │ COMP-001 │→ │ COMP-002 │→ │    COMP-003      │  │     │  ║
║  │         │            │  │  CAGE    │  │  NeMo    │  │  OPA Policy      │  │     │  ║
║  │         ↓            │  │ Gateway  │  │Guardrails│  │   Engine         │  │     │  ║
║  │  ┌─────────────┐    │  │(FastAPI/ │  │  Server  │  │  (Rego RBAC)     │  │     │  ║
║  │  │  COMP-005   │    │  │  gRPC)   │  └──────────┘  └────────┬─────────┘  │     │  ║
║  │  │  AgentSight │    │  └────┬─────┘                         │            │     │  ║
║  │  │  eBPF Side  │←──-│──────┤ eBPF monitoring               ↓            │     │  ║
║  │  │  (DaemonSet)│    │  ┌───┴──────┐                ┌──────────────────┐  │     │  ║
║  │  └─────────────┘    │  │ COMP-007 │                │    COMP-004      │  │     │  ║
║  │                     │  │  Redis   │                │ LangGraph Fin.   │  │     │  ║
║  │                     │  │  Cache   │                │   Advisor        │  │     │  ║
║  │                     │  └──────────┘                └──────────────────┘  │     │  ║
║  │                     │                                                     │     │  ║
║  │                     │  ┌──────────────────────────────────────────────┐   │     │  ║
║  │                     │  │ COMP-006 Compliance Bridge (OSCAL/ISO 42001) │   │     │  ║
║  │                     │  └──────────────────────────────────────────────┘   │     │  ║
║  │                     └─────────────────────────────────────────────────────┘     │  ║
║  │                                                                                 │  ║
║  │  ┌──────────────────────────┐    ┌──────────────────────────────────────────┐   │  ║
║  │  │  COMP-008                │    │  COMP-009                                │   │  ║
║  │  │  Cloud SQL PostgreSQL    │    │  GCS Buckets (OSCAL/Audit Artifacts)     │   │  ║
║  │  │  (GCP Managed Service)   │    │  (GCP Managed Service)                   │   │  ║
║  │  └──────────────────────────┘    └──────────────────────────────────────────┘   │  ║
║  │                                                                                 │  ║
║  │  ┌──────────────────────────┐                                                   │  ║
║  │  │  COMP-011 / COMP-012     │                                                   │  ║
║  │  │  Terraform IaC +         │                                                   │  ║
║  │  │  GitHub Actions CI/CD    │                                                   │  ║
║  │  └──────────────────────────┘                                                   │  ║
║  └─────────────────────────────────────────────────────────────────────────────────┘  ║
║                                                                                       ║
╚══════════════════════════════════╦════════════════════════════════════════════════════╝
                                   ║ BOUNDARY CROSSING POINTS
                                   ║
         ┌─────────────────────────┼───────────────────────────┐
         │                         │                           │
         ↓                         ↓                           ↓
  ┌─────────────┐          ┌──────────────┐          ┌─────────────────┐
  │  EXT-002    │          │   EXT-001    │          │    EXT-006      │
  │ vLLM /      │          │  Langfuse    │          │  Market Data    │
  │ Vertex AI   │          │  (SaaS OTel) │          │  Provider       │
  │ (HTTPS/gRPC)│          │  (HTTPS/REST)│          │  (HTTPS/REST)   │
  │ [ISA Req'd] │          │  [ISA Req'd] │          │  [ISA Req'd]    │
  └─────────────┘          └──────────────┘          └─────────────────┘

         ┌─────────────────────────────────────────┐
         │    GCP PLATFORM (INHERITED CONTROLS)    │
         │    EXT-003: Google Cloud APIs           │
         │    EXT-004: GKE Control Plane           │
         │    EXT-005: OFAC SDN (read-only)        │
         │    [No ISA — GCP FedRAMP Inherited]     │
         └─────────────────────────────────────────┘
```

### 7.1 Diagram Legend

| Symbol          | Meaning                                          |
| --------------- | ------------------------------------------------ |
| `╔═══╗`         | CAGE Authorization Boundary                      |
| `┌───┐`         | In-scope component                               |
| `→`             | Data flow direction                              |
| `←──-│`         | eBPF kernel monitoring (no network crossing)     |
| `[ISA Req'd]`   | Interconnection Security Agreement required      |
| `[GCP FedRAMP]` | Control inherited from GCP FedRAMP authorization |

---

## 8. Boundary Change Management

### 8.1 Change Management Requirements

Any change to the CAGE authorization boundary must be reviewed and approved before implementation. Boundary changes include:

- Adding new components to the `governance-stack` namespace
- Establishing new external system interconnections
- Decommissioning in-scope components
- Migrating components to different GCP regions or services
- Adding new GCP managed services under CAGE System Owner management

### 8.2 Change Review Process

1. **Change Request:** System Administrator or Development Lead submits boundary change request to ISSO
2. **Impact Assessment:** ISSO reviews the impact on existing security controls, data flows, and information types
3. **Security Review:** ISSO coordinates with the Security Control Assessor (SCA) if the change affects HIGH or CRITICAL controls
4. **AO Notification:** Changes that expand the boundary or add new interconnections are reported to the AO within 5 business days
5. **Document Update:** This Authorization Boundary Document is updated within 10 business days of approved boundary changes
6. **SSP Update:** System Security Plan is updated to reflect boundary changes

### 8.3 Triggers for Formal Re-Authorization

The following changes require a formal re-authorization review by the AO:

- Addition of new information types or elevation of impact level
- Addition of interconnections with systems that process HIGH or CRITICAL data
- Major architectural changes (e.g., migration to a different cloud provider or region)
- Addition of AI/ML models that process new categories of PII

---

## 9. Approval and Signatures

### System Owner Approval

I approve this Authorization Boundary Document as accurately reflecting the CAGE system boundary for security authorization purposes.

| Field        | Value                                      |
| ------------ | ------------------------------------------ |
| Name         | [SIGNATURE REQUIRED — PENDING AO APPROVAL] |
| Title        | System Owner                               |
| Organization | [TBD]                                      |
| Date         | [TBD]                                      |

### ISSO Concurrence

| Field        | Value                                      |
| ------------ | ------------------------------------------ |
| Name         | [SIGNATURE REQUIRED — PENDING AO APPROVAL] |
| Title        | Information System Security Officer        |
| Organization | [TBD]                                      |
| Date         | [TBD]                                      |

### Authorizing Official Approval

| Field        | Value                                      |
| ------------ | ------------------------------------------ |
| Name         | [SIGNATURE REQUIRED — PENDING AO APPROVAL] |
| Title        | Authorizing Official                       |
| Organization | [TBD]                                      |
| Date         | [TBD]                                      |

---

## Document History

| Version   | Date       | Author | Description                                                                                         |
| --------- | ---------- | ------ | --------------------------------------------------------------------------------------------------- |
| 1.0 Draft | 2026-03-06 | [ISSO] | Initial authorization boundary document created as part of NIST RMF Phase 1 (Categorize) completion |

---

_This document is controlled. The authorization boundary defined herein governs the scope of all security assessments, continuous monitoring activities, and the ATO decision. Unauthorized changes to the boundary without ISSO review may invalidate the ATO._
