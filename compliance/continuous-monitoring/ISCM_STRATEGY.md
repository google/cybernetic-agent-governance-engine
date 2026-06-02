# Information Security Continuous Monitoring (ISCM) Strategy

| Field         | Value                                                                                 |
| ------------- | ------------------------------------------------------------------------------------- |
| **System**    | Cybernetic AI Governance Engine (CAGE)                                                |
| **Version**   | 1.0                                                                                   |
| **Date**      | 2026-03-06                                                                            |
| **Status**    | DRAFT — Pending ISSO and AO Approval                                                  |
| **Satisfies** | CA-7 (Continuous Monitoring), RA-5 (Vulnerability Scanning), SI-4 (System Monitoring) |
| **Reference** | NIST SP 800-137 Rev. 1, NIST SP 800-53 Rev. 5                                         |

---

## 1. Purpose and Scope

### 1.1 Purpose

This Information Security Continuous Monitoring (ISCM) Strategy establishes the framework for maintaining ongoing situational awareness of the security posture of the Cybernetic AI Governance Engine (CAGE). Per NIST SP 800-137, ISCM enables organizations to:

- Maintain awareness of threats and vulnerabilities
- Maintain visibility into assets and configurations
- Ensure the effectiveness of implemented security controls
- Support organizational risk management decisions

This strategy directly satisfies **CA-7 (Continuous Monitoring)** and operationalizes the requirements specified in the CAGE System Security Plan (SSP).

### 1.2 Scope

This ISCM Strategy covers:

| Component                    | Description                                                                       |
| ---------------------------- | --------------------------------------------------------------------------------- |
| **AI Governance Pipeline**   | LangGraph agent graph, gateway enforcement middleware, OPA policy engine          |
| **Infrastructure**           | GKE cluster, Cloud SQL (PostgreSQL), Redis StatefulSet, Cloud Storage             |
| **Compliance Controls**      | All SP 800-53 Rev. 5 controls in the CAGE security baseline (MODERATE impact)     |
| **Third-Party Dependencies** | Python packages, container base images, OPA policies, Lula validators             |
| **Interfaces**               | REST/gRPC gateway, SSE event bus, Langfuse observability, MCP tool server         |
| **Data Flows**               | Financial advisor requests → governance enforcement → model inference → audit log |

### 1.3 Out of Scope

- GCP platform-level controls (inherited from Common Control Provider — GCP/GKE)
- End-user workstation security
- Physical facility security (GCP data center — inherited)

---

## 2. Monitoring Tiers

The CAGE ISCM program implements a tiered monitoring architecture aligned to NIST SP 800-137 §3.3 (Define Monitoring Program). Each tier reflects the latency, mechanism, and control families addressed.

| Tier               | Frequency          | Mechanism                                                                                              | Controls Covered        | Artifact / Output                                                                |
| ------------------ | ------------------ | ------------------------------------------------------------------------------------------------------ | ----------------------- | -------------------------------------------------------------------------------- |
| **Real-time**      | < 1 second         | OpenTelemetry spans with ISO 42001 governance stamps; OPA enforcement decisions inline                 | AC-3, AU-12, SI-4, AC-6 | OTel trace per request; governance decision log in Langfuse                      |
| **Event-driven**   | Seconds            | SSE governance event bus (`src/compliance_bridge/sse_events.py`); IR notifications on policy violation | IR-6, SI-4, AU-9        | SSE event stream; compliance_bridge audit webhook                                |
| **Periodic — 60s** | Every 60 seconds   | SC-4 real-time watch deployment; network policy enforcement check                                      | SC-4, CM-6, CM-7        | Watch pod logs; network policy admission events                                  |
| **Periodic — 6h**  | Every 6 hours      | Lula CronJob OSCAL assessment (`deployment/k8s/lula-cron.yaml`); automated control validation          | CA-7, SI-7, CM-6        | OSCAL Assessment Results artifact; Lula pass/fail report                         |
| **Daily**          | Daily at 02:00 UTC | GitHub Actions security scan (`.github/workflows/security-scan.yml`); pip-audit + Trivy + OPA lint     | RA-5, CM-8, SI-2, CM-6  | pip-audit JSON, SARIF (GitHub Security tab), CycloneDX SBOM, dependency snapshot |
| **Weekly**         | Every Monday       | Manual POA&M review by ISSO; triage of GitHub Security alerts                                          | CA-5, RA-3, PM-4        | Updated `docs/POAM.md`; risk register delta                                      |
| **Monthly**        | First business day | Control effectiveness review; SSP currency check; Langfuse metric review                               | CA-7, PM-6, SA-11       | Monthly ISCM Report to System Owner and AO                                       |
| **Annual**         | Each year          | Full security assessment (CA-2); ATO renewal review; penetration test                                  | CA-2, CA-6, RA-3, PM-9  | Security Assessment Report (SAR); updated ATO package                            |

---

## 3. Monitoring Tools Inventory

| Tool                         | Purpose                                                                | SP 800-53 Controls | Data Retention                                     | Location / Reference                                              |
| ---------------------------- | ---------------------------------------------------------------------- | ------------------ | -------------------------------------------------- | ----------------------------------------------------------------- |
| **OpenTelemetry (OTel)**     | Distributed tracing; per-request governance decision recording         | AU-12, SI-4, AU-9  | 90 days (Langfuse)                                 | `src/gateway/server/governance_middleware.py`                     |
| **Langfuse**                 | LLM observability; evaluation scoring; prompt management               | AU-12, SA-11, SI-4 | 90 days                                            | `deployment/langfuse/`; `scripts/evaluate_langfuse_traces.py`     |
| **OPA (Open Policy Agent)**  | Policy-as-code enforcement; rego-based access control decisions        | AC-3, CM-6, SI-7   | Policy logs: 30 days                               | `deployment/opa_config.yaml`; `deployment/system_authz.rego`      |
| **Lula**                     | Automated OSCAL control validation against live Kubernetes resources   | CA-7, SI-7         | Assessment results: 1 year                         | `compliance/lula/`; `deployment/k8s/lula-cron.yaml`               |
| **pip-audit**                | Python dependency CVE scanning against OSV/PyPI Advisory Database      | RA-5, SI-2         | Artifact: 90 days (GitHub)                         | `.github/workflows/security-scan.yml`                             |
| **Trivy (Aqua Security)**    | Container image and filesystem vulnerability scanning; SBOM generation | RA-5, CM-8         | SARIF: GitHub Security tab; SBOM artifact: 90 days | `.github/workflows/security-scan.yml`                             |
| **GitHub Advanced Security** | SARIF ingestion; secret scanning; code scanning alerts                 | RA-5, SI-3, SA-11  | Indefinite (GitHub)                                | GitHub repository Security tab                                    |
| **GKE Network Policy**       | Layer 3/4 micro-segmentation between namespace workloads               | SC-7, AC-4, SC-4   | Network policy events: 30 days (Cloud Logging)     | `deployment/k8s/network-policy.yaml`                              |
| **Cloud Logging (GCP)**      | Centralized log aggregation for GKE workloads and GCP services         | AU-3, AU-6, AU-12  | 400 days (default GCP)                             | GCP Console; `deployment/terraform/`                              |
| **Lula + OSCAL**             | Component-level compliance evidence; assessment artifacts              | CA-7, CA-2, SA-11  | 3 years (FedRAMP standard)                         | `compliance/oscal/component-definition.yaml`                      |
| **AgentSight**               | AI agent behavior monitoring; eBPF-based process and network telemetry | SI-4, AU-12, IR-5  | 30 days                                            | `deployment/agentsight/`; `deployment/k8s/agentsight-daemon.yaml` |

---

## 4. Alert Thresholds and Escalation

Alert thresholds are drawn from [`config/governance_thresholds.json`](../../config/governance_thresholds.json) and mapped to SP 800-53 controls. Escalation follows the procedure in [`docs/ROLES_AND_RESPONSIBILITIES.md`](../../docs/ROLES_AND_RESPONSIBILITIES.md).

| Threshold                             | Value               | SP 800-53 Control | Alert Trigger                                                 | Escalation Path                                          |
| ------------------------------------- | ------------------- | ----------------- | ------------------------------------------------------------- | -------------------------------------------------------- |
| `drawdown.limit`                      | 5% portfolio        | CM-6, SI-4        | Drawdown > 5% → Unsafe Control Action (UCA-5)                 | Automated block → ISSO notification within 1h            |
| `stpa.uca5_drawdown_threshold_pct`    | 4.5%                | SI-4, CM-6        | Pre-alert at 4.5% drawdown before hard limit                  | Governance middleware warning log; Langfuse alert        |
| `stpa.uca6_max_order_volume_fraction` | 1% daily volume     | SI-4, CM-6        | Order size exceeds 1% of daily trading volume                 | Automated order rejection; audit log                     |
| `stpa.max_sell_portfolio_fraction`    | 10%                 | CM-6, AC-3        | Sell order > 10% of portfolio total                           | Block + escalate to System Owner within 4h               |
| `stpa.max_latency_ms`                 | 200 ms              | SI-4, SC-5        | Round-trip latency > 200ms                                    | Governance middleware degraded-mode alert                |
| `confidence.min_trade_confidence`     | 0.95 (95%)          | SR 11-7, SA-11    | Model confidence < 95% → trade blocked                        | Blocked trade logged; weekly ISSO review                 |
| `consensus.threshold_usd`             | $10,000             | AC-3, CM-6        | Trade > $10k → multi-agent consensus required                 | Consensus check enforced; failure → block                |
| **CVE Severity: CRITICAL**            | Any                 | RA-5, SI-2        | pip-audit or Trivy CRITICAL finding                           | Immediate: ISSO notified; POA&M entry created within 24h |
| **CVE Severity: HIGH**                | Any                 | RA-5, SI-2        | pip-audit or Trivy HIGH finding                               | Within 72h: ISSO triage; POA&M updated                   |
| **Tier-1 Prompt Injection**           | 14 defined keywords | SI-3, AC-3        | Prompt contains `SYSTEM OVERRIDE`, `DISABLE GUARDRAILS`, etc. | Immediate block; IR-6 incident logged                    |

### Escalation Matrix

| Severity                                   | Response Time     | First Responder | Escalation To           |
| ------------------------------------------ | ----------------- | --------------- | ----------------------- |
| CRITICAL vulnerability / security incident | < 1 hour          | ISSO            | System Owner → AO       |
| HIGH vulnerability                         | < 72 hours        | ISSO            | System Owner            |
| MEDIUM vulnerability                       | < 30 days         | Developer Team  | ISSO                    |
| LOW / INFO                                 | < 90 days (POA&M) | Developer Team  | ISSO (quarterly review) |

---

## 5. Reporting Cadence

| Report                                      | Audience               | Frequency         | Content                                                                           | Owner                      |
| ------------------------------------------- | ---------------------- | ----------------- | --------------------------------------------------------------------------------- | -------------------------- |
| **Daily Security Scan Summary**             | ISSO                   | Daily (automated) | pip-audit findings, Trivy SARIF, OPA lint results, SBOM artifact                  | GitHub Actions (automated) |
| **Weekly POA&M Delta**                      | ISSO, System Owner     | Weekly            | New findings, remediation progress, POA&M status changes                          | ISSO                       |
| **Monthly ISCM Report**                     | System Owner, AO       | Monthly           | Control effectiveness metrics, vulnerability trends, open POA&M items, ISCM KPIs  | ISSO                       |
| **Quarterly Control Status**                | AO, Oversight Board    | Quarterly         | Inherited control status from GCP, residual risks, ATO condition compliance       | ISSO + SCA                 |
| **Annual Security Assessment Report (SAR)** | AO                     | Annual            | Full CA-2 assessment results, penetration test report, updated risk determination | SCA (independent)          |
| **Incident After-Action Report**            | ISSO, System Owner, AO | As-needed         | Incident timeline, root cause, corrective actions, POA&M entries                  | ISSO + IR Team             |

---

## 6. ISCM Roles

Roles are defined in detail in [`docs/ROLES_AND_RESPONSIBILITIES.md`](../../docs/ROLES_AND_RESPONSIBILITIES.md). The following summarizes ISCM-specific responsibilities:

| Role                                           | ISCM Responsibilities                                                                                            | SP 800-53 Mapping |
| ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ----------------- |
| **Authorizing Official (AO)**                  | Approves ISCM strategy; reviews monthly ISCM reports; makes ongoing authorization decisions                      | CA-7(1), PM-9     |
| **Information System Security Officer (ISSO)** | Owns and executes ISCM program; triages vulnerability findings; maintains POA&M; submits monthly reports         | CA-7, RA-5, CA-5  |
| **System Owner**                               | Ensures ISCM resources are funded; receives weekly POA&M delta; approves remediation priorities                  | CA-7, PM-6        |
| **Security Control Assessor (SCA)**            | Conducts annual CA-2 assessment; validates ISCM metrics; issues SAR                                              | CA-2, CA-7(2)     |
| **Developer Team**                             | Remediates MEDIUM/LOW vulnerabilities per POA&M schedule; maintains security-scan workflow; implements lockfiles | SI-2, CM-8, SA-11 |
| **DevSecOps / CI Lead**                        | Maintains `.github/workflows/security-scan.yml`; ensures SARIF uploads; monitors GitHub Security alerts          | RA-5, CM-6, SI-3  |
| **Common Control Provider (GCP/GKE)**          | Provides platform-level controls (physical, network, hypervisor); issues FedRAMP package inherited evidence      | SC-7, PE-_, MA-_  |

---

## 7. ISCM Metrics

The following key performance indicators (KPIs) measure the effectiveness of the CAGE ISCM program. Metrics are reviewed monthly and reported to the AO. Targets are based on NIST SP 800-137 and industry benchmarks for MODERATE-impact financial AI systems.

| #   | Metric                                    | Target          | Measurement Method                                                              | Control     |
| --- | ----------------------------------------- | --------------- | ------------------------------------------------------------------------------- | ----------- |
| 1   | **Policy Enforcement Rate**               | ≥ 99.9%         | OPA decision logs: `(allow + deny) / total_requests × 100`                      | AC-3, CM-6  |
| 2   | **Audit Coverage**                        | ≥ 95%           | Percentage of governance requests with complete OTel trace + audit log entry    | AU-12, AU-3 |
| 3   | **Vulnerability Scan Currency**           | 100% (daily)    | GitHub Actions `security-scan` workflow success rate; last successful run ≤ 25h | RA-5        |
| 4   | **Mean Time to Remediate — CRITICAL CVE** | ≤ 24 hours      | POA&M delta: date identified → date closed for CRITICAL findings                | SI-2, RA-5  |
| 5   | **Mean Time to Remediate — HIGH CVE**     | ≤ 30 days       | POA&M delta: date identified → date closed for HIGH findings                    | SI-2, RA-5  |
| 6   | **SBOM Freshness**                        | ≤ 25 hours old  | Trivy CycloneDX SBOM artifact timestamp vs. current time                        | CM-8        |
| 7   | **Lula OSCAL Control Pass Rate**          | ≥ 90%           | Lula CronJob results: passing validations / total validations                   | CA-7, SI-7  |
| 8   | **Model Confidence Enforcement Rate**     | 100%            | Trades blocked when confidence < 0.95 / total low-confidence requests           | SA-11, CM-6 |
| 9   | **Prompt Injection Block Rate**           | 100%            | Tier-1 keyword matches blocked / total Tier-1 detections                        | SI-3, AC-3  |
| 10  | **POA&M Item Aging**                      | 0 items overdue | Count of POA&M items past scheduled completion date                             | CA-5, RA-3  |

### Metric Collection and Reporting

- **Metrics 1–2:** Extracted from Langfuse and OPA decision logs via `scripts/automated_auditor.py` and `scripts/evaluate_langfuse_traces.py`
- **Metrics 3–6:** Extracted from GitHub Actions workflow run history and artifact metadata
- **Metrics 7:** Lula CronJob output (`deployment/k8s/lula-cron.yaml`) aggregated in OSCAL Assessment Results
- **Metrics 8–9:** Governance middleware telemetry from `src/gateway/server/governance_middleware.py`
- **Metric 10:** Manual POA&M review from `docs/POAM.md` by ISSO

---

## 8. Strategy Maintenance

This ISCM Strategy shall be reviewed and updated:

- **Annually** as part of the CA-2 security assessment cycle
- **When significant changes** occur to system architecture, threat landscape, or regulatory requirements
- **Following any security incidents** that reveal gaps in monitoring coverage
- **Upon ATO renewal** to align with current NIST SP 800-137 guidance

**Next Review Date:** 2027-03-06  
**Document Owner:** ISSO (see [`docs/ROLES_AND_RESPONSIBILITIES.md`](../../docs/ROLES_AND_RESPONSIBILITIES.md))  
**Approval Authority:** Authorizing Official (AO)

---

_This document satisfies NIST SP 800-53 Rev. 5 CA-7 (Continuous Monitoring) and supports the ongoing authorization of the CAGE system per SP 800-37 Rev. 2 Step 6 (Monitor)._
