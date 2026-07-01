# NIST RMF Step 7 (Monitor) + Consolidated Refactoring Roadmap

## Cybernetic Governance Engine — Chunk 5 of 5 (FINAL)

**Classification:** For Official Use Only (FOUO)
**Prepared:** 2026-06-01
**System:** Cybernetic Governance Engine (CAGE) v0.1.0 — GKE-hosted AI Governance Platform
**Document Status:** Final Synthesis — references all prior chunk findings; updated for v0.1.0
**Additional Frameworks:** SR 26-2 (Federal Reserve, April 17, 2026), CSA AARM v1.0

---

## Table of Contents

1. [Part A — NIST RMF Step 7: Monitor](#part-a--nist-rmf-step-7-monitor)
   - [7.1 Information Security Continuous Monitoring Strategy](#71-information-security-continuous-monitoring-iscm-strategy)
   - [7.2 Ongoing Control Assessments](#72-ongoing-control-assessments)
   - [7.3 Ongoing Remediation and POA&M Management](#73-ongoing-remediation--poam-management)
   - [7.4 Security Status Reporting](#74-security-status-reporting)
   - [7.5 System and Environment Changes](#75-system-and-environment-changes)
   - [7.6 Disposition / Decommissioning Controls](#76-disposition--decommissioning-controls)
2. [Part B — Consolidated Refactoring Roadmap](#part-b--consolidated-refactoring-roadmap)
   - [B.1 Phase 0: Authorization Foundation](#b1-phase-0-authorization-foundation-weeks-12)
   - [B.2 Phase 1: Quick Wins](#b2-phase-1-quick-wins-weeks-26)
   - [B.3 Phase 2: Core Hardening](#b3-phase-2-core-hardening-weeks-616)
   - [B.4 Phase 3: Architectural Uplift](#b4-phase-3-architectural-uplift-weeks-1652)
   - [B.5 ATO Readiness Progression Table](#b5-ato-readiness-progression-table)
   - [B.6 Control-to-Code Traceability Matrix](#b6-nist-rmf-control-to-code-traceability-matrix)
   - [B.7 Executive Summary](#b7-executive-summary)
3. [Overall RMF Readiness Dashboard](#overall-rmf-readiness-dashboard)

---

## Part A — NIST RMF Step 7: Monitor

### 7.1 Information Security Continuous Monitoring (ISCM) Strategy

#### Current State

The system implements a **two-tier monitoring approach** that partially addresses SP 800-137 ISCM requirements:

**Tier 1 — Periodic Compliance Audit (6-hour cadence):**
[`deployment/k8s/lula-cron.yaml`](deployment/k8s/lula-cron.yaml:153) deploys a `CronJob` on the schedule `"0 */6 * * *"` that runs `lula validate` against all four ISO 42001 controls (A.5.2, A.5.3, A.9.2, SC-4). On each run:

- OSCAL Assessment Result YAML is written to an ephemeral volume
- Results are persisted to GCS via [`src/compliance_bridge/storage.py`](src/compliance_bridge/storage.py:215) (idempotent, SHA-256 keyed)
- The CronJob POSTs to [`POST /v1/audit/ingest`](src/compliance_bridge/main.py:287) on the compliance bridge

**Tier 2 — Real-Time Kubernetes Watch (60-second cadence):**
[`deployment/k8s/lula-cron.yaml`](deployment/k8s/lula-cron.yaml:263) also deploys `lula-sc4-watch`, a long-running `Deployment` that polls the SC-4 ConfigMap label (`opa-compliance-status`) every 60 seconds and immediately ingests any state change.

**Tier 3 — Application-Level OTel Tracing (continuous):**
[`src/gateway/infrastructure/telemetry.py`](src/gateway/infrastructure/telemetry.py:31) provides an OTel tracer factory consumed by all gateway modules. [`src/gateway/observability/mcp_tracing.py`](src/gateway/observability/mcp_tracing.py:46) monkey-patches `ToolManager.call_tool` to inject W3C trace context into every MCP tool invocation, bridging SSE transport gaps and producing complete Langfuse waterfall traces.

**OTel Export Pipeline (v0.1.0):**
The standalone OTel Collector (`opentelemetry-collector-contrib`) has been **deprecated 2026-05-31**. Services now export OTLP traces directly to Langfuse's integrated OTLP ingestion endpoint at `http://langfuse-web:3000/api/public/otel/v1/traces`, eliminating the collector as an intermediary. W3C `traceparent` propagation is preserved end-to-end via `patch_mcp_tools()` in `src/gateway/observability/mcp_tracing.py`.

**DEFER Queue Monitoring (v0.1.0 — AARM-V7):**
[`src/gateway/governance/defer_queue.py`](src/gateway/governance/defer_queue.py) implements the DEFER state machine for confidence-starved contexts. Redis db=1 (noeviction policy) stores deferred governance decisions pending human review. The DEFER queue is monitored via SSE events (`DEFER_QUEUED`, `DEFER_RESOLVED`) published to the `GovernanceEventBus` and visible in the AgentSight KernelDashboard. Queue depth and resolution latency are tracked as OTel metrics.

**AgentSight UI Phase 1 (v0.1.0):**
[`src/agentsight-ui/`](src/agentsight-ui/) — React/Vite frontend with eBPF kernel observability. [`deployment/agentsight/agentsight-config.yaml`](deployment/agentsight/agentsight-config.yaml:19) deploys an eBPF daemon targeting `python3` processes, intercepting SSL/TLS via OpenSSL uprobes and monitoring syscalls (`execve`, `openat`, `connect`, `socket`, `bind`). **✅ POAM-021 RESOLVED:** Exporter is configured as `type: "remote"`, targeting `http://agentsight-dashboard:8080`. The prior gap (console mode) has been corrected. `KernelDashboard.tsx` displays real-time governance events, DEFER queue state, and eBPF syscall telemetry.

**SSE Real-Time Event Bus:**
[`src/compliance_bridge/sse_events.py`](src/compliance_bridge/sse_events.py:81) implements a `GovernanceEventBus` that fans `AUDIT_FINDING` and `GOVERNANCE_VIOLATION` events to all connected SSE clients via [`GET /v1/events/stream`](src/compliance_bridge/main.py:184), consumed by `KernelDashboard.tsx`.

#### Gaps

| #      | Gap                                                                          | SP 800-137 Requirement                                            | Severity |
| ------ | ---------------------------------------------------------------------------- | ----------------------------------------------------------------- | -------- |
| G7.1-1 | No documented ISCM Strategy document (SP 800-137 §3.1)                       | Documented strategy with monitoring scope, frequencies, and roles | Critical |
| ~~G7.1-2~~ | ~~AgentSight exporter set to `console` — remote dashboard not confirmed active~~ **✅ RESOLVED (POAM-021):** Exporter is `type: "remote"` targeting `http://agentsight-dashboard:8080`. | Continuous monitoring of process-level behavior | ~~High~~ **Closed** |
| ~~G7.1-3~~ | ~~OTel collector is single-replica — no HA or failover~~ | **Closed** — standalone OTel Collector deprecated 2026-05-31; Langfuse integrated OTLP ingestion used directly. | ~~High~~ **Closed** |
| G7.1-4 | No Prometheus/Grafana metrics pipeline — only Langfuse traces                | Infrastructure-level metrics monitoring                           | Medium   |
| G7.1-5 | `TRACE_SAMPLING_RATE` set to `0.01` (1%) in deploy_sw.py substitutions       | Sufficient coverage for security monitoring                       | Medium   |
| G7.1-6 | No formal monitoring frequency justification tied to FIPS 199 impact levels  | Impact-commensurate monitoring cadence                            | Medium   |

#### Recommendations

1. **Create `docs/ISCM_STRATEGY.md`** (ISSO responsible): Document monitoring scope, tools, frequencies (real-time: OTel/SSE, 60s: SC-4 watch, 6h: Lula audit, daily: Langfuse metrics), roles, and SP 800-137 alignment. Reference control families AU, SI, and CA.
2. ~~**Activate AgentSight remote dashboard**~~ **✅ RESOLVED (POAM-021):** Already configured as `type: "remote"` in `agentsight-config.yaml`.
3. ~~**Scale OTel Collector to 2 replicas**~~ **Closed** — standalone collector deprecated; Langfuse integrated OTLP ingestion used directly.
4. **Increase `TRACE_SAMPLING_RATE` to `0.10` (10%)** for security-relevant spans (governance, OPA, NeMo). Use tail-based sampling for error traces.
5. **Deploy kube-state-metrics + Prometheus** for infrastructure-layer monitoring to complement Langfuse application-layer traces.

---

### 7.2 Ongoing Control Assessments

#### Current State

**Automated Assessment Pipeline:**
The 5-step [`run_audit_workflow()`](src/compliance_bridge/audit_workflow.py:500) function executes fully automatically on each CronJob trigger:

1. Persist OSCAL artifact to GCS (idempotent — SHA-256 keyed, HEAD-check before upload)
2. Parse OSCAL YAML deterministically via [`parse_oscal_yaml()`](src/compliance_bridge/oscal_parser.py:169) — zero LLM involvement
3. Ingest findings as Langfuse compliance scores with ISO 42001 metadata tags
4. Filter FAIL findings for `CRITICAL_CONTROLS` → trigger `SlackNotifier` or `ConsoleNotifier`
5. Conditional LLM remediation advisory (human review required per ISO 42001 A.7.2)

**Control Coverage:**
All 4 Lula validations ([`lula-validation-a52.yaml`](compliance/lula/lula-validation-a52.yaml), `a53.yaml`, `a92.yaml`, `sc4.yaml`) produce OSCAL Assessment Results on every run. The metrics endpoint [`GET /v1/metrics/{control_id}`](src/compliance_bridge/main.py:240) provides a 5-minute TTL cached compliance score per control, computed from Langfuse trace aggregation over a configurable `window_hours` (default 24h, max 720h).

**Drift Detection:**
SC-4 (OPA ConfigMap label compliance) has continuous drift detection via the 60-second watch loop. API-domain controls (A.5.2, A.5.3, A.9.2) use the evidence staleness guard: `evidence_age_seconds < 172800` (48h) in the Rego rules.

#### Gaps

| #      | Gap                                                                                    | SP 800-53 Requirement      | Severity |
| ------ | -------------------------------------------------------------------------------------- | -------------------------- | -------- |
| G7.2-1 | Only 4 of 113 sampled SP 800-53 controls have automated Lula validation                | CA-7 Continuous Monitoring | Critical |
| G7.2-2 | No SP 800-53 control family mapped to Lula domain (all 4 are ISO 42001 controls)       | CA-7, CA-2                 | High     |
| G7.2-3 | OSCAL Assessment Results produced by Lula are not linked to an OSCAL SSP               | CA-7, CA-6                 | High     |
| G7.2-4 | No automated drift detection for IAM roles, NetworkPolicy, or secret rotation          | CM-3, CM-6                 | High     |
| G7.2-5 | `scripts/automated_auditor.py` uses mock trace source (noted Chunk 1) — AU-12/SI-4 gap | AU-12, SI-4                | High     |
| G7.2-6 | No assessment cadence formally approved by AO                                          | CA-7                       | Medium   |

#### Recommendations

1. **Add SP 800-53 Lula validations**: Create `compliance/lula/sp80053/` directory with at minimum:
   - `lula-au-12.yaml` — validate OTel spans are being exported (AU-12 Audit Record Generation)
   - `lula-ac-3.yaml` — validate OPA policy enforcement is active (AC-3 Access Enforcement)
   - `lula-si-4.yaml` — validate AgentSight daemon is running (SI-4 Information System Monitoring)
   - `lula-sc-8.yaml` — validate NetworkPolicy ingress/egress rules exist (SC-8 Transmission Confidentiality)
2. **Fix `scripts/automated_auditor.py`** to use the live OTel/Langfuse trace source instead of mock data (satisfies AU-12 and SI-4).
3. **Link OSCAL Assessment Results to SSP**: Once SSP exists (Phase 0), add `assessment-results.import-ssp` reference in Lula output templates.
4. **Add IAM drift detection Lula validation**: Use Kubernetes domain to check `ServiceAccount` annotations and `ClusterRoleBinding` subjects for unauthorized changes.

---

### 7.3 Ongoing Remediation / POA&M Management

#### Current State

**Automated Alert Pipeline:**
[`src/compliance_bridge/notifier.py`](src/compliance_bridge/notifier.py:315) implements a factory (`create_notifier()`) selecting among `SlackNotifier`, `ConsoleNotifier`, or `MockNotifier` via `ALERT_CHANNEL` env var. `SlackNotifier` posts Block Kit payloads to `COMPLIANCE_ALERT_WEBHOOK_URL` on:

- Critical control failures (`send_critical_alert()`)
- LLM remediation advisories (`send_remediation_followup()`)

**LLM-Assisted Remediation:**
`_step5_remediation_advisor()` in [`audit_workflow.py`](src/compliance_bridge/audit_workflow.py:327) fetches the 10 most recent failing Langfuse traces for the failing control, constructs a structured remediation prompt referencing specific codebase paths, and calls vLLM via the OpenAI SDK. All output is:

- Logged to the Langfuse compliance project with `human_review_required: true` metadata
- Sent to Slack with an explicit `⚠️ LLM-generated advisory — human verification required` disclaimer
- Not applied automatically — requires human engineer action (ISO 42001 A.7.2)

**Remediation Proposals:**
[`docs/proposals/004_risk_remediation_plan.md`](docs/proposals/004_risk_remediation_plan.md) documents architectural proposals for dynamic policy injection (OPA bundle server), stateful risk memory (Redis), and GitOps policy workflow. These are proposals, not implemented.

**Storage:**
[`src/compliance_bridge/storage.py`](src/compliance_bridge/storage.py:215) provides idempotent OSCAL artifact persistence to GCS via S3-compatible API, with SHA-256 content fingerprinting and `x-standard: ISO/IEC 42001:2023` metadata.

#### Gaps

| #      | Gap                                                                                                                    | SP 800-53 Requirement              | Severity |
| ------ | ---------------------------------------------------------------------------------------------------------------------- | ---------------------------------- | -------- |
| G7.3-1 | No formal `docs/POAM.md` — no structured POA&M item tracking with control ID, weakness, scheduled completion           | CA-5 Plan of Action and Milestones | Critical |
| G7.3-2 | No SLA tracking for remediation (Slack alert fires but no ticket/deadline created automatically)                       | CA-5                               | High     |
| G7.3-3 | No tiered escalation (Level 1 → Level 2 → AO) — only single Slack channel alert                                        | IR-6, CA-5                         | High     |
| G7.3-4 | LLM remediation advisory limited to first critical failure only — multiple concurrent failures not fully addressed     | CA-5                               | Medium   |
| G7.3-5 | `docs/proposals/004_risk_remediation_plan.md` is a proposal only — OPA bundle server and GitOps policy not implemented | CM-3, SC-12                        | Medium   |
| G7.3-6 | No remediation closure verification — no re-assessment trigger after fix applied                                       | CA-5, CA-7                         | Medium   |

#### Recommendations

1. **Create `docs/POAM.md`** (ISSO responsible): Structured POA&M with columns: `POA&M-ID`, `Control`, `Weakness`, `Responsible Party`, `Scheduled Completion`, `Milestone`, `Status`. Pre-populate with all gaps from Chunks 1–5.
2. **Integrate Jira/GitHub Issues**: On `GOVERNANCE_VIOLATION` SSE event, auto-create a GitHub Issue via API with control ID, severity, and audit ID as labels. Set due-date based on severity (Critical: 15 days, High: 30 days, Medium: 90 days).
3. **Implement tiered escalation**: Extend [`notifier.py`](src/compliance_bridge/notifier.py:315) with a `PagerDutyNotifier` class for `CRITICAL` severity, and add escalation logic: if Slack alert not acknowledged within 4h, page on-call via PagerDuty.
4. **Implement OPA bundle server** as described in `004_risk_remediation_plan.md` to reduce policy update latency from minutes to seconds.

---

### 7.4 Security Status Reporting

#### Current State

**Control-Level Metrics API:**
[`src/compliance_bridge/metrics.py`](src/compliance_bridge/metrics.py:197) provides [`get_compliance_metrics()`](src/compliance_bridge/metrics.py:197) that queries Langfuse for traces tagged `control:<controlId>`, aggregates `iso_42001_outcome` metadata into a `ComplianceMetrics` struct (safety_rate, total_traces, blocked_traces, evidence_age_seconds, startup_grace_active). A 5-minute TTL `cachetools.TTLCache` prevents Langfuse hammering.

**Real-Time SSE Dashboard:**
[`src/compliance_bridge/sse_events.py`](src/compliance_bridge/sse_events.py:81) fans `AUDIT_FINDING` and `GOVERNANCE_VIOLATION` events to connected KernelDashboard clients. The [`GovernanceEventBus`](src/compliance_bridge/sse_events.py:81) uses non-blocking `asyncio.Queue.put_nowait()` with graceful drop on queue-full.

**Langfuse Application Metrics:**
[`fetch_langfuse_metrics.py`](fetch_langfuse_metrics.py:32) provides a CLI script querying Langfuse for GENERATION observations (TTFT metrics) and SPAN observations for governance overhead (`injection`, `identity-tag`, `financial-advisor-sa` spans). This is a developer tool, not a scheduled reporting mechanism.

**Kubernetes Health Checks:**
[`deployment/deploy_sw.py`](deployment/deploy_sw.py:1264) implements `verify_pod_health()` which checks for OOMKilled containers post-deployment. The compliance bridge [`GET /health`](src/compliance_bridge/main.py:227) returns `{"status": "ok", "version": "0.1.0"}`.

#### Gaps

| #      | Gap                                                                                               | SP 800-53 Requirement | Severity |
| ------ | ------------------------------------------------------------------------------------------------- | --------------------- | -------- |
| G7.4-1 | No machine-readable OSCAL Assessment Results linked to System Security Plan (no OSCAL SSP exists) | CA-7, CA-2            | Critical |
| G7.4-2 | No executive compliance dashboard — KernelDashboard is engineering-level only                     | CA-7, PM-6            | High     |
| G7.4-3 | No periodic compliance status report (weekly/monthly) generated and retained                      | CA-7                  | High     |
| G7.4-4 | `fetch_langfuse_metrics.py` is a manual developer tool — not scheduled or retained as evidence    | AU-6                  | Medium   |
| G7.4-5 | Compliance metrics cover 4 ISO 42001 controls only; no SP 800-53 family coverage dashboard        | CA-7                  | High     |
| G7.4-6 | No AO-level security posture report format defined                                                | CA-6, CA-7            | Medium   |

#### Recommendations

1. **Create a compliance status report template** (`docs/templates/COMPLIANCE_STATUS_REPORT.md`): Weekly auto-generated report combining: current Lula pass/fail per control, trend from prior week, open POA&M items, and next assessment scheduled date.
2. **Schedule `fetch_langfuse_metrics.py`** as a Kubernetes CronJob (weekly) that writes output to GCS for retention (AU-6 evidence).
3. **Build OSCAL Assessment Results index**: Extend [`storage.py`](src/compliance_bridge/storage.py) with a `list_artifacts()` function that writes an index JSON to GCS `oscal-artifacts/index.json` — enables AO to enumerate all assessment results without GCS console access.
4. **Add compliance summary endpoint**: Create `GET /v1/compliance/summary` in [`main.py`](src/compliance_bridge/main.py) returning all control statuses, pass rates, and last-assessment timestamps in a single response.

---

### 7.5 System and Environment Changes

#### Current State

**Terraform-Driven Change Detection:**
[`deployment/terraform/deploy.tf`](deployment/terraform/deploy.tf:15) implements a `null_resource.app_deployment` with content-hash triggers for: `deploy_sw.py`, `backend-deployment.yaml.tpl`, `compliance-bridge.yaml`, `lula-rbac.yaml`, `lula-cron.yaml`, `graph.py`, all vLLM manifests, and `google_container_cluster.primary.endpoint`. Any change to these files or the GKE cluster endpoint triggers `terraform apply` to re-deploy.

**Deployment Orchestration:**
[`deployment/deploy_sw.py`](deployment/deploy_sw.py:1040) is a 1500-line orchestrator that:

- Checks sovereign license headers (Apache 2.0) as a deployment gate
- Builds 5 container images in parallel (backend, vLLM streamer, gateway, UI, compliance bridge)
- Mirrors all secrets to Kubernetes
- Deploys the ISO 42001 compliance stack as the final step

**Change Log:**
[`CHANGELOG.md`](CHANGELOG.md:1) documents infrastructure changes (GKE extensions removed, model streaming migrated from GCS Fuse to MinIO/tensorizer), bug fixes (`route_supervisor()`, `execution_analyst_node()`), and test results. Entries are date-tagged but not linked to formal change requests.

#### Gaps

| #      | Gap                                                                                                          | SP 800-53 Requirement             | Severity |
| ------ | ------------------------------------------------------------------------------------------------------------ | --------------------------------- | -------- |
| G7.5-1 | No change management process — no formal Change Request (CR) form or approval gate before `terraform apply`  | CM-3 Configuration Change Control | Critical |
| G7.5-2 | No security impact analysis step before deploying changes (e.g., does this change affect security controls?) | CM-3, RA-3                        | High     |
| G7.5-3 | No "significant change" trigger for re-authorization assessment (AO must be notified)                        | CA-3, CA-7                        | High     |
| G7.5-4 | `CHANGELOG.md` is manually maintained — no automated entry generated by CI/CD                                | CM-3, AU-9                        | Medium   |
| G7.5-5 | No dependency lockfiles for Python packages — no SBOM — supply chain risk untracked                          | SA-12, SR-3                       | High     |
| G7.5-6 | Container images tagged `latest` — no immutable image digests in manifests                                   | CM-8, SI-2                        | High     |

#### Recommendations

1. **Create `docs/CHANGE_MANAGEMENT_PROCESS.md`**: Define significant-change categories (GKE cluster version, new data flows, new external integrations, control implementation changes), required CR approval (ISSO + System Owner), and AO notification threshold.
2. **Add CI/CD gate**: Require a PR-level comment from ISSO approving security-relevant changes before merge. Use GitHub CODEOWNERS for `deployment/terraform/`, `compliance/`, `src/gateway/governance/`.
3. **Pin container image digests**: Replace `:latest` tags with `@sha256:<digest>` in all manifests to enable CM-8 software inventory integrity.
4. **Add `pip-compile` lockfiles** and integrate `pip-audit` in CI for Python dependency SBOM (satisfies SA-12, RA-5).
5. **Add automated CHANGELOG entry** in CI: on merge to `main`, append a change record with PR number, author, files changed, and SHA to `CHANGELOG.md`.

---

### 7.6 Disposition / Decommissioning Controls

#### Current State

**Teardown Script:**
[`deployment/teardown.py`](deployment/teardown.py:31) provides a 109-line script that:

1. Deletes Cloud Run services (`financial-advisor-ui`, `governed-financial-advisor`)
2. Deletes the GKE cluster (`governance-cluster`)
3. Deletes 5 named Secret Manager secrets (`opa-auth-token`, `system-authz-policy`, `finance-policy-rego`, `opa-configuration`, `hf-token-secret`)
4. Deletes NAT/Router network resources
5. Deletes the Redis instance

**Terraform State:**
`deployment/terraform/` contains `backend.tf` (presumed to reference GCS backend) and `destroy` capability implicitly via `terraform destroy`.

#### Gaps

| #      | Gap                                                                                                                                    | SP 800-53 Requirement   | Severity |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- | -------- |
| G7.6-1 | No secure data deletion step — GCS buckets with OSCAL artifacts and Langfuse event data not wiped                                      | MP-6 Media Sanitization | Critical |
| G7.6-2 | `teardown.py` deletes only 5 secrets — ISO 42001 compliance secrets, OSCAL HMAC keys, and Langfuse compliance project keys not deleted | AC-2, IA-4              | High     |
| G7.6-3 | No compliance evidence archival step before teardown — OSCAL artifacts in GCS not exported/archived                                    | AU-11, MP-6             | High     |
| G7.6-4 | No credential revocation for GCP Service Accounts (`financial-advisor-sa`, `lula-auditor`)                                             | IA-4, AC-2              | High     |
| G7.6-5 | No formal decommissioning checklist or AO notification requirement                                                                     | CA-6, CM-4              | High     |
| G7.6-6 | Teardown is entirely manual — no CI/CD protection preventing accidental teardown in production                                         | CM-3                    | Medium   |

#### Recommendations

1. **Create `docs/DECOMMISSION_CHECKLIST.md`**: Structured checklist requiring sign-off from ISSO and System Owner before execution. Include: data classification review, OSCAL artifact export to long-term archive, GCS bucket wipe (per DoD 5220.22-M for non-classified), Service Account key revocation, AO decommission notification.
2. **Extend `teardown.py`** to include:
   - `gcloud secrets delete` for all 12+ compliance-related secrets
   - `gcloud storage rm -r gs://<OSCAL_BUCKET>` with confirmation prompt
   - `gcloud iam service-accounts disable` for `financial-advisor-sa` and `lula-auditor`
   - GCS archive export: `gsutil cp gs://<bucket>/oscal-artifacts/ gs://<archive-bucket>/decommission-<date>/`
3. **Add production guard**: Require `--confirm-production-teardown=<sha>` flag where SHA must match a one-time code issued by ISSO, preventing accidental execution.

---

## Part B — Consolidated Refactoring Roadmap

### B.1 Phase 0: Authorization Foundation (Weeks 1–2)

> These artifacts are **prerequisites to all subsequent work**. No Sprint activities in Phases 1–3 have full compliance credit until these exist.

| #    | Artifact                              | Path                                                  | Template/Structure                                                                                                                                                                                                    | Responsible Role    | Controls Satisfied    |
| ---- | ------------------------------------- | ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- | --------------------- |
| P0-1 | **System Security Plan (SSP)**        | `compliance/ssp/SYSTEM_SECURITY_PLAN.md`              | NIST SP 800-18 Rev 1 format: System Description, Boundary, Data Flows, Control Implementation Statements per family (AC, AU, CA, CM, IA, IR, RA, SA, SC, SI). Reference `compliance/oscal/component-definition.yaml`. | ISSO                | CA-6, CA-2, CA-7, All |
| P0-2 | **FIPS 199 Categorization Document**  | `compliance/categorization/FIPS199_CATEGORIZATION.md` | FIPS 199 template: Confidentiality (Moderate), Integrity (High), Availability (Moderate); overall = High. Justification for AI governance of financial recommendations. Signed by System Owner.                       | System Owner + ISSO | RA-2, CA-6            |
| P0-3 | **Roles & Responsibilities Matrix**   | `compliance/governance/ROLES_MATRIX.md`               | Table: Role / Name / ATO Authority / Contact. Minimum: Authorizing Official (AO), ISSO, System Owner, ISSM.                                                                                                           | System Owner        | CA-6, PS-7, PM-2      |
| P0-4 | **SP 800-53 Profile Import in OSCAL** | `compliance/oscal/sp80053-profile.yaml`               | OSCAL Profile importing NIST SP 800-53 Rev 5 Moderate baseline with High-Integrity overlay. Reference `component-definition.yaml`.                                                                                    | ISSO                | CA-2, CA-7, SA-4      |
| P0-5 | **Inherited Controls Designation**    | `compliance/ssp/INHERITED_CONTROLS.md`                | Table listing GKE/GCP platform controls inherited from Google FedRAMP authorization (PE-_, physical security, PS-_).                                                                                                  | ISSO                | CA-6, SA-9            |
| P0-6 | **Authorization Package Index**       | `compliance/authorization/PACKAGE_INDEX.md`           | TOC of all 21 required ATO artifacts with status (Exists / Pending / N/A) and file paths.                                                                                                                             | ISSO                | CA-6                  |

---

### B.2 Phase 1: Quick Wins (Weeks 2–6)

> All items ≤ 1 week effort. Each maps to a specific file change.

| #     | File to Create/Modify                          | Exact Change                                                                                                                                                                | Controls          | Est. Hours |
| ----- | ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | ---------- |
| P1-1  | `docs/POAM.md`                                 | Create with pre-populated rows from all Chunk 1–5 gaps. Columns: POA&M-ID, Control-ID, Weakness, Responsible, Scheduled-Completion, Status                                  | CA-5              | 4h         |
| P1-2  | `docs/ISCM_STRATEGY.md`                        | Create SP 800-137 ISCM strategy document: monitoring scope, tools, frequencies table (real-time/6h/daily/weekly), roles                                                     | CA-7, SI-4        | 6h         |
| P1-3  | `docs/DECOMMISSION_CHECKLIST.md`               | Create formal decommission checklist with sequential sign-off steps                                                                                                         | MP-6, IA-4, AC-2  | 3h         |
| P1-4  | `deployment/teardown.py`                       | Add deletion of compliance secrets (`langfuse-compliance-secrets`, `oscal-artifact-secrets`, `compliance-alert-secrets`); add GCS archive export step; add `--confirm` flag | AC-2, IA-4, MP-6  | 4h         |
| P1-5  | `scripts/automated_auditor.py`                 | Replace mock trace source with live Langfuse SDK call (`fetch_traces(tags=["control:<id>"])`) mirroring [`metrics.py`](src/compliance_bridge/metrics.py:134) pattern        | AU-12, SI-4       | 4h         |
| P1-6  | `deployment/agentsight/agentsight-config.yaml` | Change `exporter.type` from `"console"` to `"remote"`; confirm `endpoint` is reachable; add `health_check` probe                                                            | SI-4, AU-6        | 2h         |
| ~~P1-7~~  | ~~OTel collector manifest (rendered via `deployment/k8s_rendered/`)~~       | ~~Set `replicas: 2`; add `podAntiAffinity` rule; increase batch `send_batch_size` to 2000~~ — **Closed** (standalone OTel Collector deprecated 2026-05-31; no collector manifest to tune) | AU-12, SI-4       | ~~2h~~         |
| P1-8  | `src/compliance_bridge/main.py`                | Add `GET /v1/compliance/summary` endpoint returning all 4 control statuses, pass rates, last-assessment timestamps, and open alert count                                    | CA-7, PM-6        | 4h         |
| P1-9  | `src/compliance_bridge/notifier.py`            | Add `PagerDutyNotifier` class; extend `create_notifier()` factory for `ALERT_CHANNEL=pagerduty`; add 4h escalation retry                                                    | IR-6, IR-7        | 6h         |
| ~~P1-10~~ | ~~`deployment/k8s/lula-cron.yaml`~~                | ~~Set `TRACE_SAMPLING_RATE` override env var to `0.10` in otel-collector deployment for governance-namespace spans~~ — **Closed** (no standalone collector; sampling rate configured directly in service env vars) | AU-12             | ~~1h~~         |
| ~~P1-11~~ | ~~`compliance/lula/sp80053/lula-au-12.yaml`~~      | ~~New Lula validation: Kubernetes domain check that `otel-collector` Deployment exists and `ready` replicas ≥ 1~~ — **Closed** (`compliance/lula/lula-validation-au12.yaml` now validates `langfuse-web-deployment readyReplicas ≥ 1`) | AU-12             | ~~3h~~         |
| P1-12 | `pyproject.toml` + `requirements*.txt`         | Run `pip-compile` to generate lockfiles; add `pip-audit` to CI workflow                                                                                                     | SA-12, RA-5, SI-2 | 3h         |
| P1-13 | `CHANGELOG.md`                                 | Standardize format; add CI automation: on merge to `main`, GitHub Action appends entry with PR#, author, SHA, files changed                                                 | CM-3, AU-9        | 2h         |

---

### B.3 Phase 2: Core Hardening (Weeks 6–16)

> Medium-effort items requiring design decisions but no fundamental architectural change.

| #     | Files/Modules                                                                                  | Description of Change                                                                                                                                                                                                  | Controls               | Est. Person-Days |
| ----- | ---------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- | ---------------- | ----------------- | --- |
| P2-1  | `src/gateway/server/governance_middleware.py`, `deployment/k8s/backend-deployment.yaml.tpl`    | Harden `CAGE_ROUTING_SEAL_SECRET` bypass path: add HMAC verification on routing override requests; log all bypass attempts as `GOVERNANCE_VIOLATION` events. Remove `                                                  |                        | true` fallback.  | SC-12, AC-3, AU-3 | 3d  |
| P2-2  | `compliance/lula/sp80053/lula-ac-3.yaml`, `lula-sc-8.yaml`, `lula-si-4.yaml`, `lula-ia-3.yaml` | Create 4 new Lula SP 800-53 validation manifests using Kubernetes domain: check OPA Deployment ready, NetworkPolicy count ≥ 9, AgentSight DaemonSet running, mTLS annotation present                                   | AC-3, SC-8, SI-4, IA-3 | 5d               |
| P2-3  | `deployment/k8s/lula-cron.yaml`                                                                | Add `sp80053/` validations to CronJob `--input` flags; extend OSCAL Assessment Results to include SP 800-53 findings                                                                                                   | CA-7, CA-2             | 2d               |
| P2-4  | ~~`scripts/vulnerability_scan.sh` (new)~~                                                      | ~~CI step: `trivy image --exit-code 1 --severity CRITICAL <image>` for all 5 container images; `pip-audit` for Python deps; output SARIF to GitHub Security tab~~ **✅ COMPLETED:** Implemented in `.github/workflows/security-scan.yml` — pip-audit, Trivy, Grype, CycloneDX SBOM. See POAM-010 (Closed). | RA-5, SI-2, CM-8       | ✅               |
| P2-5  | `compliance/sbom/` (new directory)                                                             | Generate SBOM via `syft` or `cyclonedx-py` for all container images and Python packages; store in `compliance/sbom/<image>-<date>.json`; link from SSP                                                                 | SA-12, SR-3, CM-8      | 3d               |
| P2-6  | `deployment/k8s/` + all vLLM manifests                                                         | Replace `:latest` image tags with `@sha256:<digest>` via `docker inspect --format={{.RepoDigests}} <image>` in deploy script; pin all images                                                                           | CM-8, SI-2             | 2d               |
| P2-7  | `deployment/terraform/iam.tf`                                                                  | Audit all Service Account roles; remove `roles/editor` or `roles/owner` if present; apply least-privilege IAM roles per service (`financial-advisor-sa`: `storage.objectViewer` + `secretmanager.secretAccessor` only) | AC-6, IA-5             | 3d               |
| P2-8  | `deployment/k8s/network-policy.yaml`                                                           | Add Pod Security Admission `enforce: restricted` label to `governance-stack` namespace; add `securityContext.runAsNonRoot: true`, `readOnlyRootFilesystem: true` to all Deployments                                    | SC-7, AC-3             | 3d               |
| P2-9  | `src/compliance_bridge/notifier.py`, GitHub Actions                                            | On `GOVERNANCE_VIOLATION` event, auto-create GitHub Issue with: control ID, severity label, audit ID, link to Langfuse compliance trace, due-date (15/30/90 days by severity)                                          | CA-5, IR-6             | 4d               |
| P2-10 | `deployment/terraform/secrets.tf`                                                              | Add Secret Manager rotation schedule (`rotation_period: 7776000s` = 90 days) for all secrets; add `next_rotation_time` notification                                                                                    | IA-5, SC-12            | 2d               |
| P2-11 | `docs/CHANGE_MANAGEMENT_PROCESS.md` + `.github/CODEOWNERS`                                     | Formalize change management: CODEOWNERS requiring ISSO review for `compliance/`, `deployment/terraform/`, `src/gateway/governance/`; define significant-change re-authorization trigger                                | CM-3, CA-3             | 2d               |
| P2-12 | `compliance/oscal/sp80053-assessment-results.yaml` (new)                                       | Template for OSCAL Assessment Results format for SP 800-53 controls; populate from Lula SP 800-53 validation runs; link to `sp80053-profile.yaml`                                                                      | CA-2, CA-7             | 3d               |

---

### B.4 Phase 3: Architectural Uplift (Weeks 16–52)

> Long-effort items requiring architectural decisions, infrastructure procurement, and multi-sprint implementation.

| #     | Architecture Decision                                   | Implementation Steps                                                                                                                                                                                                                                                                      | Controls                   | Est. Person-Weeks |
| ----- | ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ----------------- |
| P3-1  | ~~**Intra-cluster mTLS (Istio Service Mesh)**~~ **✅ COMPLETED: Linkerd mTLS** | ~~Istio mTLS~~ **Superseded:** Linkerd mTLS implemented via `deployment/k8s/linkerd-mtls-policy.yaml`. Server + AuthorizationPolicy + MeshTLSAuthentication enforce SPIFFE/SVID identity for Gateway→OPA and Gateway→NeMo paths. Cilium L7 egress lockdown via `deployment/k8s/cilium-egress-lockdown.yaml`. See POAM-007 (Closed 2026-05-17). | IA-3, SC-8, SC-8(1), SC-23 | ✅                |
| P3-2  | **Pod Security Admission (PSA)**                        | 1. Add `pod-security.kubernetes.io/enforce: restricted` label to `governance-stack` namespace. 2. Audit all Pods for privileged containers, hostNetwork, hostPID. 3. Add `seccompProfile: RuntimeDefault` to all containers. 4. Create Lula k8s-domain validation for PSA labels.         | SC-7(21), AC-3             | 2w                |
| P3-3  | **KMS-backed Secret Rotation**                          | 1. Configure GCP Cloud KMS CMEK for Secret Manager. 2. Enable 90-day automatic rotation. 3. Add rotation notification to Cloud Pub/Sub → Slack. 4. Implement application-side secret refresh (reload from Secret Manager on rotation event).                                              | IA-5, SC-12, SC-28         | 3w                |
| P3-4  | **SBOM Pipeline + Continuous Vulnerability Management** | 1. CI: `syft` generates SBOM on each build; `grype` scans SBOM for CVEs. 2. Weekly scheduled `trivy` scans of running images. 3. Auto-create GitHub Issues for CRITICAL CVEs. 4. Block merges with unpatched CRITICAL CVEs in direct deps.                                                | RA-5, SI-2, SA-12, CM-8    | 3w                |
| P3-5  | **SP 800-53 Lula Validation Expansion**                 | 1. Create Lula validations for 20+ SP 800-53 controls across AC, AU, CM, IA, IR, RA, SC, SI families. 2. Add to CronJob. 3. Produce OSCAL Assessment Results. 4. Automate POAM creation on failures. Target: 70% control coverage.                                                        | CA-7, CA-2, All            | 6w                |
| P3-6  | **Full OSCAL SSP (Machine-Readable)**                   | 1. Convert `compliance/ssp/SYSTEM_SECURITY_PLAN.md` to OSCAL System Security Plan XML/YAML. 2. Link all Lula Assessment Results via `import-ssp`. 3. Submit to AO as primary authorization artifact.                                                                                      | CA-6, CA-2                 | 4w                |
| P3-7  | **Zero-Trust Network Architecture**                     | 1. Implement Kubernetes NetworkPolicy for all pod-to-pod flows (replace current 9-object set with comprehensive allow-list). 2. Add egress NetworkPolicy blocking unauthorized external calls. 3. Implement API gateway WAF rules.                                                        | SC-7, SC-7(5), AC-4        | 4w                |
| P3-8  | **Incident Response Automation**                        | 1. Create `docs/IR_PLAN.md` (SP 800-61 Rev 2 format). 2. Implement automated containment: on GOVERNANCE_VIOLATION CRITICAL, suspend traffic to affected pod via NetworkPolicy patch. 3. Integrate with SIEM.                                                                              | IR-1, IR-4, IR-5, IR-6     | 5w                |
| P3-9  | **Supply Chain Risk Management**                        | 1. Implement Sigstore/cosign container image signing in CI. 2. Add admission controller verifying image signatures. 3. Create approved software list. 4. Map to NIST SP 800-161r1.                                                                                                        | SA-12, SR-3, SR-4          | 4w                |
| P3-10 | **ATO Package Submission**                              | 1. Compile all 21 ATO artifacts (use P0-3 index). 2. Schedule Security Assessment (SA) with independent assessor. 3. Submit to AO for Authorization Decision. 4. Establish ongoing authorization process for cATO.                                                                        | CA-6, CA-7, CA-2           | 4w                |
| P3-11 | **Dual GCP Project Separation**                         | 1. Create `cage-compliance` GCP project with independent IAM policy. 2. Deploy compliance Langfuse instance in isolated project. 3. Establish VPC peering / Private Service Connect for compliance bridge → compliance Langfuse. 4. Remove Terraform fallback on `main.tf` L546-547 that silently collapses to app keys. 5. Update `prod.tfvars` with compliance project credentials. See [`DUAL_PROJECT_ARCHITECTURE.md` §6](../architecture/DUAL_PROJECT_ARCHITECTURE.md). | AU-9, AC-6, SC-7           | 3w                |
| P3-12 | ~~**External Normative Provider Integration (TrustLayers)**~~ **✅ COMPLETED: Adaptive Gating Primitive** | ~~Async sidecar only.~~ **Superseded:** Implemented `normative_provider.py` with tri-state `enforce_fria_boundary()` adaptive gating primitive: Score ≥ 0.95 → async attestation; [0.70, 0.95) → synchronous blocking gate via DEFER queue + `DeferReason.EXTERNAL_VALIDATION`; < 0.70 → local hard deny. `StubNormativeProvider` (dev/CI) and `TrustLayersProvider` (production HTTP). `NormativeProviderDaemon` boot-time fetch + 6h background polling. Gateway lifespan integration in `hybrid_server.py`. 29 tests passing, 0 regressions. See [`normative_provider.py`](../src/gateway/governance/normative_provider.py) and [`EXTENSIBILITY_ARCHITECTURE.md` §2.5](../architecture/EXTENSIBILITY_ARCHITECTURE.md). Closed 2026-05-28. | CA-7, SA-9, SC-7           | ✅                |

---

### B.5 ATO Readiness Progression Table

> Scores represent percentage of SP 800-53 Moderate baseline controls with credible implementation evidence per phase completion. Step 7 score is derived from ISCM completeness assessment against SP 800-137 criteria.

| Phase             | Steps 1–2 Score | Steps 3–4 Score | Steps 5–6 Score | Step 7 Score | Overall |
| ----------------- | --------------- | --------------- | --------------- | ------------ | ------- |
| **Current State** | **28%**         | **29%**         | **22%**         | **18%**      | **24%** |
| **After Phase 0** | **58%**         | **29%**         | **42%**         | **22%**      | **38%** |
| **After Phase 1** | **62%**         | **35%**         | **46%**         | **38%**      | **45%** |
| **After Phase 2** | **68%**         | **58%**         | **54%**         | **55%**      | **59%** |
| **After Phase 3** | **82%**         | **78%**         | **76%**         | **72%**      | **77%** |

**Score Derivation Notes:**

- **Steps 1–2 (Prepare/Categorize):** Phase 0 jumps from 28% to 58% by creating SSP, FIPS 199, Roles Matrix, and OSCAL profile (the four biggest blockers identified in Chunk 2).
- **Steps 3–4 (Select/Implement):** Phase 2 drives the largest gain through SP 800-53 Lula validations (+18%), IAM hardening (+6%), and vulnerability scanning (+5%).
- **Steps 5–6 (Assess/Authorize):** Phase 0 SSP creation (+20%) unblocks the authorization package; Phase 3 OSCAL SSP and SA bring it to 76%.
- **Step 7 (Monitor):** Phase 1 creates ISCM Strategy and POA&M (+15%), Phase 2 adds SP 800-53 ongoing assessments (+17%), Phase 3 completes SBOM and IR automation (+17%).
- **100% is not achievable without AO signature** on Authorization Decision — 77% represents the maximum achievable through technical and documentation controls alone.

---

### B.6 NIST RMF Control-to-Code Traceability Matrix

> Top 20 highest-priority SP 800-53 Rev 5 Moderate baseline controls mapped to specific source files. Status: **Implemented** = credible evidence exists; **Partial** = partial coverage; **Gap** = no implementation.

| Control ID | Control Name                    | Implementation File(s)                                                                                                                                                                                         | Status  | Gap                                                                     |
| ---------- | ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ----------------------------------------------------------------------- |
| AU-2       | Event Logging                   | [`src/gateway/infrastructure/telemetry.py`](src/gateway/infrastructure/telemetry.py:31), OTel collector (rendered via `deployment/k8s_rendered/`)                                                              | Partial | No formal auditable event list                                          |
| AU-3       | Content of Audit Records        | [`src/gateway/governance/iso_control.py`](src/gateway/governance/iso_control.py), [`src/compliance_bridge/audit_workflow.py`](src/compliance_bridge/audit_workflow.py:162)                                     | Partial | Missing `user_id`, `session_id`, `outcome_reason` in some spans         |
| AU-6       | Audit Record Review             | [`src/compliance_bridge/audit_workflow.py`](src/compliance_bridge/audit_workflow.py:215), [`src/compliance_bridge/notifier.py`](src/compliance_bridge/notifier.py:68)                                          | Partial | No scheduled review process; `fetch_langfuse_metrics.py` is manual only |
| AU-9       | Protection of Audit Information | [`src/compliance_bridge/storage.py`](src/compliance_bridge/storage.py:127) SHA-256 integrity                                                                                                                   | Partial | GCS bucket IAM not audited; no immutability lock on OSCAL artifacts     |
| AU-12      | Audit Record Generation         | [`src/gateway/observability/mcp_tracing.py`](src/gateway/observability/mcp_tracing.py:46), OTel collector (rendered via `deployment/k8s_rendered/`)                                                            | Partial | `automated_auditor.py` uses mock source; 1% sampling rate               |
| AC-2       | Account Management              | [`deployment/terraform/iam.tf`](deployment/terraform/iam.tf)                                                                                                                                                   | Gap     | No IAM audit workflow; teardown leaves compliance SAs active            |
| AC-3       | Access Enforcement              | [`deployment/system_authz.rego`](deployment/system_authz.rego), [`src/governed_financial_advisor/governance/policy/trade_governance.rego`](src/governed_financial_advisor/governance/policy/trade_governance.rego) | Partial | `CAGE_ROUTING_SEAL_SECRET` bypass not hardened                          |
| AC-6       | Least Privilege                 | [`deployment/terraform/iam.tf`](deployment/terraform/iam.tf)                                                                                                                                                   | Gap     | No least-privilege audit performed; IAM gap noted in Chunk 1            |
| CA-2       | Control Assessments             | [`compliance/lula/`](compliance/lula/) (4 files), [`src/compliance_bridge/oscal_parser.py`](src/compliance_bridge/oscal_parser.py:169)                                                                         | Partial | Only ISO 42001 controls; no SP 800-53 assessment scope                  |
| CA-5       | Plan of Action and Milestones   | `docs/POAM.md`                                                                                                                                                                                                 | Gap     | File does not exist; no formal POA&M tracking                           |
| CA-6       | Authorization                   | None                                                                                                                                                                                                           | Gap     | No SSP, no AO Authorization Decision document                           |
| CA-7       | Continuous Monitoring           | [`deployment/k8s/lula-cron.yaml`](deployment/k8s/lula-cron.yaml:153), [`src/compliance_bridge/sse_events.py`](src/compliance_bridge/sse_events.py:81)                                                          | Partial | 4 controls only; no ISCM strategy document                              |
| CM-3       | Configuration Change Control    | [`deployment/terraform/deploy.tf`](deployment/terraform/deploy.tf:15) SHA triggers                                                                                                                             | Partial | No formal CR process; no AO notification for significant changes        |
| CM-8       | System Component Inventory      | [`deployment/deploy_sw.py`](deployment/deploy_sw.py:210) image builds                                                                                                                                          | Partial | `:latest` tags; no SBOM; no approved software list                      |
| IA-3       | Device Identification and Auth  | [`deployment/k8s/linkerd-mtls-policy.yaml`](deployment/k8s/linkerd-mtls-policy.yaml), [`deployment/k8s/cilium-egress-lockdown.yaml`](deployment/k8s/cilium-egress-lockdown.yaml)                               | **✅ Implemented** | **POAM-007 RESOLVED 2026-05-17:** Linkerd mTLS + Cilium L7 enforce SPIFFE/SVID identity for intra-cluster service-to-service auth |
| IA-5       | Authenticator Management        | [`deployment/terraform/secrets.tf`](deployment/terraform/secrets.tf)                                                                                                                                           | Partial | No rotation schedule; no expiry enforcement                             |
| RA-5       | Vulnerability Monitoring        | None                                                                                                                                                                                                           | Gap     | No container scanning; no dependency vulnerability scanning in CI       |
| SC-8       | Transmission Confidentiality    | [`deployment/k8s/network-policy.yaml`](deployment/k8s/network-policy.yaml) (9 objects), [`deployment/k8s/linkerd-mtls-policy.yaml`](deployment/k8s/linkerd-mtls-policy.yaml)                                   | **✅ Implemented** | **POAM-007 RESOLVED 2026-05-17:** Intra-cluster traffic encrypted via Linkerd mTLS; Cilium L7 egress lockdown enforced |
| SI-2       | Flaw Remediation                | None                                                                                                                                                                                                           | Gap     | No vulnerability scanning pipeline; images pinned to `:latest`          |
| SI-4       | System Monitoring               | [`deployment/agentsight/agentsight-config.yaml`](deployment/agentsight/agentsight-config.yaml:19), [`src/gateway/observability/mcp_tracing.py`](src/gateway/observability/mcp_tracing.py:46)                   | Partial | ~~AgentSight in console mode~~ **✅ RESOLVED (POAM-021):** remote mode active; mock auditor source remains open |

---

### B.7 Executive Summary

The **Cybernetic Governance Engine (CAGE)** is a GKE-hosted AI governance platform for regulated financial AI applications. It enforces a **7-tier governance pipeline** (STPA → Aho-Corasick keyword scan → Control Barrier Functions → [SLM — DEPRECATED, `slm_available=False`] → OPA policy enforcement → Consensus verification → Causal gating) with Cloud KMS RSA-PKCS1-4096-SHA256-sealed verdicts, ISO 42001 A-control monitoring, and NeMo Guardrails content filtering. The system processes AI-generated financial advisory outputs and enforces trade governance policies in real time, making it an **information system with High Integrity impact** under FIPS 199 (C=Moderate / I=High / A=Moderate).

**Current Security Posture Strengths:** CAGE demonstrates genuine security engineering maturity in several areas. The governance pipeline is architecturally sophisticated — every LLM output is subject to deterministic policy checks before reaching users. Four ISO 42001 controls are automatically assessed every 6 hours via Lula with OSCAL evidence artifacts persisted to GCS. Real-time SSE event streaming pushes audit findings and governance violations to the KernelDashboard within seconds of detection. The Slack/PagerDuty alert pipeline and LLM-assisted remediation advisory (with mandatory human review gates) represent a thoughtful blend of automation and human oversight aligned with ISO 42001 A.7.2.

**Critical Gaps and Business Risk:** Despite the technical sophistication of the governance pipeline, the system cannot obtain an Authority to Operate under any recognized federal or commercial compliance framework today. The three ATO blockers are: (1) **No System Security Plan** — there is no document describing what the system does, its boundary, data flows, or how SP 800-53 controls are implemented; (2) **No FIPS 199 Categorization Document** — the system's risk profile is unformalized, meaning the AO has no basis for an authorization decision; and (3) **No vulnerability scanning or dependency lockfiles** — supply chain risk is entirely uncharacterized. At an overall RMF readiness score of 24%, the organization faces regulatory exposure, potential procurement disqualification, and — most critically — an AI governance system that governs AI without itself being governed by a formal security authorization process.

**Recommended Investment and Timeline:** The highest-leverage investment is a **12-week focused effort** to complete Phase 0 (authorization documentation, 2 weeks) and Phase 1 (quick wins: POA&M, ISCM strategy, vulnerability scanning, 4 weeks), followed by Phase 2 core hardening (10 weeks). This would bring overall RMF readiness from 24% to approximately 59%, sufficient to schedule an independent Security Assessment and present a credible authorization package to an AO. Phase 3 architectural work (Istio mTLS, KMS rotation, SBOM pipeline) would bring the system to 77% readiness — the practical ceiling before the AO's Authorization Decision. The total Phase 0–2 investment is estimated at 8–12 person-weeks from a combined ISSO, DevSecOps, and software engineering team.

**Expected ATO Readiness Date:** Assuming Phase 0 begins immediately and Phase 2 completes on schedule, the system could present an authorization package for AO review approximately **Q3 2026** (approximately 16 weeks from now). Conditional ATO (cATO) based on existing continuous monitoring capabilities (Lula CronJob + SC-4 watch + SSE pipeline) could be achievable 4–6 weeks sooner if an AO is willing to accept a phased authorization with a Phase 3 completion commitment as an ATO condition.

---

## Overall RMF Readiness Dashboard

| RMF Step | Step Name      | Current Score | Target After Phase 3 | Key Blocker                                                       |
| -------- | -------------- | ------------- | -------------------- | ----------------------------------------------------------------- |
| Step 1   | **Prepare**    | 28%           | 82%                  | No Roles Matrix; no OSCAL SSP profile import                      |
| Step 2   | **Categorize** | 28%           | 82%                  | No FIPS 199 Categorization Document; no SSP                       |
| Step 3   | **Select**     | 29%           | 78%                  | SP 800-53 profile not imported; only ISO 42001 controls selected  |
| Step 4   | **Implement**  | 29%           | 78%                  | 71% of sampled controls unimplemented; IA-3/AC-6 gaps critical    |
| Step 5   | **Assess**     | 22%           | 76%                  | No independent security assessment; 15 controls auto-assessed (up from 4) |
| Step 6   | **Authorize**  | 22%           | 76%                  | No SSP (POAM-015 open); no Authorization Decision; 24% ATO package completeness |
| Step 7   | **Monitor**    | 18%           | 72%                  | No ISCM strategy document; no POA&M; DEFER queue monitoring added |
|          | **Overall**    | **24%**       | **77%**              | **SSP + FIPS 199 doc are the critical path items**                |

**Step 7 Readiness Score Derivation (18%):**

- ISCM monitoring tools exist (OTel direct Langfuse OTLP, Lula CronJob 15 manifests, SSE, AgentSight eBPF): +8 points
- Periodic assessment cadence exists (6h Lula Critical, daily High, weekly Medium, 60s SC-4 watch): +5 points
- Alert/notification pipeline exists (Slack/PagerDuty capable): +5 points
- **✅ RESOLVED (POAM-021):** AgentSight exporter confirmed as `"remote"` mode targeting `http://agentsight-dashboard:8080`
- **v0.1.0 additions:** DEFER queue monitoring (AARM-V7), SHA-256 hash-chained context accumulator (AARM-V1), KMS batch-signed OSCAL artifacts, SR 26-2 framework adopted, CSA AARM v1.0 11-vector threat coverage
- Deducted: No ISCM strategy doc (−20), no POA&M (−20), no status reporting format (−10), no decommission controls (−10), no SP 800-53 ongoing assessment (−25)

---

_Document prepared as part of the 5-chunk NIST RMF analysis series for the Cybernetic Governance Engine. This is a living document — update after each Phase completion milestone. Updated 2026-06-01 for CAGE v0.1.0._

_References: NIST SP 800-37 Rev 2, SP 800-53 Rev 5, SP 800-137, SP 800-18 Rev 1, FIPS 199, FIPS 200, ISO/IEC 42001:2023, NIST SP 800-161r1, SR 26-2 (Federal Reserve, April 17, 2026), CSA AARM v1.0._
