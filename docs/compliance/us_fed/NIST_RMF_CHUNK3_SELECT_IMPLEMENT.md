# NIST RMF Steps 3–4: Select & Implement Controls

## Cybernetic Governance Engine — Gap Analysis Report (Chunk 3 of 5)

**Date:** 2026-06-01
**System:** Cybernetic Governance Engine (CAGE) v0.1.0
**Baseline:** NIST SP 800-53 Rev 5 **HIGH** baseline (derived from FIPS 199: C=Moderate / I=High / A=Moderate → overall High)
**Scope:** Steps 3 (Select) and 4 (Implement) — Control families AC, AU, CA, CM, IA, IR, RA, SC, SI
**Additional Frameworks:** SR 26-2 (Federal Reserve, April 17, 2026), CSA AARM v1.0
**Prior Chunk Readiness Score:** Step 1–2 = 28/100

---

## Table of Contents

1. [AC — Access Control](#ac--access-control)
2. [AU — Audit and Accountability](#au--audit-and-accountability)
3. [CA — Security Assessment and Authorization](#ca--security-assessment-and-authorization)
4. [CM — Configuration Management](#cm--configuration-management)
5. [IA — Identification and Authentication](#ia--identification-and-authentication)
6. [IR — Incident Response](#ir--incident-response)
7. [RA — Risk Assessment](#ra--risk-assessment)
8. [SC — System and Communications Protection](#sc--system-and-communications-protection)
9. [SI — System and Information Integrity](#si--system-and-information-integrity)
10. [Control Coverage Heatmap](#control-coverage-heatmap)
11. [Implementation Roadmap](#implementation-roadmap)
12. [Step 3–4 Readiness Score](#step-34-readiness-score)

---

## AC — Access Control

**Controls Required (HIGH baseline):** AC-1, AC-2, AC-3, AC-4, AC-5, AC-6, AC-7, AC-8, AC-11, AC-12, AC-14, AC-17, AC-18, AC-19, AC-20, AC-22

**Current State:**

- [`deployment/system_authz.rego`](../deployment/system_authz.rego:1) implements a token-based allow/deny with a single `data.auth_token` comparison. Deny-by-default posture is established (`default allow = false`). This is a flat shared-secret check with no role differentiation.
- [`src/governed_financial_advisor/governance/policy/trade_governance.rego`](../src/governed_financial_advisor/governance/policy/trade_governance.rego:1) implements RBAC at the trade action layer: `allowed_roles := {"junior", "senior"}` with fiscal thresholds ($5k/$10k for junior, $500k/$1M for senior). Fail-closed default (`default allow = "DENY"`). Prompt injection is blocked via `allow = "GOVERNANCE_VIOLATION"` on `prompt_injection_check`.
- [`deployment/terraform/iam.tf`](../deployment/terraform/iam.tf:1) defines only two GCP service accounts (`financial-advisor-sa`, `agentsight-ui-sa`) bound with `roles/iam.workloadIdentityUser`. No additional IAM role bindings are provisioned; principle of least privilege is not demonstrably constrained in Terraform.
- [`deployment/opa_config.yaml`](../deployment/opa_config.yaml:1) configures decision logs to stdout and sets a `default_decision` of `/finance/decision`. No remote bundle server or OPA management API token is configured.

**Gaps:**

1. **AC-2 (Account Management):** No account management procedures exist. There is no lifecycle management for the shared `auth_token` credential (creation, expiry, rotation, revocation). No documentation of authorized users or service identities.
2. **AC-3 (Access Enforcement):** RBAC in OPA covers trade actions only. The API gateway layer itself (`governance_middleware.py`) performs only HMAC seal verification (`X-CAGE-Routing-Seal`), not identity-based access enforcement. Any bearer of the routing seal may invoke governance endpoints without role checks.
3. **AC-5 (Separation of Duties):** No enforcement of duty separation between the financial advisor agent (planner), OPA (enforcer), and audit functions. A single service account (`financial-advisor-sa`) could in principle act in all three roles simultaneously.
4. **AC-6 (Least Privilege):** `deployment/terraform/iam.tf` binds only `workloadIdentityUser` but the Terraform files do not bind restrictive GCP IAM roles (e.g., `roles/storage.objectCreator` scoped to the OSCAL bucket, not `roles/storage.admin`). Actual least-privilege binding is absent from IaC.
5. **AC-7 (Unsuccessful Login Attempts):** No account lockout or attempt-counting mechanism. Repeated failed token comparisons in `system_authz.rego` will pass silently; no brute-force protection.
6. **AC-11/AC-12 (Session Lock / Session Termination):** No session management — the system is stateless at the HTTP layer. No token expiry or session timeout enforced.
7. **AC-17 (Remote Access):** No documented or enforced remote access policy. Gateway is exposed via Kubernetes Ingress without client-certificate or VPN requirements documented in policy.

**Implementation Recommendations:**

1. **Add AC-2 account management policy:** Create `docs/AC2_Account_Management_Procedure.md` documenting authorized service identities, token rotation schedule (≤90 days), and revocation procedure. Map `GOVERNANCE_SALT` / `OPA_AUTH_TOKEN` rotation to this policy.
2. **Implement AC-3 role-based enforcement at the API layer:** In [`src/gateway/server/governance_middleware.py`](../src/gateway/server/governance_middleware.py:119), add a `require_role(request, allowed_roles)` dependency that extracts a JWT claim or Kubernetes service account name and validates it against an allow-list before reaching `enforce_governance()`.
3. **Implement AC-5 duty separation via OPA:** Add a Rego rule in [`deployment/system_authz.rego`](../deployment/system_authz.rego:1) that prevents the same principal that submits a trade from also approving it — require `input.submitter != input.approver` for `execute_trade` with `MANUAL_REVIEW` disposition.
4. **Enforce AC-6 in Terraform:** In [`deployment/terraform/iam.tf`](../deployment/terraform/iam.tf:1), add scoped IAM bindings — e.g., `roles/storage.objectCreator` on the OSCAL bucket only, `roles/redis.viewer` for the financial-advisor SA — replacing implicit broad permissions.
5. **Add AC-7 brute-force protection:** In `system_authz.rego`, add a `failed_attempts` rule that tracks auth failures in OPA's external data store (or emit a metric to OTel) and feed a Redis counter that the middleware checks before forwarding to OPA.

---

## AU — Audit and Accountability

**Controls Required (HIGH baseline):** AU-1, AU-2, AU-3, AU-4, AU-5, AU-6, AU-7, AU-8, AU-9, AU-10, AU-11, AU-12, AU-14

**Current State:**

- [`src/gateway/infrastructure/telemetry.py`](../src/gateway/infrastructure/telemetry.py:1) provides an OTel tracer factory via `get_tracer()`. OpenTelemetry spans are emitted for all governance pipeline stages. Graceful fallback to `None` when OTel is not installed. **v0.1.0:** Standalone OTel Collector **deprecated 2026-05-31**; direct Langfuse OTLP ingestion at `http://langfuse-web:3000/api/public/otel/v1/traces`.
- [`src/gateway/observability/mcp_tracing.py`](../src/gateway/observability/mcp_tracing.py:46) patches `ToolManager.call_tool` with W3C distributed trace context propagation. Every MCP tool invocation is wrapped in a child span with `mcp.tool.name`, input, and output attributes. Tool result is truncated to 4096 chars and recorded on the span.
- [`src/compliance_bridge/audit_workflow.py`](../src/compliance_bridge/audit_workflow.py:500) implements a 5-step audit pipeline: (1) persist OSCAL to S3/GCS with **KMS batch signing** (`kms_batch_signer.py`), (2) parse OSCAL deterministically, (3) ingest findings to Langfuse compliance project via direct OTLP, (4) alert on critical failures via Slack/console, (5) generate LLM remediation advisory. Each step records model version and trace IDs. Human review is mandatory before applying LLM suggestions (ISO 42001 A.7.2 annotation).
- [`src/compliance_bridge/metrics.py`](../src/compliance_bridge/metrics.py:197) provides TTL-cached compliance metric aggregation from Langfuse with 5-minute cache. Queries ISO 42001 control-tagged traces.
- [`scripts/automated_auditor.py`](../scripts/automated_auditor.py:22) — `TraceAuditor.fetch_recent_traces()` uses **hardcoded mock traces** at line 32, not a live Cloud Trace / OTLP endpoint. The invariant checker logic is correct but exercises only synthetic data in production. (POAM-003 open)

**Gaps:**

1. **AU-3 (Content of Audit Records):** OTel spans record `mcp.tool.name` and truncated I/O but do not systematically capture the **who** (authenticated principal identity) on every audit record. `input.identity` is present in OPA payloads but not propagated into OTel span attributes.
2. **AU-4 (Audit Log Storage Capacity):** No audit log retention policy or capacity management documented. OSCAL artifacts are stored to S3/GCS but the bucket lifecycle policy (defined in [`deployment/terraform/variables.tf`](../deployment/terraform/variables.tf:94)) names `cage-oscal-artifacts` with 7-year intent but the actual S3 lifecycle rule is not in the Terraform files.
3. **AU-9 (Protection of Audit Information):** OTel spans to Langfuse are not tamper-protected at the transport layer (no client-cert mTLS to Langfuse endpoint verified in config). OSCAL artifacts are stored with SHA-256 content hash in object metadata (`storage.py:169`) — this provides integrity evidence but no access-control restriction on the S3 bucket policy is demonstrated.
4. **AU-10 (Non-repudiation):** **v0.1.0 PARTIALLY ADDRESSED:** Cloud KMS HSM-backed asymmetric signing (`kms_signer.py`) is now the primary signing mechanism for governance verdicts, providing genuine non-repudiation. HMAC-SHA256 routing seal remains as dev/CI fallback only. KMS batch signing (`kms_batch_signer.py`) signs OSCAL artifacts before GCS persistence.
5. **AU-11 (Audit Record Retention):** No explicit retention schedule enforced programmatically. `compliance/lula/lula-validation-a53.yaml` checks evidence freshness (≤48h) but does not enforce minimum retention.
6. **AU-12 (Audit Record Generation):** `TraceAuditor` in `automated_auditor.py` must be connected to a live OTLP endpoint (Google Cloud Trace API or Jaeger) — the mock source at line 32 (`"Mock source. In production, this would query..."`) represents a critical gap.

**Implementation Recommendations:**

1. **Fix AU-12 live trace source:** Replace `fetch_recent_traces()` mock in [`scripts/automated_auditor.py`](../scripts/automated_auditor.py:32) with a real query to `google.cloud.trace_v1.TraceServiceClient` or OTLP-compatible Jaeger query API. Add environment variable `TRACE_SOURCE_URL` to `config/settings.py`.
2. **Add AU-3 principal identity to spans:** In [`src/gateway/observability/mcp_tracing.py`](../src/gateway/observability/mcp_tracing.py:63), add `span.set_attribute("enduser.id", extracted_identity)` using the `X-CAGE-Routing-Seal` verified identity or a JWT sub claim.
3. **Implement AU-9 S3 bucket policy:** Add a Terraform resource `aws_s3_bucket_policy` (or GCS IAM condition) in a new `deployment/terraform/storage_policy.tf` file that restricts `cage-oscal-artifacts` to read-only for the compliance-bridge SA and denies `s3:DeleteObject` to all principals.
4. **Add AU-11 lifecycle rule:** In `deployment/terraform/storage.tf`, add a GCS lifecycle rule (`age = 2555` days / 7 years) on the `cage-oscal-artifacts` bucket with `action = "Delete"` after 2555 days to comply with AU-11 minimum retention.
5. **Implement AU-10 asymmetric signing:** Replace HMAC-SHA256 verdict sealing (`governance_middleware.py:75`) with ECDSA P-256 signature using a private key stored in GCP Secret Manager. The verifier uses only the public key, providing non-repudiation.

---

## CA — Security Assessment and Authorization

**Controls Required (HIGH baseline):** CA-1, CA-2, CA-3, CA-5, CA-6, CA-7, CA-8, CA-9

**Current State:**

- [`compliance/oscal/component-definition.yaml`](../compliance/oscal/component-definition.yaml:1) defines 3 software components (TypeScript Gateway, OPA, NeMo+Presidio) mapped to 4 ISO 42001 controls (A.5.2, A.5.3, SC-4, A.9.2). Uses OSCAL 1.0.4 schema. No SP 800-53 control source is referenced — all `source:` fields point to the ISO 42001 URL.
- [`compliance/lula/`](../compliance/lula/) — **15 automated validation manifests** drive continuous compliance checks across ISO 42001, NIST SP 800-53, and CSA AARM controls. Cadence tiers enforced by `lula_scheduler.py`: Critical=6h, High=daily, Medium=weekly. CronJob defined in `deployment/k8s/lula-cron.yaml`.
- [`src/compliance_bridge/oscal_parser.py`](../src/compliance_bridge/oscal_parser.py:169) provides deterministic OSCAL Assessment Result YAML parsing with strict Pydantic validation. Used by `audit_workflow.py` to ingest Lula output.
- The Langfuse compliance project (dual-project architecture) acts as a continuous evidence store, with 5-minute TTL caching in `metrics.py`.

**Gaps:**

1. **CA-2 (Security Assessments):** No formal security assessment plan (SAP) document exists. Lula continuous compliance is strong but covers only 4 ISO 42001 controls. There is no penetration test plan, no security assessment report (SAR), and zero SP 800-53 controls validated by Lula.
2. **CA-3 (Information Exchange):** No System Interconnection Agreements (SIAs) documented for external service connections: Langfuse cloud, vLLM inference (potentially external), GCS/MinIO storage, Slack webhook.
3. **CA-5 (Plan of Action and Milestones):** No POA&M document exists in the repository. Gaps from Chunk 2 have no tracking entries with owners, due dates, or milestone targets.
4. **CA-6 (Authorization):** No formal Authorization to Operate (ATO) package or Memorandum of Authorization exists. No Authorizing Official (AO) named.
5. **CA-7 (Continuous Monitoring):** Lula CronJob provides continuous control monitoring for ISO 42001 controls. However, there is no continuous monitoring plan (CMP) document, no monitoring frequency formally defined per control, and NIST SP 800-53 controls are not included in the monitoring scope.
6. **CA-9 (Internal System Connections):** No internal connection inventory — Redis, OPA sidecar, vLLM, NeMo, MinIO connections are not formally documented as internal system connections with authorization decisions.

**Implementation Recommendations:**

1. **Create CA-5 POA&M:** Create `docs/POAM.md` with a table format: Weakness ID | Control | Description | Responsible Party | Scheduled Completion | Resources Required | Status. Populate with gaps from Chunks 2–3.
2. **Add SP 800-53 Lula validations:** Create `compliance/lula/lula-validation-ac3.yaml` (kubernetes domain checking `system_authz.rego` is mounted), `lula-validation-au12.yaml` (api domain checking OTel collector is reachable), and `lula-validation-si2.yaml` (checking image scan results). Add these to [`compliance/oscal/component-definition.yaml`](../compliance/oscal/component-definition.yaml:43) with `source: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"`.
3. **Create CA-7 Continuous Monitoring Plan:** Create `docs/Continuous_Monitoring_Plan.md` specifying Lula CronJob frequency (every 6h per `deployment/k8s/lula-cron.yaml`), alert thresholds, and escalation contacts.
4. **Create CA-3 System Interconnection Register:** Create `docs/System_Interconnection_Agreements.md` listing all external system connections with data flow, protection measures, and authorization status.

---

## CM — Configuration Management

**Controls Required (HIGH baseline):** CM-1, CM-2, CM-3, CM-4, CM-5, CM-6, CM-7, CM-8, CM-9, CM-10, CM-11

**Current State:**

- [`config/governance_thresholds.json`](../config/governance_thresholds.json:1) is the single source of truth for all numeric governance thresholds (CBF, drawdown, STPA, confidence, consensus, Tier-1 keywords). `_schema_version: "1.0.0"` is declared. All modules must reference the loaded Pydantic singleton — no inline literals permitted by policy.
- [`config/settings.py`](../config/settings.py:1) centralizes all environment variable resolution with `validate_required_settings()` called at startup that fails fast if required vars are absent. `REQUIRED_ENV_VARS` list is explicitly maintained.
- [`config/rails/config.yml`](../config/rails/config.yml:1) configures NeMo Guardrails with 17 PII entity types in both input and output rails. Model name is overridden at runtime via `GUARDRAILS_MODEL_NAME` env var. Colang version is pinned to `"2.x"`.
- [`deployment/terraform/variables.tf`](../deployment/terraform/variables.tf:1) provides variable definitions for 26 infrastructure parameters. Sensitive variables are marked `sensitive = true`. MinIO, PostgreSQL, GPU, OSCAL storage all parameterized.

**Gaps:**

1. **CM-2 (Baseline Configuration):** No formal configuration baseline document. `governance_thresholds.json` captures application-layer thresholds but there is no documented infrastructure baseline (OS image versions, Kubernetes version, Helm chart versions) or a process to establish and maintain it.
2. **CM-3 (Configuration Change Control):** No change control board (CCB) process documented. Changes to `governance_thresholds.json` or Rego policies can be merged without formal review — CONTRIBUTING.md exists but doesn't mandate CCB for security-relevant configuration.
3. **CM-4 (Impact Analysis):** No impact analysis requirement before configuration changes. Modifying `confidence.min_trade_confidence` from 0.95 has security implications (AC, SI) that are not formally analyzed.
4. **CM-5 (Access Restrictions for Change):** No documented access restriction on who may modify Rego policies, `governance_thresholds.json`, or Terraform IaC. Branch protection rules (if any) are not referenced in security documentation.
5. **CM-7 (Least Functionality):** No port/service inventory. Multiple services (NeMo, vLLM, Redis, OPA) are exposed within the cluster. No formal review that only necessary functions are enabled.
6. **CM-8 (System Component Inventory):** No software component inventory (SBOM) generated or maintained. Container images referenced in Dockerfiles are not pinned to content-digest hashes.
7. **CM-11 (User-Installed Software):** No policy preventing users from installing software in running containers. No immutable rootfs enforcement in k8s pod specs.

**Implementation Recommendations:**

1. **Generate CM-8 SBOM:** Add `syft` or `grype` to the CI pipeline (`.github/` workflows) to generate an SPDX SBOM on every image build. Store output as a GitHub Release artifact. Add `sbom:` key to `compliance/oscal/component-definition.yaml` back-matter.
2. **Implement CM-3 change control:** Add a required PR review rule in `.github/` for changes to `config/governance_thresholds.json`, `deployment/system_authz.rego`, and `compliance/lula/` — require at least one Security Owner approval via `CODEOWNERS`.
3. **Pin container images:** In `Dockerfile`, `Dockerfile.nemo`, `Dockerfile.vllm`, replace `FROM image:tag` with `FROM image:tag@sha256:<digest>` for all base images.
4. **Create CM-2 baseline document:** Create `docs/Configuration_Baseline.md` listing Kubernetes version, Python version, key library versions (from `pyproject.toml`), and OPA version. Establish process to update on each deployment.
5. **Add CM-7 port inventory:** Document all intra-cluster ports in `docs/Network_Architecture.md` derived from [`deployment/k8s/network-policy.yaml`](../deployment/k8s/network-policy.yaml:1) — ports 8080, 8181, 6379, 4317, 4318, 8000, 53.

---

## IA — Identification and Authentication

**Controls Required (HIGH baseline):** IA-1, IA-2, IA-2(1), IA-2(12), IA-3, IA-4, IA-5, IA-5(1), IA-6, IA-7, IA-8, IA-11, IA-12

**Current State:**

- [`src/gateway/server/governance_middleware.py`](../src/gateway/server/governance_middleware.py:55) implements `_verify_routing_seal()` using `hmac.new(CAGE_ROUTING_SEAL_SECRET, body_bytes, sha256)`. This is a message authentication code on the request body — it authenticates the _message_ origin but not the _user or service identity_. It is a seal, not an identity assertion.
- [`deployment/system_authz.rego`](../deployment/system_authz.rego:8) performs identity check via `input.identity == data.auth_token` — a single shared secret comparison. No MFA, no role encoding, no expiry.
- [`deployment/terraform/iam.tf`](../deployment/terraform/iam.tf:20) — GKE Workload Identity is configured for both SAs (`roles/iam.workloadIdentityUser`). This provides pod-level identity to GCP services via the metadata server — a meaningful IA control for GCP service calls.
- **v0.1.0:** Cloud KMS HSM-backed asymmetric signing (`kms_signer.py`) provides cryptographic service identity for governance verdict signing. Workload Identity used for GCS/KMS access. Linkerd mTLS (POAM-007 closed 2026-05-17) provides SPIFFE/SVID-based service identity for intra-cluster communication.
- No JWT or OAuth 2.0 token validation is present at the API gateway layer.

**Gaps:**

1. **IA-2 (Identification and Authentication — Organizational Users):** No human user authentication implemented. The system is designed for service-to-service communication but has no documented prohibition on direct human access to governance endpoints.
2. **IA-2(1) (MFA for Privileged Accounts):** No multi-factor authentication exists for any access path. The shared `auth_token` is single-factor.
3. **IA-2(12) (Acceptance of PIV Credentials):** Not implemented; no PIV/CAC credential support.
4. **IA-3 (Device Identification and Authentication):** Workload Identity provides GKE pod identity for GCP API calls, but within the cluster, service-to-service calls rely on the shared routing seal secret, not per-service cryptographic identities (mTLS certificates).
5. **IA-5 (Authenticator Management):** No authenticator management policy. The `OPA_AUTH_TOKEN`, `GOVERNANCE_SALT`, `CAGE_ROUTING_SEAL_SECRET` have no documented rotation schedule or minimum length requirements.
6. **IA-5(1) (Password-Based Authentication):** `config/settings.py:54` shows `OPA_AUTH_TOKEN = os.getenv("OPA_AUTH_TOKEN")` with no validation of token length, complexity, or entropy.
7. **IA-11 (Re-authentication):** No session re-authentication enforced. Stateless API with no token expiry.

**Implementation Recommendations:**

1. **Implement IA-3 mTLS for inter-service authentication:** Add an Istio service mesh or cert-manager `Certificate` resource to issue short-lived mTLS certs for each service. Alternatively, use SPIFFE/SPIRE for workload identity attestation. Document in `deployment/k8s/`.
2. **Add IA-5 secret validation at startup:** In `config/settings.py:validate_required_settings()`, add minimum entropy check: `if len(os.environ.get("CAGE_ROUTING_SEAL_SECRET","")) < 32: raise RuntimeError("CAGE_ROUTING_SEAL_SECRET must be at least 32 bytes")`. Similarly for `OPA_AUTH_TOKEN`.
3. **Implement IA-5 secret rotation:** Add a `deployment/k8s/secret-rotation-cronjob.yaml` that calls GCP Secret Manager to rotate `CAGE_ROUTING_SEAL_SECRET` and `OPA_AUTH_TOKEN` every 90 days, updates the k8s Secret, and triggers a rolling restart of affected deployments. Satisfies IA-5(1).
4. **Document IA-2 access paths:** Create `docs/Authentication_Architecture.md` documenting all access paths, their authentication mechanisms, and why human MFA (IA-2(1)) either applies or is not applicable (system-to-system boundary).

---

## IR — Incident Response

**Controls Required (HIGH baseline):** IR-1, IR-2, IR-3, IR-4, IR-5, IR-6, IR-7, IR-8, IR-10

**Current State:**

- [`src/compliance_bridge/notifier.py`](../src/compliance_bridge/notifier.py:183) implements `SlackNotifier`, `ConsoleNotifier`, and `MockNotifier` with Slack Block Kit payloads for critical compliance failures and LLM remediation advisories. Factory pattern with `ALERT_CHANNEL` env var. `MockNotifier` is gated behind `TESTING=1` check — production safety guard present.
- [`src/compliance_bridge/sse_events.py`](../src/compliance_bridge/sse_events.py:81) implements `GovernanceEventBus` — an in-process pub/sub for real-time SSE streaming of `AUDIT_FINDING` and `GOVERNANCE_VIOLATION` events to the AgentSight UI dashboard (`KernelDashboard.tsx`).
- [`src/compliance_bridge/audit_workflow.py`](../src/compliance_bridge/audit_workflow.py:215) step 4 calls `_step4_alert_on_critical_fail()` which filters for `CRITICAL_CONTROLS` and calls `notifier.send_critical_alert()`. Events are published to the SSE bus simultaneously.
- [`src/compliance_bridge/storage.py`](../src/compliance_bridge/storage.py:215) provides idempotent OSCAL artifact persistence with SHA-256 content hashing — serves as the evidence preservation function for incident records.

**Gaps:**

1. **IR-1 (Incident Response Policy):** No incident response policy or plan document exists in the repository. Alerting infrastructure exists (Slack, console) but there is no documented incident classification taxonomy, escalation path, or response procedures.
2. **IR-2 (Incident Response Training):** No evidence of incident response training or exercises.
3. **IR-3 (Incident Response Testing):** No tabletop exercise records, no automated IR drill (e.g., chaos injection that triggers alerts and verifies end-to-end alert delivery).
4. **IR-4 (Incident Handling):** Alert delivery via `SlackNotifier` is a one-way push. There is no incident ticketing integration (PagerDuty, Jira, ServiceNow) and no acknowledgement or escalation workflow — if the webhook times out in 10 seconds (`httpx.AsyncClient(timeout=10.0)`), the alert is silently lost without retry.
5. **IR-5 (Incident Monitoring):** No centralized incident log distinct from the compliance audit trail. `GOVERNANCE_VIOLATION` events are streamed to SSE but not persisted to a separate incident log store.
6. **IR-6 (Incident Reporting):** No documented process for reporting to US-CERT/CISA within required timeframes. No contact information in the system documentation.
7. **IR-8 (Incident Response Plan):** No documented IRP. The notifier infrastructure is the only response automation.

**Implementation Recommendations:**

1. **Create IR-8 Incident Response Plan:** Create `docs/Incident_Response_Plan.md` with: incident classification (Critical/High/Medium/Low), escalation matrix (On-call → ISSO → AO), response timeframes (Critical: 1h), communication templates, and recovery procedures.
2. **Add IR-4 alert retry with PagerDuty fallback:** In [`src/compliance_bridge/notifier.py`](../src/compliance_bridge/notifier.py:192), wrap the Slack `client.post()` in a retry loop (3 attempts, exponential backoff). Add a `PagerDutyNotifier` class as secondary fallback when `PAGERDUTY_ROUTING_KEY` env var is set.
3. **Add IR-5 persistent incident log:** In `audit_workflow.py`, after `_step4_alert_on_critical_fail()`, write incident records to a dedicated Postgres table (`incident_log`) with: `audit_id`, `control_id`, `severity`, `timestamp`, `resolution_status`. Add a migration in `deployment/terraform/`.
4. **Add IR-3 automated drill:** Create `tests/governance/test_ir_drill.py` that injects a synthetic FAIL finding into `run_audit_workflow()` and asserts that `SlackNotifier.send_critical_alert()` was called within 30 seconds. Run in CI nightly.

---

## RA — Risk Assessment

**Controls Required (HIGH baseline):** RA-1, RA-2, RA-3, RA-3(1), RA-5, RA-5(2), RA-5(4), RA-5(5), RA-7, RA-9

**Current State:**

- [`docs/STPA_ANALYSIS.md`](../docs/STPA_ANALYSIS.md:1) documents the System-Theoretic Process Analysis for the Financial Advisor module: control structure (Controller: AI Agent, Actuators: Gateway Tools, Controlled Process: Markets), 5 Unsafe Control Actions (UCA-1 through UCA-5), and their code implementations.
- [`src/gateway/governance/stpa_validator.py`](../src/gateway/governance/stpa_validator.py:35) implements deterministic UCA constraint checking for `execute_trade` actions: SC-1 (approval token), FIN-1 (max sell fraction), FIN-2 (latency), UCA-5 (drawdown), UCA-6 (slippage/sequence). All thresholds sourced from `config/governance_thresholds.json`.
- [`src/gateway/governance/safety.py`](../src/gateway/governance/safety.py:115) implements the Control Barrier Function (CBF) — a formal safety constraint that maintains `h(x) = cash_balance - min_cash_balance ≥ 0` with Redis-backed atomic state via WATCH/MULTI/EXEC (Phase 4.1).
- No `docs/proposals/004_risk_remediation_plan.md` exists in the repository — that path was checked and not found.

**Gaps:**

1. **RA-1 (Risk Assessment Policy):** No formal risk assessment policy document. STPA is excellent engineering practice but not a formal NIST risk assessment methodology document.
2. **RA-2 (Security Categorization):** FIPS 199 categorization is inferred from system characteristics but not documented in a formal `FIPS199_Categorization.md` or OSCAL SSP (as noted in Chunk 2).
3. **RA-3 (Risk Assessment):** No formal risk assessment (RA) document identifying threats, vulnerabilities, likelihood, impact, and risk level using NIST SP 800-30 methodology. STPA covers safety hazards but not cybersecurity threats (e.g., data exfiltration, privilege escalation, supply chain compromise).
4. **RA-5 (Vulnerability Scanning):** No container image vulnerability scanning in the CI/CD pipeline. No dependency scanning (e.g., `pip audit`, `trivy`) evidence. SBOM absent (see CM-8).
5. **RA-5(4) (Discoverable Information):** No assessment of information discoverable through reconnaissance (e.g., API endpoint enumeration, error message information disclosure).
6. **RA-9 (Criticality Analysis):** No supply chain criticality analysis. Dependencies on Langfuse (SaaS), vLLM model weights (external download), NeMo (NVIDIA), and Presidio (Microsoft) are not formally assessed for criticality or supply chain risk (SSCRM).

**Implementation Recommendations:**

1. **Create RA-3 Risk Assessment document:** Create `docs/Risk_Assessment.md` using NIST SP 800-30 Rev 1 format — threat sources, threat events, vulnerabilities, likelihood (1–5), impact (1–5), risk level matrix. Cover at minimum: prompt injection supply chain risk, model exfiltration, insider threat, cloud provider outage.
2. **Implement RA-5 vulnerability scanning:** Add `trivy image --exit-code 1 --severity CRITICAL` to the GitHub Actions workflow in `.github/` for all Dockerfiles. Add `pip audit` as a required CI check for Python dependencies.
3. **Create RA-9 Supply Chain Risk Assessment:** Create `docs/Supply_Chain_Risk_Assessment.md` mapping CAGE third-party dependencies (Langfuse, vLLM, NeMo, Presidio, Lula, OPA) to NIST SP 800-161 controls — C-SCRM.
4. **Document RA-2 formally:** Create `docs/FIPS199_Categorization.md` recording the formal categorization decision (C=Moderate, I=High, A=Moderate → HIGH), rationale, and signatures per SP 800-60 Volume II tables.

---

## SC — System and Communications Protection

**Controls Required (HIGH baseline):** SC-1, SC-2, SC-4, SC-5, SC-7, SC-8, SC-8(1), SC-10, SC-12, SC-13, SC-15, SC-17, SC-18, SC-20, SC-22, SC-23, SC-28, SC-28(1), SC-39

**Current State:**

- [`deployment/k8s/network-policy.yaml`](../deployment/k8s/network-policy.yaml:1) implements 9 Kubernetes NetworkPolicy objects with default-deny ingress and egress. Explicit allow rules for: gateway ingress (port 8080, from `cage.io/role=orchestrator` pods only), OPA (8181), Redis (6379), DNS (53/UDP), vLLM (8000), Langfuse OTLP (3000). **Note:** OTLP collector ports 4317/4318 removed — standalone OTel Collector deprecated 2026-05-31. This is a strong boundary protection implementation.
- **v0.1.0 — Linkerd mTLS + Cilium L7 egress lockdown (POAM-007 closed 2026-05-17):** [`deployment/k8s/linkerd-mtls-policy.yaml`](../deployment/k8s/linkerd-mtls-policy.yaml) enforces SPIFFE/SVID identity for Gateway→OPA and Gateway→NeMo paths via Server + AuthorizationPolicy + MeshTLSAuthentication resources. [`deployment/k8s/cilium-egress-lockdown.yaml`](../deployment/k8s/cilium-egress-lockdown.yaml) enforces FQDN allowlist for all egress traffic. This addresses SC-8(1) and IA-3 gaps identified in the prior version.
- [`deployment/terraform/networking.tf`](../deployment/terraform/networking.tf:1) provisions a GCP Cloud NAT and Cloud Router for controlled egress. NAT logging is enabled (`filter = "ERRORS_ONLY"`). All subnets use Cloud NAT for outbound connectivity (no direct internet IPs on nodes).
- [`src/gateway/server/governance_middleware.py`](../src/gateway/server/governance_middleware.py:55) enforces `X-CAGE-Routing-Seal` HMAC-SHA256 on the request body. Enforcement mode (enforce vs. log) is configurable via `CAGE_SEAL_ENFORCEMENT` env var. If `CAGE_ROUTING_SEAL_SECRET` is not set, the check is bypassed with a warning — this is a gap in production hardening.
- [`src/gateway/governance/safety.py`](../src/gateway/governance/safety.py:115) implements the Control Barrier Function with SC-relevant safety attributes (`iso42001.control = "A.4.2"` stamped on OTel spans).

**Gaps:**

1. **SC-8 / SC-8(1) (Transmission Confidentiality and Integrity / Cryptographic Protection):** No evidence of TLS enforcement between services within the cluster. NetworkPolicy restricts who can connect on which ports but does not enforce TLS. gRPC protos in `src/gateway/protos/` do not appear to use TLS credentials in the generated stubs reviewed.
2. **SC-12 (Cryptographic Key Establishment and Management):** No key management plan. HMAC secrets (`GOVERNANCE_SALT`, `CAGE_ROUTING_SEAL_SECRET`, `OPA_AUTH_TOKEN`) are managed via Kubernetes Secrets (`deployment/k8s/oscal-artifact-secrets.yaml`). No HSM or KMS-backed key storage verified in Terraform. No key rotation automation.
3. **SC-13 (Cryptographic Protection):** HMAC-SHA256 is used for integrity; OTel transport may be unencrypted within the cluster. No FIPS 140-3 validated cryptographic module reference.
4. **SC-17 (Public Key Infrastructure Certificates):** No PKI or certificate management infrastructure. Kubernetes Ingress TLS certificate management is not defined in the reviewed Terraform or k8s manifests.
5. **SC-23 (Session Authenticity):** No TLS session management — see SC-8. Stateless API with no session tokens.
6. **SC-28 / SC-28(1) (Protection of Information at Rest / Cryptographic Protection):** OSCAL artifacts in S3/GCS have content hash metadata but no server-side encryption (SSE) configuration is visible in the storage Terraform. Redis data (CBF cash balance, session state) is not encrypted at rest per any Terraform or Redis config reviewed.
7. **SC-39 (Process Isolation):** NeMo, OPA, vLLM, and the gateway run as separate pods — container-level isolation. No Pod Security Admission (PSA) or `securityContext` constraints requiring `runAsNonRoot`, `readOnlyRootFilesystem`, or `allowPrivilegeEscalation: false` are defined in the reviewed deployment templates.

**Implementation Recommendations:**

1. **Implement SC-8(1) intra-cluster TLS:** Add Istio sidecar injection annotation (`sidecar.istio.io/inject: "true"`) to all governance-stack pod specs in `deployment/k8s/`. Configure a `PeerAuthentication` policy requiring mTLS for all intra-namespace traffic. Alternatively, deploy cert-manager with a cluster CA and configure each service to present a certificate.
2. **Add SC-39 Pod Security constraints:** Add `securityContext` to all k8s Deployment templates in `deployment/k8s/`:
   ```yaml
   securityContext:
     runAsNonRoot: true
     runAsUser: 1000
     readOnlyRootFilesystem: true
     allowPrivilegeEscalation: false
   ```
3. **Add SC-12 KMS-backed secrets:** In `deployment/terraform/iam.tf`, add a `google_kms_crypto_key` resource and configure Kubernetes Secret encryption with the CMEK. Reference the key in GKE cluster configuration (`boot_disk_kms_key`).
4. **Enforce SC-12 seal secret presence:** In [`src/gateway/server/governance_middleware.py`](../src/gateway/server/governance_middleware.py:64), change the `if not _CAGE_SEAL_SECRET: return True` bypass to raise a `RuntimeError` at module load time in production (`ENVIRONMENT != "development"`).
5. **Add SC-28 GCS encryption config:** In `deployment/terraform/storage.tf`, add `encryption.default_kms_key_name` to the `google_storage_bucket` resource for the OSCAL artifacts bucket.

---

## SI — System and Information Integrity

**Controls Required (HIGH baseline):** SI-1, SI-2, SI-3, SI-4, SI-4(2), SI-5, SI-7, SI-7(1), SI-7(6), SI-10, SI-12, SI-16, SI-19

**Current State:**

- [`src/gateway/governance/symbolic_governor.py`](../src/gateway/governance/symbolic_governor.py:1) orchestrates the full governance pipeline: STPA → CBF → OPA → Consensus (7-tier). **v0.1.0:** SLM sidecar permanently deprecated; `slm_available=False` sentinel is always injected; OPA always applies elevated confidence threshold (0.97). Fail-secure degraded mode is the permanent operating mode.
- [`src/gateway/governance/stpa_validator.py`](../src/gateway/governance/stpa_validator.py:35) implements deterministic input validation against 5 STPA constraints (SC-1, FIN-1, FIN-2, UCA-5, UCA-6). All constraint failures return error messages and the action is blocked — SI-10 (Information Input Validation) is partially implemented for the trade domain.
- [`src/gateway/governance/safety.py`](../src/gateway/governance/safety.py:83) — `ac_keyword_scan()` provides Aho-Corasick O(n) Tier-1 keyword scanning for 14 forbidden prompts. This is an information integrity control preventing prompt injection (SI-3 analog).
- [`scripts/automated_auditor.py`](../scripts/automated_auditor.py:68) — `TraceAuditor.audit_trace()` implements span invariant checking: every `tool.execution` span must have a causally preceding `governance.check` span with `decision=ALLOW`. Detects "Missing Governance Check," "Execution despite DENY," and "Orphaned Execution" violations. **However, it uses mock traces (see AU-12 gap).**

**Gaps:**

1. **SI-2 (Flaw Remediation):** **v0.1.0 PARTIALLY ADDRESSED:** `CVE-2025-69872` (`outlines` package — diskcache pickle deserialization RCE) remediated by removing `outlines` from gateway dependencies entirely (POAM-016 closed 2026-05-29). SBOM CronJob deployed with pip-audit/Trivy enforcement (POAM-010 closed). Remaining gap: no documented flaw remediation SLA policy; `CVE-2026-4810` (`google-adk`) open (POAM-017, blocked by `opentelemetry-sdk` version conflict).
2. **SI-3 (Malicious Code Protection):** Tier-1 keyword scan and NeMo Guardrails protect against prompt injection but there is no container image antivirus/malware scanning in the CI pipeline, no runtime threat detection (e.g., Falco), and no supply chain integrity verification for model weights.
3. **SI-4 (System Monitoring):** `TraceAuditor` provides the monitoring concept but uses mock data. No real-time anomaly detection on governance decision rates, no baseline established for normal operation.
4. **SI-4(2) (Automated Tools and Mechanisms):** No automated intrusion detection system (IDS) beyond OPA/STPA policy enforcement. No network-level anomaly detection for lateral movement.
5. **SI-7 (Software, Firmware, and Information Integrity):** Container images are not verified against cryptographic signatures (e.g., Sigstore Cosign) before deployment. No `VERIFY` step in the deployment pipeline.
6. **SI-7(1) (Integrity Checks):** `storage.py:169` stores SHA-256 content hash of OSCAL artifacts in object metadata — this is a manual check, not an automated integrity verification triggered on read.
7. **SI-10 (Information Input Validation):** STPA validation covers only `execute_trade` inputs. The API gateway (`governance_middleware.py`) does not perform schema validation on arbitrary incoming JSON payloads before passing to OPA — malformed inputs could cause unexpected OPA behavior.
8. **SI-19 (De-identification):** Presidio PII masking (A.9.2 Lula control) de-identifies inputs, but there is no SI-19 control statement formally mapping this to NIST SI-19 requirements. No de-identification effectiveness audit.

**Implementation Recommendations:**

1. **Implement SI-3 runtime threat detection:** Add `falco` as a DaemonSet in `deployment/k8s/`. Create a Falco ruleset that alerts on: exec in governance-stack containers, unexpected outbound connections, privilege escalation attempts. Publish Falco alerts to the SSE event bus as `SECURITY_ALERT` event type.
2. **Implement SI-7 image signing:** In the GitHub Actions CI workflow, add `cosign sign` after each image push and `cosign verify` in the deployment pipeline before `kubectl apply`. Store the Sigstore bundle in the OSCAL artifacts bucket.
3. **Fix SI-4 live monitoring:** Wire `TraceAuditor.fetch_recent_traces()` (see AU-12 recommendation) to a live OTLP source. Add a CronJob (`deployment/k8s/trace-auditor-cron.yaml`) that runs `scripts/automated_auditor.py` every 15 minutes and publishes violations to the `event_bus`.
4. **Add SI-10 API schema validation:** In `governance_middleware.py`, use a Pydantic model to validate the `GovernanceCheckRequest` body: require `tool_name` (non-empty string, max 64 chars), `params` (dict, max 50 keys). Return HTTP 422 on validation failure.
5. **Add SI-2 patch SLA policy:** Create `docs/Flaw_Remediation_Policy.md` defining: Critical CVE → patch within 24h, High → 7 days, Medium → 30 days. Integrate with `trivy` output in CI to block deployments with Critical CVEs.

---

## Control Coverage Heatmap

| Control Family                   | Required Controls (HIGH) | Implemented | Partial | Gap    | Coverage % |
| -------------------------------- | ------------------------ | ----------- | ------- | ------ | ---------- |
| **AC** Access Control            | 16                       | 2           | 3       | 11     | **19%**    |
| **AU** Audit & Accountability    | 13                       | 5           | 4       | 4      | **54%**    |
| **CA** Security Assessment       | 8                        | 1           | 2       | 5      | **19%**    |
| **CM** Configuration Management  | 11                       | 3           | 2       | 6      | **32%**    |
| **IA** Identification & Auth     | 13                       | 1           | 2       | 10     | **15%**    |
| **IR** Incident Response         | 9                        | 2           | 2       | 5      | **28%**    |
| **RA** Risk Assessment           | 10                       | 1           | 2       | 7      | **15%**    |
| **SC** System & Comms Protection | 20                       | 5           | 3       | 12     | **33%**    |
| **SI** System & Info Integrity   | 13                       | 4           | 3       | 6      | **42%**    |
| **TOTAL**                        | **113**                  | **24**      | **23**  | **66** | **29%**    |

**Scoring notes:**

- **Implemented:** Control is demonstrably met by reviewed code/config with no material gaps
- **Partial:** Core mechanism exists but missing documentation, coverage gaps, or enforcement deficiencies
- **Gap:** Control is substantially absent or only nominally addressed

**Family breakdown:**

- `AU` and `SI` score highest due to the strong OTel + 5-tier governance pipeline
- `IA` and `RA` score lowest — no MFA, no formal risk assessment, no vulnerability scanning
- `SC` scores modestly — strong NetworkPolicy but no TLS enforcement, no PSA, no KMS

---

## Implementation Roadmap

### Quick Wins — Configuration, Documentation, OSCAL Metadata

| Action                                                                          | Files                                              | Controls Satisfied |
| ------------------------------------------------------------------------------- | -------------------------------------------------- | ------------------ |
| Pin container image digests in all Dockerfiles                                  | `Dockerfile`, `Dockerfile.nemo`, `Dockerfile.vllm` | CM-8, SI-7         |
| Add CAGE_ROUTING_SEAL_SECRET enforcement — fail on missing secret in production | `src/gateway/server/governance_middleware.py:64`   | SC-12, AC-3        |
| Add minimum entropy validation for secrets at startup                           | `config/settings.py:validate_required_settings()`  | IA-5(1)            |
| Create `docs/FIPS199_Categorization.md`                                         | New file                                           | RA-2, CA-6         |
| Create `docs/POAM.md` with all gaps from Chunks 2–3                             | New file                                           | CA-5               |
| Create `docs/Incident_Response_Plan.md`                                         | New file                                           | IR-8               |
| Create `docs/AC2_Account_Management_Procedure.md`                               | New file                                           | AC-2               |
| Create `docs/Continuous_Monitoring_Plan.md`                                     | New file                                           | CA-7               |
| Add port/service inventory to `docs/Network_Architecture.md`                    | New file                                           | CM-7               |
| Add Lula validation for SP 800-53 AC-3 (authz.rego mounted check)               | `compliance/lula/lula-validation-ac3.yaml`         | CA-7, AC-3         |
| Document OSCAL SSP shell (even if incomplete) with `security-impact-level`      | `compliance/oscal/system-security-plan.yaml`       | CA-6               |
| Add `CODEOWNERS` for security-critical files                                    | `.github/CODEOWNERS`                               | CM-3, CM-5         |

### Medium-Term — New Modules, Policy Additions, Test Coverage

| Action                                                                        | Files                                                                    | Controls Satisfied |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ------------------ |
| Wire `TraceAuditor.fetch_recent_traces()` to live Cloud Trace / OTLP endpoint | `scripts/automated_auditor.py:32`, `config/settings.py`                  | AU-12, SI-4        |
| Add principal identity to all OTel spans                                      | `src/gateway/observability/mcp_tracing.py:63`                            | AU-3, AC-3         |
| Add `PagerDutyNotifier` with Slack retry and fallback                         | `src/compliance_bridge/notifier.py`                                      | IR-4               |
| Add IR persistent incident log table (Postgres)                               | `src/compliance_bridge/audit_workflow.py`, Terraform                     | IR-5               |
| Add Pydantic schema validation on governance API body                         | `src/gateway/server/governance_middleware.py`                            | SI-10              |
| Add role-based enforcement at API layer (`require_role()` dependency)         | `src/gateway/server/governance_middleware.py`                            | AC-3               |
| Add duty separation Rego rule to system_authz.rego                            | `deployment/system_authz.rego`                                           | AC-5               |
| Add scoped IAM bindings in Terraform (per-bucket, per-service)                | `deployment/terraform/iam.tf`                                            | AC-6               |
| Add `trivy` image scan and `pip audit` to CI pipeline                         | `.github/workflows/`                                                     | RA-5, SI-2         |
| Generate SPDX SBOM on each image build                                        | `.github/workflows/`, `compliance/oscal/component-definition.yaml`       | CM-8               |
| Add automated IR drill test                                                   | `tests/governance/test_ir_drill.py`                                      | IR-3               |
| Add Falco DaemonSet + governance-stack ruleset                                | `deployment/k8s/falco-daemonset.yaml`, `deployment/k8s/falco-rules.yaml` | SI-3, SI-4(2)      |
| Create `lula-validation-au12.yaml`, `lula-validation-si2.yaml`                | `compliance/lula/`                                                       | CA-7, AU-12, SI-2  |
| Add `docs/Flaw_Remediation_Policy.md` with patch SLAs                         | New file                                                                 | SI-2               |
| Add bucket lifecycle rule (7-year) for OSCAL artifacts                        | `deployment/terraform/storage.tf`                                        | AU-11              |
| Add S3 bucket policy restricting deletes to OSCAL bucket                      | New Terraform resource                                                   | AU-9, SC-28        |

### Long-Term — Architectural Changes, Infrastructure Updates

| Action                                                                    | Files                                                                           | Controls Satisfied   |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | -------------------- |
| Deploy Istio service mesh with mTLS PeerAuthentication policy             | `deployment/k8s/istio-peer-auth.yaml`, all pod specs                            | SC-8(1), IA-3, SC-23 |
| Replace HMAC routing seal with ECDSA asymmetric signature                 | `src/gateway/server/governance_middleware.py`, new `src/gateway/crypto/` module | AU-10, SC-13         |
| Add Pod Security Admission (PSA) `securityContext` to all deployments     | All `deployment/k8s/*.yaml` deployment specs                                    | SC-39, CM-7          |
| Implement GCP KMS-backed Secret Manager for all credentials               | `deployment/terraform/iam.tf`, new `deployment/terraform/kms.tf`                | SC-12, IA-5          |
| Add GCS CMEK encryption for OSCAL artifacts bucket                        | `deployment/terraform/storage.tf`                                               | SC-28(1)             |
| Implement secret rotation CronJob via GCP Secret Manager                  | `deployment/k8s/secret-rotation-cronjob.yaml`                                   | IA-5, AC-2           |
| Implement Sigstore Cosign image signing in CI/CD                          | `.github/workflows/`, `deployment/deploy_sw.py`                                 | SI-7(1), SI-7(6)     |
| Create formal NIST SP 800-30 Risk Assessment                              | `docs/Risk_Assessment.md`                                                       | RA-3, RA-3(1)        |
| Create Supply Chain Risk Assessment (C-SCRM)                              | `docs/Supply_Chain_Risk_Assessment.md`                                          | RA-9                 |
| Implement JWT-based identity with role claims (replace shared auth_token) | `deployment/system_authz.rego`, `src/gateway/server/governance_middleware.py`   | AC-2, AC-3, IA-4     |
| Add Redis encryption at rest (Redis Enterprise TLS or GCP Memorystore)    | `deployment/k8s/redis-statefulset.yaml`, Terraform                              | SC-28, SC-28(1)      |
| Implement formal CCB process with GitHub required reviewers               | `.github/CODEOWNERS`, `.github/branch-protection-rules.json`                    | CM-3, CM-4           |

---

## Step 3–4 Readiness Score

### Score: **29 / 100**

**Justification:**

The cybernetic-governance-engine demonstrates sophisticated domain-specific controls that far exceed typical AI systems — the 7-tier governance pipeline (STPA → Aho-Corasick → CBF → [SLM — DEPRECATED] → OPA → Consensus → CausalGatekeeper), NeMo Guardrails, Lula continuous compliance automation, and KMS-sealed verdicts are enterprise-grade capabilities. However, scored against the NIST SP 800-53 Rev 5 **HIGH** baseline, the system has significant structural gaps across every control family reviewed.

**Strengths driving the score up (from baseline of 0):**

- **AU:** 5-step audit pipeline with deterministic OSCAL parsing, Langfuse compliance project, SSE real-time streaming, and Slack/PagerDuty alerting — strongest family (54% coverage)
- **SC:** Kubernetes NetworkPolicy with default-deny, Cloud NAT, HMAC request integrity — meaningful boundary protection
- **SI:** Aho-Corasick keyword scan, CBF formal safety, STPA invariant checking, fail-secure SLM degraded mode — strong domain-specific integrity controls
- **CM:** Single-source-of-truth `governance_thresholds.json`, Pydantic-validated singleton, fail-fast settings validation
- **CA:** Lula automated continuous compliance for 4 ISO 42001 controls is a genuine differentiator

**Primary gaps driving the score down:**

- **IA (15%):** No MFA, no mTLS, no per-service identity — the entire authentication surface rests on a single shared HMAC secret. This is the most critical NIST High baseline gap.
- **RA (15%):** No formal risk assessment, no vulnerability scanning, no SBOM, no supply chain risk analysis — the system cannot demonstrate an understanding of its own threat landscape.
- **AC (19%):** RBAC exists for trade actions but not at the API authentication layer. No account management lifecycle, no session management, no brute-force protection.
- **CA (19%):** Only 4 ISO 42001 controls in OSCAL — zero SP 800-53 controls validated by Lula. No ATO package, no SSP, no POA&M, no formal continuous monitoring plan document.
- **TraceAuditor mock source (AU-12, SI-4):** The automated auditor — the primary SI-4 control — uses hardcoded synthetic traces. This is a documented production gap that must be fixed as a prerequisite to any ATO claim.

**To reach 60/100 (minimum for LOW baseline ATO):** Complete all Quick Wins (documentation artifacts, secret enforcement) and the first 8 Medium-Term items (live trace source, PII identity on spans, SI-10 input validation, IR-4 retry, RA-5 scanning). Estimated 6–8 weeks of focused effort.

**To reach 80/100 (HIGH baseline ATO candidate):** Complete the full Medium-Term roadmap plus mTLS/Istio deployment and KMS-backed secrets. This represents the architectural maturity expected of a NIST HIGH system handling financial data.

---

_Document authored by the Architect mode analysis pipeline. Source files read directly — no content inferred. This document covers RMF Steps 3 (Select) and 4 (Implement) only. Steps 5–7 are covered in Chunks 4–5. Updated 2026-06-01 for CAGE v0.1.0: SR 26-2 framework added, CSA AARM v1.0 added, Linkerd mTLS + Cilium L7 egress lockdown noted (POAM-007 closed), outlines CVE-2025-69872 remediated (POAM-016 closed), OTel Collector deprecation noted, Lula manifest count updated to 15, Cloud KMS HSM signing noted for AU-10/IA controls._
