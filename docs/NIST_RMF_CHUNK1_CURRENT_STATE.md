# NIST RMF Chunk 1 — Current-State Inventory

## Cybernetic Governance Engine (CAGE)

**Document version:** 1.0.0  
**Date:** 2026-03-06  
**Scope:** Read-only inventory of existing codebase capabilities across five governance dimensions.  
**Purpose:** Input for subsequent NIST RMF gap-analysis chunks (Chunks 2–5).  
**Constraint:** No NIST RMF gaps are identified here; gap analysis is deferred to Chunk 2.

---

## Table of Contents

1. [Governance & Policy Enforcement](#1-governance--policy-enforcement)
2. [Compliance & OSCAL](#2-compliance--oscal)
3. [Security Controls & Infrastructure](#3-security-controls--infrastructure)
4. [Observability & Audit](#4-observability--audit)
5. [Testing & Verification](#5-testing--verification)
6. [Summary Table](#6-summary-table)

---

## 1. Governance & Policy Enforcement

### 1.1 What Capability Exists

The gateway implements a **multi-tier, neuro-symbolic governance pipeline** that intercepts every action request before it reaches the LLM inference layer. The pipeline operates in five sequential tiers:

- **Tier 0 — STPA/STAMP constraint validation** (`STPAValidator`): Evaluates deterministic Unsafe Control Actions (UCAs) against a `TradingKnowledgeGraph` ontology. Checks include SC-1 (approval token), FIN-1 (portfolio sell fraction ≤ 10 %), FIN-2 (latency ≤ 200 ms), UCA-5 (drawdown > 4.5 %), and UCA-6 (order size > 1 % of daily volume).
- **Tier 1 — Aho-Corasick keyword scan** (`ControlBarrierFunction` + `ac_keyword_scan`): O(n) scan against 14 tier-1 prompt-injection/bypass keywords loaded from `config/governance_thresholds.json`. Falls back to O(n×m) if `pyahocorasick` is absent.
- **Tier 2 — Control Barrier Function (CBF)** (`ControlBarrierFunction`): Discrete-time CBF maintaining a shared Redis cash-balance state. Uses WATCH/MULTI/EXEC optimistic locking with up to 5 retries for concurrent write safety. Tracks drawdown against configurable limits.
- **Tier 3 — SLM similarity sidecar** (`_query_slm` in `SymbolicGovernor`): External HTTP sidecar query for semantic similarity scoring. Fails gracefully: when unreachable, injects `slm_available: false` sentinel into the OPA payload so the Rego policy can apply elevated confidence thresholds (0.97 vs. 0.95).
- **Tier 4 — OPA policy enforcement** (`OPAClient`): Async HTTP client with circuit breaker (fail-DENY after 5 failures, 30 s recovery). Queries OPA with `?explain=full` for audit trail. Latency budget enforcement: hard cap at 3000 ms (bankruptcy protocol), soft ceiling at 2000 ms.
- **Tier 5 — Multi-agent consensus** (`ConsensusEngine`): Parallel LLM critic calls (`asyncio.gather`) from "Risk Manager" and "Compliance Officer" personas for trades above USD 10,000 threshold. Results are pushed to a background `asyncio.Queue` for post-execution audit (non-blocking hot path).

**NeMo Guardrails layer** (`config/rails/`): Colang 2.x flows define four active control flows:

- `check_authorization`: validates approval token (SC-1)
- `check_latency`: validates market data latency (FIN-2)
- `check_financial_risk`: validates drawdown (UCA-5) and slippage (UCA-6)
- Sensitive data detection on both input and output (15 PII entity types via Presidio/spaCy)

**ISO 42001 evidence stamping** (`stamp_iso_control` in `iso_control.py`): Every governance decision stamps six mandatory attributes on the active OTel span: `iso42001.control`, `iso42001.tier`, `iso42001.outcome`, `iso42001.timestamp`, `iso42001.gateway_version`, `iso42001.evidence_chain`.

**HMAC routing seal** (`governance_middleware.py`): `X-CAGE-Routing-Seal` header (HMAC-SHA256 of body bytes) enforced on the `/governance/check` endpoint. Configurable enforcement vs. log-only mode.

**Governance contracts** (`contracts.py`): Protocol interfaces (`SafetyFilter`, `ConsensusProvider`) decouple the gateway from specific implementations, enabling testability and substitution.

### 1.2 Key Artifacts

| Artifact                            | Location                                                                                         | Role                                                                  |
| ----------------------------------- | ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| `ControlBarrierFunction`            | [`src/gateway/governance/safety.py`](src/gateway/governance/safety.py:115)                       | Redis-backed CBF with WATCH/MULTI/EXEC                                |
| `ac_keyword_scan`                   | [`src/gateway/governance/safety.py`](src/gateway/governance/safety.py:83)                        | Aho-Corasick Tier-1 prompt-injection scan                             |
| `SymbolicGovernor`                  | [`src/gateway/governance/symbolic_governor.py`](src/gateway/governance/symbolic_governor.py:85)  | Orchestrates all 5 governance tiers                                   |
| `STPAValidator`                     | [`src/gateway/governance/stpa_validator.py`](src/gateway/governance/stpa_validator.py:36)        | Deterministic STPA UCA constraint checks                              |
| `TradingKnowledgeGraph`             | [`src/gateway/governance/ontology.py`](src/gateway/governance/ontology.py:44)                    | UCA/constraint ontology (6 UCAs, 3 constraints)                       |
| `stamp_iso_control`                 | [`src/gateway/governance/iso_control.py`](src/gateway/governance/iso_control.py:64)              | ISO 42001 OTel evidence stamping                                      |
| `ConsensusEngine`                   | [`src/gateway/governance/consensus.py`](src/gateway/governance/consensus.py:71)                  | Multi-agent LLM critic consensus                                      |
| `SafetyFilter`, `ConsensusProvider` | [`src/gateway/governance/contracts.py`](src/gateway/governance/contracts.py:24)                  | Protocol interfaces                                                   |
| NeMo actions                        | [`src/gateway/governance/nemo/actions.py`](src/gateway/governance/nemo/actions.py)               | 5 Colang-callable safety action functions                             |
| `create_nemo_manager`               | [`src/gateway/governance/nemo/manager.py`](src/gateway/governance/nemo/manager.py:99)            | NeMo Guardrails factory with vLLM + Presidio                          |
| `validate_with_nemo`                | [`src/gateway/governance/nemo/manager.py`](src/gateway/governance/nemo/manager.py:204)           | Structural rail intervention detection                                |
| `NeMoService`                       | [`src/gateway/governance/nemo/server.py`](src/gateway/governance/nemo/server.py:43)              | gRPC server for NeMo sidecar                                          |
| `enforce_governance`                | [`src/gateway/server/governance_middleware.py`](src/gateway/server/governance_middleware.py:119) | Full symbolic governor pipeline invocation                            |
| `enforce_routing_seal`              | [`src/gateway/server/governance_middleware.py`](src/gateway/server/governance_middleware.py:84)  | HMAC seal enforcement                                                 |
| `OPAClient`                         | [`src/gateway/core/policy.py`](src/gateway/core/policy.py:77)                                    | Async OPA client with circuit breaker                                 |
| `CircuitBreaker`                    | [`src/gateway/core/policy.py`](src/gateway/core/policy.py:35)                                    | Fail-fast pattern with latency budget                                 |
| Colang flows                        | [`config/rails/main_logic.co`](config/rails/main_logic.co)                                       | Authorization, latency, risk flows                                    |
| PII detection config                | [`config/rails/config.yml`](config/rails/config.yml)                                             | 15 entity types on input and output                                   |
| `THRESHOLDS` singleton              | [`src/gateway/governance/schemas/thresholds.py`](src/gateway/governance/schemas/thresholds.py)   | Single source of truth for all limits                                 |
| Thresholds JSON                     | [`config/governance_thresholds.json`](config/governance_thresholds.json)                         | CBF params, drawdown limit, confidence, consensus threshold, keywords |

### 1.3 Coverage Assessment: **Strong**

> The governance enforcement stack is multi-layered, fail-closed, and deeply instrumented. All threshold literals are centralized in a Pydantic-validated singleton. STPA UCAs map directly to Colang flows. OPA operates with a circuit breaker and latency budget. The only notable partial area is the SLM sidecar (optional HTTP dependency, not always present in all environments).

---

## 2. Compliance & OSCAL

### 2.1 What Capability Exists

The **compliance bridge** (`src/compliance_bridge/`) is a standalone FastAPI microservice that implements a fully automated, 5-step ISO 42001 compliance audit pipeline:

1. **Step 1 — Artifact persistence**: Writes raw OSCAL YAML to GCS/S3 (idempotent, skipped if `OSCAL_S3_ENDPOINT` is absent).
2. **Step 2 — Deterministic OSCAL parsing** (`parse_oscal_yaml`): Zero-LLM, Pydantic-validated extraction of `OscalFinding` objects from Lula assessment result YAML. Handles OSCAL v1.0.4 structure, maps `satisfied`/`not-satisfied` states, and extracts `safety_rate` and `evidence_age_seconds` props.
3. **Step 3 — Langfuse ingestion**: Findings are pushed as scored traces to a dedicated compliance Langfuse project (separate from application performance traces). Each finding creates a trace tagged `compliance`, `iso-42001`, `lula`, and `control:<id>`.
4. **Step 4 — Critical failure alerting**: FAIL findings on `CRITICAL_CONTROLS` (A.9.2, SC-4) trigger synchronous `Notifier` alerts.
5. **Step 5 — LLM remediation advisory** (conditional): If critical failures exist and `VLLM_BASE_URL` is set, calls vLLM to generate structured remediation recommendations. All LLM advisory outputs are logged to compliance Langfuse with `human_review_required: true`.

**Metrics API** (`GET /v1/metrics/{control_id}`): 5-minute TTL cache wraps Langfuse SDK queries aggregating `iso_42001_outcome` metadata from application traces into `ComplianceMetrics` objects. These are the exact JSON payloads Lula's OPA Rego reads as `input`.

**SSE event bus**: Real-time `AUDIT_FINDING` and `GOVERNANCE_VIOLATION` events are published to connected SSE clients (consumed by the AgentSight KernelDashboard).

**OSCAL Component Definition** (`compliance/oscal/component-definition.yaml`): OSCAL v1.0.4 document mapping four ISO 42001 controls to three system components:

- Component 1 (Governance Gateway): controls A.5.2 (Social Impact) and A.5.3 (Logging/Monitoring)
- Component 2 (OPA Policy Engine): control SC-4 (Fiscal Limits and RBAC)
- Component 3 (NeMo Guardrails + Presidio): control A.9.2 (Data Transfer to Suppliers)

**Lula validation manifests** (four files in `compliance/lula/`): Each links an OPA Rego assertion to the compliance-bridge metrics API:

| File                                                                   | Control                  | Domain                         | Threshold                             |
| ---------------------------------------------------------------------- | ------------------------ | ------------------------------ | ------------------------------------- |
| [`lula-validation-a52.yaml`](compliance/lula/lula-validation-a52.yaml) | A.5.2 Social Impact      | `api` (compliance-bridge)      | safety_rate ≥ 99%, evidence < 48h     |
| [`lula-validation-a53.yaml`](compliance/lula/lula-validation-a53.yaml) | A.5.3 Logging/Monitoring | `api` (compliance-bridge)      | safety_rate ≥ 98%, evidence < 48h     |
| [`lula-validation-a92.yaml`](compliance/lula/lula-validation-a92.yaml) | A.9.2 Data Privacy       | `api` (compliance-bridge)      | safety_rate == 1.0 (zero tolerance)   |
| [`lula-validation-sc4.yaml`](compliance/lula/lula-validation-sc4.yaml) | SC-4 Fiscal Limits       | `kubernetes` (ConfigMap label) | `compliance.iso42001/enabled: "true"` |

All four Lula manifests include a cold-start grace period rule (< 6 hours post-deployment) that relaxes sample-size requirements while maintaining safety-rate thresholds.

**Existing governance documentation**: `docs/GOVERNANCE_CROSSWALK.md`, `docs/ISO_42001_COMPLIANCE.md`, `docs/STPA_ANALYSIS.md`, and `docs/NEURO_SYMBOLIC_GOVERNANCE.md` provide architectural rationale and crosswalk tables.

### 2.2 Key Artifacts

| Artifact                       | Location                                                                                   | Role                                   |
| ------------------------------ | ------------------------------------------------------------------------------------------ | -------------------------------------- |
| `run_audit_workflow`           | [`src/compliance_bridge/audit_workflow.py`](src/compliance_bridge/audit_workflow.py:500)   | 5-step compliance audit pipeline       |
| `parse_oscal_yaml`             | [`src/compliance_bridge/oscal_parser.py`](src/compliance_bridge/oscal_parser.py:169)       | Deterministic OSCAL YAML parser        |
| `get_compliance_metrics`       | [`src/compliance_bridge/metrics.py`](src/compliance_bridge/metrics.py:197)                 | TTL-cached Langfuse metrics aggregator |
| `ComplianceMetrics`            | [`src/compliance_bridge/metrics.py`](src/compliance_bridge/metrics.py:63)                  | Pydantic model consumed by Lula Rego   |
| `OscalFinding`                 | [`src/compliance_bridge/audit_workflow.py`](src/compliance_bridge/audit_workflow.py)       | Validated OSCAL finding model          |
| FastAPI app                    | [`src/compliance_bridge/main.py`](src/compliance_bridge/main.py:139)                       | Compliance bridge service (port 3001)  |
| OSCAL component definition     | [`compliance/oscal/component-definition.yaml`](compliance/oscal/component-definition.yaml) | OSCAL v1.0.4, 3 components, 4 controls |
| Lula A.5.2                     | [`compliance/lula/lula-validation-a52.yaml`](compliance/lula/lula-validation-a52.yaml)     | API-domain Rego validation             |
| Lula A.5.3                     | [`compliance/lula/lula-validation-a53.yaml`](compliance/lula/lula-validation-a53.yaml)     | API-domain Rego validation             |
| Lula A.9.2                     | [`compliance/lula/lula-validation-a92.yaml`](compliance/lula/lula-validation-a92.yaml)     | Zero-tolerance PII control             |
| Lula SC-4                      | [`compliance/lula/lula-validation-sc4.yaml`](compliance/lula/lula-validation-sc4.yaml)     | Kubernetes ConfigMap label assertion   |
| OSCAL audit ingestion endpoint | [`src/compliance_bridge/main.py`](src/compliance_bridge/main.py:287)                       | `POST /v1/audit/ingest`                |
| Compliance metrics endpoint    | [`src/compliance_bridge/main.py`](src/compliance_bridge/main.py:240)                       | `GET /v1/metrics/{control_id}`         |
| SSE event stream               | [`src/compliance_bridge/main.py`](src/compliance_bridge/main.py:184)                       | Real-time governance event feed        |

### 2.3 Coverage Assessment: **Strong**

> OSCAL, Lula, and the compliance bridge implement a closed-loop automated compliance pipeline for 4 ISO 42001 controls. The component definition, Lula manifests, metrics aggregation, and audit pipeline are all production-quality. The 4 controls covered (A.5.2, A.5.3, A.9.2, SC-4) represent a subset of ISO 42001 Annex A — NIST RMF controls (e.g., CA, RA, SI families) are not yet mapped.

---

## 3. Security Controls & Infrastructure

### 3.1 What Capability Exists

**Kubernetes Network Policy** (`deployment/k8s/network-policy.yaml`): Nine policy objects enforcing a default-deny model within the `governance-stack` namespace:

- Default deny all ingress and egress (policies 1 and 2)
- Allow gateway ingress (port 8080) only from pods labeled `cage.io/role: orchestrator` or from the `ingress-nginx` namespace (policy 3)
- Selective egress allows: OPA on 8181 (policy 4), Redis on 6379 (policy 5), OTLP collector on 4317/4318 (policy 6), DNS on 53 (policy 7), vLLM on 8000 (policy 8), OPA ingress health checks (policy 9)

**Terraform IAM** (`deployment/terraform/iam.tf`): GCP Workload Identity Federation for two service accounts:

- `financial-advisor-sa`: bound to `governance-stack/financial-advisor-sa` Kubernetes service account
- `agentsight-ui-sa`: bound to `governance-stack/agentsight-ui` Kubernetes service account

**GCP NAT** (`deployment/terraform/networking.tf`): Cloud NAT gateway with error logging, providing private egress for GKE nodes without public IP addresses.

**OPA configuration** (`deployment/opa_config.yaml`): OPA configured with:

- Decision logs to stdout (Cloud Logging capture)
- Status monitoring via HTTP plugin (Lula queries `/v1/status`)
- Inter-query builtin cache (1 MB)
- ISO 42001 compliance labels: `compliance.iso42001/enabled: "true"`, controls `A.5.3, SC-4, A.9.2, A.5.2`
- Default decision path: `/finance/decision`

**Governance thresholds** (`config/governance_thresholds.json`): Centralized, Pydantic-validated configuration file defining:

- CBF: `min_cash_balance: 1000.0`, `gamma: 0.5`
- Drawdown limit: `0.05` (5%)
- STPA: UCA-5 threshold 4.5%, UCA-6 max order fraction 1%, max sell fraction 10%, max latency 200 ms
- Confidence: `min_trade_confidence: 0.95` (elevated to 0.97 when SLM unavailable)
- Consensus: `threshold_usd: 10000.0`
- Tier-1 keywords: 14 bypass/injection phrases

**Safety params** (`src/gateway/governance/safety_params.json`): Minimal legacy file (`drawdown_limit: 0.05`) — superseded by the `THRESHOLDS` singleton.

**OPA Rego policies** (active): Three policy packages in use:

- `system.authz` (`deployment/system_authz.rego`): Identity-based allow, confidence thresholds (0.95 normal / 0.97 SLM-degraded), `slm_degraded_warning` audit metadata
- `trade.governance` (`src/governed_financial_advisor/governance/policy/trade_governance.rego`): RBAC-based limits (junior ≤ $5k/$10k, senior ≤ $500k/$1M), risk-profile rules, prompt-injection detection
- `finance.generated` (`src/governed_financial_advisor/governance/policy/generated_rules.rego`): Auto-generated from transpiler — DENY slippage (MARKET order > 1% daily volume) and drawdown (BUY with drawdown > 4.5%). **Note:** This file has been purged from the active repository; the consolidated canonical policy is `trade_governance.rego`.

Two deprecated stub packages exist for historical tracking: `finance` and `financial.trade`.

### 3.2 Key Artifacts

| Artifact                  | Location                                                                                                                                           | Role                                         |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| NetworkPolicy (9 objects) | [`deployment/k8s/network-policy.yaml`](deployment/k8s/network-policy.yaml)                                                                         | Default-deny namespace isolation             |
| GCP Service Accounts      | [`deployment/terraform/iam.tf`](deployment/terraform/iam.tf)                                                                                       | Workload Identity for 2 SAs                  |
| Cloud NAT                 | [`deployment/terraform/networking.tf`](deployment/terraform/networking.tf)                                                                         | Private egress for GKE nodes                 |
| OPA config                | [`deployment/opa_config.yaml`](deployment/opa_config.yaml)                                                                                         | Decision logs, cache, ISO labels             |
| `system.authz`            | [`deployment/system_authz.rego`](deployment/system_authz.rego)                                                                                     | Identity + confidence enforcement            |
| `trade.governance`        | [`src/governed_financial_advisor/governance/policy/trade_governance.rego`](src/governed_financial_advisor/governance/policy/trade_governance.rego) | RBAC, fiscal limits, risk profiles (canonical policy) |
| ~~`finance.generated`~~   | ~~`src/governed_financial_advisor/governance/policy/generated_rules.rego`~~ (purged)                                                               | Transpiler-generated rules — removed; consolidated into `trade_governance.rego` |
| `THRESHOLDS` singleton    | `config/governance_thresholds.json` + `src/gateway/governance/schemas/thresholds.py`                                                               | Single source for all security thresholds    |
| `CircuitBreaker`          | [`src/gateway/core/policy.py`](src/gateway/core/policy.py:35)                                                                                      | OPA fail-fast with 3000 ms hard limit        |

### 3.3 Coverage Assessment: **Partial**

> Network microsegmentation is strong (default-deny with selective egress). OPA policies cover RBAC, fiscal limits, and confidence enforcement. However, Terraform IAM coverage is minimal (2 service accounts, no least-privilege role bindings beyond `workloadIdentityUser`). There are no Pod Security Admission policies, no secrets management automation (e.g., Vault/GSM rotation), and TLS enforcement is not visible in the reviewed files.

---

## 4. Observability & Audit

### 4.1 What Capability Exists

**Gateway telemetry** (`src/gateway/infrastructure/telemetry.py`): Factory function `get_tracer(name)` wrapping `opentelemetry.trace.get_tracer`. Gracefully degrades to a no-op stub when `opentelemetry-api` is absent. Used by safety.py and other gateway modules.

**MCP distributed tracing** (`src/gateway/observability/mcp_tracing.py`): `patch_mcp_tools(mcp_server)` monkey-patches `ToolManager.call_tool` to:

1. Extract W3C `traceparent` from `_otel_carrier` in MCP arguments (before Pydantic validation strips it)
2. Create child OTel spans linked to the upstream trace context
3. Record tool name, input args, and truncated output (4096 chars) as span attributes
4. Bridge SSE transport gap for seamless Langfuse waterfall traces

**ISO 42001 evidence on every span**: Every governance decision sets 6 attributes on the active OTel span via `stamp_iso_control`. The SymbolicGovernor additionally sets `langfuse.observation.type`, `langfuse.observation.name`, `langfuse.observation.input`, and `langfuse.observation.output` on governance spans.

**Compliance audit workflow** (`src/compliance_bridge/audit_workflow.py`): Structured 5-step pipeline (see Dimension 2). All audit events emit SSE frames (`AUDIT_FINDING`, `GOVERNANCE_VIOLATION`) to the KernelDashboard in real time.

**Compliance metrics aggregation** (`src/compliance_bridge/metrics.py`): `get_compliance_metrics(control_id, window_hours)` queries application Langfuse for traces tagged `control:<id>` and aggregates `iso_42001_outcome` metadata into `ComplianceMetrics` (safety_rate, total_traces, blocked_traces, evidence_age_seconds). Startup grace period logic prevents false failures immediately after deployment.

**Evaluator Auditor** (`src/governed_financial_advisor/agents/evaluator/auditor.py`): `EvaluatorAuditor.audit_trace(trace)` — System 3 (Algedonic) governance component that audits agent execution traces against SC-1 constraints. Produces `verdict`, `safety_score` (0–100), `quality_score` (0–1), and `violations` list. Rewards governance-positive steps (market analysis, risk assessment, wait_for_approval) with quality score bonuses.

**Automated Auditor** (`scripts/automated_auditor.py`): `TraceAuditor` class implementing a continuous verification loop. Audits OTel trace spans for the invariant: every `tool.execution` span must be causally preceded by a `governance.check` span with `decision=ALLOW`. Detects three violation patterns: missing governance check, orphaned execution, and execution despite DENY. Currently uses mock trace data; production integration requires Cloud Trace API or Jaeger/OTLP query.

**Consensus background audit queue** (`src/gateway/governance/consensus.py`): All consensus decisions (above USD 10,000) are pushed to `_AUDIT_QUEUE` (asyncio.Queue, maxsize=1000) for background logging by `_background_audit_worker`, keeping the governance hot-path non-blocking.

### 4.2 Key Artifacts

| Artifact                                    | Location                                                                                                                                               | Role                                         |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------- |
| `get_tracer`                                | [`src/gateway/infrastructure/telemetry.py`](src/gateway/infrastructure/telemetry.py:31)                                                                | OTel tracer factory for gateway modules      |
| `patch_mcp_tools`                           | [`src/gateway/observability/mcp_tracing.py`](src/gateway/observability/mcp_tracing.py:46)                                                              | W3C trace context propagation across MCP SSE |
| `stamp_iso_control`                         | [`src/gateway/governance/iso_control.py`](src/gateway/governance/iso_control.py:64)                                                                    | 6-attribute ISO 42001 span stamping          |
| `run_audit_workflow`                        | [`src/compliance_bridge/audit_workflow.py`](src/compliance_bridge/audit_workflow.py:500)                                                               | 5-step audit pipeline with SSE events        |
| `get_compliance_metrics`                    | [`src/compliance_bridge/metrics.py`](src/compliance_bridge/metrics.py:197)                                                                             | TTL-cached Langfuse safety_rate aggregation  |
| `EvaluatorAuditor`                          | [`src/governed_financial_advisor/agents/evaluator/auditor.py`](src/governed_financial_advisor/agents/evaluator/auditor.py)                              | Agent trace auditor (SC-1, quality scoring)  |
| `TraceAuditor`                              | [`scripts/automated_auditor.py`](scripts/automated_auditor.py:22)                                                                                      | Invariant-based continuous span auditor      |
| `_AUDIT_QUEUE` + `_background_audit_worker` | [`src/gateway/governance/consensus.py`](src/gateway/governance/consensus.py:43)                                                                        | Non-blocking consensus audit queue           |
| `GovernanceEventBus`                        | [`src/compliance_bridge/sse_events.py`](src/compliance_bridge/sse_events.py)                                                                           | Real-time SSE event distribution             |
| NeMoOTelCallback                            | [`src/governed_financial_advisor/infrastructure/telemetry/nemo_exporter.py`](src/governed_financial_advisor/infrastructure/telemetry/nemo_exporter.py) | NeMo-to-OTel span callback                   |

### 4.3 Coverage Assessment: **Strong**

> OTel instrumentation is pervasive: every governance tier stamps ISO 42001 evidence attributes. MCP distributed tracing bridges the SSE transport gap. The compliance bridge provides closed-loop audit ingestion and real-time SSE alerting. The main gap is the `TraceAuditor`, which still relies on mock trace data rather than a live Cloud Trace or OTLP query.

---

## 5. Testing & Verification

### 5.1 What Capability Exists

The `tests/` directory contains **28 test files** spanning unit, integration, red-team, load, and evaluation categories:

**Unit and integration tests (key files):**

- `test_symbolic_governor.py`: 5 async tests covering confidence pass/fail (SR 11-7), OPA DENY, CBF UNSAFE, and consensus REJECT paths through `SymbolicGovernor.govern()`.
- `test_nemo_actions.py`: 10+ tests for all 5 NeMo Colang action functions (`check_approval_token`, `check_data_latency`, `check_drawdown_limit`, `check_slippage_risk`, `check_atomic_execution`) with mocked STPA validator.
- `test_compliance_bridge.py`: Comprehensive FastAPI test client coverage — `OscalFinding` and `ComplianceMetrics` model validation, `parse_oscal_yaml` with 5 scenarios (valid, invalid YAML, missing results, no findings, state mapping), and endpoint tests for `/health`, `/v1/metrics/{control_id}`, `/v1/audit/ingest`.
- `test_trade_governance_rego.py`: Dual-mode Rego tests — live OPA integration tests (skipped unless `OPA_URL` is set) with 11 scenarios covering junior/senior RBAC boundaries (the R-12 $90k conflict resolution), plus mocked tests for payload correctness, empty results, and HTTP 500 propagation.
- `test_red_teaming.py`: 4 parameterized tests for CBF drawdown limit including default limit behavior, hot-reload with TTL cache expiry, invalid value sanitization, and corrupt JSON resilience.
- `test_opa_client.py`: OPA client circuit breaker and policy evaluation tests.
- `test_safety_node.py`: Safety node graph integration tests.
- `test_optimistic_graph.py`, `test_optimistic_execution.py`: Concurrent execution path tests.
- `test_pii_integration.py`: PII detection and masking integration tests.
- `test_refactor_integrity.py`: Import and structural integrity checks.

**Adversarial / Red-team tests:**

- `tests/red_team/adversarial_red_team.py` + `tests/red_teaming/test_adversarial.py`: Adversarial datasets and red-team execution scripts.
- `tests/red_team/adversarial_dataset.json`: Structured adversarial test case definitions.

**Governance-specific tests:**

- `tests/governance/test_automated_loop.py`: Governance automated loop tests.
- `tests/governance/test_nemo_refinements.py`: NeMo rail refinement tests.

**Evaluation and benchmarking:**

- `tests/evaluation/evaluator_agent_eval.py`: Evaluator agent evaluation harness.
- `tests/evaluation/agentbeats_sim.py`: Agent behavior simulation.
- `tests/load/locustfile.py`: Locust-based load testing.
- `scripts/run_agent_benchmark.py`: vLLM performance benchmark (latency, P95, throughput via OpenAI SDK).
- `scripts/verify_colang_locally.py`: Colang syntax validation by loading NeMo rails.
- `scripts/verify_remote.py`: Remote deployment verification script.
- `tests/opa_snapshots/`: Two OPA decision snapshot files for regression testing (`01_no_identity_match.json`, `02_trade_no_auth.json`).

**Additional test files:** `test_agent_accuracy.py`, `test_agent_performance.py`, `test_cage_graph.py`, `test_config_manager.py`, `test_demo.py`, `test_deployment_verification.py`, `test_evaluator_mcp.py`, `test_gateway_client_perf.py`, `test_gateway_connectivity.py`, `test_governance_client.py`, `test_langfuse_evaluation.py`, `test_pipeline_compilation.py`, `test_profile_check.py`, `test_redis_config.py`, `test_trades_mcp.py`, `test_transpiler_llm.py`.

### 5.2 Key Artifacts

| Artifact                        | Location                                                                             | Role                                  |
| ------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------- |
| `test_symbolic_governor.py`     | [`tests/test_symbolic_governor.py`](tests/test_symbolic_governor.py)                 | 5-tier governance pipeline unit tests |
| `test_compliance_bridge.py`     | [`tests/test_compliance_bridge.py`](tests/test_compliance_bridge.py)                 | OSCAL parser + FastAPI endpoint tests |
| `test_trade_governance_rego.py` | [`tests/test_trade_governance_rego.py`](tests/test_trade_governance_rego.py)         | Rego policy tests (live OPA + mocked) |
| `test_nemo_actions.py`          | [`tests/test_nemo_actions.py`](tests/test_nemo_actions.py)                           | Colang action function tests          |
| `test_red_teaming.py`           | [`tests/test_red_teaming.py`](tests/test_red_teaming.py)                             | CBF drawdown resilience tests         |
| Adversarial dataset             | [`tests/red_team/adversarial_dataset.json`](tests/red_team/adversarial_dataset.json) | Structured adversarial test cases     |
| OPA snapshots                   | [`tests/opa_snapshots/`](tests/opa_snapshots/)                                       | OPA decision regression fixtures      |
| Load test                       | [`tests/load/locustfile.py`](tests/load/locustfile.py)                               | Locust performance test               |
| vLLM benchmark                  | [`scripts/run_agent_benchmark.py`](scripts/run_agent_benchmark.py)                   | Latency/throughput/P95 measurement    |
| Colang verifier                 | [`scripts/verify_colang_locally.py`](scripts/verify_colang_locally.py)               | Colang 2.x syntax validation          |

### 5.3 Coverage Assessment: **Strong**

> 28 test files cover unit, integration, red-team, load, and evaluation scenarios. Governance pipeline, OSCAL parsing, Rego policies, NeMo actions, and adversarial inputs all have dedicated test coverage. Live OPA integration tests are correctly gated on `OPA_URL`. Key gaps: no dedicated STPA validator unit tests visible at top level, no automated CI pipeline configuration was reviewed, and the `TraceAuditor` invariant tests use mock traces.

---

## 6. Summary Table

| Dimension                                 | Key Artifacts                                                                                                                                                                                                                                                                                   | Current Coverage Level | Notes                                                                                                                                                                                                               |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1. Governance & Policy Enforcement**    | `ControlBarrierFunction`, `SymbolicGovernor`, `STPAValidator`, `TradingKnowledgeGraph`, `ConsensusEngine`, `OPAClient`/`CircuitBreaker`, `stamp_iso_control`, NeMo manager/server/actions, Colang flows, `THRESHOLDS` singleton, `trade.governance` + `finance.generated` + `system.authz` Rego | **Strong**             | 5-tier neuro-symbolic pipeline; fail-closed; all thresholds centralized; HMAC routing seal; SLM graceful degradation with elevated OPA confidence threshold                                                         |
| **2. Compliance & OSCAL**                 | `run_audit_workflow`, `parse_oscal_yaml`, `get_compliance_metrics`, `compliance/oscal/component-definition.yaml`, 4 Lula validation YAMLs (A.5.2, A.5.3, A.9.2, SC-4), compliance-bridge FastAPI, SSE event bus                                                                                 | **Strong**             | Closed-loop automated compliance for 4 ISO 42001 controls; OSCAL v1.0.4; Lula with cold-start grace; LLM remediation advisory (human-review gated); NIST SP 800-53 controls not yet mapped                          |
| **3. Security Controls & Infrastructure** | 9 NetworkPolicy objects (default-deny), `iam.tf` (2 Workload Identity SAs), `networking.tf` (Cloud NAT), `opa_config.yaml` (decision logs + ISO labels), `system_authz.rego`, `trade_governance.rego`, `governance_thresholds.json`                                                             | **Partial**            | Strong network microsegmentation and OPA policy coverage; minimal Terraform IAM (no least-privilege role bindings beyond workloadIdentityUser); no Pod Security Admission; no secrets management automation visible |
| **4. Observability & Audit**              | `get_tracer`, `patch_mcp_tools`, `stamp_iso_control`, `run_audit_workflow`, `get_compliance_metrics`, `EvaluatorAuditor`, `TraceAuditor`, `_AUDIT_QUEUE`/`_background_audit_worker`, `GovernanceEventBus`, `NeMoOTelCallback`                                                                   | **Strong**             | Pervasive OTel instrumentation with ISO 42001 evidence stamping on every governance span; MCP distributed tracing bridges SSE gap; real-time SSE alerting; `TraceAuditor` currently uses mock trace source          |
| **5. Testing & Verification**             | 28 test files — unit, integration, red-team, load, evaluation; `test_symbolic_governor.py`, `test_compliance_bridge.py`, `test_trade_governance_rego.py`, `test_nemo_actions.py`, `test_red_teaming.py`; OPA snapshots; `scripts/run_agent_benchmark.py`, `scripts/verify_colang_locally.py`    | **Strong**             | Broad coverage including adversarial/red-team; live OPA tests correctly gated; `TraceAuditor` tests use mock data; no CI pipeline config reviewed                                                                   |

---

_This document covers current-state inventory only. NIST RMF gap analysis, control mapping, and remediation planning are addressed in Chunks 2–5._
