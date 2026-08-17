# NIST RMF Chunk 1 — Current-State Inventory

## Cybernetic Governance Engine (CAGE)

**Document version:** 0.1.0
**Date:** 2026-06-03
**Scope:** Read-only inventory of existing codebase capabilities across five governance dimensions.
**Purpose:** Input for subsequent NIST RMF gap-analysis chunks (Chunks 2–5).
**Constraint:** No NIST RMF gaps are identified here; gap analysis is deferred to Chunk 2.
**System Version:** CAGE v2.0.0-rc.2 (promoted 2026-06-03)
**Overall NIST RMF Readiness:** 24% (NIST SP 800-53 Rev 5 HIGH baseline)
**Primary Compliance Frameworks:** ISO/IEC 42001:2023 (primary), SR 26-2 (Federal Reserve, April 17, 2026), NIST SP 800-53 Rev 5 HIGH (FedRAMP in progress), CSA AARM v1.0

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

The gateway implements a **multi-tier, neuro-symbolic governance pipeline** that intercepts every action request before it reaches the LLM inference layer. The pipeline operates as an **8-tier governance pipeline** (FTRA pre-pipeline boundary gate plus 7 in-pipeline tiers via SymbolicGovernor) with a **10-node LangGraph StateGraph**:

- **Pre-pipeline — Aho-Corasick keyword scan** (`ac_keyword_scan`): O(n) scan against 14 prohibited prompt-injection/bypass keywords loaded from `config/governance_thresholds.json`. Falls back to O(n×m) if `pyahocorasick` is absent. Runs before `SymbolicGovernor._run_checks()` is invoked — not a numbered tier of the pipeline itself.
- **Tier 0 — STPA/STAMP constraint validation** (`GeneratedSTPAValidator`): Evaluates deterministic Unsafe Control Actions (UCAs) against a `TradingKnowledgeGraph` ontology. Checks include SC-1 (approval token), FIN-1 (portfolio sell fraction ≤ 10 %), FIN-2 (latency ≤ 200 ms), UCA-5 (drawdown > 4.5 %), and UCA-6 (order size > 1 % of daily volume).
- **Tier 1 — Agent confidence pre-check**: Fast-fail local check against `AGENT_CONFIDENCE_THRESHOLD` (default 0.95), avoiding unneeded CBF/OPA round-trips.
- **Tier 2 — Control Barrier Function (CBF)** (`ControlBarrierFunction`): Discrete-time CBF maintaining a shared Redis cash-balance state. Uses WATCH/MULTI/EXEC optimistic locking with up to 5 retries for concurrent write safety. Tracks drawdown against configurable limits. Runs **concurrently** with Tier 4 (OPA) via `asyncio.gather`. **v2.0.0:** External ledger reconciliation via `AnchorageGrpcLedgerProvider` is **FUTURE STATE** (POAM-023, target 2026-09-08) — not yet implemented; CBF currently uses Redis-only state.
- **Tier 3 — Fiscal Limit Pre-Reservation** (`FiscalLimitGuard`): Atomically reserves the requested USD amount against the daily fiscal cap in Redis (WATCH/MULTI/EXEC) before the consensus gate, closing the TOCTOU race between the CBF balance check and actual trade execution. The legacy SLM similarity sidecar tier slot has been fully retired — `slm_available=False` is a permanent sentinel injected into the OPA payload; OPA applies elevated confidence threshold (0.97) unconditionally.
- **Tier 4 — OPA policy enforcement** (`OPAClient`): Async HTTP client with circuit breaker (fail-DENY after 5 failures, 30 s recovery). Queries OPA with `?explain=full` for audit trail. Latency budget enforcement: hard cap at 3000 ms (bankruptcy protocol), soft ceiling at 2000 ms. Runs **concurrently** with Tier 2 (CBF).
- **Tier 5 — Multi-agent consensus** (`ConsensusEngine`): Parallel LLM critic calls (`asyncio.gather`) from "Risk Manager" and "Compliance Officer" personas for trades above USD 10,000 threshold. Results are pushed to a background `asyncio.Queue` for post-execution audit (non-blocking hot path). **v2.0.0:** Heterogeneous multi-model consensus via `ConsensusModelRegistry`.
- **Tier 6 — Causal gating** (`CausalGatekeeper`): Causal inference gate preventing spurious correlations from driving trade decisions.
- **Tier 6b — Adaptive FRIA enforcement**: Confidence-mapped zone classification (ALLOW/DEFER/DENY) via the External Normative Provider.

**NeMo Guardrails layer** (`config/rails/`): Colang 2.x flows define four active control flows:

- `check_authorization`: validates approval token (SC-1)
- `check_latency`: validates market data latency (FIN-2)
- `check_financial_risk`: validates drawdown (UCA-5) and slippage (UCA-6)
- Sensitive data detection on both input and output (15 PII entity types via Presidio/spaCy)

**ISO 42001 evidence stamping** (`stamp_iso_control` in `iso_control.py`): Every governance decision stamps six mandatory attributes on the active OTel span: `iso42001.control`, `iso42001.tier`, `iso42001.outcome`, `iso42001.timestamp`, `iso42001.gateway_version`, `iso42001.evidence_chain`.

**Cloud KMS HSM-backed asymmetric governance signing** (`kms_signer.py`): v2.0.0 replaces HMAC-SHA256 as the primary signing mechanism. `KMSSigner` uses Cloud KMS asymmetric keys (HSM-backed) for governance verdict signing. HMAC-SHA256 remains as dev/CI fallback only.

**HMAC routing seal** (`governance_middleware.py`): `X-CAGE-Routing-Seal` header (HMAC-SHA256 of body bytes) enforced on the `/governance/check` endpoint. Configurable enforcement vs. log-only mode. In production, superseded by KMS asymmetric signing.

**DEFER state machine** (`defer_queue.py`): AARM-V7 implementation. Confidence-starved contexts are queued to Redis db=1 (noeviction policy) rather than hard-denied, enabling asynchronous human review. Implements the DEFER disposition in the governance state machine.

**HITL TOCTOU remediation**: v2.0.0 adds `post_hitl_rehydrate` and `post_hitl_revalidate` LangGraph nodes to prevent time-of-check/time-of-use race conditions in human-in-the-loop approval flows.

**External Normative Provider** (`normative_provider.py`): Adaptive FRIA (Fundamental Rights Impact Assessment) gating for EU AI Act compliance. Tri-state enforcement: Score ≥ 0.95 → async attestation; 0.70, 0.95) → synchronous blocking via DEFER queue; < 0.70 → local hard deny.

**SHA-256 hash-chained context accumulator** (`context_accumulator.py`): AARM-V1 implementation. Maintains a tamper-evident chain of governance context across the LangGraph execution, providing cryptographic evidence of decision lineage.

**Governance contracts** (`contracts.py`): Protocol interfaces (`SafetyFilter`, `ConsensusProvider`) decouple the gateway from specific implementations, enabling testability and substitution.

### 1.2 Key Artifacts

| Artifact                            | Location                                                                                         | Role                                                                  |
| ----------------------------------- | ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| `ControlBarrierFunction`            | [`src/gateway/governance/cbf.py`](../../../src/gateway/governance/cbf.py) (**v3.0.0:** `safety.py` removed) | Redis-backed CBF with WATCH/MULTI/EXEC                                |
| `ac_keyword_scan`                   | [`src/gateway/governance/text_filter.py`](../../../src/gateway/governance/text_filter.py) (**v3.0.0:** `safety.py` removed) | Aho-Corasick Tier-1 prompt-injection scan                             |
| `SymbolicGovernor`                  | `src/gateway/governance/symbolic_governor.py`  | Orchestrates all 5 governance tiers                                   |
| `GeneratedSTPAValidator`            | [`src/gateway/governance/generated_stpa_validator.py`](../../../src/gateway/governance/generated_stpa_validator.py) (**v3.0.0:** `stpa_validator.py` removed) | Deterministic STPA UCA constraint checks                              |
| `TradingKnowledgeGraph`             | `src/gateway/governance/ontology.py`                    | UCA/constraint ontology (6 UCAs, 3 constraints)                       |
| `stamp_iso_control`                 | `src/gateway/governance/iso_control.py`              | ISO 42001 OTel evidence stamping                                      |
| `ConsensusEngine`                   | `src/gateway/governance/consensus.py`                  | Multi-agent LLM critic consensus                                      |
| `SafetyFilter`, `ConsensusProvider` | `src/gateway/governance/contracts.py`                  | Protocol interfaces                                                   |
| NeMo actions                        | [`src/gateway/governance/nemo/actions.py`](../../../config/rails/actions.py)               | 5 Colang-callable safety action functions                             |
| `create_nemo_manager`               | `src/gateway/governance/nemo/manager.py`            | NeMo Guardrails factory with vLLM + Presidio                          |
| `validate_with_nemo`                | `src/gateway/governance/nemo/manager.py`           | Structural rail intervention detection                                |
| `NeMoService`                       | `src/gateway/governance/nemo/server.py`              | gRPC server for NeMo sidecar                                          |
| `enforce_governance`                | `src/gateway/server/governance_middleware.py` | Full symbolic governor pipeline invocation                            |
| `enforce_routing_seal`              | `src/gateway/server/governance_middleware.py`  | HMAC seal enforcement                                                 |
| `OPAClient`                         | `src/gateway/core/policy.py`                                    | Async OPA client with circuit breaker                                 |
| `CircuitBreaker`                    | `src/gateway/core/policy.py`                                    | Fail-fast pattern with latency budget                                 |
| Colang flows                        | [`config/rails/main_logic.co`](../../../config/rails/main_logic.co)                                       | Authorization, latency, risk flows                                    |
| PII detection config                | [`config/rails/config.yml`](../../../config/rails/config.yml)                                             | 15 entity types on input and output                                   |
| `THRESHOLDS` singleton              | [`src/gateway/governance/schemas/thresholds.py`](../../../src/gateway/governance/schemas/thresholds.py)   | Single source of truth for all limits                                 |
| Thresholds JSON                     | [`config/governance_thresholds.json`](../../../config/governance_thresholds.json)                         | CBF params, drawdown limit, confidence, consensus threshold, keywords |

### 1.3 Coverage Assessment: **Strong**

> The governance enforcement stack is multi-layered, fail-closed, and deeply instrumented. All threshold literals are centralized in a Pydantic-validated singleton. STPA UCAs map directly to Colang flows. OPA operates with a circuit breaker and latency budget. v2.0.0 adds: Cloud KMS HSM-backed asymmetric signing (primary), DEFER queue (AARM-V7) for confidence-starved contexts, SHA-256 hash-chained context accumulator (AARM-V1), HITL TOCTOU remediation, External Normative Provider with adaptive FRIA gating, and heterogeneous multi-model consensus via ConsensusModelRegistry. The SLM sidecar is permanently deprecated with `slm_available=False` sentinel.

---

## 2. Compliance & OSCAL

### 2.1 What Capability Exists

The **compliance bridge** (`src/compliance_bridge/`) is a standalone FastAPI microservice that implements a fully automated, 5-step ISO 42001 compliance audit pipeline:

1. **Step 1 — Artifact persistence**: Writes raw OSCAL YAML to GCS/S3 (idempotent, skipped if `OSCAL_S3_ENDPOINT` is absent). **v2.0.0:** KMS batch signing (`kms_batch_signer.py`) signs OSCAL artifacts before persistence.
2. **Step 2 — Deterministic OSCAL parsing** (`parse_oscal_yaml`): Zero-LLM, Pydantic-validated extraction of `OscalFinding` objects from Lula assessment result YAML. Handles OSCAL v1.0.4 structure, maps `satisfied`/`not-satisfied` states, and extracts `safety_rate` and `evidence_age_seconds` props.
3. **Step 3 — Langfuse ingestion**: Findings are pushed as scored traces to a dedicated compliance Langfuse project (separate from application performance traces). Each finding creates a trace tagged `compliance`, `iso-42001`, `lula`, and `control:<id>`. **v2.0.0:** Direct Langfuse OTLP ingestion at `http://langfuse-web:3000/api/public/otel/v1/traces` — standalone OTel Collector **deprecated 2026-05-31**.
4. **Step 4 — Critical failure alerting**: FAIL findings on `CRITICAL_CONTROLS` (A.9.2, SC-4) trigger synchronous `Notifier` alerts.
5. **Step 5 — LLM remediation advisory** (conditional): If critical failures exist and `VLLM_BASE_URL` is set, calls vLLM to generate structured remediation recommendations. All LLM advisory outputs are logged to compliance Langfuse with `human_review_required: true`.

**Metrics API** (`GET /v1/metrics/{control_id}`): 5-minute TTL cache wraps Langfuse SDK queries aggregating `iso_42001_outcome` metadata from application traces into `ComplianceMetrics` objects. These are the exact JSON payloads Lula's OPA Rego reads as `input`.

**SSE event bus**: Real-time `AUDIT_FINDING` and `GOVERNANCE_VIOLATION` events are published to connected SSE clients (consumed by the AgentSight KernelDashboard).

**OSCAL Component Definition** (`compliance/oscal/component-definition.yaml`): OSCAL v1.0.4 document mapping four ISO 42001 controls to three system components:

- Component 1 (Governance Gateway): controls A.5.2 (Social Impact) and A.5.3 (Logging/Monitoring)
- Component 2 (OPA Policy Engine): control SC-4 (Fiscal Limits and RBAC)
- Component 3 (NeMo Guardrails + Presidio): control A.9.2 (Data Transfer to Suppliers)

**Lula validation manifests** (15 manifests in `compliance/lula/`): Each links an OPA Rego assertion to the compliance-bridge metrics API or Kubernetes state. The Lula scheduler (`lula_scheduler.py`) enforces cadence tiers: Critical=6h, High=daily, Medium=weekly.

| Control          | Standard          | Cadence          | Domain                         |
| ---------------- | ----------------- | ---------------- | ------------------------------ |
| ISO 42001 A.5.2  | AI system lifecycle | 6h (Critical)  | `api` (compliance-bridge)      |
| ISO 42001 A.5.3  | AI system roles   | Daily (High)     | `api` (compliance-bridge)      |
| ISO 42001 A.9.2  | AI system monitoring | 6h (Critical) | `api` (compliance-bridge)      |
| NIST AC-2        | Account management | —               | `kubernetes`                   |
| NIST AC-3        | Access enforcement | Daily (High)    | `kubernetes`                   |
| NIST AU-12       | Audit record generation | Daily (High) | `kubernetes`                  |
| NIST CM-6        | Configuration settings | Weekly (Medium) | `kubernetes`                 |
| NIST IA-3        | Device identification | —             | `kubernetes`                   |
| NIST IA-5        | Authenticator management | —           | `kubernetes`                   |
| NIST IR-6        | Incident reporting | Daily (High)    | `api`                          |
| NIST RA-5        | Vulnerability scanning | Weekly (Medium) | `api`                        |
| NIST SC-4        | Information in shared resources | 6h (Critical) | `kubernetes` (ConfigMap label) |
| NIST SC-8        | Transmission confidentiality | —     | `kubernetes`                   |
| NIST SI-2        | Flaw remediation  | —                | `api`                          |
| CSA AARM vectors | AARM threat ledger | —               | `api`                          |

All Lula manifests include a cold-start grace period rule (< 6 hours post-deployment) that relaxes sample-size requirements while maintaining safety-rate thresholds.

**Existing governance documentation**: `docs/GOVERNANCE_CROSSWALK.md`, `docs/ISO_42001_COMPLIANCE.md`, `docs/STPA_ANALYSIS.md`, and `docs/NEURO_SYMBOLIC_GOVERNANCE.md` provide architectural rationale and crosswalk tables.

### 2.2 Key Artifacts

| Artifact                       | Location                                                                                   | Role                                   |
| ------------------------------ | ------------------------------------------------------------------------------------------ | -------------------------------------- |
| `run_audit_workflow`           | `src/compliance_bridge/audit_workflow.py`   | 5-step compliance audit pipeline       |
| `parse_oscal_yaml`             | `src/compliance_bridge/oscal_parser.py`       | Deterministic OSCAL YAML parser        |
| `get_compliance_metrics`       | `src/compliance_bridge/metrics.py`                 | TTL-cached Langfuse metrics aggregator |
| `ComplianceMetrics`            | `src/compliance_bridge/metrics.py`                  | Pydantic model consumed by Lula Rego   |
| `OscalFinding`                 | [`src/compliance_bridge/audit_workflow.py`](../../../src/compliance_bridge/audit_workflow.py)       | Validated OSCAL finding model          |
| FastAPI app                    | `src/compliance_bridge/main.py`                       | Compliance bridge service (port 3001)  |
| OSCAL component definition     | [`compliance/oscal/component-definition.yaml`](../../../compliance/oscal/component-definition.yaml) | OSCAL v1.0.4, 3 components, 4 controls |
| Lula A.5.2                     | [`compliance/lula/lula-validation-a52.yaml`](../../../compliance/lula/lula-validation-a52.yaml)     | API-domain Rego validation             |
| Lula A.5.3                     | [`compliance/lula/lula-validation-a53.yaml`](../../../compliance/lula/lula-validation-a53.yaml)     | API-domain Rego validation             |
| Lula A.9.2                     | [`compliance/lula/lula-validation-a92.yaml`](../../../compliance/lula/lula-validation-a92.yaml)     | Zero-tolerance PII control             |
| Lula SC-4                      | [`compliance/lula/lula-validation-sc4.yaml`](../../../compliance/lula/lula-validation-sc4.yaml)     | Kubernetes ConfigMap label assertion   |
| OSCAL audit ingestion endpoint | `src/compliance_bridge/main.py`                       | `POST /v1/audit/ingest`                |
| Compliance metrics endpoint    | `src/compliance_bridge/main.py`                       | `GET /v1/metrics/{control_id}`         |
| SSE event stream               | `src/compliance_bridge/main.py`                       | Real-time governance event feed        |

### 2.3 Coverage Assessment: **Strong**

> OSCAL, Lula, and the compliance bridge implement a closed-loop automated compliance pipeline for **15 controls** (ISO 42001 + NIST SP 800-53 + CSA AARM). The component definition, Lula manifests, metrics aggregation, and audit pipeline are all production-quality. v2.0.0 adds: KMS batch signing for OSCAL artifacts, direct Langfuse OTLP ingestion (OTel Collector deprecated 2026-05-31), AARM threat ledger validation, and cadenced Lula scheduling (Critical=6h, High=daily, Medium=weekly). The full NIST SP 800-53 HIGH baseline (~300 controls) is not yet mapped.

---

## 3. Security Controls & Infrastructure

### 3.1 What Capability Exists

**Kubernetes Network Policy** (`deployment/k8s/network-policy.yaml`): Nine policy objects enforcing a default-deny model within the `governance-stack` namespace:

- Default deny all ingress and egress (policies 1 and 2)
- Allow gateway ingress (port 8080) only from pods labeled `cage.io/role: orchestrator` or from the `ingress-nginx` namespace (policy 3)
- Selective egress allows: OPA on 8181 (policy 4), Redis on 6379 (policy 5), DNS on 53 (policy 6), vLLM on 8000 (policy 7), OPA ingress health checks (policy 8), Langfuse OTLP on 3000 (policy 9) — **Note:** OTLP collector ports 4317/4318 removed; direct Langfuse OTLP ingestion used since 2026-05-31.

**Linkerd mTLS + Cilium L7 egress lockdown** (v2.0.0, POAM-007 closed 2026-05-17): `deployment/k8s/linkerd-mtls-policy.yaml` enforces SPIFFE/SVID identity for Gateway→OPA and Gateway→NeMo paths. `deployment/k8s/cilium-egress-lockdown.yaml` enforces FQDN allowlist for all egress traffic, preventing lateral movement.

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
| NetworkPolicy (9 objects) | [`deployment/k8s/network-policy.yaml`](../../../deployment/k8s/network-policy.yaml)                                                                         | Default-deny namespace isolation             |
| GCP Service Accounts      | [`deployment/terraform/iam.tf`](../../../infra/targets/gcp-gke/iam.tf)                                                                                       | Workload Identity for 2 SAs                  |
| Cloud NAT                 | [`deployment/terraform/networking.tf`](../../../infra/modules/gcp_gke_cluster/networking.tf)                                                                         | Private egress for GKE nodes                 |
| OPA config                | [`deployment/opa_config.yaml`](../../../deployment/opa_config.yaml)                                                                                         | Decision logs, cache, ISO labels             |
| `system.authz`            | [`deployment/system_authz.rego`](../../../deployment/system_authz.rego)                                                                                     | Identity + confidence enforcement            |
| `trade.governance`        | [`src/governed_financial_advisor/governance/policy/trade_governance.rego`](../../../src/governed_financial_advisor/governance/policy/trade_governance.rego) | RBAC, fiscal limits, risk profiles (canonical policy) |
| ~~`finance.generated`~~   | ~~`src/governed_financial_advisor/governance/policy/generated_rules.rego`~~ (purged)                                                               | Transpiler-generated rules — removed; consolidated into `trade_governance.rego` |
| `THRESHOLDS` singleton    | `config/governance_thresholds.json` + `src/gateway/governance/schemas/thresholds.py`                                                               | Single source for all security thresholds    |
| `CircuitBreaker`          | `src/gateway/core/policy.py`                                                                                      | OPA fail-fast with 3000 ms hard limit        |

### 3.3 Coverage Assessment: **Partial**

> Network microsegmentation is strong (default-deny with selective egress). OPA policies cover RBAC, fiscal limits, and confidence enforcement. **v2.0.0 improvements:** Linkerd mTLS + Cilium L7 egress lockdown deployed (POAM-007 closed 2026-05-17); Cloud KMS HSM-backed asymmetric signing replaces HMAC as primary; `outlines` CVE-2025-69872 remediated (POAM-016 closed 2026-05-29); SBOM CronJob deployed with pip-audit/Trivy enforcement (POAM-010 closed). Remaining gaps: Terraform IAM coverage minimal (2 service accounts, no least-privilege role bindings beyond `workloadIdentityUser`); no Pod Security Admission policies; no secrets rotation automation.

---

## 4. Observability & Audit

### 4.1 What Capability Exists

**OTel export pipeline (v2.0.0):** The standalone OTel Collector (`opentelemetry-collector-contrib`) has been **deprecated 2026-05-31**. Services now export OTLP traces directly to Langfuse's integrated OTLP ingestion endpoint at `http://langfuse-web:3000/api/public/otel/v1/traces`. W3C `traceparent` propagation is preserved end-to-end.

**AgentSight UI** (`src/agentsight-ui/`): React/Vite frontend with eBPF kernel observability. Phase 1 deployed: `KernelDashboard.tsx` displays real-time governance events from the SSE event bus. eBPF daemon (`deployment/agentsight/agentsight-config.yaml`) targets `python3` processes, intercepting SSL/TLS via OpenSSL uprobes and monitoring syscalls (`execve`, `openat`, `connect`, `socket`, `bind`). Exporter configured as `type: "remote"` targeting `http://agentsight-dashboard:8080` (POAM-021 closed 2026-05-27).

**Gateway telemetry** (`src/gateway/infrastructure/telemetry.py`): Factory function `get_tracer(name)` wrapping `opentelemetry.trace.get_tracer`. Gracefully degrades to a no-op stub when `opentelemetry-api` is absent. Used by `cbf.py` and other gateway modules (**v3.0.0:** `safety.py` removed).

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
| `get_tracer`                                | `src/gateway/infrastructure/telemetry.py`                                                                | OTel tracer factory for gateway modules      |
| `patch_mcp_tools`                           | `src/gateway/observability/mcp_tracing.py`                                                              | W3C trace context propagation across MCP SSE |
| `stamp_iso_control`                         | `src/gateway/governance/iso_control.py`                                                                    | 6-attribute ISO 42001 span stamping          |
| `run_audit_workflow`                        | `src/compliance_bridge/audit_workflow.py`                                                               | 5-step audit pipeline with SSE events        |
| `get_compliance_metrics`                    | `src/compliance_bridge/metrics.py`                                                                             | TTL-cached Langfuse safety_rate aggregation  |
| `EvaluatorAuditor`                          | [`src/governed_financial_advisor/agents/evaluator/auditor.py`](../../../src/governed_financial_advisor/agents/evaluator/auditor.py)                              | Agent trace auditor (SC-1, quality scoring)  |
| `TraceAuditor`                              | `scripts/automated_auditor.py`                                                                                      | Invariant-based continuous span auditor      |
| `_AUDIT_QUEUE` + `_background_audit_worker` | `src/gateway/governance/consensus.py`                                                                        | Non-blocking consensus audit queue           |
| `GovernanceEventBus`                        | [`src/compliance_bridge/sse_events.py`](../../../src/compliance_bridge/sse_events.py)                                                                           | Real-time SSE event distribution             |
| NeMoOTelCallback                            | [`src/governed_financial_advisor/infrastructure/telemetry/nemo_exporter.py`](../../../src/governed_financial_advisor/infrastructure/telemetry/nemo_exporter.py) | NeMo-to-OTel span callback                   |

### 4.3 Coverage Assessment: **Strong**

> OTel instrumentation is pervasive: every governance tier stamps ISO 42001 evidence attributes. MCP distributed tracing bridges the SSE transport gap. The compliance bridge provides closed-loop audit ingestion and real-time SSE alerting. **v2.0.0:** Direct Langfuse OTLP ingestion (OTel Collector deprecated 2026-05-31); AgentSight UI Phase 1 with eBPF kernel observability deployed (POAM-021 closed); DEFER queue monitoring via Redis db=1 noeviction. The main gap is the `TraceAuditor`, which still relies on mock trace data rather than a live Cloud Trace or OTLP query (POAM-003 open).

---

## 5. Testing & Verification

### 5.1 What Capability Exists

The `tests/` directory contains **644 tests** across 28+ test files spanning unit, integration, red-team, load, and evaluation categories:

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
| `test_symbolic_governor.py`     | [`tests/test_symbolic_governor.py`](../../../tests/test_symbolic_governor.py)                 | 5-tier governance pipeline unit tests |
| `test_compliance_bridge.py`     | [`tests/test_compliance_bridge.py`](../../../tests/test_compliance_bridge.py)                 | OSCAL parser + FastAPI endpoint tests |
| `test_trade_governance_rego.py` | [`tests/test_trade_governance_rego.py`](../../../tests/test_trade_governance_rego.py)         | Rego policy tests (live OPA + mocked) |
| `test_nemo_actions.py`          | [`tests/test_nemo_actions.py`](../../../tests/test_nemo_actions.py)                           | Colang action function tests          |
| `test_red_teaming.py`           | [`tests/test_red_teaming.py`](../../../tests/test_red_teaming.py)                             | CBF drawdown resilience tests         |
| Adversarial dataset             | [`tests/red_team/adversarial_dataset.json`](../../../tests/red_team/adversarial_dataset.json) | Structured adversarial test cases     |
| OPA snapshots                   | `tests/opa_snapshots/`                                       | OPA decision regression fixtures      |
| Load test                       | [`tests/load/locustfile.py`](../../../tests/load/locustfile.py)                               | Locust performance test               |
| vLLM benchmark                  | [`scripts/run_agent_benchmark.py`](../../../scripts/run_agent_benchmark.py)                   | Latency/throughput/P95 measurement    |
| Colang verifier                 | [`scripts/verify_colang_locally.py`](../../../scripts/verify_colang_locally.py)               | Colang 2.x syntax validation          |

### 5.3 Coverage Assessment: **Strong**

> 644 tests across 28+ test files cover unit, integration, red-team, load, and evaluation scenarios. Governance pipeline, OSCAL parsing, Rego policies, NeMo actions, and adversarial inputs all have dedicated test coverage. Live OPA integration tests are correctly gated on `OPA_URL`. Key gaps: no dedicated STPA validator unit tests visible at top level, and the `TraceAuditor` invariant tests use mock traces (POAM-003 open).

---

## 6. Summary Table

| Dimension                                 | Key Artifacts                                                                                                                                                                                                                                                                   | Current Coverage Level | Notes                                                                                                                                                                                               |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1. Governance & Policy Enforcement**    | `ControlBarrierFunction`, `SymbolicGovernor` (8-tier), `STPAValidator`, `TradingKnowledgeGraph`, `ConsensusEngine` (ConsensusModelRegistry), `OPAClient`/`CircuitBreaker`, `stamp_iso_control`, NeMo manager/server/actions, Colang flows, `THRESHOLDS` singleton, `trade.governance` + `system.authz` Rego, `KMSSigner`, `DeferQueue`, `ContextAccumulator`, `NormativeProvider`, `CausalGatekeeper` | **Strong**             | 8-tier governance pipeline (FTRA + 7 in-pipeline tiers); 10-node LangGraph StateGraph; fail-closed; Cloud KMS HSM-backed asymmetric signing (primary); DEFER queue (AARM-V7); SHA-256 hash-chained context accumulator (AARM-V1); HITL TOCTOU remediation; SLM sidecar permanently deprecated |
| **2. Compliance & OSCAL**                 | `run_audit_workflow`, `parse_oscal_yaml`, `get_compliance_metrics`, `compliance/oscal/component-definition.yaml`, **15 Lula validation manifests** (ISO 42001 + NIST SP 800-53 + CSA AARM), compliance-bridge FastAPI, SSE event bus, `kms_batch_signer.py`, `lula_scheduler.py`                | **Strong**             | Closed-loop automated compliance for 15 controls; OSCAL v1.0.4; KMS batch signing for OSCAL artifacts; direct Langfuse OTLP (OTel Collector deprecated 2026-05-31); cadenced Lula scheduling (Critical=6h, High=daily, Medium=weekly) |
| **3. Security Controls & Infrastructure** | 9 NetworkPolicy objects (default-deny), Linkerd mTLS (`linkerd-mtls-policy.yaml`), Cilium L7 egress lockdown (`cilium-egress-lockdown.yaml`), `iam.tf` (2 Workload Identity SAs), `networking.tf` (Cloud NAT), `opa_config.yaml`, `system_authz.rego`, `trade_governance.rego`, `governance_thresholds.json` | **Partial**            | v2.0.0: Linkerd mTLS + Cilium L7 deployed (POAM-007 closed); `outlines` CVE-2025-69872 remediated (POAM-016 closed); SBOM/Trivy CI enforcement (POAM-010 closed); remaining gaps: Terraform IAM minimal, no Pod Security Admission, no secrets rotation |
| **4. Observability & Audit**              | `get_tracer`, `patch_mcp_tools`, `stamp_iso_control`, `run_audit_workflow`, `get_compliance_metrics`, `EvaluatorAuditor`, `TraceAuditor`, `_AUDIT_QUEUE`/`_background_audit_worker`, `GovernanceEventBus`, AgentSight UI (React/Vite + eBPF), direct Langfuse OTLP                              | **Strong**             | v2.0.0: Direct Langfuse OTLP ingestion (OTel Collector deprecated 2026-05-31); AgentSight UI Phase 1 with eBPF kernel observability (POAM-021 closed); DEFER queue monitoring; `TraceAuditor` still uses mock trace source (POAM-003 open) |
| **5. Testing & Verification**             | **644 tests** across 28+ test files — unit, integration, red-team, load, evaluation; `test_symbolic_governor.py`, `test_compliance_bridge.py`, `test_trade_governance_rego.py`, `test_nemo_actions.py`, `test_red_teaming.py`; OPA snapshots; `scripts/run_agent_benchmark.py`, `scripts/verify_colang_locally.py` | **Strong**             | Broad coverage including adversarial/red-team; live OPA tests correctly gated; `TraceAuditor` tests use mock data (POAM-003 open)                                                                   |

---

---

## 7. POAM Summary (as of 2026-05-29)

> Authoritative source: [`docs/POAM.md`](../cross-region/POAM.md) (v1.4, dated 2026-05-29)

| Metric          | Count |
| --------------- | ----- |
| **Total Items** | 23    |
| **Critical**    | 3     |
| **High**        | 13    |
| **Moderate**    | 7     |
| **Open**        | 13    |
| **In Progress** | 3     |
| **Closed**      | 6     |

**Closed items (v1.1.0–v2.0.0):** POAM-003 (closed), POAM-007 (Linkerd mTLS, 2026-05-17), POAM-010 (vulnerability scanning CI, closed), POAM-016 (CVE-2025-69872 `outlines` removed, 2026-05-29), POAM-020 (technical report version mismatch, 2026-05-27), POAM-021 (AgentSight remote mode, 2026-05-27).

**Critical open items:** POAM-005 (no ATO letter, CA-6), POAM-009 (FIPS 199 unsigned, RA-2), POAM-015 (no SSP, PL-2).

---

_This document covers current-state inventory only. NIST RMF gap analysis, control mapping, and remediation planning are addressed in Chunks 2–5._
