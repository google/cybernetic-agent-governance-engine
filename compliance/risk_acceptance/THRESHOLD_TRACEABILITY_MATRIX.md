# CAGE Threshold Traceability Matrix

> **Document ID:** CAGE-TTM-001  
> **Version:** 1.1 (Draft — Pending AO Approval)  
> **Created:** 2026-03-06 · **Last Updated:** 2026-05-22 (SR 26-2 remediation)  
> **System:** Cybernetic AI Governance Engine (CAGE) — Governed Financial Advisor  
> **Classification:** INTERNAL — COMPLIANCE SENSITIVE  
> **NIST Controls:** CM-6, CM-8, SA-8, RA-3  
> **ISO 42001:** A.5.2 (Policies for AI risk), A.9.4 (Monitoring)  
> **Reference:** NIST SP 800-53 Rev. 5, EO 14028, NIST SP 800-218 (SSDF)

---

## Table of Contents

1. [Document Purpose and Scope](#1-document-purpose-and-scope)
2. [Governance Threshold Registry](#2-governance-threshold-registry)
3. [Control-to-Threshold Mapping](#3-control-to-threshold-mapping)
4. [Threshold Change Control](#4-threshold-change-control)
5. [Threshold Risk Acceptance Register](#5-threshold-risk-acceptance-register)
6. [Approval Block](#6-approval-block)

---

## 1. Document Purpose and Scope

### 1.1 Purpose

This **Threshold Traceability Matrix (TTM)** is the authoritative record tracing every machine-enforceable governance threshold in the CAGE system to:

1. Its **regulatory or control source** (NIST SP 800-53 control, ISO 42001 control, STPA hazard analysis, or organizational policy)
2. Its **implementation location** in the CAGE codebase
3. Its **Lula validation** (automated compliance assertion)
4. Its **Langfuse monitoring metric** (observability telemetry)
5. Its **POAM reference** (if the threshold addresses an open weakness)
6. Its **risk acceptance rationale** (if the threshold represents a known risk tradeoff)

### 1.2 Scope

This document covers all thresholds that are:

- **Machine-enforced** — validated at runtime by the CAGE gateway, OPA policy engine, or NeMo Guardrails
- **Configuration-controlled** — stored in `config/governance_thresholds.json`, `src/gateway/governance/safety_params.json`, or equivalent
- **Observable** — emitted as telemetry to Langfuse or Cloud Monitoring

Thresholds that exist only in documentation (not enforced in code) are excluded from this matrix but are noted in the relevant POAM items.

### 1.3 Normative References

| Reference                                | Relevance                                                      |
| ---------------------------------------- | -------------------------------------------------------------- |
| NIST SP 800-53 Rev. 5, CM-6              | Configuration Settings — basis for threshold governance        |
| NIST SP 800-53 Rev. 5, SA-8              | Security engineering principles — threshold design             |
| NIST SP 800-53 Rev. 5, RA-3              | Risk assessment — threshold value justification                |
| NIST SP 800-53 Rev. 5, SR 11-7           | AI component supply chain risk — confidence thresholds (non-agentic components)  |
| SR 26-2 (Federal Reserve, April 2026)    | Agentic AI risk management — bounding, monitoring, world-model, non-determinism  |
| ISO 42001:2023, A.5.2                    | Policies for AI risk management                                |
| ISO 42001:2023, A.9.4                    | Monitoring of AI system performance                            |
| STPA (System Theoretic Process Analysis) | UCA (Unsafe Control Action) threshold derivation               |
| EO 14028 § 4(e)(ix)                      | AI system supply chain risk — confidence and safety thresholds |

### 1.4 Threshold ID Scheme

Threshold IDs follow the pattern `THR-<CATEGORY>-<NNN>`:

| Prefix     | Category                                                   |
| ---------- | ---------------------------------------------------------- |
| `THR-FIN`  | Financial guardrails (trade limits, portfolio constraints) |
| `THR-LAT`  | Latency / performance thresholds                           |
| `THR-CONF` | AI model confidence thresholds                             |
| `THR-SEC`  | Security / access control thresholds                       |
| `THR-AUD`  | Audit / logging thresholds                                 |
| `THR-OBS`  | Observability / telemetry thresholds                       |
| `THR-SAF`  | Safety / hazard control thresholds                         |
| `THR-CBF`  | Control Barrier Function (formal safety) parameters        |
| `THR-CON`  | Consensus / multi-agent quorum thresholds                  |

---

## 2. Governance Threshold Registry

> **Source of Truth:** `config/governance_thresholds.json` (schema validated at gateway startup by `src/gateway/governance/schemas/thresholds.py`)  
> **Safety Supplement:** `src/gateway/governance/safety_params.json`

### 2.1 Full Threshold Registry Table

| Threshold ID     | Threshold Name                                       | Value       | Unit                | Source Control                       | Code Location                                                                                                                                                                   | Lula Validation                                                        | Langfuse Metric                                                                              | POAM Ref                          | Risk Acceptance                                                                                                                                                                                                                                            |
| ---------------- | ---------------------------------------------------- | ----------- | ------------------- | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **THR-FIN-001**  | Minimum Cash Balance Floor                           | 1,000.00    | USD                 | CM-6, AC-3, RA-3                     | `governance_thresholds.json` → `cbf.min_cash_balance`; enforced in `src/gateway/governance/safety.py`                                                                           | `lula-validation-cm6.yaml` (CM-6 config enforcement)                   | `cage.fin.cash_balance_floor_usd` (gauge)                                                    | —                                 | Operational floor; set by risk management. Lower bound must be ≥ $500 per financial services policy.                                                                                                                                                       |
| **THR-FIN-002**  | Maximum Portfolio Drawdown Fraction                  | 0.05 (5%)   | fraction [0,1)      | RA-3, IR-4, ISO 42001 A.9.4          | `governance_thresholds.json` → `drawdown.limit`; `safety_params.json` → `drawdown_limit`; enforced in `src/gateway/governance/stpa_validator.py`                                | `lula-validation-cm6.yaml`                                             | `cage.fin.drawdown_current_pct` (gauge), `cage.fin.drawdown_limit_breach` (counter)          | —                                 | 5% max drawdown aligns with institutional risk tolerance. Documented in risk management charter. AO-accepted.                                                                                                                                              |
| **THR-FIN-003**  | Max Portfolio Sell Fraction per Order (FIN-1)        | 0.10 (10%)  | fraction            | RA-3, CM-6, STPA FIN-1               | `governance_thresholds.json` → `stpa.max_sell_portfolio_fraction`; enforced in `src/gateway/governance/stpa_validator.py`                                                       | `lula-validation-cm6.yaml`                                             | `cage.stpa.fin1_violations` (counter)                                                        | —                                 | Prevents large single-order market impact. Conservative bound per STPA FIN-1 hazard analysis.                                                                                                                                                              |
| **THR-FIN-004**  | UCA-5 Drawdown Block Threshold                       | 4.5         | percent             | STPA UCA-5, RA-3, IR-4               | `governance_thresholds.json` → `stpa.uca5_drawdown_threshold_pct`; enforced in `src/gateway/governance/stpa_validator.py`                                                       | `lula-validation-cm6.yaml`                                             | `cage.stpa.uca5_trigger_count` (counter)                                                     | —                                 | Set 0.5% below absolute 5% limit to provide early warning buffer before hard stop.                                                                                                                                                                         |
| **THR-FIN-005**  | UCA-6 Max Order Volume Fraction of Daily Volume      | 0.01 (1%)   | fraction            | STPA UCA-6, RA-3, CM-6               | `governance_thresholds.json` → `stpa.uca6_max_order_volume_fraction`; enforced in `src/gateway/governance/stpa_validator.py`                                                    | `lula-validation-cm6.yaml`                                             | `cage.stpa.uca6_trigger_count` (counter)                                                     | —                                 | Order size > 1% of daily volume causes slippage. Derived from STPA Unsafe Control Action UCA-6 analysis.                                                                                                                                                   |
| **THR-FIN-006**  | Consensus Trigger Threshold                          | 10,000.00   | USD                 | RA-3, SA-8, ISO 42001 A.5.2          | `governance_thresholds.json` → `consensus.threshold_usd`; enforced in `src/governed_financial_advisor/governance/client.py`                                                     | `lula-validation-cm6.yaml`                                             | `cage.consensus.triggered_count` (counter), `cage.consensus.threshold_usd` (gauge)           | —                                 | Trades above $10K USD require multi-agent consensus check (evaluator + risk analyst agreement). AO-accepted risk acceptance threshold.                                                                                                                     |
| **THR-CBF-001**  | CBF Minimum Cash Balance (γ parameter)               | 0.50        | dimensionless [0,1) | SA-8, CM-6, STPA                     | `governance_thresholds.json` → `cbf.gamma`; used in Control Barrier Function in `src/gateway/governance/safety.py`                                                              | `lula-validation-cm6.yaml`                                             | `cage.cbf.gamma_value` (gauge)                                                               | —                                 | CBF decay factor γ ∈ (0,1). Tuned to provide exponential safety guarantee around cash balance floor. Mathematically derived.                                                                                                                               |
| **THR-LAT-001**  | Max Trade Round-Trip Latency (FIN-2)                 | 200.0       | ms                  | STPA FIN-2, SA-8, SC-7               | `governance_thresholds.json` → `stpa.max_latency_ms`; enforced in `src/gateway/governance/stpa_validator.py`                                                                    | `lula-validation-cm6.yaml`                                             | `cage.latency.trade_rtt_ms` (histogram), `cage.stpa.fin2_violations` (counter)               | —                                 | 200ms is a conservative bound derived from STPA FIN-2 hazard: stale market data risk above this threshold.                                                                                                                                                 |
| **THR-LAT-002**  | SLA Latency P50 Target                               | 100         | ms                  | SA-8, SC-8 (availability)            | Defined in SLA documentation; monitored via OTel histogram in `src/governed_financial_advisor/utils/telemetry.py`                                                               | — (SLA monitoring only)                                                | `cage.gateway.request_duration_ms` (histogram, p50 percentile)                               | POAM-011 (TLS)                    | P50 target. Informational — no hard enforcement gate in code currently.                                                                                                                                                                                    |
| **THR-LAT-003**  | SLA Latency P95 Target                               | 500         | ms                  | SA-8                                 | Defined in SLA documentation; monitored via OTel histogram                                                                                                                      | —                                                                      | `cage.gateway.request_duration_ms` (histogram, p95 percentile)                               | —                                 | P95 target. Informational.                                                                                                                                                                                                                                 |
| **THR-LAT-004**  | SLA Latency P99 Target                               | 2,000       | ms                  | SA-8                                 | Defined in SLA documentation; monitored via OTel histogram                                                                                                                      | —                                                                      | `cage.gateway.request_duration_ms` (histogram, p99 percentile)                               | —                                 | P99 target. Long tail budget for LLM inference.                                                                                                                                                                                                            |
| **THR-CONF-001** | Minimum AI Model Confidence for Trade Execution      | 0.95 (95%)  | probability [0,1]   | ISO 42001 A.5.2, RA-3, CM-6 | `governance_thresholds.json` → `confidence.min_trade_confidence`; enforced in `symbolic_governor.py` (`CTRL_AGT_001`) and OPA policy                        | `lula-validation-cm6.yaml`                                             | `cage.model.confidence_score` (histogram), `cage.model.confidence_below_threshold` (counter) | —                                 | 95% confidence requirement (ISO 42001 §A.5.2 agentic AI bounding). Violation string: `[CTRL_AGT_001] ISO 42001 §A.5.2 Violation: Agentic Confidence Below Threshold`. Legacy citation `SR 26-2 §IV.B` preserved in `control_mappings.json` for SIEM back-compat. |
| **THR-SEC-001**  | Tier-1 Prompt Injection Keyword Blocklist            | 14 keywords | count               | SI-10, SI-15 (AI), AC-3, SC-8        | `governance_thresholds.json` → `tier1_keywords[]` (14 entries: SYSTEM OVERRIDE, IGNORE PREVIOUS INSTRUCTIONS, etc.); enforced in NeMo Guardrails `src/gateway/governance/nemo/` | `lula-validation-ac3.yaml` (AC-3 access enforcement)                   | `cage.security.tier1_injection_blocked` (counter)                                            | —                                 | Hardcoded blocklist of known prompt injection attack patterns. Any match triggers immediate request rejection (no partial confidence scoring). Blocklist is append-only — removals require AO approval.                                                    |
| **THR-SEC-002**  | OPA Circuit Breaker — Max Policy Evaluation Failures | 5           | count               | IR-4, SC-7, SI-7                     | OPA config in `deployment/opa_config.yaml`; circuit breaker logic in `src/governed_financial_advisor/governance/client.py`                                                      | `lula-validation-cm6.yaml`                                             | `cage.opa.policy_eval_failures` (counter), `cage.opa.circuit_breaker_open` (gauge)           | —                                 | If OPA fails to respond 5 consecutive times, the circuit breaker opens and all requests are blocked (fail-closed). Prevents governance bypass on OPA outage.                                                                                               |
| **THR-AUD-001**  | Audit Log Retention Period                           | 90          | days                | AU-11, AU-12                         | GCS lifecycle policy in `deployment/terraform/storage.tf`; Langfuse trace retention configured in Langfuse admin                                                                | `lula-validation-au12.yaml` (AU-12 audit record generation)            | `cage.audit.log_age_days` (gauge — alert if logs deleted early)                              | POAM-003 (AU-12 synthetic traces) | 90 days is the minimum for HIGH-impact systems per AU-11. Organization retains for 1 year for financial regulatory compliance.                                                                                                                             |
| **THR-AUD-002**  | Lula Audit Run Cadence                               | 6           | hours               | CA-7, AU-12                          | CronJob schedule in `deployment/k8s/lula-cron.yaml` → `schedule: "0 */6 * * *"`                                                                                                 | Self-validating (Lula run produces OSCAL assessment result)            | `cage.lula.last_run_age_seconds` (gauge)                                                     | —                                 | 6-hour cadence provides near-real-time continuous monitoring per CA-7.                                                                                                                                                                                     |
| **THR-AUD-003**  | SBOM Generation Cadence                              | 24          | hours               | CM-8                                 | CronJob schedule in `deployment/k8s/sbom-cronjob.yaml` → `schedule: "0 2 * * *"`                                                                                                | `lula-validation-cm6.yaml` (CM-8 component inventory)                  | `cage.sbom.last_generated_age_hours` (gauge)                                                 | POAM-006                          | Daily SBOM generation provides CM-8 continuous component inventory. Remediates POAM-006.                                                                                                                                                                   |
| **THR-OBS-001**  | OpenTelemetry Trace Sampling Rate                    | 0.01 (1%)   | probability         | AU-2, AU-12, SA-8                    | OTel SDK config in `src/governed_financial_advisor/utils/telemetry.py`; `OTEL_TRACES_SAMPLER_ARG=0.01` env var                                                                  | `lula-validation-au12.yaml`                                            | `cage.otel.trace_sample_rate` (gauge)                                                        | —                                 | **KNOWN RISK ACCEPTANCE** — see Section 5. 1% sampling is insufficient for full AU-12 audit evidence. Compensating control: all governance decisions (policy evaluations, confidence checks, trade blocks) are logged at 100% regardless of sampling rate. |
| **THR-OBS-002**  | Langfuse Evidence Age Maximum (ISO 42001 A.5.2)      | 172,800     | seconds (48 hr)     | ISO 42001 A.5.2, AU-12, CA-7         | Lula validation Rego in `deployment/k8s/lula-cron.yaml` → `evidence_age_seconds < 172800`                                                                                       | `lula-validation-cm6.yaml`                                             | `cage.langfuse.evidence_age_seconds` (gauge)                                                 | —                                 | 48-hour evidence freshness window ensures Lula can validate continuous monitoring evidence.                                                                                                                                                                |
| **THR-OBS-003**  | ISO 42001 A.5.2 Safety Rate Minimum                  | 0.99 (99%)  | rate [0,1]          | ISO 42001 A.5.2, RA-3                | Lula Rego in `lula-cron.yaml` → `safety_rate >= 0.99`                                                                                                                           | Lula A.5.2 validation manifest (lula-validation-a52.yaml in ConfigMap) | `cage.iso42001.a52_safety_rate` (gauge)                                                      | —                                 | 99% of all inference requests must pass safety checks. Derived from ISO 42001 A.5.2 monitoring requirements.                                                                                                                                               |
| **THR-OBS-004**  | ISO 42001 A.5.3 Safety Rate Minimum                  | 0.98 (98%)  | rate [0,1]          | ISO 42001 A.5.3                      | Lula Rego → `safety_rate >= 0.98`                                                                                                                                               | Lula A.5.3 manifest                                                    | `cage.iso42001.a53_safety_rate` (gauge)                                                      | —                                 | 98% safety rate for A.5.3 (transparency). Slightly lower than A.5.2 to account for edge cases where transparency metadata is unavailable.                                                                                                                  |
| **THR-OBS-005**  | ISO 42001 A.9.2 Safety Rate Minimum                  | 1.00 (100%) | rate [0,1]          | ISO 42001 A.9.2                      | Lula Rego → `safety_rate == 1.0`                                                                                                                                                | Lula A.9.2 manifest                                                    | `cage.iso42001.a92_safety_rate` (gauge)                                                      | —                                 | 100% required for A.9.2 (human oversight). Every governance override must have a corresponding human review record. No sampling allowed.                                                                                                                   |
| **THR-SAF-001**  | Safety Parameter Drawdown Limit                      | 0.05 (5%)   | fraction [0,1)      | RA-3, STPA, CM-6                     | `src/gateway/governance/safety_params.json` → `drawdown_limit: 0.05`; loaded by `src/gateway/governance/safety.py`                                                              | `lula-validation-cm6.yaml`                                             | `cage.safety.drawdown_limit` (gauge — invariant; alerts if modified)                         | —                                 | Duplicate of THR-FIN-002 (intentional redundancy). Safety params file is read-only at runtime and serves as a tamper-evident copy independent of the main thresholds JSON.                                                                                 |
| **THR-CON-001**  | Multi-Agent Consensus Quorum                         | 2 of 2      | agents              | RA-3, SA-8, ISO 42001 A.5.2          | Consensus logic in `src/governed_financial_advisor/governance/client.py`; requires both evaluator_agent and risk_analyst to agree                                               | `lula-validation-cm6.yaml`                                             | `cage.consensus.quorum_met` (gauge), `cage.consensus.dissent_count` (counter)                | —                                 | All agents must agree (unanimity) for high-value trades. Any dissent blocks the trade. Conservative — reduces throughput but maximizes safety. Triggered when trade > THR-FIN-006.                                                                         |

---

### 2.2 Tier-1 Prompt Injection Keyword Inventory

The following 14 keywords constitute the `tier1_keywords` blocklist enforced by NeMo Guardrails (THR-SEC-001):

| #   | Keyword                               | Classification               |
| --- | ------------------------------------- | ---------------------------- |
| 1   | `SYSTEM OVERRIDE`                     | Privilege escalation pattern |
| 2   | `IGNORE PREVIOUS INSTRUCTIONS`        | Jailbreak pattern            |
| 3   | `DISABLE GUARDRAILS`                  | Safety bypass pattern        |
| 4   | `DISABLE SAFETY`                      | Safety bypass pattern        |
| 5   | `ENTER DEBUG MODE`                    | Privilege escalation pattern |
| 6   | `ENTER ADMIN MODE`                    | Privilege escalation pattern |
| 7   | `ENTER SUDO MODE`                     | Privilege escalation pattern |
| 8   | `YOU ARE NOW FREE`                    | Jailbreak pattern            |
| 9   | `YOU ARE NOW UNFILTERED`              | Jailbreak pattern            |
| 10  | `ROOT-ACCESS`                         | Privilege escalation token   |
| 11  | `BYPASS-ALL-LIMITS`                   | Safety bypass token          |
| 12  | `ADMIN-9999`                          | Privilege escalation token   |
| 13  | `ROOT-ACCESS-2026`                    | Privilege escalation token   |
| 14  | `ACT AS A DEVELOPER WITH ROOT ACCESS` | Role manipulation jailbreak  |

_This list is version-controlled. Additions require security team review; removals require AO written approval._

---

## 3. Control-to-Threshold Mapping

This section provides a reverse lookup: for each NIST SP 800-53 control family, which thresholds enforce it.

| Control ID  | Control Name                 | Enforcing Thresholds                                                                                         | Threshold IDs                                | Implementation Status                                               |
| ----------- | ---------------------------- | ------------------------------------------------------------------------------------------------------------ | -------------------------------------------- | ------------------------------------------------------------------- |
| **AC-3**    | Access Enforcement           | Prompt injection blocklist enforces access control to system resources via AI input vector                   | THR-SEC-001                                  | ✅ Implemented — NeMo Guardrails runtime enforcement                |
| **AC-4**    | Information Flow Enforcement | Confidence threshold gates information flow from AI model to trade execution                                 | THR-CONF-001                                 | ✅ Implemented — `safety_node.py` enforcement                       |
| **AU-2**    | Event Logging                | OTel sampling rate determines audit event capture rate                                                       | THR-OBS-001                                  | ⚠️ PARTIAL — 1% sampling; compensated by 100% governance logging    |
| **AU-11**   | Audit Record Retention       | Audit log retention period                                                                                   | THR-AUD-001                                  | ✅ Implemented — GCS lifecycle + Langfuse retention                 |
| **AU-12**   | Audit Record Generation      | Lula cadence, OTel sampling, evidence age freshness                                                          | THR-AUD-002, THR-OBS-001, THR-OBS-002        | ⚠️ PARTIAL — POAM-003 (synthetic traces); AU-12 validated by Lula   |
| **CM-6**    | Configuration Settings       | All thresholds in governance_thresholds.json are CM-6 configuration settings                                 | ALL THR-\*                                   | ✅ Validated by `schemas/thresholds.py` Pydantic enforcement + Lula |
| **CM-7**    | Least Functionality          | OPA circuit breaker (fail-closed) prevents unauthorized gateway functionality on policy engine failure       | THR-SEC-002                                  | ✅ Implemented — fail-closed circuit breaker                        |
| **CM-8**    | System Component Inventory   | SBOM generation cadence                                                                                      | THR-AUD-003                                  | 🔄 IN PROGRESS — POAM-006; remediated by sbom-cronjob.yaml          |
| **IR-4**    | Incident Handling            | Drawdown thresholds trigger automated incident response (trade halt)                                         | THR-FIN-002, THR-FIN-004                     | ✅ Implemented — STPA validator auto-halt                           |
| **RA-3**    | Risk Assessment              | All financial guardrail thresholds derive from RA-3 risk assessment                                          | THR-FIN-001 through THR-FIN-006, THR-CBF-001 | ✅ Threshold values documented with risk rationale                  |
| **RA-5**    | Vulnerability Monitoring     | SBOM generation (CM-8/RA-5 overlap) enables CVE cross-referencing                                            | THR-AUD-003                                  | 🔄 IN PROGRESS — POAM-010; Grype integration added                  |
| **SA-8**    | Security Engineering         | Confidence threshold, latency SLAs, CBF parameter reflect security engineering principles                    | THR-CONF-001, THR-LAT-001, THR-CBF-001       | ✅ Documented with STPA and formal methods derivation               |
| **SC-7**    | Boundary Protection          | OPA circuit breaker enforces boundary between external input and trade execution                             | THR-SEC-002                                  | ✅ Implemented                                                      |
| **SC-8**    | Transmission Confidentiality | Latency SLAs indirectly enforce SC-8 (slow responses may indicate TLS inspection); latency anomaly detection | THR-LAT-001                                  | ⚠️ PARTIAL — POAM-011 (no TLS assertion test)                       |
| **SI-10**   | Information Input Validation | Tier-1 keyword blocklist is the primary input validation control for AI prompt injection                     | THR-SEC-001                                  | ✅ Implemented — NeMo Guardrails                                    |
| **SI-15**   | Information Output Filtering | Confidence threshold gates model output from reaching trade execution                                        | THR-CONF-001                                 | ✅ Implemented                                                      |
| **CTRL_MRM_004** | Traditional MRM Controls (CBF + DoWhy Kernel) | Deterministic formula (`h(x) = cash − floor`, γ decay) and DoWhy linear regression coefficients | `safety.py` (`CTRL_MRM_004` OTel span), `causal_gatekeeper.py` Phase 1 (`causal_gatekeeper.statistical_kernel` span) | SR 26-2 §IV MRM | ✅ Implemented — CTRL_MRM_004 wired; dual OTel span tagging on DoWhy |
| **SR 26-2**      | Agentic AI Confidence + Scope | Minimum AI model confidence threshold implements agentic bounding (`CTRL_AGT_001`); agent scope boundary declared in `config/agent_scope.yaml` | THR-CONF-001 | ✅ Implemented — all 4 governance gaps closed; regulatory strings decoupled to `control_mappings.json` via Option 3 refactor |
| **SR 11-7**      | AI Component Risk (legacy, non-agentic) | SR 11-7 thresholds remain applicable to non-agentic model components; `legacy_citation` field in `control_mappings.json` preserves SIEM backward-compatibility | THR-CONF-001 | ✅ Implemented — legacy citation preserved in registry, not in source code |

---

## 4. Threshold Change Control

### 4.1 Change Request Process

All changes to governance thresholds in `config/governance_thresholds.json` or `src/gateway/governance/safety_params.json` require:

1. **Formal Change Request (CR)** — submitted to the Change Advisory Board (CAB)
2. **Risk Impact Assessment** — ISSO reviews whether the change affects CM-6 configuration settings or triggers re-authorization
3. **CAB Approval** — required for ALL threshold changes in a HIGH-impact system
4. **Testing** — threshold change must pass all Lula validations and governance unit tests
5. **Deployment** — approved changes are merged to `main` via PR with required code review
6. **Evidence** — PR number, CR number, and CAB approval date are recorded in this document (Section 4.3)

### 4.2 Re-Authorization Triggers

Changes to the following thresholds trigger a **re-authorization event** (must be reviewed by the AO before deployment):

| Change Type                                           | Re-Authorization Category             | Rationale                                                                          |
| ----------------------------------------------------- | ------------------------------------- | ---------------------------------------------------------------------------------- |
| Decrease `confidence.min_trade_confidence` below 0.90 | CM-Cat-M (Major Configuration Change) | Lowering AI confidence gate materially increases risk of erroneous trade execution |
| Increase `drawdown.limit` above 0.10 (10%)            | CM-Cat-M                              | Increases maximum financial loss exposure; changes risk posture                    |
| Remove any entry from `tier1_keywords`                | CM-Cat-N (New Authorization)          | Reduces prompt injection protection surface                                        |
| Decrease `consensus.threshold_usd` below $5,000       | CM-Cat-M                              | Lowers the bar for consensus-gated trades; affects multi-agent safety controls     |
| Modify `cbf.gamma` outside [0.3, 0.7]                 | CM-Cat-M                              | CBF safety guarantee degrades outside this validated range                         |
| Set `stpa.max_latency_ms` > 1000ms                    | CM-Cat-M                              | Allows stale market data risk beyond STPA hazard analysis bounds                   |

**All other threshold changes:** CAB approval required; re-authorization not triggered if change is within validated range and risk posture is unchanged.

### 4.3 Threshold Value History

> _This section is maintained as a version-controlled record. Entries are added when thresholds are changed._

| CR #   | Change Date | Threshold ID | Old Value     | New Value       | CAB Approval           | AO Review          | Reason                                                         |
| ------ | ----------- | ------------ | ------------- | --------------- | ---------------------- | ------------------ | -------------------------------------------------------------- |
| CR-000 | 2026-03-06  | ALL          | N/A (initial) | See Section 2.1 | N/A (initial baseline) | Pending (POAM-005) | Initial threshold baseline established during NIST RMF Phase 3 |

### 4.4 Emergency Change Process

In the event of an active security incident (e.g., detected prompt injection attack at scale), threshold changes may be applied as **Emergency Changes**:

1. ISSO or On-Call Engineer applies the change via hotfix PR
2. CAB is notified within 4 hours
3. AO is notified within 24 hours
4. Full change request is retroactively filed within 5 business days
5. Post-incident review assesses whether re-authorization is required

---

## 5. Threshold Risk Acceptance Register

This section documents thresholds that represent **known risk acceptances** — cases where the threshold value provides less protection than ideally desired, compensated by other controls.

---

### 5.1 RA-001: OTel Trace Sampling at 1% (THR-OBS-001)

| Field                     | Value                                                                                                                                                                                                                                                                                                                                                                                 |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Risk Acceptance ID**    | RA-001                                                                                                                                                                                                                                                                                                                                                                                |
| **Threshold**             | THR-OBS-001 — OpenTelemetry Trace Sampling Rate                                                                                                                                                                                                                                                                                                                                       |
| **Current Value**         | 0.01 (1%)                                                                                                                                                                                                                                                                                                                                                                             |
| **Ideal Value**           | 1.00 (100%) for full AU-12 compliance                                                                                                                                                                                                                                                                                                                                                 |
| **Risk Accepted**         | 99% of inference traces are NOT captured as full OTel spans. AU-12 requires records of all events for audit. At 1% sampling, most requests produce no durable audit trace.                                                                                                                                                                                                            |
| **Why Not 100%?**         | At production scale, 100% trace sampling would generate >10TB/day of trace data, exceeding GCS budget and Langfuse ingest capacity. Cloud Trace costs at 100% sampling for HIGH-volume AI inference are prohibitive without a dedicated trace store.                                                                                                                                  |
| **Who Accepted**          | Authorizing Official (AO) — [SIGNATURE PENDING]                                                                                                                                                                                                                                                                                                                                       |
| **Acceptance Date**       | Pending AO signature (target: 2026-04-30)                                                                                                                                                                                                                                                                                                                                             |
| **Compensating Controls** | (1) All governance decisions — policy evaluations, confidence checks, trade blocks, prompt injection rejections — are emitted as **structured audit log events at 100%** regardless of OTel sampling. (2) Langfuse captures every LLM call via LangChain instrumentation at 100% to the compliance project. (3) OPA decision logs are 100% captured via `deployment/opa_config.yaml`. |
| **Residual Risk**         | Moderate — non-governance ordinary request traces (e.g., health checks, benign market data queries) are under-sampled. These have low security impact.                                                                                                                                                                                                                                |
| **Review Date**           | 2026-09-30 (6-month review; reassess if trace volume or budget changes)                                                                                                                                                                                                                                                                                                               |
| **POAM Ref**              | POAM-003 (AU-12 synthetic traces) — related but separate weakness                                                                                                                                                                                                                                                                                                                     |

---

### 5.2 RA-002: Consensus Threshold at $10,000 USD (THR-FIN-006)

| Field                     | Value                                                                                                                                                                                                                                                                                  |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Risk Acceptance ID**    | RA-002                                                                                                                                                                                                                                                                                 |
| **Threshold**             | THR-FIN-006 — Multi-Agent Consensus Trigger                                                                                                                                                                                                                                            |
| **Current Value**         | $10,000 USD                                                                                                                                                                                                                                                                            |
| **Ideal Value**           | $0 (consensus on ALL trades)                                                                                                                                                                                                                                                           |
| **Risk Accepted**         | Trades below $10,000 USD are executed by a single agent without multi-agent consensus review. A compromised or hallucinating agent could execute up to $9,999.99 in trades without consensus check.                                                                                    |
| **Why Not $0?**           | Requiring consensus on all trades — including small test orders, fee payments, and routine rebalancing — would create unacceptable latency (multi-agent round-trip adds ~500ms per trade) and would make the system operationally unviable for high-frequency small-amount activities. |
| **Who Accepted**          | Authorizing Official (AO) — [SIGNATURE PENDING]                                                                                                                                                                                                                                        |
| **Acceptance Date**       | Pending AO signature (target: 2026-04-30)                                                                                                                                                                                                                                              |
| **Compensating Controls** | (1) All trades below threshold still pass the 95% confidence gate (THR-CONF-001). (2) All trades pass STPA drawdown/volume checks (THR-FIN-002, THR-FIN-003, THR-FIN-004, THR-FIN-005). (3) All trades pass OPA Rego policy evaluation. (4) All trade events are logged via AU-12.     |
| **Residual Risk**         | Low-Moderate — mitigated by overlapping safety controls on single-agent path.                                                                                                                                                                                                          |
| **Review Date**           | 2026-09-30                                                                                                                                                                                                                                                                             |
| **POAM Ref**              | —                                                                                                                                                                                                                                                                                      |

---

### 5.3 RA-003: SBOM Scanning Latency — Daily vs. Real-Time (THR-AUD-003)

| Field                     | Value                                                                                                                                                                                                                                                                                                              |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Risk Acceptance ID**    | RA-003                                                                                                                                                                                                                                                                                                             |
| **Threshold**             | THR-AUD-003 — SBOM Generation Cadence                                                                                                                                                                                                                                                                              |
| **Current Value**         | 24 hours (daily at 02:00 UTC)                                                                                                                                                                                                                                                                                      |
| **Ideal Value**           | Per-build SBOM generation (on every CI push)                                                                                                                                                                                                                                                                       |
| **Risk Accepted**         | A new CVE disclosed after a container image is built but before the next daily SBOM scan (up to 23h 59m) would not be detected until the next scheduled scan. In a zero-day scenario, CAGE could run vulnerable code for up to 24 hours without automated detection.                                               |
| **Why Not Per-Build?**    | Full container image SBOM scanning (Syft + Grype) takes 3–8 minutes per image. The K8s CronJob scans all 4 CAGE images; doing this on every git push would add 15–30 minutes to CI and create GCS cost concerns for artifact storage. Per-build Python SBOM is implemented in CI (mitigates Python-specific risk). |
| **Who Accepted**          | Authorizing Official (AO) — [SIGNATURE PENDING]                                                                                                                                                                                                                                                                    |
| **Acceptance Date**       | Pending AO signature (target: 2026-04-30)                                                                                                                                                                                                                                                                          |
| **Compensating Controls** | (1) Python dependency SBOM IS generated on every CI push via `sbom-generation` GitHub Actions job. (2) pip-audit runs on every PR. (3) Trivy filesystem scan runs on every PR. (4) GitHub Dependabot alerts provide near-real-time CVE notification independent of SBOM pipeline.                                  |
| **Residual Risk**         | Low — container image CVE exposure window is 24h max; Python dependency exposure is near-zero due to per-build scanning.                                                                                                                                                                                           |
| **Review Date**           | 2026-09-30                                                                                                                                                                                                                                                                                                         |
| **POAM Ref**              | POAM-006 (being remediated), POAM-010                                                                                                                                                                                                                                                                              |

---

### 5.4 RA-004: Single-Node OPA (No HA) (THR-SEC-002)

| Field                     | Value                                                                                                                                                                                                                                                                           |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Risk Acceptance ID**    | RA-004                                                                                                                                                                                                                                                                          |
| **Threshold**             | THR-SEC-002 — OPA Circuit Breaker Max Failures                                                                                                                                                                                                                                  |
| **Current Value**         | 5 consecutive failures before circuit open                                                                                                                                                                                                                                      |
| **Ideal Value**           | 0 failures (HA OPA cluster — no circuit breaker needed)                                                                                                                                                                                                                         |
| **Risk Accepted**         | OPA runs as a single pod (`deployment/k8s/opa.yaml`). If OPA crashes, the circuit breaker opens after 5 failures and blocks all requests. During those 5 failed requests, trades may be executed without full OPA policy evaluation.                                            |
| **Why Not HA OPA?**       | Multi-replica OPA with distributed bundle synchronization requires Kubernetes leader election and increases infrastructure complexity. Deferred to post-ATO hardening.                                                                                                          |
| **Who Accepted**          | ISSO (interim acceptance) — AO review required for ATO                                                                                                                                                                                                                          |
| **Acceptance Date**       | 2026-03-06 (interim)                                                                                                                                                                                                                                                            |
| **Compensating Controls** | (1) Fail-closed circuit breaker blocks ALL requests after 5 failures (no silent passthrough). (2) NeMo Guardrails provides independent Tier-1 keyword filtering independent of OPA. (3) Confidence threshold (THR-CONF-001) is enforced in `safety_node.py` independent of OPA. |
| **Residual Risk**         | Low — window of 5 requests is small; fail-closed guarantees no long-term governance bypass.                                                                                                                                                                                     |
| **Review Date**           | 2026-07-31 (align with POAM-007 mTLS remediation)                                                                                                                                                                                                                               |
| **POAM Ref**              | — (not currently in POAM; ISSO to evaluate adding)                                                                                                                                                                                                                              |

---

## 6. Approval Block

```
================================================================================
  CAGE THRESHOLD TRACEABILITY MATRIX — SIGNATURE PAGE
  Document ID: CAGE-TTM-001
  Version: 1.0 Draft
  Date: 2026-03-06
================================================================================

[SIGNATURE REQUIRED — PENDING AO APPROVAL]

This document requires review and signature by the following officials before
it carries formal risk acceptance authority:

┌─────────────────────────────────────────────────────────────────────────────┐
│ SYSTEM OWNER                                                                 │
│                                                                              │
│ Name:    _______________________________  Date: ___________________________  │
│ Title:   System Owner — CAGE                                                 │
│ Signature: _____________________________                                     │
│                                                                              │
│ Attestation: I certify that the threshold values in Section 2 represent      │
│ the current operational configuration of the CAGE system and that the        │
│ risk acceptances in Section 5 reflect considered organizational risk         │
│ decisions within my authority.                                               │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ INFORMATION SYSTEM SECURITY OFFICER (ISSO)                                   │
│                                                                              │
│ Name:    _______________________________  Date: ___________________________  │
│ Title:   ISSO — CAGE                                                         │
│ Signature: _____________________________                                     │
│                                                                              │
│ Attestation: I have reviewed this Threshold Traceability Matrix for          │
│ completeness and accuracy. All threshold-to-control mappings in Section 3    │
│ are accurate to the best of my knowledge. POAM references are current        │
│ as of the date of this document.                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ AUTHORIZING OFFICIAL (AO)                                                    │
│                                                                              │
│ Name:    _______________________________  Date: ___________________________  │
│ Title:   Authorizing Official                                                │
│ Signature: _____________________________                                     │
│                                                                              │
│ Attestation: Having reviewed the threshold values, control mappings, change  │
│ control procedures, and risk acceptances documented herein, I authorize the  │
│ CAGE system to operate under these threshold values. Risk acceptances        │
│ RA-001 through RA-004 are formally accepted with the compensating controls   │
│ described in Section 5.                                                      │
│                                                                              │
│ This acceptance expires: _________________________ (not to exceed 1 year)   │
└─────────────────────────────────────────────────────────────────────────────┘
================================================================================
```

---

## Appendix A: Threshold Configuration Files

| File                                                                                           | Description                                | Schema Enforced By                                                              |
| ---------------------------------------------------------------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------------------- |
| [`config/governance_thresholds.json`](../../config/governance_thresholds.json)                 | Primary threshold registry                 | `src/gateway/governance/schemas/thresholds.py` (Pydantic, fail-fast on startup) |
| [`src/gateway/governance/safety_params.json`](../../src/gateway/governance/safety_params.json) | Safety parameter supplement                | `src/gateway/governance/safety.py`                                              |
| [`deployment/k8s/lula-cron.yaml`](../../deployment/k8s/lula-cron.yaml)                         | Lula validation thresholds (embedded Rego) | Lula validate runtime                                                           |
| [`deployment/opa_config.yaml`](../../deployment/opa_config.yaml)                               | OPA bundle configuration                   | OPA runtime                                                                     |

## Appendix B: Langfuse Metric Naming Convention

All CAGE Langfuse metrics follow the schema: `cage.<subsystem>.<metric_name>`

Metric types:

- **counter** — monotonically increasing event count (resets on restart)
- **gauge** — current point-in-time value
- **histogram** — distribution with configurable percentile buckets (p50, p95, p99)

Governance-critical metrics (emitted at 100% regardless of OTel sampling rate):

- All `cage.stpa.*` metrics (STPA violation counters)
- All `cage.security.*` metrics (prompt injection, circuit breaker)
- All `cage.consensus.*` metrics (consensus gate events)
- All `cage.model.confidence_below_threshold` counters

---

_This document is maintained under CAGE document control. Unauthorized modification is prohibited. See [Section 4](#4-threshold-change-control) for the change control process._

_Last reviewed: 2026-03-06 | Next scheduled review: 2026-09-06_
