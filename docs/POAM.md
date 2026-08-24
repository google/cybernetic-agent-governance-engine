# Security Posture Statement — Plan of Action and Milestones (POAM)

**System:** Cybernetic AI Governance Engine (CAGE)
**Document:** Public Security Posture Statement
**Frameworks:** NIST SP 800-53 Rev. 5, NIST AI 600-1, ISO 42001, EU AI Act, DORA, GDPR, MAS FEAT, MAS TRM, MAS Notice 655
**Last Updated:** 2026-08-16

---

## Purpose

This document is a public transparency statement about the security posture of the Cybernetic Governance Engine (CAGE). It describes the compliance controls being addressed, the frameworks they map to, and the general remediation timeline.

CAGE is an open-source AI governance platform for financial services. It enforces governance policies over multi-agent LLM workflows via:

- **Pre-Pipeline Boundary Gate**: FTRA (Forward-Looking Trajectory Reachability Analyzer) — operates on the whole execution graph before per-tool-call checks begin
- **Tiers 0–6b** (per-tool-call checks in `_run_checks()`): NeMo Guardrails → STPA/UCA validation → Agentic confidence check → Control Barrier Function + OPA Rego (concurrent) → Fiscal Limit Pre-Reservation → Multi-model consensus → Causal gatekeeper → Adaptive FRIA gate

The system is designed for deployment across three regulatory regions: US Federal (`US_FED`), EU ECB (`EU_ECB`), and APAC MAS (`APAC_MAS`).

---

## Compliance Frameworks

| Framework | Scope |
|-----------|-------|
| NIST SP 800-53 Rev. 5 (HIGH baseline) | US Federal deployment |
| NIST AI 600-1 | AI-specific risk controls (all regions) |
| ISO 42001:2023 | AI management system (all regions) |
| EU AI Act | EU ECB deployment |
| DORA (Digital Operational Resilience Act) | EU ECB deployment |
| GDPR Art. 22 | EU ECB deployment |
| MAS FEAT Principles | APAC MAS deployment |
| MAS Notice 655 | APAC MAS deployment |
| MAS TRM Guidelines §6.3 | APAC MAS deployment |

---

## Security Strengths

The following controls are fully implemented and validated via automated Lula compliance assertions:

| Control | Framework | Status |
|---------|-----------|--------|
| AC-2 — Account Management | NIST SP 800-53 | ✅ Implemented |
| AC-3 — Access Enforcement (OPA + NeMo Guardrails) | NIST SP 800-53 | ✅ Implemented |
| AU-12 — Audit Record Generation (OpenTelemetry + Langfuse) | NIST SP 800-53 | ✅ Implemented |
| IA-3 — Device Identification (Linkerd mTLS) | NIST SP 800-53 | ✅ Implemented |
| CM-6 — Configuration Settings (schema-validated thresholds) | NIST SP 800-53 | ✅ Implemented |
| IR-6 — Incident Reporting | NIST SP 800-53 | ✅ Implemented |
| SC-4 — Fiscal Limits / RBAC | NIST SP 800-53 | ✅ Implemented |
| ISO 42001 A.5.2 — Social Impact Assessment | ISO 42001 | ✅ Implemented |
| ISO 42001 A.5.3 — Logging and Monitoring | ISO 42001 | ✅ Implemented |
| ISO 42001 A.9.2 — Data Transfer to Suppliers | ISO 42001 | ✅ Implemented |
| CSA AARM — All 11 threat vectors | CSA AARM | ✅ Implemented |
| NIST AI 600-1 §2.1 — Confabulation controls | NIST AI 600-1 | ✅ Implemented |
| NIST AI 600-1 §2.2 — Data Privacy | NIST AI 600-1 | ✅ Implemented |
| NIST AI 600-1 §2.3 — Prompt Injection | NIST AI 600-1 | ✅ Implemented |
| NIST AI 600-1 §2.5 — Human-AI Configuration | NIST AI 600-1 | ✅ Implemented |

---

## Open Findings

The following findings are tracked as open items with target remediation dates. All findings are captured in the automated Lula compliance validation suite in `compliance/lula/`.

### US Federal Region (US_FED)

| ID | Control | Description | Severity | Target Date |
|----|---------|-------------|----------|-------------|
| POAM-2026-010 | RA-5 | In-cluster vulnerability scanning CronJob not yet deployed | High | 2026-09-30 |
| POAM-2026-016 | RA-5 / SI-2 | `torch` dev-only dependency carries PYSEC-2026-139; no upstream fix available; dev-only scope, not in production images | Low | 2026-12-31 |
| POAM-2026-023 | RA-5 | CVE-2025-13462 in `libpython3.11` base layer; no Debian bookworm fix available; base pinned to bookworm with build-time upgrade and network egress locked down via Cilium | Critical | 2026-09-08 |
| POAM-2026-024 | CM-6 | Staging environment compliance posture not yet verified against Lula validation suite | Moderate | 2026-09-30 |
| POAM-2026-025 | NIST AI 600-1 §2.6 | CBRN / harmful content Lula validation is a stub pending AO pre-approval for NeMo CBRN rail deployment | High | 2026-12-31 |
| POAM-2026-026 | ISO 42001 A.8.4 | Standalone `token-quota-proxy` Deployment not yet created; TokenQuotaProxy runs inline in gateway | Moderate | 2026-09-30 |

### EU ECB Region (EU_ECB)

| ID | Control | Description | Severity | Target Date |
|----|---------|-------------|----------|-------------|
| EU-DORA-001 | DORA Art. 10 | Compliance bridge endpoint for DORA ICT operational resilience evidence not yet implemented | High | 2026-12-31 |
| EU-AI-ACT-001 | EU AI Act Art. 9 | Compliance bridge endpoint for EU AI Act risk management system evidence not yet implemented | High | 2026-12-31 |
| EU-GDPR-001 | GDPR Art. 22 | Compliance bridge endpoint for GDPR human oversight of automated decisions not yet implemented | High | 2026-12-31 |
| EU-001 | EU AI Act Art. 29a | FRIA gating normative provider is in stub mode; external compliance validation provider not yet configured for EU_ECB | High | 2026-12-31 |

### APAC MAS Region (APAC_MAS)

| ID | Control | Description | Severity | Target Date |
|----|---------|-------------|----------|-------------|
| APAC-MAS-FEAT-001 | MAS FEAT | Compliance bridge endpoint for MAS FEAT fairness/ethics/accountability/transparency evidence not yet implemented | High | 2026-12-31 |
| APAC-MAS-N655-001 | MAS Notice 655 | Compliance bridge endpoint for MAS Notice 655 technology risk management audit logging not yet implemented | High | 2026-12-31 |
| APAC-MAS-TRM-001 | MAS TRM §6.3 | Compliance bridge endpoint for MAS TRM AI/ML controls evidence not yet implemented | High | 2026-12-31 |

---

## Closed Findings

The following findings have been remediated and verified via Lula validation and unit/manifest regression suites:

| ID | Control | Description | Closed |
|----|---------|-------------|--------|
| POAM-2026-001 | AC-2 | Account management procedures gap — remediated via named ServiceAccount pattern with `cage.io/account-purpose` labels | 2026-06-08 |
| POAM-2026-007 | IA-3 | No intra-cluster mTLS — remediated via Linkerd service mesh deployment across all `governance-stack` services | 2026-05-17 |
| POAM-2026-011 | SC-8 | TLS enforcement assertion added to gateway test suite via `tests/test_tls_enforcement.py` covering NIST SP 800-52 Rev. 2 minimum TLS 1.2+ validation, OIDC HTTPS enforcement, and Linkerd mTLS manifest policies | 2026-08-22 |
| POAM-2026-012 | SC-12 / IA-5 | Cryptographic key rotation schedule and lifecycle management documented in [`docs/operations/KEY_ROTATION.md`](operations/KEY_ROTATION.md) covering Cloud KMS HSM keys (90-day), HMAC routing seal secrets (30-day), and emergency revocation | 2026-08-22 |
| POAM-2026-013 | SI-2 | Third-party container images (`openpolicyagent/opa:0.68.0-static`, `redis/redis-stack-server:7.4.0-v1`, `aquasec/trivy:0.51.4`, `anchore/syft:v1.10.0`) pinned to deterministic versions across `deployment/k8s/` manifests | 2026-08-22 |
| POAM-2026-027 | Structural | POAM tracking document absent from repository — remediated by creating this document | 2026-06-30 |
| POAM-2026-028 | RA-5 / SI-2 | `langchain` GHSA-gr75-jv2w-4656 and related transitive CVEs — remediated by upgrading to `langchain==1.3.11`, `langsmith==0.9.5`, `python-multipart==0.0.32` | 2026-07-02 |
| POAM-2026-037 | RA-5 / SI-2 | Base images across all Dockerfiles (`Dockerfile`, `src/compliance_bridge/Dockerfile`, `src/gateway/Dockerfile`) standardized to `python:3.12-slim-bookworm` with build-time `apt-get upgrade -y --no-install-recommends` and `.trivyignore` tracking | 2026-08-22 |
| POAM-2026-029 | CA-7 | `src/compliance_bridge/sla_monitor.py` imported the deprecated flat `EVIDENCE_SLA_SECONDS` alias instead of the region-aware `get_sla_seconds(region)` accessor in `types.py` — remediated via a new `_active_sla_seconds()` helper that resolves `CAGE_DEPLOYMENT_REGION` fresh on every poll cycle; jurisdictional SLA controls (SC-7/SC-8 for US_FED, Article 12 for EU_ECB, MAS-FEAT-1 for APAC_MAS) are now monitored in their applicable region; FINDING-05 in `docs/compliance/cross-region/JURISDICTIONAL_SEPARATION_ANALYSIS.md` closed; covered by 6 new tests in `tests/test_compliance_bridge_tier2.py::TestSlaMonitor` | 2026-07-30 |
| POAM-2026-030 | SA-11 | `src/gateway/governance/ftra/` (the production FTRA Pre-Pipeline Boundary Gate) had zero test coverage — remediated by adding `tests/test_ftra_package.py` (30 tests covering `IrreversibilityClassifier`, `PlanGraphAnalyzer`, `create_ftra_node()`, `route_after_ftra()`); this exposed two previously-undetected production defects, both fixed in the same change and now regression-tested (see POAM-2026-033) | 2026-07-30 |
| POAM-2026-031 | CBF / SI-2 | External CBF state reconciliation not implemented — remediated by `src/compliance_bridge/reconciliation_worker.py` (v2.1.0); reconciled balances are KMS-signed before Redis write; CBF fails closed on TTL expiry | 2026-07-27 |
| POAM-2026-032 | SA-11 | `src/gateway/governance/ftra_reachability.py` was an unwired `FtraReachabilityGate` scaffold committed alongside the production `src/gateway/governance/ftra/` package in the same commit but never imported by `SymbolicGovernor` or any production code path; its dedicated test file (`tests/test_ftra_reachability.py`) exercised only this dead code, giving a false impression of FTRA test coverage — remediated by deleting both files; documentation across 5 files corrected to describe the actual `ftra/` implementation (`PlanGraphAnalyzer`, `IrreversibilityClassifier`, `create_ftra_node`) instead of the removed scaffold | 2026-07-30 |
| POAM-2026-033 | CA-7 / SI-2 | Two defects in `src/gateway/governance/ftra/node_factory.py` uncovered while closing POAM-2026-030's test-coverage gap: **(1)** `_park_in_defer_queue()` instantiated `DeferQueue()` with zero arguments, but `DeferQueue.__init__` requires a `redis_client` — this always raised `TypeError`, silently caught by a broad `except Exception`, so every HITL_REQUIRED verdict's DeferToken was never actually persisted to Redis db=1, making it unreachable via the external HITL resolution API (`POST /v1/defer/{id}/escalate`); **(2)** `ftra_node()`'s outer exception handler caught `NodeInterrupt` (a subclass of `Exception` in LangGraph) unconditionally, converting every HITL_REQUIRED verdict into a fail-closed `BLOCKED` response before the thread could ever suspend for human review — remediated by **(1)** connecting via `redis.asyncio.from_url(REDIS_URL, db=1)` then `DeferQueue(client)`, mirroring the working pattern in `src/compliance_bridge/main.py`, and **(2)** re-raising `GraphInterrupt`/`NodeInterrupt` before the generic exception handler runs; both fixes covered by dedicated regression tests in `tests/test_ftra_package.py::TestCreateFtraNode` | 2026-07-30 |
| POAM-2026-034 | R-2, R-6 | `GovernanceThresholds.pii_audit_retention_days` / `pii_audit_retention_authority` hardcoded a 90-day / FISMA AU-11 default regardless of `CAGE_DEPLOYMENT_REGION` — remediated via `_resolve_pii_retention()` in `src/gateway/governance/schemas/thresholds.py`, which resolves the citation from `constants.PII_RETENTION_AUTHORITY` (`FISMA AU-11` for US_FED, `GDPR Art. 5(1)(e)` for EU_ECB, `MAS Notice 655 §4.3` for APAC_MAS, ISO 42001 §A.9.2 fallback) at call time; an explicit value in `governance_thresholds.json` still overrides the region-derived default; FINDING-07 in `docs/compliance/cross-region/JURISDICTIONAL_SEPARATION_ANALYSIS.md` closed; covered by `tests/test_governance_thresholds_pii_retention.py` | 2026-07-31 |
| POAM-2026-035 | R-2, R-3, R-4 | `pii_audit_log()` in `src/gateway/governance/pii_sanitizer.py` cited `FISMA AU-11` as the universal PII retention authority with no `CAGE_DEPLOYMENT_REGION` guard — remediated by adding an optional `region` parameter and sourcing the citation from `constants.PII_RETENTION_AUTHORITY`; the returned audit record now carries a jurisdiction-correct `retention_authority` field; FINDING-08 closed; covered by `tests/test_pii_audit_log.py::TestPiiAuditLogJurisdictionalRetentionAuthority` | 2026-07-31 |
| POAM-2026-036 | R-2 | `src/gateway/governance/hitl_escalator.py` and `src/gateway/governance/prompt_injection_detector.py` declared `Region: US_FED` in their module docstrings only, with no runtime region check backing the claim (the SR 26-2 §3.2 4-hour HITL SLA has no legal force outside US_FED) — remediated by adding `get_hitl_sla_hours(region)`, `get_hitl_regulatory_citation(region)`, and `hitl_override_audit_span()` to `hitl_escalator.py` (backed by new `HITL_SLA_HOURS` / `HITL_CITATIONS` tables in `constants.py`), and `get_injection_citation(region)` to `prompt_injection_detector.py` (backed by `constants.INJECTION_CITATION`); FINDING-09 closed; covered by `tests/test_hitl_escalator.py` and `tests/test_prompt_injection_detector.py::TestGetInjectionCitation` | 2026-07-31 |
| POAM-2026-038 | SC-4 / SI-2 | ✅ **CLOSED 2026-08-16.** `reconciliation-worker` CronJob now operational. GCS bucket created (`cage-reconciliation-laah-cybernetics`), KMS key created (`governance/balance-signer`), IAM bindings applied, secrets populated, code bug fixed (`GcsLedgerProvider` field mismatch). Redis now contains verified balance: `{"balance_usd":1000000.0,"source":"gcs","verified_at":1786850100.0}` with 300s TTL. Peer review fix applied: added atomic epoch-check validation to `GcsLedgerProvider`. | 2026-08-16 |
| POAM-2026-039 | SC-4 / SI-2 | `routing_seal.py` `generate_seal()` did not sanitize dots in `action_slug` — an action name containing a literal `.` (e.g. `execute.trade`) would shift `seal.split(".", 2)` in `verify_seal()`, causing valid seals to fail verification with a parse error rather than a proper `SymbolicGovernorViolation`. Remediated by adding `.replace(".", "-")` to the slug normalization step (commit 2026-08-06). Covered by existing routing seal unit tests. | 2026-08-06 |
| POAM-2026-040 | CA-7 / SI-2 | `causal_gatekeeper.py` invoked `backdoor.linear_regression` with no minimum-sample guard — on cold-start or sparse-telemetry conditions (< 50 observations), the regression produced a meaningless estimate that could incorrectly approve or reject trades. Remediated by adding `_MIN_CAUSAL_SAMPLES = int(os.getenv("CAUSAL_MIN_SAMPLES", "50"))` guard that fails closed with `CTRL_TEL_003` when insufficient telemetry is available (commit 2026-08-06). | 2026-08-06 |
| POAM-2026-041 | AU-12 / SI-2 | `context_accumulator.py` `_content_hash()` used `json.dumps(..., sort_keys=True)` without `separators=(",", ":")`, while `_link_hash()` used `separators=(",", ":")`. Cross-platform whitespace differences (CPython vs PyPy, Windows vs Linux) could produce different serializations for the same payload, breaking hash-chain verification. Remediated by adding `separators=(",", ":")` to `_content_hash()` (commit 2026-08-06). | 2026-08-06 |
| POAM-2026-042 | AU-12 / SA-11 | `reconciliation_worker.py` registered providers `stub`, `anchorage`, and `plaid` but `deployment/k8s/gateway.yaml` sets `RECONCILIATION_PROVIDER=gcs` — the registry raised `ValueError: Unknown reconciliation provider 'gcs'` on every worker startup, making the reconciliation loop dead code. Remediated by adding `GcsLedgerProvider` class and registering `"gcs"` in the provider dict (commit 2026-08-06). The reconciliation-worker `CronJob` manifest was also added to `deployment/k8s/reconciliation-worker.yaml`. | 2026-08-06 |
| POAM-2026-043 | SC-4 / IA-5 | `routing_seal.py` and `tools/api.py` lacked atomic single-use nonce consumption — a valid routing seal could be replayed within the 30-second TTL window before expiration (`CAGE-SEC-008`). Remediated by implementing `verify_and_consume_seal()` with atomic Redis `SETNX EX` key burning, enforcing fail-closed replay rejection (commit `88fa9d7`). Covered by `tests/test_routing_seal_security.py`. | 2026-08-11 |
| POAM-2026-044 | AU-12 / SA-11 | Denial and refusal paths in `symbolic_governor.py` raised string `GovernanceError` without structured audit-grade cryptographic proofs (`CAGE-SEC-009`). Remediated by introducing immutable `RefusalReceipt` dataclass with SHA-256 canonical hashing across `thread_id`, `action`, `violated_tier`, and `violated_rule` (commit `88fa9d7`). | 2026-08-11 |
| POAM-2026-045 | A.8.4 / ISO 42001 | `governed_financial_advisor` had disconnected the 4-state `DeferQueue` primitive, bypassing the CSA AARM ambiguity/deferral state (`CAGE-REM-004`). Remediated by implementing `defer_node` and routing $[0.70, 0.95)$ confidence bands to `DeferQueue` in Redis `db=1` (commit `88fa9d7`). Covered by `tests/test_hitl_toctou_revalidation.py`. | 2026-08-11 |
| POAM-2026-046 | SA-9 / External | Provider 03 integration boundary was unspecified at the code level (`CAGE-REM-006`). Remediated by implementing `Provider03NormativeProvider` adapter in `src/integrations/provider_03/` satisfying the 3-endpoint `NormativeProvider` contract and bind receipt ingestion (commit `88fa9d7`). Covered by `tests/test_provider_03_integration.py`. | 2026-08-11 |
| POAM-2026-030-B | SC-7 / AC-4 | `CAGE_FTRA_BOUNDARY_ENABLED` feature flag removed — FTRA boundary check is now **mandatory** and unconditional in `SymbolicGovernor._run_checks()` (line 970–999 of `src/gateway/governance/symbolic_governor.py`). Risk R-03 (Trust Boundary Bypass) is now fully mitigated at the controller level; direct HTTP access to `/validate-action` or ext_authz can no longer bypass FTRA classification. The in-graph `ftra_node` remains active as a first-pass gate. See [`docs/operations/FTRA_COMPENSATING_CONTROLS.md`](operations/FTRA_COMPENSATING_CONTROLS.md) for NetworkPolicy defense-in-depth documentation (still in place for R-02 mitigation). | 2026-08-16 |
| POAM-2026-050 | AC-3 / SI-7 | `NARROW` governance decision primitive added for partial-authority execution with clamped scope — enables constrained action approval when full approval is not warranted but outright denial would be overly restrictive. Implemented in `src/gateway/governance/decisions.py` and integrated into `src/gateway/governance/symbolic_governor.py`. Feature flag: `CAGE_NARROW_ENABLED` (default `false`). | 2026-08-16 |
| POAM-2026-051 | AC-3 / SI-7 | `PAUSE` governance decision primitive added for resumable execution suspension with cryptographic token-based resume — enables temporal suspension of action execution pending external conditions or time-based release. Implemented in `src/gateway/governance/pause_primitive.py` and integrated into `src/gateway/server/hybrid_server.py`. Feature flag: `CAGE_PAUSE_ENABLED` (default `false`). Endpoints: `POST /v1/pause/{token}/resume`, `GET /v1/pause/{token}`. | 2026-08-16 |
| POAM-2026-052 | AU-12 | `DEFER` tokens now persisted via `DeferQueue` for client polling — replaces bare UUID generation with persistent queue-backed deferral state. `SymbolicGovernor._park_defer_context()` now atomically enqueues defer tokens to Redis `db=1` with full audit trail. | 2026-08-16 |
| POAM-2026-053 | SC-4 / SI-2 | Monotonic fence epoch counter added for Redis failover safety — prevents stale replica reads during primary/replica failover by incrementing epoch on each write and validating epoch freshness on reads. Implemented in `src/gateway/governance/cbf.py`. Feature flag: `CAGE_REDIS_SYNCHRONOUS_REPLICATION` (default `true`). | 2026-08-16 |
| POAM-2026-054 | SC-8 / SI-7 | Monotonic sequence numbers embedded in KMS-signed balance payloads for reconciliation replay defense — prevents replay attacks where stale signed balances could be re-submitted. Implemented in `src/gateway/governance/cbf.py` and `src/compliance_bridge/reconciliation_worker.py`. Feature flag: `CAGE_RECONCILIATION_REPLAY_DEFENSE` (default `false`). | 2026-08-16 |
| POAM-2026-055 | AU-12 | `EVIDENCE_CHAIN_BLOCKING` default changed from `false` to `true` — evidence stream now synchronously blocks until evidence records are durably persisted to Langfuse backend, providing stronger audit durability guarantees at the cost of slightly increased latency. Implemented in `src/compliance_bridge/evidence_stream.py`. | 2026-08-16 |
| POAM-2026-056 | SI-7 / SC-4 | Two-phase pipeline reordering in `SymbolicGovernor._run_checks()` — decouples read-only validation gates (Phase 1: STPA, Confidence, OPA, Consensus, Causal, FRIA) from state-mutating gates (Phase 2: CBF Lua atomic check+commit, FiscalLimitGuard), eliminating downstream budget leakage and saga-atomicity gaps. | 2026-08-18 |
| POAM-2026-057 | SI-7 / CA-7 | Causal Gatekeeper fail-closed on non-positive slope ($\beta \le 0$) and bounded marginal risk scoring $\min(1.0, \max(0.0, 0.5 + \beta \times \text{amount})) \in [0.0, 1.0]$. | 2026-08-18 |
| POAM-2026-058 | SC-4 / SI-2 | FiscalLimitGuard rollback and release window-key verification — ensures counter rollbacks do not execute against expired daily keys, preventing negative counter underflow across TTL boundaries. | 2026-08-18 |
| POAM-2026-059 | SI-7 / SA-11 | Formal verification proof model extended to 57 sequential / 66 concurrent reachable states with single-use, TTL, and downstream actuator choke-point verification in Gap 2 negative controls (`proof/model.py`). | 2026-08-18 |

---

## Lula Validation Coverage

CAGE uses [Lula](https://github.com/defenseunicorns/lula) for compliance-as-code validation. The following manifests are maintained in `compliance/lula/`:

| Manifest | Framework | Control | Region |
|----------|-----------|---------|--------|
| `lula-validation-a52.yaml` | ISO 42001 | A.5.2 Social Impact Assessment | Universal |
| `lula-validation-a53.yaml` | ISO 42001 | A.5.3 Logging and Monitoring | Universal |
| `lula-validation-a92.yaml` | ISO 42001 | A.9.2 Data Transfer to Suppliers | Universal |
| `lula-validation-aarm-vectors.yaml` | CSA AARM | All 11 threat vectors | Universal |
| `lula-validation-iso001-token-quota.yaml` | ISO 42001 | A.4 Token Quota OPA Injection | Universal |
| `lula-validation-tqp007.yaml` | ISO 42001 | A.8.4 TokenQuotaProxy fail-closed | Universal |
| `lula-validation-ac2.yaml` | NIST SP 800-53 | AC-2 Account Management | US_FED |
| `lula-validation-ac3.yaml` | NIST SP 800-53 | AC-3 Access Enforcement | US_FED |
| `lula-validation-au12.yaml` | NIST SP 800-53 | AU-12 Audit Record Generation | US_FED |
| `lula-validation-cm6.yaml` | NIST SP 800-53 | CM-6 Configuration Settings | US_FED |
| `lula-validation-ia3.yaml` | NIST SP 800-53 | IA-3 Device Identification | US_FED |
| `lula-validation-ia5.yaml` | NIST SP 800-53 | IA-5 Authenticator Management | US_FED |
| `lula-validation-ir6.yaml` | NIST SP 800-53 | IR-6 Incident Reporting | US_FED |
| `lula-validation-ra5.yaml` | NIST SP 800-53 | RA-5 Vulnerability Scanning | US_FED |
| `lula-validation-sc4.yaml` | NIST SP 800-53 | SC-4 Fiscal Limits / RBAC | US_FED |
| `lula-validation-sc8.yaml` | NIST SP 800-53 | SC-8 Transmission Confidentiality | US_FED |
| `lula-validation-si2.yaml` | NIST SP 800-53 | SI-2 Flaw Remediation | US_FED |
| `lula-validation-ai600-cbrn.yaml` | NIST AI 600-1 | §2.6 CBRN / Harmful Content | US_FED |
| `lula-validation-ai600-confabulation.yaml` | NIST AI 600-1 | §2.1 Confabulation | US_FED |
| `lula-validation-ai600-data-privacy.yaml` | NIST AI 600-1 | §2.2 Data Privacy | US_FED |
| `lula-validation-ai600-human-ai-config.yaml` | NIST AI 600-1 | §2.5 Human-AI Configuration | US_FED |
| `lula-validation-ai600-prompt-injection.yaml` | NIST AI 600-1 | §2.3 Prompt Injection | US_FED |
| `lula-validation-dora-art10.yaml` | DORA | Art. 10 ICT Resilience | EU_ECB |
| `lula-validation-eu-ai-act-art9.yaml` | EU AI Act | Art. 9 Risk Management | EU_ECB |
| `lula-validation-eu-fria.yaml` | EU AI Act | Art. 29a FRIA Gating | EU_ECB |
| `lula-validation-gdpr-art22.yaml` | GDPR | Art. 22 Automated Decisions | EU_ECB |
| `lula-validation-mas-feat.yaml` | MAS FEAT | Fairness/Ethics/Accountability/Transparency | APAC_MAS |
| `lula-validation-mas-notice655.yaml` | MAS Notice 655 | Technology Risk Management | APAC_MAS |
| `lula-validation-mas-trm-s6.yaml` | MAS TRM | §6.3 AI/ML Controls | APAC_MAS |

---

## Contributing to Remediation

Contributors who wish to help close open findings should:

1. Reference the POAM ID in the commit message (e.g., `fix(compliance): add vulnerability scan CronJob [POAM-2026-010]`)
2. Run `lula validate` against the relevant manifest on a live cluster
3. Update this document with the closure date and commit SHA
4. Update the corresponding OSCAL component in `compliance/oscal/` within 2 business days of merge

See [CONTRIBUTING.md](../CONTRIBUTING.md) and the compliance validation guide in `compliance/lula/` for details.
