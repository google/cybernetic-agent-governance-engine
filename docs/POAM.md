# Security Posture Statement — Plan of Action and Milestones (POAM)

**System:** Cybernetic AI Governance Engine (CAGE)
**Document:** Public Security Posture Statement
**Frameworks:** NIST SP 800-53 Rev. 5, NIST AI 600-1, ISO 42001, EU AI Act, DORA, GDPR, MAS FEAT, MAS TRM, MAS Notice 655
**Last Updated:** 2026-08-28

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
| POAM-2026-011 | SC-8 | TLS 1.0/1.1 deprecation remediated via `src/gateway/infrastructure/tls_context.py::create_hardened_client_context()` enforcing TLS 1.2+ minimum version with `ssl.TLSVersion.TLSv1_2` and disabling legacy protocols (OP_NO_TLSv1/TLSv1_1). Test suite validation via `tests/test_tls_enforcement.py::TestTlsProtocolStandards` confirms NIST SP 800-52 Rev. 2 compliance. Remediation commit: `c8d66189a94cb782f4e0f61e14e05e341d27a8f6`. | 2026-08-27 |
| POAM-2026-012 | SC-12 / IA-5 | Cryptographic key rotation schedule and lifecycle management documented in [`docs/operations/KEY_ROTATION.md`](operations/KEY_ROTATION.md) covering Cloud KMS HSM keys (90-day), HMAC routing seal secrets (30-day), and emergency revocation | 2026-08-22 |
| POAM-2026-013 | SI-2 | Third-party container images (`openpolicyagent/opa:0.68.0-static`, `redis/redis-stack-server:7.4.0-v1`, `aquasec/trivy:0.51.4`, `anchore/syft:v1.10.0`) pinned to deterministic versions across `deployment/k8s/` manifests | 2026-08-22 |
| POAM-2026-027 | Structural | POAM tracking document absent from repository — remediated by creating this document | 2026-06-30 |
| POAM-2026-028 | RA-5 / SI-2 | `langchain` GHSA-gr75-jv2w-4656 and related transitive CVEs — remediated by upgrading to `langchain==1.3.11`, `langsmith==0.9.5`, `python-multipart==0.0.32` | 2026-07-02 |
| POAM-2026-037 | RA-5 / SI-2 | Base images across all Dockerfiles (`Dockerfile`, `src/compliance_bridge/Dockerfile`, `src/gateway/Dockerfile`) standardized to `python:3.12-slim-bookworm` with build-time `apt-get upgrade -y --no-install-recommends` and `.trivyignore` tracking | 2026-08-22 |
| POAM-2026-029 | CA-7 | `src/compliance_bridge/sla_monitor.py` imported the deprecated flat `EVIDENCE_SLA_SECONDS` alias instead of the region-aware `get_sla_seconds(region)` accessor in `types.py` — remediated via a new `_active_sla_seconds()` helper that resolves `CAGE_DEPLOYMENT_REGION` fresh on every poll cycle; jurisdictional SLA controls (SC-7/SC-8 for US_FED, Article 12 for EU_ECB, MAS-FEAT-1 for APAC_MAS) are now monitored in their applicable region; FINDING-05 in `docs/compliance/cross-region/JURISDICTIONAL_SEPARATION_ANALYSIS.md` closed; covered by 6 new tests in `tests/test_compliance_bridge_tier2.py::TestSlaMonitor` | 2026-07-30 |
| POAM-2026-030 | SA-11 | `src/gateway/governance/ftra/` (the production FTRA Pre-Pipeline Boundary Gate) had zero test coverage — remediated by adding `tests/test_ftra_package.py` (30 tests covering `IrreversibilityClassifier`, `PlanGraphAnalyzer`, `create_ftra_node()`, `route_after_ftra()`); this exposed two previously-undetected production defects, both fixed in the same change and now regression-tested (see POAM-2026-033) | 2026-07-30 |
| POAM-2026-023 | SC-4 / SI-2 | **External Reconciliation Not Enforced on Atomic Commit Path** — discovered 2026-08-28 by Miracle Owolabi (external security researcher, OWASP AI Exchange Author). `LUA_ATOMIC_CBF` read `safety:current_cash` directly instead of KMS-signed reconciled balance from `reconciliation:verified_balance`. This bypassed five separate controls: (1) KMS signature verification (POAM-2026-031, POAM-2026-038), (2) `_CBF_STRICT_MODE` fail-closed behavior, (3) R-04 replay sequence defense (POAM-2026-054), (4) TTL staleness rejection, (5) R-05 fence-epoch validation. Atomic commit enforcement used self-reported balance without verification. Reconciliation subsystem could validate external balance without influencing trade authorization. **Additional Findings:** Fence-epoch regression detection (R-05) was implemented but never executed on commit path. Local debit tracking gap allowed double-spend within reconciliation window. Remediated by creating `_resolve_ground_truth_balance()` seam for KMS-verified balance resolution, modifying `LUA_ATOMIC_CBF` to accept ground truth balance as ARGV[5], adding fence-epoch regression detection on commit path, adding local debit tracking to prevent double-spend within reconciliation window. Remediation commit: `fix(cbf)!: enforce POAM-023 reconciliation on atomic commit path`. Test coverage: 5 new test cases in `tests/test_cbf_reconciliation.py`. **Related POAMs Closed:** POAM-2026-031, POAM-2026-038, POAM-2026-054 (all enforced via reconciliation path). **Dependency:** This fix assumes accurate balance values from the reconciliation worker. PR #93 (zero balance masking fix) must be deployed first to ensure `GcsLedgerProvider` and `ObjectStoreLedgerProvider` return accurate 0.0 balances for drained accounts rather than fallback values. | 2026-08-28 |
| POAM-2026-031 | CBF / SI-2 | External CBF state reconciliation not implemented — remediated by `src/compliance_bridge/reconciliation_worker.py` (v2.1.0); reconciled balances are KMS-signed before Redis write; CBF fails closed on TTL expiry. **CLOSED via POAM-2026-023 remediation** (2026-08-28) — KMS signature verification now enforced on atomic commit path. | 2026-07-27 |
| POAM-2026-032 | SA-11 | `src/gateway/governance/ftra_reachability.py` was an unwired `FtraReachabilityGate` scaffold committed alongside the production `src/gateway/governance/ftra/` package in the same commit but never imported by `SymbolicGovernor` or any production code path; its dedicated test file (`tests/test_ftra_reachability.py`) exercised only this dead code, giving a false impression of FTRA test coverage — remediated by deleting both files; documentation across 5 files corrected to describe the actual `ftra/` implementation (`PlanGraphAnalyzer`, `IrreversibilityClassifier`, `create_ftra_node`) instead of the removed scaffold | 2026-07-30 |
| POAM-2026-033 | CA-7 / SI-2 | Two defects in `src/gateway/governance/ftra/node_factory.py` uncovered while closing POAM-2026-030's test-coverage gap: **(1)** `_park_in_defer_queue()` instantiated `DeferQueue()` with zero arguments, but `DeferQueue.__init__` requires a `redis_client` — this always raised `TypeError`, silently caught by a broad `except Exception`, so every HITL_REQUIRED verdict's DeferToken was never actually persisted to Redis db=1, making it unreachable via the external HITL resolution API (`POST /v1/defer/{id}/escalate`); **(2)** `ftra_node()`'s outer exception handler caught `NodeInterrupt` (a subclass of `Exception` in LangGraph) unconditionally, converting every HITL_REQUIRED verdict into a fail-closed `BLOCKED` response before the thread could ever suspend for human review — remediated by **(1)** connecting via `redis.asyncio.from_url(REDIS_URL, db=1)` then `DeferQueue(client)`, mirroring the working pattern in `src/compliance_bridge/main.py`, and **(2)** re-raising `GraphInterrupt`/`NodeInterrupt` before the generic exception handler runs; both fixes covered by dedicated regression tests in `tests/test_ftra_package.py::TestCreateFtraNode` | 2026-07-30 |
| POAM-2026-034 | R-2, R-6 | `GovernanceThresholds.pii_audit_retention_days` / `pii_audit_retention_authority` hardcoded a 90-day / FISMA AU-11 default regardless of `CAGE_DEPLOYMENT_REGION` — remediated via `_resolve_pii_retention()` in `src/gateway/governance/schemas/thresholds.py`, which resolves the citation from `constants.PII_RETENTION_AUTHORITY` (`FISMA AU-11` for US_FED, `GDPR Art. 5(1)(e)` for EU_ECB, `MAS Notice 655 §4.3` for APAC_MAS, ISO 42001 §A.9.2 fallback) at call time; an explicit value in `governance_thresholds.json` still overrides the region-derived default; FINDING-07 in `docs/compliance/cross-region/JURISDICTIONAL_SEPARATION_ANALYSIS.md` closed; covered by `tests/test_governance_thresholds_pii_retention.py` | 2026-07-31 |
| POAM-2026-035 | R-2, R-3, R-4 | `pii_audit_log()` in `src/gateway/governance/pii_sanitizer.py` cited `FISMA AU-11` as the universal PII retention authority with no `CAGE_DEPLOYMENT_REGION` guard — remediated by adding an optional `region` parameter and sourcing the citation from `constants.PII_RETENTION_AUTHORITY`; the returned audit record now carries a jurisdiction-correct `retention_authority` field; FINDING-08 closed; covered by `tests/test_pii_audit_log.py::TestPiiAuditLogJurisdictionalRetentionAuthority` | 2026-07-31 |
| POAM-2026-036 | R-2 | `src/gateway/governance/hitl_escalator.py` and `src/gateway/governance/prompt_injection_detector.py` declared `Region: US_FED` in their module docstrings only, with no runtime region check backing the claim (the SR 26-2 §3.2 4-hour HITL SLA has no legal force outside US_FED) — remediated by adding `get_hitl_sla_hours(region)`, `get_hitl_regulatory_citation(region)`, and `hitl_override_audit_span()` to `hitl_escalator.py` (backed by new `HITL_SLA_HOURS` / `HITL_CITATIONS` tables in `constants.py`), and `get_injection_citation(region)` to `prompt_injection_detector.py` (backed by `constants.INJECTION_CITATION`); FINDING-09 closed; covered by `tests/test_hitl_escalator.py` and `tests/test_prompt_injection_detector.py::TestGetInjectionCitation` | 2026-07-31 |
| POAM-2026-038 | SC-4 / SI-2 | ✅ **CLOSED 2026-08-16.** `reconciliation-worker` CronJob now operational. GCS bucket created (`cage-reconciliation-laah-cybernetics`), KMS key created (`governance/balance-signer`), IAM bindings applied, secrets populated, code bug fixed (`GcsLedgerProvider` field mismatch). Redis now contains verified balance: `{"balance_usd":1000000.0,"source":"gcs","verified_at":1786850100.0}` with 300s TTL. Peer review fix applied: added atomic epoch-check validation to `GcsLedgerProvider`. **CLOSED via POAM-2026-023 remediation** (2026-08-28) — external balance verification now enforced on atomic commit path. | 2026-08-16 |
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
| POAM-2026-054 | SC-8 / SI-7 | Monotonic sequence numbers embedded in KMS-signed balance payloads for reconciliation replay defense — prevents replay attacks where stale signed balances could be re-submitted. Implemented in `src/gateway/governance/cbf.py` and `src/compliance_bridge/reconciliation_worker.py`. Feature flag: `CAGE_RECONCILIATION_REPLAY_DEFENSE` (default `false`). **CLOSED via POAM-2026-023 remediation** (2026-08-28) — R-04 replay sequence defense now enforced on atomic commit path. | 2026-08-16 |
| POAM-2026-055 | AU-12 | `EVIDENCE_CHAIN_BLOCKING` default changed from `false` to `true` — evidence stream now synchronously blocks until evidence records are durably persisted to Langfuse backend, providing stronger audit durability guarantees at the cost of slightly increased latency. Implemented in `src/compliance_bridge/evidence_stream.py`. | 2026-08-16 |
| POAM-2026-056 | SI-7 / SC-4 | Two-phase pipeline reordering in `SymbolicGovernor._run_checks()` — decouples read-only validation gates (Phase 1: STPA, Confidence, OPA, Consensus, Causal, FRIA) from state-mutating gates (Phase 2: CBF Lua atomic check+commit, FiscalLimitGuard), eliminating downstream budget leakage and saga-atomicity gaps. | 2026-08-18 |
| POAM-2026-057 | SI-7 / CA-7 | Causal Gatekeeper fail-closed on non-positive slope ($\beta \le 0$) and bounded marginal risk scoring $\min(1.0, \max(0.0, 0.5 + \beta \times \text{amount})) \in [0.0, 1.0]$. | 2026-08-18 |
| POAM-2026-058 | SC-4 / SI-2 | FiscalLimitGuard rollback and release window-key verification — ensures counter rollbacks do not execute against expired daily keys, preventing negative counter underflow across TTL boundaries. | 2026-08-18 |
| POAM-2026-059 | SI-7 / SA-11 | Formal verification proof model extended to 57 sequential / 66 concurrent reachable states with single-use, TTL, and downstream actuator choke-point verification in Gap 2 negative controls (`proof/model.py`). | 2026-08-18 |
| POAM-2026-061 | SC-13 / IA-5 | Ed25519 signature verification defect in `src/gateway/governance/kms_signer.py` — `_kms_verify()` rejected all Ed25519 signatures due to incorrect `hashlib.new("raw", ...)` call (no such algorithm) and wrong isinstance branch. Remediated by fixing Ed25519 detection logic and removing the invalid hashlib call. Covered by `tests/test_kms_signer_new_features.py` regression tests. FlowSignal Phase 2 ST-1. Remediation commit: pending (working tree uncommitted). | 2026-08-27 |
| POAM-2026-060 | SC-13 / SI-7 | ✅ **CLOSED — RFC 8785 JCS migration complete.** Every executable `json.dumps(..., sort_keys=True)` canonicalization site in `src/` now uses `jcs_canonicalize_plan()`; zero remain (excluding the vendored RFC 8785 reference implementation under `src/gateway/governance/vendor/jcs/` and docstring references). Migrated surfaces: the `ContextAccumulator` and `EvidenceStreamSink` hash chains (write and verify paths migrated atomically, with `_SCHEMA` sentinels bumped to `cage-context-accumulator/2.0` and `cage-evidence-stream/2.0` so the break is self-identifying), the WORM/KMS-signed UCA record signing path in `src/gateway/governance/uca_logger.py`, the JWS header/payload in `consequence_token.py` (60 s TTL), routing seals in `routing_seal.py` (30 s TTL), OPA and query cache keys, the reconciliation signed balance (300 s TTL), the control-registry profile hash, and provider receipt/state digests. Sites previously relying on `default=str` received explicit `datetime`/`Decimal` pre-normalization (`_normalize_for_jcs()` in the compliance-bridge modules) because `jcs_canonicalize_plan()` has no `default=` escape hatch. **Record correction — the original finding was factually wrong on three counts:** (1) it stated "10 identified sites" when the real figure was ~25 executable call sites across 32 `sort_keys=True` occurrences; (2) it claimed the hashes "are compared against persisted data", which was true only for the WORM UCA record — all other chains are self-verifying, recomputing digests with the same function used at write time, with no independently-stored ground truth; (3) it recorded a backward-compatibility blocker that did not exist — no adopter deployment's chains could be invalidated, and the repository had already shipped an equivalent canonicalization break for `normative_provider.py`. The WORM/KMS path was migrated with **no compatibility shim** following the deactivation of the data-at-rest exception in [`AGENTS.md`](../AGENTS.md) (relocated to *Dormant Rules — Reactivate When CAGE Begins Real Deployments*); pre-change WORM records will not verify under the new algorithm. Breaking changes documented in [`docs/BREAKING_CHANGES_v3.md`](BREAKING_CHANGES_v3.md). Lula result: no manifest change required (all Lula manifests assert over Kubernetes resources; verified — see *Lula Verification* below); `lula-validation-au12.yaml` narrative text corrected for the removed dual-schema apparatus. Remediation commit: `<pending-squash-merge-sha>`. | 2026-08-27 |

| POAM-2026-062 | AU-12 | Evidence-stream v1.0/v1.1 dual-schema machinery (surfaced by code inspection as **BC-01**, not previously tracked in this POAM). `src/compliance_bridge/evidence_stream.py` retained a full dual-schema apparatus — `_detect_schema_version()`, `migrate_record_1_0_to_1_1()`, `get_last_v1_0_hash()`, `_link_hash_v1_1()`, and the `schema_version` field on `EvidenceRecord` — despite v1.0 write support already being removed and `verify_record()` already hard-rejecting v1.0 records. A repo-wide search found zero production callers outside the module itself; the sole external consumer was a test suite existing only to exercise the dead compatibility path. Remediated by deleting the four functions and the `schema_version` field, collapsing `_link_hash_v1_1()` into a single unconditional `_link_hash()`, and deleting `tests/test_dual_schema_verification.py`; still-relevant hash-determinism assertions were folded into `tests/test_evidence_stream.py`. Schema sentinel bumped to `cage-evidence-stream/2.0`. Lula result: no manifest change required; the stale dual-schema narrative in `compliance/lula/lula-validation-au12.yaml` was corrected. Remediation commit: `<pending-squash-merge-sha>`. | 2026-08-27 |
| POAM-2026-063 | SA-9 | Provider 03 backward-compatibility alias methods (**BC-02**, previously untracked). `Provider03NormativeProvider` exposed three dict-returning shadow methods — `fetch_legal_baseline()`, `validate_external_fria()`, `submit_evidence_chain()` — alongside the canonical dataclass-returning `NormativeProvider` protocol. **Security-relevant:** `validate_external_fria()` returned a hardcoded `APPROVED` verdict unconditionally, so any caller reaching it would have silently bypassed governance. None of the three were part of the canonical protocol and the only callers were integration tests. Remediated by deleting all three aliases and rewriting the integration tests against the canonical three-endpoint contract required by the Universal Protocol Conformance Suite. Remediation commit: `<pending-squash-merge-sha>`. | 2026-08-27 |
| POAM-2026-064 | SA-9 / CA-7 | Provider 01 legacy binary `admitted`/`findings` response fallback (**BC-03**, previously untracked). **Security-relevant — closes a latent fail-open.** `src/integrations/provider_01/provider.py` accepted two wire formats and fell back to a legacy binary shape when the FlowSignal tri-state `decision` field was absent. A response that lost its `decision` key — for example a proxy error page that happens to parse as JSON carrying `admitted: true` — was admitted without ever passing through `_map_flowsignal_decision()` or ConsequenceToken minting. Two tests in the Universal Protocol Conformance Suite were actively locking this fail-open behavior in. Remediated by deleting the legacy branch: a missing or unrecognized `decision` now fails closed with `ValidationResult(admitted=False)` and a structured finding carrying `code="cage.endpoint_error"`, matching the fail-closed vendor-adapter semantics mandated by [`AGENTS.md`](../AGENTS.md). The two conformance tests were **inverted**, not deleted, so the fail-closed contract is now the asserted one. Remediation commit: `<pending-squash-merge-sha>`. | 2026-08-27 |
| POAM-2026-065 | AU-12 / AU-10 | Provenance-chain legacy decision vocabulary (**BC-04**, previously untracked). `VALID_DECISIONS` in `src/gateway/governance/provenance_chain.py` admitted eight values — the six canonical `GovernanceDecision` members plus the execution-phase statuses `BLOCK` and `ESCALATE` — weakening the provenance record's audit semantics by making `BLOCK` and `DENY` indistinguishable to a downstream auditor. Remediated by remapping emitters (`BLOCK → DENY`, `ESCALATE → REQUIRE_APPROVAL`) and narrowing `VALID_DECISIONS` to the canonical six: `ALLOW`, `DENY`, `DEFER`, `NARROW`, `PAUSE`, `REQUIRE_APPROVAL`. `build_provenance_record()` now raises `ValueError` for `BLOCK`/`ESCALATE`. Covered by `tests/test_provenance_chain.py`. Remediation commit: `<pending-squash-merge-sha>`. | 2026-08-27 |
| POAM-2026-066 | AU-12 | Duplicated legacy DEFER response fields (**BC-05**, previously untracked). Three sites emitted three names for the same value in an audit-relevant response body: `verdict` and `missing_input_reason` in `src/gateway/governance/decisions.py` and `src/gateway/server/agent_gateway_adapter.py`, and `defer_id` in `src/gateway/governance/symbolic_governor.py`. Beyond the redundancy this created a divergence risk if one site were updated and the others not. Remediated by deleting all three legacy keys from the response bodies and the `DeferResponse` model; the canonical fields are now `decision`, `defer_token`, and `classification_reason`. Assertions updated in `tests/test_defer_queue.py` and `tests/test_governance_middleware.py`. Remediation commit: `<pending-squash-merge-sha>`. | 2026-08-27 |
| POAM-2026-067 | SC-4 | Fiscal limit guard legacy window-key fallback (**BC-07**, previously untracked). **Security-relevant — defeated an existing control.** When `rollback()` in `src/gateway/governance/fiscal_limit_guard.py` was called with neither `window_key` nor `token`, a legacy fallback silently computed the *current* window rather than the window the reservation was made against. This guaranteed `target == current`, so the cross-window guard sitting immediately below it could never fire on that path — nullifying the very control **POAM-2026-058** was closed to add. Remediated by making `window_key` or `token` mandatory: `rollback()` now raises `ValueError` when neither is supplied, mirroring the existing `amount`/`amount_minor` guard, and all callers were updated to pass the `ReservationToken`. Remediation commit: `<pending-squash-merge-sha>`. | 2026-08-27 |
| POAM-2026-068 | CM-6 | `ControlRegistry` legacy control-mappings fallback (**BC-08**, previously untracked). **Security-relevant — reintroduced a closed defect.** `src/gateway/governance/constants.py` fell back to `_LEGACY_PATH` (`config/control_mappings.json`) with `region="LEGACY"` whenever the regional compliance profile was missing. A region-guarded system that silently degrades to a non-regional profile emits audit spans bearing jurisdictionally wrong citations — precisely the class of defect that **POAM-2026-034**, **POAM-2026-035** and **POAM-2026-036** were opened and closed to eliminate; the fallback reintroduced it through the back door. Remediated by deleting `_LEGACY_PATH` and the fallback branch; a missing regional profile now raises `RuntimeError` at startup ("Cannot start governance engine without a valid profile"). Adopter deployments must provision `config/compliance/{US_FED,EU_ECB,APAC_MAS}_BASELINE.json` — see [`docs/BREAKING_CHANGES_v3.md`](BREAKING_CHANGES_v3.md). Verified across all three region-gated test postures. Remediation commit: `<pending-squash-merge-sha>`. | 2026-08-27 |
| POAM-2026-069 | SC-4 / SI-2 | **R-05 Fence-Epoch Validation Bypass** — discovered during POAM-2026-023 remediation (2026-08-28) by Miracle Owolabi (external security researcher, OWASP AI Exchange Author). Fence-epoch regression detection (R-05) was implemented in reconciliation subsystem but never executed on the atomic commit path. The commit path read balances without checking if the fence epoch had regressed (indicating a Redis primary/replica failover or clock skew), potentially accepting stale data from a failed-over replica. Remediated by adding fence-epoch validation in `_resolve_ground_truth_balance()` before CBF atomic commit. The fence check now fails closed with `REPLICATION_UNCONFIRMED` when epoch regression is detected. Covered by test cases in `tests/test_cbf_reconciliation.py`. Closed as part of POAM-2026-023 remediation. | 2026-08-28 |
| POAM-2026-070 | SC-4 / SI-2 | **Local Debit Tracking Gap** — discovered during POAM-2026-023 remediation (2026-08-28) by Miracle Owolabi (external security researcher, OWASP AI Exchange Author). No local debit tracking existed to prevent double-spend within the reconciliation window (300s TTL). An attacker could submit multiple concurrent trade requests that individually pass CBF balance checks but collectively exceed available funds, exploiting the gap between local Redis state and external ledger synchronization. Remediated by adding `_register_pending_debit()` in `_resolve_ground_truth_balance()` to atomically decrement local pending balance before CBF evaluation, preventing double-spend races. Covered by test cases in `tests/test_cbf_reconciliation.py`. Closed as part of POAM-2026-023 remediation. | 2026-08-28 |
| CAGE-SEC-003 | ISO 42001 A.8.4 | **DeferQueue Phase-3 Confidence Recheck Bypass** — discovered 2026-08-28 by Miracle Owolabi (external security researcher, OWASP AI Exchange Author). `/v1/defer/{defer_id}/inject` endpoint called `queue.resolve()` directly without invoking `replay_evaluate()`, bypassing Phase-3 confidence recheck against `DEFER_CONFIDENCE_THRESHOLD` (0.70). Additionally published forged ISO 42001 A.8.4 attestations. Deferred tokens could be resolved without validating injected context raised confidence above threshold. Audit trail contained inaccurate compliance attestations. Remediated by wiring `replay_evaluate()` into `/v1/defer/{defer_id}/inject` endpoint, making `confidence_score` required field with NaN validator, returning 409 Conflict for sub-threshold injections, and splitting SSE events: `DEFER_PARKED` vs `DEFER_RESOLVED` for audit accuracy. Remediation commit: `fix(defer)!: enforce Phase-3 confidence recheck on token injection`. Test coverage: 6 new test cases in `tests/test_defer_queue.py`. | 2026-08-28 |
| CAGE-SEC-004 | AC-3 / SI-7 | **NARROW Verdict Transport Architectural Gap** — discovered 2026-08-28 by Miracle Owolabi (external security researcher, OWASP AI Exchange Author). NARROW verdicts computed narrowed params but Envoy `OkHttpResponse` proto has no body field. Unclamped requests forwarded to upstream. Currently fails-safe (seal mismatch) but feature incomplete. NARROW feature non-functional in ext_authz deployments. Requests executed with original (unclamped) parameters despite NARROW verdict. Remediated by implementing receipt-based transport using Redis fetch-and-burn pattern: receipt keyed by seal prefix (`narrow:receipt:{seal[:32]}`), MCP server fetches and burns receipt before execution, signature verification prevents receipt forgery, 5-minute TTL prevents receipt leakage. Remediation commit: `feat(narrow)!: implement receipt-based NARROW verdict transport`. Test coverage: 9 new test cases in `tests/test_narrow_transport.py`. | 2026-08-28 |

---

## Deliberate No-Change Decisions

The following compatibility surfaces were reviewed during the backward-compatibility
remediation and **deliberately left unchanged**. They are recorded here so a future
reviewer does not re-flag them as unremediated compatibility debt.

| ID | Surface | Decision | Rationale |
|----|---------|----------|-----------|
| BC-06 | Routing seal v2 HMAC-SHA256 signing mode in [`src/gateway/governance/routing_seal.py`](../src/gateway/governance/routing_seal.py) | **Retain — no change** | Despite the `v2`/`v3` naming this is **not** a version-negotiation shim for older clients. It is the KMS-free signing mode required for local development, CI, and the offline `local`/`unit` test markers that constitute the project's primary regression gate; removing it would make the entire governance path untestable without a live Cloud KMS key. It is already fail-closed in production — verification raises `SymbolicGovernorViolation` with a `[DOWNGRADE_ATTACK]` log whenever `CAGE_SEAL_STRICT_MODE=true` or the runtime is production. The seal's `_canonical_payload()` **was** migrated to RFC 8785 JCS under POAM-2026-060 (seals are 30 s TTL and single-use, so this is not an at-rest concern); only the HMAC signing mode itself is retained. |

---

## Lula Verification

**Finding: no Lula validation manifest required a change for this remediation.**
Every manifest in [`compliance/lula/`](../compliance/lula/) asserts over **Kubernetes
resources** — Deployment readiness, container specs, environment-variable presence,
ConfigMaps, and Secret references — or over live compliance-bridge API responses.
No change in this remediation adds, removes, or renames a Deployment, container,
environment variable, or Secret reference, and none alters a value a Rego assertion
compares against.

One documentary correction was made: [`compliance/lula/lula-validation-au12.yaml`](../compliance/lula/lula-validation-au12.yaml)
carried an AU-12(1) *description* stating that each evidence record includes a
`schema_version` field "for dual-schema verification (v1.0/v1.1)". That narrative
became false once the dual-schema apparatus and the `schema_version` field were
removed (POAM-2026-062). This is prose inside an `implemented-requirements`
description, **not** a Rego assertion — no validation logic changed and the
manifest's pass/fail behavior is unaffected.

The [`compliance/lula/lula-validation-cm6.yaml`](../compliance/lula/lula-validation-cm6.yaml)
manifest asserts that governance threshold ConfigMaps are deployed. It requires no
manifest edit, but note that after POAM-2026-068 a deployment missing its regional
baseline will now fail gateway startup rather than degrading silently — a deployment
configuration consequence, not a manifest change.

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
| `lula-validation-flowsignal.yaml` | ISO 42001 | A.8.4 FlowSignal Consequence Authority | Universal |
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
