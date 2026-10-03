# Security Posture Statement — Plan of Action and Milestones (POAM)

**System:** Cybernetic AI Governance Engine (CAGE)
**Document:** Public Security Posture Statement
**Frameworks:** NIST SP 800-53 Rev. 5, NIST AI 600-1, ISO 42001, EU AI Act, DORA, GDPR, MAS FEAT, MAS TRM, MAS Notice 655
**Last Updated:** 2026-10-01

---

## Purpose

This document is a public transparency statement about the security posture of the Cybernetic Governance Engine (CAGE). It describes the compliance controls being addressed, the frameworks they map to, and the general remediation timeline.

CAGE is an open-source, domain-agnostic AI governance platform. Its kernel enforces governance policies over multi-agent LLM workflows independently of any domain; finance and healthcare ship as equal-standing optional example domain plugins, and jurisdictional compliance is a configurable posture. Enforcement is delivered via:

- **Pre-Pipeline & Tier 0.5 Boundary Gate**: NeMo Guardrails (Layer 0) and FTRA (`ftra`, Tier 0.5 — Forward-Looking Trajectory Reachability Analyzer, operating both on the whole execution graph via `create_ftra_node()` and per-request via `FtraStage`)
- **Tiers 0.5–6** (two-phase per-tool-call checks in `run_pipeline()`): Phase 1 read-only validation — FTRA (Tier 0.5) → STPA/UCA validation (Tier 1) → OPA Rego policy (Tier 3b) → Agentic confidence (Tier 2) → Multi-model consensus (Tier 5) → Causal gatekeeper (Tier 6); followed on zero violations by Phase 2 mutating commits — Control Barrier Function (Tier 3a) → Fiscal Limit Pre-Reservation (Tier 4)

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
| POAM-2026-025 | NIST AI 600-1 §2.6 | CBRN / harmful content Lula validation is a stub pending AO pre-approval for NeMo CBRN rail deployment | High | 2026-12-31 |
| POAM-2026-026 | ISO 42001 A.8.4 | Standalone `token-quota-proxy` Deployment not yet created; TokenQuotaProxy runs inline in gateway | Moderate | 2026-09-30 |
| POAM-2026-076 | SI-10 / ISO 42001 A.6.2.6 | Physical-AI barriers (separation, velocity, torque) are declared but not enforced: no cost resolver, so `KinematicBarrierTier` has no CBF and fails closed (DENY) on every governed physical action | Moderate | 2026-12-31 |
| POAM-2026-077 | CM-6 / SC-24 | Physical-AI plugin declares no `DomainConfig` (no FTRA terminal registry), so `CAGE_DOMAIN=physical_ai` refuses to start (fail closed); `finance` and (since 2026-09-30) `healthcare` are runnable | Moderate | 2026-12-31 |
| POAM-2026-078 | SI-10 / SA-8 | Plugin-contributed CBF invariants (healthcare serum concentration, physical-AI separation/velocity/torque) are validated (V1-V4) at governor assembly and recorded on `GovernorComponents.invariants`, but not enforced until the CBF engine becomes invariant-parametric (PR 4b) | Moderate | 2026-12-31 |
| POAM-2026-082 | IA-5 / SC-7 / SC-28 | Hugging Face token (`HUGGING_FACE_HUB_TOKEN`) was baked into `Dockerfile.vllm` image config (`ENV HUGGING_FACE_HUB_TOKEN`), passed as a plaintext Cloud Build substitution (`_HF_TOKEN`), and stored in Terraform state / `hf-token-secret`. Code and IaC remediated to remove all token references and stream weights from GCS (`gs://`) via `runai_streamer` under `HF_HUB_OFFLINE=1`; item remains Open pending manual token rotation on `huggingface.co` and deletion of historical `vllm-streamer` image digests | High | 2026-10-05 |
| POAM-2026-083 | SI-2 / SI-3 / SI-7 / CM-7 | Follow-on to `POAM-2026-013`: Terraform GKE module image inputs and Cloud Build configs previously used `:latest` tags and an unkeyed Binary Authorization attestor; remediated in IaC and build pipelines via `google_kms_crypto_key.binauthz_attestor`, `pkix_public_key`, `var.image_digests` (`@sha256:` digest pinning), and `scripts/mirror_and_attest_images.sh`, pending live staging cluster verification of mirrored third-party image attestations and `lula-validation-si2.yaml` | High | 2026-10-15 |
| POAM-2026-084 | AU-9 / AU-9(3) / AU-10 / AU-11 | Evidence pipeline integrity: the gateway `EvidenceStreamSink` was never started by the server lifespan (no evidence recorded), gateway replicas could fork the hash chain, the gateway held its own signer and cold-store flush (signatures never persisted; failed flushes silently skipped), and async Redis clients ignored TLS/IAM. Remediated in code on `fix/evidence-pipeline-integrity` and `feat/evidence-custody-verifier`: lifespan starts the sink via `start_evidence_sink()` (fail closed when enforcing); Lua compare-and-append keeps one linear chain; [`ConsequenceGateway`](../src/gateway/governance/consequence_gateway.py) and [`ingest_actuation_receipt()`](../src/gateway/governance/execution_actuator.py) emit post-evaluation decisions and actuation refusals into `EvidenceStreamSink`; custody moved to the compliance-bridge [`EvidenceCustodian`](../src/compliance_bridge/evidence_custodian.py) (re-verify, KMS-signed batch attestation with `EVIDENCE_KMS_KEY`, WORM `put_if_absent`, durable cursor); `build_async_redis()` enforces TLS/IAM. See [`EVIDENCE_CHAIN.md`](architecture/EVIDENCE_CHAIN.md). OSCAL AU-9 / AU-9(3) / AU-10 / AC-6 statements updated in [`sp800-53-component-definition.yaml`](../compliance/oscal/sp800-53-component-definition.yaml) (status `partial`); ClickHouse sink moved to the INSERT-only `cage_evidence_sink` user; unsigned (dev/test/ci) attestations marked non-evidentiary and rejected by `assert_citable()`; read-back [`CustodyVerifier`](../src/compliance_bridge/evidence_verifier.py) added (kid-resolved signature, object binding, record re-verification, chain continuity, scheduled `run_forever()` loop, Prometheus metrics, `GET /v1/evidence/verify`, fail-closed OSCAL citation gating in [`oscal_exporter.py`](../src/compliance_bridge/oscal_exporter.py), and Terraform/Kubernetes manifest wiring for `EVIDENCE_VERIFY_INTERVAL_S`, `OSCAL_REQUIRE_VERIFIED_CUSTODY`, and `EVIDENCE_TRUST_ANCHORS_FILE`). Remains Open pending merge SHAs and live staging verification of signed attestations in the WORM bucket | High | 2026-10-15 |
| POAM-2026-085 | SI-10 / `CTRL_MRM_004` | Causal gatekeeper cache bypassed the per-request risk boundary: a cached ALLOW for a small trade was replayed for any amount, and a cached DENY denied small ones (Redis with `cache_ttl_seconds > 0`, within one TTL window). Remediated in `refactor/ftra-scope` by caching only the params-independent world-model verdict; closes at merge | High | 2026-10-15 |
| POAM-2026-086 | SC-8 / SC-23 | Memorystore server CA not delivered to gateway/compliance-bridge pods; evidence-stream fail-closed check exposed it on 2026-10-01. Remediated in IaC (PR-3, `fix/memorystore-ca-pinning`) by mounting `module.memorystore_governance.managed_server_ca` via `<app>-redis-ca` ConfigMaps at `/etc/cage/tls/redis/ca.pem` (`REDIS_CA_CERT_PATH`, `cage.io/redis-ca-sha256` rollout annotation, and `lula-validation-sc8.yaml` Check 5); remains Open pending PR-4 (`fix/redis-tls-one-rule`) unification of synchronous/module-level Redis TLS verification across all enforcing postures | High | 2026-10-15 |
| POAM-2026-094 | SI-10 / CA-7 / `CTRL_MRM_004` | The causal tier has no live world-model feed outside dev/test/ci, so it denies every `execute_trade` in enforcing postures. The 2026-10-03 staging benchmark (`docs/paper/measurements/2026-10-03-5aa1a65f/`) recorded all 4 benign trade prompts as refused, first with `CAUSAL_TELEMETRY_UNAVAILABLE`. [`LangfuseTelemetryProvider`](../src/integrations/telemetry_langfuse/provider.py) called `Langfuse.fetch_traces`, which SDK v3 removed; that is fixed on `fix/fp-judge-context-pii`. With the call fixed, the tier denies with `CAUSAL_INSUFFICIENT_SAMPLES` instead, because nothing produces the rows the model needs. `amount` is real. `market_volatility` comes only from [`StubMarketDataProvider`](../src/cage_finance/safety/bounding/providers.py) (a constant 0.15). No component observes a post-trade `risk_score` outcome. The deny is correct fail-closed bootstrap behaviour (POAM-2026-088). The gap is the missing Tier 2 data source: a deterministically seeded, fault-injectable market-data and outcome backend. Emitting the system's own risk formula as the outcome would make DoWhy validate the model against itself, so that is not a remediation | Moderate | 2026-12-31 |

### EU ECB Region (EU_ECB)

| ID | Control | Description | Severity | Target Date |
|----|---------|-------------|----------|-------------|
| EU-DORA-001 | DORA Art. 10 | Compliance bridge endpoint for DORA ICT operational resilience evidence not yet implemented | High | 2026-12-31 |
| EU-AI-ACT-001 | EU AI Act Art. 9 | Compliance bridge endpoint for EU AI Act risk management system evidence not yet implemented | High | 2026-12-31 |
| EU-GDPR-001 | GDPR Art. 22 | Compliance bridge endpoint for GDPR human oversight of automated decisions not yet implemented | High | 2026-12-31 |
| EU-001 | EU AI Act Art. 27 | FRIA gating normative provider is in stub mode; external compliance validation provider not yet configured for EU_ECB | High | 2026-12-31 |
| POAM-2026-084 | EU AI Act Art. 27 / SI-10 | FRIA (`CTRL_FRIA_006`) was never enforced: from v2.0.0-dev.1 (2026-06-01) `enforce_fria_boundary()` had no pipeline caller, so no EU_ECB decision consulted an impact assessment. Remediated in `refactor/fria-jurisdiction` by the EU_ECB-only `fria` jurisdiction tier; closes at merge | High | 2026-10-15 |

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
| POAM-2026-023 | SC-4 / SI-2 | **External Reconciliation Not Enforced on Atomic Commit Path** — discovered 2026-08-28 by Miracle Owolabi (external security researcher, OWASP AI Exchange Author). `LUA_ATOMIC_CBF` read `safety:current_cash` directly instead of KMS-signed reconciled balance from `reconciliation:verified_balance`. This bypassed five separate controls: (1) KMS signature verification (POAM-2026-031, POAM-2026-038), (2) `_CBF_STRICT_MODE` fail-closed behavior, (3) R-04 replay sequence defense (POAM-2026-054), (4) TTL staleness rejection, (5) R-05 fence-epoch validation. Atomic commit enforcement used self-reported balance without verification. Reconciliation subsystem could validate external balance without influencing trade authorization. **Additional Findings:** Fence-epoch regression detection (R-05) was implemented but never executed on commit path. Local debit tracking gap allowed double-spend within reconciliation window. Remediated by creating `_resolve_ground_truth_balance()` seam for KMS-verified balance resolution, modifying `LUA_ATOMIC_CBF` to accept ground truth balance as ARGV[5], adding fence-epoch regression detection on commit path, adding local debit tracking to prevent double-spend within reconciliation window. Remediation commit: `fix(cbf)!: enforce POAM-023 reconciliation on atomic commit path`. Test coverage: 5 new test cases in `tests/cage_finance/test_cbf_reconciliation.py`. **Related POAMs Closed:** POAM-2026-031, POAM-2026-038, POAM-2026-054 (all enforced via reconciliation path). **Dependency:** This fix assumes accurate balance values from the reconciliation worker. PR #93 (zero balance masking fix) must be deployed first to ensure `GcsLedgerProvider` and `ObjectStoreLedgerProvider` return accurate 0.0 balances for drained accounts rather than fallback values. | 2026-08-28 |
| POAM-2026-031 | CBF / SI-2 | External CBF state reconciliation not implemented — remediated by `src/gateway/governance/reconciliation/daemon.py` (v2.1.0); reconciled balances are KMS-signed before Redis write; CBF fails closed on TTL expiry. **CLOSED via POAM-2026-023 remediation** (2026-08-28) — KMS signature verification now enforced on atomic commit path. | 2026-07-27 |
| POAM-2026-032 | SA-11 | `src/gateway/governance/ftra/graph_analyzer.py` was an unwired `FtraReachabilityGate` scaffold committed alongside the production `src/gateway/governance/ftra/` package in the same commit but never imported by `SymbolicGovernor` or any production code path; its dedicated test file (`tests/test_ftra_reachability.py`) exercised only this dead code, giving a false impression of FTRA test coverage — remediated by deleting both files; documentation across 5 files corrected to describe the actual `ftra/` implementation (`PlanGraphAnalyzer`, `IrreversibilityClassifier`, `create_ftra_node`) instead of the removed scaffold | 2026-07-30 |
| POAM-2026-033 | CA-7 / SI-2 | Two defects in `src/gateway/governance/ftra/node_factory.py` uncovered while closing POAM-2026-030's test-coverage gap: **(1)** `_park_in_defer_queue()` instantiated `DeferQueue()` with zero arguments, but `DeferQueue.__init__` requires a `redis_client` — this always raised `TypeError`, silently caught by a broad `except Exception`, so every HITL_REQUIRED verdict's DeferToken was never actually persisted to Redis db=1, making it unreachable via the external HITL resolution API (`POST /v1/defer/{id}/escalate`); **(2)** `ftra_node()`'s outer exception handler caught `NodeInterrupt` (a subclass of `Exception` in LangGraph) unconditionally, converting every HITL_REQUIRED verdict into a fail-closed `BLOCKED` response before the thread could ever suspend for human review — remediated by **(1)** connecting via `redis.asyncio.from_url(REDIS_URL, db=1)` then `DeferQueue(client)`, mirroring the working pattern in `src/compliance_bridge/main.py`, and **(2)** re-raising `GraphInterrupt`/`NodeInterrupt` before the generic exception handler runs; both fixes covered by dedicated regression tests in `tests/test_ftra_package.py::TestCreateFtraNode` | 2026-07-30 |
| POAM-2026-034 | R-2, R-6 | `GovernanceThresholds.pii_audit_retention_days` / `pii_audit_retention_authority` hardcoded a 90-day / FISMA AU-11 default regardless of `CAGE_DEPLOYMENT_REGION` — remediated via `_resolve_pii_retention()` in `src/gateway/governance/schemas/thresholds.py`, which resolves the citation from `constants.PII_RETENTION_AUTHORITY` (`FISMA AU-11` for US_FED, `GDPR Art. 5(1)(e)` for EU_ECB, `MAS Notice 655 §4.3` for APAC_MAS, ISO 42001 §A.9.2 fallback) at call time; an explicit value in `governance_thresholds.json` still overrides the region-derived default; FINDING-07 in `docs/compliance/cross-region/JURISDICTIONAL_SEPARATION_ANALYSIS.md` closed; covered by `tests/test_governance_thresholds_pii_retention.py` | 2026-07-31 |
| POAM-2026-035 | R-2, R-3, R-4 | `pii_audit_log()` in `src/gateway/governance/pii_sanitizer.py` cited `FISMA AU-11` as the universal PII retention authority with no `CAGE_DEPLOYMENT_REGION` guard — remediated by adding an optional `region` parameter and sourcing the citation from `constants.PII_RETENTION_AUTHORITY`; the returned audit record now carries a jurisdiction-correct `retention_authority` field; FINDING-08 closed; covered by `tests/test_pii_audit_log.py::TestPiiAuditLogJurisdictionalRetentionAuthority` | 2026-07-31 |
| POAM-2026-036 | R-2 | `src/gateway/governance/hitl_escalator.py` and `src/gateway/governance/prompt_injection_detector.py` declared `Region: US_FED` in their module docstrings only, with no runtime region check backing the claim (the SR 26-2 §3.2 4-hour HITL SLA has no legal force outside US_FED) — remediated by adding `get_hitl_sla_hours(region)`, `get_hitl_regulatory_citation(region)`, and `hitl_override_audit_span()` to `hitl_escalator.py` (backed by new `HITL_SLA_HOURS` / `HITL_CITATIONS` tables in `constants.py`), and `get_injection_citation(region)` to `prompt_injection_detector.py` (backed by `constants.INJECTION_CITATION`); FINDING-09 closed; covered by `tests/test_hitl_escalator.py` and `tests/test_prompt_injection_detector.py::TestGetInjectionCitation` | 2026-07-31 |
| POAM-2026-038 | SC-4 / SI-2 | ✅ **CLOSED 2026-08-16.** `reconciliation-worker` CronJob now operational. GCS bucket created (`cage-reconciliation-<project-id>`), KMS key created (`governance/balance-signer`), IAM bindings applied, secrets populated, code bug fixed (`GcsLedgerProvider` field mismatch). Redis now contains verified balance: `{"balance_usd":1000000.0,"source":"gcs","verified_at":1786850100.0}` with 300s TTL. Peer review fix applied: added atomic epoch-check validation to `GcsLedgerProvider`. **CLOSED via POAM-2026-023 remediation** (2026-08-28) — external balance verification now enforced on atomic commit path. | 2026-08-16 |
| POAM-2026-071 | IA-5 / SC-28 | ✅ **CLOSED 2026-09-05.** Sensitive credentials in local Terraform state backups (`infra/targets/gcp-gke/*.tfstate*`) identified during vendor decoupling audit. Remediated by rotating exposed credentials, confirming untracked status via `.gitignore`, genericizing templates and manifests, and adding `scripts/check_project_id_hygiene.py` CI gate. | 2026-09-05 |
| POAM-2026-039 | SC-4 / SI-2 | `routing_seal.py` `generate_seal()` did not sanitize dots in `action_slug` — an action name containing a literal `.` (e.g. `execute.trade`) would shift `seal.split(".", 2)` in `verify_seal()`, causing valid seals to fail verification with a parse error rather than a proper `SymbolicGovernorViolation`. Remediated by adding `.replace(".", "-")` to the slug normalization step (commit 2026-08-06). Covered by existing routing seal unit tests. | 2026-08-06 |
| POAM-2026-040 | CA-7 / SI-2 | `src/gateway/governance/causal/gatekeeper.py` invoked `backdoor.linear_regression` with no minimum-sample guard — on cold-start or sparse-telemetry conditions (< 50 observations), the regression produced a meaningless estimate that could incorrectly approve or reject trades. Remediated by adding `_MIN_CAUSAL_SAMPLES = int(os.getenv("CAUSAL_MIN_SAMPLES", "50"))` guard that fails closed with `CTRL_TEL_003` when insufficient telemetry is available (commit 2026-08-06). | 2026-08-06 |
| POAM-2026-041 | AU-12 / SI-2 | `context_accumulator.py` `_content_hash()` used `json.dumps(..., sort_keys=True)` without `separators=(",", ":")`, while `_link_hash()` used `separators=(",", ":")`. Cross-platform whitespace differences (CPython vs PyPy, Windows vs Linux) could produce different serializations for the same payload, breaking hash-chain verification. Remediated by adding `separators=(",", ":")` to `_content_hash()` (commit 2026-08-06). | 2026-08-06 |
| POAM-2026-042 | AU-12 / SA-11 | `src/gateway/governance/reconciliation/daemon.py` registered providers `stub`, `anchorage`, and `plaid` but `deployment/k8s/gateway.yaml` sets `RECONCILIATION_PROVIDER=gcs` — the registry raised `ValueError: Unknown reconciliation provider 'gcs'` on every worker startup, making the reconciliation loop dead code. Remediated by adding `GcsLedgerProvider` class and registering `"gcs"` in the provider dict (commit 2026-08-06). The reconciliation-worker `CronJob` manifest was also added to `deployment/k8s/reconciliation-worker.yaml`. | 2026-08-06 |
| POAM-2026-043 | SC-4 / IA-5 | `routing_seal.py` and `src/governed_financial_advisor/tools/api.py` lacked atomic single-use nonce consumption — a valid routing seal could be replayed within the 30-second TTL window before expiration (`CAGE-SEC-008`). Remediated by implementing `verify_and_consume_seal()` with atomic Redis `SETNX EX` key burning, enforcing fail-closed replay rejection (commit `88fa9d7`). Covered by `tests/test_routing_seal_security.py`. | 2026-08-11 |
| POAM-2026-044 | AU-12 / SA-11 | Denial and refusal paths in `src/gateway/governance/governor/verdicts.py` raised string `GovernanceError` without structured audit-grade cryptographic proofs (`CAGE-SEC-009`). Remediated by introducing immutable `RefusalReceipt` dataclass with SHA-256 canonical hashing across `thread_id`, `action`, `violated_tier`, and `violated_rule` (commit `88fa9d7`). | 2026-08-11 |
| POAM-2026-045 | A.8.4 / ISO 42001 | `governed_financial_advisor` had disconnected the 4-state `DeferQueue` primitive, bypassing the CSA AARM ambiguity/deferral state (`CAGE-REM-004`). Remediated by implementing `defer_node` and routing $[0.70, 0.95)$ confidence bands to `DeferQueue` in Redis `db=1` (commit `88fa9d7`). Covered by `tests/test_hitl_toctou_revalidation.py`. | 2026-08-11 |
| POAM-2026-046 | SA-9 / External | Provider 03 integration boundary was unspecified at the code level (`CAGE-REM-006`). Remediated by implementing `Provider03NormativeProvider` adapter in `src/integrations/provider_03/` satisfying the 3-endpoint `NormativeProvider` contract and bind receipt ingestion (commit `88fa9d7`). Covered by `tests/test_provider_03_adapter.py`. | 2026-08-11 |
| POAM-2026-030-B | SC-7 / AC-4 | `CAGE_FTRA_BOUNDARY_ENABLED` feature flag removed — FTRA boundary check is now **mandatory** and unconditional in `SymbolicGovernor._run_checks()` (line 970–999 of `src/gateway/governance/governor/stages/ftra.py`). Risk R-03 (Trust Boundary Bypass) is now fully mitigated at the controller level; direct HTTP access to `/validate-action` or ext_authz can no longer bypass FTRA classification. The in-graph `ftra_node` remains active as a first-pass gate. See [`docs/operations/FTRA_COMPENSATING_CONTROLS.md`](operations/FTRA_COMPENSATING_CONTROLS.md) for NetworkPolicy defense-in-depth documentation (still in place for R-02 mitigation). | 2026-08-16 |
| POAM-2026-050 | AC-3 / SI-7 | `NARROW` governance decision primitive added for partial-authority execution with clamped scope — enables constrained action approval when full approval is not warranted but outright denial would be overly restrictive. Implemented in `src/gateway/governance/decisions.py` and integrated into `src/gateway/governance/governor/verdicts.py`. Feature flag: `CAGE_NARROW_ENABLED` (default `false`). | 2026-08-16 |
| POAM-2026-051 | AC-3 / SI-7 | `PAUSE` governance decision primitive added for resumable execution suspension with cryptographic token-based resume (`pause_primitive.py`, `/v1/pause/*`, `CAGE_PAUSE_ENABLED`). **Superseded 2026-10-01:** the primitive, the verdict, `ViolationKind.TRANSIENT`, the endpoints and the flag were removed (`docs/BREAKING_CHANGES_v3.md` P4-1–P4-5) because no tier ever produced a `TRANSIENT` violation, so `PAUSE` was unreachable in every posture. A transient fault is a `HARD` violation → `DENY` with a refusal receipt. `proof/model.py` `phases_closed` now asserts the model names no verdict the runtime lacks. | 2026-08-16 |
| POAM-2026-052 | AU-12 | `DEFER` tokens now persisted via `DeferQueue` for client polling — replaces bare UUID generation with persistent queue-backed deferral state. `SymbolicGovernor._park_defer_context()` now atomically enqueues defer tokens to Redis `db=1` with full audit trail. | 2026-08-16 |
| POAM-2026-053 | SC-4 / SI-2 | Monotonic fence epoch counter added for Redis failover safety — prevents stale replica reads during primary/replica failover by incrementing epoch on each write and validating epoch freshness on reads. Implemented in `src/gateway/governance/safety/cbf_engine.py`. Feature flag: `CAGE_REDIS_SYNCHRONOUS_REPLICATION` (default `true`). | 2026-08-16 |
| POAM-2026-054 | SC-8 / SI-7 | Monotonic sequence numbers embedded in KMS-signed balance payloads for reconciliation replay defense — prevents replay attacks where stale signed balances could be re-submitted. Implemented in `src/gateway/governance/safety/cbf_engine.py` and `src/gateway/governance/reconciliation/daemon.py`. Feature flag: `CAGE_RECONCILIATION_REPLAY_DEFENSE` (default `false`). **CLOSED via POAM-2026-023 remediation** (2026-08-28) — R-04 replay sequence defense now enforced on atomic commit path. | 2026-08-16 |
| POAM-2026-055 | AU-12 | `EVIDENCE_CHAIN_BLOCKING` default changed from `false` to `true` — evidence stream now synchronously blocks until evidence records are durably persisted to Langfuse backend, providing stronger audit durability guarantees at the cost of slightly increased latency. Implemented in `src/gateway/governance/evidence/stream.py`. | 2026-08-16 |
| POAM-2026-056 | SI-7 / SC-4 | Two-phase pipeline reordering in `SymbolicGovernor._run_checks()` — decouples read-only validation gates (Phase 1: STPA, Confidence, OPA, Consensus, Causal, FRIA) from state-mutating gates (Phase 2: CBF Lua atomic check+commit, FiscalLimitGuard), eliminating downstream budget leakage and saga-atomicity gaps. | 2026-08-18 |
| POAM-2026-057 | SI-7 / CA-7 | Causal Gatekeeper fail-closed on non-positive slope ($\beta \le 0$) and bounded marginal risk scoring $\min(1.0, \max(0.0, 0.5 + \beta \times \text{amount})) \in [0.0, 1.0]$. | 2026-08-18 |
| POAM-2026-058 | SC-4 / SI-2 | FiscalLimitGuard rollback and release window-key verification — ensures counter rollbacks do not execute against expired daily keys, preventing negative counter underflow across TTL boundaries. | 2026-08-18 |
| POAM-2026-059 | SI-7 / SA-11 | Formal verification proof model extended to 57 sequential / 66 concurrent reachable states with single-use, TTL, and downstream actuator choke-point verification in Gap 2 negative controls (`proof/model.py`). | 2026-08-18 |
| POAM-2026-061 | SC-13 / IA-5 | Ed25519 signature verification defect in `src/gateway/governance/kms_signer.py` — `_kms_verify()` rejected all Ed25519 signatures due to incorrect `hashlib.new("raw", ...)` call (no such algorithm) and wrong isinstance branch. Remediated by fixing Ed25519 detection logic and removing the invalid hashlib call. Covered by `tests/test_kms_signer_new_features.py` regression tests. FlowSignal Phase 2 ST-1. Remediation commit: pending (working tree uncommitted). | 2026-08-27 |
| POAM-2026-060 | SC-13 / SI-7 | ✅ **CLOSED — RFC 8785 JCS migration complete.** Every executable `json.dumps(..., sort_keys=True)` canonicalization site in `src/` now uses `jcs_canonicalize_plan()`; zero remain (excluding the vendored RFC 8785 reference implementation under `src/gateway/governance/vendor/jcs/` and docstring references). Migrated surfaces: the `ContextAccumulator` and `EvidenceStreamSink` hash chains (write and verify paths migrated atomically, with `_SCHEMA` sentinels bumped to `cage-context-accumulator/2.0` and `cage-evidence-stream/2.0` so the break is self-identifying), the WORM/KMS-signed UCA record signing path in `src/gateway/governance/uca_logger.py`, the JWS header/payload in `consequence_token.py` (60 s TTL), routing seals in `routing_seal.py` (30 s TTL), OPA and query cache keys, the reconciliation signed balance (300 s TTL), the control-registry profile hash, and provider receipt/state digests. Sites previously relying on `default=str` received explicit `datetime`/`Decimal` pre-normalization (`_normalize_for_jcs()` in the compliance-bridge modules) because `jcs_canonicalize_plan()` has no `default=` escape hatch. **Record correction — the original finding was factually wrong on three counts:** (1) it stated "10 identified sites" when the real figure was ~25 executable call sites across 32 `sort_keys=True` occurrences; (2) it claimed the hashes "are compared against persisted data", which was true only for the WORM UCA record — all other chains are self-verifying, recomputing digests with the same function used at write time, with no independently-stored ground truth; (3) it recorded a backward-compatibility blocker that did not exist — no adopter deployment's chains could be invalidated, and the repository had already shipped an equivalent canonicalization break for `normative_provider.py`. The WORM/KMS path was migrated with **no compatibility shim** following the deactivation of the data-at-rest exception in [`AGENTS.md`](../AGENTS.md) (relocated to *Dormant Rules — Reactivate When CAGE Begins Real Deployments*); pre-change WORM records will not verify under the new algorithm. Breaking changes documented in [`docs/BREAKING_CHANGES_v3.md`](BREAKING_CHANGES_v3.md). Lula result: no manifest change required (all Lula manifests assert over Kubernetes resources; verified — see *Lula Verification* below); `lula-validation-au12.yaml` narrative text corrected for the removed dual-schema apparatus. Remediation commit: `<pending-squash-merge-sha>`. | 2026-08-27 |

| POAM-2026-062 | AU-12 | Evidence-stream v1.0/v1.1 dual-schema machinery (surfaced by code inspection as **BC-01**, not previously tracked in this POAM). `src/gateway/governance/evidence/stream.py` retained a full dual-schema apparatus — `_detect_schema_version()`, `migrate_record_1_0_to_1_1()`, `get_last_v1_0_hash()`, `_link_hash_v1_1()`, and the `schema_version` field on `EvidenceRecord` — despite v1.0 write support already being removed and `verify_record()` already hard-rejecting v1.0 records. A repo-wide search found zero production callers outside the module itself; the sole external consumer was a test suite existing only to exercise the dead compatibility path. Remediated by deleting the four functions and the `schema_version` field, collapsing `_link_hash_v1_1()` into a single unconditional `_link_hash()`, and deleting `tests/test_dual_schema_verification.py`; still-relevant hash-determinism assertions were folded into `tests/test_evidence_stream.py`. Schema sentinel bumped to `cage-evidence-stream/2.0`. Lula result: no manifest change required; the stale dual-schema narrative in `compliance/lula/lula-validation-au12.yaml` was corrected. Remediation commit: `<pending-squash-merge-sha>`. | 2026-08-27 |
| POAM-2026-063 | SA-9 | Provider 03 backward-compatibility alias methods (**BC-02**, previously untracked). `Provider03NormativeProvider` exposed three dict-returning shadow methods — `fetch_legal_baseline()`, `validate_external_fria()`, `submit_evidence_chain()` — alongside the canonical dataclass-returning `NormativeProvider` protocol. **Security-relevant:** `validate_external_fria()` returned a hardcoded `APPROVED` verdict unconditionally, so any caller reaching it would have silently bypassed governance. None of the three were part of the canonical protocol and the only callers were integration tests. Remediated by deleting all three aliases and rewriting the integration tests against the canonical three-endpoint contract required by the Universal Protocol Conformance Suite. Remediation commit: `<pending-squash-merge-sha>`. | 2026-08-27 |
| POAM-2026-064 | SA-9 / CA-7 | Provider 01 legacy binary `admitted`/`findings` response fallback (**BC-03**, previously untracked). **Security-relevant — closes a latent fail-open.** `src/integrations/provider_01/provider.py` accepted two wire formats and fell back to a legacy binary shape when the FlowSignal tri-state `decision` field was absent. A response that lost its `decision` key — for example a proxy error page that happens to parse as JSON carrying `admitted: true` — was admitted without ever passing through `_map_flowsignal_decision()` or ConsequenceToken minting. Two tests in the Universal Protocol Conformance Suite were actively locking this fail-open behavior in. Remediated by deleting the legacy branch: a missing or unrecognized `decision` now fails closed with `ValidationResult(admitted=False)` and a structured finding carrying `code="cage.endpoint_error"`, matching the fail-closed vendor-adapter semantics mandated by [`AGENTS.md`](../AGENTS.md). The two conformance tests were **inverted**, not deleted, so the fail-closed contract is now the asserted one. Remediation commit: `<pending-squash-merge-sha>`. | 2026-08-27 |
| POAM-2026-065 | AU-12 / AU-10 | Provenance-chain legacy decision vocabulary (**BC-04**, previously untracked). `VALID_DECISIONS` in `src/gateway/governance/provenance_chain.py` admitted eight values — the six canonical `GovernanceDecision` members plus the execution-phase statuses `BLOCK` and `ESCALATE` — weakening the provenance record's audit semantics by making `BLOCK` and `DENY` indistinguishable to a downstream auditor. Remediated by remapping emitters (`BLOCK → DENY`, `ESCALATE → REQUIRE_APPROVAL`) and narrowing `VALID_DECISIONS` to the canonical six: `ALLOW`, `DENY`, `DEFER`, `NARROW`, `PAUSE`, `REQUIRE_APPROVAL` (since 2026-10-01 derived from the `GovernanceDecision` enum — five values, `PAUSE` retired). `build_provenance_record()` now raises `ValueError` for `BLOCK`/`ESCALATE`. Covered by `tests/test_provenance_chain.py`. Remediation commit: `<pending-squash-merge-sha>`. | 2026-08-27 |
| POAM-2026-066 | AU-12 | Duplicated legacy DEFER response fields (**BC-05**, previously untracked). Three sites emitted three names for the same value in an audit-relevant response body: `verdict` and `missing_input_reason` in `src/gateway/governance/decisions.py` and `src/gateway/server/agent_gateway_adapter.py`, and `defer_id` in `src/gateway/governance/governor/governor.py`. Beyond the redundancy this created a divergence risk if one site were updated and the others not. Remediated by deleting all three legacy keys from the response bodies and the `DeferResponse` model; the canonical fields are now `decision`, `defer_token`, and `classification_reason`. Assertions updated in `tests/test_defer_queue.py` and `tests/test_governance_middleware.py`. Remediation commit: `<pending-squash-merge-sha>`. | 2026-08-27 |
| POAM-2026-067 | SC-4 | Fiscal limit guard legacy window-key fallback (**BC-07**, previously untracked). **Security-relevant — defeated an existing control.** When `rollback()` in `src/gateway/governance/safety/resource_guard.py` was called with neither `window_key` nor `token`, a legacy fallback silently computed the *current* window rather than the window the reservation was made against. This guaranteed `target == current`, so the cross-window guard sitting immediately below it could never fire on that path — nullifying the very control **POAM-2026-058** was closed to add. Remediated by making `window_key` or `token` mandatory: `rollback()` now raises `ValueError` when neither is supplied, mirroring the existing `amount`/`amount_minor` guard, and all callers were updated to pass the `ReservationToken`. Remediation commit: `<pending-squash-merge-sha>`. | 2026-08-27 |
| POAM-2026-068 | CM-6 | `ControlRegistry` legacy control-mappings fallback (**BC-08**, previously untracked). **Security-relevant — reintroduced a closed defect.** `src/gateway/governance/constants.py` fell back to `_LEGACY_PATH` (`config/control_mappings.json`) with `region="LEGACY"` whenever the regional compliance profile was missing. A region-guarded system that silently degrades to a non-regional profile emits audit spans bearing jurisdictionally wrong citations — precisely the class of defect that **POAM-2026-034**, **POAM-2026-035** and **POAM-2026-036** were opened and closed to eliminate; the fallback reintroduced it through the back door. Remediated by deleting `_LEGACY_PATH` and the fallback branch; a missing regional profile now raises `RuntimeError` at startup ("Cannot start governance engine without a valid profile"). Adopter deployments must provision `config/compliance/{US_FED,EU_ECB,APAC_MAS}_BASELINE.json` — see [`docs/BREAKING_CHANGES_v3.md`](BREAKING_CHANGES_v3.md). Verified across all three region-gated test postures. Remediation commit: `<pending-squash-merge-sha>`. | 2026-08-27 |
| POAM-2026-069 | SC-4 / SI-2 | **R-05 Fence-Epoch Validation Bypass** — discovered during POAM-2026-023 remediation (2026-08-28) by Miracle Owolabi (external security researcher, OWASP AI Exchange Author). Fence-epoch regression detection (R-05) was implemented in reconciliation subsystem but never executed on the atomic commit path. The commit path read balances without checking if the fence epoch had regressed (indicating a Redis primary/replica failover or clock skew), potentially accepting stale data from a failed-over replica. Remediated by adding fence-epoch validation in `_resolve_ground_truth_balance()` before CBF atomic commit. The fence check now fails closed with `REPLICATION_UNCONFIRMED` when epoch regression is detected. Covered by test cases in `tests/test_reconciliation_daemon.py`. Closed as part of POAM-2026-023 remediation. | 2026-08-28 |
| POAM-2026-070 | SC-4 / SI-2 | **Local Debit Tracking Gap** — discovered during POAM-2026-023 remediation (2026-08-28) by Miracle Owolabi (external security researcher, OWASP AI Exchange Author). No local debit tracking existed to prevent double-spend within the reconciliation window (300s TTL). An attacker could submit multiple concurrent trade requests that individually pass CBF balance checks but collectively exceed available funds, exploiting the gap between local Redis state and external ledger synchronization. Remediated by adding `_register_pending_debit()` in `_resolve_ground_truth_balance()` to atomically decrement local pending balance before CBF evaluation, preventing double-spend races. Covered by test cases in `tests/test_reconciliation_daemon.py`. Closed as part of POAM-2026-023 remediation. | 2026-08-28 |
| CAGE-SEC-003 | ISO 42001 A.8.4 | **DeferQueue Phase-3 Confidence Recheck Bypass** — discovered 2026-08-28 by Miracle Owolabi (external security researcher, OWASP AI Exchange Author). `/v1/defer/{defer_id}/inject` endpoint called `queue.resolve()` directly without invoking `replay_evaluate()`, bypassing Phase-3 confidence recheck against `DEFER_CONFIDENCE_THRESHOLD` (0.70). Additionally published forged ISO 42001 A.8.4 attestations. Deferred tokens could be resolved without validating injected context raised confidence above threshold. Audit trail contained inaccurate compliance attestations. Remediated by wiring `replay_evaluate()` into `/v1/defer/{defer_id}/inject` endpoint, making `confidence_score` required field with NaN validator, returning 409 Conflict for sub-threshold injections, and splitting SSE events: `DEFER_PARKED` vs `DEFER_RESOLVED` for audit accuracy. Remediation commit: `fix(defer)!: enforce Phase-3 confidence recheck on token injection`. Test coverage: 6 new test cases in `tests/test_defer_queue.py`. | 2026-08-28 |
| CAGE-SEC-004 | AC-3 / SI-7 | **NARROW Verdict Transport Architectural Gap** — discovered 2026-08-28 by Miracle Owolabi (external security researcher, OWASP AI Exchange Author). NARROW verdicts computed narrowed params but Envoy `OkHttpResponse` proto has no body field. Unclamped requests forwarded to upstream. Currently fails-safe (seal mismatch) but feature incomplete. NARROW feature non-functional in ext_authz deployments. Requests executed with original (unclamped) parameters despite NARROW verdict. Remediated by implementing receipt-based transport using Redis fetch-and-burn pattern: receipt keyed by seal prefix (`narrow:receipt:{seal[:32]}`), MCP server fetches and burns receipt before execution, signature verification prevents receipt forgery, 5-minute TTL prevents receipt leakage. Remediation commit: `feat(narrow)!: implement receipt-based NARROW verdict transport`. Test coverage: 9 new test cases in `tests/test_narrow_transport.py`. | 2026-08-28 |
| POAM-2026-072 | AC-3 / SC-4 | Two-Stage Execution Boundary (ADR-008 Phase 1 & 2) — remediated by ActuatorRegistry ([`src/gateway/governance/execution_actuator.py`](../src/gateway/governance/execution_actuator.py)) & BrokerActuator wiring in [`src/cage_finance/tools/tool_provider.py`](../src/cage_finance/tools/tool_provider.py)). OSCAL AU-10/AU-12 updates completed in compliance/oscal/sp800-53-component-definition.yaml documenting RawMessageSigner protocol abstraction and multi-vendor KMS lifecycle management. | 2026-09-14 |
| POAM-2026-073 | AC-4 | ~~Semantic classifier boundary enforcement (`allow_extra_fields=False`) — remediated by FTRA boundary validation schema hardening~~ **Claim withdrawn 2026-10-01:** no `ActionSchema` was ever registered, so this remediation never ran. The FTRA semantic validator was deleted in `refactor/ftra-scope` (Phase 7), and AC-4 was removed from the US_FED control metadata and from the FTRA OSCAL component, which is restated as `ftra0001-4e47-bbc8-irreversibility01`. Its SI-10 statement now cites value validation by the STPA UCA rules and domain OPA ([`FTRA_SCOPE.md`](governance/FTRA_SCOPE.md)), verified by the OSCAL export and [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py). AC-4 remains claimed only for NetworkPolicy flow enforcement (`deployment/k8s/`). | 2026-09-14 (withdrawn 2026-10-01) |
| POAM-2026-074 | SI-10 | Multi-component input validation (NeMo Guardrails + FTRA integration) — remediated by [`src/gateway/governance/ftra/`](../src/gateway/governance/ftra/) package integration | 2026-09-14 |
| POAM-2026-024 | CM-6 / AC-3 / AU-10 / SC-8 / SC-23 | ✅ **CLOSED — Sprint 6 client-governor interaction formal verification complete.** TLA+ LangGraph harness specification extended with client SDK session lifecycle states (`Active`, `ParkedForReview`, `PausedBudgetExceeded`, `Completed`), consecutive denial budget enforcement (`MaxConsecutiveDenials = 2`), and single-use deferral ticket invariant (`SingleUseDeferralTicket`). OSCAL component definition created at [`compliance/oscal/components/cage_client_sdk.yaml`](../compliance/oscal/components/cage_client_sdk.yaml) mapping AC-3 (out-of-process PDP client mediation), AU-10 (W3C traceparent and HMAC routing seal validation), SC-8 (mTLS HTTP/2 transport), and SC-23 (routing seal micro-TTL validation). TLA+ model checker parameters documented in [`proof/README.md`](../proof/README.md). Verified against staging environment with formal verification proof model showing `BudgetNeverExceededWithoutPause` invariant holds: `(consecutive_denials > MaxConsecutiveDenials) => (phase = "PausedBudgetExceeded")`. Verification commit: `<pending-squash-merge-sha>`. **Note 2026-10-03:** the 2026-09-18 verification claim was vacuous. `LangGraphHarness.tla` never loaded in TLC (its cfg named constants the spec lacked and its actions left variables unassigned), the session states above were unreachable from `Init`, and `SingleUseDeferralTicket` was a tautology. It is superseded by the POAM-2026-091 verification (#380), which models the code's per-turn pause (`HARD_PAUSE_BUDGET_EXCEEDED` once a refusal brings `consecutive_denials` to 2) instead of the session states, and by POAM-2026-093, the defect the check found. | 2026-09-18 |
| POAM-2026-075 | AC-3 / IA-2 / IA-3 | ✅ **CLOSED — Strict fail-closed workload identity ingress enforcement complete.** BREAKING CHANGE: Removed X-Agent-ID and X-SPIFFE-ID HTTP header parsing. All public inference and AGW ingress endpoints now enforce Linkerd mTLS workload identity authentication and caller identity extraction (`l5d-client-id`) via [`src/gateway/server/workload_identity.py`](../src/gateway/server/workload_identity.py) (`WorkloadIdentityMiddleware` and `extract_client_identity`). Requests without a valid workload identity fail closed (403/401). Agent-to-Agent (A2A) authorization implemented via SPIFFE namespace prefix matching in [`config/opa/agent_catalog.rego`](../config/opa/agent_catalog.rego): subagents declare `authorized_parent_prefixes` arrays enabling hierarchical trust delegation without enumerating every parent SPIFFE ID. OPA evaluation uses `startswith(parent_spiffe, prefix)` for declarative A2A authorization. Vendor-neutral DPoP ProofOfPossessionValidator protocol added to [`src/gateway/server/dpop_validator.py`](../src/gateway/server/dpop_validator.py) for RFC 9449 token binding (mTLS certificate thumbprint validation). OSCAL AC-3, IA-2, and IA-3 control mappings updated in [`compliance/oscal/sp800-53-component-definition.yaml`](../compliance/oscal/sp800-53-component-definition.yaml). Test coverage: [`tests/test_inference_proxy_extended.py`](../tests/test_inference_proxy_extended.py) validates fail-closed authentication, identity extraction, and 401 rejection paths. Remediation commit: `feat(gateway)!: replace X-Agent-ID header parsing with native SPIFFE extraction`. | 2026-09-22 |
| POAM-2026-079 | AC-2 / AC-6 / SC-12 | ✅ **CLOSED — Per-workload identity partition, authoritative key-level KMS policies, and full removal of governance signing/refinement from the advisor complete.** Each workload runs as its own Kubernetes ServiceAccount (`cage-gateway-sa`, `cage-advisor-sa`, `cage-reconciler-sa`, `cage-compliance-bridge-sa`, `cage-vllm-sa`, `cage-langfuse-sa`, `cage-agentsight-ui-sa`, `cage-benchmark-sa` in [`deployment/k8s/service-account.yaml`](../deployment/k8s/service-account.yaml)) bound 1:1 via Workload Identity to a dedicated GCP service account ([`infra/targets/gcp-gke/iam.tf`](../infra/targets/gcp-gke/iam.tf)). Each KMS signing key (`gateway-seal`, `reconciler-snapshot`, `compliance-evidence`, `benchmark-signing` in [`infra/targets/gcp-gke/kms_signing.tf`](../infra/targets/gcp-gke/kms_signing.tf)) uses an authoritative `google_kms_crypto_key_iam_policy` granting `roles/cloudkms.signer` to a single owning workload SA only. The advisor's in-process governor, NeMo refinement endpoints, `DeferQueue`, `KMS_GOVERNANCE_KEY`, `CAGE_SEAL_ENFORCEMENT`, and `GOVERNANCE_SALT` have been completely removed from `src/governed_financial_advisor/`; all governance evaluation, post-HITL revalidation, trade execution, and refinement run exclusively inside the gateway, and the advisor never receives a seal. Update (2026-10-01): approval custody moved to `DeferQueue` (`validate_action` runs `Profile.DRY_RUN` and mints no seal, parking `REQUIRE_APPROVAL` as `DeferReason.HITL_REQUIRED` and returning `deferred_id`, consumed atomically via `DeferQueue.consume_approval` inside `enforce_approved_governance`). Verified by [`tests/infrastructure/test_workload_identity_partition.py`](../tests/infrastructure/test_workload_identity_partition.py), [`tests/test_trade_governance_e2e.py`](../tests/test_trade_governance_e2e.py), and [`compliance/lula/lula-validation-ac2.yaml`](../compliance/lula/lula-validation-ac2.yaml). Remediation commits: `e0f7700`, `b2369c6`, `f566e9e`, `9d5d61a`. | 2026-09-27 (updated 2026-10-01) |
| POAM-2026-080 | IA-9 / AC-3 / SC-8 | ✅ **CLOSED — Linkerd mTLS + `WorkloadIdentityMiddleware` ingress authentication, Google CAS trust anchor, and retirement of `CAGE_ROUTING_SEAL_SECRET` complete.** [`WorkloadIdentityMiddleware`](../src/gateway/server/workload_identity.py) is the outermost gateway middleware in [`src/gateway/server/hybrid_server.py`](../src/gateway/server/hybrid_server.py), enforcing `CAGE_TRUSTED_CLIENT_IDENTITIES` (`cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local`) across all environments (`dev`, `test`, `ci`, `production`). At the mesh layer, [`infra/modules/gateway/mesh-policy`](../infra/modules/gateway/mesh-policy) and [`deployment/k8s/linkerd-mtls-policy.yaml`](../deployment/k8s/linkerd-mtls-policy.yaml) enforce `Server`, `HTTPRoute`, `AuthorizationPolicy`, and `MeshTLSAuthentication` rules, while [`infra/modules/service_mesh`](../infra/modules/service_mesh) provisions a Google CAS root CA trust anchor and cert-manager `GoogleCASClusterIssuer` (with CEL subject/SAN constraints). `enforce_routing_seal()`, `X-CAGE-Routing-Seal`, `CAGE_ROUTING_SEAL_SECRET`, `spiffe_extractor.py`, `agent_gateway_adapter.py`, and the legacy Cloud Run Terraform target have been deleted. Verified by [`tests/test_workload_identity_middleware.py`](../tests/test_workload_identity_middleware.py), [`tests/test_gateway_mesh_policy.py`](../tests/test_gateway_mesh_policy.py), [`tests/integration/test_linkerd_mesh_conformance.py`](../tests/integration/test_linkerd_mesh_conformance.py) (automated in CI `mesh-conformance` job), [`tests/live/test_cas_mesh_issuer_live.py`](../tests/live/test_cas_mesh_issuer_live.py), and [`compliance/lula/lula-validation-ac3.yaml`](../compliance/lula/lula-validation-ac3.yaml) / [`compliance/lula/lula-validation-sc8.yaml`](../compliance/lula/lula-validation-sc8.yaml). Remediation commits: `8df072e`, `f566e9e`, `420854f`. | 2026-09-27 |
| POAM-2026-081 | SI-10 / AC-3 / SI-7 | ✅ **CLOSED — Strict consensus critic vote parsing, pinned gateway prompt fields, and fail-closed magnitude/status validation across kernel and domain tiers complete.** Replaced substring vote matching in [`src/gateway/governance/consensus/engine.py`](../src/gateway/governance/consensus/engine.py) with `_parse_critic_vote()` (handling leading `<think>…</think>` blocks, rejecting unclosed `<think>` as `ERROR`, parsing enum-constrained JSON or line-prefix whole-word `APPROVE`/`REJECT`/`ESCALATE` tokens with `REJECT` precedence, and requesting `response_format` JSON schema). Added `context_keys: tuple[str, ...] = ()` to [`CriticSpec`](../src/gateway/governance/contracts.py) and all three domain [`critics.yaml`](../src/cage_finance/config/critics.yaml) configurations, formatted non-reserved parameters as RFC 8785 canonical JSON inside `<params_json>...</params_json>`, and pinned `role`, `action`, `action_type`, and `magnitude` from gateway-owned values instead of `setdefault`. Hardened `check_consensus()` and [`ConsensusTierPlugin`](../src/cage_finance/tiers/consensus_tier.py), [`ClinicalConsensusTier`](../src/cage_healthcare/tiers/clinical_consensus_tier.py), and [`PhysicalSafetyConsensusTier`](../src/cage_physical_ai/tiers/physical_consensus_tier.py) to fail closed (`DENY` / `ViolationKind.HARD`) on invalid/bool/non-finite/negative magnitudes, non-dict results, unknown/`None` statuses, or missing consensus engines, and removed the unused `quorum` field. Verified by [`tests/cage_finance/test_consensus_gate.py`](../tests/cage_finance/test_consensus_gate.py) and [`tests/test_consensus_config_failclosed.py`](../tests/test_consensus_config_failclosed.py). Remediation commit: `8bdd5b2`. | 2026-09-28 |
| POAM-2026-087 | SI-10 / `CTRL_MRM_004` | ✅ **CLOSED — Settlement-aware O(1) CBF debit ledger and absolute discrepancy floor merged in the same release (D6).** The reconciled CBF no longer prunes debits per poll through a local sequence: [`debit_ledger.py`](../src/gateway/governance/safety/debit_ledger.py) keeps every admitted debit in `cbf:debits` / `cbf:debits:by_time` / `cbf:debits:total` and settles it only after a signed snapshot attests `settled_through` (or `verified_at − settlement_lag_seconds`), minus `settlement_clock_skew_seconds`; [`LUA_ATOMIC_CBF`](../src/gateway/governance/safety/cbf_engine.py) nets `scalar − total` inside the fence CAS and refuses with `SNAPSHOT_CHANGED` if the published snapshot is not byte-identical to the verified one; rollback is exact and idempotent by `debit_id`; previews are debit-aware; the discrepancy guard is `max(ratio·|baseline|, floor)` from `ReconciliationThresholds` ([`thresholds.py`](../src/gateway/governance/schemas/thresholds.py)) and is settlement-aware. Design: [ADR-010](adr/ADR-010-settlement-aware-debit-ledger.md). Verified by [`tests/test_cbf_settlement_ledger.py`](../tests/test_cbf_settlement_ledger.py) and [`tests/test_reconciliation_discrepancy_floor.py`](../tests/test_reconciliation_discrepancy_floor.py); `make test-fast` on `main` at `980e1ace` (5988 passed, 99 skipped) and OSCAL SSP export + [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) (50 passed) on 2026-10-02. Remediation commits: `ea92089e` (#345, discrepancy floor), `980e1ace` (#346, ledger). Known limitation (ADR-010 §4): the skew margin must exceed commit-to-custodian latency. | 2026-10-02 |
| POAM-2026-088 | SI-10 / `CTRL_MRM_004` | ✅ **CLOSED — The causal tier runs on live telemetry and denies with distinct HARD codes (D3).** `create_finance_tiers` wires `get_telemetry_provider()` into [`CausalTierPlugin`](../src/cage_finance/tiers/causal_tier.py), which fetches live rows per evaluation off the event loop; [`CausalGatekeeper.evaluate()`](../src/gateway/governance/causal/gatekeeper.py) returns `CausalDecision(safe, reason)` and the tier maps it to `CAUSAL_TELEMETRY_UNAVAILABLE` (no live rows or provider error), `CAUSAL_INSUFFICIENT_SAMPLES` (below `causal.min_samples`, default 50) or `CAUSAL_CHECK_FAILED`; enforcing postures never substitute synthetic data; the Langfuse provider ([`provider.py`](../src/integrations/telemetry_langfuse/provider.py)) returns its real rows with each trace's `timestamp`. No DEFER bootstrap (tracked as WS-C2). Verified by [`tests/test_causal_tier_telemetry.py`](../tests/test_causal_tier_telemetry.py) and [`tests/test_telemetry_provider.py`](../tests/test_telemetry_provider.py); `make test-fast` on `main` at `0f7c00a9` (6008 passed, 99 skipped) and OSCAL SSP export + [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) (50 passed) on 2026-10-02. Remediation commit: `0f7c00a9` (#349). | 2026-10-02 |
| POAM-2026-089 | AC-3 / IA-5 | ✅ **CLOSED — Routing seal verified before its nonce is consumed (D1); `ConsequenceGateway` prose corrected (D2).** [`verify_and_consume_seal()`](../src/gateway/governance/routing_seal.py) now runs verify → burn → execute, so a forged JWT carrying a known nonce can no longer burn a genuine seal; the atomic `SET NX EX` consume and the execute-only-after-winning rule are unchanged. `AGENTS.md`, ADR-008, the architecture docs and [`component-definition.yaml`](../compliance/oscal/component-definition.yaml) name `verify_and_consume_seal()` + `ActuatorRegistry` as the execution boundary and `ConsequenceGateway` as the normative-token boundary. Verified by [`tests/test_routing_seal_security.py`](../tests/test_routing_seal_security.py) (forgery, 20-way concurrency and Redis-failure cases); `make test-fast` on `main` at `0f7c00a9` (6008 passed, 99 skipped) and OSCAL SSP export + [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) (50 passed) on 2026-10-02. Remediation commit: `9e40dade` (#348). | 2026-10-02 |
| POAM-2026-090 | CA-7 / SA-11 | ✅ **CLOSED — Distributed-CBF model checks under TLC and models stale-replica failover.** [`proof/distributed_cbf_model.py`](../proof/distributed_cbf_model.py) and [`proof/DistributedCBF.tla`](../proof/DistributedCBF.tla) transliterate the `cbf_engine.py` protocol including `StaleFailover`; the shipped posture (reconciled + `WAIT 1`) holds SP-1/SP-2/SP-4 (1,945 states at N=2), and the `_nosync` / `_selfreported` negative controls fail as expected. TLC v1.7.4 and the BFS agree on all four cfgs ([`scripts/verify_tla.py`](../scripts/verify_tla.py)); counts pinned by [`tests/test_distributed_cbf_proof.py`](../tests/test_distributed_cbf_proof.py); published `proof/model.py` counts corrected to 38/19/35/36 (EU_ECB 42). `make test-fast` on the branch (6034 passed, 100 skipped); on `main` at `e3f1f7ff`, TLC on the shipped cfg and OSCAL SSP export + [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) passed on 2026-10-02. Residuals: self-reported-mode defects (dev-only) noted in the detail section; unchecked sibling specs tracked as POAM-2026-091. Remediation commit: `e3f1f7ff` (#351). | 2026-10-02 |
| POAM-2026-091 | CA-7 / SA-11 | ✅ **CLOSED — FtraBoundary and LangGraphHarness model-check under TLC.** Both specs were rewritten against HEAD: [`proof/FtraBoundary.tla`](../proof/FtraBoundary.tla) models one request through the in-graph `ftra_node` and the unconditional controller `FtraStage`; [`proof/LangGraphHarness.tla`](../proof/LangGraphHarness.tla) models one advisor thread over three turns plus the DeferQueue tickets it parks. Every action assigns every variable; no invariant was weakened. Shipped cfgs hold every invariant (FtraBoundary 8,272 distinct states with `EveryRequestTerminates` under fairness; `_nonetpol` 8,756; LangGraphHarness 82,652). Negative controls fail as expected: `FtraBoundary_noboundary` (13,792) violates `NoUnreviewedIrreversibleExecution`, `ControllerBoundaryCoversInGraphBypass` and `ControllerBoundaryUnconditional`; `LangGraphHarness_unguarded` (906) violates `SingleUseDeferralTicket`. Pinned in [`proof/tla_pins.py`](../proof/tla_pins.py), run by [`scripts/verify_tla.py`](../scripts/verify_tla.py), parity-checked by [`tests/test_tla_specs_proof.py`](../tests/test_tla_specs_proof.py). Checking `SingleUseDeferralTicket` against the code found POAM-2026-093. `make test-fast` on the branch: 6080 passed, 105 skipped, 1 failed (`test_gfa_nodes_coverage.py::test_circuit_breaker_fires_at_loop_count_3`, which fails identically at the merge base `7d359c80`: 6054 passed, 100 skipped, 1 failed); OSCAL SSP export + [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) (50 passed) on 2026-10-03. Remediation: #380. | 2026-10-03 |
| POAM-2026-092 | SI-10 / `CTRL_MRM_004` | ✅ **CLOSED — Only debits confirmed after execution settle.** The settlement-aware ledger stamped `submitted_at` at CBF commit, before actuation, so a debit could settle before the custodian carried it whenever commit-to-custodian latency exceeded `settlement_clock_skew_seconds`. A commit now enters `cbf:debits:pending`; `confirm()` (run by the governor only after the action executed) moves it to `cbf:debits:by_time` stamped at confirm, and `LUA_SETTLE_DEBITS` settles only confirmed debits, promoting unconfirmed ones after `reconciliation.pending_debit_max_age_seconds` (600 s). Evidence: [`tests/test_cbf_settlement_ledger.py`](../tests/test_cbf_settlement_ledger.py), [`tests/governor/test_commit_receipts.py`](../tests/governor/test_commit_receipts.py); `make test-fast` on `main` at `e1a9687f` (6037 passed, 100 skipped) and OSCAL SSP export + [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) (50 passed) on 2026-10-03. Remediation commit: `42ee97a5` (#359). | 2026-10-03 |
| POAM-2026-093 | AC-3 / SI-10 | ✅ **CLOSED — A DeferQueue token resolves at most once.** Found and fixed on 2026-10-03 while model-checking POAM-2026-091. `replay_evaluate` (the compliance bridge's `POST /v1/defer/{id}/inject`) and `_resolve` compared only the token revision, never its status, so an inject re-resolved a token that was already `INJECTED`, quorum-approved (`ESCALATED`, which the bridge's reason gates let through for a 2/2 `HITL_REQUIRED` token) or `CONSUMED`, and `expire_stale` could overwrite a quorum approval between `approve()`'s CAS and its `zrem`. The approval itself was never double-spent (`consume_approval` needs `ESCALATED` and is an atomic CAS). [`defer_queue.py`](../src/gateway/governance/defer_queue.py) now refuses any resolution not allowed by `_RESOLVABLE_FROM` (inject only from `PARKED`; expiry or escalation only from `PARKED` / `PARTIALLY_APPROVED`), `replay_evaluate` returns `ReplayResult.ALREADY_RESOLVED`, and the bridge maps it to HTTP 409 `DEFER_TOKEN_ALREADY_RESOLVED`. Evidence: [`tests/test_defer_queue_single_use.py`](../tests/test_defer_queue_single_use.py) (9 tests; 8 fail without the fix) and the `LangGraphHarness_unguarded` negative control. `make test-fast` on the branch: 6080 passed, 105 skipped, 1 failed (`test_gfa_nodes_coverage.py::test_circuit_breaker_fires_at_loop_count_3`, which fails identically at the merge base `7d359c80`: 6054 passed, 100 skipped, 1 failed); Remediation: #380. | 2026-10-03 |

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
| `lula-validation-eu-fria.yaml` | EU AI Act | Art. 27 FRIA Gating | EU_ECB |
| `lula-validation-gdpr-art22.yaml` | GDPR | Art. 22 Automated Decisions | EU_ECB |
| `lula-validation-mas-feat.yaml` | MAS FEAT | Fairness/Ethics/Accountability/Transparency | APAC_MAS |
| `lula-validation-mas-notice655.yaml` | MAS Notice 655 | Technology Risk Management | APAC_MAS |
| `lula-validation-mas-trm-s6.yaml` | MAS TRM | §6.3 AI/ML Controls | APAC_MAS |
| `lula-validation-ftra.yaml` | OWASP AISVS | C9 FTRA Reachability Registry Integrity | Universal |
| `lula-validation-cilium-dpv2.yaml` | NIST SP 800-53 | SC-7 Boundary Protection (GKE Dataplane V2) | US_FED |

---

## Contributing to Remediation

Contributors who wish to help close open findings should:

1. Reference the POAM ID in the commit message (e.g., `fix(compliance): add vulnerability scan CronJob [POAM-2026-010]`)
2. Run `lula validate` against the relevant manifest on a live cluster
3. Update this document with the closure date and commit SHA
4. Update the corresponding OSCAL component in `compliance/oscal/` within 2 business days of merge

See [CONTRIBUTING.md](../CONTRIBUTING.md) and the compliance validation guide in `compliance/lula/` for details.

### POAM-2026-073: Re-verification of Decoupled Governance Post-Refactoring

**Control:** ISO 42001 A.5.2, A.5.3, A.8.4, NIST SC-4
**Risk Level:** Medium
**Status:** Open
**Date Opened:** 2026-08-30
**Target Closure:** 2026-09-06

**Description:**
The CAGE Layered Refactoring (PRs 1-4) restructured governance boundaries, invalidating closure evidence for seven previous POAMs:
- POAM-2026-023: Evidence cites relocated governance path
- POAM-2026-056: Evidence cites `fiscal_limit_guard.py` pre-move
- POAM-2026-057: Tier-sequencing assertion affected by registry
- POAM-2026-058: Rollback atomicity affected by D6 rewrite
- POAM-2026-067: STPA-derived control affected by source split
- POAM-2026-069: OPA policy-path evidence affected
- POAM-2026-070: Plugin-boundary/isolation evidence newly applicable

**Remediation Plan:**
1. Re-run Lula validation for all affected controls in the GKE staging environment.
2. Verify formal proof assertions still align with the loaded plugin sequence.
3. Attach updated `lula-validation` execution logs proving the newly decoupled pipeline preserves all gating criteria.

### POAM-2026-076: Physical-AI Safety Barriers Declared but Not Enforced

**Control:** NIST SI-10, ISO 42001 A.6.2.6
**Risk Level:** Moderate
**Status:** Open
**Date Opened:** 2026-09-26
**Target Closure:** 2026-12-31

**Description:**
`src/cage_physical_ai/invariants.py` declares `SpatialSeparationBarrier`, `KinematicVelocityBarrier` and `TorqueSaturationBarrier`, but no cost resolver maps a physical action to its effect on those state variables, and `ControlBarrierFunction` accepts a single invariant. `create_physical_ai_tiers()` therefore builds `KinematicBarrierTier(cbf=None)`. That tier now fails closed: `evaluate()` and `commit()` return a HARD `KINEMATIC_BARRIER_UNCONFIGURED` violation, so every action in `PHYSICAL_AI_GOVERNED_ACTIONS` is denied. Before this change the tier returned no violations and allowed the action.

**Remediation Plan:**
1. Make the CBF engine invariant-parametric (governor refactor plan §4b.1).
2. Define domain cost resolvers (action → Δseparation, Δvelocity, Δtorque) from a cell-specific ISO/TS 15066 risk assessment.
3. Build `KinematicBarrierTier` with a CBF over all three barriers and add tests observing each barrier refuse.

### POAM-2026-077: Physical-AI Domain Cannot Be Activated (Healthcare Remediated)

**Control:** NIST CM-6, SC-24
**Risk Level:** Moderate
**Status:** Open (partially remediated 2026-09-30 — healthcare runnable; physical-AI open)
**Date Opened:** 2026-09-26
**Target Closure:** 2026-12-31

**Description:**
A CAGE process now runs exactly one domain, named by the required `CAGE_DOMAIN` environment variable ([`env_posture.py`](../src/gateway/governance/env_posture.py)). The kernel reads its FTRA terminal registry and causal graph only from the active plugin's `DomainConfig` ([`contracts.py`](../src/gateway/governance/contracts.py), [`plugin_loader.py`](../src/gateway/governance/plugin_loader.py)). Previously the FTRA classifier and causal gatekeeper silently read finance's registry and causal graph whatever domain was loaded. [`src/cage_physical_ai/plugin.py`](../src/cage_physical_ai/plugin.py) ships no FTRA registry, so it declares `domain_config = None` and `domain_config_of()` refuses to start it. This is fail-closed: no domain runs under another domain's reachability model.

**Progress (2026-09-30):** [`src/cage_healthcare/plugin.py`](../src/cage_healthcare/plugin.py) now declares a `DomainConfig`: its own FTRA registry ([`terminal_registry.json`](../src/cage_healthcare/config/ftra/terminal_registry.json), 7 actions, all `IRREVERSIBLE_TERMINAL`, no autonomous envelope, signed `manifest_sha256`), `opa_package="dosing.governance"` / `opa_required_rules=("allow",)`, and its causal graph. `REGISTERED_ACTIONS` in [`constants.py`](../src/cage_healthcare/constants.py) matches the registry (`scripts/check_ftra_registry_staleness.py --domain src.cage_healthcare.constants --registry src/cage_healthcare/config/ftra/terminal_registry.json --strict` passes). Startup is covered by `tests/test_plugin_loader.py::test_healthcare_is_runnable_and_declares_existing_config`. Healthcare's `dose_barrier` is re-checked under POST_HITL now that stage selection is structural (`stage_runs_under`).

**Remediation Plan (remaining):**
1. Author an FTRA terminal registry for physical-AI under `src/cage_physical_ai/config/`.
2. Author a causal graph where the domain's tiers need one, or leave `causal_graph_path=None` (the causal check then fails closed).
3. Declare `DomainConfig` on the physical-AI plugin and add a startup test; add a per-domain CI matrix (PR 4a).

### POAM-2026-078: Contributed Invariants Validated but Not Enforced

**Control:** NIST SI-10, SA-8
**Risk Level:** Moderate
**Status:** Open
**Date Opened:** 2026-09-26
**Target Closure:** 2026-12-31

**Description:**
Domain plugins now hand their CBF barriers to the kernel as data (`PluginContribution.invariants`, [`contracts.py`](../src/gateway/governance/contracts.py)). The composition root [`assemble_governor()`](../src/gateway/governance/governor/assembly.py) validates every contributed invariant against V1-V4 across all domains (`invariants.validate_invariant`) and records them on the immutable `GovernorComponents.invariants`; an invalid or duplicate invariant refuses startup. The CBF engine ([`cbf_engine.py`](../src/gateway/governance/safety/cbf_engine.py)) still takes a single invariant at construction, so only finance's `CashBarrier` is enforced (it is also passed directly to finance's CBF). The healthcare and physical-AI barriers are validated but not enforced; their barrier tiers are built without a CBF and fail closed (DENY), see POAM-2026-076 and POAM-2026-077.

**Remediation Plan:**
1. Make the CBF engine invariant-parametric and consume `GovernorComponents.invariants` (governor refactor plan §4b.1).
2. Add tests observing each contributed barrier refuse an unsafe action.

### POAM-2026-079: Shared Workload Identity and Keyring-Scope KMS Grants

**Control:** NIST AC-2, AC-6, SC-12
**Risk Level:** High
**Status:** Closed
**Date Opened:** 2026-09-27
**Date Closed:** 2026-09-27

**Closure Summary:**
1. Partitioned Kubernetes and GCP service accounts 1:1 per workload (`cage-gateway-sa`, `cage-advisor-sa`, `cage-reconciler-sa`, `cage-compliance-bridge-sa`, `cage-vllm-sa`, `cage-langfuse-sa`, `cage-agentsight-ui-sa`, `cage-benchmark-sa`) in [`deployment/k8s/service-account.yaml`](../deployment/k8s/service-account.yaml) and [`infra/targets/gcp-gke/iam.tf`](../infra/targets/gcp-gke/iam.tf).
2. Provisioned four dedicated asymmetric KMS signing keys (`gateway-seal`, `reconciler-snapshot`, `compliance-evidence`, `benchmark-signing`) with authoritative key-level `google_kms_crypto_key_iam_policy` resources in [`infra/targets/gcp-gke/kms_signing.tf`](../infra/targets/gcp-gke/kms_signing.tf).
3. Removed the advisor's in-process governor, `KMS_GOVERNANCE_KEY`, `CAGE_SEAL_ENFORCEMENT`, `GOVERNANCE_SALT`, NeMo refinement endpoints, and `DeferQueue` from `src/governed_financial_advisor/`; all governance evaluation, post-HITL revalidation, trade execution, and refinement run exclusively inside the gateway, and the advisor never receives a seal.
4. Approval custody moved to `DeferQueue` (2026-10-01, commit `9d5d61a`): `SymbolicGovernor.validate_action()` runs under `Profile.DRY_RUN` and mints no seal; `REQUIRE_APPROVAL` parks a `DeferToken` (`DeferReason.HITL_REQUIRED`) in `DeferQueue` returning `deferred_id`, approved via `DeferQueue.approve()` (with server-stamped `approved_barrier_preview`) and consumed atomically once by `execute_trade_action(..., deferred_id=...)` via `DeferQueue.consume_approval()` inside `enforce_approved_governance()` (`src/gateway/server/governance_middleware.py`).
5. Verified by [`tests/infrastructure/test_workload_identity_partition.py`](../tests/infrastructure/test_workload_identity_partition.py), [`tests/test_trade_governance_e2e.py`](../tests/test_trade_governance_e2e.py), and [`compliance/lula/lula-validation-ac2.yaml`](../compliance/lula/lula-validation-ac2.yaml). Remediation commits: `e0f7700`, `b2369c6`, `f566e9e`, `9d5d61a`.

### POAM-2026-080: GatewayClient Ingress Authentication Gap

**Control:** NIST IA-9, AC-3, SC-8
**Risk Level:** High
**Status:** Closed
**Date Opened:** 2026-09-27
**Date Closed:** 2026-09-27

**Closure Summary:**
1. [`WorkloadIdentityMiddleware`](../src/gateway/server/workload_identity.py) is the outermost gateway middleware ([`hybrid_server.py`](../src/gateway/server/hybrid_server.py)). It is deny-by-default across all environments (`dev`, `test`, `ci`, `production`) and admits non-open routes only when a single Linkerd-verified `l5d-client-id` header matches `CAGE_TRUSTED_CLIENT_IDENTITIES` (`cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local`).
2. At the mesh layer, [`infra/modules/gateway/mesh-policy`](../infra/modules/gateway/mesh-policy) and [`deployment/k8s/linkerd-mtls-policy.yaml`](../deployment/k8s/linkerd-mtls-policy.yaml) define `Server`, `HTTPRoute`, `AuthorizationPolicy`, and `MeshTLSAuthentication` resources restricting gated gateway routes to `cage-advisor-sa`. [`infra/modules/service_mesh`](../infra/modules/service_mesh) provisions a Google CAS root CA trust anchor and cert-manager `GoogleCASClusterIssuer` with CEL subject/SAN constraints (`identity.linkerd.cluster.local`) so no CA private key enters Terraform state.
3. Retired `enforce_routing_seal()`, `X-CAGE-Routing-Seal`, `CAGE_ROUTING_SEAL_SECRET`, `spiffe_extractor.py`, `agent_gateway_adapter.py`, and the legacy Cloud Run Terraform target.
4. Verified by [`tests/test_workload_identity_middleware.py`](../tests/test_workload_identity_middleware.py), [`tests/test_gateway_mesh_policy.py`](../tests/test_gateway_mesh_policy.py), [`tests/integration/test_linkerd_mesh_conformance.py`](../tests/integration/test_linkerd_mesh_conformance.py) (automated on `kind` + Linkerd in CI `mesh-conformance`), and [`tests/live/test_cas_mesh_issuer_live.py`](../tests/live/test_cas_mesh_issuer_live.py) (live Google CAS issuance). OSCAL SC-8, AC-3, and SC-12 updated to `implemented`. Remediation commits: `8df072e`, `f566e9e`, `420854f`.

### POAM-2026-081: Consensus Gate Fail-Open Vote Parser & Prompt Placeholder Override

**Control:** NIST SI-10, AC-3, SI-7
**Risk Level:** High
**Status:** Closed
**Date Opened:** 2026-09-28
**Date Closed:** 2026-09-28

**Closure Summary:**
1. Replaced substring critic vote matching in [`src/gateway/governance/consensus/engine.py`](../src/gateway/governance/consensus/engine.py) with `_parse_critic_vote()` supporting leading `<think>…</think>` stripping (rejecting unclosed `<think>` as `ERROR`), strict JSON (`{"decision": "APPROVE" | "REJECT" | "ESCALATE", "reason": "..."}`) and line-prefix whole-word token parsing with whole-word `REJECT` precedence, and `response_format` JSON schema requests on both LLM client paths.
2. Added `context_keys: tuple[str, ...] = ()` to [`CriticSpec`](../src/gateway/governance/contracts.py) and all three domain [`critics.yaml`](../src/cage_finance/config/critics.yaml) files, formatted non-reserved parameters as RFC 8785 canonical JSON inside `<params_json>...</params_json>`, and pinned `role`, `action`, `action_type`, and `magnitude` from gateway-owned values so caller parameters cannot overwrite trusted prompt placeholders.
3. Hardened `ConsensusGate.check_consensus()` and [`ConsensusTierPlugin`](../src/cage_finance/tiers/consensus_tier.py), [`ClinicalConsensusTier`](../src/cage_healthcare/tiers/clinical_consensus_tier.py), and [`PhysicalSafetyConsensusTier`](../src/cage_physical_ai/tiers/physical_consensus_tier.py) to fail closed (`DENY` / `ViolationKind.HARD`) on invalid/bool/non-finite/negative magnitudes, non-dict results, unknown/`None` statuses, or missing consensus engines, and removed the unused `quorum` field.
4. Verified by [`tests/cage_finance/test_consensus_gate.py`](../tests/cage_finance/test_consensus_gate.py), [`tests/test_consensus_config_failclosed.py`](../tests/test_consensus_config_failclosed.py), and [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py). Remediation commit: `8bdd5b2`.

### POAM-2026-082: Hugging Face Hub Token Exposure in vLLM Image Config, Cloud Build, and Terraform State

**Control:** NIST IA-5, SC-7, SC-28
**Risk Level:** High
**Status:** Open
**Date Opened:** 2026-09-28
**Target Closure:** 2026-10-05

**Description:**
Five coupled defects exposed `HUGGING_FACE_HUB_TOKEN` and prevented vLLM from loading model weights on GKE:
1. [`deployment/docker/Dockerfile.vllm`](../deployment/docker/Dockerfile.vllm) declared `ARG HF_TOKEN=""` and `ENV HUGGING_FACE_HUB_TOKEN=${HF_TOKEN}`, persisting the token in the container image configuration despite a comment claiming it was not baked in.
2. [`deployment/docker/cloudbuild.vllm.yaml`](../deployment/docker/cloudbuild.vllm.yaml) and [`scripts/build_images.sh`](../scripts/build_images.sh) passed `_HF_TOKEN` as a plaintext Cloud Build substitution visible to anyone with build-viewer permissions, even though the image build only runs `pip install`.
3. [`infra/modules/app_secrets/main.tf`](../infra/modules/app_secrets/main.tf) stored `hf_token` in Terraform state and created `hf-token-secret`, which [`infra/modules/governed_advisor/main.tf`](../infra/modules/governed_advisor/main.tf) mounted into the advisor pod even though no code in `src/` reads it.
4. `default-deny-external-egress` in [`infra/targets/gcp-gke/network_policy.tf`](../infra/targets/gcp-gke/network_policy.tf) blocked all external egress for `vllm-inference` and `vllm-reasoning` pods (including GKE Workload Identity metadata server `169.254.169.254:80` / `169.254.169.252:988` and GCS `storage.googleapis.com:443`), and `local.fqdn_network_policies` was only hashed into `terraform_data.network_policy_workload_rollout` without a `kubernetes_manifest` resource to materialize the `FQDNNetworkPolicy` objects in the cluster.
5. [`infra/targets/gcp-gke/main.tf`](../infra/targets/gcp-gke/main.tf) set `vllm_load_format = "gcs_filesystem"` (an invalid vLLM loader name instead of `"runai_streamer"`), omitted `--load-format $VLLM_LOAD_FORMAT` and `--served-model-name $SERVED_MODEL_NAME` from `vllm_command`, and defaulted `model_fast` / `model_reasoning` to bare Hugging Face Hub IDs instead of `gs://` paths in the model bucket.

**Remediation Plan:**
1. **(Completed in code/IaC)** Removed `ARG HF_TOKEN` / `ENV HUGGING_FACE_HUB_TOKEN` from [`deployment/docker/Dockerfile.vllm`](../deployment/docker/Dockerfile.vllm), `_HF_TOKEN` from [`deployment/docker/cloudbuild.vllm.yaml`](../deployment/docker/cloudbuild.vllm.yaml) and [`scripts/build_images.sh`](../scripts/build_images.sh), and `hf_token` / `hf-token-secret` from [`infra/modules/app_secrets/`](../infra/modules/app_secrets/main.tf), [`infra/modules/governed_advisor/main.tf`](../infra/modules/governed_advisor/main.tf), [`infra/targets/gcp-gke/`](../infra/targets/gcp-gke/variables.tf), [`infra/targets/agnostic/`](../infra/targets/agnostic/variables.tf), [`deploy_all.sh`](../deploy_all.sh), and [`infra/load_env.sh`](../infra/load_env.sh).
2. **(Completed in code/IaC)** Configured all GKE postures to load `model_fast` and `model_reasoning` from `gs://` paths in the model bucket via `vllm_load_format = "runai_streamer"`, passing `--load-format $VLLM_LOAD_FORMAT` and `--served-model-name $SERVED_MODEL_NAME` with `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1` in [`infra/modules/vllm_inference/`](../infra/modules/vllm_inference/main.tf) and [`infra/targets/gcp-gke/main.tf`](../infra/targets/gcp-gke/main.tf).
3. **(Completed in code/IaC)** Added `kubernetes_network_policy_v1.vllm_egress_l3_l4` (DNS + GKE metadata server `169.254.169.254:80` and `169.254.169.252:988`), added `vllm_egress_fqdn` (`storage.googleapis.com` and `oauth2.googleapis.com` on TCP 443) to `local.fqdn_network_policies` and [`deployment/k8s/cilium/egress-lockdown.yaml`](../deployment/k8s/cilium/egress-lockdown.yaml), and materialized `local.fqdn_network_policies` via `kubernetes_manifest.fqdn_network_policy` in [`infra/targets/gcp-gke/network_policy.tf`](../infra/targets/gcp-gke/network_policy.tf).
4. **(Pending operator action required before closure)** Rotate the exposed Hugging Face token on `huggingface.co` and delete all historical `gcr.io/$PROJECT_ID/vllm-streamer` image digests that contain `ENV HUGGING_FACE_HUB_TOKEN` in their image configuration.
### POAM-2026-083: GKE Image Digest Pinning and Binary Authorization Attestation Chain (Follow-on to POAM-2026-013)

**Control:** NIST SI-2, SI-3, SI-7, CM-7
**Risk Level:** High
**Status:** Open
**Date Opened:** 2026-09-28
**Target Closure:** 2026-10-15

**Description:**
While `POAM-2026-013` pinned third-party image tags in `deployment/k8s/`, the sole GKE Terraform target ([`infra/targets/gcp-gke/main.tf`](../infra/targets/gcp-gke/main.tf)) and Cloud Build configurations ([`deployment/docker/`](../deployment/docker/)) still defaulted to `:latest` tags, and `google_binary_authorization_attestor.build_attestor` in [`infra/targets/gcp-gke/perimeter.tf`](../infra/targets/gcp-gke/perimeter.tf) declared no `public_keys` block or signing step. Consequently, enabling `enable_binary_authorization = true` with `evaluation_mode = "REQUIRE_ATTESTATION"` and `enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"` caused GKE Binary Authorization admission to reject every workload pod.

**Root Cause Analysis (2026-10-01 Staging Rollout):**
1. **Cloud Build Identity Mismatch (P1):** Key-level IAM on `google_kms_crypto_key.binauthz_attestor`, `google_binary_authorization_attestor.build_attestor`, and `google_container_analysis_note.build_attestor_note` was bound to the legacy Cloud Build service account (`[PROJECT_NUMBER]@cloudbuild.gserviceaccount.com`), whereas projects created after May 2023 execute builds without an explicit `serviceAccount:` as the Compute Engine default service account (`[PROJECT_NUMBER]-compute@developer.gserviceaccount.com`) — which is also the GKE node identity and must never hold `roles/cloudkms.signer` on the Binary Authorization attestor key.
2. **GA vs. Beta `gcloud` Track & Duplication (P2):** `sign-and-create` exists only under `gcloud beta container binauthz attestations sign-and-create` (and `alpha`), not the GA `gcloud container binauthz attestations` track. Because the inline shell snippet was duplicated across 10 files (`deployment/docker/cloudbuild.*.yaml`, [`scripts/build_images.sh`](../scripts/build_images.sh), and [`scripts/mirror_and_attest_images.sh`](../scripts/mirror_and_attest_images.sh)) without a post-signing verification check, every automated attestation step failed on the CLI track mismatch.

**Break-Glass Record (2026-10-01):**
- commits `ad9ba9c7` (`gateway`) and `8d2ccf03` (`compliance-bridge`) were attested manually by an operator on `2026-10-01` while P1/P2 blocked in-build signing. These digests are superseded once all images are rebuilt and attested by `cage-cloudbuild-staging` under PR-2.

**Remediation Implemented in Code & IaC:**
1. Provisioned an asymmetric Cloud KMS signing key (`google_kms_crypto_key.binauthz_attestor` in [`infra/targets/gcp-gke/kms_signing.tf`](../infra/targets/gcp-gke/kms_signing.tf)) with authoritative key-level IAM granting `roles/cloudkms.signer` exclusively to `local.cloudbuild_member`, and wired its public key into `google_binary_authorization_attestor.build_attestor` via `public_keys { pkix_public_key { ... } }` in [`infra/targets/gcp-gke/perimeter.tf`](../infra/targets/gcp-gke/perimeter.tf).
2. Replaced all `:latest` image references across [`infra/targets/gcp-gke/main.tf`](../infra/targets/gcp-gke/main.tf), [`infra/targets/gcp-gke/variables.tf`](../infra/targets/gcp-gke/variables.tf), and [`deployment/docker/`](../deployment/docker/) with `var.image_digests` (`name -> repo@sha256:<64-hex>`), backed by a fail-closed Terraform `validation` block rejecting tag-only or `:latest` references when `enable_binary_authorization = true`.
3. **(PR-2 — `fix/cloudbuild-identity`)** Provisioned a dedicated, least-privilege Cloud Build service account (`google_service_account.cloudbuild`, `cage-cloudbuild-${var.environment}`) in [`infra/targets/gcp-gke/iam.tf`](../infra/targets/gcp-gke/iam.tf) with `roles/logging.logWriter`, `roles/artifactregistry.writer`, and bucket-scoped `roles/storage.objectViewer` on `${var.project_id}_cloudbuild`, plus `roles/containeranalysis.notes.occurrences.viewer` in [`infra/targets/gcp-gke/perimeter.tf`](../infra/targets/gcp-gke/perimeter.tf), and repointed `local.cloudbuild_member` in [`infra/targets/gcp-gke/kms_signing.tf`](../infra/targets/gcp-gke/kms_signing.tf) so the authoritative KMS policy revokes the legacy `@cloudbuild.gserviceaccount.com` binding automatically.
4. **(PR-2 — `fix/cloudbuild-identity`)** Consolidated all 10 inline attestation snippets into a single fail-closed script ([`scripts/attest_image.sh`](../scripts/attest_image.sh)) that invokes `gcloud beta container binauthz attestations sign-and-create` and verifies the created occurrence via `gcloud beta container binauthz attestations list`, and replaced the per-service duplicate configs with [`deployment/docker/cloudbuild.image.yaml`](../deployment/docker/cloudbuild.image.yaml) and [`scripts/render_image_digests.sh`](../scripts/render_image_digests.sh).
5. Updated [`compliance/lula/lula-validation-si2.yaml`](../compliance/lula/lula-validation-si2.yaml) to validate `@sha256:` digest pinning and `imagePullPolicy in {"Always", "IfNotPresent"}` across all Terraform-managed Deployments (`gateway`, `governed-financial-advisor`, `vllm-inference`, `vllm-reasoning`, `nemo-guardrails`, `agentsight-ui`, and optional `compliance-bridge`), and updated the OSCAL SI-3 narrative in [`src/gateway/governance/oscal_ssp_exporter.py`](../src/gateway/governance/oscal_ssp_exporter.py) and [`compliance/oscal/system-security-plan.yaml`](../compliance/oscal/system-security-plan.yaml).

**Remaining Closure Criteria:**
1. Every image digest referenced by [`infra/targets/gcp-gke/staging.tfvars`](../infra/targets/gcp-gke/staging.tfvars) carries a Binary Authorization attestation whose creator is `cage-cloudbuild-staging@<project>.iam.gserviceaccount.com`; zero manual `sign-and-create` executions since PR-2.
2. Confirm all pods in `governance-stack` pass Binary Authorization admission and record live `lula validate -f compliance/lula/lula-validation-si2.yaml` evidence.

### POAM-2026-084: FRIA Declared but Never Enforced (EU_ECB)

**Control:** EU AI Act Art. 27 (`CTRL_FRIA_006`), NIST SI-10
**Risk Level:** High
**Status:** Open (remediated in `refactor/fria-jurisdiction`, pending merge)
**Date Opened:** 2026-10-01
**Target Closure:** 2026-10-15

**Description:**
From `v2.0.0-dev.1` (commit `1902c92`, 2026-06-01) until `refactor/fria-jurisdiction`, the Fundamental Rights Impact Assessment existed only as the `enforce_fria_boundary()` primitive in `normative_provider.py`. `run_pipeline()` never called it, and no other in-tree caller did. No EU_ECB decision therefore consulted an impact assessment or the normative provider's `validate_fria()`, even though `CTRL_FRIA_006` was listed as an EU_ECB control. The primitive also let an action through on model confidence ≥ 0.95 without any assessment. The universal confidence band was misnamed "FRIA" (`fria.zone_allow` / `fria.zone_defer`) in every region.

**Remediation Implemented in Code:**
1. The `fria` tier ([`FriaTier`](../src/gateway/governance/jurisdiction/eu_ai_act/fria_tier.py)) is contributed only by the EU_ECB entry of [`JURISDICTIONS`](../src/gateway/governance/jurisdiction/registry.py) and assembled by [`assemble_governor()`](../src/gateway/governance/governor/assembly.py) as a phase-1 tier after `causal`. It denies when the deployer's FRIA artefact is stale or missing (Art. 27(2), 365-day interval), and when the provider is unavailable, times out or refuses. It requires approval on a `needs_human_review` finding. There is no confidence fast path.
2. `assert_production_posture()` ([`posture.py`](../src/gateway/governance/governor/posture.py)) refuses an enforcing EU_ECB posture backed by the stub `NormativeProvider` (`jurisdiction_requirements` check).
3. `enforce_fria_boundary()` and `FRIAEnforcementResult` are deleted. The universal band is renamed `confidence.agent_threshold` / `confidence.defer_floor` ([`BREAKING_CHANGES_v3.md`](BREAKING_CHANGES_v3.md) P6-1).
4. `ControlRegistry.reconfigure()` no longer resets `active_region` to the default after loading a region. Without this fix, a reconfigured EU_ECB registry would have assembled without the `fria` tier.
5. Verified by [`tests/governor/test_jurisdiction_wiring.py`](../tests/governor/test_jurisdiction_wiring.py), which observes each fail-closed path failing, and by the `JURISDICTION_TIERS` sub-proof in [`proof/model.py`](../proof/model.py), with parity in [`tests/test_formal_profile_parity.py`](../tests/test_formal_profile_parity.py). [`compliance/lula/lula-validation-eu-fria.yaml`](../compliance/lula/lula-validation-eu-fria.yaml) now also asserts `CAGE_DEPLOYMENT_REGION=EU_ECB`.

**Remaining Closure Criteria:**
1. Merge `refactor/fria-jurisdiction`; record the merge commit SHA and the actual merge date here.
2. Independent external FRIA validation remains tracked by EU-001 (provider credentials).

### POAM-2026-085: Causal Gatekeeper Cache Bypassed the Risk Boundary

**Control:** NIST SI-10, `CTRL_MRM_004` (model risk management)
**Risk Level:** High
**Status:** Open (remediated in `refactor/ftra-scope`, pending merge)
**Date Opened:** 2026-10-01
**Target Closure:** 2026-10-15

**Description:**
The causal gatekeeper cached its whole verdict per `(action, context)`. The verdict included the per-request risk-boundary check, which depends on the trade's parameters. A cached ALLOW for a small trade was therefore replayed for a trade of any size, skipping `CAUSAL_LOCK_RISK_BOUNDARY`, and a cached DENY denied small trades. Exposure required Redis and `cache_ttl_seconds > 0` (default 60) and lasted one TTL window per cache entry.

**Remediation Implemented in Code:**
1. [`gatekeeper.py`](../src/gateway/governance/causal/gatekeeper.py) caches only the params-independent `WorldModelVerdict` (refutation beta and placebo verdict), keyed by causal-spec fingerprint, action and context, and only for synthetic-factory telemetry. Explicit telemetry is never cached.
2. The risk boundary is evaluated on every request, cached or not.
3. Verified by [`tests/test_causal_world_model_cache.py`](../tests/test_causal_world_model_cache.py) (`TestRiskBoundaryIsPerRequest`), which observes a large trade denied after a small one was admitted from the cache. Lula: not applicable (no Kubernetes resource changed).

**Remaining Closure Criteria:**
1. Merge `refactor/ftra-scope`; record the merge commit SHA and the actual merge date here.

### POAM-2026-086: Memorystore Managed Private CA Unpinned in Gateway and Compliance Bridge

**Control:** NIST SP 800-53 SC-8 (Transmission Confidentiality and Integrity), SC-8(1)
**Risk Level:** High
**Status:** Open (remediated in `fix/memorystore-ca-pinning`, pending live staging rollout and Lula SC-8 validation)
**Date Opened:** 2026-10-01
**Target Closure:** 2026-10-15

**Description:**
[`infra/modules/memorystore/main.tf`](../infra/modules/memorystore/main.tf) exported `managed_server_ca` (the Google-managed private CA PEM certificates from `google_memorystore_instance.this.managed_server_ca[0].ca_certs[*].certificates`), and [`infra/modules/gateway/variables.tf`](../infra/modules/gateway/variables.tf) and [`infra/modules/compliance_bridge/variables.tf`](../infra/modules/compliance_bridge/variables.tf) declared `redis_ca_cert_path`, but [`infra/targets/gcp-gke/main.tf`](../infra/targets/gcp-gke/main.tf) never wired the two together. Neither module created a `ConfigMap`, volume, or `volumeMount`. With `enable_memorystore_tls = true` (`REDIS_TLS=true`), [`redis_client.py`](../src/gateway/infrastructure/redis_client.py) enforced `ssl_cert_reqs=ssl.CERT_REQUIRED` against the container's default Mozilla CA bundle (`certifi`), which does not include Memorystore's per-instance Google-managed private CA. Consequently, `start_evidence_sink()` failed on startup with `SSLCertVerificationError: certificate verify failed: self-signed certificate in certificate chain`, leaving `EVIDENCE_CHAIN_BLOCKING=true` fail-closed and `deploy/gateway` `0/1 Ready`.

**Remediation Implemented in Code:**
1. Replaced the dangling `redis_ca_cert_path` variable with `redis_ca_pem` (`string`, default `""`) in [`infra/modules/gateway/variables.tf`](../infra/modules/gateway/variables.tf) and [`infra/modules/compliance_bridge/variables.tf`](../infra/modules/compliance_bridge/variables.tf).
2. In [`infra/modules/gateway/main.tf`](../infra/modules/gateway/main.tf) and [`infra/modules/compliance_bridge/main.tf`](../infra/modules/compliance_bridge/main.tf), when `var.redis_ca_pem != ""`: created `kubernetes_config_map_v1.redis_ca` (`gateway-redis-ca` / `compliance-bridge-redis-ca` with key `ca.pem`), mounted it read-only at `/etc/cage/tls/redis`, set `REDIS_CA_CERT_PATH=/etc/cage/tls/redis/ca.pem`, added pod-template annotation `cage.io/redis-ca-sha256 = sha256(var.redis_ca_pem)` so CA rotation triggers a rolling restart, set `revision_history_limit = 3`, and added a `lifecycle.precondition` requiring `redis_ca_pem` to be non-empty whenever `enable_redis_tls = true`.
3. Wired `redis_ca_pem = var.enable_memorystore_tls ? join("\n", module.memorystore_governance.managed_server_ca) : ""` into both `module.gateway` and `module.compliance_bridge` in [`infra/targets/gcp-gke/main.tf`](../infra/targets/gcp-gke/main.tf), and added a `precondition` asserting `length(module.memorystore_governance.managed_server_ca) > 0` when `var.enable_memorystore_tls` is true.
4. Added Check 5 (`redis_ca_pinned`) to [`compliance/lula/lula-validation-sc8.yaml`](../compliance/lula/lula-validation-sc8.yaml) and static regression gates in [`tests/infrastructure/test_evidence_custody_wiring.py`](../tests/infrastructure/test_evidence_custody_wiring.py).
5. **(PR-4 — `fix/redis-tls-one-rule`)** Unified Redis TLS certificate verification in [`src/gateway/infrastructure/redis_client.py`](../src/gateway/infrastructure/redis_client.py) into `resolve_redis_tls(use_tls)`, enforcing `ssl.CERT_REQUIRED` under every enforcing posture (`is_enforcing()`, including `staging` and `production`) or whenever a readable `REDIS_CA_CERT_PATH` exists, across both the module-level client and `build_async_redis()`. Verified by [`tests/test_redis_async_builder.py`](../tests/test_redis_async_builder.py).

**Remaining Closure Criteria:**
1. Apply Terraform on `cage-staging`, verify `deploy/gateway` reaches `1/1 Ready` with `cert_reqs=REQUIRED` and `EvidenceStream` connected, and record the commit SHA, live `lula validate -f compliance/lula/lula-validation-sc8.yaml` result, and closure date.

### POAM-2026-087: Settlement-Lag Double-Spend Window in the Reconciled CBF Ledger

**Control:** NIST SI-10, `CTRL_MRM_004` (model risk management)
**Risk Level:** High
**Status:** ✅ Closed 2026-10-02 — WS-B merged as `ea92089e` (#345) and WS-A as `980e1ace` (#346) in the same release (D6). See [ADR-010](adr/ADR-010-settlement-aware-debit-ledger.md) (Accepted).
**Date Opened:** 2026-10-02
**Target Closure:** 2026-10-16

**Description:**
In reconciled mode the CBF nets the KMS-verified custodian balance against a Redis list of local debits (`cbf:local_debits`). The list is pruned by the reconciler on every poll ([`daemon.py`](../src/gateway/governance/reconciliation/daemon.py), `_write_verified_balance`) through a "sequence" that is a local Redis `INCR` when replay defence is on, or `0` when it is off (the default). Nothing ties that number to whether the custodian has settled the trade. The commit path in [`cbf_engine.py`](../src/gateway/governance/safety/cbf_engine.py) (`atomic_verify_and_commit`) sums only the debits whose sequence **equals** the current snapshot's, so a committed debit disappears from the effective balance the moment the next snapshot is readable, whether or not that snapshot reflects it. A trade can therefore be counted against the balance twice: once in the custodian's eventual snapshot and never in between. The window is up to one poll interval (`RECONCILIATION_POLL_INTERVAL_SECONDS`, default 60 s) per trade. Aggravating facts: the rollback script removes the newest amount-equal entry rather than the committed debit (`commit_barrier` passes no identifier); `verify_action` and `admissible_cost` read the raw scalar and ignore outstanding debits, so NARROW bounds and HITL previews can over-promise; the only backstop is the discrepancy guard, an inline `0.5·|baseline|` with no absolute floor and no entry in `config/governance_thresholds.json`; and `SimulatedSource.record_debit()` has no caller, so the shipped simulation cannot exhibit the defect. The effective-balance sum is O(L) in Python over one `LRANGE`, and rollback/trim are O(L) blocking Lua scripts.

**Remediation (merged; verified 2026-10-02):**
1. **Discrepancy guard** (`ea92089e`, #345): `ReconciliationThresholds` in [`thresholds.py`](../src/gateway/governance/schemas/thresholds.py) (`discrepancy_ratio`, `discrepancy_abs_floor`, `settlement_lag_seconds`, `settlement_clock_skew_seconds`) with env overrides; the daemon uses `max(ratio·|baseline|, floor)`. WS-A then made the guard settlement-aware: the compared delta is the distance outside `[baseline, baseline + unsettled]` ([`unsettled_total_sync`](../src/gateway/governance/safety/debit_ledger.py)), and the `finance.cash_balance` baseline key was corrected from the stale `safety:cash_balance` to the barrier's `safety:current_cash`.
2. **Settlement-aware ledger** (`980e1ace`, #346): [`debit_ledger.py`](../src/gateway/governance/safety/debit_ledger.py) replaces the list with `cbf:debits` (HASH by `debit_id`), `cbf:debits:by_time` (ZSET by `submitted_at`), `cbf:debits:total` and `cbf:debits:rolled_back` (tombstones). [`LUA_ATOMIC_CBF`](../src/gateway/governance/safety/cbf_engine.py) nets `scalar − total` inside the same script as the fence CAS, after checking that the published snapshot is byte-identical to the one Python verified (`SNAPSHOT_CHANGED` otherwise), and ledgers every admitted debit. `debit_id` is minted in `commit_barrier`, carried in `CommitReceipt.token`, and used by an exact, idempotent O(1) rollback (`ROLLED_BACK` / `ROLLED_BACK_SETTLED` / `NOOP`), including the `WAIT`-timeout rollback. Debits are settled by `settle_debits_sync()` only after a signed snapshot is published and only up to `min(settled_through, verified_at) − skew` (`settled_through` is new in `GroundTruthSnapshot` / `ReconciliationResult` and is part of `snapshot_signing_payload`), or `verified_at − settlement_lag_seconds − skew` when the provider does not attest; `cbf:debits:total` is recomputed from the HASH on every settle.
3. **Previews are debit-aware:** `_read_cbf_state_atomic` reads the total before the snapshot and returns the netted `current_cash`, so `verify_action`, `admissible_cost` and the barrier preview agree with the commit.
4. **Simulated custodian that settles:** `SimulatedSource(journal, settlement_lag_s)` with `RedisLedgerJournal` (`sim:ledger:{invariant_id}`) selected by `CAGE_SIM_LEDGER_BACKEND=redis` and `CAGE_SIM_SETTLEMENT_LAG_SECONDS` (both set in [`gateway.yaml`](../deployment/k8s/gateway.yaml) and [`reconciliation-worker.yaml`](../deployment/k8s/reconciliation-worker.yaml)); [`BrokerActuator`](../src/cage_finance/actuators/broker_actuator.py) journals each accepted fill under the clearance nonce and fails closed (`CUSTODIAN_JOURNAL_FAILED`) if it cannot; `FaultMode.SETTLEMENT_STALL` freezes the attestation.
5. **Fail-closed tests** in [`tests/test_cbf_settlement_ledger.py`](../tests/test_cbf_settlement_ledger.py) (22 tests, all observing the blocked path): lagging-ledger double spend denied; no settlement before attestation; skew margin delays settlement and covers commit-to-custodian latency up to exactly `skew`; rollback exact and idempotent; rollback after settlement restores once; `WAIT`-timeout rollback removes its own debit; drift corrected on settle; constant round-trips on commit (10 vs 1 000 debits); preview headroom equals commit headroom; previews never touch the ledger; settlement stall fails closed; tampered `settled_through` fails signature verification; snapshot replaced mid-flight refused; guard band tolerates unsettled debits but not external moves; actuator journals the fill and refuses when the journal fails. [`test_cbf_durability.py`](../tests/test_cbf_durability.py), [`test_memorystore_failover.py`](../tests/infrastructure/test_memorystore_failover.py) and [`test_cbf_reconciliation.py`](../tests/cage_finance/test_cbf_reconciliation.py) were rewritten against the new keys.
6. **Verification on the branch (2026-10-02):** `rg -n 'local_debits|trim_local_debits|reconciliation_sequence' src/` returns nothing; Gate G3 green; `make test-fast` green; the STPA Safety Validator component in [`sp800-53-component-definition.yaml`](../compliance/oscal/sp800-53-component-definition.yaml) now states the ledger control and points at `src/gateway/governance/safety/cbf_engine.py` (the three stale single-file `safety.py` references are gone); `uv run python -m src.gateway.governance.oscal_ssp_exporter export` passes [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py).

**Closure Verification (2026-10-02):**
1. Both workstreams squash-merged to `main` in the same release: `ea92089e` (#345) then `980e1ace` (#346).
2. `make test-fast` on `main` at `980e1ace`: 5988 passed, 99 skipped.
3. `uv run python -m src.gateway.governance.oscal_ssp_exporter export` succeeded and [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) passed (50 tests).
4. Residual limitation carried forward (not a closure blocker): the ledger stamps `submitted_at` at CBF commit, so `settlement_clock_skew_seconds` must exceed commit-to-custodian latency (ADR-010 §4). Tracked and remediated as POAM-2026-092: only debits confirmed after execution settle.

### POAM-2026-088: Causal Gatekeeper Inoperative in Enforcing Posture

**Control:** NIST SI-10, `CTRL_MRM_004` (model risk management)
**Risk Level:** High
**Status:** ✅ Closed 2026-10-02 — WS-C merged as `0f7c00a9` (#349).
**Date Opened:** 2026-10-02
**Target Closure:** 2026-10-16

**Description:**
[`CausalTierPlugin.evaluate()`](../src/cage_finance/tiers/causal_tier.py) calls the gatekeeper with no telemetry, and `get_telemetry_provider()` in [`telemetry_provider.py`](../src/gateway/governance/telemetry_provider.py) has no caller anywhere in `src/`. In enforcing postures [`CausalGatekeeper.causal_safety_check()`](../src/gateway/governance/causal/gatekeeper.py) refuses synthetic substitution and fails closed before it counts samples, so every `execute_trade` under `CAGE_DOMAIN=finance` is denied with the generic `CAUSAL_CHECK_FAILED`. The sample-adequacy gate (`causal.min_samples`, default 50) is never reached, there is no bootstrap behaviour, and the condition is indistinguishable in evidence from a genuine refutation failure. In `dev`/`test`/`ci` the gatekeeper substitutes 1 000 synthetic rows and always passes, which is why no test observed the production deadlock. The fixture in [`tests/test_causal_gatekeeper.py`](../tests/test_causal_gatekeeper.py) (`_create_mock_governor`) builds a telemetry provider and never passes it. *(Correction 2026-10-02: this finding originally said the OSCAL SI-10 statement describes the causal gatekeeper; neither OSCAL component definition mentions it at all, so a statement was added instead — see item 6.)*

**Remediation (merged; verified 2026-10-02 — decision D3: deny, do not defer):**
1. Kernel: treat an empty telemetry frame like `None` for synthetic substitution (`NullTelemetryProvider` returns an empty `DataFrame`); add a structured `CausalDecision(safe, reason)` so the tier can see *why* the check failed. Enforcing posture still fails closed.
2. Tier: `CausalTierPlugin(telemetry_provider=…)` fetches `get_latest_data(max(min_samples, 500))` per request (off the event loop; a provider exception is `CAUSAL_TELEMETRY_UNAVAILABLE`) and maps reasons to distinct HARD codes: `CAUSAL_INSUFFICIENT_SAMPLES` (below `causal.min_samples`), `CAUSAL_TELEMETRY_UNAVAILABLE` (no live telemetry in enforcing posture), else `CAUSAL_CHECK_FAILED`. `create_finance_tiers` constructs the tier with `get_telemetry_provider()`.
3. Provider: the Langfuse provider ([`provider.py`](../src/integrations/telemetry_langfuse/provider.py)) returns the rows it has below `MIN_SAMPLES` instead of silently substituting the fallback, so the gatekeeper is the single observable decision point. It now also emits each trace's `timestamp`: without it the gatekeeper's freshness check failed every live frame as stale, so the refuter was unreachable even with enough rows.
4. A DEFER-based bootstrap is explicitly **not** implemented: `ClassificationEngine` only emits DEFER together with low confidence, no re-evaluation path exists in `DeferQueue`, and `proof/model.py` does not model DEFER. It is tracked as follow-up WS-C2 with those three prerequisites.
5. Fail-closed tests in [`tests/test_causal_tier_telemetry.py`](../tests/test_causal_tier_telemetry.py) (14): enforcing posture with the null provider, or with no provider, is denied with `CAUSAL_TELEMETRY_UNAVAILABLE`; a provider exception likewise; 30 live rows are denied with `CAUSAL_INSUFFICIENT_SAMPLES`; 60 live rows reach the refuter (ALLOW on a stable model) and a breached risk boundary keeps `CAUSAL_CHECK_FAILED`; dev posture with an empty frame uses synthetic telemetry; a non-empty frame is never overridden; `create_finance_tiers` wires the resolved provider and fails at assembly for `remote` without credentials. The dead fixture in `tests/test_causal_gatekeeper.py` now passes its provider; [`tests/test_telemetry_provider.py`](../tests/test_telemetry_provider.py) pins the real-rows and timestamp behaviour.
6. Docs and compliance: [`CAUSAL_AND_CBF_GOVERNANCE.md`](governance/CAUSAL_AND_CBF_GOVERNANCE.md) gains "Telemetry Wiring and Violation Codes" and the corrected `min_samples` default (50, not 30); the STPA Safety Validator RA-3 statement in [`sp800-53-component-definition.yaml`](../compliance/oscal/sp800-53-component-definition.yaml) now describes the causal gatekeeper, the bootstrap deny and the distinct codes.

**Closure Verification (2026-10-02):**
1. Squash-merged to `main` as `0f7c00a9` (#349).
2. `make test-fast` on `main` at `0f7c00a9`: 6008 passed, 99 skipped.
3. `uv run python -m src.gateway.governance.oscal_ssp_exporter export` succeeded and [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) passed (50 tests).
4. Carried forward (not a closure blocker): DEFER-based bootstrap (WS-C2); `get_telemetry_provider()` selects `remote` from `TELEMETRY_*` credentials while `LangfuseTelemetryProvider.from_env` reads `LANGFUSE_*`.

### POAM-2026-089: Routing-Seal Nonce Burned Before Signature Verification

**Control:** NIST AC-3 (Access Enforcement), IA-5 (Authenticator Management)
**Risk Level:** Low
**Status:** ✅ Closed 2026-10-02 — WS-D merged as `9e40dade` (#348).
**Date Opened:** 2026-10-02
**Target Closure:** 2026-10-16

**Description:**
[`verify_and_consume_seal()`](../src/gateway/governance/routing_seal.py) decodes the seal with `verify_signature=False`, burns the nonce with the atomic `SET NX EX` script, and only then calls `verify_seal()`. The TOCTOU property this ordering was written for comes from the atomic consume plus the rule "execute only after winning the consume", and holds under either order. Burning an unverified nonce, however, lets any caller who can reach the function and knows a nonce burn a legitimate seal with a forged JWT; the legitimate request then fails as a replay. The exposure is narrow: the seal is `governance_result`, minted and consumed inside the gateway process ([`tool_provider.py`](../src/cage_finance/tools/tool_provider.py)), and the advisor only ever submits a `deferred_id` (POAM-2026-079), so the nonce never leaves the gateway. Separately, `AGENTS.md`, [ADR-008](adr/ADR-008-wire-phantom-gates-into-production-call-paths.md) and the OSCAL component definition describe `ConsequenceGateway` as the mandatory execution boundary, while it has no call site on the governor ALLOW path; the live boundary is `verify_and_consume_seal()` plus `ActuatorRegistry`.

**Remediation (merged; verified 2026-10-02 — decisions D1, D2):**
1. Reorder to verify → burn → execute. `verify_seal()` is stateless (the JWKS set is cached after a one-time KMS fetch), so no steady-state I/O moves ahead of the burn.
2. Rewrite the docstring and the "nonce remains burned" comments to state the real invariant.
3. Prose: `AGENTS.md` and ADR-008 name `verify_and_consume_seal()` + `ActuatorRegistry` as the execution boundary and `ConsequenceGateway` as the single-use boundary for normative-provider `ConsequenceToken`s; delete the placeholder comment in `tool_provider.py`; correct `compliance/oscal/component-definition.yaml`; note in the FRIA tier that findings on an admitted result (including a token) are dropped.
4. Fail-closed tests in [`tests/test_routing_seal_security.py`](../tests/test_routing_seal_security.py): `test_failed_verification_does_not_burn_nonce` (three forgeries carrying a victim's nonce — unknown `kid`, valid `kid` with a foreign signature, genuine key with a mismatched action — each raises and leaves `dbsize() == 0`, after which the genuine seal consumes; all three failed against the old order); `test_concurrent_valid_replays_exactly_one_wins` (20 concurrent presentations → exactly one `True`, 19 `already consumed`); `test_redis_failure_after_valid_verification_fails_closed`.
5. Prose corrected in `AGENTS.md`, ADR-008 (correction note, implementation-status lines), `GATEWAY_ARCHITECTURE.md`, `ARCHITECTURE.md`, `SYMBOLIC_GOVERNOR_RUNTIME.md`, `NON_FORMATION_PROOF_SPEC.md` (order stated; line anchors refreshed) and `compliance/oscal/component-definition.yaml` (three ConsequenceGateway statements); the placeholder in `tool_provider.py` is deleted, the `trade_executor.py` refusal message names the real boundary, and [`fria_tier.py`](../src/gateway/governance/jurisdiction/eu_ai_act/fria_tier.py) documents that admission findings (including a token) are dropped.

**Closure Verification (2026-10-02):**
1. Squash-merged to `main` as `9e40dade` (#348); the OSCAL ConsequenceGateway wording shipped in the same commit (no AC-3 statement elsewhere describes the consumption order).
2. `make test-fast` on `main` at `0f7c00a9` (which contains `9e40dade`): 6008 passed, 99 skipped.
3. `uv run python -m src.gateway.governance.oscal_ssp_exporter export` succeeded and [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) passed (50 tests).

### POAM-2026-090: Distributed-CBF Formal Model Cannot Be Checked and Omits the Stale-Replica Regression

**Control:** NIST CA-7 (Continuous Monitoring), SA-11 (Developer Testing and Evaluation)
**Risk Level:** Moderate
**Status:** Closed (2026-10-02)
**Date Opened:** 2026-10-02
**Target Closure:** 2026-10-23

**Description:**
[`proof/DistributedCBF.cfg`](../proof/DistributedCBF.cfg) declares constants `Agents`, `InitialAvailable`, `MaxAmount` and invariants `SP2_ReserveNonNegative`, `SP3_AvailableNonNegative`; [`proof/DistributedCBF.tla`](../proof/DistributedCBF.tla) defines `AgentIDs`, `InitialPool`, `MaxFenceEpoch`, `MaxAgentReserve`, `ReserveAmount` and `SP2_NonNegativeReserves`, `SP3_NonNegativeAvailable`. TLC therefore cannot load the model, `make verify-tla` only prints instructions, and TLC is not in CI. The spec's `Failover` action increments the epoch and releases reservations — a benevolent failover — so the failure mode the runtime actually defends against (a replica promoted with a lower balance and a lower fence epoch) is unmodelled; the runtime's defences for it are `WAIT N` synchronous replication with strict rollback and the in-process `_last_seen_epoch` / Redis HWM pair. The Python BFS pins in `proof/distributed_cbf_model.py` run only under `__main__`. Published state counts for `proof/model.py` are stale in two places and disagree with each other ([`proof/README.md`](../proof/README.md): 42/21/49/39; [`REVISION_TRACKER.md`](paper/REVISION_TRACKER.md): 42/21/39/40); `uv run python proof/model.py` at HEAD yields gated 38 / ungated 19 / DoWhy-absent 35 / EU_ECB 42.

**Remediation (approved design):**
1. Rewrite the cfg to the spec's names; make `make verify-tla` execute TLC when `tla2tools.jar` is available; add a `workflow_dispatch` CI job that caches the jar.
2. Add `rep_balance` / `rep_epoch`, a `SyncReplication` constant, `Replicate`, `StaleFailover` (balance and epoch regress, `agent_epochs` unchanged) and `AgentRestart`; guard reserve/commit on `agent_epochs[a] > fence_epoch`; under `SyncReplication` require `rep_epoch = fence_epoch`. Keep today's benevolent `Failover` as the negative control.
3. Pin the regenerated `EXPECTED_STATE_COUNTS` in a new pytest module `test_distributed_cbf_proof`; add `verdict_of()` and a parity test against `ClassificationEngine` to `proof/model.py`; correct the published counts.

**Remediation (as implemented):**
1. [`proof/distributed_cbf_model.py`](../proof/distributed_cbf_model.py) and [`proof/DistributedCBF.tla`](../proof/DistributedCBF.tla) were rewritten as a line-for-line pair modelling the runtime protocol of [`cbf_engine.py`](../src/gateway/governance/safety/cbf_engine.py): epoch CAS + barrier + ledger write (`LUA_ATOMIC_CBF`), `WAIT`-gated actuation, `LUA_ROLLBACK` including `ROLLED_BACK_SETTLED`, the per-process `_last_seen_epoch`, `Replicate`, `AgentRestart` and `StaleFailover` (balance, epoch and ledger regress; the broker side effect does not). The approved design's benevolent-`Failover` negative control was replaced by three negative-control configurations (`_nosync`, `_selfreported`, `_unfenced`), which isolate each defence.
2. Four cfgs load and run under TLC; [`scripts/verify_tla.py`](../scripts/verify_tla.py) compares TLC output to the Python pins, `make verify-tla` runs it when `TLA_TOOLS_JAR` is set, and [`.github/workflows/tlc-model-check.yml`](../.github/workflows/tlc-model-check.yml) runs it on `workflow_dispatch` against a SHA-256-pinned `tla2tools.jar` v1.7.4.
3. [`tests/test_distributed_cbf_proof.py`](../tests/test_distributed_cbf_proof.py) pins `EXPECTED_STATE_COUNTS` for $N \in \{1,2,3\}$, the counterexamples, cfg/spec/Python constant parity, the `proof/model.py` counts (38/19/42), I-6 as `narrow_valid`, the verdict lattice, and `verdict_of()` parity against `ClassificationEngine`.
4. Published counts corrected in `proof/README.md`, `FORMAL_VERIFICATION.md`, `NON_FORMATION_PROOF_SPEC.md` and `REVISION_TRACKER.md`.

**Results (TLC v1.7.4 and BFS agree at $N = 2$, 2026-10-02):** the shipped posture (reconciled + `WAIT 1`) reaches 1,945 states with SP-1, SP-2 and SP-4 holding; `_nosync` (4,232) and `_selfreported` (1,933) violate SP-1 and SP-2; `_unfenced` (2,536) holds.

**Findings recorded by the remediation:**
- The plan's hypothesis that, without synchronous replication, "SP-1 holds iff no `AgentRestart` precedes `Replicate`" is **false**: a second process, or a rollback re-assigning `_last_seen_epoch` to the regressed epoch, re-admits the lost debit. `WAIT N` with strict rollback is the load-bearing defence.
- In reconciled mode the fence CAS is not needed for SP-1.
- Self-reported mode (refused by `CAGE_CBF_STRICT_MODE` under every enforcing posture) has a fence-epoch ABA and a rollback over-credit through `ROLLED_BACK_SETTLED`. This is a dev-only residual; no fix is in scope here. **Update 2026-10-03:** fixed in `e1a9687f` (#361): the self-reported script reads the live state key, a rollback without a ledger entry credits nothing (`ROLLED_BACK_UNLEDGERED`), and the `_selfreported` cfg was retired as identical to `DistributedCBF` (re-pinned counts: 1,811 / 3,972 / 2,388 at $N = 2$).
- Fixing the other cfgs so their constants load exposed POAM-2026-091.

**Closure Verification (2026-10-02):**
1. Squash-merged to `main` as `e3f1f7ff` (#351); `make test-fast` on the branch: 6034 passed, 100 skipped.
2. On `main` at `e3f1f7ff`: `TLA_TOOLS_JAR=… uv run python scripts/verify_tla.py` reported `DistributedCBF.cfg: TLC (states, SP-1, SP-2) = (1945, True, True); BFS = (1945, True, True)`, and all three negative-control cfgs matched their pins.
3. `uv run python -m src.gateway.governance.oscal_ssp_exporter export` succeeded; [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) and [`tests/test_distributed_cbf_proof.py`](../tests/test_distributed_cbf_proof.py) passed (76 passed, 1 skipped: the live-TLC test, which needs `TLA_TOOLS_JAR`).

### POAM-2026-091: FtraBoundary and LangGraphHarness TLA+ Specifications Have Never Been Model-Checked

**Control:** NIST CA-7 (Continuous Monitoring), SA-11 (Developer Testing and Evaluation)
**Risk Level:** Moderate
**Status:** Closed (2026-10-03)
**Date Opened:** 2026-10-02
**Target Closure:** 2026-11-13

**Description:**
While remediating POAM-2026-090, [`proof/FtraBoundary.cfg`](../proof/FtraBoundary.cfg) and [`proof/LangGraphHarness.cfg`](../proof/LangGraphHarness.cfg) were rewritten so their constants load. TLC then fails both specifications:
- [`proof/FtraBoundary.tla`](../proof/FtraBoundary.tla): the initial state violates `ControllerBoundaryCoversInGraphBypass`.
- [`proof/LangGraphHarness.tla`](../proof/LangGraphHarness.tla): several actions leave `consecutive_denials` and `deferral_resolved` unassigned, so successor states are undefined.

Neither specification had been model-checked before, so their stated invariants, including `SingleUseDeferralTicket` and `BudgetNeverExceededWithoutPause`, are unverified. `proof/README.md` marks both as "not model-checked".

**What was wrong beyond the reported symptoms:**
- *FtraBoundary:* the old spec claimed `market_analysis` was a registered `READ_ONLY` terminal (it is unregistered, so it classifies `IRREVERSIBLE_TERMINAL`), applied the 0.95 allow floor to `EMPTY_STEPS` plans (the node uses a literal 0.70), and stated the bypass invariant over every state, including the initial one. It modelled `bypassed_ftra_node` as a detection; in the code it is a telemetry label, because the controller cannot know whether the in-graph node ran.
- *LangGraphHarness:* the client-SDK session states (`Active`, `ParkedForReview`, `PausedBudgetExceeded`, `Completed`) were unreachable from `Init`. `SingleUseDeferralTicket` was a set tautology, and deferral resolution picked from `1..100`. The graph order was wrong (governance before FTRA), and an FTRA HITL resume could trade in the same turn; in the code it routes to the explainer.

**Remediation (as implemented):**
1. `FtraBoundary.tla` was rewritten as one request's lifecycle through the network policy, the in-graph `ftra_node` and the controller `FtraStage`, with the finance registry, independent registry loads per process, conditional auto-clear (registered terminal, envelope, magnitude inside it, confidence ≥ 0.95) and the in-graph verdict table. `ControllerBoundaryCoversInGraphBypass` is stated over governor phases. New invariants: `ControllerBoundaryUnconditional`, `NoUnreviewedIrreversibleExecution`, `RegistryUnavailableFailsClosed`, `AutoClearOnlyInsideEnvelope`, `HITLRequiredPropagates`, `ParseErrorsPreventClear`; liveness `EveryRequestTerminates` under weak fairness.
2. `LangGraphHarness.tla` was rewritten as one advisor thread over `MaxTurns` turns following `graph.py`, `safety_node.py` and the governed-trader subgraph, plus one DeferQueue ticket per turn (DEFER, FTRA and APPROVAL kinds) changing asynchronously. `BudgetNeverExceededWithoutPause` is checked at the real threshold: a refused turn reports `HARD_PAUSE_BUDGET_EXCEEDED` exactly when `consecutive_denials` ≥ 2. `SingleUseDeferralTicket` bounds each ticket to one resolution and one consumption. New invariants: `RefusedTurnNeverTrades`, `FtraHoldNeverTradesThisTurn`.
3. Negative controls `FtraBoundary_noboundary.cfg` (governor without `FtraStage`) and `LangGraphHarness_unguarded.cfg` (DeferQueue before POAM-2026-093); `FtraBoundary_nonetpol.cfg` shows the controller check alone suffices without the NetworkPolicy.
4. Results are pinned in [`proof/tla_pins.py`](../proof/tla_pins.py) and compared by [`scripts/verify_tla.py`](../scripts/verify_tla.py) (`make verify-tla`, [`.github/workflows/tlc-model-check.yml`](../.github/workflows/tlc-model-check.yml)). [`tests/test_tla_specs_proof.py`](../tests/test_tla_specs_proof.py) checks cfg/spec constant and invariant parity without Java and runs TLC when `TLA_TOOLS_JAR` is set.

**Results (TLC v1.7.4, `-continue`, 2026-10-03):**

| cfg | Distinct states | Result |
|-----|-----------------|--------|
| `FtraBoundary` (shipped; `FairSpec` + `EveryRequestTerminates`) | 8,272 | all invariants hold; liveness holds |
| `FtraBoundary_nonetpol` | 8,756 | all invariants hold |
| `FtraBoundary_noboundary` (negative control) | 13,792 | violates `NoUnreviewedIrreversibleExecution`, `ControllerBoundaryCoversInGraphBypass`, `ControllerBoundaryUnconditional` |
| `LangGraphHarness` (HEAD; 3 turns) | 82,652 | all invariants hold |
| `LangGraphHarness_unguarded` (negative control; 1 turn) | 906 | violates `SingleUseDeferralTicket` |

**Findings recorded by the remediation:**
- `SingleUseDeferralTicket` failed against the code: tracked and fixed as POAM-2026-093.
- The POAM-2026-024 verification claim was vacuous; a dated note on that row records it.
- The consecutive-denial pause ends the turn; it does not lock the thread, and the counter persists in the thread checkpoint. [`cage_client_sdk.yaml`](../compliance/oscal/components/cage_client_sdk.yaml) was corrected accordingly.
- `loop_count` is never reset within a thread, so after three rejected plans every later plan on that thread goes straight to the explainer.
- `ConsistentClassification` holds when both processes load the registry the same way; when only one load fails, the two classifications differ, but both fail closed.
- The NetworkPolicy remains an interim compensating control; the shipped posture does not depend on it (`_nonetpol`).

**Closure Verification (2026-10-03):**
1. `JAVA=… TLA_TOOLS_JAR=… uv run python scripts/verify_tla.py` on the branch reported `OK` for all eight cfgs (three `DistributedCBF`, three `FtraBoundary`, two `LangGraphHarness`), with the counts above.
2. `make test-fast` on the branch: 6080 passed, 105 skipped. One failure, `tests/test_gfa_nodes_coverage.py::TestExecutionAnalystNodeBehavior::test_circuit_breaker_fires_at_loop_count_3`, is order-dependent and pre-existing: it fails identically at the merge base `7d359c80` (6054 passed, 100 skipped, 1 failed) and passes in isolation.
3. `uv run python -m src.gateway.governance.oscal_ssp_exporter export` succeeded; [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) passed (50 passed).
4. Squash-merged to `main` as #380.

### POAM-2026-092: Reconciled CBF Settles Debits the Custodian Does Not Yet Carry

**Control:** NIST SI-10 (Information Input Validation), `CTRL_MRM_004`
**Risk Level:** High
**Status:** Closed (2026-10-03)
**Date Opened:** 2026-10-03
**Target Closure:** 2026-10-17

**Description:**
The settlement-aware ledger (POAM-2026-087, ADR-010) stamped each debit's `submitted_at` when the CBF committed it, which is before the actuator tells the custodian about the fill. The reconciler settles debits stamped at or before `min(settled_through, verified_at) − settlement_clock_skew_seconds`. If the commit-to-custodian latency exceeded the 5 s margin, a debit could be settled while the snapshot did not yet carry it, and the admissible headroom was overstated by that debit until the custodian caught up. The discrepancy guard only catches trades that are large relative to the balance. POAM-2026-087 recorded this as a residual limitation.

**Remediation (implemented):**
1. [`debit_ledger.py`](../src/gateway/governance/safety/debit_ledger.py): a commit enters `cbf:debits:pending`. `LUA_CONFIRM_DEBIT` moves it to `cbf:debits:by_time` stamped with the confirm time. `LUA_SETTLE_DEBITS` settles only `by_time` and promotes pending entries older than `reconciliation.pending_debit_max_age_seconds` (default 600 s, at least the governor's settlement hold) stamped at promotion. `LUA_UNSETTLED_TOTAL` counts every pending debit.
2. [`cbf_engine.py`](../src/gateway/governance/safety/cbf_engine.py): the commit script writes the pending set; rollback clears both sets; new `ControlBarrierFunction.confirm_debit()`.
3. [`barrier_tier.py`](../src/gateway/governance/safety/barrier_tier.py): `confirm_barrier()`; the finance, healthcare and physical-AI barrier tiers call it from ADR-009 `confirm()`, which the governor runs only after the action executed. The multi-engine kinematic tier now keeps each engine's receipt, so rollback and confirm address each engine's own `debit_id` (rollback previously restored by magnitude only and left the ledger entries in place).
4. Tests: `test_unconfirmed_debit_is_never_settled_however_late_the_actuator_runs`, `test_unconfirmed_debit_is_promoted_after_the_max_age`, `test_settle_never_prunes_pending_debits`, `test_pending_max_age_outlasts_the_governor_settlement_hold` ([`tests/test_cbf_settlement_ledger.py`](../tests/test_cbf_settlement_ledger.py)); tier wiring in [`tests/governor/test_commit_receipts.py`](../tests/governor/test_commit_receipts.py).

**Closure Verification (2026-10-03):**
1. Squash-merged to `main` as `42ee97a5` (#359); `make test-fast` on the branch: 6037 passed, 100 skipped.
2. `make test-fast` on `main` at `e1a9687f`: 6037 passed, 100 skipped.
3. `uv run python -m src.gateway.governance.oscal_ssp_exporter export` succeeded; [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) passed (50 passed).

### POAM-2026-093: DeferQueue Tokens Could Be Resolved More Than Once

**Control:** NIST AC-3 (Access Enforcement), SI-10 (Information Input Validation)
**Risk Level:** High
**Status:** Closed (2026-10-03)
**Date Opened:** 2026-10-03
**Target Closure:** 2026-10-03

**Description:**
Found while model-checking `SingleUseDeferralTicket` for POAM-2026-091. [`DeferQueue._resolve`](../src/gateway/governance/defer_queue.py) and `replay_evaluate` checked only the token revision in their CAS, never the token status:
- `POST /v1/defer/{id}/inject` on the compliance bridge ([`main.py`](../src/compliance_bridge/main.py)) re-resolved a token that was already `INJECTED`, already `CONSUMED`, or quorum-approved (`ESCALATED`). The bridge's reason gates reject quorum-3 tokens and partial approvals, but a fully approved 2/2 `HITL_REQUIRED` token passed them.
- `expire_stale` could overwrite a quorum approval with `EXPIRED` in the window between `approve()`'s CAS and its `zrem` from the expiry index.

The approval itself could not be spent twice: `consume_approval` requires `ESCALATED`, and `RESOLVED → CONSUMED` is an atomic CAS. The defect let the resolution record, and the audit trail built from it, be rewritten after the fact.

**Remediation (implemented):**
1. `_RESOLVABLE_FROM` in [`defer_queue.py`](../src/gateway/governance/defer_queue.py): `INJECTED` only from `PARKED`; `EXPIRED` and `ESCALATED` only from `PARKED` or `PARTIALLY_APPROVED`. `_resolve` raises on an unknown resolution and refuses (logs, drops the expiry-index entry, returns `None`) any other status.
2. `replay_evaluate` reads the status with the revision and returns the new `ReplayResult.ALREADY_RESOLVED` for any token not `PARKED` or when `_resolve` refuses.
3. `defer_inject` maps `ALREADY_RESOLVED` to HTTP 409 `DEFER_TOKEN_ALREADY_RESOLVED` (previously a 500 path).
4. [`tests/test_defer_queue_single_use.py`](../tests/test_defer_queue_single_use.py): re-inject after `INJECTED`, inject after quorum approval, after `CONSUMED` and after a partial approval, the `expire_stale`-vs-approve race at the guard, expiry of parked and partially approved tokens still working, unknown resolution, and two endpoint 409 tests. Eight of the nine fail without the fix.

**Closure Verification (2026-10-03):**
1. `LangGraphHarness.cfg` (guarded `_resolve`) holds `SingleUseDeferralTicket` over 82,652 states; `LangGraphHarness_unguarded.cfg` (the code before the fix) violates it.
2. `make test-fast` on the branch: 6080 passed, 105 skipped. One failure, `tests/test_gfa_nodes_coverage.py::TestExecutionAnalystNodeBehavior::test_circuit_breaker_fires_at_loop_count_3`, is order-dependent and pre-existing: it fails identically at the merge base `7d359c80` (6054 passed, 100 skipped, 1 failed) and passes in isolation.
3. Squash-merged to `main` as #380.
