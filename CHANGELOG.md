# Changelog

All notable changes to the Cybernetic Governance Engine (CAGE) are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Change record authority:** Per `.clinerules` §8.5 and `docs/CHANGE_MANAGEMENT_PROCESS.md`, every Cat-N (Normal) and Cat-M (Major) change must be recorded here before the associated tag is pushed. This file is referenced by the `gh release create` runbook step in `docs/V2_RELEASE_RUNBOOK.md` §6.9.

---

## [Unreleased]

> Sprint 2 production-readiness fixes — in progress as of 2026-06-07. Required before `git tag v2.0.0` is applied per `docs/PRODUCTION_READINESS_REPORT.md` §7 Sprint 2 roadmap.

### Fixed

- **`causal_gatekeeper.py`** — Eliminated `run_until_complete()` calls in thread-pool context (BLOCKER-01). The DoWhy causal model is now offloaded via `asyncio.to_thread()` from `symbolic_governor.py._run_checks()`, removing the event-loop deadlock that caused E2E p95 latency of 20,528ms (10× over the 3,000ms budget) and made the system effectively single-threaded under governance load.
- **`governance_middleware.py`** — Sanitized internal exception details from HTTP 500 responses (MED-03). The `validate_action` endpoint no longer leaks internal stack traces, file paths, or variable names to API callers via `detail=str(exc)`.
- **`consensus.py`** — Added 30-second hard timeout on `GatewayClient` LLM critic calls (HIGH-07). Prevents the governance pipeline from hanging up to 600 seconds (the `AsyncOpenAI` default) under LLM provider degradation, which caused cascading timeouts across all concurrent requests for trades above the $10k consensus threshold.
- **`hybrid_server.py`** + **`reconciliation_worker.py`** — Added production guard blocks that assert `RECONCILIATION_PROVIDER != "stub"` when `ENVIRONMENT=production` (BLOCKER-06). The `StubLedgerProvider` (which evaluates CBF fiscal safety invariants against a fabricated $100,000 balance) is now explicitly prohibited in production, preventing silent governance bypass of real custody limits.

### Security

- **`docker-compose.yml`** — OPA no longer exposed unauthenticated on host port `8181` (HIGH-01). Removed the `8181:8181` host port binding; OPA is now accessible only via the internal service mesh. Bearer token authentication configured via Kubernetes Secret.
- **`docker-compose.yml`** — `.env` file no longer mounted as a volume into containers (HIGH-03). Secrets are now injected via `secretKeyRef` references in pod specs, eliminating the attack surface where a compromised dependency (e.g., CVE-2026-4810 in `google-adk`) could read all secrets from `/app/.env`.
- **`redis_client.py`** — Redis connections upgraded to TLS (`rediss://`) with `ssl=True, ssl_cert_reqs="required"` (HIGH-04, POAM-011). All governance-critical data in Redis — fiscal limits, OPA cache, DEFER queue state, routing seal state — is now encrypted in transit. GCP Memorystore in-transit encryption enabled.

### Added

- **Startup validation for Langfuse compliance credentials** (HIGH-05, POAM-018). A startup assertion now validates that `LANGFUSE_COMPLIANCE_PUBLIC_KEY` and `LANGFUSE_COMPLIANCE_SECRET_KEY` are present and reachable. On failure, startup hard-fails in production (or emits a `CRITICAL` log with a Prometheus alert in non-production), preventing silent loss of all compliance audit traces.
- **`tests/test_governance_middleware.py`** — Governance API surface coverage using `fastapi.testclient.TestClient` (BLOCKER-08). Covers the `/governance/check` endpoint, `/governance/validate-action` endpoint, `enforce_routing_seal()` log-mode bypass path, `_emit_refusal_receipt()` KMS signing, and `_verify_governance_signature()`. Brings `governance_middleware.py` coverage from ~5% toward the ≥80% target.
- **`tests/load/locustfile.py`** — Load test updated to target live governance endpoints (`/governance/validate-action`, `/tools/execute`) instead of the removed `/agent/query` endpoint (HIGH-11). Re-establishes meaningful performance baseline data for production readiness validation.

### Docs

- docs: update markdown files to reflect v2.0.0-rc.3 state — corrected stale `deployment/terraform/` path references in `infra/ROLLBACK_PROCEDURES.md` and `infra/DEPLOYMENT_GUIDE.md` to active `infra/targets/gcp-gke/`; updated POAM-007 mTLS status from pending to closed (Linkerd mTLS implemented 2026-05-17) in `compliance/pia/PRIVACY_IMPACT_ASSESSMENT.md`; added historical notice to `plans/path-b-deployment-plan.md`; replaced stale "module not extracted yet" markers in `infra/targets/agnostic/README.md` with accurate module completion status.

---

## [2.0.0-rc.3] — 2026-06-06

> Production readiness assessment completed 2026-06-07 (`docs/PRODUCTION_READINESS_REPORT.md`). GKE rolling deployment and test remediation completed 2026-06-06 (`docs/DEPLOYMENT_FIX_REPORT_2026Q2.md`). Final test result: **852 passed, 24 skipped, 0 failed**.

### Added

- **DEFER state machine (AARM-V7)** — Redis `db=1` noeviction-backed deferral queue with SSE event streaming and OTel metrics. Closes the AARM-V7 threat vector (unauthorized deferred execution). Implemented in `src/gateway/governance/defer_queue.py`.
- **SHA-256 hash-chained context accumulator** — Tamper-evident audit trail for the agent context window. Each governance event is chained to its predecessor via SHA-256, closing the AARM-V1 threat vector (context manipulation between governance checks). Implemented in `src/compliance_bridge/evidence_stream.py`.
- **External Normative Provider** — Adaptive FRIA (Fundamental Rights Impact Assessment) gating for EU AI Act compliance. Operates in stub mode until TrustLayers credentials are provisioned (POAM-022). Implemented in `src/gateway/governance/normative_provider.py`.
- **OSCAL SSP Exporter** — Machine-readable System Security Plan export via `src/gateway/governance/oscal_ssp_exporter.py`. Generates OSCAL Assessment Results ingested into Langfuse via direct OTLP. Supports the ATO package compilation workflow in `docs/V2_RELEASE_RUNBOOK.md` §6.7.
- **KMS batch signing for OSCAL artifacts** — `src/compliance_bridge/kms_batch_signer.py` provides HSM-backed asymmetric signing for compliance evidence artifacts stored in GCS. Closes the cryptographic evidence chain for MiFID II / GDPR audit requirements.
- **AgentSight eBPF remote exporter** — `exporter.type: "remote"` confirmed active in `deployment/k8s/agentsight-daemon.yaml` (POAM-021 closed). eBPF kernel observability data now flows to the remote collector rather than console-only mode.
- **Security-scan CronJob manifest** — `deployment/k8s/security-scan-cronjob.yaml` created with PSA `restricted:latest`-compliant `securityContext`. Runs Trivy weekly (Sunday 03:00 UTC) against `gcr.io/YOUR_GCP_PROJECT_ID/cage-gateway:latest`. Satisfies the RA-5 Lula assertion in `compliance/lula/lula-validation-ra5.yaml`.
- **15 Lula validation manifests (4 Active, 11 Stub)** — Automated continuous compliance assessment covering NIST SP 800-53, ISO 42001 Annex A, and CSA AARM controls. 4 manifests are production-ready and Active (A.5.2, A.5.3, A.9.2, SC-4); 11 are Stubs requiring cluster-specific configuration before activation. CronJob runs every 6 hours for Active manifests; findings expressed as OSCAL Assessment Results. See [`compliance/lula/README.md`](compliance/lula/README.md) for full status.

### Fixed

- **`governed-financial-advisor` CrashLoopBackOff** (140 restarts) — Rogue `ingress-agent` container added out-of-band via `kubectl edit` caused a port conflict on `PORT=8080`. Removed via JSON patch (`kubectl patch --type='json'`). Pod restored to `Running 1/1`.
- **`lula-sc4-watch` ImagePullBackOff** — `deployment/k8s/lula-cron.yaml` corrected from non-existent `lula:0.9.0` tag to `lula:0.9.5`. Rolling update applied.
- **PodSecurity `restricted:latest` admission blocking new pods** — Added compliant `securityContext` (`runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, `seccompProfile: RuntimeDefault`) to `financial-advisor.yaml`, `compliance-bridge.yaml`, `opa.yaml`, and `lula-cron.yaml`.
- **Gateway manifest env var conflict** — Removed `VLLM_GATEWAY_URL: ""` empty-string conflict and aligned `REDIS_PASSWORD` to use `valueFrom` secret reference consistently across live deployment and manifest.
- **`verify_seal()` API contract mismatch** — 21 routing seal test failures resolved. `verify_seal()` now returns `bool` (`True` on success, `False` on `SymbolicGovernorViolation`). `require_cleared_seal` decorator and `tools/api.py` caller updated to match the new contract.
- **pytest global timeout false failures** — `pytest.ini` timeout increased from 30s to 90s; switched from signal-based to thread-based timeout method (`--timeout-method=thread`) to accommodate background Langfuse SDK and `OtelBatchSpanRecordProcessor` daemon threads.
- **`test_metric_endpoint_per_control` flaky on port-forward drop** — Added `@pytest.mark.timeout(60)`, increased `requests` timeout from 20s to 45s, and wrapped `session.get()` in `try/except ConnectionError → pytest.skip()` so transient port-forward drops produce a skip rather than a failure.
- **Technical report README version mismatch** (POAM-020 closed) — All documentation aligned to v2.0.0. Closure evidence recorded in `docs/POAM.md`.

### Security

- **CVE-2025-69872 (diskcache RCE) mitigated** (POAM-016 closed) — `outlines` dependency removed from gateway `pyproject.toml`. The `diskcache` transitive dependency carrying the RCE is no longer present in the gateway image.
- **POAM-010 closed** — Vulnerability scanning pipeline active in CI: `pip-audit`, Trivy, Grype, and CycloneDX SBOM generation integrated in `.github/workflows/security-scan.yml`.

### Changed

- **OpenTelemetry Collector deprecated** (2026-05-31) — Standalone OTel Collector decommissioned in favor of Langfuse's native OTLP ingestion endpoint. Simplifies the telemetry pipeline and ensures direct trace delivery without an intermediate hop. All references to the OTel Collector updated across documentation.

---

## [2.0.0-rc.2] — 2026-05-17

> Linkerd mTLS and Cilium egress lockdown completed 2026-05-17 (FIND-011 resolved, POAM-007 closed). Full test suite: **844 passed, 28 skipped, 0 failed** against live GKE cluster (`cage-dev`, namespace `governance-stack`).

### Added

- **Causal gatekeeper (DoWhy)** — `src/gateway/governance/causal_gatekeeper.py` implements DoWhy-based causal safety checks as a mandatory governance node. Evaluates counterfactual trade impact before execution approval.
- **Control Barrier Function (CBF)** — `src/gateway/governance/cbf.py` implements Redis-backed cash/drawdown invariant enforcement. Externally reconciled via `AnchorageGrpcLedgerProvider` (stub mode until gRPC connectivity implemented, POAM-023). Parallelized with OPA via `asyncio.gather()` in `symbolic_governor.py`.
- **Consensus engine** — `src/gateway/governance/consensus.py` implements multi-agent unanimity requirement for trades above $10k. `ConsensusModelRegistry` manages the critic ensemble. Background audit worker queues consensus decisions for async processing.
- **STPA-to-Policy Compiler** — `src/gateway/governance/stpa_compiler.py` compiles Unsafe Control Actions (UCAs) from YAML to Rego + Colang + Python policy artifacts. No hand-edited policy files; all governance policy is derived from the STPA hazard model.
- **DEFER state machine foundation** — `src/gateway/governance/defer_queue.py` initial implementation. Redis `db=1` noeviction store; SSE event streaming for real-time deferral status.
- **Linkerd mTLS with SPIFFE/SVID identity** (POAM-007 closed 2026-05-17) — SPIFFE/SVID identity enforced across gateway↔OPA and gateway↔NeMo communication channels. `MeshTLSAuthentication` policies finalized. Closes FIND-011.
- **Cilium L7 egress lockdown** (FIND-011 resolved 2026-05-17) — `deployment/k8s/cilium-egress-lockdown.yaml` enforces FQDN allowlist for gateway pods (approved market providers, secure telemetry endpoints only). Internal-only egress for agent pods.
- **Network policy hardening** — Default-deny Kubernetes `NetworkPolicy` and `CiliumNetworkPolicy` applied across `governance-stack` namespace. `deployment/k8s/network-policy-hardening.yaml` applied.
- **Exhaustive state-space formal verification** — `NoDirectBind` safety invariant verified across all execution paths. Cryptographic attestation enforced on all execution paths. CBF `CBF_FAIL_OPEN` and DoWhy causal gatekeeper production fail-closed gates verified.
- **HMAC routing seal** — `src/gateway/governance/routing_seal.py` implements HMAC-SHA256 routing seal with `hmac.compare_digest()` constant-time comparison and TTL enforcement. Prevents timing oracle attacks on the governance enforcement layer.
- **Cloud KMS asymmetric signing** — `src/gateway/governance/kms_signer.py` implements HSM-backed asymmetric signing. Private key never leaves the HSM. HMAC-SHA256 fallback for dev/CI environments. SC-28 enforced at startup via CMEK validation (hard-fail in production).
- **Aho-Corasick keyword scan** — O(n) prompt-injection detection with 14+ patterns in `src/gateway/governance/text_filter.py`. Mandatory first-pass filter on all inbound governance requests.
- **Recursion guard** — `loop_count >= 3 → explainer` escape hatch in the LangGraph agent graph. Prevents infinite agent loops; correct safety bound for the governed financial advisor.

### Fixed

- **CBF `CBF_FAIL_OPEN` production gate** — Fail-closed behavior enforced; CBF no longer silently passes governance checks when Redis is unavailable.
- **Causal gatekeeper production gate** — DoWhy causal model fail-closed behavior enforced; governance check fails closed on causal model exception rather than passing through.

### Security

- **OPA circuit breaker defaults to DENY** — On OPA service unavailability, the circuit breaker now defaults to `DENY` rather than `ALLOW`. Defense-in-depth against OPA pod restarts or network partitions.
- **Presidio PII detection** — 15 entity types detected on both input and output paths via NeMo Guardrails in-process integration. Prevents PII exfiltration through the governance API surface.

---

## [2.0.0-rc.1] — 2026-04-15

> Initial v2.0 release candidate. Establishes the AgentSight UI uplift (Phase 1 of the v2.0 roadmap), the core governance gateway, NeMo Guardrails integration, and OPA policy enforcement. HITL TOCTOU remediation fully implemented and unit-tested (41/41 passing).

### Added

- **AgentSight UI Phase 1 — Reviewer Input Panel** — `src/agentsight-ui/src/KernelDashboard.tsx` displays an interactive, adjustable control allowing compliance operators to set `max_slippage_pct` (default 2.0%) before approving a trade. Closes the HITL closed loop for human reviewers.
- **AgentSight UI — Live Price Drift Indicator** — Real-time computed price drift delta (ΔP = |P_fresh − P_stale| / P_stale) displayed next to transaction details in the dashboard.
- **AgentSight UI — TTL Countdown Visualizer** — Visual countdown timer for `hitl_expires_at`. Automatically greys out the approval action on expiry and prompts the operator to request a fresh trade evaluation, enforcing the TOCTOU remediation window.
- **AgentSight UI — Audit Evidence Display** — `rehydration_result` (with P_stale, P_fresh, and `drift_pct`) rendered in the transaction history panel for compliance audit review.
- **AgentSight eBPF DaemonSet** — `deployment/k8s/agentsight-daemon.yaml` deploys the eBPF kernel observability DaemonSet across the `governance-stack` namespace.
- **Governance gateway** — `src/gateway/server/hybrid_server.py` and `src/gateway/server/governance_middleware.py` implement the primary governance enforcement API surface. Routes: `/governance/check`, `/governance/validate-action`, `/mcp/execute`.
- **NeMo Guardrails integration** — `src/gateway/governance/nemo/` implements mandatory first and final LangGraph nodes. Input gate (fail-closed on exception) and output rail (in-process Presidio PII egress filter). `src/gateway/governance/langgraph_harness/nemo_node_factory.py` wires NeMo into the LangGraph execution graph.
- **OPA policy enforcement** — `src/gateway/governance/langgraph_harness/opa_node_factory.py` implements direct OPA REST integration with circuit breaker defaulting to DENY on failure. `src/governed_financial_advisor/governance/policy/trade_governance.rego` defines the trade authorization policy.
- **Human-in-the-loop (HITL) gate** — `interrupt_before=["governed_trader"]` in the LangGraph graph definition. Redis-persisted checkpoint for HITL state. `post_hitl_rehydrate` and `post_hitl_revalidate` nodes implement TOCTOU remediation: fresh price fetch and re-validation before trade execution after human approval.
- **Safety check node** — Explicit OPA gate between the evaluator and governed trader nodes. Prevents the governed trader from executing without a passing OPA policy decision.
- **Governed financial advisor agent graph** — Multi-agent LangGraph graph: `data_analyst` → `risk_analyst` → `evaluator` → `[HITL]` → `governed_trader` → `explainer`. Recursion guard at `loop_count >= 3`.
- **W3C traceparent propagation** — Full OTel trace waterfall with 100% sampling for governance spans. Direct Langfuse OTLP ingestion. `src/gateway/tracing_setup.py` configures the tracer provider.
- **Symbolic governor** — `src/gateway/governance/symbolic_governor.py` orchestrates the governance check pipeline: CBF + OPA parallelized via `asyncio.gather()`, causal gatekeeper, NeMo rails, routing seal verification.
- **Fiscal limit guard** — `src/gateway/governance/fiscal_limit_guard.py` implements Redis `WATCH/MULTI/EXEC` atomic fiscal limit transactions with exponential backoff retry. Gold-standard test coverage in `tests/test_fiscal_limit_guard.py`.
- **OSCAL compliance bridge** — `src/compliance_bridge/` implements OSCAL parser, exporter, evidence stream, and GCS storage. Compliance findings expressed as OSCAL Assessment Results.
- **Lula validation pipeline** — Initial Lula validation manifests for ISO 42001 (A.5.2, A.5.3, A.9.2), NIST SP 800-53 (SC-4, AU-12, AC-3, RA-5, CM-6, IR-6, AC-2, SC-8, IA-3, IA-5, SI-2), and CSA AARM vectors.
- **Terraform GKE infrastructure** — `infra/targets/gcp-gke/` and `infra/modules/` define the full GKE cluster, namespace, gateway, compliance bridge, Langfuse stack, Redis cache, PostgreSQL, MinIO, vLLM inference, and NeMo Guardrails infrastructure as code.
- **Multi-region deployment targets** — `infra/targets/gcp-gke/eu-dev.tfvars` (EU, `europe-west1`) and `infra/targets/gcp-gke/apac-dev.tfvars` (APAC, `asia-southeast1`) for GDPR and MAS TRM data residency compliance.
- **POAM tracking** — `docs/POAM.md` established as the authoritative Plan of Action & Milestones document. Initial entries POAM-001 through POAM-015 documented with target dates and ownership.
- **Apache 2.0 license headers** — CI-enforced license header check across all `src/` files. `cloudbuild.compliance.yaml` and `cloudbuild.ui.yaml` enforce the check on every build.

### Security

- **`default allow = "DENY"` OPA posture** — All OPA policies default to deny. No allow-by-default paths exist in the governance policy set.
- **Zero `verify=False` instances** — TLS verification is never disabled anywhere in the codebase. Consistent TLS discipline enforced via CI lint check.
- **`terraform.auto.tfvars` gitignored** — All Terraform secret values (Redis password, PostgreSQL password, Langfuse keys, GCS HMAC keys, HuggingFace token) are stored in gitignored `terraform.auto.tfvars` files. No production secrets committed to source control.

---

## Version History Summary

| Version | Date | Test Results | Key Theme |
|---------|------|--------------|-----------|
| [Unreleased] | — | — | Sprint 2 production-readiness fixes (BLOCKER-01, MED-03, HIGH-07, BLOCKER-06, HIGH-01, HIGH-03, HIGH-04, HIGH-05, BLOCKER-08, HIGH-11) |
| [2.0.0-rc.3] | 2026-06-06 | 852 passed, 24 skipped, 0 failed | Governance hardening, OSCAL compliance, KMS signing, DEFER state machine, SHA-256 hash chain, GKE rolling deployment fixes |
| [2.0.0-rc.2] | 2026-05-17 | 844 passed, 28 skipped, 0 failed | Causal gatekeeper, CBF, consensus engine, Linkerd mTLS, Cilium egress, formal verification of `NoDirectBind` |
| [2.0.0-rc.1] | 2026-04-15 | 41/41 unit tests passing | Initial gateway, NeMo Guardrails, OPA policy engine, HITL TOCTOU remediation, AgentSight UI Phase 1 |

---

[Unreleased]: https://github.com/YOUR_GCP_PROJECT_ID/cybernetic-governance-engine/compare/v2.0.0-rc.3...HEAD
[2.0.0-rc.3]: https://github.com/YOUR_GCP_PROJECT_ID/cybernetic-governance-engine/compare/v2.0.0-rc.2...v2.0.0-rc.3
[2.0.0-rc.2]: https://github.com/YOUR_GCP_PROJECT_ID/cybernetic-governance-engine/compare/v2.0.0-rc.1...v2.0.0-rc.2
[2.0.0-rc.1]: https://github.com/YOUR_GCP_PROJECT_ID/cybernetic-governance-engine/releases/tag/v2.0.0-rc.1
