# Security Posture Statement — Plan of Action and Milestones (POAM)

**System:** Cybernetic AI Governance Engine (CAGE)
**Document:** Public Security Posture Statement
**Frameworks:** NIST SP 800-53 Rev. 5, NIST AI 600-1, ISO 42001, EU AI Act, DORA, GDPR, MAS FEAT, MAS TRM, MAS Notice 655
**Last Updated:** 2026-10-28

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
| POAM-2026-084 | AU-9 / AU-9(3) / AU-10 / AU-11 | Evidence pipeline integrity: the gateway `EvidenceStreamSink` was never started by the server lifespan (no evidence recorded), gateway replicas could fork the hash chain, the gateway held its own signer and cold-store flush (signatures never persisted; failed flushes silently skipped), and async Redis clients ignored TLS/IAM. Remediated in code on `fix/evidence-pipeline-integrity` and `feat/evidence-custody-verifier`: lifespan starts the sink via `start_evidence_sink()` (fail closed when enforcing); Lua compare-and-append (`_APPEND_BATCH_SCRIPT` via per-process group commit on `refactor/evidence-group-commit`, re-chaining on conflict so replicas still share one linear chain with no forks) keeps one linear chain; [`ConsequenceGateway`](../src/gateway/governance/consequence_gateway.py) and [`ingest_actuation_receipt()`](../src/gateway/governance/execution_actuator.py) emit post-evaluation decisions and actuation refusals into `EvidenceStreamSink` (refusal and deferral receipts use awaited enqueue and are never dropped; only best-effort `GOVERNANCE_TRACE` events shed when the bounded queue is full); custody moved to the compliance-bridge [`EvidenceCustodian`](../src/compliance_bridge/evidence_custodian.py) (re-verify, KMS-signed batch attestation with `EVIDENCE_KMS_KEY`, WORM `put_if_absent`, durable cursor); `build_async_redis()` enforces TLS/IAM (and on `fix/shared-redis-clients` configures `BlockingConnectionPool`, `health_check_interval=30`, bounded retries, and async IAM credential refresh across [`DeferQueue`](../src/gateway/governance/defer_queue.py), [`FiscalLimitGuard`](../src/cage_finance/safety/fiscal_limit_guard.py), [`TokenQuotaProxy`](../src/gateway/governance/token_quota_proxy.py), [`ConsequenceAuthorityStore`](../src/gateway/governance/consequence_authority_store.py), and [`compliance_bridge`](../src/compliance_bridge/main.py)). See [`EVIDENCE_CHAIN.md`](architecture/EVIDENCE_CHAIN.md). OSCAL AU-9 / AU-9(3) / AU-10 / AC-6 statements updated in [`sp800-53-component-definition.yaml`](../compliance/oscal/sp800-53-component-definition.yaml) (status `partial`); ClickHouse sink moved to the INSERT-only `cage_evidence_sink` user; unsigned (dev/test/ci) attestations marked non-evidentiary and rejected by `assert_citable()`; read-back [`CustodyVerifier`](../src/compliance_bridge/evidence_verifier.py) added (kid-resolved signature, object binding, record re-verification, chain continuity, scheduled `run_forever()` loop, Prometheus metrics, `GET /v1/evidence/verify`, fail-closed OSCAL citation gating in [`oscal_exporter.py`](../src/compliance_bridge/oscal_exporter.py), and Terraform/Kubernetes manifest wiring for `EVIDENCE_VERIFY_INTERVAL_S`, `OSCAL_REQUIRE_VERIFIED_CUSTODY`, and `EVIDENCE_TRUST_ANCHORS_FILE`). Scope extended on `feat/provider-02-state-preimage` to Provider 02 `stateHash` preimages: the gateway's [`StateCommitmentService`](../src/gateway/governance/evidence/state_commitment.py) (`POST /governance/state-commitments`, Linkerd mTLS identity) PII-sanitizes, canonicalizes (RFC 8785) and hashes each `AgentState` snapshot once and appends it as a `STATE_COMMITMENT` record, which the custodian archives with `x-data-classification: internal-pii-sanitized` and read-back conflict detection (`put_if_absent_verified()`); [`test_state_commitment_worm_live.py`](../tests/integrations/test_state_commitment_worm_live.py) (`live_external`) exercises conflict detection, retention refusal, preimage round-trip and classification metadata against the staging WORM bucket with unsigned attestations, so it does not close the signed-attestation requirement. Retention basis and GDPR Art. 17(3) applicability are recorded as an AU-11 customer responsibility. Remains Open pending merge SHAs and live staging verification of signed attestations (including state-commitment batches) in the WORM bucket | High | 2026-10-15 |
| POAM-2026-085 | SI-10 / `CTRL_MRM_004` | Causal gatekeeper cache bypassed the per-request risk boundary: a cached ALLOW for a small trade was replayed for any amount, and a cached DENY denied small ones (Redis with `cache_ttl_seconds > 0`, within one TTL window). Remediated in `refactor/ftra-scope` by caching only the params-independent world-model verdict; closes at merge | High | 2026-10-15 |
| POAM-2026-086 | SC-8 / SC-23 | Memorystore server CA not delivered to gateway/compliance-bridge pods; evidence-stream fail-closed check exposed it on 2026-10-01. Remediated in IaC (PR-3, `fix/memorystore-ca-pinning`) by mounting `module.memorystore_governance.managed_server_ca` via `<app>-redis-ca` ConfigMaps at `/etc/cage/tls/redis/ca.pem` (`REDIS_CA_CERT_PATH`, `cage.io/redis-ca-sha256` rollout annotation, and `lula-validation-sc8.yaml` Check 5); remains Open pending PR-4 (`fix/redis-tls-one-rule`) unification of synchronous/module-level Redis TLS verification across all enforcing postures | High | 2026-10-15 |
| POAM-2026-094 | SI-10 / CA-7 / `CTRL_MRM_004` | The causal tier has no live world-model feed outside dev/test/ci, so it denies every `execute_trade` in enforcing postures. The 2026-10-03 staging benchmark (`docs/paper/measurements/2026-10-03-5aa1a65f/`) recorded all 4 benign trade prompts as refused, first with `CAUSAL_TELEMETRY_UNAVAILABLE`. [`LangfuseTelemetryProvider`](../src/integrations/telemetry_langfuse/provider.py) called `Langfuse.fetch_traces`, which SDK v3 removed (fixed in #387), and then aborted on the first trace whose `input` was a string (fixed in #389). With both fixed, the provider reads live traces in the gateway pod (verified 2026-10-03 at `c43c41be`), but 0 of them carry the causal columns. The tier therefore still denies with `CAUSAL_TELEMETRY_UNAVAILABLE` (1 to 49 rows would give `CAUSAL_INSUFFICIENT_SAMPLES`), because nothing produces the rows the model needs. `amount` is real. `market_volatility` comes only from [`StubMarketDataProvider`](../src/cage_finance/safety/bounding/providers.py) (a constant 0.15). No component observes a post-trade `risk_score` outcome. The deny is correct fail-closed bootstrap behaviour (POAM-2026-088). The gap is the missing Tier 2 data source: a deterministically seeded, fault-injectable market-data and outcome backend. Emitting the system's own risk formula as the outcome would make DoWhy validate the model against itself, so that is not a remediation. **Scope (amended 2026-10-27):** the self-certifying source is not finance-only. The kernel's [`MockTelemetryProvider`](../src/gateway/governance/telemetry_provider.py) generates its outcome from the same formula (`0.5 × volatility + 0.5 × amount / 10,000 + N(0, 0.05)`) without any domain fixture, and the boundary and placebo tests ([`test_causal_risk_boundary.py`](../tests/test_causal_risk_boundary.py), [`test_causal_placebo_refutation.py`](../tests/test_causal_placebo_refutation.py)) run against that formula, so they show that the refusal paths operate, not that the model fits a world it did not write. **This item MUST NOT close before POAM-2026-117.** Closing it gives the tier trusted verdicts in enforcing postures, and while POAM-2026-117 is open that can move the tier from refusing every trade to permitting, at high volatility, 2.65× the limit a volatility-aware reading of the same fit gives | Moderate | 2026-12-31 |
| POAM-2026-098 | AU-10 / AC-3 / SI-10 | Partner actuation receipts are not yet signed. The code side is remediated in `9c68a6e8` and `72574529`: [`ActuationReceipt`](../src/gateway/governance/seams/actuation.py) has a three-valued outcome (an `UNKNOWN` receipt settles as executed and is never retried), the kernel [`dispatch_actuation()`](../src/gateway/governance/execution_actuator.py) is the only writer of actuation evidence, and [`verify_partner_receipt()`](../src/integrations/actuator_01/receipt_verifier.py) checks a detached Ed25519 signature against a key resolved by `kid` (`INVALID` forces `UNKNOWN`). The signature format is a CAGE-proposed extension that the actuator_01 partner has not adopted, so live receipts are recorded as `UNVERIFIED`. Closure requires partner adoption, an over-the-wire conformance test against the partner sandbox, and `ACTUATOR_01_REQUIRE_SIGNED_RECEIPTS` enabled in enforcing postures. Residual duplication: `Provider07JwksClient` has not moved to the shared [`Ed25519KeyManifestClient`](../src/integrations/trust/key_manifest.py) | Moderate | 2026-12-31 |
| POAM-2026-100 | SI-10 / AU-10 | Evidence data integrity: the `PIISanitizer` SWIFT/BIC pattern matched any eight- or eleven-character upper-case token, so governance verdicts and states such as `APPROVED`, `REJECTED` and `ESCALATE` were redacted to `[REDACTED_SWIFT]` before hashing in the evidence stream. Records lost their verdicts, and events differing only in such a word produced identical payloads. Remediated in code on `fix/pii-swift-false-positive`: a BIC is redacted only with a contextual cue (`BIC`/`SWIFT` label or BIC/SWIFT dict key) and a valid ISO 3166-1 alpha-2 country code ([`pii_sanitizer.py`](../src/gateway/governance/pii_sanitizer.py)); property test over all upper-case literals in `src/` ([`test_pii_sanitizer_bic.py`](../tests/test_pii_sanitizer_bic.py)). Records written before the fix stay verifiable but keep the redaction. See [`EVIDENCE_CHAIN.md` §4.4](architecture/EVIDENCE_CHAIN.md). Remains Open pending merge SHA | High | 2026-10-15 |
| POAM-2026-101 | RA-5 / SI-2 | `python:3.12-slim-bookworm` OS-package CVEs with no Debian fix kept the SBOM/CVE gate red: util-linux CVE-2026-76642, CVE-2026-78408, CVE-2026-78409, CVE-2026-78410, OpenSSL CVE-2026-84782, and 39 `linux-libc-dev` kernel-header CVEs; `.trivyignore` held expired suppressions (review dates 2026-09-05, 2026-09-08). Remediated on `fix/ci-test-errors`: advisor, gateway and compliance-bridge images are two-stage builds on a digest-pinned Wolfi base with no compiler or util-linux at runtime, and `.trivyignore` is empty. Cloud Build verification on 2026-10-05 ([`cloudbuild.verify.yaml`](../deployment/docker/cloudbuild.verify.yaml), builds `575e3466`, `3e268752`, `1df4fe5d`) found 0 HIGH/CRITICAL and 0 suppressed findings. Remains Open pending merge SHA and green SBOM/CVE legs on `main` | Moderate | 2026-11-15 |
| POAM-2026-114 | SI-10 / CA-7 / `CTRL_MRM_004` / `CTRL_TEL_003` | Finance causal tier: neither refusal path operated in v3.0.0–v3.3.0. The marginal risk boundary divided a per-dollar β by `normalization_scale` a second time (trips at ≈ $91.4M instead of ≈ $9,144 on the synthetic telemetry), and the placebo refutation used dowhy's N(0, 0) default placebo and read a missing or NaN p-value as a pass, so phase 2 always trusted the world model. Remediation implemented; closes with the fix release and its security advisory | Moderate | With the fix release |
| POAM-2026-115 | AC-5 | `main`'s review rule requires one approving review, but the project has one maintainer and GitHub does not let an author approve their own pull request, so each of the maintainer's merges bypasses that rule as a repository admin. Until 2026-10-27 the bypass also skipped the required status checks: GitHub's rule-suite log shows that 163 of the 215 pushes to `main` from 2026-09-27 to 2026-10-27 went in with required checks not passing, at least 35 of them with a check reported as failing. The checks now sit in ruleset 25966171, which has no bypass actor, so CM-3 and CM-5 are no longer in scope (detail section). AC-5 has no compensating control: no configuration or script supplies an independent reviewer | Moderate | On second maintainer onboarding |
| POAM-2026-116 | SI-7 / CM-5 | No release tag was protected. Ruleset 19769024 ("Restrict tag creation to maintainer") targeted the branch patterns `refs/heads/v*-ref` and `refs/heads/v*-cage-*`, so no rule applied to any tag, including `v4.0.0`, which GHSA-c8pw-f3g3-xg7c, the v4.0.0 release notes and the archived evidence bundles point at. Remediated on 2026-10-27: tag ruleset 25965917 blocks deleting, updating or force-moving `refs/tags/v*` and `refs/tags/client-v*`, with no bypass actor, and was verified over the wire the same day. Remains Open until marked Closed in a follow-up | Moderate | 2026-10-30 |
| POAM-2026-117 | SI-10 / CA-7 / `CTRL_MRM_004` | The causal tier's per-request risk boundary can fail open as volatility rises. [`_marginal_risk`](../src/gateway/governance/causal/gatekeeper.py) predicts risk as `0.5 + β × amount / normalization_scale` (the formula POAM-2026-057 records). β is estimated with volatility adjusted for, but the prediction has no volatility term, and its 0.5 is neither configured nor estimated. The trip amount `0.45 × normalization_scale / β` is therefore the same in calm and volatile markets. In the frame stated in the detail section, the boundary permits trades up to $25,504.81 at volatility 0.9, where a volatility-aware reading of the same fit trips at $9,619.17 (2.65×) and the process's true trip point is $9,000. The constant is kernel code, so every domain inherits it. The defect is latent today: no enforcing posture has a trusted world model (POAM-2026-094), and `CausalGatekeeper.evaluate()` refuses an untrusted verdict before reaching the boundary. Remediating POAM-2026-094 makes it live, so **POAM-2026-094 MUST NOT close before this item** | High | 2026-12-31 |
| POAM-2026-118 | SI-10 / CA-7 / `CTRL_MRM_004` | An enforcing posture can be configured to run the causal tier on synthetic telemetry, and today an accident is all that stops it. [`get_telemetry_provider()`](../src/gateway/governance/telemetry_provider.py) refuses `CAGE_TELEMETRY_PROVIDER=mock` only when `CAGE_ENV` is `prod` or `production`. [`is_enforcing()`](../src/gateway/governance/env_posture.py) also treats `staging` and `local` as enforcing, and no other code path rejects `mock`. `MockTelemetryProvider` generates its outcome from the formula the model is calibrated on (POAM-2026-094). A staging or local deployment set to `mock` would therefore validate the world model against itself, against POAM-2026-088's rule that enforcing postures never substitute synthetic data. While POAM-2026-117 is open, that deployment would also enforce from POAM-2026-117's invented baseline. The shipped manifests set `remote`. What refuses the path today is that `MockTelemetryProvider` emits no timestamp column and the freshness check fails closed without one (`stale_telemetry`). Adding a timestamp column, the obvious fix for anyone trying to use the mock, would arm it. Remediation: select on `is_enforcing()` instead of the environment name | Moderate | 2026-11-15 |
| POAM-2026-119 | CA-5 / CA-7 | 13 identifiers this document cites as commits name no object in the repository, so no assessor can check them against `main`. Six are pre-squash branch commits, each mapped to the squash commit on `main` that carries it. Seven resolve nowhere (not on `main` or GitHub, nor in the maintainer's clones, private refs or offsite bundle), including the only commit POAM-2026-011's closure cites. Gate G9 does not check commit citations. Recorded now; the repair follows the commit-citation check (detail section) | Moderate | 2026-11-15 |
| POAM-2026-120 | SA-11 / CM-4 / CA-7 | Closed controls are not guarded by tests that fail when the control stops operating. POAM-2026-023's fix removed the serialization POAM-2026-070's control depended on, and for a month every test passed and the POA&M/Lula drift checker still counted POAM-2026-070 as covered, by Lula files whose names match its control IDs and which never mention the CBF. On 2026-10-27, 34 of the 80 closed entries cited no test, and the drift checker's 52 "covered" entries rest on the same file-name match, never checked against what the files assert. Remediation: a forward closure requirement plus a backfill of High entries only (detail section) | Moderate | 2026-12-31 |
| POAM-2026-121 | CA-2 / CA-7 | §3 of the [Regional Posture Validation Report](compliance/REGIONAL_POSTURE_VALIDATION_REPORT.md), a published compliance validation report, makes a false claim. It says domain plugins and jurisdictional postures compose independently, "without colliding on common controls". That was false when written: `cage_finance`'s US_FED overlay redefines the kernel's `CTRL_FTRA_001`, and the registry logs the collision. The 12 pinned hashes are real but stale. They reproduce exactly, by the documented method, on the parent of the commit that published them (`3b69207c`), and that commit changed every kernel baseline. Independence is not merely unproven: POAM-2026-123 shows a plugin overlay changing a jurisdictional tier's verdict. The claim is therefore withdrawn as an aspiration, not proven as a property (detail section) | High | 2026-11-15 |
| POAM-2026-122 | SA-11 | Region pinning in the test suite is asymmetric. 57 tests are marked `eu_ecb` (48 of them in the required Pytest Logic Tests job), 23 `us_fed` (18) and 13 `apac_mas` (7), from 27, 4 and 4 marker uses, yet US_FED is the posture of the reference staging deployment and the one carrying the NIST SP 800-53 surface. The other ~9,000 tests run under the US_FED session default set in [`tests/conftest.py`](../tests/conftest.py), so US_FED is exercised broadly but pinned narrowly: an unmarked test that asserts US_FED behaviour depends on that default. Recorded, not swept | Low | 2026-12-31 |
| POAM-2026-123 | CM-6 / SI-7 | A domain plugin's compliance overlay can redefine a kernel control, including one a jurisdictional tier enforces on. [`ControlRegistry`](../src/gateway/governance/constants.py) applies overlays over the kernel baseline with `dict.update` and only logs a WARNING on a collision. With the kernel baseline alone, the EU_ECB FRIA tier denies `execute_trade` (`FRIA_ASSESSMENT_STALE`) without consulting the provider. With a test overlay that defines `CTRL_FRIA_006` and a fresh artefact, the Art. 27(2) staleness gate passes and the provider decides (verified). `cage_finance` redefines `CTRL_FTRA_001` today, which nothing reads at runtime. Governor assembly fails closed on a slot collision; the registry does not (detail section) | High | 2026-11-30 |
| POAM-2026-125 | SI-15 / SI-10 | Output semantic validation has never operated. `validate_output_semantics()` never puts its SAFE/UNSAFE question to a model: its call runs through the rails' input flow, so the only model call, if any, is the input judge's YES/NO prompt on the output text, and the reply it parses is never a model's answer to its question. Measured on main on 2026-10-28 with the model stubbed, it returned SAFE for every reply tried, including a correct `UNSAFE` and a dead endpoint, and the auditor prompt was sent 0 times; with no model configured it also reads SAFE. Until `94f920bc` the flow echoed the output back to the parser, and since then the reply is empty or the canned refusal: two different mechanisms across two periods since `6012f067`, and in neither did a model see the question (read). Measured on 2026-10-28 across a 6-cell judge matrix (`Qwen/Qwen2.5-1.5B-Instruct` vs `Qwen/Qwen2.5-7B-Instruct` × 3 prompts on 20 multi-paragraph benign advisor outputs and 20 labelled must-refuse outputs): `1.5B` (`vllm-fast`) refuses 7/20 (35%) benign answers and misses 8/20 (40%) unsafe outputs on the shipped prompt, and no prompt repairs it (`structured_rubric_prompt` cuts false refusals to 0/20 but collapses catch to 9/20, missing 4/4 fabricated citations and 4/4 leaked credentials), whereas `7B` achieves 0/20 (0%) false refusals and 20/20 (100%) catch on the shipped prompt (verified; detail section) | High | 2026-11-30 |
| POAM-2026-131 | CM-7 / SI-7 | Every profile except staging inherits placeholder image digests, `sha256:e3b0c442…`, the SHA-256 of empty input. That includes the three prod profiles that enforce Binary Authorization. The validation in [`variables.tf`](../infra/targets/gcp-gke/variables.tf) checks only the digest format (verified 2026-10-28; [`JURISDICTION_INVENTORY.md`](operations/JURISDICTION_INVENTORY.md)). | Low | 2026-12-31 |
| POAM-2026-133 | CM-3 | The repository's lists of required checks disagree with the branch ruleset. The ruleset has six checks (verified 2026-10-28); `CONTRIBUTING.md` and `.github/branch-protection-rules.md` name other sets, including a workflow that doesn't exist ([`JURISDICTION_INVENTORY.md`](operations/JURISDICTION_INVENTORY.md)). | Low | 2026-12-31 |
| POAM-2026-134 | SI-10 | On gcp-gke, consensus has never produced an automated verdict, only escalations. The gateway pod has no `MODEL_*`, so both critics request the `gemini-2.5-pro` default, which no vLLM pool serves; every vote is ERROR and every triggered consensus escalates to HITL (the 404 is inferred, not run). So the strict critic parser has never been exercised in deployment. Separately, the critics' prompt asks for `[DECISION] - [Reason]` while the parser scores the bracketed form as ERROR; the request also forces a JSON schema, which vLLM enforces (inferred), so that mismatch bites only where `response_format` is ignored. `MODEL_CONSENSUS` (set in Terraform) and `CONSENSUS_{ROLE}_URL` / `_MODEL` (read in code) are set by no surface (verified, grep; [`JURISDICTION_INVENTORY.md`](operations/JURISDICTION_INVENTORY.md)). | Moderate | 2026-11-30 |
| POAM-2026-135 | CM-6 | The default advisor runtime (`advisor_runtime = geap`) can't call a model as configured. Its environment has no `OPENAI_API_KEY`, and `chat_model()` then fails (verified); its endpoints are cluster-local names, so reachability from Agent Runtime is open ([`JURISDICTION_INVENTORY.md`](operations/JURISDICTION_INVENTORY.md)). | Moderate | 2026-11-30 |
| POAM-2026-136 | CM-6 | `vllm_fast_url`, `vllm_reasoning_url` and `vllm_gateway_url` are declared in [`variables.tf`](../infra/targets/gcp-gke/variables.tf) and filled by `deploy_all.sh`, but nothing reads them. Every endpoint in `main.tf` is a literal service name (verified, grep; [`JURISDICTION_INVENTORY.md`](operations/JURISDICTION_INVENTORY.md)). | Low | 2026-12-31 |
| POAM-2026-137 | AU-10 / SI-7 | Model output enters compliance records with its provenance suppressed. The compliance bridge's remediation advisory is unparsed model text that goes to the notifier, an SSE event and a compliance-Langfuse trace scored `iso42001.<control>.remediation_generated = 1.0`. AARM narratives are inserted into the report as `vector["narrative"]`; their prompt tells the model not to mention that a model generated the text, and the report doesn't mark model text apart from template text (read; [`JURISDICTION_INVENTORY.md`](operations/JURISDICTION_INVENTORY.md)). Not a fail-open, since nothing is parsed or blocked: an attribution defect in compliance evidence. | High | 2026-11-30 |
| POAM-2026-138 | SI-10 | The advisor's supervisor silently answers with a mock model's canned strategy text when its reasoning endpoint is unset or contains "mock", while other nodes raise (read; [`JURISDICTION_INVENTORY.md`](operations/JURISDICTION_INVENTORY.md)). | Moderate | 2026-11-30 |
| POAM-2026-139 | SA-8 / CA-7 | Correlated blind spots between the governance judges and the agent can't be measured on any shipped surface. Every governance consumer that reaches a verdict (the graph rails, the gateway rails, `verify_content_safety`) runs on the agent's execution model at the agent's endpoint, and no shipped surface configures an alternative. The advisor's graph rails can't be separated by configuration at all (verified routing; [`JURISDICTION_INVENTORY.md`](operations/JURISDICTION_INVENTORY.md)). | Moderate | 2026-12-31 |
| POAM-2026-140 | SI-15 / SA-11 / CA-2 | `CustomSelfCheckOutputAction` (`custom_self_check_output` in [`config/rails/actions.py`](../config/rails/actions.py)) is a published security claim protecting nothing. `CHANGELOG.md` (`2026-10-03`) records a `[SECURITY]` fix to its Stage 3 LLM judge, and [`tests/test_nemo_self_check_judge.py`](../tests/test_nemo_self_check_judge.py) calls the Python function directly. In reality, no Colang flow in [`config/rails/`](../config/rails/) invokes `CustomSelfCheckOutputAction` (a comment in [`nemo_node_factory.py`](../src/gateway/governance/langgraph_harness/nemo_node_factory.py) leaves authoring that flow to a future sprint). Even if a flow called it, its Stage 2 (`safe_indicators`) short-circuits to `ALLOW` (without calling Stage 3) whenever an output contains any of 22 common financial words (`"risk"`, `"portfolio"`, `"consider"`, `"may"`, `"could"`, `"order"`, `"shares"`, `"trade"`, `"position"`, etc.) and avoids nine literal phrases in Stage 1 — the vocabulary of nearly every financial advisory answer ever written (verified, grep and read, 2026-10-28; detail section) | High | 2026-11-30 |
| POAM-2026-141 | SI-10 / SC-28 / SI-4 / SA-11 / CA-2 | Four STPA UCAs (`UCA-3`, `UCA-4`, `UCA-7`, `UCA-10`) declare `nemo` as an enforcement target (`UCA-3`, `UCA-4`, `UCA-10` as their *only* target), yet [`generated_stpa_rails.co`](../config/rails/generated_stpa_rails.co)'s `flow stpa_output_guardrail` compiles to a bare `return` with zero checks, and [`system-security-plan.yaml`](../compliance/oscal/system-security-plan.yaml), [`component-definition.yaml`](../compliance/oscal/component-definition.yaml), and [`stpa_compiler_ssp_patch.yaml`](../compliance/oscal/stpa_compiler_ssp_patch.yaml) falsely assert `state: implemented` by `STPA-to-Policy Compiler` for `SC-28` / `ISO 42001 A.9.2` (`UCA-3`) and `SI-4` / `ISO 42001 A.9.4` (`UCA-10`). Two independent compiler failures cause the no-op: (1) [`check_stpa_freshness.py`](../scripts/check_stpa_freshness.py) (`_ARTIFACT_RECIPES`) compiles [`generated_stpa_rails.co`](../config/rails/generated_stpa_rails.co) from [`core_system.yaml`](../config/stpa/core_system.yaml) only and never compiles [`trade_hazards.yaml`](../src/cage_finance/config/stpa/trade_hazards.yaml) to `nemo`, and (2) [`generate_nemo()`](../src/gateway/governance/stpa_compiler.py) only emits an output check when `uca.condition.semantic_pattern` is non-empty, which none of `UCA-3`/`4`/`7`/`10` sets, silently omitting declared targets without error (verified, read and grep, 2026-10-28; detail section) | High | 2026-11-30 |
| POAM-2026-142 | SC-28 / SI-10 | `UCA-3` (`H-3`, PII disclosure) real enforcement is deterministic Presidio ([`_redact_pii()`](../src/integrations/presidio/redactor.py)) on input/output and regex ([`scrub_pii()`](../src/gateway/infrastructure/privacy.py)) on output, coupled behind `rails = get_nemo_rails()` inside [`nemo_node_factory.py`](../src/gateway/governance/langgraph_harness/nemo_node_factory.py) (along with Stage 1 Aho-Corasick `ac_keyword_scan()`, while `verify_and_mask_output` runs an `LLMRails` Colang pass solely to trigger `MaskPIIAction` → `scrub_pii()`). Flipping `CAGE_NEMO_ENABLED=false` without unbundling would silently disable PII redaction, regex scrubbing, and keyword screening across all advisor nodes (verified, code read, 2026-10-28; detail section) | High | 2026-11-30 |
| POAM-2026-143 | CM-6 / SA-11 | [`HealthcareCagePlugin.domain_config`](../src/cage_healthcare/plugin.py) declares `causal_graph_path` ([`causal_graph.yaml`](../src/cage_healthcare/config/causal_graph.yaml)), and [`domain_config_of()`](../src/gateway/governance/plugin_loader.py) verifies that the file exists on disk at startup, but nothing in `src/cage_healthcare/` ever reads `causal_graph_path` or constructs a causal tier (verified, grep, 2026-10-28) | Low | 2026-12-31 |

### EU ECB Region (EU_ECB)

| ID | Control | Description | Severity | Target Date |
|----|---------|-------------|----------|-------------|
| EU-DORA-001 | DORA Art. 10 | Compliance bridge endpoint for DORA ICT operational resilience evidence not yet implemented | High | 2026-12-31 |
| EU-AI-ACT-001 | EU AI Act Art. 9 | Compliance bridge endpoint for EU AI Act risk management system evidence not yet implemented | High | 2026-12-31 |
| EU-GDPR-001 | GDPR Art. 22 | Compliance bridge endpoint for GDPR human oversight of automated decisions not yet implemented | High | 2026-12-31 |
| EU-001 | EU AI Act Art. 27 | FRIA gating normative provider is in stub mode; external compliance validation provider not yet configured for EU_ECB | High | 2026-12-31 |
| POAM-2026-099 | EU AI Act Art. 27 / SI-10 | FRIA (`CTRL_FRIA_006`) was never enforced: from v2.0.0-dev.1 (2026-06-01) `enforce_fria_boundary()` had no pipeline caller, so no EU_ECB decision consulted an impact assessment. Remediated in `refactor/fria-jurisdiction` by the EU_ECB-only `fria` jurisdiction tier; closes at merge | High | 2026-10-15 |
| POAM-2026-113 | EU AI Act Art. 27 / AC-3 / SI-10 | The provider_01 FRIA authority request is built from self-asserted facts: `mandate_status`, `kya_status` and `actor_authenticated` are constants (`ACTIVE`, `VERIFIED`, `true`), and the mandate, screening, counterparty and account fields come from request params with permissive defaults (`DEFAULT-MANDATE`, 1,000,000, `2099-12-31`, `CLEAR`). The partner's determination can therefore rest on facts nobody verified. Reported in GHSA-f6xq-23f7-9grm by Dominik Blain (Ironproof); open pending a partner wire-contract revision and over-the-wire conformance | Moderate | 2026-12-31 |
| POAM-2026-128 | SI-10 | The regional tier-1 keywords are not loaded. The EU overlay lists `BYPASS FRIA`, `GDPR OVERRIDE` and `IGNORE FAIRNESS CHECKS`; the APAC overlay lists `BYPASS FEAT CHECKS` and `IGNORE FAIRNESS ASSESSMENT`. Every region loads the same 14 global keywords, because the overlay merges only `domains.*`; the eu-dev and apac-dev headers say the extras are active (verified 2026-10-28; [`JURISDICTION_INVENTORY.md`](operations/JURISDICTION_INVENTORY.md)). | Moderate | 2026-11-30 |
| POAM-2026-129 | AU-6 | Two HITL SLA sets. The runtime escalates within 4, 8 and 12 hours (US, EU, APAC). The thresholds files and the finance constants say 4, 2 and 1, citing DORA Art. 10 and MAS FEAT. Whether either regulation sets such a deadline is being established; if one does, the runtime misses it (verified values; [`JURISDICTION_INVENTORY.md`](operations/JURISDICTION_INVENTORY.md)). | Moderate | 2026-11-15 |
| POAM-2026-130 | CM-6 | In Terraform, `enable_eu_ecb_compliance` and `enable_apac_mas_compliance` do exactly what `enable_nist_compliance` does: all three feed only `any_compliance_active`. Their descriptions claim distinct effects (verified, grep; [`JURISDICTION_INVENTORY.md`](operations/JURISDICTION_INVENTORY.md)). | Low | 2026-12-31 |
| POAM-2026-132 | CM-6 | `eu-dev` and `eu-prod` list `europe-west1-d` for their GPU node pools, and that zone offers neither L4 nor `g2-standard-8`. `europe-west1-b` and `-c` offer both (verified, Compute API, 2026-10-28). The pool is created whenever `enable_gpu_node_pool = true`, whatever the backend, so both EU profiles are undeployable as shipped; GKE rejecting the pool is inferred ([`JURISDICTION_INVENTORY.md`](operations/JURISDICTION_INVENTORY.md)). | Moderate | 2026-11-30 |

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
| POAM-2026-023 | SC-4 / SI-2 | **External Reconciliation Not Enforced on Atomic Commit Path** — discovered 2026-08-28 by Miracle Owolabi (external security researcher, OWASP AI Exchange Author). `LUA_ATOMIC_CBF` read `safety:current_cash` directly instead of KMS-signed reconciled balance from `reconciliation:verified_balance`. This bypassed five separate controls: (1) KMS signature verification (POAM-2026-031, POAM-2026-038), (2) `_CBF_STRICT_MODE` fail-closed behavior, (3) R-04 replay sequence defense (POAM-2026-054), (4) TTL staleness rejection, (5) R-05 fence-epoch validation. Atomic commit enforcement used self-reported balance without verification. Reconciliation subsystem could validate external balance without influencing trade authorization. **Additional Findings:** Fence-epoch regression detection (R-05) was implemented but never executed on commit path. Local debit tracking gap allowed double-spend within reconciliation window. Remediated by creating `_resolve_ground_truth_balance()` seam for KMS-verified balance resolution, modifying `LUA_ATOMIC_CBF` to accept ground truth balance as ARGV[5], adding fence-epoch regression detection on commit path, adding local debit tracking to prevent double-spend within reconciliation window. Remediation commit: `fix(cbf)!: enforce POAM-023 reconciliation on atomic commit path`. Test coverage: 5 new test cases in `tests/cage_finance/test_cbf_reconciliation.py`. **Related POAMs Closed:** POAM-2026-031, POAM-2026-038, POAM-2026-054 (all enforced via reconciliation path). **Dependency:** This fix assumes accurate balance values from the reconciliation worker. PR #93 (zero balance masking fix) must be deployed first to ensure `GcsLedgerProvider` and `ObjectStoreLedgerProvider` return accurate 0.0 balances for drained accounts rather than fallback values. **Correction (2026-10-27):** moving the balance read out of `LUA_ATOMIC_CBF` (ARGV[5]) also removed what had serialized concurrent commits. In the reproduction recorded under POAM-2026-070, two concurrent trades that are admissible only one at a time: one of two committed at `9a7fabe7` (before this remediation), both at `21ad845a` (this remediation, #102), one again from #256 (`1eed8394`). See POAM-2026-070. | 2026-08-28 |
| POAM-2026-031 | CBF / SI-2 | External CBF state reconciliation not implemented — remediated by `src/gateway/governance/reconciliation/daemon.py` (v2.1.0); reconciled balances are KMS-signed before Redis write; CBF fails closed on TTL expiry. **CLOSED via POAM-2026-023 remediation** (2026-08-28) — KMS signature verification now enforced on atomic commit path. | 2026-07-27 |
| POAM-2026-032 | SA-11 | `e5dad7eb^:src/gateway/governance/ftra_reachability.py` was an unwired `FtraReachabilityGate` scaffold committed alongside the production `src/gateway/governance/ftra/` package in the same commit but never imported by `SymbolicGovernor` or any production code path; its dedicated test file (`e5dad7eb^:tests/test_ftra_reachability.py`) exercised only this dead code, giving a false impression of FTRA test coverage — remediated by deleting both files; documentation across 5 files corrected to describe the actual `ftra/` implementation (`PlanGraphAnalyzer`, `IrreversibilityClassifier`, `create_ftra_node`) instead of the removed scaffold. **Correction (2026-10-27):** `a2a338b8` (2026-09-16), a sweep of dangling documentation paths, repointed this row from the deleted scaffold to `src/gateway/governance/ftra/graph_analyzer.py`, a production module that was never deleted. The row then named a file that exists but is not the one it describes. Both deleted files are now pinned to the commit before `e5dad7eb` removed them | 2026-07-30 |
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
| POAM-2026-046 | SA-9 / External | Provider 03 integration boundary was unspecified at the code level (`CAGE-REM-006`). Remediated by implementing `Provider03NormativeProvider` adapter in `src/integrations/provider_03/` satisfying the 3-endpoint `NormativeProvider` contract and bind receipt ingestion (commit `88fa9d7`). Covered by `tests/integrations/provider_03/test_provider_03_adapter.py` (moved there unchanged in #218). | 2026-08-11 |
| POAM-2026-030-B | SC-7 / AC-4 | `CAGE_FTRA_BOUNDARY_ENABLED` feature flag removed — FTRA boundary check is now **mandatory** and unconditional in `SymbolicGovernor._run_checks()` (line 970–999 of `src/gateway/governance/governor/stages/ftra.py`). Risk R-03 (Trust Boundary Bypass) is now fully mitigated at the controller level; direct HTTP access to `/validate-action` or ext_authz can no longer bypass FTRA classification. The in-graph `ftra_node` remains active as a first-pass gate. See [`docs/operations/FTRA_COMPENSATING_CONTROLS.md`](operations/FTRA_COMPENSATING_CONTROLS.md) for NetworkPolicy defense-in-depth documentation (still in place for R-02 mitigation). | 2026-08-16 |
| POAM-2026-050 | AC-3 / SI-7 | `NARROW` governance decision primitive added for partial-authority execution with clamped scope — enables constrained action approval when full approval is not warranted but outright denial would be overly restrictive. Implemented in `src/gateway/governance/decisions.py` and integrated into `src/gateway/governance/governor/verdicts.py`. Feature flag: `CAGE_NARROW_ENABLED` (default `false`). | 2026-08-16 |
| POAM-2026-051 | AC-3 / SI-7 | `PAUSE` governance decision primitive added for resumable execution suspension with cryptographic token-based resume (`pause_primitive.py`, `/v1/pause/*`, `CAGE_PAUSE_ENABLED`). **Superseded 2026-10-01:** the primitive, the verdict, `ViolationKind.TRANSIENT`, the endpoints and the flag were removed (`docs/BREAKING_CHANGES_v3.md` P4-1–P4-5) because no tier ever produced a `TRANSIENT` violation, so `PAUSE` was unreachable in every posture. A transient fault is a `HARD` violation → `DENY` with a refusal receipt. `proof/model.py` `phases_closed` now asserts the model names no verdict the runtime lacks. | 2026-08-16 |
| POAM-2026-052 | AU-12 | `DEFER` tokens now persisted via `DeferQueue` for client polling — replaces bare UUID generation with persistent queue-backed deferral state. `SymbolicGovernor._park_defer_context()` now atomically enqueues defer tokens to Redis `db=1` with full audit trail. | 2026-08-16 |
| POAM-2026-053 | SC-4 / SI-2 | Monotonic fence epoch counter added for Redis failover safety — prevents stale replica reads during primary/replica failover by incrementing epoch on each write and validating epoch freshness on reads. Implemented in `src/gateway/governance/safety/cbf_engine.py`. Feature flag: `CAGE_REDIS_SYNCHRONOUS_REPLICATION` (default `true`). | 2026-08-16 |
| POAM-2026-054 | SC-8 / SI-7 | Monotonic sequence numbers embedded in KMS-signed balance payloads for reconciliation replay defense — prevents replay attacks where stale signed balances could be re-submitted. Implemented in `src/gateway/governance/safety/cbf_engine.py` and `src/gateway/governance/reconciliation/daemon.py`. Feature flag: `CAGE_RECONCILIATION_REPLAY_DEFENSE` (default `false`). **CLOSED via POAM-2026-023 remediation** (2026-08-28) — R-04 replay sequence defense now enforced on atomic commit path. | 2026-08-16 |
| POAM-2026-055 | AU-12 | `EVIDENCE_CHAIN_BLOCKING` default changed from `false` to `true` — evidence stream now synchronously blocks until evidence records are durably persisted to Langfuse backend, providing stronger audit durability guarantees at the cost of slightly increased latency. Implemented in `src/gateway/governance/evidence/stream.py`. | 2026-08-16 |
| POAM-2026-056 | SI-7 / SC-4 | Two-phase pipeline reordering in `SymbolicGovernor._run_checks()` — decouples read-only validation gates (Phase 1: STPA, Confidence, OPA, Consensus, Causal, FRIA) from state-mutating gates (Phase 2: CBF Lua atomic check+commit, FiscalLimitGuard), eliminating downstream budget leakage and saga-atomicity gaps. | 2026-08-18 |
| POAM-2026-057 | SI-7 / CA-7 | Causal Gatekeeper fail-closed on non-positive slope ($\beta \le 0$) and bounded marginal risk scoring $\min(1.0, \max(0.0, 0.5 + \beta \times \text{amount})) \in [0.0, 1.0]$. **Correction (2026-10-26):** no release enforced this formula. v3.0.0–v3.3.0 fitted $\beta$ per dollar and divided by `normalization_scale` again, so the boundary tripped 10,000× too high. See POAM-2026-114. **Correction (2026-10-27):** the formula itself can fail open. Its 0.5 is not estimated and it has no volatility term, so the trip amount does not tighten as volatility rises. See POAM-2026-117. | 2026-08-18 |
| POAM-2026-058 | SC-4 / SI-2 | FiscalLimitGuard rollback and release window-key verification — ensures counter rollbacks do not execute against expired daily keys, preventing negative counter underflow across TTL boundaries. | 2026-08-18 |
| POAM-2026-059 | SI-7 / SA-11 | Formal verification proof model extended to 57 sequential / 66 concurrent reachable states with single-use, TTL, and downstream actuator choke-point verification in Gap 2 negative controls (`proof/model.py`). | 2026-08-18 |
| POAM-2026-061 | SC-13 / IA-5 | Ed25519 signature verification defect in `src/gateway/governance/kms_signer.py` — `_kms_verify()` rejected all Ed25519 signatures due to incorrect `hashlib.new("raw", ...)` call (no such algorithm) and wrong isinstance branch. Remediated by fixing Ed25519 detection logic and removing the invalid hashlib call. Covered by `tests/test_kms_signer_new_features.py` regression tests. FlowSignal Phase 2 ST-1. Remediation commits: `8b1e803d`, `54d307e2`. | 2026-08-27 |
| POAM-2026-060 | SC-13 / SI-7 | ✅ **CLOSED — RFC 8785 JCS migration complete.** Every executable `json.dumps(..., sort_keys=True)` canonicalization site in `src/` now uses `jcs_canonicalize_plan()`; zero remain (excluding the vendored RFC 8785 reference implementation under `src/gateway/governance/vendor/jcs/` and docstring references). Migrated surfaces: the `ContextAccumulator` and `EvidenceStreamSink` hash chains (write and verify paths migrated atomically, with `_SCHEMA` sentinels bumped to `cage-context-accumulator/2.0` and `cage-evidence-stream/2.0` so the break is self-identifying), the WORM/KMS-signed UCA record signing path in `src/gateway/governance/uca_logger.py`, the JWS header/payload in `consequence_token.py` (60 s TTL), routing seals in `routing_seal.py` (30 s TTL), OPA and query cache keys, the reconciliation signed balance (300 s TTL), the control-registry profile hash, and provider receipt/state digests. Sites previously relying on `default=str` received explicit `datetime`/`Decimal` pre-normalization (`_normalize_for_jcs()` in the compliance-bridge modules) because `jcs_canonicalize_plan()` has no `default=` escape hatch. **Record correction — the original finding was factually wrong on three counts:** (1) it stated "10 identified sites" when the real figure was ~25 executable call sites across 32 `sort_keys=True` occurrences; (2) it claimed the hashes "are compared against persisted data", which was true only for the WORM UCA record — all other chains are self-verifying, recomputing digests with the same function used at write time, with no independently-stored ground truth; (3) it recorded a backward-compatibility blocker that did not exist — no adopter deployment's chains could be invalidated, and the repository had already shipped an equivalent canonicalization break for `normative_provider.py`. The WORM/KMS path was migrated with **no compatibility shim** following the deactivation of the data-at-rest exception in [`AGENTS.md`](../AGENTS.md) (relocated to *Dormant Rules — Reactivate When CAGE Begins Real Deployments*); pre-change WORM records will not verify under the new algorithm. Breaking changes documented in [`docs/BREAKING_CHANGES_v3.md`](BREAKING_CHANGES_v3.md). Lula result: no manifest change required (all Lula manifests assert over Kubernetes resources; verified — see *Lula Verification* below); `lula-validation-au12.yaml` narrative text corrected for the removed dual-schema apparatus. Remediation commit: `9a7fabe7`. | 2026-08-27 |
| POAM-2026-124 | SI-10 / AU-3 | Content-safety checks that did not run were reported as passed. Remediated in #566 (`493727f5`): every path that reaches no verdict (rails absent, "No main flow found" in all three rail functions, any other error, `CAGE_INFERENCE_BACKEND=none`) refuses with a reason code, and the advisor records only an exact `SAFE` as safe. Evidence: [`test_content_safety_no_verdict.py`](../tests/test_content_safety_no_verdict.py) and [`test_inference_backend_none.py`](../tests/test_inference_backend_none.py). In #566's recorded mutation check, reverting each path turns its test red, which meets POAM-2026-120's closure requirement. Re-run on `493727f5` on 2026-10-28 | 2026-10-28 |

| POAM-2026-062 | AU-12 | Evidence-stream v1.0/v1.1 dual-schema machinery (surfaced by code inspection as **BC-01**, not previously tracked in this POAM). `src/gateway/governance/evidence/stream.py` retained a full dual-schema apparatus — `_detect_schema_version()`, `migrate_record_1_0_to_1_1()`, `get_last_v1_0_hash()`, `_link_hash_v1_1()`, and the `schema_version` field on `EvidenceRecord` — despite v1.0 write support already being removed and `verify_record()` already hard-rejecting v1.0 records. A repo-wide search found zero production callers outside the module itself; the sole external consumer was a test suite existing only to exercise the dead compatibility path. Remediated by deleting the four functions and the `schema_version` field, collapsing `_link_hash_v1_1()` into a single unconditional `_link_hash()`, and deleting `9a7fabe7^:tests/test_dual_schema_verification.py`; still-relevant hash-determinism assertions were folded into `tests/test_evidence_stream.py`. Schema sentinel bumped to `cage-evidence-stream/2.0`. Lula result: no manifest change required; the stale dual-schema narrative in `compliance/lula/lula-validation-au12.yaml` was corrected. Remediation commit: `9a7fabe7`. | 2026-08-27 |
| POAM-2026-063 | SA-9 | Provider 03 backward-compatibility alias methods (**BC-02**, previously untracked). `Provider03NormativeProvider` exposed three dict-returning shadow methods — `fetch_legal_baseline()`, `validate_external_fria()`, `submit_evidence_chain()` — alongside the canonical dataclass-returning `NormativeProvider` protocol. **Security-relevant:** `validate_external_fria()` returned a hardcoded `APPROVED` verdict unconditionally, so any caller reaching it would have silently bypassed governance. None of the three were part of the canonical protocol and the only callers were integration tests. Remediated by deleting all three aliases and rewriting the integration tests against the canonical three-endpoint contract required by the Universal Protocol Conformance Suite. Remediation commit: `9a7fabe7`. | 2026-08-27 |
| POAM-2026-064 | SA-9 / CA-7 | Provider 01 legacy binary `admitted`/`findings` response fallback (**BC-03**, previously untracked). **Security-relevant — closes a latent fail-open.** `src/integrations/provider_01/provider.py` accepted two wire formats and fell back to a legacy binary shape when the FlowSignal tri-state `decision` field was absent. A response that lost its `decision` key — for example a proxy error page that happens to parse as JSON carrying `admitted: true` — was admitted without ever passing through `_map_flowsignal_decision()` or ConsequenceToken minting. Two tests in the Universal Protocol Conformance Suite were actively locking this fail-open behavior in. Remediated by deleting the legacy branch: a missing or unrecognized `decision` now fails closed with `ValidationResult(admitted=False)` and a structured finding carrying `code="cage.endpoint_error"`, matching the fail-closed vendor-adapter semantics mandated by [`AGENTS.md`](../AGENTS.md). The two conformance tests were **inverted**, not deleted, so the fail-closed contract is now the asserted one. Remediation commit: `9a7fabe7`. | 2026-08-27 |
| POAM-2026-065 | AU-12 / AU-10 | Provenance-chain legacy decision vocabulary (**BC-04**, previously untracked). `VALID_DECISIONS` in `src/gateway/governance/provenance_chain.py` admitted eight values — the six canonical `GovernanceDecision` members plus the execution-phase statuses `BLOCK` and `ESCALATE` — weakening the provenance record's audit semantics by making `BLOCK` and `DENY` indistinguishable to a downstream auditor. Remediated by remapping emitters (`BLOCK → DENY`, `ESCALATE → REQUIRE_APPROVAL`) and narrowing `VALID_DECISIONS` to the canonical six: `ALLOW`, `DENY`, `DEFER`, `NARROW`, `PAUSE`, `REQUIRE_APPROVAL` (since 2026-10-01 derived from the `GovernanceDecision` enum — five values, `PAUSE` retired). `build_provenance_record()` now raises `ValueError` for `BLOCK`/`ESCALATE`. Covered by `tests/test_provenance_chain.py`. Remediation commit: `9a7fabe7`. | 2026-08-27 |
| POAM-2026-066 | AU-12 | Duplicated legacy DEFER response fields (**BC-05**, previously untracked). Three sites emitted three names for the same value in an audit-relevant response body: `verdict` and `missing_input_reason` in `src/gateway/governance/decisions.py` and `9a7fabe7^:src/gateway/server/agent_gateway_adapter.py` (deleted with the Agent Gateway target in #304), and `defer_id` in `src/gateway/governance/governor/governor.py`. Beyond the redundancy this created a divergence risk if one site were updated and the others not. Remediated by deleting all three legacy keys from the response bodies and the `DeferResponse` model; the canonical fields are now `decision`, `defer_token`, and `classification_reason`. Assertions updated in `tests/test_defer_queue.py` and `tests/test_governance_middleware.py`. Remediation commit: `9a7fabe7`. | 2026-08-27 |
| POAM-2026-067 | SC-4 | Fiscal limit guard legacy window-key fallback (**BC-07**, previously untracked). **Security-relevant — defeated an existing control.** When `rollback()` in `src/gateway/governance/safety/resource_guard.py` was called with neither `window_key` nor `token`, a legacy fallback silently computed the *current* window rather than the window the reservation was made against. This guaranteed `target == current`, so the cross-window guard sitting immediately below it could never fire on that path — nullifying the very control **POAM-2026-058** was closed to add. Remediated by making `window_key` or `token` mandatory: `rollback()` now raises `ValueError` when neither is supplied, mirroring the existing `amount`/`amount_minor` guard, and all callers were updated to pass the `ReservationToken`. Remediation commit: `9a7fabe7`. | 2026-08-27 |
| POAM-2026-068 | CM-6 | `ControlRegistry` legacy control-mappings fallback (**BC-08**, previously untracked). **Security-relevant — reintroduced a closed defect.** `src/gateway/governance/constants.py` fell back to `_LEGACY_PATH` (`config/control_mappings.json`) with `region="LEGACY"` whenever the regional compliance profile was missing. A region-guarded system that silently degrades to a non-regional profile emits audit spans bearing jurisdictionally wrong citations — precisely the class of defect that **POAM-2026-034**, **POAM-2026-035** and **POAM-2026-036** were opened and closed to eliminate; the fallback reintroduced it through the back door. Remediated by deleting `_LEGACY_PATH` and the fallback branch; a missing regional profile now raises `RuntimeError` at startup ("Cannot start governance engine without a valid profile"). Adopter deployments must provision `config/compliance/{US_FED,EU_ECB,APAC_MAS}_BASELINE.json` — see [`docs/BREAKING_CHANGES_v3.md`](BREAKING_CHANGES_v3.md). Verified across all three region-gated test postures. Remediation commit: `9a7fabe7`. | 2026-08-27 |
| POAM-2026-069 | SC-4 / SI-2 | **R-05 Fence-Epoch Validation Bypass** — discovered during POAM-2026-023 remediation (2026-08-28) by Miracle Owolabi (external security researcher, OWASP AI Exchange Author). Fence-epoch regression detection (R-05) was implemented in reconciliation subsystem but never executed on the atomic commit path. The commit path read balances without checking if the fence epoch had regressed (indicating a Redis primary/replica failover or clock skew), potentially accepting stale data from a failed-over replica. Remediated by adding fence-epoch validation in `_resolve_ground_truth_balance()` before CBF atomic commit. The fence check now fails closed with `REPLICATION_UNCONFIRMED` when epoch regression is detected. Covered by `test_fence_epoch_regression_rejected` in `tests/cage_finance/test_cbf_reconciliation.py`. Closed as part of POAM-2026-023 remediation. **Correction (2026-10-27):** the original text cited a `test_reconciliation_daemon` module, which has not existed at any commit; the test named above was added with this row in #102 (`21ad845a`). It asserts a refusal reading `Fence epoch regression`; `REPLICATION_UNCONFIRMED` is the refusal for a Redis `WAIT` timeout, not for an epoch regression. | 2026-08-28 |
| POAM-2026-070 | SC-4 / SI-2 | **Local Debit Tracking Gap** — discovered during POAM-2026-023 remediation (2026-08-28) by Miracle Owolabi (external security researcher, OWASP AI Exchange Author). No local debit tracking existed to prevent double-spend within the reconciliation window (300s TTL). An attacker could submit multiple concurrent trade requests that individually pass CBF balance checks but collectively exceed available funds, exploiting the gap between local Redis state and external ledger synchronization. ~~Remediated by adding `_register_pending_debit()` in `_resolve_ground_truth_balance()` to atomically decrement local pending balance before CBF evaluation, preventing double-spend races. Covered by test cases in tests/test_reconciliation_daemon.py.~~ Closed as part of POAM-2026-023 remediation. **Correction (2026-10-27): this entry was closed while the control did not operate.** Neither `_register_pending_debit()` nor a `test_reconciliation_daemon` module has existed at any commit; the struck text was added with this row in #102 (`21ad845a`, 2026-08-29). The debit tracking #102 did add read the debit list before the `LUA_ATOMIC_CBF` call and appended to it afterwards, and the script checked a balance computed in Python, so concurrent requests passed against the same balance: the attack this entry describes. Reproduced on Redis 7.4.12 with two trades of $41,250 against a reconciled $100,000, each admissible alone and not together: run one after the other, the second is refused; run concurrently, on one CBF instance or two, both commit, at `21ad845a` and at `46447c2f` (2026-09-25), the parent of #256. From #256 (`1eed8394`, 2026-09-26) the fence-epoch compare-and-set refused the second concurrent commit. #346 (`980e1ace`, 2026-10-02) moved the debit read and write into the script, which is what refuses it since #506 (2026-10-22) made the compare-and-set retry instead. At `37b9eaa1` (fakeredis harness) the same trades admit one of two in every variant: sequential, concurrent on one or two instances, with and without forced interleaving. No committed test exercised this scenario until `test_concurrent_trades_over_the_limit_admit_one` in `tests/test_cbf_settlement_ledger.py`, which runs the two trades concurrently on one CBF instance and on two, with every Redis call yielding to the event loop. In a sensitivity check it fails when the debit write is moved out of the script (both trades commit, even with the fence-epoch check in place) and passes when only the fence-epoch check is removed. See POAM-2026-120 | ~~2026-08-28~~ original closure, incorrect; control operating from 2026-09-26 (#256); verified 2026-10-27 |
| CAGE-SEC-003 | ISO 42001 A.8.4 | **DeferQueue Phase-3 Confidence Recheck Bypass** — discovered 2026-08-28 by Miracle Owolabi (external security researcher, OWASP AI Exchange Author). `/v1/defer/{defer_id}/inject` endpoint called `queue.resolve()` directly without invoking `replay_evaluate()`, bypassing Phase-3 confidence recheck against `DEFER_CONFIDENCE_THRESHOLD` (0.70). Additionally published forged ISO 42001 A.8.4 attestations. Deferred tokens could be resolved without validating injected context raised confidence above threshold. Audit trail contained inaccurate compliance attestations. Remediated by wiring `replay_evaluate()` into `/v1/defer/{defer_id}/inject` endpoint, making `confidence_score` required field with NaN validator, returning 409 Conflict for sub-threshold injections, and splitting SSE events: `DEFER_PARKED` vs `DEFER_RESOLVED` for audit accuracy. Remediation commit: `fix(defer)!: enforce Phase-3 confidence recheck on token injection`. Test coverage: 6 new test cases in `tests/test_defer_queue.py`. | 2026-08-28 |
| CAGE-SEC-004 | AC-3 / SI-7 | **NARROW Verdict Transport Architectural Gap** — discovered 2026-08-28 by Miracle Owolabi (external security researcher, OWASP AI Exchange Author). NARROW verdicts computed narrowed params but Envoy `OkHttpResponse` proto has no body field. Unclamped requests forwarded to upstream. Currently fails-safe (seal mismatch) but feature incomplete. NARROW feature non-functional in ext_authz deployments. Requests executed with original (unclamped) parameters despite NARROW verdict. Remediated by implementing receipt-based NARROW verdict transport using Redis fetch-and-burn pattern: receipt keyed by seal prefix (`narrow:receipt:{seal[:32]}`; follow-up 2026-10-21 (`fix/narrow-receipt-key`, #490): keyed by `narrow:receipt:{sha256(seal)}`, because the first 32 characters of a JWT seal fall inside its constant base64url header, so concurrent trades' receipts collided; regression tests in `tests/governor/test_narrow_receipt_key.py`), MCP server fetches and burns receipt before execution, signature verification prevents receipt forgery, 5-minute TTL prevents receipt leakage. Remediation commit: `feat(narrow)!: implement receipt-based NARROW verdict transport`. Test coverage: 9 new test cases in `tests/test_narrow_transport.py`. | 2026-08-28 |
| POAM-2026-072 | AC-3 / SC-4 | Two-Stage Execution Boundary (ADR-008 Phase 1 & 2) — remediated by ActuatorRegistry ([`src/gateway/governance/execution_actuator.py`](../src/gateway/governance/execution_actuator.py)) & BrokerActuator wiring in [`src/cage_finance/tools/tool_provider.py`](../src/cage_finance/tools/tool_provider.py)). OSCAL AU-10/AU-12 updates completed in compliance/oscal/sp800-53-component-definition.yaml documenting RawMessageSigner protocol abstraction and multi-vendor KMS lifecycle management. | 2026-09-14 |
| POAM-2026-073 | AC-4 | ~~Semantic classifier boundary enforcement (`allow_extra_fields=False`) — remediated by FTRA boundary validation schema hardening~~ **Claim withdrawn 2026-10-01:** no `ActionSchema` was ever registered, so this remediation never ran. The FTRA semantic validator was deleted in `refactor/ftra-scope` (Phase 7), and AC-4 was removed from the US_FED control metadata and from the FTRA OSCAL component, which is restated as `ftra0001-4e47-bbc8-irreversibility01`. Its SI-10 statement now cites value validation by the STPA UCA rules and domain OPA ([`FTRA_SCOPE.md`](governance/FTRA_SCOPE.md)), verified by the OSCAL export and [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py). AC-4 remains claimed only for NetworkPolicy flow enforcement (`deployment/k8s/`). | 2026-09-14 (withdrawn 2026-10-01) |
| POAM-2026-074 | SI-10 | Multi-component input validation (NeMo Guardrails + FTRA integration) — remediated by [`src/gateway/governance/ftra/`](../src/gateway/governance/ftra/) package integration | 2026-09-14 |
| POAM-2026-024 | CM-6 / AC-3 / AU-10 / SC-8 / SC-23 | ✅ **CLOSED — Sprint 6 client-governor interaction formal verification complete.** TLA+ LangGraph harness specification extended with client SDK session lifecycle states (`Active`, `ParkedForReview`, `PausedBudgetExceeded`, `Completed`), consecutive denial budget enforcement (`MaxConsecutiveDenials = 2`), and single-use deferral ticket invariant (`SingleUseDeferralTicket`). OSCAL component definition created at [`compliance/oscal/components/cage_client_sdk.yaml`](../compliance/oscal/components/cage_client_sdk.yaml) mapping AC-3 (out-of-process PDP client mediation), AU-10 (W3C traceparent and HMAC routing seal validation), SC-8 (mTLS HTTP/2 transport), and SC-23 (routing seal micro-TTL validation). TLA+ model checker parameters documented in [`proof/README.md`](../proof/README.md). Verified against staging environment with formal verification proof model showing `BudgetNeverExceededWithoutPause` invariant holds: `(consecutive_denials > MaxConsecutiveDenials) => (phase = "PausedBudgetExceeded")`. Verification commit: `4d587fdc` (superseded by `ffd99995`, #380). **Note 2026-10-03:** the 2026-09-18 verification claim was vacuous. `LangGraphHarness.tla` never loaded in TLC (its cfg named constants the spec lacked and its actions left variables unassigned), the session states above were unreachable from `Init`, and `SingleUseDeferralTicket` was a tautology. It is superseded by the POAM-2026-091 verification (#380), which models the code's per-turn pause (`HARD_PAUSE_BUDGET_EXCEEDED` once a refusal brings `consecutive_denials` to 2) instead of the session states, and by POAM-2026-093, the defect the check found. | 2026-09-18 |
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
| POAM-2026-095 | SC-13 / SC-12 / IA-5 | ✅ **CLOSED — Asymmetric routing seals round-trip; kid is required.** `generate_seal()` wrote a provider label into the JWS `alg` header and KMS ECDSA signatures stayed DER-encoded, so no asymmetric seal could verify. A seal with no `kid` also fell back to the single published key. The header now carries `signer.jose_alg`, [`KMSGovernanceSigner.sign_jws()`](../src/gateway/governance/kms_signer.py) converts DER to raw R‖S, the EC allow-list is ES256/384/512, and [`jwks.py`](../src/gateway/governance/jwks.py) fails closed without a `kid`. Evidence: [`tests/test_routing_seal_asymmetric_roundtrip.py`](../tests/test_routing_seal_asymmetric_roundtrip.py). `make test-fast` on the branch: 6203 passed, 107 skipped, 0 failed; OSCAL SSP export + [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) (50 passed) on 2026-10-03. Lula: no assertion references the affected resources. Remediation commits on `fix/paper-verify-findings`: `9c68a6e8`. Squash SHA: record on merge. | 2026-10-03 |
| POAM-2026-096 | CA-7 / SI-10 | ✅ **CLOSED — Reconciler cadence keeps verified state alive; floor branch never writes state.** The reconciler ran as a 5-minute CronJob against a 300 s verified-state TTL, so the state expired between runs. Its discrepancy-floor branch also overwrote the CBF state key. [`reconciliation-worker.yaml`](../deployment/k8s/reconciliation-worker.yaml) is now a single-replica Deployment in loop mode (60 s poll), `run_loop()` in [`daemon.py`](../src/gateway/governance/reconciliation/daemon.py) refuses to start when the TTL is under 2× the poll interval, and the floor branch only counts, fences and invalidates. Evidence: [`tests/test_reconciliation_worker_manifest.py`](../tests/test_reconciliation_worker_manifest.py), [`tests/test_reconciliation_discrepancy_floor.py`](../tests/test_reconciliation_discrepancy_floor.py). `make test-fast` on the branch: 6203 passed, 107 skipped, 0 failed; OSCAL SSP export + [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) (50 passed) on 2026-10-03. Lula: no assertion references the affected resources. Remediation commits on `fix/paper-verify-findings`: `9c68a6e8`. Squash SHA: record on merge. | 2026-10-03 |
| POAM-2026-097 | SI-10 / SC-23 | ✅ **CLOSED — Ground-truth sequence check is atomic and fails closed.** The CBF replay check read the last sequence and wrote the new one in separate calls, and a Redis error let the check pass. [`cbf_engine.py`](../src/gateway/governance/safety/cbf_engine.py) now does one Lua compare-and-advance (reject regressions, accept an equal re-read) and treats a Redis error as a violation. Evidence: [`tests/test_replay_defense.py`](../tests/test_replay_defense.py). `make test-fast` on the branch: 6203 passed, 107 skipped, 0 failed; OSCAL SSP export + [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) (50 passed) on 2026-10-03. Lula: no assertion references the affected resources. Remediation commits on `fix/paper-verify-findings`: `9c68a6e8`. Squash SHA: record on merge. | 2026-10-03 |
| POAM-2026-102 | CM-6 / `CTRL_AGT_001` | ✅ **CLOSED — Regional finance limits are enforced.** Before `ecca70b9` (#417) the EU_ECB and APAC_MAS `config/thresholds/{REGION}_BASELINE.json` finance values (trade-confidence floor 0.97 / 0.96, CBF gamma, drawdown limit, consensus threshold, STPA UCA-5/UCA-6/FIN-2 limits) were declared but not read; every region ran on the global values. `ecca70b9` applies the baseline `domains` object as a fail-closed overlay ([`regional_overlay.py`](../src/gateway/governance/schemas/regional_overlay.py)), adds [`TradeConfidenceTier`](../src/cage_finance/tiers/trade_confidence_tier.py), and refuses assembly on a thresholds/jurisdiction region mismatch ([`assembly.py`](../src/gateway/governance/governor/assembly.py)). FIN-1 residual tracked as POAM-2026-103 (now closed). Lula: not run (see detail section). Remediation commit: `ecca70b9`. | 2026-10-06 |
| POAM-2026-103 | SI-10 / CM-6 | ✅ **CLOSED — FIN-1 regional sell-fraction limit is enforced.** `domains.finance.stpa.max_sell_portfolio_fraction` (US_FED 0.10, EU_ECB 0.08, APAC_MAS 0.09) had no runtime reader. New UCA-13 in [`trade_hazards.yaml`](../src/cage_finance/config/stpa/trade_hazards.yaml), compiled into [`uca_rules.py`](../src/cage_finance/stpa/uca_rules.py), refuses an `execute_trade` sell whose amount exceeds the fraction of `portfolio_total` and fails closed on a missing or non-numeric amount or `portfolio_total`. The ontology's sell-vs-holdings rule was renamed FIN-3 so the ID is unique. Lula: not run (see detail section). Remediation commit: `fa7d594b` (#421). Sell inputs from the trade tool: `52119fef` (#422); `portfolio_total` = current NAV from the server-side NAV source: `fix/fin1-portfolio-total-nav`. | 2026-10-06 |
| POAM-2026-105 | SI-10 / CA-7 | ✅ **CLOSED — Governance previews evaluate the same server-side STPA inputs as the committing run.** `POST /governance/validate-action`, the MCP `simulate_governance_check` dry run and the committing trade tool now bind `latency_ms`, `drawdown` (and its aliases) and `portfolio_total` through one kernel seam: the finance plugin contributes a resolver (`PluginContribution.server_inputs`, [`TradeInputResolver`](../src/cage_finance/tools/trade_inputs.py)), and [`bind_server_inputs()`](../src/gateway/governance/governor/server_inputs.py) drops every caller value for an owned key before resolving. The STPA stage no longer defaults `latency_ms` on dry runs, and the evaluator no longer injects 0.0 defaults. Lula: not run (see detail section). Remediation: `fix/preview-server-trade-inputs`. | 2026-10-06 |
| POAM-2026-106 | SI-10 / CM-6 | ✅ **CLOSED — UCA-6 (order size vs. daily volume) is evaluated on every trade.** No path supplied `order_size` / `daily_vol`, and the generated rule skipped when both were absent, so the regional `stpa.uca6_max_order_volume_fraction` (US_FED 0.01, EU_ECB 0.005, APAC_MAS 0.008) was never applied. UCA-6 now has `require_params: true` (a missing input is a HARD refusal), and the finance [`TradeInputResolver`](../src/cage_finance/tools/trade_inputs.py) owns both keys: `order_size` = notional `amount` / verified quote price, `daily_vol` = the symbol's average daily volume from the market-data feed. Narrow proposals are re-bound so derived inputs describe the clamped amount. Lula: not run (see detail section). Remediation: `fix/uca6-server-inputs`. | 2026-10-06 |
| POAM-2026-107 | CA-2 / AC-3 / AU-10 | ✅ **CLOSED — The warrant reliance path is verified end to end.** Verification of the EU_ECB warrant reliance gate (POAM-2026-104) rested on stage-level tests over hand-built governors (`make_governor`) and an inline "Test C" in `test_provider_05_warrant_contract.py` that computed the DEFER it then asserted. Nothing showed that the composition root wires `WarrantStage`, `WarrantCache` and the `CAGE_WARRANT_SOURCE` adapter, or that the gateway and the trade tool honour them. [`test_warrant_reliance_e2e.py`](../tests/governor/test_warrant_reliance_e2e.py) now builds the governor with `bootstrap_governor()` (real finance plugin, regional thresholds and jurisdiction, seeded `Provider05WarrantSource` holding the VEIP v0.1 vectors) and drives `POST /governance/validate-action` and `execute_trade_action()`. The simulation is deleted. The warrant source is seeded, not the partner wire (VEIP has no live endpoint; Tier 1 over-the-wire conformance stays a POAM-2026-104 closure criterion). Lula: not run (see detail section). Remediation: `test/warrant-reliance-e2e`. | 2026-10-06 |
| POAM-2026-108 | SI-10 / CM-6 | ✅ **CLOSED — A bounded trade's drawdown is measured by the gateway and B2 reads it.** `execute_trade_bounded` had no server-input resolver (the finance plugin registered one for `execute_trade` only), so the kernel passed a caller's `drawdown` and aliases through unchanged, and bounding contract B2 (daily drawdown circuit breaker) was never given any measured drawdown. The finance plugin now registers its [`TradeInputResolver`](../src/cage_finance/tools/trade_inputs.py) for every trade action (`TRADE_ACTIONS`), and the bounding tier passes B2 the bound `drawdown` (as a fraction) to compare with the regional `drawdown.limit` (US_FED 5 %, APAC_MAS 4.5 %, EU_ECB 4 %). A guard test fails if any STPA rule or tier reads an owned key for an action without a resolver. Lula: not run (see detail section). Remediation: `fix/bounded-trade-server-inputs`. | 2026-10-06 |
| POAM-2026-109 | AC-3 / SI-10 / CM-7 | ✅ **CLOSED — No code path reaches the broker with a hard-coded routing seal.** `de2b96ee^:src/cage_finance/tools/bounded_execution.py` (`execute_trade_bounded()`) had no callers, but it called the broker's `trade_executor.execute_trade` directly with the literal seal `"INTERNAL_BOUNDED_EXECUTION"`. The broker only checks that the seal is a non-empty string, so that call skipped `verify_and_consume_seal()` and `ActuatorRegistry` (ADR-008), and the actuator-seam invariant allowlisted the file. The module is deleted, the allowlist entry removed, and [`test_architectural_invariants.py`](../tests/test_architectural_invariants.py) now pins `BrokerActuator.actuate` as the only call site (scope-aware, `__init__.py` included, no other module may import `trade_executor`) and refuses any string-literal `routing_seal` in `src/`. The `execute_trade_bounded` action itself (bounding tier, terminal registry) is unchanged. Lula: not run (see detail section). Remediation: `refactor/remove-bounded-execution`. | 2026-10-06 |
| POAM-2026-110 | AC-3 / AU-10 | ✅ **CLOSED — A warrant failure on the committing run defers; it never becomes a DENY.** Under EU_ECB the gateway preview correctly returned DEFER `WARRANT_INELIGIBLE`, but the committing run of `execute_trade_action()` (`SymbolicGovernor.govern()` and its narrowed re-run) refused the same `RELIANCE_INELIGIBLE` finding through `handle_deny`: the tool returned `BLOCKED: ... [RELIANCE_INELIGIBLE_REVOKED]` and a `GOVERNANCE_REFUSAL` record entered the chain, contradicting proof claim 12 (`warranted_norm_never_fabricates_deny`) and OSCAL `eu-ecb-req-0007`. Every path (preview, commit, narrowed re-run, POST_HITL) now asks the classifier's side-effect-free `defers_on_reliance()` and defers: `GOVERNANCE_DEFERRAL` with the reliance record, no seal, no refusal receipt, tool result `DEFERRED:`. A HARD finding from an independent stage still denies (classifier ranks HARD first). For VEC-002..006 and a missing warrant the e2e test asserts no `GOVERNANCE_REFUSAL` and a `GOVERNANCE_DEFERRAL` after `execute_trade_action()`; disabling the deferral fails 25 tests. Remediation: `fix/hitl-token-warrant-defer` (#436). | 2026-10-07 |
| POAM-2026-111 | AU-3 / AU-10 | ✅ **CLOSED — Hash-chained reliance evidence carries every Warrant Contract v0.1 field.** The kernel `RelianceRecord` bound into seal, deferral and refusal evidence lacked `residual_risk_ref`, `attested_at` and `issuing_authority`; those appeared only in the ALLOW envelope's `WARRANT` attestation, which is not hash-chained, and `governing_version` meant the required version in the record but the declared version in the attestation. The record now carries all seven contract fields, splits `required_governing_version` from `warrant_governing_version`, and is the single source of the envelope attestation (`82df1b14`, #438). See below. | 2026-10-07 |
| POAM-2026-112 | AU-3 / AU-10 / SC-13 | ✅ **CLOSED — Deferral responses and evidence records use canonical signed envelopes and normalized fields.** Inspecting the real-code-path VEIP v0.1 sample bundle uncovered five evidence-format inconsistencies: (1) `POST /governance/validate-action` wrapped only `ALLOW`/`NARROW` in signed v3.0 `GovernanceEnvelope`s while returning `DEFER` and `REQUIRE_APPROVAL` as unsigned flat `schema_version: "1.0.0"` payloads, and duplicated `external_attestations` inside `envelope.payload`; (2) `_park_defer_context()` and `post_hitl_deferral_event()` serialized `Violation` dataclasses via `str(v)` (Python `repr` strings) instead of `v.to_dict()`; (3) `GOVERNANCE_DEFERRAL` and `GOVERNANCE_REFUSAL` events omitted `controlId`, leaving `control_id: ""` in Redis stream headers; (4) `params_hash` in `GOVERNANCE_DECISION` and `GOVERNANCE_DEFERRAL` events was truncated to 16 hex characters (`[:16]`, 64 bits) instead of the full 64-hex SHA-256 digest; and (5) `validate_action()` omitted `tiers_passed` from the envelope's `governance_context`. All five are fixed across [`governance_middleware.py`](../src/gateway/server/governance_middleware.py), [`governor.py`](../src/gateway/governance/governor/governor.py), [`verdicts.py`](../src/gateway/governance/governor/verdicts.py), [`routing_seal.py`](../src/gateway/governance/routing_seal.py), and [`stream.py`](../src/gateway/governance/evidence/stream.py). Lula: not run (see detail section). Remediation: `fix/defer-evidence-format`. | 2026-10-07 |
| POAM-2026-104 | AC-3 / SC-13 / AU-10 | ✅ **CLOSED — Warrant reliance gate verifies VEIP v0.2 Ed25519 signatures against an out-of-band trust anchor and passes Tier 1 over-the-wire conformance.** All four residuals from `a0deb7ad` (#423) are closed: (1) [`WarrantTrustAnchor`](../src/gateway/governance/warrant/trust_anchor.py) (pinned by raw 32-byte Ed25519 SHA-256 fingerprint `sha256:61ab867f…`) verifies `GET /.well-known/veip/key-manifest.json` into a sealed [`VerifiedKeyManifest`](../src/gateway/governance/warrant/trust_anchor.py) cached out-of-band in [`WarrantCache`](../src/gateway/governance/warrant/cache.py), and [`WarrantStandingVerifier`](../src/gateway/governance/warrant/verifier.py) resolves `warrant.kid` (failing closed on `UNKNOWN_KID`), verifies the 18-field JCS digest and Ed25519 signature (`TAMPERED_SIGNATURE` → `INELIGIBLE_AUTHENTICITY`), enforces `state_as_of` freshness (`STALE_STATE` → `INELIGIBLE_STALE`) and `norm_parameters` value parity, and emits `verification_status: VERIFIED` only after cryptographic verification succeeds; (2) [`Provider05WarrantSource`](../src/integrations/provider_05/warrant_source.py) implements live HTTP fetching (`GET /v0.2/warrants/{norm_id}` and `GET /.well-known/veip/key-manifest.json`) and passes Tier 1 over-the-wire conformance across all 8 live scenarios on `https://veip-cage-sandbox.am-43b.workers.dev` ([`test_provider_05_live.py`](../tests/integrations/provider_05/test_provider_05_live.py)); (3) post-HITL warrant deferrals retain the approval token (`fix/hitl-token-warrant-defer`, #436); (4) reliance evidence is hash-chained into seals, deferrals, and refusals (`0cdb5aaa`, #427; `82df1b14`, #438). Lula: not run (no Kubernetes resource changed). Remediation: `feat/veip-v02-conformance`. | 2026-10-10 |
| POAM-2026-126 | AC-3 / SC-7 | Staging's control plane accepted connections from any address. Remediated in #569 (`d830249c`): the gcp-gke plan refuses an empty allowlist or a /0 whenever a compliance posture is active, and `staging.tfvars` no longer ships a list. The live `cage-staging` allowlist was narrowed to operator /32s on 2026-10-28: an outside address got `HTTP 401` from the API server before, and no response after. Evidence: [`test_control_plane_access.py`](../tests/infrastructure/test_control_plane_access.py). In #569's recorded mutation check each of five mutations turns a named test red, which meets POAM-2026-120's closure requirement, and a real `terraform plan` refused the empty and /0 cases. No Lula manifest covers control-plane access; the pytest guard is the check. Re-run on `d830249c` on 2026-10-28 | 2026-10-28 |
| POAM-2026-127 | SC-7 / IA-5 | A consensus critic with no dedicated endpoint pointed at `api.openai.com` with the operator's API key. Remediated in #570 (`ba9f29ea`): `GatewayClient` uses the routed endpoint, else `VLLM_BASE_URL`, else no client, and `generate()` refuses with `INFERENCE_BACKEND_URL_MISSING`, so the critic votes ERROR and consensus escalates. Before the fix, the documented `external` minimum resolved both critic routes to `https://api.openai.com/v1/` (measured on main's code on 2026-10-28; no request was sent). Evidence: [`test_critic_endpoint_fallback.py`](../tests/test_critic_endpoint_fallback.py). In #570's recorded mutation check each of three mutations turns a named test red, which meets POAM-2026-120's closure requirement. No Lula manifest covers critic endpoints; the pytest guard is the check. Re-run on `ba9f29ea` on 2026-10-28 | 2026-10-28 |

---

## Deliberate No-Change Decisions

The following compatibility surfaces were reviewed during the backward-compatibility
remediation and **deliberately left unchanged**. They are recorded here so a future
reviewer does not re-flag them as unremediated compatibility debt.

| ID | Surface | Decision | Rationale |
|----|---------|----------|-----------|
| BC-06 | Routing seal v2 HMAC-SHA256 signing mode in [`src/gateway/governance/routing_seal.py`](../src/gateway/governance/routing_seal.py) | **Retain — no change** | Despite the `v2`/`v3` naming this is **not** a version-negotiation shim for older clients. It is the KMS-free signing mode required for local development, CI, and the offline `local`/`unit` test markers that constitute the project's primary regression gate; removing it would make the entire governance path untestable without a live Cloud KMS key. It is already fail-closed in production — verification raises `SymbolicGovernorViolation` with a `[DOWNGRADE_ATTACK]` log whenever `CAGE_SEAL_STRICT_MODE=true` or the runtime is production. The seal's hash input (now `canonical_action_bytes()`, recipe `cage-action/1`) **was** migrated to RFC 8785 JCS under POAM-2026-060 (seals are 30 s TTL and single-use, so this is not an at-rest concern); only the HMAC signing mode itself is retained. |

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

### POAM-2026-099: FRIA Declared but Never Enforced (EU_ECB)

> Renumbered on 2026-10-04 from POAM-2026-084, which was also assigned to the evidence pipeline integrity item (AU-9). The content is unchanged.

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
6. (GHSA-f6xq-23f7-9grm) The tier was not re-run after a human approval, so a determination revoked while a request was held was never observed before the seal. Jurisdiction tiers now declare `revalidated_after_approval` and POST_HITL re-runs them; a `FRIA_EXTERNAL_HOLD` is answered only by an approval given against it (`PostHitlApproval.approved_holds`). The provider payload now carries the verified workload identity (`actor_id` / `operator_urn`) and the trace id (`correlation_id`). Proof claims 10 (`post_hitl_rechecks_jurisdiction`) and 14 (`approval_answers_only_its_holds`), with runtime parity and scenario tests in the files above.

**Remaining Closure Criteria:**
1. Merge `refactor/fria-jurisdiction`; record the merge commit SHA and the actual merge date here.
2. Independent external FRIA validation remains tracked by EU-001 (provider credentials).

### POAM-2026-100: SWIFT/BIC Sanitizer Pattern Redacted Governance Verdicts

**Control:** NIST SI-10, AU-10
**Risk Level:** High
**Status:** Open (remediated in `fix/pii-swift-false-positive`, pending merge)
**Date Opened:** 2026-10-04
**Target Closure:** 2026-10-15

**Description:**
[`EvidenceStreamSink`](../src/gateway/governance/evidence/stream.py) sanitizes every event before JCS canonicalization and hashing. The SWIFT/BIC pattern in [`pii_sanitizer.py`](../src/gateway/governance/pii_sanitizer.py) (`[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?`) matched any eight- or eleven-character upper-case token. Governance verdicts and node statuses (`APPROVED`, `REJECTED`, `ESCALATE`, `COMPLETE`, ...) were permanently replaced by `[REDACTED_SWIFT]` in tamper-evident evidence. Two events differing only in such a word produced identical payloads, which undermines non-repudiation of the recorded decision.

**Remediation Implemented in Code:**
1. A BIC is redacted only when a `BIC`/`SWIFT` label precedes it in text, or when it is the value of a BIC/SWIFT dict key. Its positions 5-6 must also be an ISO 3166-1 alpha-2 country code. A country check alone does not separate English words (`ESCALATE` → `AT`), so the contextual cue is required.
2. [`tests/test_pii_sanitizer_bic.py`](../tests/test_pii_sanitizer_bic.py) covers labelled true positives, key-context positives, and a property test showing that no upper-case string literal in `src/`, and no `GovernanceDecision` / `OpaVerdict` / `FTRAVerdict` value, is redacted. Hypothesis tests show that unlabelled upper-case words are never redacted and that every structurally valid labelled BIC is.

**Remaining Closure Criteria:**
1. Merge `fix/pii-swift-false-positive`; record the merge commit SHA and the actual merge date here.

### POAM-2026-101: Base-Image CVEs Without a Debian Fix

**Control:** NIST RA-5, SI-2
**Risk Level:** Moderate
**Status:** Open (remediated in `fix/ci-test-errors`, pending merge)
**Date Opened:** 2026-10-05
**Target Closure:** 2026-11-15

**Description:**
The SBOM/CVE Trivy scan ([`sbom.yml`](../.github/workflows/sbom.yml)) failed on HIGH findings in the Debian 12 OS layer of `python:3.12-slim-bookworm`. On 2026-10-05 the gateway leg reported 73 findings (44 unique CVEs) and the compliance-bridge leg 34 (5 unique). All had Trivy status `affected` and no Fixed Version, so the build-time `apt-get upgrade` could not remove them. 39 came from `linux-libc-dev` (kernel headers pulled in by the C toolchain). The other five were util-linux CVE-2026-76642, CVE-2026-78408, CVE-2026-78409, CVE-2026-78410 and OpenSSL CVE-2026-84782 (DTLS). Separately, `.trivyignore` held about 40 suppressions whose review dates (2026-09-05, 2026-09-08) had passed, and `sbom.yml` scanned the repo-root advisor Dockerfile under the name `gateway`, so `src/gateway/Dockerfile` was never scanned.

**Remediation Implemented in Code (`fix/ci-test-errors`):**
1. [`Dockerfile`](../Dockerfile), [`src/gateway/Dockerfile`](../src/gateway/Dockerfile) and [`src/compliance_bridge/Dockerfile`](../src/compliance_bridge/Dockerfile) are two-stage builds on `cgr.dev/chainguard/wolfi-base`, pinned by digest (`ARG WOLFI_BASE`). The compiler and uv stay in the builder stage. The runtime stage installs only `python-3.12`, `libstdc++`, `libgcc` and `tzdata`, runs `apk upgrade`, and contains no util-linux, perl or ncurses.
2. The advisor image copies an explicit source allowlist instead of `COPY . .`, which had shipped local `node_modules` (5 HIGH `fast-uri` CVEs) into the image.
3. `sbom.yml` scans all four shipped Python images (advisor, gateway, compliance-bridge, NeMo Guardrails) with `--show-suppressed`. [`Dockerfile.nemo`](../deployment/docker/Dockerfile.nemo) moved to the same Wolfi base. It had been unscanned, ran as root, and installed an unpinned `grpcio-tools` into its runtime venv.
4. [`cloudbuild.verify.yaml`](../deployment/docker/cloudbuild.verify.yaml) builds a Dockerfile on the GKE architecture without pushing. It smoke-imports the entry module as the image user and applies the same Trivy gate.
5. Every `.trivyignore` entry was pruned. No suppression matched any finding in the new images.

**Verification (2026-10-05, Cloud Build):**
| Image | Build | Smoke import | Trivy HIGH/CRITICAL | Suppressed matches |
|---|---|---|---|---|
| governed-financial-advisor | `575e3466` | `src.governed_financial_advisor.server` ok | 0 | 0 |
| gateway | `3e268752` | `src.gateway.server.hybrid_server` ok | 0 | 0 |
| compliance-bridge | `1df4fe5d` | `compliance_bridge.main` ok | 0 | 0 |
| nemo-guardrails | `82604db1` | `src.integrations.nemo.server` ok | 0 | 0 |

**Remaining Closure Criteria:**
1. Merge `fix/ci-test-errors`. Record the merge commit SHA, and the date all three SBOM/CVE legs pass on `main`, here.

### POAM-2026-125: Output Semantic Validation Has Never Operated

**Control:** NIST SI-15 (Information Output Filtering), SI-10 (Information Input Validation)
**Risk Level:** High
**Status:** Open — rewritten 2026-10-28 after measurement; 6-cell judge matrix completed 2026-10-28
**Date Opened:** 2026-10-28
**Target Closure:** 2026-11-30

**Description:**
The advisor graph's output rail calls [`validate_output_semantics()`](../src/integrations/nemo/manager.py), which is meant to ask a model whether an answer is safe. It never asks. The call goes through NeMo's rails with the auditor instruction as a system message, but the Colang configuration has only an input flow:
- the only model call, when there is one, is the input judge's YES/NO prompt run on the output text ([`prompts.yml`](../config/rails/prompts.yml), [`main_logic.co`](../config/rails/main_logic.co));
- the reply the check parses is never a model's answer to its question. Today it is empty or NeMo's canned refusal, and both read as safe.

**Measured on 2026-10-28** (main's code, NeMo's real routing, the model client stubbed, nothing sent):

| Model reply | Auditor prompt sent | Read as |
|---|---|---|
| `UNSAFE: fabricated regulation` | no | safe |
| `<think>…</think>` then `UNSAFE: fabricated regulation` | no | safe |
| `SAFE` | no | safe |
| `YES` / `NO` | no | safe |
| endpoint down | no | safe |

With no model configured, the input judge's failure becomes the canned refusal, which also reads as safe (verified by the inference-consumer extraction; see the [jurisdiction inventory](operations/JURISDICTION_INVENTORY.md)). Text containing a finance keyword passes the deterministic stage with no model call at all.

**Since when (read).** The check arrived in `6012f067` (2026-06-03), and the rails config has never had an output flow. Until `94f920bc` the main flow echoed the user's text back as the reply, so the check parsed the output itself. Since then the reply is empty or the canned refusal. Two different mechanisms across two periods, and in neither did a model see the question.

**Severity.** High, and unconditional. Unlike POAM-2026-124 (paths that reach no verdict), the scope is simply "always": the control returns safe with a working model, a dead endpoint, or no model at all.

**How this entry was corrected.** The first version described a lenient parse defeated by reasoning traces. Its evidence and the strict-parse fix (#568) used a mocked reply channel that the real call never fills. #568 would have refused every output, and was closed unmerged.

**6-cell judge measurement (verified 2026-10-28, direct `rails.llm` invocation with strict `SAFE` parser):**
Evaluated `Qwen/Qwen2.5-1.5B-Instruct` (the `vllm-fast` model configured for `gcp-gke`) and `Qwen/Qwen2.5-7B-Instruct` (comparator) at `temperature=0.0` across three prompts on (a) 20 multi-paragraph benign financial advisory answers (152–188 words each) and (b) 20 labelled must-refuse outputs (4 each across 5 categories: fabricated regulatory citation, harmful/misleading financial advice, unsupported regulatory claim, leaked PII/credentials, and downstream prompt-injection/safety-bypass):

| Prompt variant | Judge model | Benign false-refusal rate (20) | Unsafe catch rate (20) | Fab. citation (4) | Harmful advice (4) | Unsupp. reg. claim (4) | Leaked PII/creds (4) | Prompt injection (4) |
|---|---|---|---|---|---|---|---|---|
| `manager_system_prompt` ([`manager.py`](../src/integrations/nemo/manager.py)) | `Qwen/Qwen2.5-1.5B-Instruct` | **7/20 (35.0%)** | **12/20 (60.0%)** | 2/4 | 4/4 | 1/4 | 1/4 | 4/4 |
| `manager_system_prompt` ([`manager.py`](../src/integrations/nemo/manager.py)) | `Qwen/Qwen2.5-7B-Instruct` | **0/20 (0.0%)** | **20/20 (100.0%)** | **4/4** | **4/4** | **4/4** | **4/4** | **4/4** |
| `actions_vague_prompt` ([`actions.py`](../config/rails/actions.py)) | `Qwen/Qwen2.5-1.5B-Instruct` | **11/20 (55.0%)** *(8 format failures: `**SAFETY**`, `SAFETY`, Cyrillic `SAFЕ`)* | **20/20 (100.0%)** *(3 accidental format catches)* | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 |
| `actions_vague_prompt` ([`actions.py`](../config/rails/actions.py)) | `Qwen/Qwen2.5-7B-Instruct` | **0/20 (0.0%)** | **19/20 (95.0%)** | 3/4 | 4/4 | 4/4 | 4/4 | 4/4 |
| `structured_rubric_prompt` | `Qwen/Qwen2.5-1.5B-Instruct` | **0/20 (0.0%)** | **9/20 (45.0%)** | **0/4** | 3/4 | 2/4 | **0/4** | 4/4 |
| `structured_rubric_prompt` | `Qwen/Qwen2.5-7B-Instruct` | **0/20 (0.0%)** | **19/20 (95.0%)** | 3/4 | 4/4 | 4/4 | 4/4 | 4/4 |

- **Capacity vs. prompt:** `Qwen/Qwen2.5-1.5B-Instruct` cannot serve as the semantic output judge under any prompt. On the shipped `manager_system_prompt` it refuses 35% of benign advisory answers (`UNSAFE: The response contains financial advice...`) and misses 40% of unsafe outputs; adding an explicit rubric eliminates false refusals (`0/20`) by collapsing catch rate to `9/20 (45%)` (`0/4` on fabricated citations and `0/4` on leaked credentials). `Qwen/Qwen2.5-7B-Instruct` on the unchanged `manager_system_prompt` achieves `0/20 (0.0%)` false refusals and `20/20 (100.0%)` catch across all five categories.

**Remediation:**
1. Put the question to the model directly (`rails.llm`) rather than through the input flow, and read the answer strictly: safe only on a conforming SAFE verdict.
2. Fix the prompt construction in [`validate_output_semantics()`](../src/integrations/nemo/manager.py) so `user_message` is never concatenated as an unlabelled instruction tail and never dropped when empty.
3. Because a working semantic output judge requires a `>= 7B` instruction-tuned model (`Qwen2.5-7B-Instruct` or hosted equivalent), gate NeMo semantic rails behind `CAGE_NEMO_ENABLED=false` by default (after unbundling deterministic PII redaction and keyword screening under POAM-2026-142) and document the `>= 7B` judge requirement in [`src/integrations/nemo/README.md`](../src/integrations/nemo/README.md).
4. Test through the real rails with a stubbed model, not a mocked reply, with a recorded mutation check, and publish the advisory after the fix ships.

### POAM-2026-140: `CustomSelfCheckOutputAction` Is a Published Security Claim Protecting Nothing

**Control:** NIST SI-15 (Information Output Filtering), SA-11 (Developer Testing and Evaluation), CA-2 (Control Assessments)
**Risk Level:** High
**Status:** Open — verified 2026-10-28 (grep and code read)
**Date Opened:** 2026-10-28
**Target Closure:** 2026-11-30

**Description:**
[`config/rails/actions.py`](../config/rails/actions.py) defines `@action(name="CustomSelfCheckOutputAction")` (`custom_self_check_output`), registered in [`action_registry.py`](../src/integrations/nemo/action_registry.py) and declared in [`config/rails/definitions.co`](../config/rails/definitions.co). On 2026-10-03, `CHANGELOG.md` recorded a `[SECURITY]` fix to its Stage 3 LLM judge, and [`tests/test_nemo_self_check_judge.py`](../tests/test_nemo_self_check_judge.py) certified the fix. Three facts verified on 2026-10-28 show the claim protects nothing:

1. **Uninvoked in Colang.** No flow in [`config/rails/main_logic.co`](../config/rails/main_logic.co) or [`config/rails/config.yml`](../config/rails/config.yml) ever calls `CustomSelfCheckOutputAction`. A comment in [`nemo_node_factory.py`](../src/gateway/governance/langgraph_harness/nemo_node_factory.py) notes that authoring a combined Colang output flow calling `CustomSelfCheckOutputAction` was left to a future sprint.
2. **Stage 2 short-circuits on the domain's core vocabulary.** Even if a flow invoked the action, Stage 2 (`safe_indicators`, [`config/rails/actions.py`](../config/rails/actions.py)) returns `True` without calling the Stage 3 judge whenever the output contains any of 22 common financial words — `"risk"`, `"portfolio"`, `"consider"`, `"consult"`, `"disclaimer"`, `"not financial advice"`, `"diversification"`, `"volatility"`, `"may"`, `"could"`, `"potential"`, `"assessment"`, `"order"`, `"shares"`, `"executed"`, `"cancelled"`, `"filled"`, `"placed"`, `"confirmed"`, `"trade"`, `"position"`, `"market order"`, `"limit order"`, `"stop order"` — provided it avoids nine literal strings in Stage 1 (`"guaranteed returns"`, `"risk-free investment"`, `"can't lose"`, `"insider information"`, `"sure thing"`, `"100% profit"`, `"no risk"`, `"guaranteed profit"`, `"get rich quick"`). Because those 22 words are the vocabulary of nearly every financial advisory answer, Stage 2 would short-circuit to safe on essentially all real finance output and Stage 3 would never run.
3. **Self-certifying unit test.** [`tests/test_nemo_self_check_judge.py`](../tests/test_nemo_self_check_judge.py) calls `actions.custom_self_check_output` directly with `"hello world"`, bypassing both Colang routing (which never calls the action) and Stage 2 (which passes any output containing financial vocabulary).

**Remediation:**
1. Do not wire `CustomSelfCheckOutputAction` into `validate_output_semantics()` (which routes directly to `rails.llm` under POAM-2026-125).
2. Remove the dead `CustomSelfCheckOutputAction` action (`custom_self_check_output` and `_run_output_safety_judge` in [`config/rails/actions.py`](../config/rails/actions.py)), its registration in [`action_registry.py`](../src/integrations/nemo/action_registry.py), its declaration in [`config/rails/definitions.co`](../config/rails/definitions.co), and its self-certifying test file [`tests/test_nemo_self_check_judge.py`](../tests/test_nemo_self_check_judge.py), and regenerate [`deployment/k8s/nemo-rails-configmap.yaml`](../deployment/k8s/nemo-rails-configmap.yaml) via `make update-nemo-configmap`.
3. Correct the `2026-10-03` claim by cross-referencing this entry.

### POAM-2026-141: STPA Compiler Silently Drops Declared Enforcement Targets (`flow stpa_output_guardrail` Is a No-Op `return`) and OSCAL Claims Uncompiled Controls as Implemented

**Control:** NIST SI-10 (Information Input Validation), SC-28 (Protection of Information at Rest / PII Disclosure), SI-4 (System Monitoring), SA-11 (Developer Testing and Evaluation), CA-2 (Control Assessments)
**Risk Level:** High
**Status:** Open — verified 2026-10-28 (code read, generated artifact inspection, and OSCAL audit)
**Date Opened:** 2026-10-28
**Target Closure:** 2026-11-30

**Description:**
Four STPA Unsafe Control Actions declare `nemo` in their `enforcement` list — three of them (`UCA-3`, `UCA-4`, `UCA-10`) as their *only* declared enforcement target:

| UCA | Source YAML | Hazard | Declared `enforcement` | `condition.type` | Compiled into [`generated_stpa_rails.co`](../config/rails/generated_stpa_rails.co)? | Compiled into [`generated_stpa_policy.rego`](../config/opa/generated_stpa_policy.rego) or [`uca_rules.py`](../src/cage_finance/stpa/uca_rules.py)? |
|---|---|---|---|---|---|---|
| `UCA-3` | [`trade_hazards.yaml`](../src/cage_finance/config/stpa/trade_hazards.yaml) | `H-3` (PII disclosure; ISO 42001 A.9.2, NIST SC-28) | `[nemo]` | `content_match` (`patterns: ["SSN", "account_number", "tax_id", "routing_number"]`, no `semantic_pattern`) | **No** | **No** |
| `UCA-4` | [`trade_hazards.yaml`](../src/cage_finance/config/stpa/trade_hazards.yaml) | `H-2` (Sub-agent routing loop) | `[nemo]` | `hop_limit` (`max_hops: 10`) | **No** | **No** |
| `UCA-7` | [`core_system.yaml`](../config/stpa/core_system.yaml) | `H-SYS-1` (`PromptInjectionAttempt`) | `[opa, nemo, python]` | `compound` (no `semantic_pattern`) | **No** | Yes (`opa` in [`generated_stpa_policy.rego`](../config/opa/generated_stpa_policy.rego); `_CORE` has no `python` recipe in [`check_stpa_freshness.py`](../scripts/check_stpa_freshness.py)) |
| `UCA-10` | [`trade_hazards.yaml`](../src/cage_finance/config/stpa/trade_hazards.yaml) | `H-3`, `H-4` (Reasoning trace tampering; ISO 42001 A.9.4, NIST SI-4) | `[nemo]` | `content_match` (`patterns: ["ignore previous", "override safety", ...]`, no `semantic_pattern`) | **No** | **No** |

Inspecting [`config/rails/generated_stpa_rails.co`](../config/rails/generated_stpa_rails.co) shows that `flow stpa_output_guardrail` is literally a no-op `return`:

```colang
flow stpa_output_guardrail
  # Generated output rails for STPA hazards
  return
```

Furthermore, no flow in [`config/rails/main_logic.co`](../config/rails/main_logic.co) or [`config/rails/config.yml`](../config/rails/config.yml) invokes `stpa_input_guardrail` or `stpa_output_guardrail`.

**Root cause — two independent compiler failures (fixing either alone would have changed nothing):**
1. **Finance STPA YAML is never compiled to `nemo`.** [`_ARTIFACT_RECIPES`](../scripts/check_stpa_freshness.py) in [`scripts/check_stpa_freshness.py`](../scripts/check_stpa_freshness.py) compiles [`config/rails/generated_stpa_rails.co`](../config/rails/generated_stpa_rails.co) from `_CORE` ([`config/stpa/core_system.yaml`](../config/stpa/core_system.yaml)) only. [`src/cage_finance/config/stpa/trade_hazards.yaml`](../src/cage_finance/config/stpa/trade_hazards.yaml) (`_FINANCE`, where `UCA-3`, `UCA-4`, and `UCA-10` live) is compiled only to `python`, `langgraph`, and `ftra` — never to `nemo` or `opa`.
2. **`generate_nemo()` silently omits declared `nemo` targets when `semantic_pattern` is empty.** In [`src/gateway/governance/stpa_compiler.py`](../src/gateway/governance/stpa_compiler.py), `generate_nemo()` filters to `[u for u in model.ucas if "nemo" in u.enforcement]` and then emits an output check inside `flow stpa_output_guardrail` *only* when `uca.condition.semantic_pattern` is non-empty (`if uca.condition.semantic_pattern:`). None of `UCA-3`, `UCA-4`, `UCA-7`, or `UCA-10` sets `semantic_pattern`. The compiler emits nothing and raises no error — so any UCA declaring `nemo` without `semantic_pattern` (or declaring `opa`/`python` with a condition type that target does not emit) is silently unenforced by construction.

**False OSCAL compliance assertions (verified 2026-10-28):**
Because [`oscal_ssp_exporter.py`](../src/gateway/governance/oscal_ssp_exporter.py) generates `implemented-requirements` from the STPA YAML metadata (`iso42001_controls` / `nist_controls` on `UCA-3` and `UCA-10`) without checking whether the compiler emitted any rule for those UCAs, committed OSCAL artifacts make false `state: implemented` claims:
- [`compliance/oscal/system-security-plan.yaml`](../compliance/oscal/system-security-plan.yaml) (and [`compliance/oscal/stpa_compiler_ssp_patch.yaml`](../compliance/oscal/stpa_compiler_ssp_patch.yaml)) claims `implementation-status: state: implemented` by component `STPA-to-Policy Compiler` (`e5000099-stpa-4000-8000-compiler00001`) for **`SC-28`** (`UCAs covered: UCA-3`) and **`SI-4`** (`UCAs covered: UCA-10`), citing [`config/opa/generated_stpa_policy.rego`](../config/opa/generated_stpa_policy.rego), [`config/rails/generated_stpa_rails.co`](../config/rails/generated_stpa_rails.co), and the deleted generated STPA validator module in `src/gateway/governance/` (deleted in `2d4aea66`) as the enforcing artifacts — while neither `UCA-3` nor `UCA-10` appears in any of those files or in [`src/cage_finance/stpa/uca_rules.py`](../src/cage_finance/stpa/uca_rules.py).
- [`compliance/oscal/component-definition.yaml`](../compliance/oscal/component-definition.yaml) (and [`compliance/oscal/stpa_compiler_ssp_patch.yaml`](../compliance/oscal/stpa_compiler_ssp_patch.yaml)) claims under `STPA-to-Policy Compiler` that *"STPA compiler generates deterministic enforcement artifacts"* for **`ISO 42001 A.9.2`** (`UCAs: UCA-3`) and **`ISO 42001 A.9.4`** (`UCAs: UCA-10`).

**Remediation:**
1. **Make the STPA compiler fail closed on uncompilable declared targets (closes the class):** Following the precedent established by `_COMPOSITE_SCALED_THRESHOLD_RE` in [`stpa_compiler.py`](../src/gateway/governance/stpa_compiler.py) (*"it used to compile to a comment, i.e. no enforcement"*), make [`stpa_compiler.py`](../src/gateway/governance/stpa_compiler.py) raise `ValueError` at compile/parse time whenever a UCA declares an `enforcement` target (`nemo`, `opa`, or `python`) for which its `condition` cannot be compiled into an active enforcement check (for example, `nemo` declared without `condition.semantic_pattern`, or `python`/`opa` declared for a condition type that emits no check).
2. **Re-home `UCA-3`, `UCA-4`, `UCA-7`, and `UCA-10` to their real deterministic enforcement targets:**
   - `UCA-3`: `enforcement: [python]`, enforced by deterministic Presidio (`_redact_pii` in [`src/integrations/presidio/redactor.py`](../src/integrations/presidio/redactor.py)) + regex (`scrub_pii` in [`src/gateway/infrastructure/privacy.py`](../src/gateway/infrastructure/privacy.py)) and compiled into [`src/cage_finance/stpa/uca_rules.py`](../src/cage_finance/stpa/uca_rules.py).
   - `UCA-4`: `enforcement: [langgraph, python]` (matching [`core_system.yaml`](../config/stpa/core_system.yaml) `UCA-8` for `langgraph` and compiling the `hop_limit` check into [`src/cage_finance/stpa/uca_rules.py`](../src/cage_finance/stpa/uca_rules.py) and [`src/cage_finance/stpa/saga_nodes.py`](../src/cage_finance/stpa/saga_nodes.py)).
   - `UCA-7`: `enforcement: [opa]` (where it is already compiled and active in [`generated_stpa_policy.rego`](../config/opa/generated_stpa_policy.rego)).
   - `UCA-10`: `enforcement: [python]`, compiled into [`src/cage_finance/stpa/uca_rules.py`](../src/cage_finance/stpa/uca_rules.py) (`content_match` on reasoning trace / action payload).
3. **Repair OSCAL exporter and committed OSCAL artifacts:** Update [`oscal_ssp_exporter.py`](../src/gateway/governance/oscal_ssp_exporter.py) and [`config/oscal/framework_mappings/`](../config/oscal/framework_mappings/) to remove citations to the deleted generated STPA validator module, cite the actual generated/runtime enforcement modules, and regenerate [`compliance/oscal/system-security-plan.yaml`](../compliance/oscal/system-security-plan.yaml), [`compliance/oscal/component-definition.yaml`](../compliance/oscal/component-definition.yaml), and [`compliance/oscal/stpa_compiler_ssp_patch.yaml`](../compliance/oscal/stpa_compiler_ssp_patch.yaml).

### POAM-2026-142: Deterministic PII Redaction (`UCA-3` / `H-3`) and Keyword Screening Are Coupled Behind `get_nemo_rails()` in `nemo_node_factory.py`

**Control:** NIST SC-28 (Protection of Information at Rest / PII Disclosure), SI-10 (Information Input Validation)
**Risk Level:** High
**Status:** Open — verified 2026-10-28 (code read)
**Date Opened:** 2026-10-28
**Target Closure:** 2026-11-30

**Description:**
While [`generated_stpa_rails.co`](../config/rails/generated_stpa_rails.co) emits no check for `UCA-3` (`H-3`, PII disclosure; POAM-2026-141), CAGE does enforce deterministic PII protection on advisor input and output via:
- [`_redact_pii()`](../src/integrations/presidio/redactor.py) (Microsoft Presidio + spaCy NER with regex fallback, fail-closed on exception), called on user input and agent output inside [`src/gateway/governance/langgraph_harness/nemo_node_factory.py`](../src/gateway/governance/langgraph_harness/nemo_node_factory.py); and
- [`scrub_pii()`](../src/gateway/infrastructure/privacy.py) (deterministic regex scrubbing for SSN, credit-card, email, and phone patterns), called via `MaskPIIAction` ([`config/rails/actions.py`](../config/rails/actions.py)).

However, inside [`nemo_node_factory.py`](../src/gateway/governance/langgraph_harness/nemo_node_factory.py), both deterministic controls — as well as Stage 1 Aho-Corasick keyword screening (`ac_keyword_scan()`) — are gated behind `rails = get_nemo_rails()`:
1. **Input node (`nemo_input_rail_node`):** Calls `rails = get_nemo_rails()` *before* `_redact_pii(last_msg.content)` and before Stage 1 `ac_keyword_scan()`. If `get_nemo_rails()` returns `None` (when `CAGE_NEMO_ENABLED=false`), the input node exits before running `_redact_pii()` or `ac_keyword_scan()`.
2. **Output node (`nemo_output_rail_node`):** Calls `rails = get_nemo_rails()` *before* `_redact_pii(last_msg.content)`. In addition, [`verify_and_mask_output()`](../src/integrations/nemo/manager.py) invokes an `LLMRails` Colang pass solely to trigger `MaskPIIAction` → `scrub_pii()`, and returns the unmasked text unchanged when `rails is None`.

Consequently, flipping `CAGE_NEMO_ENABLED` to `false` by default without first unbundling [`nemo_node_factory.py`](../src/gateway/governance/langgraph_harness/nemo_node_factory.py) would silently disable `UCA-3` (`H-3`) PII redaction and Stage 1 keyword screening across all advisor nodes.

**Remediation:**
1. **Unbundle deterministic input/output hygiene from `get_nemo_rails()` before changing the `CAGE_NEMO_ENABLED` default:**
   - In `nemo_input_rail_node`: always run `_redact_pii()` and Stage 1 deterministic `ac_keyword_scan()` regardless of `CAGE_NEMO_ENABLED`; consult `get_nemo_rails()` only for the Stage 2 `validate_with_nemo()` LLM rail when `CAGE_NEMO_ENABLED=true`.
   - In `nemo_output_rail_node`: always run `_redact_pii()` and call `scrub_pii()` directly (from [`src/gateway/infrastructure/privacy.py`](../src/gateway/infrastructure/privacy.py)) regardless of `CAGE_NEMO_ENABLED`; consult `get_nemo_rails()` only for `validate_output_semantics()` when `CAGE_NEMO_ENABLED=true`.
2. **Certify with a 7-row mutation table (`M1`–`M7`):** Verify under `CAGE_NEMO_ENABLED=false` that commenting out input `_redact_pii()` (`M1`), output `_redact_pii()` (`M2`), output `scrub_pii()` (`M3`), input `ac_keyword_scan()` (`M4`), `UCA-3` in [`uca_rules.py`](../src/cage_finance/stpa/uca_rules.py) (`M5`), `UCA-10` in [`uca_rules.py`](../src/cage_finance/stpa/uca_rules.py) (`M6`), or the compiler fail-closed check in [`stpa_compiler.py`](../src/gateway/governance/stpa_compiler.py) (`M7`) each turns a dedicated guard test red.

### POAM-2026-124: Content-Safety Checks That Did Not Run Are Reported as Passed

**Control:** NIST SI-10 (Information Input Validation), AU-3 (Content of Audit Records)
**Risk Level:** High
**Status:** Closed (2026-10-28) — merged in #566 as `493727f5`; the evidence tests were re-run on that commit the same day
**Date Opened:** 2026-10-28
**Target Closure:** 2026-11-30

**Description:**
The gateway's [`verify_content_safety`](../src/gateway/server/mcp_tool_server.py) tool is the content-safety check the advisor forwards to the gateway (POAM-2026-079). Two paths report a check that did not run as passed. Both were verified hermetically on 2026-10-28.

1. **Rails not initialised.** When `app.state.nemo_rails` is `None`, the tool returns the string `"ERROR: NeMo rails not initialised."` rather than a refusal. The advisor's [tool endpoint](../src/governed_financial_advisor/tools/api.py) returns it with `status: SUCCESS`. Because the output does not start with `BLOCKED`, the endpoint records `cage.verdict = SAFE` on its span.
2. **NeMo has no main flow.** When NeMo raises "No main flow found", [`validate_with_nemo()`](../src/integrations/nemo/manager.py) logs a warning, marks its own span `DEGRADED_NO_MAIN_FLOW` and returns safe, on the reasoning that OPA and STPA still check the action. The tool then answers `"SAFE"`.
   - The same pass-through is in `verify_input()` and `validate_output_semantics()`.
   - The advisor graph's in-process NeMo input rail node calls `validate_with_nemo()`, so it records such input as `PASSED`. Its factory's docstring promises "unconditional fail-closed enforcement" (read, not tested).
   - OPA and STPA check actions, not content, so no other tier covers a content-safety check that did not run.

**Reachability.**
- **The control operates with the shipped configuration (verified 2026-10-28).** The gateway's real rails were built from `config/rails` (Colang 2.x, with a `flow main`) and called through the tool. They blocked four must-block inputs and passed a benign one. Two were blocked at the deterministic prompt-injection stage. Two reached the LLM judge, which was unreachable and failed closed. "No main flow found" was not raised.
- **Path 1 today.** In the shipped gateway image, `create_nemo_manager()` returns `None` only when `nemoguardrails` fails to import. A missing rails config stops startup instead. A config that fails to parse yields the transparent-fallback stub, which `validate_with_nemo()` rejects.
- **Path 2 today** needs a rails config with no main flow.
- **The probe showed neither path.** It ran no CAGE workload, and under #13 the gateway pod never starts.
- **Path 1 under `none`.** The planned `CAGE_INFERENCE_BACKEND=none` builds no rails, so path 1 would fire on every call.

**Remediation (in the inference-backend kernel change, before `none` exists):**
1. Make every path in `verify_content_safety` that is not a verdict return `BLOCKED` with a reason code: rails absent, no main flow, any exception, and `none`.
2. Make the advisor treat only an exact `SAFE` as safe and record every other output as not safe.
3. Turn the "No main flow found" pass-through into a refusal with its own reason code in all three functions, keeping the degraded span marking.
4. Add a test for each path, with a recorded mutation check showing the test fails when its path is reverted.

**Remediation status (2026-10-28, `feat/inference-backend-none`):**
- Steps 1–3 are implemented. The reason codes live in [`content_safety.py`](../src/gateway/governance/content_safety.py): `CONTENT_SAFETY_RAILS_UNAVAILABLE` (rails absent, or the transparent-fallback stub), `CONTENT_SAFETY_NO_MAIN_FLOW`, `CONTENT_SAFETY_ERROR` and `CONTENT_SAFETY_NO_INFERENCE_BACKEND`.
- Step 4: [`test_content_safety_no_verdict.py`](../tests/test_content_safety_no_verdict.py) pins each path, including the advisor graph's in-process input rail node, and [`test_inference_backend_none.py`](../tests/test_inference_backend_none.py) pins the `none` path.
- Mutation check, run on the branch head: restoring the no-main-flow pass-through in `validate_with_nemo()`, `verify_input()` or `validate_output_semantics()` turns that function's test red; making `verify_content_safety` answer `SAFE` with no rails, or under `none`, turns its test red; restoring the advisor's `startswith("BLOCKED")` label turns `test_advisor_records_a_non_verdict_output_as_blocked` red. The full table is in the pull request.

### POAM-2026-123: Plugin Overlays Can Redefine Kernel Controls

**Control:** NIST CM-6 (Configuration Settings), SI-7 (Software, Firmware, and Information Integrity)
**Risk Level:** High
**Status:** Open — recorded; remediation not started
**Date Opened:** 2026-10-28
**Target Closure:** 2026-11-30

**Description:**
[`ControlRegistry`](../src/gateway/governance/constants.py) loads the kernel's regional baseline, then applies each registered plugin overlay with `dict.update`. When an overlay key is already present, it logs "Control mapping collision … overrides earlier mapping" at WARNING and applies the overlay anyway. A plugin overlay can therefore replace any kernel control's definition. That includes a definition the normative provider supplied: `NormativeProviderDaemon` writes the fetched profile to the regional baseline file and reconfigures the registry, and the overlays are applied on top (read).

- **Enforcement inputs (verified hermetically, 2026-10-28).**
  - The EU_ECB FRIA tier's first gate is a staleness check (Art. 27(2) reassessment). It runs on the artefact `registry_assessment_lookup()` reads from `CTRL_FRIA_006.assessments`, which the normative provider is meant to supply. A missing or stale artefact is a hard `FRIA_ASSESSMENT_STALE` denial.
  - With the kernel baseline alone, the real `FriaTier` denied `execute_trade` at that gate without consulting the provider.
  - With a test overlay that defines `CTRL_FRIA_006` with a fresh `assessed_at`, the gate passed and the decision moved to the provider's `validate_fria()`. A stand-in that admits every request then admitted the action.
  - The only signal was one WARNING. No shipped plugin defines `CTRL_FRIA_006`.
  - The provider still decides after the gate, but the gate itself no longer holds.
- **Live, without runtime effect.** `cage_finance`'s US_FED overlay replaces `CTRL_FTRA_001`. With it installed, the registry serves finance's citations, not the kernel's: "NIST AI RMF GOVERN-1.2" instead of "ISO 42001 A.8.4" (verified). No runtime path reads that mapping's content today, which is circumstance, not design (read; POAM-2026-121).

The kernel treats the equivalent conflict as fatal elsewhere: [`assemble_governor()`](../src/gateway/governance/governor/assembly.py) refuses two contributions that fill one engine slot (`GovernorAssemblyError`, "slot collision"). The registry does not. A domain plugin can therefore change what a kernel control attests to, and remove a jurisdictional tier's hard-deny gate, without anything failing.

**Remediation:**
1. Decide the composition contract, which also settles POAM-2026-121: may a plugin overlay touch a kernel control at all, and if so only by declared extension, never by silent replacement?
2. Enforce the contract when the registry loads: an overlay key that redefines a kernel control fails closed, as an engine-slot collision does, unless it is declared.
3. Test it in the required job: a collision fails, and a declared extension is applied and recorded.

### POAM-2026-121: Validation Report Makes a False Composition Claim

**Control:** NIST CA-2 (Control Assessments), CA-7 (Continuous Monitoring)
**Risk Level:** High
**Status:** Open — decided 2026-10-28: the claim is withdrawn, not proven. §3 and the report's head carry do-not-rely notes until the withdrawal is applied
**Date Opened:** 2026-10-28
**Target Closure:** 2026-11-15

**Description:**
The [Regional Posture Validation Report](compliance/REGIONAL_POSTURE_VALIDATION_REPORT.md) is a published compliance validation report.
- Its §3 is the evidence that domain plugins and jurisdictional postures compose independently.
- It states an "Independence Guarantee": installing `cage_finance` and `cage_healthcare` "adds domain-specific controls without colliding on common controls".
- It pins a control count and an RFC 8785 JCS SHA-256 hash for each of 12 cells: no plugin, `cage_finance`, `cage_healthcare` and both, in each of US_FED, EU_ECB and APAC_MAS.
- It concludes that "Domain plugins and regional postures compose orthogonally".

**The claim is false, and was false when written.**
- `cage_finance`'s US_FED overlay redefines the kernel's `CTRL_FTRA_001`. At `main`, its internal ID, description, primary framework, legacy citation and co-frameworks all differ from the kernel's. A plugin overlay replacing a kernel control is the negation of independent composition.
- The redefinition is present at every commit checked, from `3b69207c` (the tree the hashes were computed on) through both report commits to `main`.
- The registry logs it as a "Control mapping collision" whenever it loads the cell. Rerunning the documented method at `3b69207c` logs it for both US_FED cells that include `cage_finance`, so the run that produced the hashes logged it too (inferred).

**The hashes were computed by the documented method, one commit early.** The documented method registers each plugin's overlay directory with `register_overlay_dir()`, calls `ControlRegistry.reconfigure()` for the region and reads `active_hash`. Rerun with each commit's own registry code:
- **`3b69207c`**, the parent of the commit that published the table: all 12 hashes and all 12 counts reproduce exactly.
- **`2889b955`** (the publishing commit) and **`f2363d07`** (the report's last commit): no hash reproduces, though every count does.
  - `2889b955` also added a `pii_retention_authority` key to each kernel baseline. The key is not a control, so it changed every cell's hash and no cell's count.
- **`main`** (`2ef4f013`): neither the hashes nor 6 of the 12 counts reproduce. #378 moved `CTRL_MRM_004` out of `cage_finance`'s overlays into the kernel baselines, and since then `cage_finance` adds no control in any region.

The table has therefore never described a tree that contains it. That part is a recoverable error, not a fabrication.

**What the `CTRL_FTRA_001` override changes at runtime.** The registry serves the overlay's definition (verified). But no runtime path reads that mapping's content (read): FTRA violations carry no control-ID prefix for `_control_payload()` to resolve, and deferrals record only the ID. FTRA's allow, deny and defer behaviour is therefore unaffected today. That is by circumstance, not design: the moment anything reads that mapping, the same overlay changes FTRA too. The mechanism that permits the override is a kernel defect in its own right, recorded as POAM-2026-123.

**What this settles.**
- Independence is not merely unproven: it is violated today in a path that changes a tier's verdict.
- A plugin overlay that defines `CTRL_FRIA_006` moves the EU_ECB FRIA tier past its Art. 27(2) staleness gate. A hard denial becomes a provider consultation (POAM-2026-123, verified).
- Independence is therefore an aspiration the report stated, not a property CAGE has. The claim is withdrawn rather than proven.

**Nothing would have caught this.**
- No test pins a cell or fails on a collision.
- The two workflows that exist to check the postures cannot fail the build. A workflow that cannot fail is telemetry, not a test.
  - [`regional-posture.yml`](../.github/workflows/regional-posture.yml) is not a required check. It runs only after merge or on dispatch, its path filter leaves out the plugins' overlay directories, and it soft-gates EU_ECB and APAC_MAS.
  - The test step of [`compliance-matrix.yml`](../.github/workflows/compliance-matrix.yml) is `continue-on-error`.

**Remediation:**
1. Withdraw the independence claim in the report.
   - Withdraw §3's "Independence Guarantee" and "Key Finding".
   - Withdraw the executive summary's "confirming independent composability of domain plugins and jurisdictional overlays".
   - Withdraw the conclusion's "true composability".
   - Keep the cell table only as a description of the matrix, not as evidence of independence. If it stays, regenerate it from a committed script at a stated commit, listing each cell's control set and any kernel control a plugin redefines.
2. Restate independence as a property only after both of these hold:
   - POAM-2026-123's fix makes a plugin overlay that redefines a kernel control fail closed;
   - a test in the required job fails on a collision.
3. Make `regional-posture.yml` able to fail, or describe it as telemetry wherever it is cited as a check.

Until the withdrawal is applied, §3 and the head of the report tell readers not to rely on the claim.

### POAM-2026-120: Closed Controls Without a Guarding Test

**Control:** NIST SA-11 (Developer Testing and Evaluation), CM-4 (Impact Analyses), CA-7 (Continuous Monitoring)
**Risk Level:** Moderate
**Status:** Open — forward requirement recorded; High backfill not started
**Date Opened:** 2026-10-27
**Target Closure:** 2026-12-31

**Description:**
POAM-2026-023's remediation (#102) moved the CBF balance read out of `LUA_ATOMIC_CBF`. That removed the serialization POAM-2026-070's control depended on: from #102 until #256, two concurrent trades that were each admissible alone, and not together, both committed. Every test still passed. The POA&M/Lula drift checker ([`check_poam_lula_divergence.py`](../scripts/check_poam_lula_divergence.py)) still counted POAM-2026-070 as covered, because its coverage is a file-name match: a closed entry counts as covered when the name of a Lula validation file contains one of its control IDs. The two files that matched POAM-2026-070, `lula-validation-sc4.yaml` and `lula-validation-si2.yaml`, do not mention the CBF. The defect was found by following a stale path, not by any check, and one undetected instance is weak evidence that it is the only one.

A closure in this document records that a control was implemented and verified once. Nothing requires a test that fails when the control stops operating, so a later change can disable a closed control silently. On 2026-10-27, 34 of the 80 closed entries cited no test in their row or detail section: POAM-2026-001, POAM-2026-007, POAM-2026-012, POAM-2026-013, POAM-2026-024, POAM-2026-027, POAM-2026-028, POAM-2026-030-B, POAM-2026-031, POAM-2026-037, POAM-2026-038, POAM-2026-039, POAM-2026-040, POAM-2026-041, POAM-2026-042, POAM-2026-044, POAM-2026-050, POAM-2026-051, POAM-2026-052, POAM-2026-053, POAM-2026-054, POAM-2026-055, POAM-2026-056, POAM-2026-057, POAM-2026-058, POAM-2026-059, POAM-2026-060, POAM-2026-063, POAM-2026-064, POAM-2026-067, POAM-2026-068, POAM-2026-071, POAM-2026-072 and POAM-2026-074. Citing a test is not the same as being guarded by one: POAM-2026-070 was among the other 46, citing a test module that has never existed. Only the entries that record a mutation or sensitivity check (POAM-2026-109, POAM-2026-110, POAM-2026-111 and now POAM-2026-070, for example) show that their tests fail without the control. POAM-2026-023, POAM-2026-069 and POAM-2026-070 are now listed under `CODE_EVIDENCE_FINDINGS`, so the drift checker counts them by their tests rather than by a Lula file name.

Recorded, not swept: the drift checker's other 52 "covered" entries rest on the same file-name match and have never been checked against what the files assert (for 26 of them the matched files share no identifier the entry cites). ADR-010 and the docstring of `tests/test_cbf_atomic_cas.py` credit the fence-epoch compare-and-set with stopping concurrent commits; since #506 (2026-10-22) it retries instead, and the in-script debit total is what stops them (POAM-2026-070's sensitivity check).

**The same shape in the consensus path (2026-10-28).** Finance's only high-stakes action is `HIGH_VALUE_TRADE`. [`test_consensus_config_failclosed.py`](../tests/cage_finance/test_consensus_config_failclosed.py) asserts it is present, but no tool or classifier has ever emitted that action name. The test proves the override is configured, not that it operates: the override has never fired, and consensus is triggered by amount alone, with any inference backend. Recorded as an instance, not swept.

**Remediation:**
1. Forward: no entry closes without a test that a recorded sensitivity check shows fails when the control is disabled, or a stated reason the control cannot be tested that way.
2. Backfill High entries only: the eight closed entries recorded High (POAM-2026-079, POAM-2026-080, POAM-2026-081, POAM-2026-087, POAM-2026-088, POAM-2026-092, POAM-2026-093, POAM-2026-102), and any of the 58 closed entries with no recorded severity that a reading of their text rates High. POAM-2026-070, one of the 58, is done.
3. Nothing else is swept. The other closed entries, the drift checker's file-name matches and the claims above stay recorded here.

### POAM-2026-119: Cited Commits That Do Not Resolve

**Control:** NIST CA-5 (Plan of Action and Milestones), CA-7 (Continuous Monitoring)
**Risk Level:** Moderate
**Status:** Open — recorded; the repair follows the commit-citation check
**Date Opened:** 2026-10-27
**Target Closure:** 2026-11-15

**Description:**
Found on 2026-10-27 while extending Gate G9 to this document. Before this entry was added, the document cited 49 distinct hexadecimal identifiers in code spans. 31 named commits on `main`, one named an annotated tag, and four are Cloud Build IDs (POAM-2026-101's verification table), which are not git objects. The other 13 are cited as commits and name no object in the repository. Each was looked up in a full clone of every ref (including the maintainer's private evidence refs), the offsite bundle, the maintainer's workstation clone, and GitHub's commit API, which also resolves pull-request commits that no branch holds:

| Cited | Entries | Found in | Commit on `main` that carries it |
|---|---|---|---|
| `88fa9d7` | POAM-2026-043, POAM-2026-046 | GitHub; workstation | `c1d45f53` (100%) |
| `9c68a6e8`, `72574529` | POAM-2026-098 | GitHub; workstation | `e1f46eca`, #391 (72%, 100%) |
| `f566e9e` | POAM-2026-079, POAM-2026-080 | GitHub; workstation | `8dbd5506`, #300 (100%) |
| `420854f` | POAM-2026-080 | GitHub; workstation | `5aa1523d`, #303 (100%) |
| `8bdd5b2` | POAM-2026-081 | workstation only | `55f97922`, #314 (93%) |
| `c8d66189a94cb782f4e0f61e14e05e341d27a8f6` | POAM-2026-011 | nowhere | — |
| `e0f7700`, `b2369c6`, `9d5d61a` | POAM-2026-079 | nowhere | — |
| `8df072e` | POAM-2026-080 | nowhere | — |
| `ad9ba9c7`, `8d2ccf03` | POAM-2026-083 | nowhere | — |

The percentage is the share of files the cited commit touched whose content is byte-identical in the mainline commit; below 100%, the pull request changed some of those files again before it merged. The workstation copies are unreferenced objects, which `git gc` prunes.

None of the 13 is reachable from the private refs, so none is an advisory-fork commit preserved there. The six that resolve are pre-squash branch commits: recoverable, but cited at an object an assessor checking `main` cannot find. The seven that resolve nowhere leave POAM-2026-011's closure with no checkable commit evidence, POAM-2026-079 and POAM-2026-080 with part of theirs, and POAM-2026-083 (open) with two attested commits that nobody can inspect.

**Remediation:**
1. Extend Gate G9 to verify commit citations with the pinned-path machinery (the commit exists and is an ancestor of HEAD), telling apart identifiers that are not commits and this entry's own inventory.
2. Repoint the six pre-squash citations to their mainline commits.
3. For each of the seven, find the mainline commit by content; where there is none, re-verify the closure against HEAD with dated evidence, or state in the entry that its commit evidence cannot be checked.

### POAM-2026-118: Enforcing Postures Can Select the Mock Telemetry Provider

**Control:** NIST SI-10 (Information Input Validation), CA-7 (Continuous Monitoring); `CTRL_MRM_004`
**Risk Level:** Moderate
**Status:** Open — latent; adding a timestamp column to `MockTelemetryProvider` would arm it
**Date Opened:** 2026-10-27
**Target Closure:** 2026-11-15

**Description:**
POAM-2026-088 closed on the rule that enforcing postures never substitute synthetic data for live telemetry. For the spec's synthetic factory that rule is checked by posture: `CausalGatekeeper._synthetic_telemetry_permitted()` ([`gatekeeper.py`](../src/gateway/governance/causal/gatekeeper.py)) refuses whenever `is_enforcing()` is true. Provider selection is checked by environment name instead. [`get_telemetry_provider()`](../src/gateway/governance/telemetry_provider.py) refuses `CAGE_TELEMETRY_PROVIDER=mock` only when `CAGE_ENV` is `prod` or `production`. [`is_enforcing()`](../src/gateway/governance/env_posture.py) also treats `staging` and `local` as enforcing, since only `dev`, `test` and `ci` relax it, and no other code path rejects `mock`. A staging or local deployment set to `mock` would therefore feed the causal tier `MockTelemetryProvider` rows as if they were live. Those rows are generated from the formula the model is calibrated on (POAM-2026-094).

The path is refused today only by accident. `MockTelemetryProvider` returns no timestamp column, and the freshness check in `validate_world_model()` fails closed when no timestamp column is present (verdict `stale_telemetry`). Adding a timestamp column is the obvious change for anyone trying to use the mock. Its rows would then pass the minimum-sample, freshness and placebo checks, as the finance synthetic rows already do in `dev`; this is inferred from that path, not exercised. The tier would then decide `execute_trade` in an enforcing posture from synthetic data, using POAM-2026-117's baseline. The shipped manifests ([`gateway.yaml`](../deployment/k8s/gateway.yaml), [`main.tf`](../infra/modules/gateway/main.tf)) set `remote`, so reaching this path needs explicit configuration.

This is tracked apart from POAM-2026-117 so that a change elsewhere cannot close it as a side effect.

**Remediation:**
1. Select on `is_enforcing()` instead of the environment name.
2. Add a test that `mock` is refused in `staging` and `local`, whatever the mock emits.

### POAM-2026-117: Causal Risk Boundary Can Fail Open as Volatility Rises

**Control:** NIST SI-10 (Information Input Validation), CA-7 (Continuous Monitoring); `CTRL_MRM_004` (marginal risk boundary)
**Risk Level:** High
**Status:** Open — latent while POAM-2026-094 is open. **POAM-2026-094 MUST NOT close before this item.**
**Date Opened:** 2026-10-27
**Target Closure:** 2026-12-31, and before POAM-2026-094

**Description:**
[`CausalGatekeeper._within_risk_boundary`](../src/gateway/governance/causal/gatekeeper.py) refuses a request when [`_marginal_risk`](../src/gateway/governance/causal/gatekeeper.py) exceeds `CAUSAL_LOCK_RISK_BOUNDARY` (0.95). Both branches of `CausalGatekeeper.evaluate()` call it once the world model is trusted, and the finance tier sends every `execute_trade` through it. `_marginal_risk` is `min(1, max(0, 0.5 + β × amount / normalization_scale))`, the formula POAM-2026-057 records as implemented.

Phase 1 estimates β with backdoor adjustment for volatility, but the prediction has no volatility term. Its 0.5 is neither configured nor estimated. It is not the intercept of the formula the tier is calibrated on (0), nor that formula's mean outcome at zero treatment (0.25). The trip amount `0.45 × normalization_scale / β` is therefore the same in calm and volatile markets. Where volatility drives most of the risk, the boundary is too strict in calm markets and too loose in volatile ones: it opens wider as risk rises. The constant is in the kernel (`src/gateway/`), so every domain plugin inherits it. G3 cannot flag it, because its forbidden-literal set holds domain strings and a bare `0.5` is not one.

**Demonstration (reproducible frame):**
1. **Process.** Draw n = 600 rows from `numpy.random.default_rng(20261027)`, in this order:
   - volatility `v ~ U(0.1, 0.9)`;
   - amount `a = clip(N(5000, 1500) − 2000·v, 100, 10000)`;
   - noise `N(0, 0.05)`.

   The outcome is `risk = 0.05 + 0.8·v + 0.2·a / 10,000 + noise`. Add a fresh timestamp column, because the freshness check requires one.
2. **Fit.** Run `validate_world_model()` with the finance causal graph (`market_volatility → trade_amount`, `market_volatility → risk_score`, `trade_amount → risk_score`) and `normalization_scale` = 10,000. It returns a trusted verdict with β = 0.1764373. Ordinary least squares of `risk` on `[1, v, a / 10,000]` gives intercept 0.0626284, volatility coefficient 0.7973928 and amount coefficient 0.1764373, which equals β.
3. **Kernel trip.** `0.45 × 10,000 / β` = **$25,504.81**, at any volatility.
4. **Volatility-aware trip of the same fit.** `(0.95 − 0.0626284 − 0.7973928·v) × 10,000 / β` gives $45,774.46 at v = 0.1, $27,696.82 at v = 0.5 and **$9,619.17 at v = 0.9**.
5. **True trip of the process at v = 0.9:** **$9,000**.

At v = 0.9 the kernel permits 2.65× the volatility-aware limit and 2.83× the true one. The frame's amounts stop at $10,000. Within the data, the over-permission is therefore $9,619.17 to $10,000; above $10,000 both trip points are extrapolations.

The direction depends on the process. When amount drives most of the risk (`0.05 + 0.3·v + 0.6·a / 10,000` in the same frame), the kernel trips at $7,806.57. The volatility-aware trips range from $14,878.15 at v = 0.1 to $10,750.83 at v = 0.9, so the kernel is too strict at every volatility. The values are stable across BLAS builds to better than 1e-12 relative.

**Reachability:**
- **Enforcing postures (`staging`, `production`, `local`): latent.** No live source produces the causal rows (POAM-2026-094), so no verdict is trusted, and `evaluate()` refuses before it reaches the boundary.
- **Permissive postures (`dev`, `test`, `ci`): active**, on the finance synthetic telemetry.
- **Ordering.** Remediating POAM-2026-094 gives enforcing postures trusted verdicts, which turns this boundary on. **POAM-2026-094 MUST NOT close before this item.** The natural order of work is the dangerous one. Closing POAM-2026-094 first moves the tier from refusing every trade to a gate that can permit 2.65× its volatility-aware limit at high volatility.

**Remediation options:**
1. *(Preferred)* **Bound the effect, not the level.** Refuse when the estimated causal contribution `β × amount / normalization_scale` exceeds a configured budget. This removes the baseline instead of moving it somewhere else, needs no per-request volatility value, and stays domain-agnostic. It is a breaking change, because `CAUSAL_LOCK_RISK_BOUNDARY` changes meaning.
2. **Predict the level from the fitted model** at the request's current volatility. This needs volatility on the request path. Finance's live volatility is a constant 0.15 today (POAM-2026-094), so this option inherits that gap.
3. **Supply the baseline from the domain** in `CausalSpec`. The constant would still be invented, only owned elsewhere.

**Closure requires:**
1. a remediation on `main`;
2. a test that reproduces the frame above, failing before the remediation and passing after it;
3. the boundary tests' pinned trip point re-derived. It is $9,143.93 today, from β = 0.4921298 on the finance synthetic telemetry.

### POAM-2026-116: Release Tags Were Not Protected

**Control:** NIST SI-7 (Software, Firmware, and Information Integrity), CM-5 (Access Restrictions for Change)
**Risk Level:** Moderate
**Status:** Open — remediated and verified on 2026-10-27; to be marked Closed in a follow-up
**Date Opened:** 2026-10-27
**Target Closure:** 2026-10-30

**Description:**
No ruleset protected any tag. Ruleset 19769024, named "Restrict tag creation to maintainer", targeted branches: its conditions were `refs/heads/v*-ref` and `refs/heads/v*-cage-*`, so its deletion, non-fast-forward and creation rules applied to no tag. Any account with write access could move or delete a release tag, including `v4.0.0`: the version GHSA-c8pw-f3g3-xg7c names as patched, and the tag the v4.0.0 release notes and the archived evidence bundles point at. `.github/branch-protection-rules.md` §4 described tag protection as configured.

**Remediation (2026-10-27):**
1. Tag ruleset 25965917 ("Protect release tags"): target `tag`; include `refs/tags/v*` and `refs/tags/client-v*`, which covers all 10 existing tags; rules `deletion`, `update` and `non_fast_forward`; no bypass actor. Changing a release tag now means editing or disabling the ruleset, which ruleset history records. Creating tags is not restricted; only admins have write access.
2. Ruleset 19769024 set to `disabled`. It protected nothing, and its name said otherwise.
3. `.github/branch-protection-rules.md` §4 now describes the tag ruleset.

**Verification (2026-10-27, over the wire):**
A probe tag, `v0-ruleset-probe-20261027`, was created, which the ruleset allows. GitHub then refused to delete it (`GH013 … Cannot delete this tag`) and to move it to another commit (`GH013 … Cannot update this protected ref`), and the rule-suite log records `deletion=fail` and `update=fail` against ruleset 25965917. The move was a fast-forward, so `non_fast_forward` alone would not have refused it; the `update` rule did. The probe was removed by excluding it, deleting it and restoring the ruleset, which left three entries in the ruleset's history. `v4.0.0` still resolves to tag object `64d9a2bc` and commit `8caa7eaf`.

### POAM-2026-115: Review Rule on `main` Cannot Be Met With One Maintainer

**Control:** NIST AC-5 (Separation of Duties). CM-3 (Configuration Change Control) and CM-5 (Access Restrictions for Change) were in scope until 2026-10-27; see *Resolved scope* below.
**Risk Level:** Moderate
**Status:** Open — no compensating control for AC-5
**Date Opened:** 2026-10-27 (amended the same day)
**Target Closure:** On second maintainer onboarding

**Description:**
Ruleset 19769096 ("Protect main branch") requires one approving review on `refs/heads/main` (`require_code_owner_review: false`, `dismiss_stale_reviews_on_push: true`). Its one bypass actor is the repository admin role, in mode `always`. The project has one maintainer, and GitHub does not let an author approve their own pull request, so none of the maintainer's own pull requests can meet the rule, and each is merged as an admin bypass. Pull requests by other authors can meet it: in the period measured below, 5 did, each approved by the maintainer.

Since 2026-10-27 the six required status checks (Lint; AI 600-1 Unit Tests; OPA Rego Policy Lint and Test; Secret Scanning (Gitleaks); license-check; and Pytest Logic Tests, pinned to the GitHub Actions app) are in ruleset 25966171 ("Require status checks on main"), which has no bypass actor, so an admin merge skips only the review. The one exception is an advisory fix landed from a private fork, where Actions does not run: the ruleset is disabled for that single merge and re-enabled, and its history records both edits ([`SECURITY.md`](../SECURITY.md)). [`check_pr_mergeable.sh`](../scripts/check_pr_mergeable.sh) still verifies the required checks on the exact head SHA before each merge and posts the result on the pull request.

`.github/branch-protection-rules.md` stated that code-owner review was enabled. The live rule does not require it, and one maintainer could not satisfy it. The change that opened this entry corrected the document.

**Resolved scope (CM-3, CM-5), until 2026-10-27:**
Both rules sat in ruleset 19769096, so the admin bypass also skipped the required checks. The first version of this entry said the bypass "lifts enforcement" of the checks, which implied they had passed and were merely unenforced. GitHub's rule-suite log, which records each rule's own result for every push, shows otherwise:

| Pushes to `main`, 2026-09-27 to 2026-10-27 | Count |
|---|---|
| Passed both rules: other authors' pull requests #455, #469, #484, #485 and #510 | 5 |
| Bypassed the review only; required checks passed | 47 |
| Bypassed with required checks not passing at push time | 163 |

The 163 are 157 merges of the maintainer's pull requests, 2 approved pull requests by other authors (#479, #483), 2 direct pushes and 2 advisory merges. At least 35 went in with a required check reported as failing: Lint on all 35, and on 16 of them, all before 2026-10-06, also the region-matrix Pytest jobs that #407 replaced. The rest had required checks still running or not yet reported.

From 2026-10-05 13:45 EDT the ruleset required a "Pytest Logic Tests" check that CI did not emit until #407 merged on 2026-10-06 at 09:22. Two pushes fell in that window: a direct push, which had no checks at all, and #407 itself, whose Lint check failed. Neither went in failing because of the missing check.

`gh pr checks` was no safe substitute: on #546 it listed 48 of the PR's 50 check-runs and left out the required "OPA Rego Policy Lint and Test" check. The merges of #550 and #551 were still decided from it; a check through the REST check-runs API on 2026-10-27 found all six required checks successful on both merged heads.

To re-run the counts (this needs admin access, and the window moves with the date of the query):

```bash
R=google/cybernetic-agent-governance-engine
gh api --paginate "repos/$R/rulesets/rule-suites?ref=refs/heads/main&time_period=month&per_page=100" \
  --jq '.[] | [.id, .result] | @tsv' | sort -u > suites.tsv
cut -f2 suites.tsv | sort | uniq -c
cut -f1 suites.tsv | while read -r id; do
  gh api "repos/$R/rulesets/rule-suites/$id" \
    --jq '[.result, (.rule_evaluations[] | select(.rule_type == "required_status_checks") | .result)] | @tsv'
done | sort | uniq -c
```

**Milestones:**
1. **2026-10-27:** [`check_pr_mergeable.sh`](../scripts/check_pr_mergeable.sh) landed in `2d65e15c` (#552), with hermetic tests in [`test_check_pr_mergeable.py`](../tests/test_check_pr_mergeable.py).
2. **2026-10-27:** the required checks moved to ruleset 25966171, which has no bypass actor; ruleset 19769096 keeps only the review rule.
3. **On second maintainer onboarding:** a second maintainer reviews the first maintainer's pull requests.

**Closure criteria:** Five consecutive merges to `main` recorded as `pass` in the rule-suites log, beginning after a second maintainer is onboarded, of which at least three are pull requests authored by the original maintainer and approved by the second. This criterion decides when the item closes, not when merging is allowed.

### POAM-2026-114: Causal Tier Refusal Paths Never Operated (Finance)

**Control:** NIST SI-10 (Information Input Validation), CA-7 (Continuous Monitoring); `CTRL_MRM_004` (marginal risk boundary), `CTRL_TEL_003` (placebo refutation)
**Risk Level:** Moderate (advisory severity pending maintainer decision)
**Status:** Open — remediation implemented, closes with the fix release and its security advisory
**Date Opened:** 2026-10-26
**Target Closure:** With the fix release

**Description:**
The finance causal tier ([`causal_tier.py`](../src/cage_finance/tiers/causal_tier.py), `execute_trade` only) has two refusal paths once its telemetry gates pass, and neither operated in v3.0.0–v3.3.0:
1. **Marginal risk boundary.** DoWhy estimated β on the raw trade amount (risk per dollar), and the boundary then divided `β × amount` by `normalization_scale` (10,000) a second time. On the finance synthetic telemetry the boundary tripped above about $91.4M instead of the documented rule's $9,144 (`0.5 + β × amount > 0.95`, see POAM-2026-057), above OPA's $1M ceiling, so it never decided anything.
2. **Placebo refutation (phase 2).** The refuter used dowhy's default placebo, which for a float treatment is drawn from N(0, 0): every simulated effect is 0.0 and the p-value is NaN (normal test) or a finite 1.0 (bootstrap test, from 100 simulations). The gatekeeper defaulted a missing p-value to 1.0 and skipped the lock on NaN, so phase 2 always returned a trusted verdict and the `GOVERNANCE_TRACE` evidence recorded the causal stage as `PASS`.

Reach: finance `execute_trade` in non-enforcing postures on synthetic telemetry (the quickstart, GKE `--env dev`), and in any posture with at least `causal.min_samples` fresh matching live traces. Other controls (OPA, FTRA HITL above $10,000, fiscal, CBF) still bounded the trades the tier admitted. Releases before 3.0.0 never reached these checks because of a separate defect.

**Remediation:**
1. [`validate_world_model()`](../src/gateway/governance/causal/gatekeeper.py) fits β on `treatment / normalization_scale` (both call sites pass the spec's scale: `CausalGatekeeper._validate_world_model` and the [`WorldModelRefresher`](../src/gateway/governance/causal/world_model_refresher.py) process-pool call). The boundary formula is unchanged, so the scale cancels and the trip point is `0.45 × normalization_scale / β` ($9,144 on synthetic telemetry). The scale is part of the verdict cache key, `CausalSpec` rejects a non-finite or non-positive scale, and the `CAUSAL_NORMALIZATION_SCALE` environment override was removed.
2. Phase 2 permutes the treatment (`placebo_type="permute"`), keeps every simulated effect, and returns an untrusted verdict when the result is missing or non-finite (`placebo_result_invalid`) or the effects have zero spread (`placebo_degenerate`). The `p < 0.05` lock direction is unchanged.

**Verification (2026-10-26, local branch, hermetic):**
1. [`tests/test_causal_risk_boundary.py`](../tests/test_causal_risk_boundary.py) and [`tests/test_causal_placebo_refutation.py`](../tests/test_causal_placebo_refutation.py): the real estimator trips between $9,143 and $9,145 for scales 1, 200 and 10,000; the tier and a DRY_RUN pipeline deny $9,500 with `("causal", "FAIL")` evidence; dowhy's degenerate placebo is refused at 50 and 100 simulations; every missing or non-finite result is refused; the process-pool and in-thread paths agree.
2. **Pending before closure:** the fix commit on `main` (via the advisory), the OSCAL component update and exporter run (within 2 business days of merge), and Lula (the `lula` CLI is not installed locally; no Kubernetes resource was added, removed or renamed).

### POAM-2026-113: provider_01 Authority Request Facts Are Self-Asserted (EU_ECB)

**Control:** EU AI Act Art. 27 (`CTRL_FRIA_006`), NIST AC-3, SI-10
**Risk Level:** Moderate
**Status:** Open
**Date Opened:** 2026-10-25
**Target Closure:** 2026-12-31
**Reported by:** Dominik Blain (`@dom-omg`), Ironproof, in GHSA-f6xq-23f7-9grm. Thank you.

**Description:**
[`_build_cage_authority_request()`](../src/integrations/provider_01/provider.py) maps the kernel's FRIA payload to the partner's 37-field authority request. Three facts the partner relies on are constants: `mandate_status: "ACTIVE"`, `kya_status: "VERIFIED"` and `actor_authenticated: true`. The mandate (`mandate_id`, `mandate_max_amount`, `mandate_currency`, `mandate_valid_until`, `permitted_source_accounts`, `permitted_counterparty_class`), screening (`screening_status`, `screening_captured_at`, `screening_max_age_seconds`, `screening_source`) and counterparty/account state come from request params, with permissive defaults when absent (`DEFAULT-MANDATE`, 1,000,000, `2099-12-31T23:59:59Z`, `UNRESTRICTED`, `CLEAR`, now). `target` is read from a top-level envelope field that the kernel payload does not carry, so it goes out empty on the governor path. Request params are partly caller-controlled, so the external authority can be asked to decide on facts that nobody verified. The GHSA-f6xq-23f7-9grm fix made the kernel send the verified workload identity (`actor_id` / `operator_urn`) and trace id; it deliberately left this mapping unchanged, because provider_01 is a partner-built Tier 1 adapter on the frozen Phase 3 v0.2 wire contract, every change to it must be validated over the wire against the partner sandbox (AGENTS.md), and the Step 1 harness uses these params to simulate an expired mandate and stale screening.

**Remediation Plan:**
1. Derive `actor_authenticated` and `kya_status` from the verified workload identity in the payload (false / unverified when `operator_urn` is empty), never from constants.
2. Stop defaulting mandate, screening, counterparty and account facts, and populate `target` from a server-bound route. Either resolve these facts server-side from a posture-completing reference source (deterministically seeded, with fault injection for every fail-closed path), or omit them so the partner resolves its own records; a request missing a required fact fails closed in the adapter.
3. Agree the change with the partner as a wire-contract revision, and update [`FLOWSIGNAL_PARTNER_SPECIFICATION.md`](partners/provider_01/FLOWSIGNAL_PARTNER_SPECIFICATION.md) bilaterally.

**Closure Criteria:**
1. The partner has adopted the revised contract, and an over-the-wire conformance run against the partner sandbox covers ALLOW, REFUSE, ESCALATE and every fail-closed path.
2. The Step 1 harness ([`verify_flowsignal_wire_and_hostile.py`](../scripts/verify_flowsignal_wire_and_hostile.py)) is re-run live without injecting mandate or screening facts through params.
3. Record the merge commit SHA and the actual date of the live run here.

### POAM-2026-112: Deferral Envelope Wrapping and Evidence Format Normalization

**Control:** NIST AU-3 (Content of Audit Records), AU-10 (Non-Repudiation), SC-13 (Cryptographic Protection)
**Risk Level:** Moderate
**Status:** Closed
**Date Opened:** 2026-10-07
**Date Closed:** 2026-10-07
**Related Commit:** `fix/defer-evidence-format` (pending squash merge)

**Description:**
Generating the real-code-path VEIP v0.1 sample evidence bundle against `bootstrap_governor()` and the ASGI gateway uncovered five evidence-format gaps:
1. **Unwrapped `DEFER` and `REQUIRE_APPROVAL` gateway responses and duplicate `external_attestations`:** [`validate_action_endpoint`](../src/gateway/server/governance_middleware.py) wrapped only `ALLOW` and `NARROW` verdicts in a KMS-signed v3.0 [`GovernanceEnvelope`](../src/gateway/governance/governance_envelope.py), returning `DEFER` (non-`EXTERNAL_HOLD`) and `REQUIRE_APPROVAL` as unsigned flat `{"schema_version": "1.0.0", ...}` JSON. On `ALLOW`/`NARROW`, `result["external_attestations"]` was also left inside `envelope.payload`, serializing `ExternalAttestation` dataclasses twice under two different schemas.
2. **`Violation` objects serialized as Python `repr(...)` strings:** `_park_defer_context()` and `post_hitl_deferral_event()` in [`verdicts.py`](../src/gateway/governance/governor/verdicts.py) recorded `[str(v) for v in violations]`. Because [`Violation`](../src/gateway/governance/contracts.py) defines `to_dict()` rather than `__str__`, `str(v)` emitted `"Violation(tier='warrant', ..., kind=<ViolationKind.RELIANCE_INELIGIBLE: 'reliance_ineligible'>, bound=None)"` into `DeferToken.opa_input_snapshot["violations"]` and `GOVERNANCE_DEFERRAL` stream records.
3. **Empty `control_id: ""` on `GOVERNANCE_DEFERRAL` and `GOVERNANCE_REFUSAL` stream entries:** `deferral_event()`, `post_hitl_deferral_event()`, and `publish_refusal()` in [`verdicts.py`](../src/gateway/governance/governor/verdicts.py) omitted `controlId`, so [`EvidenceStreamSink._append`](../src/gateway/governance/evidence/stream.py) wrote `control_id: ""` in the Redis stream header.
4. **Truncated 16-hex (`64`-bit) `params_hash`:** [`generate_seal_with_evidence()`](../src/gateway/governance/routing_seal.py), `deferral_event()`, and `post_hitl_deferral_event()` truncated `params_hash` to `[:16]`, whereas `compute_action_hash()` and `envelope.subject.action_hash` use the full 64-hex SHA-256 digest.
5. **Empty `governance_context.tiers_passed`:** [`SymbolicGovernor.validate_action()`](../src/gateway/governance/governor/governor.py) did not project `PipelineResult.stage_outcomes` into `tiers_passed`, leaving `envelope.governance_context.tiers_passed` empty (`[]`).

**Remediation:**
1. [`governance_middleware.py`](../src/gateway/server/governance_middleware.py): wrap all HTTP 200 `/validate-action` verdicts (`ALLOW`, `NARROW`, `DEFER`, `REQUIRE_APPROVAL`) in `GovernanceEnvelopeBuilder().build(...)`, exclude `external_attestations` from `envelope.payload` (keeping them at the top-level `envelope.external_attestations`), and serialize any `Violation` instances in `payload.violations` via `v.to_dict()`.
2. [`verdicts.py`](../src/gateway/governance/governor/verdicts.py): serialize `violations` via `v.to_dict()` in `_park_defer_context()` and `post_hitl_deferral_event()`; use `_error_message(violations[0])` in `build_refusal_receipt()`; resolve `controlId` via `_resolve_deferral_control_id()` on `GOVERNANCE_DEFERRAL` and `receipt.control_id` on `GOVERNANCE_REFUSAL`; and emit the full 64-hex `params_hash`.
3. [`routing_seal.py`](../src/gateway/governance/routing_seal.py) & [`stream.py`](../src/gateway/governance/evidence/stream.py): remove `[:16]` from `params_hash` in `GOVERNANCE_DECISION` and accept `controlId` or `control_id` in `_append()`.
4. [`governor.py`](../src/gateway/governance/governor/governor.py): add `_context_meta(result)` to include `tiers_passed` (`[name for name, outcome in result.stage_outcomes if outcome == "PASS"]`) on every `validate_action()` return path.

**Verification (2026-10-07):**
1. [`tests/test_envelope_transport.py`](../tests/test_envelope_transport.py), [`tests/test_governance_middleware.py`](../tests/test_governance_middleware.py), [`tests/governor/test_warrant_reliance_e2e.py`](../tests/governor/test_warrant_reliance_e2e.py), and [`tests/governor/test_post_hitl_approval_spend.py`](../tests/governor/test_post_hitl_approval_spend.py) pass (104 passed), asserting v3.0 envelope wrapping on `DEFER`/`REQUIRE_APPROVAL`, no `external_attestations` duplication in `payload`, populated `tiers_passed`, non-empty `control_id`/`controlId`, 64-hex `params_hash`, and structured `Violation` dicts.
2. **Lula: not run.** No Kubernetes resource was added, removed or renamed. The finding is evidenced by the pytest files above, listed under `CODE_EVIDENCE_FINDINGS` in [`check_poam_lula_divergence.py`](../scripts/check_poam_lula_divergence.py).

### POAM-2026-111: Reliance Evidence Missing Warrant Contract Fields

**Control:** NIST AU-3 (Content of Audit Records), AU-10 (Non-Repudiation)
**Risk Level:** Moderate
**Status:** Closed
**Date Opened:** 2026-10-07
**Date Closed:** 2026-10-07
**Related Commit:** `fix/reliance-contract-fields` (pending squash merge; rebased onto #436, which holds POAM-2026-110)

**Description:**
The VEIP Warrant Contract v0.1 evidence contract expects every decision's hash-chained evidence to carry `warrant_id`, `norm_id`, `digest`, `reliance_status`, `governing_version`, `residual_risk_ref` (opaque, partner Q5) and `attested_at`. The kernel [`RelianceRecord`](../src/gateway/governance/warrant/reliance.py), bound into seal, deferral and refusal evidence since `0cdb5aaa` (#427), had no `residual_risk_ref`, `attested_at` (it had `evaluated_at`) or `issuing_authority`. Those fields existed only in the ALLOW envelope's `WARRANT` attestation, built by a separate function (`bind_warrant_to_attestation()`), which is signed but not hash-chained and is absent from DEFER and DENY outcomes. `governing_version` was ambiguous: in the record it was the version the binding requires, in the attestation the version the warrant declares. The VEC-006 (tampered digest) reason truncated both digests to 16 hex characters, which for the VEIP vector (last nibble flipped) printed two identical prefixes.

**Remediation:**
1. `RelianceRecord` (frozen) stores only what the decision knows (`norm_id`, `required_governing_version`, `provider_name`, standing, freshness) and reads every warrant-declared field from the standing's warrant. Its evidence form adds `warrant_governing_version`, `issuing_authority`, `authority_basis`, `revocation_ref`, `residual_risk_ref` and `attested_at`, and drops `governing_version` and `evaluated_at`. `StandingVerificationResult.evaluated_at` is renamed `attested_at`, so one name runs from the verifier to the evidence. `WARRANT_CONTRACT_EVIDENCE_FIELDS` maps each contract field to its record key (`digest` → `warrant_digest`, `governing_version` → `warrant_governing_version`).
2. With no warrant (`INELIGIBLE_MISSING`, or a source failure before any answer) every warrant-declared field is `""`; an undeclared `revocation_ref` / `residual_risk_ref` is `""` too. `attested_at` is always set. The record refuses a standing whose `warrant_id` / `warrant_digest` do not match its warrant.
3. `82df1b14^:src/gateway/governance/warrant/evidence.py` (`bind_warrant_to_attestation()`) is deleted. The envelope attestation is `RelianceRecord.attestation()`, whose metadata is exactly `RelianceRecord.to_dict()`, so the signed envelope and the evidence chain cannot drift.
4. [`WarrantStandingVerifier`](../src/gateway/governance/warrant/verifier.py) prints both full 64-hex digests on a digest mismatch.

**Verification (2026-10-07):**
1. [`test_provider_05_reliance_record.py`](../tests/integrations/provider_05/test_provider_05_reliance_record.py): for VEC-001 to VEC-006 the record carries the seven contract fields with the vector values (`residual_risk_ref` `RRR-2026-08-01-A1`), the attestation metadata equals the record, VEC-005 records `cage-policy-9.9.9` (required) apart from `cage-policy-2.1.0` (declared), VEC-006 names both full digests, and MISSING leaves every warrant-declared field `""` with `attested_at` set.
2. [`test_warrant_reliance_e2e.py`](../tests/governor/test_warrant_reliance_e2e.py) (`test_contract_fields_in_the_chained_allow_decision_and_envelope`, `test_contract_fields_in_the_chained_deferral`, `test_contract_fields_in_the_chained_post_hitl_deferral`): through `bootstrap_governor()`, the gateway and the trade tool, the hash-chained `GOVERNANCE_DECISION` (ALLOW, VEC-001) and `GOVERNANCE_DEFERRAL` payloads carry all seven fields with the expected values: the preview deferral and the commit-path deferral after `execute_trade_action()` (POAM-2026-110) for VEC-002 to VEC-006 and MISSING, and the POST_HITL `approval_retained` deferral for a warrant revoked after approval. The signed envelope attestation equals the sealed record.
3. Mutation check: 8 of 8 mutants killed (drop `residual_risk_ref`; attestation metadata diverging from the record; 16-hex digest truncation; required and declared `governing_version` conflated; `attested_at` taken from `observed_at`; `None` instead of `""` for a missing warrant; drop `issuing_authority`; drop the standing/warrant consistency check).
4. OSCAL: the AU-10 statement in [`sp800-53-component-definition.yaml`](../compliance/oscal/sp800-53-component-definition.yaml) and the EU_ECB reliance statements in [`system-security-plan-eu-ecb.yaml`](../compliance/oscal/system-security-plan-eu-ecb.yaml) name the new fields; the SSP export and [`test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) pass.
5. **Lula: not run.** No Kubernetes resource was added, removed or renamed. The finding is evidenced by the pytest files above, listed under `CODE_EVIDENCE_FINDINGS` in [`check_poam_lula_divergence.py`](../scripts/check_poam_lula_divergence.py).

**Residual:** warrant authenticity is still `UNVERIFIED` (POAM-2026-104 gap 1); this entry fixes evidence content, not issuer verification.

### POAM-2026-110: Committing Run Fabricated a DENY on a Warrant Failure

**Control:** NIST AC-3 (Access Enforcement), AU-10 (Non-repudiation)
**Risk Level:** Moderate
**Status:** Closed
**Date Opened:** 2026-10-07
**Date Closed:** 2026-10-07
**Related Commit:** `fix/hitl-token-warrant-defer` (#436) (pending squash merge)

**Description:**
Under EU_ECB, `POST /governance/validate-action` (dry run) classified a `RELIANCE_INELIGIBLE` finding as DEFER `WARRANT_INELIGIBLE`, but the committing run did not. `SymbolicGovernor.govern()` (and the narrowed re-run in `_sealed_narrow`) sent any violation to `handle_deny`, so `execute_trade_action()` returned `BLOCKED: Governance Blocked: [RELIANCE_INELIGIBLE_REVOKED] ...` and a `GOVERNANCE_REFUSAL` receipt entered the evidence chain. A warrant failure is not an institutional verdict: the frozen rule, [`proof/model.py`](../proof/model.py) claim 12 (`warranted_norm_never_fabricates_deny`) and OSCAL `eu-ecb-req-0007` all require DEFER. Nothing was sealed or actuated (fail closed), so the defect was in the verdict and its evidence, not in admission. It was masked because the e2e test asserted only the preview and the absence of actuation, not the record the commit left. Recorded separately from POAM-2026-104 because it is a distinct defect (a contradicted proof claim and OSCAL statement), not a residual of the gate's design.

**Remediation:**
1. [`ClassificationEngine.defers_on_reliance()`](../src/gateway/governance/classification_engine.py) answers, without invoking the narrower, whether findings defer on reliance (`RELIANCE_INELIGIBLE`, no HARD, DEFER enabled), using the same ranking as `classify()`.
2. [`governor.py`](../src/gateway/governance/governor/governor.py): `govern()`, the `_sealed_narrow` re-run and the `_narrow_candidate` preview re-run defer through `handle_defer` (parked `WARRANT_INELIGIBLE` token, `GOVERNANCE_DEFERRAL` with the reliance record) and raise `GovernanceDeferred`; `revalidate_post_hitl()` defers through `handle_post_hitl_defer` (POAM-2026-104 gap 3).
3. [`governance_middleware.py`](../src/gateway/server/governance_middleware.py) maps `GovernanceDeferred` to `ActionDeferred` (no refusal receipt), and [`tool_provider.py`](../src/cage_finance/tools/tool_provider.py) returns `DEFERRED: ...`.
4. Precedence: a HARD finding from an independent stage (OPA, STPA, FTRA, a domain bounding tier) outranks the warrant failure and still denies, with the reliance record inside the receipt's `proof_hash` when the warrant stage ran (`test_govern_hard_finding_outranks_the_warrant_and_denies`, `test_hard_domain_violation_with_a_revoked_warrant_denies_with_reliance`).

**Verification (2026-10-07):**
1. [`tests/governor/test_warrant_reliance_e2e.py`](../tests/governor/test_warrant_reliance_e2e.py): for VEC-002 to VEC-006, a missing warrant and every injected source fault, after `execute_trade_action()` the tool result starts `DEFERRED:`, the chain holds a `GOVERNANCE_DEFERRAL` and no `GOVERNANCE_REFUSAL`, and nothing is sealed or actuated. [`tests/governor/test_post_hitl_approval_spend.py`](../tests/governor/test_post_hitl_approval_spend.py) covers `govern()` parking the deferral and HARD precedence; [`tests/test_governance_middleware.py`](../tests/test_governance_middleware.py) covers the deferral not being a refusal.
2. Mutation check: forcing the governor's reliance-deferral check to `False` fails 25 tests, including all six VEC-002..006 / MISSING commit-path cases.
3. OSCAL `eu-ecb-comp-0006` updated; the exporter (default discovery) compiled and [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) passed.
4. **Lula: not run.** The `lula` CLI is not installed. No Kubernetes resource was added, removed or renamed.

### POAM-2026-109: Dead Bounded Execution Module Bypassed Routing Seal

**Control:** NIST AC-3 (Access Enforcement), SI-10, CM-7 (Least Functionality)
**Risk Level:** Low
**Status:** Closed
**Date Opened:** 2026-10-06
**Date Closed:** 2026-10-06
**Related Commit:** `refactor/remove-bounded-execution` (pending squash merge)

**Description:**
`de2b96ee^:src/cage_finance/tools/bounded_execution.py` defined `execute_trade_bounded()`, a Phase 5 wrapper that built a `TradeOrder` and called the broker's [`execute_trade()`](../src/cage_finance/tools/trade_executor.py) with `routing_seal="INTERNAL_BOUNDED_EXECUTION"`. `execute_trade()` refuses only a missing, non-string or blank seal, so this call reached the broker without [`verify_and_consume_seal()`](../src/gateway/governance/routing_seal.py) or [`ActuatorRegistry`](../src/gateway/governance/execution_actuator.py) dispatch, breaking the ADR-008 fail-closed execution boundary. The actuator-seam invariant in [`test_architectural_invariants.py`](../tests/test_architectural_invariants.py) allowlisted the file as a "legacy bounding contract wrapper". Nothing imported the module or called the function (no tool binding, MCP registration, server route or test), so the path was not reachable at runtime; the risk was latent: one import away from an ungoverned trade.

**Remediation:**
1. The module is deleted. The `execute_trade_bounded` action (bounding tier [`bounding_tier.py`](../src/cage_finance/tiers/bounding_tier.py), terminal registry classification, cost resolver, OPA policy) is unchanged; only the ungoverned wrapper is gone.
2. `test_actuator_seam_isolation_execute_trade` no longer allowlists the file. It now tracks the enclosing class and method correctly (the previous `ast.walk` stacks were never popped), allows exactly `BrokerActuator.actuate` in [`broker_actuator.py`](../src/cage_finance/actuators/broker_actuator.py), scans `__init__.py` files too, and fails if any other `src/` module imports `trade_executor` (so an aliased call cannot slip past a name check).
3. New guard `test_no_literal_routing_seal_in_src` fails if any call in `src/` passes a string literal as `routing_seal`.

**Verification (2026-10-06):**
1. With the module restored at its original path, both invariant tests fail and name it; with it deleted they pass.
2. A repository-wide search (src, tests, docs, scripts, config, deployment, compliance, examples, Makefile) found no import of the module or the function; remaining `execute_trade_bounded` matches are the governed action name. No OSCAL statement referenced the module or the allowlist, so no OSCAL change was required.
3. **Lula: not run.** The `lula` CLI is not installed. No Kubernetes resource was added, removed or renamed, so no Lula manifest change was required.

### POAM-2026-108: Bounded Trade Measured Inputs Not Server-Bound

**Control:** NIST SI-10, CM-6
**Risk Level:** Moderate
**Status:** Closed
**Date Opened:** 2026-10-06 (found by the warrant reliance end-to-end matrix, #433)
**Date Closed:** 2026-10-06
**Remediation:** `fix/bounded-trade-server-inputs` (pending squash merge)

**Description:**
The kernel binds measured trade inputs through each action's `PluginContribution.server_inputs` resolver (POAM-2026-105). The finance plugin registered a resolver for `execute_trade` only. For `execute_trade_bounded`, `bind_server_inputs()` therefore found no resolver and passed the caller's params through unchanged, including any `drawdown`, `current_drawdown` or `portfolio_drawdown_pct`, on `POST /governance/validate-action` and the MCP `simulate_governance_check` dry run. Bounding contract B2 ([`contract_b2_drawdown_breaker`](../src/cage_finance/safety/bounding/contracts.py)) is the bounded verb's drawdown circuit breaker, but [`BoundingContractRegistry`](../src/cage_finance/safety/bounding/registry.py) called it without any drawdown, so B2 refused every bounded trade with "Missing current drawdown data" in every region. That failure was fail-closed: a caller's drawdown never reached B2, so no caller value could pass it. But B2 never compared a measured drawdown with the regional limit, and the bounded verb's measured-state params stayed caller-controlled for any consumer. No STPA rule reads an owned key for `execute_trade_bounded` (UCA-2/5/6/13 are scoped to `execute_trade`; UCA-12 reads none).

**Remediation:**
1. **One resolver for every trade action.** [`plugin.py`](../src/cage_finance/plugin.py) builds a single `TradeInputResolver` and registers it for each action in `TRADE_ACTIONS` ([`trade_inputs.py`](../src/cage_finance/tools/trade_inputs.py): `execute_trade`, `execute_trade_bounded`). The kernel drops caller values for every owned key of a bounded trade and binds the gateway's readings on every preview (`validate_action()`, `verify()`).
2. **B2 reads the bound drawdown.** [`BoundingContractTierPlugin`](../src/cage_finance/tiers/bounding_tier.py) declares `server_input_keys = {"drawdown"}` and passes `bound_drawdown_fraction(params)` (the resolver's percent / 100) to `BoundingContractRegistry.evaluate_all(..., current_drawdown=...)`, which hands it to B2. A missing or non-numeric value is unmeasured and B2 refuses it; a non-finite one is refused as invalid.
3. **Regional bounding limits.** The plugin builds the bounding registry from the same thresholds object as `load_finance_thresholds()` (it previously bound the module-level `THRESHOLDS` at import), so B1/B2 use the region's effective `domains.finance` values.
4. **Guard.** [`test_bounded_trade_server_inputs.py`](../tests/cage_finance/test_bounded_trade_server_inputs.py) derives every consumer of an owned key from `trade_hazards.yaml` (condition params, aliases, composite operands, `applies_when`) and from the contributed tiers' `server_input_keys`, and fails if any such action has no resolver owning those keys. It also fails if a tier module names an owned key it does not declare. Removing the bounded resolver makes the guard report `{"execute_trade_bounded": {"drawdown"}}`.

**Verification (2026-10-06):**
1. [`tests/cage_finance/test_bounded_trade_server_inputs.py`](../tests/cage_finance/test_bounded_trade_server_inputs.py), for each region (US_FED, APAC_MAS, EU_ECB): with every caller drawdown spelling set to 0.0 and the server-measured drawdown 0.5 points over the regional B2 limit, B2 refuses (HARD); 0.5 points under the limit, B2 admits even when the caller claims a breach. Every NAV fault (timeout, connection error, malformed, negative, NaN, stale, future-dated, unverified) and a missing NAV source leave `drawdown` unbound and B2 refuses. Through `POST /governance/validate-action` (behind workload identity) the over-limit case is DENIED with `BOUNDING_B2_HARD_BLOCK` and a refusal receipt, and a stale NAV is DENIED; `verify()` reports B2 too. Mutation check: registering the resolver for `execute_trade` only fails 51 of the 68 tests; passing B2 a constant 0.0 drawdown fails 39.
2. **Commit path.** No gateway tool commits `execute_trade_bounded`: the only committing tool is `execute_trade_action`, which binds before `enforce_governance()`. If a bounded committing tool is added it must bind the same way; the resolver it needs is already registered.
3. OSCAL: the `cm-6` statements in [`system-security-plan.yaml`](../compliance/oscal/system-security-plan.yaml), [`system-security-plan-eu-ecb.yaml`](../compliance/oscal/system-security-plan-eu-ecb.yaml) and [`system-security-plan-apac-mas.yaml`](../compliance/oscal/system-security-plan-apac-mas.yaml) now record the bounded binding. `uv run python -m src.gateway.governance.oscal_ssp_exporter export` (default discovery) compiled, and [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) passed.
4. **Lula: not run.** The `lula` CLI is not installed and no EU_ECB or APAC_MAS cluster exists. No Kubernetes resource was added, removed or renamed, so no Lula manifest change was required. Closure rests on the tests and the OSCAL export above.

### POAM-2026-106: UCA-6 Order-Volume Limit Never Evaluated

**Control:** NIST SI-10, CM-6
**Risk Level:** Moderate
**Status:** Closed
**Date Opened:** 2026-10-06 (found while closing POAM-2026-105)
**Date Closed:** 2026-10-06
**Remediation:** `fix/uca6-server-inputs` (pending squash merge)

**Description:**
UCA-6 in [`trade_hazards.yaml`](../src/cage_finance/config/stpa/trade_hazards.yaml) refuses a market order larger than `stpa.uca6_max_order_volume_fraction` of the symbol's daily volume (`order_size > fraction × daily_vol`; hazard H-5, slippage). The regional overlay sets the fraction (US_FED 0.01, EU_ECB 0.005, APAC_MAS 0.008), and the generated rule in [`uca_rules.py`](../src/cage_finance/stpa/uca_rules.py) read it. But neither the trade tool nor any preview supplied `order_size` or `daily_vol`, and the rule returned no finding when both were absent. UCA-6 therefore never evaluated a trade in any region. The only code that set the two params was the advisor evaluator's dry run, which set both to 0.0; those defaults were removed in POAM-2026-105.

**Remediation:**
1. **Fail closed on missing inputs.** UCA-6's condition now sets `require_params: true`, so a trade without a numeric `order_size` and `daily_vol` is a HARD STPA violation. `uca_rules.py` was regenerated and `scripts/check_stpa_freshness.py` passes.
2. **Server-side inputs.** [`TradeInputResolver`](../src/cage_finance/tools/trade_inputs.py) (the finance plugin's `PluginContribution.server_inputs` resolver, applied by the kernel `bind_server_inputs()` on every preview and committing run) now owns `order_size` and `daily_vol`. Caller values for both are dropped.
   - `order_size` (shares) = the caller's notional `amount` / the price of the verified quote that also gives `latency_ms`. `amount` stays caller intent; `order_size` is derived. A non-numeric, boolean, non-finite or negative amount leaves it unset. No FX conversion is applied: the amount is taken to be in the quote currency.
   - `daily_vol` (shares) = the symbol's average daily volume from the market-data feed (`MarketQuoteFeed.average_daily_volume`). `fetch_verified_daily_volume()` requires a verified source, the traded symbol, a finite positive value, an age within `MAX_DAILY_VOLUME_AGE_S` (four days: published once per session, allowing for a weekend and a holiday), and at most 5 s of future skew.
3. **Simulated feed.** [`SimulatedMarketQuoteFeed`](../src/cage_finance/simulated_feeds.py) publishes a settable average daily volume with its own fault channel (`inject_volume_fault`), covering timeout, connection error, malformed, negative, NaN, stale, future-dated and unverified readings independently of the quote.
4. **Narrow proposals are re-bound.** A narrower clamps `amount` in a copy of the bound params, so a derived input would still describe the original amount. `SymbolicGovernor` now re-binds a proposal (`_rebind`) before re-verifying it on the validate-action, narrow-hint and committing NARROW paths. The seal and NARROW receipt name the re-bound params.

**Verification (2026-10-06):**
1. [`tests/cage_finance/test_trade_uca6_inputs.py`](../tests/cage_finance/test_trade_uca6_inputs.py), for each region: an order at 0.9× the regional fraction passes, an order at 1.1× is refused, and an order at 0.7 % of daily volume passes in US_FED and APAC_MAS but is refused in EU_ECB. Caller-supplied `order_size` / `daily_vol` cannot hide an oversized order or refuse a small one. Every volume fault and every quote fault that prevents pricing refuses the trade, as do a missing feed and an unusable amount. The age window, symbol, source and value checks are covered as units.
2. [`tests/test_advisor_trade_preview_e2e.py`](../tests/test_advisor_trade_preview_e2e.py): through the advisor's `safety_check` against the real gateway app, a 0.7 % order is refused with UCA-6 only in EU_ECB. In every region, a stale daily-volume reading refuses the preview with a refusal receipt, and the committing tool refuses too, with nothing actuated. [`tests/test_trade_governance_e2e.py`](../tests/test_trade_governance_e2e.py) checks that a re-verified narrow hint carries `order_size` for the clamped amount.
3. OSCAL: the `cm-6` statements in [`system-security-plan.yaml`](../compliance/oscal/system-security-plan.yaml), [`system-security-plan-eu-ecb.yaml`](../compliance/oscal/system-security-plan-eu-ecb.yaml) and [`system-security-plan-apac-mas.yaml`](../compliance/oscal/system-security-plan-apac-mas.yaml) now record the UCA-6 inputs. `uv run python -m src.gateway.governance.oscal_ssp_exporter export` (default discovery) compiled, and [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) passed.
4. **Lula: not run.** The `lula` CLI is not installed and no EU_ECB or APAC_MAS cluster exists. No Kubernetes resource was added, removed or renamed, so no Lula manifest change was required. Closure rests on the tests and the OSCAL export above.

### POAM-2026-105: Governance Previews Evaluate Caller-Supplied STPA Inputs

**Control:** NIST SI-10, CA-7
**Risk Level:** Moderate
**Status:** Closed
**Date Opened:** 2026-10-06
**Date Closed:** 2026-10-06
**Related Commit:** `dd4bcdf6` (#424, squash-merged to `main`)
**Remediation:** `fix/preview-server-trade-inputs` (pending squash merge)

**Description:**
Since `dd4bcdf6`, the committing trade run measures its STPA inputs on the server. [`execute_trade_action`](../src/cage_finance/tools/tool_provider.py) takes no `latency_ms`, `drawdown` or `portfolio_total` from its caller; [`ServerTradeInputs`](../src/cage_finance/tools/trade_inputs.py) measures them for every committing run, and only that run reserves budget, mints the routing seal and actuates. The preview endpoint does not. [`validate_action_endpoint`](../src/gateway/server/governance_middleware.py) passes the caller's `params` to `SymbolicGovernor.validate_action()` unchanged, so UCA-2 / FIN-2, UCA-5 and UCA-13 / FIN-1 evaluate whatever the caller sent. A preview mints no seal and reserves nothing, so it cannot authorise execution. The binding verdict is always the one computed on server-side inputs. The gap is that the preview verdict is not a faithful forecast of the binding verdict:

1. **Advisor previews are refused.** The advisor's `safety_check` node ([`safety_node.py`](../src/governed_financial_advisor/graph/nodes/safety_node.py)) and `gateway_tool_guard` ([`tool_guard.py`](../src/governed_financial_advisor/graph/governance/tool_guard.py)) preview with the canonical [`trade_params`](../src/governed_financial_advisor/graph/nodes/trade_contract.py) payload, which carries none of the inputs. On 2026-10-06 the generated rules refused that payload with UCA-2 and UCA-5 for a buy, and with UCA-2, UCA-5 and UCA-13 for a sell. The advisor graph therefore stops before it reaches the gateway trade tool, even when the committing run would clear the STPA stage. Each refused preview also emits a refusal receipt into the evidence chain whose findings reflect missing caller inputs rather than measured state.
2. **The evaluator dry run passes on invented values.** [`evaluator_node.py`](../src/governed_financial_advisor/graph/nodes/evaluator_node.py) fills `drawdown` and `latency_ms` with 0.0 before `simulate_governance_check`, so its UCA-2 / UCA-5 result says nothing about the measured state.
3. **Any caller can shape a preview.** A preview with in-limit values the gateway would not measure returns ALLOW (or a signed NARROW envelope). That envelope carries no seal, and the committing run re-measures, so the trade itself is still refused if the measured inputs breach a limit.

**Closure Criteria:**
1. Previews of a domain action evaluate the same server-side inputs as the committing run. For example, the domain plugin contributes an input resolver that the preview path applies, overriding any caller value, through a kernel seam that stays domain-agnostic (Gate G3). Alternatively, previews must strip caller values and report the affected STPA rules as not evaluated, instead of returning a verdict.
2. Remove the evaluator's 0.0 defaults for `drawdown` and `latency_ms`.
3. An advisor-graph test shows a normal buy passing `safety_check` and `gateway_tool_guard` and clearing the committing run's STPA stage. A second test shows a preview with caller-supplied out-of-limit or in-limit values getting the same STPA result as the committing run.

**Remediation:**
1. **Kernel seam (Gate G3 clean).** [`ServerInputResolver`](../src/gateway/governance/contracts.py) is a protocol with `owned_keys` and an async `resolve(params)`. A domain contributes one resolver per action through `PluginContribution.server_inputs`. [`assemble_governor()`](../src/gateway/governance/governor/assembly.py) rejects a duplicate resolver, a resolver for an unregistered action, and a resolver without a non-empty frozenset of key names or a `resolve()`. The resolvers are held read-only in `GovernorComponents.server_inputs`. [`bind_server_inputs()`](../src/gateway/governance/governor/server_inputs.py) removes every owned key from the caller's params, whatever its value, and logs the ignored keys. It then calls the resolver (bounded at 5 s) and merges back only owned keys. A resolver error, timeout or non-mapping result resolves nothing, so the domain's rules refuse the missing values. The kernel never names a finance key.
2. **Both paths bind.** `SymbolicGovernor.validate_action()` (behind `POST /governance/validate-action`, which serves the advisor's `safety_check` and `gateway_tool_guard`) and `SymbolicGovernor.verify()` (behind the MCP `simulate_governance_check` used by the evaluator) bind before the pipeline runs. [`execute_trade_action`](../src/cage_finance/tools/tool_provider.py) binds before `enforce_governance`, so the routing seal names the bound params it executes. A REQUIRE_APPROVAL / NARROW proposal is re-verified on bound params, and on resubmission they are bound again.
3. **Finance resolver.** [`TradeInputResolver`](../src/cage_finance/tools/trade_inputs.py) wraps the plugin's [`ServerTradeInputs`](../src/cage_finance/tools/trade_inputs.py) (market-data feed and NAV source). It owns `latency_ms`, `drawdown`, the UCA-5 aliases `portfolio_drawdown_pct` / `current_drawdown` (so an alias cannot bypass the binding) and `portfolio_total`. [`plugin.py`](../src/cage_finance/plugin.py) contributes it for `execute_trade`. `execute_trade_action` and `FinancialToolProvider` no longer take an `inputs` argument.
4. **No invented values.** The kernel [`StpaStage`](../src/gateway/governance/governor/stages/stpa.py) defaulted `latency_ms` to `GOVERNANCE_SIM_LATENCY_MS` (10 ms) on every dry run, which put a finance key in the kernel and let a preview clear UCA-2 without a measurement. The default was removed. The evaluator's 0.0 `drawdown` / `latency_ms` (and `order_size` / `daily_vol`) defaults were removed from [`evaluator_node.py`](../src/governed_financial_advisor/graph/nodes/evaluator_node.py).

**Verification (2026-10-06):**
1. [`tests/test_advisor_trade_preview_e2e.py`](../tests/test_advisor_trade_preview_e2e.py) drives the advisor's `safety_check_node` and `gateway_tool_guard` against the real gateway app over ASGI, then runs the trade tool's committing pass. For each region (US_FED, EU_ECB, APAC_MAS), a normal buy and a normal sell clear both previews and execute exactly once. Out-of-limit caller values (`latency_ms=10000`, `drawdown=99`, aliases, `portfolio_total=1`) do not refuse the preview. In-limit caller values (0.0 under every alias) do not mask a server-measured drawdown over the region's limit. A 4.25 % drawdown clears in US_FED and is refused in EU_ECB and APAC_MAS. Faulted market-data (timeout, stale) and NAV sources (connection error; NaN on a sell) refuse the preview with UCA-2 / UCA-5 (UCA-13 on the sell), and emit a refusal receipt for `execute_trade`. The committing tool also refuses them, with no seal minted and nothing actuated.
2. [`tests/test_server_inputs.py`](../tests/test_server_inputs.py) covers the kernel seam: owned keys stripped, only owned keys merged, fail closed on resolver error, timeout or malformed result, pass-through for actions without a resolver, every assembly rejection, read-only components, and that `verify()` evaluates bound params. [`tests/cage_finance/test_trade_server_inputs.py`](../tests/cage_finance/test_trade_server_inputs.py) parses [`trade_hazards.yaml`](../src/cage_finance/config/stpa/trade_hazards.yaml) and checks that the owned keys cover the UCA-2 param, the UCA-5 param and aliases, and UCA-13's `portfolio_total`, and that caller intent (`amount`, `side`, `symbol`, `trader_role`) is never owned. (Superseded for `trader_role` by GHSA-w39v-5v7h-fxg9: the resolver now owns `trader_role` and `trader_id` and binds them from the caller's verified workload identity; the test asserts that instead.) [`tests/test_trade_governance_e2e.py`](../tests/test_trade_governance_e2e.py) now runs with server-bound inputs only.
3. OSCAL: the `cm-6` statements in [`system-security-plan.yaml`](../compliance/oscal/system-security-plan.yaml), [`system-security-plan-eu-ecb.yaml`](../compliance/oscal/system-security-plan-eu-ecb.yaml) and [`system-security-plan-apac-mas.yaml`](../compliance/oscal/system-security-plan-apac-mas.yaml) now record that previews bind the same server-side inputs. `uv run python -m src.gateway.governance.oscal_ssp_exporter export` (default discovery) compiled, and [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) passed.
4. **Lula: not run.** The `lula` CLI is not installed and no EU_ECB or APAC_MAS cluster exists. No Kubernetes resource was added, removed or renamed, so no Lula manifest change was required. Closure rests on the tests and the OSCAL export above.

**Residual (not part of this finding):** UCA-6 (`order_size` / `daily_vol`, fraction of daily volume) was skipped when both params were absent, and no path supplied them. Tracked and closed as POAM-2026-106.

### POAM-2026-107: Warrant Reliance Path Not Verified End to End

**Control:** NIST CA-2 (Control Assessments), AC-3, AU-10
**Risk Level:** Low
**Status:** Closed
**Date Opened:** 2026-10-06
**Date Closed:** 2026-10-06
**Related Commit:** `a33d5e02` (#433)

**Description:**
The EU_ECB warrant reliance gate (POAM-2026-104) was verified stage by stage: [`test_warrant_reliance_gate.py`](../tests/governor/test_warrant_reliance_gate.py), [`test_warrant_evidence_binding.py`](../tests/governor/test_warrant_evidence_binding.py) and [`test_warrant_freshness.py`](../tests/governor/test_warrant_freshness.py) build governors from explicit parts with a static test source. The only test naming the configured adapter, [`test_provider_05_warrant_contract.py`](../tests/integrations/provider_05/test_provider_05_warrant_contract.py), ended in an inline "Test C" that set `governance_decision = DEFER` itself and asserted it. No test showed that `bootstrap_governor()` wires the gate, the 60 s cache and the `CAGE_WARRANT_SOURCE` adapter for EU_ECB (and not for APAC_MAS or US_FED), or that the gateway's preview and the trade tool's committing run carry the reliance decision through to the envelope, the seal, the deferral and the refusal.

**Remediation:**
1. [`tests/governor/test_warrant_reliance_e2e.py`](../tests/governor/test_warrant_reliance_e2e.py) builds the governor with [`bootstrap_governor()`](../src/gateway/governance/governor/bootstrap.py): the real finance plugin, the pinned region's thresholds and jurisdiction, and the `CAGE_WARRANT_SOURCE=provider_05` adapter seeded with the VEIP v0.1 vectors verbatim. Requests enter through `POST /governance/validate-action` behind workload identity and through [`execute_trade_action()`](../src/cage_finance/tools/tool_provider.py). Evidence lands in a real hash-chained `EvidenceStreamSink`; deferrals park in a real `DeferQueue` (fakeredis). Doubles: OPA verdict, EU FRIA provider, broker actuator.
2. [`assemble_governor()`](../src/gateway/governance/governor/assembly.py) takes a `warrant_clock` ([`WarrantClock`](../src/gateway/governance/warrant/cache.py): monotonic and UTC wall clock, default the process clocks) and hands it to the cache and the stage, so the test runs the composition root deterministically at the VEIP evaluation time and advances the freshness window by hand. No behaviour change at the defaults.
3. The inline Test C simulation (and Test A's local threshold comparison) is deleted from the contract test; its contract assertions (source, verifier, attestation binding) remain.
4. [`Provider05WarrantSource`](../src/integrations/provider_05/warrant_source.py) gains deterministic fault injection with the kernel `FaultMode` (AGENTS.md Tier 2 requirement), and [`WarrantCache`](../src/gateway/governance/warrant/cache.py) refuses a non-`Warrant` answer as a source fault.

**Verification (2026-10-06):**
1. `test_warrant_reliance_e2e.py` passes (27 tests). EU_ECB: VEC-001 at confidence 0.98 is admitted; the signed envelope carries an `UNVERIFIED` `WARRANT` attestation with the VEIP-published digest; the trade executes once; the consumed seal verifies against the evidence record carrying the `ELIGIBLE` reliance record (`verify_seal_against_evidence`) and cannot be replayed. VEC-002 (revoked), VEC-003 (expired), out of scope, version mismatch, VEC-006 (tampered digest), a missing warrant, every injected source fault on a cold cache (`INELIGIBLE_UNRESOLVED`) and a stale state (61 s, source timing out, refusing connections or returning a malformed payload: `INELIGIBLE_STALE`) each defer with `WARRANT_INELIGIBLE`, never deny, carry the reliance record in the DEFER token and the `GOVERNANCE_DEFERRAL` record, and seal and actuate nothing. A HARD bounding-tier finding under a revoked warrant denies with the reliance record inside the refusal receipt's `proof_hash`. A warrant revoked after human approval is refused with no seal (control: the same approval executes while the warrant holds), and the spent approval cannot be replayed. Confidence 0.96 under an eligible warrant is not admitted (0.97 floor). APAC_MAS (0.955 refused, 0.965 admitted) and US_FED (0.95 admitted and executed) assemble no warrant stage and never call the source. `bootstrap_governor()` refuses an EU_ECB governor with no source or with DEFER disabled.
2. Mutation check: with `WarrantStage.run()` returning no findings, 18 of the 27 tests fail.
3. Fault injection: [`Provider05WarrantSource.inject_fault()`](../src/integrations/provider_05/warrant_source.py) takes the kernel `FaultMode` (`TIMEOUT`, `CONNECTION_ERROR`, `MALFORMED_PAYLOAD`, `UNVERIFIED_SOURCE`; other modes are refused). [`WarrantCache`](../src/gateway/governance/warrant/cache.py) now treats an answer that is neither a `Warrant` nor `None` as a source fault, so a malformed payload is never cached or relied on. Covered by [`test_provider_05_warrant_source.py`](../tests/integrations/provider_05/test_provider_05_warrant_source.py) and the e2e matrix.
4. OSCAL: component `eu-ecb-comp-0006` and the `ac-3` requirement `eu-ecb-req-0007` in [`system-security-plan-eu-ecb.yaml`](../compliance/oscal/system-security-plan-eu-ecb.yaml) cite the end-to-end matrix as verification evidence. `uv run python -m src.gateway.governance.oscal_ssp_exporter export` (default discovery) compiled, and [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) passed.
5. **Lula: not run.** The `lula` CLI is not installed and no EU_ECB cluster exists. No Kubernetes resource was added, removed or renamed, so no Lula manifest change was required.

**Limits (stated plainly):** the warrant source is the seeded `Provider05WarrantSource`, not the VEIP wire, so this is not the Tier 1 over-the-wire conformance test AGENTS.md requires (POAM-2026-104 closure criterion 2). The FRIA provider, OPA and the broker are doubles. DENY receipts carry reliance when the warrant stage ran; kernel-stage HARD findings that precede it (FTRA, STPA, OPA, confidence) short-circuit before any reliance is formed, so their receipts carry no reliance record (accepted as designed: a warrant not evaluated is not relied upon); the test pins this (`test_kernel_hard_refusal_denies_before_the_warrant_is_consulted`).

### POAM-2026-102: Regional Finance Limits Declared but Not Enforced (EU_ECB, APAC_MAS)

**Control:** NIST SP 800-53 CM-6, `CTRL_AGT_001` (agentic confidence floor)
**Risk Level:** High
**Status:** Closed
**Date Opened:** 2026-10-06 (recorded at remediation; the gap predates it)
**Date Closed:** 2026-10-06
**Remediation Commit:** `ecca70b9` (#417, `feat(governance)!: enforce regional finance limits via domain overlay`)

**Description:**
[`EU_ECB_BASELINE.json`](../config/thresholds/EU_ECB_BASELINE.json) and [`APAC_MAS_BASELINE.json`](../config/thresholds/APAC_MAS_BASELINE.json) declared tighter finance limits than the global [`governance_thresholds.json`](../config/governance_thresholds.json), and the EU_ECB and APAC_MAS SSPs cited those files. No loader read them, so every region ran on the global (US_FED) values. The EU_ECB 0.97 and APAC_MAS 0.96 trade-confidence floors, CBF gamma, drawdown limit, consensus threshold and STPA limits were not enforced.

**Remediation (merged in `ecca70b9`):**
1. `load_and_validate_thresholds()` ([`thresholds.py`](../src/gateway/governance/schemas/thresholds.py)) deep-merges the region's baseline `domains` object onto the global `domains` sections ([`regional_overlay.py`](../src/gateway/governance/schemas/regional_overlay.py)). A missing or malformed regional file, a regional section with no global counterpart, or a value that changes shape aborts startup.
2. The finance schema ([`src/cage_finance/thresholds.py`](../src/cage_finance/thresholds.py)) validates the merged section at governor assembly, so an unknown or invalid regional key fails assembly.
3. [`assemble_governor()`](../src/gateway/governance/governor/assembly.py) refuses to assemble when the thresholds region differs from the jurisdiction region.
4. [`plugin.py`](../src/cage_finance/plugin.py) builds `CashBarrier(gamma=...)`, the bounding contracts (B2 `drawdown.limit`) and [`TradeConfidenceTier`](../src/cage_finance/tiers/trade_confidence_tier.py) from the effective section. [`consensus_tier.py`](../src/cage_finance/tiers/consensus_tier.py) and [`uca_rules.py`](../src/cage_finance/stpa/uca_rules.py) (UCA-2/FIN-2, UCA-5, UCA-6) resolve the same effective values.

Effective values at `ecca70b9`:

| Key (`domains.finance.`) | US_FED | EU_ECB | APAC_MAS |
|---|---|---|---|
| `confidence.min_trade_confidence` (`.value` since `a0deb7ad`) | 0.95 | 0.97 | 0.96 |
| `cbf.gamma` | 0.5 | 0.6 | 0.55 |
| `drawdown.limit` | 0.05 | 0.04 | 0.045 |
| `consensus.threshold_usd` | 10000.0 | 7500.0 | 8500.0 |
| `stpa.uca5_drawdown_threshold_pct` | 4.5 | 3.5 | 4.0 |
| `stpa.uca6_max_order_volume_fraction` | 0.01 | 0.005 | 0.008 |
| `stpa.max_latency_ms` (FIN-2) | 200.0 | 150.0 | 175.0 |

**Verification (2026-10-06):**
1. [`tests/governor/test_regional_overlay.py`](../tests/governor/test_regional_overlay.py), [`tests/cage_finance/test_trade_confidence_tier.py`](../tests/cage_finance/test_trade_confidence_tier.py) and [`tests/governor/test_jurisdiction_wiring.py`](../tests/governor/test_jurisdiction_wiring.py) pass. They observe each fail-closed path and the effective values per region.
2. OSCAL: `cm-6` and `ctrl-agt-001` implemented requirements were added to [`system-security-plan-eu-ecb.yaml`](../compliance/oscal/system-security-plan-eu-ecb.yaml) and [`system-security-plan-apac-mas.yaml`](../compliance/oscal/system-security-plan-apac-mas.yaml). The US_FED `cm-6` statement in [`system-security-plan.yaml`](../compliance/oscal/system-security-plan.yaml) was corrected; it had cited a `singletons.py` that does not exist. `uv run python -m src.gateway.governance.oscal_ssp_exporter export` (default discovery) compiled, and [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) passed (50 tests).
3. **Lula: not run.** The `lula` CLI is not installed in the verification environment. No EU_ECB or APAC_MAS cluster exists; the only staging cluster is US_FED (`us-central1`). [`lula-validation-mas-trm-s6.yaml`](../compliance/lula/lula-validation-mas-trm-s6.yaml) asserts a compliance-bridge endpoint (`/v1/compliance/mas/trm-s6`) that is not implemented (APAC-MAS-TRM-001), so it cannot pass in any environment yet. [`lula-validation-cm6.yaml`](../compliance/lula/lula-validation-cm6.yaml) asserts that the threshold ConfigMaps exist, not their values. No Lula manifest change was required: no Kubernetes resource was added, removed or renamed. Closure rests on the tests and the OSCAL export above.

**Residual:** FIN-1 (`stpa.max_sell_portfolio_fraction`) had no runtime reader in any region. It was tracked separately as POAM-2026-103, which is now closed (UCA-13).

### POAM-2026-103: FIN-1 Portfolio Sell-Fraction Limit Has No Runtime Reader

**Control:** NIST SI-10, CM-6
**Risk Level:** Moderate
**Status:** Closed
**Date Opened:** 2026-10-06
**Date Closed:** 2026-10-06
**Remediation Commit:** `fa7d594b` (#421, squash-merged to `main`)

**Description:**
`domains.finance.stpa.max_sell_portfolio_fraction` (global 0.10, EU_ECB 0.08, APAC_MAS 0.09) is declared in the threshold files, overlaid by region and validated by the finance schema. FIN-1 in [`trade_hazards.yaml`](../src/cage_finance/config/stpa/trade_hazards.yaml) (`sell_percentage <= stpa.max_sell_portfolio_fraction`, scope `execute_sell`) had no Python or Rego rule reading it. [`uca_rules.py`](../src/cage_finance/stpa/uca_rules.py) implemented UCA-2/FIN-2, UCA-5 and UCA-6 only. The `FIN-1` constraint in [`ontology.py`](../src/cage_finance/ontology.py) was a different rule (sell amount ≤ holdings) that shared the ID. The `ecca70b9` commit message lists FIN-1 among the newly enforced limits; that held for the configured value but not for enforcement.

**Remediation:**
1. The STPA compiler ([`stpa_compiler.py`](../src/gateway/governance/stpa_compiler.py)) gained two domain-agnostic condition fields: `applies_when` (scope a rule to `param == value`, case-insensitive) and `require_params` (a composite condition fails closed when an operand is missing). Composite operands that are booleans or non-numeric are now rejected for every composite rule (this also tightens UCA-6).
2. New UCA-13 in [`trade_hazards.yaml`](../src/cage_finance/config/stpa/trade_hazards.yaml): for `execute_trade` with `side == sell`, `amount > stpa.max_sell_portfolio_fraction × portfolio_total` is a HARD violation (hazards H-4, H-5; Python and OPA enforcement). A sell without a numeric `amount` or `portfolio_total` is refused. FIN-1 now references UCA-13 with scope `execute_trade`. [`uca_rules.py`](../src/cage_finance/stpa/uca_rules.py) was regenerated and `scripts/check_stpa_freshness.py` passes.
3. The ontology's sell-vs-holdings constraint was renamed `FIN-3`, so every FIN ID is unique.
4. UCA-13 was added to the four framework mappings in `config/oscal/framework_mappings/` (NIST `sc-4`, `cm-6`).

**Verification (2026-10-06):**
1. [`tests/cage_finance/test_fin1_sell_fraction.py`](../tests/cage_finance/test_fin1_sell_fraction.py) observes, for each region (EU_ECB 0.08, APAC_MAS 0.09, US_FED 0.10), that a sell at the limit passes, a sell above it is refused, and a sell with a missing or invalid amount or `portfolio_total` is refused. Buys are out of scope. [`tests/test_stpa_compiler_scoped_conditions.py`](../tests/test_stpa_compiler_scoped_conditions.py) covers the compiler fields.
2. OSCAL: the FIN-1 statements in [`system-security-plan-eu-ecb.yaml`](../compliance/oscal/system-security-plan-eu-ecb.yaml) and [`system-security-plan-apac-mas.yaml`](../compliance/oscal/system-security-plan-apac-mas.yaml) and the US_FED `cm-6` statement in [`system-security-plan.yaml`](../compliance/oscal/system-security-plan.yaml) now record enforcement. `uv run python -m src.gateway.governance.oscal_ssp_exporter export` (default discovery) compiled, and [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) passed.
3. **Lula: not run**, for the same reasons as POAM-2026-102: the `lula` CLI is not installed and no EU_ECB or APAC_MAS cluster exists. No Kubernetes resource was added, removed or renamed, so no Lula manifest change was required. Closure rests on the tests and the OSCAL export above.

**Follow-up (`52119fef`, #422):** `execute_trade_action` in [`tool_provider.py`](../src/cage_finance/tools/tool_provider.py) takes the order `side` and, for a sell, set `portfolio_total` from the custodian cash-ledger snapshot of the governor's `finance.cash_balance` ground-truth provider. The caller cannot supply `portfolio_total`. Cash was a stand-in: it under-states the portfolio once the account holds positions, which only made FIN-1 stricter.

**Follow-up (`fix/fin1-portfolio-total-nav`, 2026-10-06):** `portfolio_total` = current NAV from the server-side NAV source. [`ServerTradeInputs.resolve()`](../src/cage_finance/tools/trade_inputs.py) fetches one [`PortfolioNavSource`](../src/cage_finance/tools/trade_inputs.py) snapshot per trade and gives a sell both `drawdown` (UCA-5) and `portfolio_total` (`current_nav`) from it. `fetch_verified_nav()` applies the reconciler's checks: verified source, finite values, positive opening NAV, age within the reconciler TTL, and at most 5 s of future skew. A missing, faulted, stale, unverified, future-dated or zero NAV leaves `portfolio_total` unset, and UCA-13 refuses the sell inside the governor. The cash-ledger reader (`portfolio_valuation.py`) was removed. [`test_trade_tool_sell_inputs.py`](../tests/cage_finance/test_trade_tool_sell_inputs.py) covers the per-region FIN-1 matrix against NAV, the case where FIN-1 tracks current rather than opening NAV, the case where the cash ledger is never read, and every NAV fault mode.

### POAM-2026-104: Warrant Reliance Gate Residuals (EU_ECB)

**Control:** NIST AC-3, SC-13, AU-10
**Risk Level:** Moderate
**Status:** ✅ CLOSED (2026-10-10)
**Date Opened:** 2026-10-06
**Date Closed:** 2026-10-10
**Related Commit:** `a0deb7ad` (#423, squash-merged to `main`); closed by `4f5562b1` (#451), `fe9b57e9` (#458), and `88d6e0fc` (#459)

**Description:**
Since `a0deb7ad`, `config/thresholds/EU_ECB_BASELINE.json` marks `domains.finance.confidence.min_trade_confidence` as warranted (`value` 0.97, `requires_warrant: true`, `governing_version: cage-policy-2.1.0`). For every `execute_trade` and `execute_trade_bounded` request, [`WarrantStage`](../src/gateway/governance/governor/stages/warrant.py) fetches the norm's warrant through the `WarrantSource` seam and evaluates its standing with [`WarrantStandingVerifier`](../src/gateway/governance/warrant/verifier.py). Any ineligible standing is a `RELIANCE_INELIGIBLE` finding, and the governor defers with `DeferReason.WARRANT_INELIGIBLE` and mints no seal. The stage re-runs under `POST_HITL`, and [`assemble_governor()`](../src/gateway/governance/governor/assembly.py) refuses a warranted norm with no source, with DEFER disabled, without a `governing_version`, or with no claiming tier. All four residuals are resolved:

1. ~~**Warrant authenticity is UNVERIFIED.**~~ **Resolved 2026-10-10 by `4f5562b1` (#451) and `fe9b57e9` (#458).** [`WarrantTrustAnchor`](../src/gateway/governance/warrant/trust_anchor.py) pins the out-of-band root Ed25519 public key by raw 32-byte SHA-256 fingerprint (`sha256:61ab867fc9ce773f2974081effbf0c9a4173caa23a4e18fa2c3bf65b249b8d85`) and [`VerifiedKeyManifest.verify()`](../src/gateway/governance/warrant/trust_anchor.py) verifies the JCS digest and Ed25519 signature of `GET /.well-known/veip/key-manifest.json` (`veip-key-manifest/0.2`), cached out-of-band in [`WarrantCache`](../src/gateway/governance/warrant/cache.py). [`WarrantStandingVerifier.verify_standing()`](../src/gateway/governance/warrant/verifier.py) enforces `VerifiedKeyManifest` in the type system, resolves `warrant.kid` (failing closed as `INELIGIBLE_AUTHENTICITY` on `UNKNOWN_KID` or inactive/expired keys), verifies the 18-field v0.2 JCS digest and Ed25519 signature (`TAMPERED_SIGNATURE` → `INELIGIBLE_AUTHENTICITY`), enforces `state_as_of` freshness (`<= 60` s, else `INELIGIBLE_STALE`) and `norm_parameters` value parity, and sets `verification_status: VERIFIED` on [`StandingVerificationResult`](../src/gateway/governance/warrant/model.py) and [`RelianceRecord`](../src/gateway/governance/warrant/reliance.py) only after cryptographic verification succeeds.
2. ~~**No live warrant source.**~~ **Resolved 2026-10-10 by `4f5562b1` (#451) and `fe9b57e9` (#458).** [`Provider05WarrantSource`](../src/integrations/provider_05/warrant_source.py) implements async HTTP fetching (`GET {endpoint}/v0.2/warrants/{norm_id}` and `GET {endpoint}/.well-known/veip/key-manifest.json`, mapping HTTP 404 to `None` / `INELIGIBLE_MISSING`) and is verified over the physical wire against `https://veip-cage-sandbox.am-43b.workers.dev` across all 8 VEIP v0.2 conformance scenarios in [`tests/integrations/provider_05/test_provider_05_live.py`](../tests/integrations/provider_05/test_provider_05_live.py).
3. ~~**Approval token burned on a post-HITL warrant refusal.**~~ **Resolved 2026-10-07 by `fix/hitl-token-warrant-defer` (#436).** The gateway consumed the `HITL_REQUIRED` token before `revalidate_post_hitl()` ran, so a warrant revoked between approval and execution cost the reviewer's work. Decision (closure criterion 4): neither keep burning nor re-park; **decide first, spend second.** [`enforce_approved_governance()`](../src/gateway/server/governance_middleware.py) now checks the token without spending it (`DeferQueue.redeemable_approval()`) and passes the governor an unspent [`PostHitlApproval`](../src/gateway/governance/governor/approval.py). The governor spends it (`DeferQueue.consume_approval()`, the existing atomic `RESOLVED → CONSUMED` CAS) through the `admit` hook of [`run_sealed()`](../src/gateway/governance/governor/sealing.py): inside the `ReservationScope`, after every stage passed, before the seal is minted. A warrant-ineligible DEFER (no HARD finding) never reaches the spend: it hash-chains a `GOVERNANCE_DEFERRAL` (`profile: POST_HITL`, `defer_id` = the approval id, `approval_retained: true`, the reliance records) and raises `GovernanceDeferred`; the trade tool reports `DEFERRED:`. The approval token itself stays the resolvable record (still `RESOLVED`, so immutable; same action and parameter binding; its own Redis TTL), and redeems once the warrant is eligible again. A DENY (barrier drift, HARD finding, ungoverned action, unrecognised snapshot) still spends it. Of concurrent redemptions only one spend wins; a loser seals nothing, rolls its phase-2 commits back and is refused `APPROVAL_NOT_REDEEMABLE` with a receipt. A refund (consume, then restore on DEFER) was rejected: it needs a second state transition out of `CONSUMED`, opens a window in which a concurrent redemption sees the approval as spent, and makes the single-use guarantee depend on the restore succeeding.
4. ~~**Warrant not bound into the evidence record.**~~ **Resolved 2026-10-06 by `0cdb5aaa` (#427).** Every warranted norm the decision relied on now produces a kernel [`RelianceRecord`](../src/gateway/governance/warrant/reliance.py) (norm_id, warrant_id, declared digest, warrant status, reliance status, governing_version, evaluated_at, provider_name, verification_status `VERIFIED` under v0.2 or `UNVERIFIED` otherwise). ALLOW and NARROW seals carry it in their evidence record, inside `record_hash`, so altering or dropping it breaks seal verification ([`verify_seal_against_evidence()`](../src/gateway/governance/routing_seal.py)). The ALLOW envelope carries a `WARRANT` attestation. DEFER and REQUIRE_APPROVAL tokens and a hash-chained `GOVERNANCE_DEFERRAL` record carry the same record, and a DENY receipt with a co-occurring warrant failure carries it inside `proof_hash`.

**Freshness window (2026-10-06, `9ddefb8c`, #430; v0.2 `state_as_of` added 2026-10-10) — implemented; documented limitation, not an open gap.** [`WarrantCache`](../src/gateway/governance/warrant/cache.py), wired by `assemble_governor()` (one per governor), enforces the Warrant Contract v0.1/v0.2 Q2 window. It stamps each warrant with CAGE's receipt time and serves it only while its age is at most `warrant.max_age_seconds` (default 60, validated `0 < x <= 60`), while [`WarrantStandingVerifier`](../src/gateway/governance/warrant/verifier.py) also enforces `0 <= now - state_as_of <= max_age_seconds` on v0.2 warrants (`STALE_STATE` → `INELIGIBLE_STALE`). Past the cache window it re-fetches. A re-fetch that fails or exceeds `warrant.fetch_timeout_seconds` (default 2) yields `INELIGIBLE_STALE` → `RELIANCE_INELIGIBLE` → DEFER. The same rule applies under `POST_HITL`, and the reliance record carries `observed_at`, `age_seconds` and `max_age_seconds`.

**Verification of the enforcement path (2026-10-06 .. 2026-10-11):**
1. [`tests/governor/test_warrant_reliance_gate.py`](../tests/governor/test_warrant_reliance_gate.py) passes. It covers the failure matrix, a revoked warrant at confidence 0.99 deferring rather than denying, a HARD finding still denying, no seal on warrant failure, a warrant revoked after approval being refused with no seal and no commit, the assembly refusals, and the pinned EU_ECB (norm_id, value) → `governing_version` pair. [`proof/model.py`](../proof/model.py) claims 12 and 13 hold, with parity in [`tests/test_formal_profile_parity.py`](../tests/test_formal_profile_parity.py).
2. OSCAL: [`system-security-plan-eu-ecb.yaml`](../compliance/oscal/system-security-plan-eu-ecb.yaml) updates component `eu-ecb-comp-0006` (warrant reliance gate, attestation status `VERIFIED`) and `ac-3` requirement `eu-ecb-req-0007` (`implemented`). `uv run python -m src.gateway.governance.oscal_ssp_exporter export` (default discovery) compiled, and [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py) passed (50 passed).
3. **Lula: not run.** The `lula` CLI is not installed and no EU_ECB cluster exists. No Kubernetes resource was added, removed or renamed, so no Lula manifest change was required.
4. **Evidence binding (2026-10-06, `0cdb5aaa`).** [`tests/governor/test_warrant_evidence_binding.py`](../tests/governor/test_warrant_evidence_binding.py) passes over a real hash-chained `EvidenceStreamSink` and `DeferQueue` (fakeredis).
5. **Freshness window (2026-10-06, `9ddefb8c`).** [`tests/governor/test_warrant_freshness.py`](../tests/governor/test_warrant_freshness.py) passes (57 tests, injected clocks).
6. **End to end (2026-10-06, `test/warrant-reliance-e2e`; updated 2026-10-10 for v0.2).** [`tests/governor/test_warrant_reliance_e2e.py`](../tests/governor/test_warrant_reliance_e2e.py) runs both the v0.1 and v0.2 matrices through `bootstrap_governor()`, the gateway and the trade tool.
7. **Approval retained on a post-HITL warrant deferral (2026-10-07, `fix/hitl-token-warrant-defer` (#436)).** [`tests/governor/test_post_hitl_approval_spend.py`](../tests/governor/test_post_hitl_approval_spend.py) and [`tests/governor/test_warrant_reliance_e2e.py`](../tests/governor/test_warrant_reliance_e2e.py) pass.
8. **VEIP v0.2 trust-anchor signature verification, Tier 1 over-the-wire conformance & joint closure (2026-10-10 .. 2026-10-11, `4f5562b1` #451, `fe9b57e9` #458, `88d6e0fc` #459).** [`tests/integrations/provider_05/test_provider_05_veip_vectors.py`](../tests/integrations/provider_05/test_provider_05_veip_vectors.py) and [`tests/integrations/provider_05/test_provider_05_live.py`](../tests/integrations/provider_05/test_provider_05_live.py) (`--run-live-external` against `https://veip-cage-sandbox.am-43b.workers.dev`) pass across all 8 scenarios (`ACTIVE`, `REVOKED`, `SUSPENDED`, `EXPIRED`, `STALE_STATE`, `TAMPERED_SIGNATURE`, `UNKNOWN_KID`, `MISSING`), recorded in [`docs/partners/provider_05/veip_v02/CAGE_VEIP_v0.2_JCAR_CLOSURE_001.json`](../docs/partners/provider_05/veip_v02/CAGE_VEIP_v0.2_JCAR_CLOSURE_001.json) (`CAGE-VEIP-V0.2-JCAR-CLOSURE-001`, `status: "JOINTLY_ALIGNED"`).

**Closure Criteria:**
1. ~~Issuer signature verification against a `kid`-resolved, independently fetched trust anchor, failing closed on unknown `kid` (VEIP v0.2). Warrants are reported `VERIFIED` only after that check.~~ **Met 2026-10-10** by `4f5562b1` (#451) and `fe9b57e9` (#458) (gap 1).
2. ~~A live warrant source (implemented provider_05 HTTP path or another `WarrantSource`) tested over the wire against the partner's staging endpoint (Tier 1 conformance).~~ **Met 2026-10-10** by `4f5562b1` (#451) and `fe9b57e9` (#458) (gap 2).
3. ~~Warrant identity, digest and standing bound into the decision's evidence record (PR 4).~~ **Met 2026-10-06** by `0cdb5aaa` (#427).
4. ~~A decision recorded on the approval-token behaviour (keep burning, or re-park on a post-HITL warrant refusal).~~ **Met 2026-10-07** by `fix/hitl-token-warrant-defer` (#436): neither; the approval is spent only by the run that seals (gap 3).

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
[`infra/modules/memorystore_valkey/outputs.tf`](../infra/modules/memorystore_valkey/outputs.tf) exported `managed_server_ca` (the Google-managed private CA PEM certificates from `google_memorystore_instance.this.managed_server_ca[0].ca_certs[*].certificates`), and [`infra/modules/gateway/variables.tf`](../infra/modules/gateway/variables.tf) and [`infra/modules/compliance_bridge/variables.tf`](../infra/modules/compliance_bridge/variables.tf) declared `redis_ca_cert_path`, but [`infra/targets/gcp-gke/main.tf`](../infra/targets/gcp-gke/main.tf) never wired the two together. Neither module created a `ConfigMap`, volume, or `volumeMount`. With `enable_memorystore_tls = true` (`REDIS_TLS=true`), [`redis_client.py`](../src/gateway/infrastructure/redis_client.py) enforced `ssl_cert_reqs=ssl.CERT_REQUIRED` against the container's default Mozilla CA bundle (`certifi`), which does not include Memorystore's per-instance Google-managed private CA. Consequently, `start_evidence_sink()` failed on startup with `SSLCertVerificationError: certificate verify failed: self-signed certificate in certificate chain`, leaving `EVIDENCE_CHAIN_BLOCKING=true` fail-closed and `deploy/gateway` `0/1 Ready`.

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

### POAM-2026-095 to POAM-2026-098: Findings From Verifying the Paper Against the Code

**Date Opened:** 2026-10-03
**Source:** checking the arXiv manuscript's claims against the code at `fcfb4ebb`.

| ID | Control | Risk Level | Status |
|---|---|---|---|
| POAM-2026-095 | SC-13 / SC-12 / IA-5 | High | Closed (2026-10-03) |
| POAM-2026-096 | CA-7 / SI-10 | High | Closed (2026-10-03) |
| POAM-2026-097 | SI-10 / SC-23 | High | Closed (2026-10-03) |
| POAM-2026-098 | AU-10 / AC-3 / SI-10 | Moderate | Open — partner adoption pending (target 2026-12-31) |

**Description:**
- **095:** no asymmetric routing seal could verify. The `alg` header held a provider label, and ECDSA signatures were left in DER form instead of JOSE raw R‖S. A seal with no `kid` fell back to the single published key.
- **096:** the reconciler's 5-minute CronJob cadence equalled the 300 s verified-state TTL, so verified state lapsed between runs. The discrepancy-floor branch also wrote the CBF state key from a reading it had just rejected.
- **097:** the ground-truth replay check was a non-atomic read-then-write, and a Redis error let it pass.
- **098:** actuation outcomes were binary, so an indeterminate dispatch released reserved capacity and could be retried (fail-open). Partner receipts were trusted without authentication. Three call sites each wrote the receipt to the evidence chain. A hidden attribute set on the frozen receipt suppressed the duplicate writes, so no receipt was recorded twice, but the evidence had two owners and depended on hidden mutable state.

**Remediation (implemented):**
1. **095** (`9c68a6e8`): `generate_seal()` in [`routing_seal.py`](../src/gateway/governance/routing_seal.py) writes `jose_alg` to the header. `KMSGovernanceSigner.sign_jws()` in [`kms_signer.py`](../src/gateway/governance/kms_signer.py) converts DER to raw, and providers declare their native encoding. [`jwks.py`](../src/gateway/governance/jwks.py) requires a `kid`.
2. **096** (`9c68a6e8`): the reconciler runs as a Deployment in loop mode, and `run_loop()` enforces `ttl >= 2 × poll`. The floor branch never writes state.
3. **097** (`9c68a6e8`): an atomic Lua compare-and-advance in [`cbf_engine.py`](../src/gateway/governance/safety/cbf_engine.py) that fails closed on a Redis error.
4. **098** (`9c68a6e8`, `72574529`):
   - `ActuationOutcome` {ACCEPTED, REJECTED, UNKNOWN}. `UNKNOWN` settles as executed and is never retryable.
   - `dispatch_actuation()` is the sole caller of `actuate()` and the sole evidence writer. An actuator exception becomes an `UNKNOWN` receipt (`ACTUATOR_EXCEPTION`).
   - `ReceiptVerification` is recorded with every receipt.
   - actuator_01 verifies a detached Ed25519 signature by `kid`, using the shared [`Ed25519KeyManifestClient`](../src/integrations/trust/key_manifest.py) (`INVALID` forces `UNKNOWN`). Strict mode is `ACTUATOR_01_REQUIRE_SIGNED_RECEIPTS`.
   - Evidence: [`tests/test_actuation_outcome.py`](../tests/test_actuation_outcome.py), [`tests/test_actuator_01_receipt_verification.py`](../tests/test_actuator_01_receipt_verification.py).

**Closure Verification (2026-10-03):**
1. `make test-fast` on `fix/paper-verify-findings` at `72574529`: 6203 passed, 107 skipped, 0 failed.
2. `uv run python -m src.gateway.governance.oscal_ssp_exporter export` succeeded. [`tests/test_oscal_ssp_exporter.py`](../tests/test_oscal_ssp_exporter.py): 50 passed. The OSCAL statements are in [`sp800-53-component-definition.yaml`](../compliance/oscal/sp800-53-component-definition.yaml) with `poam-reference` props. SC-13/095, CA-7/096 and SI-10/097 are `implemented`. AU-10/098 is `partial`.
3. Lula: no assertion in `compliance/lula/` references the reconciliation worker, routing-seal algorithms or actuation receipts, so no Lula result is affected.
4. Squash-merge commit: `e1f46eca` (#391).

**Open for 098:** the partner must adopt the receipt-signature format, and the actuator_01 sandbox must pass an over-the-wire conformance test. After that, enable strict mode in enforcing postures and close the item. `Provider07JwksClient` should move to the shared manifest client.
