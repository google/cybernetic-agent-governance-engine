# Changelog

All notable changes to the Cybernetic Governance Engine (CAGE) are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Change record authority:** Per `.clinerules` §8.5 and `docs/CHANGE_MANAGEMENT_PROCESS.md`, every Cat-N (Normal) and Cat-M (Major) change must be recorded here before the associated tag is pushed. This file is referenced by the `gh release create` runbook step in `docs/V2_RELEASE_RUNBOOK.md` §6.9.

---

## [Unreleased]

---

## [2.0.0] — 2026-06-08

> Stable release. All P0/P1 blockers resolved (Sprint 1 + Sprint 2). Track C (seal enforcement) and Track D (compliance validation) gates complete. All universal Lula assertions PASS. Trivy scan risk-accepted (POAM-023). Token Quota Proxy, PII Sanitizer, and UCA Logger active in production.

### Added — [CR-2026-TQP-001] Token Quota Proxy (Cat-N)

- **Token Quota Proxy** (`src/gateway/governance/token_quota_proxy.py`) — Per-session step-count and token quota enforcement via Redis atomic Lua counters. ISO 42001 Annex A.4. Governance control `CTRL_TQP_007`. Fail-CLOSED: Redis unavailability blocks the request. Returns HTTP 429 with structured JSON body on quota exceeded.
- **PII Sanitizer** (`src/gateway/governance/pii_sanitizer.py`) — Pre-ledger PII sanitization pipeline. ISO 42001 Annex A.6. Redacts SSN, credit card numbers, email addresses, phone numbers, and API key/Bearer token patterns before writing UCA records to the WORM ledger.
- **UCA Logger** (`src/gateway/governance/uca_logger.py`) — ISO 42001 Clause 6.1 Unsafe Control Action record logger. Builds 16-field compliance records, signs with KMS (HMAC-SHA256 stub in `CAGE_ENV=test`), and writes to region-gated WORM bucket (`CAGE_DEPLOYMENT_REGION`).
- **Token quota thresholds config** (`config/thresholds/token_quota.yaml`) — Declarative quota thresholds: `step_quota_max: 12`, `token_quota_max: 100 000`, `session_ttl_seconds: 3600`. Model overrides for `deepseek-r1` and `deepseek-reasoning` (50 000 tokens).
- **`CTRL_TQP_007` registered** in `config/thresholds/US_FED_BASELINE.json`, `EU_ECB_BASELINE.json`, `APAC_MAS_BASELINE.json` — ISO 42001 Annex A.4, enforcement tier 2, region-specific WORM bucket env var.
- **`TOKEN_QUOTA_ENFORCEMENT = "CTRL_TQP_007"`** added to `GovernanceControl` enum (`src/gateway/governance/constants.py`).
- **Unit tests** — `tests/test_pii_sanitizer.py` (10 tests), `tests/test_token_quota_proxy.py` (8 async tests, `fakeredis`-backed), `tests/test_uca_logger.py` (9 tests). All `@pytest.mark.local`.

### Changed — [CR-2026-TQP-001] Token Quota Proxy (Cat-N)

- **`src/gateway/server/inference_proxy.py`** — Quota check inserted as Step 2 in the 6-stage governance pipeline. HTTP 429 returned on quota exceeded. `rollback_step()` called on NeMo exception.
- **`src/gateway/server/hybrid_server.py`** — `TokenQuotaProxy` and `UCALogger` pre-warmed into `app.state` at startup in `_gateway_lifespan()`.
- **`deployment/system_authz.rego`** — Appended `quota_within_limits`, `token_quota_within_limits`, `tool_approved` (9-tool allowlist), and `cage_systemic_governance_allow` Rego rules. Token quota injection from `governance_middleware.py` deferred (plan §23.7); rules default to `true` when session state is absent.

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

### Track C & D — Seal Enforcement + Compliance Validation — [CR-2026-TQP-001] (Cat-N, 2026-06-08)

> Track C (Seal Enforcement Verification) is complete. Track D (Compliance Validation) is complete — all cluster-side gates executed against live GKE environment (`cage-dev`, namespace `governance-stack`). Both tracks are part of the same release gate sequence as the Token Quota Proxy (CR-2026-TQP-001).
>
> Commits: `a7e01ea` (Track C — `verify_remote.py` seal enforcement checks), `554f5af` (Track D — `fiscal_limit_guard.py` async heuristic fix).
>
> reviewed-by: N/A — self-verified via automated test suite | approved date: 2026-06-08 | implemented date: 2026-06-08 | Lula validation result: PASS (all 4 manifests: a52, a53, a92, aarm-vectors)

#### Gate Status

| Gate | ID | Description | Status |
|------|----|-------------|--------|
| U-15 | C2 | Unsigned gateway request → HTTP 403 | ✅ Green |
| U-16 | C2 | Valid signed gateway request → non-403 | ✅ Green |
| U-01–U-04 | D1 | Lula re-validation (ISO 42001 / CSA AARM) | ✅ Green |
| U-05 | D2 | SBOM generation (CycloneDX) | ✅ Green |
| U-06 | D2 | Trivy container scan | ⚠️ Risk Accepted — 19 CRITICAL CVEs (CVE-2025-13462, libpython3.11); no Debian fix; suppressed via `.trivyignore`; POAM-023 opened |
| U-08 | D3 | Full test suite 796 passed, 0 failed | ✅ Green |
| U-09 | D4 | STPA freshness check | ✅ Green |
| U-10 | D5 | Langfuse posture verification | ✅ Green |
| U-17 | — | security-scanner-cronjob present | ✅ Green |
| U-18 | — | PSA labels applied (restricted/baseline) | ✅ Green |
| U-21 | D6 | `terraform.auto.tfvars` gitignored | ✅ Green |

#### Track C — Seal Enforcement Verification (complete)

- **C1 — `CAGE_SEAL_ENFORCEMENT=enforce` confirmed** (`src/gateway/server/governance_middleware.py`) — `enforce_routing_seal()` raises HTTP 403 on missing or invalid `X-CAGE-Routing-Seal` header. Implementation verified in-source; no code change required.
- **C2/C3 — `TestRoutingSealEnforcement` + `test_routing_seal.py`** (gates U-15, U-16) — 18/18 tests pass. `TestRoutingSealEnforcement` (7 tests) covers the middleware enforcement path; `tests/test_routing_seal.py` (11 tests) covers the HMAC seal construction and verification logic. Both gate conditions confirmed green.
- **C4 — `scripts/verify_remote.py` enhanced** (SHA `a7e01ea`) — Added `check_seal_enforcement()` (remote U-15/U-16 verification via live HTTP probes) and `check_langfuse_posture()` (subprocess delegation to `scripts/verify_langfuse_posture.py`). Script now exits with code 1 on any gate failure, making it suitable as a blocking pre-release check.

#### Track D — Compliance Validation (complete)

- **D1 — Lula re-validation passes** (gates U-01–U-04) — `lula validate` executed against all 4 active manifests on live cluster: `lula-validation-a52.yaml`, `lula-validation-a53.yaml`, `lula-validation-a92.yaml`, `lula-validation-aarm-vectors.yaml`. All assertions pass. ISO 42001 and CSA AARM posture confirmed.
- **D2 — SBOM generation passes** (gate U-05) — `python scripts/generate_sbom.py` executed on live cluster. CycloneDX SBOM artifact generated and validated. Gate U-05 green.
- **D2 — Trivy scan: risk accepted** (gate U-06) — Trivy container scan identified 19 CRITICAL CVEs in `libpython3.11` (CVE-2025-13462) in the `python:3.12-slim-bookworm` base layer. No Debian bookworm fix available as of 2026-06-08. `apt-get upgrade -y` applied during image build cannot remediate this CVE. Risk accepted: CVE suppressed via `.trivyignore`; POAM-023 opened with review date 2026-09-08; network egress locked down via Cilium to reduce exploitability.
- **D3 — Full test suite passes** (gate U-08) — **796 passed, 0 failed** (148 skipped). `fiscal_limit_guard.py` async heuristic fix (SHA `554f5af`) confirmed effective. Gate U-08 green.
- **D4 — STPA freshness check passes** (gate U-09) — `scripts/check_stpa_freshness.py` confirms all 3 generated STPA artifacts are current relative to `config/stpa_control_structure.yaml`. No regeneration required.
- **D5 — Langfuse posture verification passes** (gate U-10) — `python3 scripts/verify_langfuse_posture.py` confirms dual-project isolation: core project `cmpugv47f000dwq07fqu86ral`, compliance project `cage-compliance`. Evidentiary independence of audit traces confirmed.
- **D6 — `terraform.auto.tfvars` gitignored** (gate U-21) — Confirmed via `*.auto.tfvars` pattern present in both `infra/targets/gcp-gke/.gitignore` and `infra/targets/agnostic/.gitignore`. No secrets in working tree.
- **U-17 — security-scanner-cronjob present** — `security-scanner-cronjob` confirmed present in `governance-stack` namespace. Scan target corrected to `gateway:latest` (was previously misconfigured). Gate green.
- **U-18 — PSA labels applied** — PodSecurity admission labels confirmed: `governance-stack=restricted`, `langfuse=baseline`, `vllm=baseline`. Gate green.
- **`.env.example` updated** — Langfuse compliance variables (`LANGFUSE_COMPLIANCE_PUBLIC_KEY`, `LANGFUSE_COMPLIANCE_SECRET_KEY`, `LANGFUSE_COMPLIANCE_HOST`) added to `.env.example` to document the dual-project configuration requirement.

### Post-Release CI & Infra Fixes (Cat-S, 2026-06-08 – 2026-06-09)

> These fixes were discovered during CI execution after the local release gate verification at `7d5990c`. They are included in the v2.0.0 stable tag (moved to `8ce3cae`) because: (a) the STPA freshness CI gate and security scan were provably failing at the original tag commit; (b) the IAM bindings are deployment prerequisites without which Cloud Build cannot push images; (c) the tag had never been pushed to a public remote, making recreation safe. No application logic was changed.
>
> Commits: `d3408a8`, `46a908d` (PR #9), `030cf88` (PR #10), `51c5df2` (PR #11), `8ce3cae`.

#### Fixed

- **CI: STPA freshness check broken in shallow clones** (`d3408a8`, `.github/workflows/ci.yml`) — Added `fetch-depth: 0` to the `stpa-freshness-check` checkout step. Without full history, `git log` could not resolve source file commit times in CI shallow clones, causing the U-09 gate to fail on every CI run post-tag.
- **CI: Security scan CVEs resolved** (`d3408a8`, `uv.lock`, `.github/workflows/security-scan.yml`) — Upgraded aiohttp 3.13.5→3.14.1 (CVE-2026-34993, CVE-2026-47265), starlette 0.52.1→1.2.1 (PYSEC-2026-161) via google-adk 2.2.0, pip 26.1.1→26.1.2 (PYSEC-2026-196), pyjwt 2.12.1→2.13.0 (PYSEC-2026-175/177/178/179). Removed `--ignore-vuln CVE-2026-4810` (resolved by google-adk 2.2.0). Added `--ignore-vuln PYSEC-2026-139` (torch 2.10.0, dev-only, no upstream fix; POAM-016 to be created).
- **CI: Security scan now uses locked dependency tree** (`46a908d`, `.github/workflows/security-scan.yml`) — Replaced `pip install pip-audit` + `pip install -e ".[dev]"` with `uv sync --frozen --all-groups --all-extras` + `uv run pip-audit`. Ensures pip-audit scans the exact versions in `uv.lock`, not a fresh pip-resolved tree.
- **`stpa_compiler.py`: `validate()` shim added to compiler template** (`d3408a8`, `src/gateway/governance/stpa_compiler.py`) — Added `validate()` public entry-point to the `GeneratedSTPAValidator` class template so it is emitted on every compiler run rather than manually maintained. Regenerated all STPA artifacts (timestamp: `2026-06-08T19:22:41Z`).
- **`compliance_bridge/Dockerfile`: pin uv to 0.10.9 and add `--no-build`** (`030cf88`, `src/compliance_bridge/Dockerfile`) — Pinned `uv` from `:latest` to `:0.10.9` for reproducible Cloud Build runs. Added `--no-build` to `uv sync` to prevent silent C-compile fallback when a pre-built wheel is unavailable.
- **Infra: Cloud Build SA missing `artifactregistry.writer`** (`51c5df2`, PR #11, `infra/targets/gcp-gke/main.tf`) — Added `google_project_iam_member` binding granting `roles/artifactregistry.writer` to the default Cloud Build SA (`[PROJECT_NUMBER]@cloudbuild.gserviceaccount.com`). Without this, the Cloud Build push step failed with `Permission 'artifactregistry.repositories.uploadArtifacts' denied`.
- **Infra: compliance-bridge-sa missing `artifactregistry.writer`** (`8ce3cae`, `infra/targets/gcp-gke/main.tf`) — Added a second `google_project_iam_member` binding for the custom compliance-bridge Cloud Build SA (`compliance-bridge-sa@YOUR_GCP_PROJECT_ID.iam.gserviceaccount.com`). The previous binding only covered the default Cloud Build SA; the compliance-bridge trigger uses a custom SA.

---

## Version History Summary

| Version | Date | Test Results | Key Theme |
|---------|------|--------------|-----------|
| [Unreleased] | — | — | Post-stable backlog |
| [2.0.0] | 2026-06-08 | 796 passed, 0 failed, 148 skipped | Stable release: Token Quota Proxy, PII Sanitizer, UCA Logger, CTRL_TQP_007, gateway CVE remediation, seal enforcement, all universal Lula assertions PASS |

---

[Unreleased]: https://github.com/YOUR_GCP_PROJECT_ID/cybernetic-governance-engine/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/YOUR_GCP_PROJECT_ID/cybernetic-governance-engine/releases/tag/v2.0.0
